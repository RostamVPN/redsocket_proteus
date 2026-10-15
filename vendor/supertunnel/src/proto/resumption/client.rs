//! Client-side session resumption.
//!
//! Manages session identifiers and coordinates with the server to re-establish
//! dropped connections without losing active session state.

use std::collections::VecDeque;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures::SinkExt;
use rand::Rng;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::Protocol;
use crate::proto::resumption::{Command, ResumptionCodec, ResumptionMessage};
use crate::sync::{ChannelCommand, ChannelSink, ChannelStream};
use crate::util::{DecodedSink, EncodedStream};

/// Errors that can occur when initiating a session resumption request.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum RequestError {
    /// A previous resumption request is still pending a response.
    ResponsePending,
    /// The background controller task has terminated, closing the communication channel.
    ChannelClosed,
    /// The request timed out before we received a response from the controller.
    ChannelTimeout,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RequestError::{:?}", self)
    }
}

/// Errors that can occur while awaiting the server's response to a resumption request.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ResponseError {
    /// No pending request was found. You must call `resume_request()` before awaiting a response.
    ChannelNotFound,
    /// The response channel was closed, indicating the controller failed or the server dropped.
    ChannelClosed,
    /// Timed out waiting for the resume operation to complete (including the server-side resumption steps).
    ChannelTimeout,
    /// The resumption attempt explicitly failed on the server (e.g., the session expired).
    ResumeFailed,
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ResponseError::{:?}", self)
    }
}

/// The client-side protocol layer for managing session resumption.
///
/// Handles obtaining a session ID and negotiating reconnection after a network drop.
pub struct ResumptionClient<T>
where
    T: Protocol + 'static,
{
    stream: ChannelStream<ResumptionMessage, EncodedStream<T>>,
    sink: ChannelSink<ResumptionMessage>,
    handle: ResumptionHandle,
}

impl<T> ResumptionClient<T>
where
    T: Protocol + Send,
    T::Message: Send,
    T::SinkHalf: Send,
    T::StreamHalf: Send,
    T::Codec: Send,
{
    /// Creates a new [`ResumptionClient`] protocol instance.
    ///
    /// This function wraps the next protocol layer and sets up a background controller task
    /// to manage session IDs and resumption logic. It immediately sends a `GetId` request
    /// so that we are ready to resume later if needed.
    ///
    /// # Inputs
    ///
    /// * `next: T` - The next [`Protocol`] layer to be wrapped.
    pub fn new(next: T) -> Self {
        Self::new_with(next, rand::rng().next_u64())
    }

    // New with a specified id, to ease testing.
    fn new_with(next: T, id: u64) -> Self {
        let (stream, sink) = next.into_split();
        let stream = EncodedStream::new(stream, T::codec());
        let sink = Box::pin(DecodedSink::<T>::new(sink, T::codec()));

        let (sink_tx_ctrl, ctrl_rx_sink) = mpsc::channel(1);
        let (ctrl_tx_stream, stream_rx_ctrl) = mpsc::unbounded_channel();

        let (request_tx, request_rx) = mpsc::channel(5);

        // True means we can stream data immediately.
        let (stream_next_tx, stream_next_rx) = watch::channel(true);
        let _ = ctrl_tx_stream.send(ResumptionMessage::from(Command::Start(id)));
        let token = CancellationToken::new();

        let controller = Controller {
            rx: ctrl_rx_sink,
            tx: Some(ctrl_tx_stream),
            request_rx,
            stream_open: token.clone(),
            stream_next_tx,
            id,
            sink,
            sink_closed: false,
            pending_sink: VecDeque::new(),
            pending_resume: None,
        };

        controller.into_background();

        Self {
            stream: ChannelStream::new(stream_rx_ctrl, stream, Some(stream_next_rx), Some(token)),
            sink: ChannelSink::new(sink_tx_ctrl),
            handle: ResumptionHandle::new(request_tx),
        }
    }

    /// Returns a reference to the `ResumptionHandle` from which you can later initiate a resume request. The
    /// handle can be cheaply cloned
    ///   1. to persist it after dropping the client, and
    ///   2. to initiate session resumption after a disconnect.
    pub fn handle(&self) -> &ResumptionHandle {
        &self.handle
    }
}

impl<T: Protocol> Protocol for ResumptionClient<T> {
    type Message = ResumptionMessage;
    type Codec = ResumptionCodec;
    type StreamHalf = ChannelStream<ResumptionMessage, EncodedStream<T>>;
    type SinkHalf = ChannelSink<ResumptionMessage>;

    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
        (self.stream, self.sink)
    }

    fn codec() -> Self::Codec {
        ResumptionCodec::new()
    }
}

/// A cloneable handle to initiate session resumption from within other application components.
pub struct ResumptionHandle {
    // The outer sender is used to send a resume request to the background task.
    // The background task replies with the result using the inner sender.
    request_tx: mpsc::Sender<oneshot::Sender<Result<u64, ResponseError>>>,
    // The channel where we can async wait for the result.
    response_rx: Option<oneshot::Receiver<Result<u64, ResponseError>>>,
}

impl ResumptionHandle {
    fn new(request_tx: mpsc::Sender<oneshot::Sender<Result<u64, ResponseError>>>) -> Self {
        Self {
            request_tx,
            response_rx: None,
        }
    }

    /// Initiates a session resumption request to attempt to recover from a network error
    /// on the TCP connection to the server
    ///
    /// This sends a request to the background controller task, asking it to send a `Resume`
    /// command to the server. The response must be awaited separately via `resume_response`.
    ///
    /// # Inputs
    ///
    /// * `timeout: Option<Duration>` - An optional timeout for sending the request to the controller.
    ///
    /// # Returns
    ///
    /// * `Result<(), RequestError>` - Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// * `RequestError::ResponsePending` - If a previous request is still awaiting a response.
    /// * `RequestError::ChannelClosed` - If the background controller has terminated.
    /// * `RequestError::ChannelTimeout` - If the request times out.
    pub async fn resume_request(&mut self, timeout: Option<Duration>) -> Result<(), RequestError> {
        if self.response_rx.is_some() {
            return Err(RequestError::ResponsePending);
        }

        let (response_tx, response_rx) = oneshot::channel();
        let timeout_dur = timeout.unwrap_or(Duration::MAX);

        log::debug!("Sending resume request to server");

        // Send the resume request to the background task. The request
        // contains the response channel where they will send the result.
        let result = match self.request_tx.send_timeout(response_tx, timeout_dur).await {
            Ok(()) => {
                self.response_rx = Some(response_rx);
                Ok(())
            }
            Err(mpsc::error::SendTimeoutError::Closed(_)) => Err(RequestError::ChannelClosed),
            Err(mpsc::error::SendTimeoutError::Timeout(_)) => Err(RequestError::ChannelTimeout),
        };

        log::debug!("Resume request result {result:?}");
        result
    }

    /// Waits for the server's response to a `resume_request`.
    ///
    /// This should be called after `resume_request` succeeds. It waits for the background
    /// controller to receive a resumption response from the server.
    ///
    /// # Inputs
    ///
    /// * `timeout: Option<Duration>` - An optional timeout for awaiting the response.
    ///
    /// # Returns
    ///
    /// * `Result<u64, ResponseError>` - On success, returns `Ok(new_id)`.
    ///
    /// # Errors
    ///
    /// * `ResponseError::ChannelNotFound` - If `resume_request()` was not called first.
    /// * `ResponseError::ChannelClosed` - If the background controller or response channel closed unexpectedly.
    /// * `ResponseError::ChannelTimeout` - If the response was not received within the timeout.
    /// * `ResponseError::ResumeFailed` - If the server response was received and indicated that the resumption failed.
    pub async fn resume_response(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<u64, ResponseError> {
        let Some(response_rx) = self.response_rx.as_mut() else {
            return Err(ResponseError::ChannelNotFound);
        };

        let timeout_dur = timeout.unwrap_or(Duration::MAX);

        log::debug!("Waiting for resume response");

        let result = match tokio::time::timeout(timeout_dur, response_rx).await {
            Ok(recv_result) => match recv_result {
                Ok(resume_result) => resume_result,
                Err(_) => Err(ResponseError::ChannelClosed),
            },
            Err(_) => Err(ResponseError::ChannelTimeout),
        };

        log::debug!("Resume response result {result:?}");
        result
    }
}

impl Clone for ResumptionHandle {
    fn clone(&self) -> Self {
        Self {
            request_tx: self.request_tx.clone(),
            response_rx: None,
        }
    }
}

struct Controller<T: Protocol> {
    /// For incoming messages from the sink.
    rx: mpsc::Receiver<ChannelCommand<ResumptionMessage>>,
    /// For outgoing messages to the stream.
    /// The option is so we can drop it when we want to close.
    tx: Option<mpsc::UnboundedSender<ResumptionMessage>>,
    /// Resume handles ask us to initiate a resumption here.
    request_rx: mpsc::Receiver<oneshot::Sender<Result<u64, ResponseError>>>,
    /// Token that triggers when the next stream is no longer open.
    stream_open: CancellationToken,
    /// Bool to control if the stream calls poll_next or only waits on the channel.
    stream_next_tx: watch::Sender<bool>,
    id: u64,
    sink: Pin<Box<DecodedSink<T>>>,
    sink_closed: bool,
    pending_sink: VecDeque<Bytes>,
    pending_resume: Option<oneshot::Sender<Result<u64, ResponseError>>>,
}

#[derive(Debug, Eq, PartialEq, Clone)]
enum ControllerError {
    StreamSendFailed,
    StreamSenderDropped,
    SinkSendFailed,
    SinkFlushFailed,
    SinkCloseFailed,
}

impl<T> Controller<T>
where
    T: Protocol + Send + 'static,
    T::Message: Send,
    T::SinkHalf: Send,
    T::StreamHalf: Send,
    T::Codec: Send,
{
    fn into_background(self) {
        tokio::spawn(async move {
            let id = self.id;
            let result = self.run().await;
            log::debug!("Controller({id}) finished: {result:?}");
            result
        });
    }

    /// The main loop for the controller.
    async fn run(mut self) -> Result<(), ControllerError> {
        loop {
            log::trace!("Controller({:?}) select input", self.id);
            tokio::select! {
                biased;

                // Handle any incoming bytes for the next sink.
                result = async {
                    if let Some(chunk) = self.pending_sink.front() {
                        self.sink.send(chunk.clone()).await
                    } else {
                        std::future::pending().await
                    }
                }, if !self.pending_sink.is_empty() => {
                    log::trace!("Controller({:?}) selected sink_send: {result:?}", self.id);
                    result.map_err(|_| ControllerError::SinkSendFailed)?;
                    self.pending_sink.pop_front();
                }

                // Check if a client handle wants us to request the server to resume.
                result = self.request_rx.recv(),
                if !(self.request_rx.is_closed() && self.request_rx.is_empty()) => {
                    log::trace!("Controller({:?}) selected resume_recv: {:?}", self.id, result.as_ref().map(|_| ()));
                    if let Some(reply_tx) = result {
                        self.resume(reply_tx)?;
                    } else {
                        log::trace!("Controller({:?}) resume_recv disconnected", self.id);
                    }
                }

                // Check if we have an incoming message from our sink.
                result = self.rx.recv(),
                if !(self.rx.is_closed() && self.rx.is_empty())
                    && (self.pending_sink.is_empty() || self.pending_resume.is_some()) => {
                    log::trace!("Controller({:?}) selected sink_recv: {result:?}", self.id);
                    if let Some(cmd) = result {
                        self.process_cmd(cmd).await?;
                    } else {
                        log::trace!("Controller({:?}) sink_recv disconnected", self.id);
                    }
                }

                // Check if our outer stream is done.
                _ = self.stream_open.cancelled(),
                if self.tx.is_some() => {
                    // Drop the channel to close out the outer stream (and this branch).
                    self.tx.take();
                }

                // We are done if all branches are disabled.
                else => return Ok(())
            }
        }
    }

    fn send_stream(&mut self, cmd: Command) -> Result<(), ControllerError> {
        if let Some(sender) = self.tx.as_mut() {
            sender
                .send(ResumptionMessage::from(cmd))
                .map_err(|_| ControllerError::StreamSendFailed)
        } else {
            Err(ControllerError::StreamSenderDropped)
        }
    }

    fn set_stream_next(&mut self, new_val: bool) {
        self.stream_next_tx.send_if_modified(|cur_val| {
            if *cur_val != new_val {
                *cur_val = new_val;
                true // Changed, notify receivers.
            } else {
                false // Unchanged, do NOT notify receivers.
            }
        });
    }

    fn resume(
        &mut self,
        reply_tx: oneshot::Sender<Result<u64, ResponseError>>,
    ) -> Result<(), ControllerError> {
        // Stop sending payloads from the next stream until we synchronize the resume.
        self.set_stream_next(false);

        // Store the reply channel. Note, we drop an existing channel if one
        // exists. (Since the client requested this resume, we assume the
        // existing channel timed out and the client wants to retry.)
        self.pending_resume = Some(reply_tx);

        // Send a resume request to the server.
        self.send_stream(Command::Resume(self.id))
    }

    async fn flush_sink(&mut self) -> Result<(), ControllerError> {
        while let Some(chunk) = self.pending_sink.pop_front() {
            self.sink
                .send(chunk)
                .await
                .map_err(|_| ControllerError::SinkSendFailed)?;
        }
        self.sink
            .flush()
            .await
            .map_err(|_| ControllerError::SinkFlushFailed)
    }

    async fn close_sink(&mut self) -> Result<(), ControllerError> {
        let _ = self.flush_sink().await;
        self.sink_closed = true;
        self.sink
            .close()
            .await
            .map_err(|_| ControllerError::SinkCloseFailed)
    }

    async fn process_cmd(
        &mut self,
        cmd: ChannelCommand<ResumptionMessage>,
    ) -> Result<(), ControllerError> {
        match cmd {
            ChannelCommand::Message(msg) => self.process_msg(msg),
            ChannelCommand::ExplicitFlush => self.flush_sink().await,
            ChannelCommand::ExplicitClose => self.close_sink().await,
        }
    }

    fn process_msg(&mut self, msg: ResumptionMessage) -> Result<(), ControllerError> {
        // Client does not take action on some message types.
        match msg.command {
            Command::Start(_) => {}
            Command::Resume(_) => {}
            Command::ResumeOk(id) => {
                // We can start sending again.
                self.set_stream_next(true);

                // Mark ourselves as done resuming by taking the option.
                // Send reply, safely ignore if the receiver handle already dropped.
                if let Some(sender) = self.pending_resume.take() {
                    let _ = sender.send(Ok(id));
                }
            }
            Command::ResumeErr(_id) => {
                if let Some(sender) = self.pending_resume.take() {
                    let _ = sender.send(Err(ResponseError::ResumeFailed));
                }
            }
            Command::Forward(payload) => self.pending_sink.push_back(payload.chunk),
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use std::future::poll_fn;
    use std::io;
    use std::task::{Context, Poll, Waker};

    use bytes::Bytes;
    use futures::{FutureExt, SinkExt, StreamExt};
    use tokio::task::yield_now;
    use tokio_test::io::Builder;

    use crate::proto::resumption::ResumptionClient;
    use crate::proto::resumption::client::ResponseError;
    use crate::proto::resumption::message::{Command, ResumptionMessage};
    use crate::test::{TestCodec, TestIoProtocol};

    const ID: u64 = 1;

    fn encode_io(data: &'static str) -> Bytes {
        TestCodec::encode_str(data)
    }

    fn forward_msg(data: &'static str) -> ResumptionMessage {
        ResumptionMessage::from(Command::Forward(encode_io(data).into()))
    }

    async fn poll_next(
        client: &mut ResumptionClient<TestIoProtocol>,
    ) -> Poll<Option<ResumptionMessage>> {
        let mut fut = client.stream.next().boxed();
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = poll_fn(move |cx| fut.poll_unpin(cx));
        yield_now().await;
        f.poll_unpin(&mut cx)
    }

    #[tokio::test]
    async fn stream_data_before_id() {
        let io = Builder::new().read(b"a").read(b"b").read(b"c").build();
        let mut client = ResumptionClient::new(TestIoProtocol::from_mock(io));

        let msg = client.stream.next().await.unwrap();
        assert!(matches!(msg.command, Command::Start(_)));
        yield_now().await;

        // Can stream bytes BEFORE the id is set.
        for char in ["a", "b", "c"] {
            assert_eq!(client.stream.next().await, Some(encode_io(char).into()));
            yield_now().await;
        }
        // EOF.
        assert_eq!(client.stream.next().await, None);
    }

    #[tokio::test]
    async fn stream_data_after_id() {
        let io = Builder::new().read(b"a").read(b"b").read(b"c").build();
        let mut client = ResumptionClient::new(TestIoProtocol::from_mock(io));

        let msg = client.stream.next().await.unwrap();
        assert!(matches!(msg.command, Command::Start(_)));
        yield_now().await;

        // Can stream bytes since the id is set.
        for char in ["a", "b", "c"] {
            assert_eq!(client.stream.next().await, Some(encode_io(char).into()));
            yield_now().await;
        }
        // EOF.
        assert_eq!(client.stream.next().await, None);
    }

    #[tokio::test]
    async fn stream_data_after_sink_close() {
        let io = Builder::new().read(b"a").read(b"b").read(b"c").build();
        let mut client = ResumptionClient::new(TestIoProtocol::from_mock(io));

        let msg = client.stream.next().await.unwrap();
        assert!(matches!(msg.command, Command::Start(_)));
        yield_now().await;

        client.sink.close().await.unwrap();
        yield_now().await;

        // Can stream bytes AFTER the sink closed.
        for char in ["a", "b", "c"] {
            assert_eq!(client.stream.next().await, Some(encode_io(char).into()));
            yield_now().await;
        }
        // EOF.
        assert_eq!(client.stream.next().await, None);
    }

    #[tokio::test]
    async fn sink_data_before_id() {
        let io = Builder::new().write(b"a").write(b"b").write(b"c").build();
        let mut client = ResumptionClient::new(TestIoProtocol::from_mock(io));

        // Can sink bytes BEFORE the id is set.
        for char in ["a", "b", "c"] {
            assert!(client.sink.send(forward_msg(char)).await.is_ok());
            yield_now().await;
        }
    }

    #[tokio::test]
    async fn sink_data_after_id() {
        let io = Builder::new().write(b"a").write(b"b").write(b"c").build();
        let mut client = ResumptionClient::new(TestIoProtocol::from_mock(io));

        // Can sink bytes since the id is set.
        for char in ["a", "b", "c"] {
            assert!(client.sink.send(forward_msg(char)).await.is_ok());
            yield_now().await;
        }
    }

    #[tokio::test]
    async fn sink_data_after_stream_eof() {
        let io = Builder::new()
            .read_error(io::ErrorKind::UnexpectedEof.into())
            .write(b"a")
            .write(b"b")
            .write(b"c")
            .build();
        let mut client = ResumptionClient::new(TestIoProtocol::from_mock(io));

        // Stream always sends Start first.
        let msg = client.stream.next().await.unwrap();
        assert!(matches!(msg.command, Command::Start(_)));
        yield_now().await;

        // Now stream EOF.
        assert_eq!(client.stream.next().await, None);
        yield_now().await;

        // Can sink bytes AFTER stream EOF.
        for char in ["a", "b", "c"] {
            assert!(client.sink.send(forward_msg(char)).await.is_ok());
            yield_now().await;
        }
    }

    async fn resume_request_response(
        id: u64,
        simulate_resume_success: bool,
    ) -> (
        ResumptionClient<TestIoProtocol>,
        Poll<Result<u64, ResponseError>>,
    ) {
        let io = Builder::new().read(b"a").read(b"b").build();
        let proto = TestIoProtocol::from_mock(io);
        let mut client = ResumptionClient::new_with(proto, id);
        let mut handle = client.handle().clone();

        // Handshake to send the tunnel id.
        let msg = client.stream.next().await.unwrap();
        assert!(matches!(msg.command, Command::Start(_)));

        // The server does not respond.

        // Should be able to read a payload.
        assert_eq!(client.stream.next().await, Some(encode_io("a").into()));

        // Client should be able to later resume using the handle.
        assert_eq!(handle.resume_request(None).await, Ok(()));

        // The response won't be ready yet.
        let mut fut = handle.resume_response(None).boxed();
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = poll_fn(move |cx| fut.poll_unpin(cx));
        yield_now().await;
        assert_eq!(f.poll_unpin(&mut cx), Poll::Pending);

        // Client sends out a Resume command.
        let msg = client.stream.next().await.unwrap();
        assert_eq!(msg.command, Command::Resume(id));

        let response = if simulate_resume_success {
            Command::ResumeOk(id)
        } else {
            Command::ResumeErr(id)
        };

        // And gets the (simulated) server response.
        client.sink.send(response.into()).await.unwrap();

        // Now the handle should get a result.
        yield_now().await;
        let result = f.poll_unpin(&mut cx);
        (client, result)
    }

    #[tokio::test]
    async fn resume_request_response_ok() {
        // Simulate server success.
        let (mut client, result) = resume_request_response(ID, true).await;
        assert_eq!(result, Poll::Ready(Ok(ID)));

        // Should be able to read the last payload.
        assert_eq!(client.stream.next().await, Some(encode_io("b").into()));

        // Done now that all bytes are read.
        assert_eq!(client.stream.next().await, None);
    }

    #[tokio::test]
    async fn resume_request_response_err() {
        // Simulate server error.
        let (mut client, result) = resume_request_response(ID, false).await;
        assert_eq!(result, Poll::Ready(Err(ResponseError::ResumeFailed)));

        // Even though the resume failed, the stream does not close to allow us
        // to retry a resumption on a new connection. It will be pending.
        assert_eq!(poll_next(&mut client).await, Poll::Pending);
    }
}
