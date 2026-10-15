//! Server-side session resumption.
//!
//! Maintains session state mappings and handles client requests to resume
//! previously established sessions after a network interruption.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::SinkExt;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::Protocol;
use crate::proto::resumption::message::Data;
use crate::proto::resumption::{Command, ResumptionCodec, ResumptionMessage};
use crate::sync::{ChannelCommand, ChannelSink, ChannelStream, SharedReplaceableStream};
use crate::util::{DecodedSink, EncodedStream};

/// A thread-safe registry of active, resumable client sessions.
///
/// Maps session IDs to their associated handles to facilitate state recovery.
pub struct ResumptionMap<T: Protocol> {
    inner: Arc<Mutex<HashMap<u64, ResumeHandle<T>>>>,
}

impl<T: Protocol> Default for ResumptionMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Protocol> ResumptionMap<T> {
    /// Creates a new, empty `ResumptionMap`.
    pub fn new() -> Self {
        Self::new_inner(HashMap::new())
    }

    fn new_inner(map: HashMap<u64, ResumeHandle<T>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(map)),
        }
    }

    /// Clears the map, removing all key-value pairs.
    pub async fn clear(&mut self) {
        self.inner.lock().await.clear();
    }
}

impl<T: Protocol> Clone for ResumptionMap<T> {
    fn clone(&self) -> Self {
        Self {
            // Increments the Arc ref count, does not deep copy the inner HashMap.
            inner: self.inner.clone(),
        }
    }
}

#[derive(Debug)]
struct ResumeHandle<T: Protocol> {
    /// Signal a running controller that I want to steal their state.
    /// The stolen state will be delivered through the inner channel.
    tx: mpsc::Sender<oneshot::Sender<State<T>>>,
}

/// The server-side protocol layer for managing session resumption.
///
/// Validates client resumption requests and re-links them to existing session states.
pub struct ResumptionServer<T>
where
    T: Protocol + 'static,
{
    stream: ChannelStream<ResumptionMessage, SharedReplaceableStream<EncodedStream<T>>>,
    sink: ChannelSink<ResumptionMessage>,
    resume_map: ResumptionMap<T>,
}

impl<T> ResumptionServer<T>
where
    T: Protocol + Send,
    T::Message: Send,
    T::SinkHalf: Send,
    T::StreamHalf: Send,
    T::Codec: Send,
{
    /// Creates a new `ResumptionServer` that forwards payloads to the next protocol `T`.
    pub fn new(next: T) -> Self {
        Self::new_with(next, ResumptionMap::new())
    }

    /// Creates a new `ResumptionServer` that shares an existing `ResumptionMap`.
    ///
    /// This is used when multiple server instances need to coordinate session resumption.
    ///
    /// # Inputs
    ///
    /// * `next: T` - The next `Protocol` layer to wrap.
    /// * `map: ResumptionMap<T>` - The shared map for storing session handles.
    pub fn new_with(next: T, map: ResumptionMap<T>) -> Self {
        let (resume_tx, resume_rx) = mpsc::channel(5);
        let handle = ResumeHandle { tx: resume_tx };

        let (stream, sink) = next.into_split();
        let stream = SharedReplaceableStream::new(EncodedStream::new(stream, T::codec()));
        let sink = Box::pin(DecodedSink::new(sink, T::codec()));

        let state = State {
            id: None,
            stream: stream.clone(),
            sink,
            sink_closed: false,
            pending_sink: VecDeque::new(),
            old_stream: None,
            old_sink: None,
        };

        let (sink_tx_ctrl, ctrl_rx_sink) = mpsc::channel(1);
        let (ctrl_tx_stream, stream_rx_ctrl) = mpsc::unbounded_channel();

        // False means wait until we get an id request before forwarding data.
        let (stream_next_tx, stream_next_rx) = watch::channel(false);
        let token = CancellationToken::new();

        let controller = Controller {
            rx: ctrl_rx_sink,
            tx: Some(ctrl_tx_stream),
            state,
            resume_rx,
            resume_handle: Some(handle),
            resume_map: map.clone(),
            stream_open: token.clone(),
            stream_next_tx,
        };

        controller.into_background();

        Self {
            stream: ChannelStream::new(stream_rx_ctrl, stream, Some(stream_next_rx), Some(token)),
            sink: ChannelSink::new(sink_tx_ctrl),
            resume_map: map,
        }
    }

    /// Returns a reference to the `ResumptionMap` used by this server.
    ///
    /// The map can be cloned and shared across multiple threaded connection
    /// handlers. It can be passed to new `ResumptionServer`s (using
    /// `new_with()`) that are created for every new incoming server connection,
    /// so that each server can resume from previous resumption state.
    pub fn handle(&self) -> &ResumptionMap<T> {
        &self.resume_map
    }
}

impl<T: Protocol> Protocol for ResumptionServer<T> {
    type Message = ResumptionMessage;
    type Codec = ResumptionCodec;
    type StreamHalf = ChannelStream<ResumptionMessage, SharedReplaceableStream<EncodedStream<T>>>;
    type SinkHalf = ChannelSink<ResumptionMessage>;

    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
        (self.stream, self.sink)
    }

    fn codec() -> Self::Codec {
        ResumptionCodec::new()
    }
}

struct Controller<T: Protocol> {
    /// For incoming messages from the sink.
    rx: mpsc::Receiver<ChannelCommand<ResumptionMessage>>,
    /// For outgoing messages to the stream.
    /// The option is so we can drop it when we want to close.
    tx: Option<mpsc::UnboundedSender<ResumptionMessage>>,
    /// Internal server state. When another controller initiates resumption, we
    /// send this to them and stop ourselves.
    state: State<T>,
    /// Resumption is requested here, we send our state to the inner channel.
    resume_rx: mpsc::Receiver<oneshot::Sender<State<T>>>,
    /// When I receive the id from the client, add this to the map to enable resumption.
    resume_handle: Option<ResumeHandle<T>>,
    /// I can communicate with other controllers here.
    resume_map: ResumptionMap<T>,
    /// Token that triggers when the next stream is no longer open.
    stream_open: CancellationToken,
    /// Bool to control if the stream calls poll_next or only waits on the channel.
    stream_next_tx: watch::Sender<bool>,
}

struct State<T: Protocol> {
    id: Option<u64>,
    stream: SharedReplaceableStream<EncodedStream<T>>,
    sink: Pin<Box<DecodedSink<T>>>,
    sink_closed: bool,
    pending_sink: VecDeque<Bytes>,
    old_stream: Option<Pin<Box<EncodedStream<T>>>>,
    old_sink: Option<Pin<Box<DecodedSink<T>>>>,
}

#[derive(Debug, Eq, PartialEq, Clone)]
enum ControllerError {
    StreamSendFailed,
    StreamSenderDropped,
    SinkSendFailed,
    SinkFlushFailed,
    SinkCloseFailed,
    ResumeServerChannelClosed,
    ResumeServerStateSendFailed,
    ResumeServerTimeout,
    ResumeClientMapTimeout,
    ResumeClientHandleNone,
    ResumeClientReplySendTimeout,
    ResumeClientReplyRecvTimeout,
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
            let result = self.run().await;
            log::debug!("Controller finished: {result:?}");
            result
        });
    }

    /// The main loop for the controller.
    async fn run(mut self) -> Result<(), ControllerError> {
        loop {
            let ready = *self.stream_next_tx.borrow();

            tokio::select! {
                // If we have ties, select in order from top to bottom.
                // This ensures we drain our buffers before taking in more work.
                biased;

                // Handle any incoming bytes for the next sink.
                result = async {
                    if let Some(chunk) = self.state.pending_sink.front() {
                        self.state.sink.send(chunk.clone()).await
                    } else {
                        std::future::pending().await
                    }
                }, if !self.state.sink_closed && ready && !self.state.pending_sink.is_empty() => {
                    if result.map_err(|_| ControllerError::SinkSendFailed).is_ok() {
                        self.state.pending_sink.pop_front();
                    } else {
                        self.state.sink_closed = true;
                    }
                }

                // Check if another controller wants to resume from our state.
                result = self.resume_rx.recv(),
                if !(self.resume_rx.is_closed() && self.resume_rx.is_empty()) => {
                    if let Some(reply_tx) = result {
                        return self.into_resumed(reply_tx);
                    }
                }

                // Check if we have an incoming message from our sink.
                // If we are not ready yet, we will buffer all sink data.
                // If we are ready, then we enforce a buf limit to provide backpressure.
                result = self.rx.recv(),
                if !(self.rx.is_closed() && self.rx.is_empty())
                    && (!ready || self.state.pending_sink.is_empty()) => {
                    if let Some(cmd) = result
                        && let Ok(Some(payload)) = self.process_cmd(cmd).await {
                        self.state.pending_sink.push_back(payload.chunk)
                    }
                }

                // Check if our internal stream is done.
                _ = self.stream_open.cancelled(),
                if self.tx.is_some() => {
                    // Drop the channel to close out the outer stream (and this branch).
                    self.tx.take();
                    self.state.old_stream = None;
                    self.state.old_sink = None;
                }

                // We are done if all branches are disabled.
                else => return Ok(())
            }

            // Could do it sync here, but this might block our receiving of a resume command.
            // if self.stream_next.load(Ordering::Acquire) {
            //     while let Some(chunk) = self.state.pending_sink.pop_front() {
            //         self.state
            //             .sink
            //             .send(chunk)
            //             .await
            //             .map_err(|_| ControllerError::SinkSendFailed)?;
            //     }
            // }

            if self.rx.is_closed()
                && self.rx.is_empty()
                && self.tx.is_none()
                && self.state.pending_sink.is_empty()
            {
                if self.state.sink_closed {
                    return Ok(());
                } else {
                    return self.into_wait_resume(Duration::from_secs(120)).await;
                }
            }
        }
    }

    async fn into_wait_resume(mut self, timeout: Duration) -> Result<(), ControllerError> {
        let future = async {
            match self.resume_rx.recv().await {
                Some(reply_tx) => self.into_resumed(reply_tx),
                None => Err(ControllerError::ResumeServerChannelClosed),
            }
        };

        // Run the future with a timeout.
        match tokio::time::timeout(timeout, future).await {
            Ok(result) => result,
            Err(_) => Err(ControllerError::ResumeServerTimeout),
        }
    }

    fn into_resumed(mut self, reply_tx: oneshot::Sender<State<T>>) -> Result<(), ControllerError> {
        // Make sure we don't lose any incoming messages in the channel. It
        // might be the case that we won't be able to send any potential replies
        // (if the network to the tunnel client went down), so we let the new
        // controller handle these.
        self.close_sink_channel();

        // The send channel is consumed when we send our state, so we end our
        // controller even if the send fails.
        log::trace!("Trying to send my state to controller reply channel");
        match reply_tx.send(self.state) {
            Ok(()) => {
                log::debug!("Successfully sent resume state to another controller");
                Ok(())
            }
            Err(_) => {
                log::debug!("Failed to send resume state to another controller");
                Err(ControllerError::ResumeServerStateSendFailed)
            }
        }
    }

    /// Close and then drain our channel to the sink.
    fn close_sink_channel(&mut self) {
        self.rx.close();
        // Use try_recv to avoid deadlocks caused by the sender side.
        while let Ok(cmd) = self.rx.try_recv() {
            if let ChannelCommand::Message(msg) = cmd
                && let Command::Forward(payload) = msg.command
            {
                self.state.pending_sink.push_back(payload.chunk);
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

    async fn flush_sink(&mut self) -> Result<(), ControllerError> {
        let ready = *self.stream_next_tx.borrow();
        while ready && let Some(chunk) = self.state.pending_sink.pop_front() {
            self.state
                .sink
                .send(chunk)
                .await
                .map_err(|_| ControllerError::SinkSendFailed)?;
        }
        self.state
            .sink
            .flush()
            .await
            .map_err(|_| ControllerError::SinkFlushFailed)
    }

    async fn close_sink(&mut self) -> Result<(), ControllerError> {
        let _ = self.flush_sink().await;
        self.state.sink_closed = true;
        self.state
            .sink
            .close()
            .await
            .map_err(|_| ControllerError::SinkCloseFailed)
    }

    async fn process_cmd(
        &mut self,
        cmd: ChannelCommand<ResumptionMessage>,
    ) -> Result<Option<Data>, ControllerError> {
        match cmd {
            ChannelCommand::Message(msg) => self.process_msg(msg).await,
            ChannelCommand::ExplicitFlush => self.flush_sink().await.map(|_| None),
            ChannelCommand::ExplicitClose => self.close_sink().await.map(|_| None),
        }
    }

    async fn process_msg(
        &mut self,
        msg: ResumptionMessage,
    ) -> Result<Option<Data>, ControllerError> {
        // Servers do not take action on some message types.
        match msg.command {
            Command::Start(id) => self.start_id(id).await?,
            Command::Resume(id) => self.resume_id(id).await?,
            Command::ResumeOk(_) => {}
            Command::ResumeErr(_) => {}
            Command::Forward(payload) => return Ok(Some(payload)),
        }
        Ok(None)
    }

    async fn start_id(&mut self, id: u64) -> Result<(), ControllerError> {
        // If they already send a Start command, this one is ignored.
        let Some(handle) = self.resume_handle.take() else {
            return Ok(());
        };

        self.set_stream_next(true);

        // Lock the shared map, but don't wait too long.
        let lock = tokio::time::timeout(Duration::from_secs(1), self.resume_map.inner.lock());
        let Ok(mut map) = lock.await else {
            return Ok(());
        };

        // In the unlikely event of a collision, we will be unable to resume later.
        if let Entry::Vacant(entry) = map.entry(id) {
            entry.insert(handle);
        }

        self.state.id = Some(id);

        Ok(())
    }

    async fn resume_id(&mut self, id: u64) -> Result<(), ControllerError> {
        match self.replace_and_resume(id).await {
            Ok(()) => self.send_resume_ok(id),
            Err(e) => {
                log::debug!("Resumption attempt failed: {e:?}");
                self.send_resume_err(id)
            }
        }
    }

    fn send_resume_err(&mut self, id: u64) -> Result<(), ControllerError> {
        self.send_stream(Command::ResumeErr(id))?;
        self.set_stream_next(false);
        Ok(())
    }

    fn send_resume_ok(&mut self, id: u64) -> Result<(), ControllerError> {
        self.send_stream(Command::ResumeOk(id))?;
        self.set_stream_next(true);
        Ok(())
    }

    async fn replace_and_resume(&mut self, id: u64) -> Result<(), ControllerError> {
        // Make sure our resume operations don't hang too long.
        log::debug!("Controller attempting to resume from {id}");

        // We will send our state through this channel.
        let (state_tx, state_rx) = oneshot::channel();

        // Stop accesses to the resume map during a resumption.
        let Ok(mut map) =
            tokio::time::timeout(Duration::from_secs(1), self.resume_map.inner.lock()).await
        else {
            return Err(ControllerError::ResumeClientMapTimeout);
        };

        // Look up the resume handle for the requested id.
        let Some(handle) = map.remove(&id) else {
            return Err(ControllerError::ResumeClientHandleNone);
        };

        // Send the oneshot sender to the other controller.
        let Ok(()) = handle
            .tx
            .send_timeout(state_tx, Duration::from_secs(1))
            .await
        else {
            map.insert(id, handle);
            return Err(ControllerError::ResumeClientReplySendTimeout);
        };

        // Wait for the other controller to send us its state.
        let Ok(Ok(prev_state)) = tokio::time::timeout(Duration::from_secs(3), state_rx).await
        else {
            map.insert(id, handle);
            return Err(ControllerError::ResumeClientReplyRecvTimeout);
        };

        log::debug!("Controller proceeding to resume from {id}");

        // Get the handle for our controller.
        let maybe_handle = self.resume_handle.take();

        // Replace our state with the previous.
        self.state.replace(prev_state, id).await;

        // Store our handle for the next resumption.
        if let Some(handle) = maybe_handle {
            map.insert(id, handle);
        }
        self.state.id = Some(id);

        Ok(())
    }
}

impl<T> State<T>
where
    T: Protocol + Send + 'static,
    T::Message: Send,
    T::SinkHalf: Send,
    T::StreamHalf: Send,
    T::Codec: Send,
{
    async fn replace(&mut self, mut src: Self, id: u64) {
        // Replace the stream.
        log::trace!("Controller {id} replacing stream");
        let my_old_stream = match src.stream.take_inner().await {
            Some(prev) => {
                // Make our stream use their stream instead.
                self.stream.replace_inner(prev).await
            }
            None => {
                // Make our stream None too.
                self.stream.take_inner().await
            }
        };
        log::trace!("Controller {id} stream is replaced");

        // Replace the sink. The sink is not shared.
        log::trace!("Controller {id} replacing sink");
        let my_old_sink = std::mem::replace(&mut self.sink, src.sink);
        log::trace!("Controller {id} sink is replaced");

        // Keep any bytes for the next layer.
        for chunk in src.pending_sink {
            self.pending_sink.push_back(chunk);
        }

        // Adopt the previous id.
        log::trace!("Controller {id} is replaced");

        // Clean up the old stream and sink in the background to break a
        // deadlock with the controller that sent us the state.
        // tokio::task::spawn(async move {
        //     tokio::time::sleep(Duration::from_secs(5)).await;
        //     drop(my_old_sink);
        //     drop(my_old_stream);
        // })
        // Hold these until our own state is dropped later.
        self.old_stream = my_old_stream;
        self.old_sink = Some(my_old_sink);
    }
}

#[cfg(test)]
pub mod tests {
    use std::future::poll_fn;
    use std::io;
    use std::task::{Context, Poll, Waker};

    use bytes::Bytes;
    use futures::{FutureExt, SinkExt, StreamExt};
    use rand::Rng;
    use tokio::task::yield_now;
    use tokio_test::io::Builder;

    use crate::proto::resumption::message::{Command, ResumptionMessage};
    use crate::proto::resumption::{ResumptionMap, ResumptionServer};
    use crate::test::{TestCodec, TestIoProtocol};

    fn encode_io(data: &'static str) -> Bytes {
        TestCodec::encode_str(data)
    }

    fn forward_msg(data: &'static str) -> ResumptionMessage {
        ResumptionMessage::from(Command::Forward(encode_io(data).into()))
    }

    async fn poll_next(
        server: &mut ResumptionServer<TestIoProtocol>,
    ) -> Poll<Option<ResumptionMessage>> {
        let mut fut = server.stream.next().boxed();
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = poll_fn(move |cx| fut.poll_unpin(cx));
        yield_now().await;
        f.poll_unpin(&mut cx)
    }

    async fn assert_handshake(server: &mut ResumptionServer<TestIoProtocol>) -> u64 {
        // Client sends id in a Start message
        let id = rand::rng().next_u64();
        assert!(server.sink.send(Command::Start(id).into()).await.is_ok());

        yield_now().await;

        // The server does not send a handshake reply.
        id
    }

    #[tokio::test]
    async fn replace() {
        // let _ = env_logger::try_init();

        // Server a reads 'a' bytes.
        let io_a = Builder::new().read(b"a").read(b"a").build();
        let proto_a = TestIoProtocol::from_mock(io_a);
        let mut srv_a = ResumptionServer::new(proto_a);

        // Handshake first, get the tunnel id from the first server.
        let id_a: u64 = 123456789;
        srv_a.sink.send(Command::Start(id_a).into()).await.unwrap();
        yield_now().await;

        // Payload is available now.
        assert_eq!(srv_a.stream.next().await, Some(encode_io("a").into()));

        // Use the same resumption lookup map.
        let map = srv_a.handle().clone();

        // Server b reads 'b' bytes.
        let io_b = Builder::new().read(b"b").read(b"b").build();
        let proto_b = TestIoProtocol::from_mock(io_b);
        let mut srv_b = ResumptionServer::new_with(proto_b, map);

        // Tell the second server we want to steal the other server state.
        srv_b.sink.send(Command::Resume(id_a).into()).await.unwrap();
        yield_now().await;
        let msg = srv_b.stream.next().await.unwrap();
        let Command::ResumeOk(id_b) = msg.command else {
            unreachable!()
        };
        assert_eq!(id_a, id_b);

        // Server a state was stolen, so it should be dead.
        assert!(srv_a.stream.next().await.is_none());
        assert!(srv_a.sink.send(Command::Start(123).into()).await.is_err());

        // Server b now has server a state, so when we read we get 'a' bytes.
        assert_eq!(
            srv_b.stream.next().await,
            Some(ResumptionMessage::from(encode_io("a")))
        );
        // Server b is done when it read all the bytes.
        assert!(srv_b.stream.next().await.is_none());
    }

    #[tokio::test]
    async fn stream_data_before_handshake() {
        let io = Builder::new().read(b"a").read(b"b").read(b"c").build();
        let mut server = ResumptionServer::new(TestIoProtocol::from_mock(io));

        // We should not get data before GetId.
        for _ in 0..3 {
            assert_eq!(poll_next(&mut server).await, Poll::Pending);
        }
    }

    #[tokio::test]
    async fn stream_data_after_handshake() {
        let io = Builder::new().read(b"a").read(b"b").read(b"c").build();
        let mut server = ResumptionServer::new(TestIoProtocol::from_mock(io));

        assert_handshake(&mut server).await;

        // Now we should get data.
        for char in ["a", "b", "c"] {
            assert_eq!(
                poll_next(&mut server).await,
                Poll::Ready(Some(forward_msg(char)))
            );
        }
    }

    #[tokio::test]
    async fn stream_data_after_sink_close() {
        let io = Builder::new().read(b"a").read(b"b").read(b"c").build();
        let mut server = ResumptionServer::new(TestIoProtocol::from_mock(io));

        assert_handshake(&mut server).await;

        server.sink.close().await.unwrap();
        yield_now().await;

        // Can stream bytes AFTER the sink closed.
        for char in ["a", "b", "c"] {
            assert_eq!(
                poll_next(&mut server).await,
                Poll::Ready(Some(forward_msg(char)))
            );
        }

        // EOF.
        assert_eq!(server.stream.next().await, None);
    }

    #[tokio::test]
    async fn sink_data_before_handshake() {
        let io = Builder::new().write(b"a").write(b"b").write(b"c").build();
        let mut server = ResumptionServer::new(TestIoProtocol::from_mock(io));

        // Can sink bytes BEFORE the handshake.
        for char in ["a", "b", "c"] {
            assert!(server.sink.send(forward_msg(char)).await.is_ok());
            yield_now().await;
        }

        assert_handshake(&mut server).await;
    }

    #[tokio::test]
    async fn sink_data_after_handshake() {
        let io = Builder::new().write(b"a").write(b"b").write(b"c").build();
        let mut server = ResumptionServer::new(TestIoProtocol::from_mock(io));

        assert_handshake(&mut server).await;

        // Can sink bytes AFTER the handshake.
        for char in ["a", "b", "c"] {
            assert!(server.sink.send(forward_msg(char)).await.is_ok());
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
        let mut server = ResumptionServer::new(TestIoProtocol::from_mock(io));

        assert_handshake(&mut server).await;

        // Now stream EOF.
        assert_eq!(server.stream.next().await, None);
        yield_now().await;

        // Can sink bytes AFTER stream EOF.
        for char in ["a", "b", "c"] {
            assert!(server.sink.send(forward_msg(char)).await.is_ok());
            yield_now().await;
        }
    }

    async fn server_init() -> (
        ResumptionMap<TestIoProtocol>,
        ResumptionServer<TestIoProtocol>,
        u64,
    ) {
        let io = Builder::new().read(b"a").read(b"b").build();
        let proto = TestIoProtocol::from_mock(io);
        let mut server = ResumptionServer::new(proto);
        let handle = server.handle().clone();

        // Handshake then server returns first byte.
        let id = assert_handshake(&mut server).await;
        assert_eq!(server.stream.next().await, Some(forward_msg("a")));

        (handle, server, id)
    }

    async fn server_resume(
        handle: ResumptionMap<TestIoProtocol>,
        id: u64,
    ) -> ResumptionServer<TestIoProtocol> {
        let io = Builder::new().build();
        let proto = TestIoProtocol::from_mock(io);
        let mut server = ResumptionServer::new_with(proto, handle);

        // On the server, we ask to resume the previous.
        let resume_msg = ResumptionMessage::new(Command::Resume(id));
        assert!(server.sink.send(resume_msg).await.is_ok());

        server
    }

    async fn assert_resume_success(mut server: ResumptionServer<TestIoProtocol>) {
        // Resume should have succeeded.
        assert!(matches!(
            server.stream.next().await,
            Some(ResumptionMessage {
                command: Command::ResumeOk(_id),
            })
        ));

        // Server gets the second byte and then EOF.
        assert_eq!(server.stream.next().await, Some(forward_msg("b")));
        assert_eq!(server.stream.next().await, None);
    }

    #[tokio::test]
    async fn resume_request_response_ok() {
        let (map, mut server, id) = server_init().await;
        let server2 = server_resume(map.clone(), id).await;

        // Server2 resume should have succeeded.
        assert_resume_success(server2).await;

        // Original server is done.
        assert_eq!(server.stream.next().await, None);
    }

    #[tokio::test]
    async fn resume_request_response_err() {
        let (map, _, id) = server_init().await;
        let mut server2 = server_resume(map.clone(), id + 1).await;

        // Server2 resume should have failed.
        assert!(matches!(
            server2.stream.next().await,
            Some(ResumptionMessage {
                command: Command::ResumeErr(_id),
            })
        ));
    }

    #[tokio::test]
    async fn resume_request_response_retry() {
        let (map, mut server, id) = server_init().await;

        // Do a failed resume attempt.
        let mut server2 = server_resume(map.clone(), id + 1).await;
        assert!(matches!(
            server2.stream.next().await,
            Some(ResumptionMessage {
                command: Command::ResumeErr(_id),
            })
        ));

        // Retry should succeed.
        let server3 = server_resume(map.clone(), id).await;
        assert_resume_success(server3).await;
        assert_eq!(server.stream.next().await, None);
    }

    #[tokio::test]
    async fn resume_with_data_first() {
        let (map, mut server, id) = server_init().await;

        let io = Builder::new().build();
        let proto = TestIoProtocol::from_mock(io);
        let mut server2 = ResumptionServer::new_with(proto, map);

        // Send some data before the resume.
        for char in ["a", "b", "c"] {
            assert!(server2.sink.send(forward_msg(char)).await.is_ok());
        }

        // The resume arrives after the data.
        let resume_msg = ResumptionMessage::new(Command::Resume(id));
        assert!(server2.sink.send(resume_msg).await.is_ok());

        // Should still succeed.
        assert_resume_success(server2).await;
        assert_eq!(server.stream.next().await, None);
    }
}
