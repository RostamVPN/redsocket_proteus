//! Client-side connection routing.
//!
//! Manages multiplexed session lifecycle, requesting the server to open
//! new connections to specific network targets on behalf of the client.

use std::collections::HashMap;
use std::time::Duration;

use futures::SinkExt;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::net::NetworkTarget;
use crate::proto::routing::message::Data;
use crate::proto::routing::{Command, RoutingCodec, RoutingMessage};
use crate::sync::{ChannelCommand, ChannelSink, ChannelStream, SharedStream};
use crate::util::{DemuxedDecodedSink, EndMethod, MuxedEncodedStream};
use crate::{Identify, Protocol};

type SessionId = u64;

#[derive(Debug, Eq, PartialEq, Clone)]
/// Errors that can occur when managing routed multiplexed sessions.
pub enum RoutingError {
    /// The provided session ID is invalid, unrecognized, or already active.
    InvalidSessionId,
    /// The internal communication channel to the routing controller was unexpectedly closed.
    ChannelClosed,
    /// The operation timed out while waiting for a response from the controller or server.
    ChannelTimeout,
    /// The remote server failed to establish a connection to the requested target.
    ServerConnectFailed,
}

/// The client-side routing protocol manager.
///
/// Multiplexes multiple logical network sessions over a single underlying transport connection.
pub struct RoutingClient<T>
where
    T: Protocol + 'static,
    T::Message: Identify,
{
    stream: ChannelStream<RoutingMessage, SharedStream<MuxedEncodedStream<T>>>,
    sink: ChannelSink<RoutingMessage>,
    handle: RoutingHandle<T>,
}

impl<T> RoutingClient<T>
where
    T: Protocol + Send,
    T::Message: Identify + Send,
    T::SinkHalf: Send,
    T::StreamHalf: Identify + Send,
    T::Codec: Send,
{
    /// Creates a new `RoutingClient` instance.
    ///
    /// It initializes the multiplexed stream, demultiplexed sink, and a background controller
    /// task to manage session routing and lifecycle.
    pub fn new() -> Self {
        let streams = SharedStream::new(MuxedEncodedStream::new(T::codec()));
        let sinks = DemuxedDecodedSink::new(T::codec());

        let (sink_tx_ctrl, ctrl_rx_sink) = mpsc::channel(1);
        let (ctrl_tx_stream, stream_rx_ctrl) = mpsc::unbounded_channel();

        let (request_tx, request_rx) = mpsc::channel(100);
        let token = CancellationToken::new();

        let controller = Controller {
            rx: ctrl_rx_sink,
            tx: Some(ctrl_tx_stream),
            request_rx,
            stream_token: token.clone(),
            streams: streams.clone(),
            sinks,
            connecting: HashMap::new(),
        };

        controller.into_background();

        Self {
            stream: ChannelStream::new(stream_rx_ctrl, streams, None, Some(token)),
            sink: ChannelSink::new(sink_tx_ctrl),
            handle: RoutingHandle::new(request_tx),
        }
    }

    /// Returns a reference to a `RoutingHandle` from which you can later initiate requests. The
    /// handle can be cheaply cloned to
    ///   1. persist it after dropping the client, and
    ///   2. to manage sessions (connect, add, remove) from different parts of the application.
    pub fn handle(&self) -> &RoutingHandle<T> {
        &self.handle
    }
}

impl<T> Default for RoutingClient<T>
where
    T: Protocol + Send,
    T::Message: Identify + Send,
    T::SinkHalf: Send,
    T::StreamHalf: Identify + Send,
    T::Codec: Send,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Protocol> Protocol for RoutingClient<T>
where
    T::Message: Identify,
    T::StreamHalf: Identify,
{
    type Message = RoutingMessage;
    type Codec = RoutingCodec;
    type StreamHalf = ChannelStream<RoutingMessage, SharedStream<MuxedEncodedStream<T>>>;
    type SinkHalf = ChannelSink<RoutingMessage>;

    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
        (self.stream, self.sink)
    }

    fn codec() -> Self::Codec {
        RoutingCodec::new()
    }
}

type ResponseTx<T> = oneshot::Sender<Result<T, RoutingError>>;
type ResponseRx<T> = oneshot::Receiver<Result<T, RoutingError>>;

enum Request<T: Protocol>
where
    T::Message: Identify,
{
    IsEmpty(ResponseTx<bool>),
    SetEndMethod((EndMethod, ResponseTx<()>)),
    ConnectSession((NetworkTarget, ResponseTx<SessionId>)),
    AddSession((SessionId, T, ResponseTx<()>)),
    RemoveSession((SessionId, ResponseTx<bool>)),
}

/// A cheaply cloneable handle used to command the routing client.
///
/// Allows the application to dynamically add, connect, or remove multiplexed sessions.
pub struct RoutingHandle<T: Protocol>
where
    T::Message: Identify,
{
    // The outer sender is used to send a request to the background task.
    // The background task replies with the result using the inner sender.
    request_tx: mpsc::Sender<Request<T>>,
}

impl<T: Protocol> RoutingHandle<T>
where
    T::Message: Identify,
{
    fn new(request_tx: mpsc::Sender<Request<T>>) -> Self {
        Self { request_tx }
    }

    async fn run_task<U>(
        &mut self,
        request_args: Request<T>,
        response_rx: ResponseRx<U>,
        timeout: Option<Duration>,
    ) -> Result<U, RoutingError> {
        // Send the request to the background task. The request contains the
        // response channel sender where they will send the result.
        // Group the send and receive operations in a single future.
        let future = async {
            if self.request_tx.send(request_args).await.is_err() {
                return Err(RoutingError::ChannelClosed);
            }
            match response_rx.await {
                Ok(response_result) => response_result,
                Err(_) => Err(RoutingError::ChannelClosed),
            }
        };

        // Run the future with a timeout.
        let timeout_dur = timeout.unwrap_or(Duration::MAX);
        match tokio::time::timeout(timeout_dur, future).await {
            Ok(result) => result,
            Err(_) => Err(RoutingError::ChannelTimeout),
        }
    }

    /// Checks if the router is managing any active sessions.
    ///
    /// # Returns
    ///
    /// * `Result<bool, RoutingError>` - `Ok(true)` if there are no active or connecting sessions.
    pub async fn is_empty(&mut self) -> Result<bool, RoutingError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request_args = Request::IsEmpty(response_tx);
        self.run_task(request_args, response_rx, None).await
    }

    /// Sets the behavior for when the router should terminate.
    ///
    /// # Inputs
    ///
    /// * `end_method: EndMethod` - The desired termination behavior (e.g., `EndMethod::Empty` to close when all sessions are done).
    pub async fn set_end_method(&mut self, end_method: EndMethod) -> Result<(), RoutingError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request_args = Request::SetEndMethod((end_method, response_tx));
        self.run_task(request_args, response_rx, None).await
    }

    /// Requests the server to establish a new session to a target address.
    ///
    /// This sends a `Connect` command to the server. The server will attempt to connect
    /// to the target and respond with `ConnectOk` or `ConnectErr`.
    ///
    /// # Inputs
    ///
    /// * `target: NetworkTarget` - The destination address for the new session.
    /// * `timeout: Option<Duration>` - An optional timeout for the entire operation (including the
    ///   server-side DNS lookup and connection establishment).
    ///
    /// # Returns
    ///
    /// * `Result<SessionId, RoutingError>` - On success, returns a new `SessionId` for the new session.
    ///   The session is considered pending (no data will be forwarded) until `add_session()` is called.
    ///
    /// # Errors
    ///
    /// * `RoutingError::ServerConnectFailed` - If the server could not connect to the target.
    /// * `RoutingError::ChannelClosed` - If the communication channel with the controller is closed.
    /// * `RoutingError::ChannelTimeout` - If the task did not complete within the specified timeout.
    pub async fn connect_session(
        &mut self,
        target: NetworkTarget,
        timeout: Option<Duration>,
    ) -> Result<SessionId, RoutingError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request_args = Request::ConnectSession((target, response_tx));
        self.run_task(request_args, response_rx, timeout).await
    }

    /// Associates the local application I/O object with the session
    /// that was previously successfully connected via `connect_session()`.
    ///
    /// After `connect_session()` succeeds, this function associates a local protocol instance
    /// (like `TcpPayload`) with the `SessionId`. It sends an `Add` command to the server
    /// to move the session from a pending to an active state.
    ///
    /// # Inputs
    ///
    /// * `sid: SessionId` - The ID of the session returned by `connect_session()`.
    /// * `client_io: T` - The local protocol instance that will handle I/O for this session.
    ///
    /// # Errors
    ///
    /// * `RoutingError::InvalidSessionId` - If the session ID is not recognized or is already active.
    /// * `RoutingError::ChannelClosed` - If the communication channel with the controller is closed.
    pub async fn add_session(&mut self, sid: SessionId, client_io: T) -> Result<(), RoutingError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request_args = Request::AddSession((sid, client_io, response_tx));
        self.run_task(request_args, response_rx, None).await
    }
}

impl<T: Protocol> RoutingHandle<T>
where
    T::Message: Identify,
    T::StreamHalf: Identify,
{
    /// Removes a session from the router.
    ///
    /// This function removes the session from both the local stream/sink multiplexers and
    /// sends a `Remove` command to the server to tear down the remote end.
    ///
    /// # Inputs
    ///
    /// * `sid: SessionId` - The ID of the session to remove.
    ///
    /// # Returns
    ///
    /// * `Result<bool, RoutingError>` - `Ok(true)` if the session was found and removed.
    pub async fn remove_session(&mut self, sid: SessionId) -> Result<bool, RoutingError> {
        let (response_tx, response_rx) = oneshot::channel();
        let request_args = Request::RemoveSession((sid, response_tx));
        self.run_task(request_args, response_rx, None).await
    }
}

impl<T: Protocol> Clone for RoutingHandle<T>
where
    T::Message: Identify,
{
    fn clone(&self) -> Self {
        Self {
            request_tx: self.request_tx.clone(),
        }
    }
}

pub struct Controller<T>
where
    T: Protocol,
    T::Message: Identify,
{
    /// For incoming messages from the outer router sink.
    rx: mpsc::Receiver<ChannelCommand<RoutingMessage>>,
    /// For outgoing messages to the outer router stream.
    /// The option is so we can drop it when we want to close writing.
    tx: Option<mpsc::UnboundedSender<RoutingMessage>>,
    /// Client routing handles request actions here.
    request_rx: mpsc::Receiver<Request<T>>,
    /// Token that triggers when the outer router stream closes.
    stream_token: CancellationToken,
    /// The inner stream side of the internal router.
    streams: SharedStream<MuxedEncodedStream<T>>,
    /// The inner sink side of the internal router.
    sinks: DemuxedDecodedSink<T>,
    /// In-progress connection requests, waiting for server response.
    connecting: HashMap<SessionId, oneshot::Sender<Result<SessionId, RoutingError>>>,
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
    T::Message: Identify + Send,
    T::SinkHalf: Send,
    T::StreamHalf: Identify + Send,
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
            tokio::select! {
                // Check if we have an incoming message from our sink.
                result = self.rx.recv(), if !(self.rx.is_closed() && self.rx.is_empty()) => {
                    if let Some(cmd) = result {
                        // Exit if we have data for the sink but sending it failed.
                        if let Some(payload) = self.process_cmd(cmd).await? {
                            self.send_sink(payload).await?;
                        }
                    } else {
                        // We cannot accept any more data, tell the server to
                        // stop reading and then sending it to us.
                        let _ = self.send_stream(Command::ShutRead);
                    }
                }

                // Check if we have an incoming request from any client handles.
                result = self.request_rx.recv(), if !(self.request_rx.is_closed() && self.request_rx.is_empty()) => {
                    if let Some(request) = result {
                        self.process_request(request).await;
                    }
                }

                // Check if our internal router stream is done.
                _ = self.stream_token.cancelled(), if self.tx.is_some() => {
                    // Tell the server we are done writing.
                    let _ = self.send_stream(Command::ShutWrite);
                    // Drop the channel to close out the outer stream (and this branch).
                    self.tx.take();
                }

                // All branches are inactive.
                else => return Ok(())
            }
        }
    }

    fn send_stream(&mut self, cmd: Command) -> Result<(), ControllerError> {
        if let Some(sender) = self.tx.as_mut() {
            sender
                .send(RoutingMessage::from(cmd))
                .map_err(|_| ControllerError::StreamSendFailed)
        } else {
            Err(ControllerError::StreamSenderDropped)
        }
    }

    async fn send_sink(&mut self, payload: Data) -> Result<(), ControllerError> {
        self.sinks
            .send(payload.chunk)
            .await
            .map_err(|_| ControllerError::SinkSendFailed)
    }

    async fn flush_sink(&mut self) -> Result<(), ControllerError> {
        self.sinks
            .flush()
            .await
            .map_err(|_| ControllerError::SinkFlushFailed)
    }

    async fn close_sink(&mut self) -> Result<(), ControllerError> {
        self.sinks
            .close()
            .await
            .map_err(|_| ControllerError::SinkCloseFailed)
    }

    async fn process_cmd(
        &mut self,
        cmd: ChannelCommand<RoutingMessage>,
    ) -> Result<Option<Data>, ControllerError> {
        match cmd {
            ChannelCommand::Message(msg) => Ok(self.process_msg(msg).await),
            ChannelCommand::ExplicitFlush => self.flush_sink().await.map(|_| None),
            ChannelCommand::ExplicitClose => self.close_sink().await.map(|_| None),
        }
    }

    async fn process_msg(&mut self, msg: RoutingMessage) -> Option<Data> {
        // Clients do not take action on some message types.
        match msg.command {
            Command::Connect(_) => {}
            Command::ConnectOk(sid) => {
                // Done connecting now. Safely ignore if the client handle was dropped.
                if let Some(resp_tx) = self.connecting.remove(&sid) {
                    let _ = resp_tx.send(Ok(sid));
                }
            }
            Command::ConnectErr(sid) => {
                // Done connecting now. Safely ignore if the client handle was dropped.
                if let Some(resp_tx) = self.connecting.remove(&sid) {
                    let _ = resp_tx.send(Err(RoutingError::ServerConnectFailed));
                }
            }
            Command::Add(_) => {}
            Command::Remove(sid) => {
                self.sinks.remove(&sid);
                self.streams.lock().await.remove(&sid);
            }
            Command::Forward(payload) => return Some(payload),
            Command::ShutRead => {
                // The peer cannot write any more payload data, so we should
                // stop sending it to them.
                let mut streams = self.streams.lock().await;
                streams.clear();
                streams.set_end_method(EndMethod::Now);
            }
            Command::ShutWrite => {
                // The peer reached EOF, it will send us no more payload data.
                // Thus, we have no more data to send our sinks, so close them.
                let _ = self.sinks.close().await;
            }
        }
        None
    }

    async fn process_request(&mut self, args: Request<T>) {
        match args {
            Request::IsEmpty(resp_tx) => {
                let sink_empty = self.sinks.is_empty();
                let stream_empty = self.streams.lock().await.is_empty();
                let _ = resp_tx.send(Ok(sink_empty && stream_empty));
            }
            Request::SetEndMethod((method, resp_tx)) => {
                self.streams.lock().await.set_end_method(method);
                let _ = resp_tx.send(Ok(()));
            }
            Request::ConnectSession((target, resp_tx)) => {
                // Reserve a free session id for the new session.
                let sid: SessionId = self.sinks.reserve_id();

                // If there is a pending connector at sid, tell the server to
                // cancel it. Otherwise, tell the server side to establish a
                // session by connecting to target. (The order of ops is
                // important here.)
                if (self.connecting.contains_key(&sid)
                    && self.send_stream(Command::Remove(sid)).is_err())
                    || self.send_stream(Command::Connect((sid, target))).is_err()
                {
                    self.sinks.remove(&sid);
                    let _ = resp_tx.send(Err(RoutingError::ChannelClosed));
                    return;
                }

                // Store the response channel so we can reply later.
                self.connecting.insert(sid, resp_tx);
            }
            Request::AddSession((sid, client_io, resp_tx)) => {
                let (stream, sink) = client_io.into_split();

                if self.sinks.try_add_with_reserved_id(sink, sid).is_err() {
                    let _ = resp_tx.send(Err(RoutingError::InvalidSessionId));
                } else {
                    // Tell the server the pending session is now starting.
                    if self.send_stream(Command::Add(sid)).is_ok() {
                        self.streams.lock().await.add(stream);
                        let _ = resp_tx.send(Ok(()));
                    } else {
                        let _ = resp_tx.send(Err(RoutingError::ChannelClosed));
                    }
                }
            }
            Request::RemoveSession((sid, resp_tx)) => {
                let sink_removed = self.sinks.remove(&sid);
                let stream_removed = self.streams.lock().await.remove(&sid);
                if self.send_stream(Command::Remove(sid)).is_ok() {
                    let _ = resp_tx.send(Ok(stream_removed && sink_removed));
                } else {
                    let _ = resp_tx.send(Err(RoutingError::ChannelClosed));
                }
            }
        }
    }
}
