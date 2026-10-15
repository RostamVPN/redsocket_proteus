//! Server-side connection routing.
//!
//! Processes routing commands from the client, establishing actual outbound
//! network connections and linking them to multiplexed sessions.

use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;

use futures::stream::FuturesUnordered;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::proto::routing::message::Data;
use crate::proto::routing::{Command, RoutingCodec, RoutingMessage};
use crate::sync::{ChannelCommand, ChannelSink, ChannelStream, SharedStream};
use crate::util::{DemuxedDecodedSink, EndMethod, MuxedEncodedStream};
use crate::{Identify, Protocol, SessionConnector};

/// The server-side routing protocol manager.
///
/// Receives connection requests from the client, establishes outbound
/// connections to specified targets, and demultiplexes messages from the client.
pub struct RoutingServer<P, S>
where
    P: Protocol + 'static,
    P::Message: Identify,
    S: SessionConnector<Item = P> + 'static,
{
    stream: ChannelStream<RoutingMessage, SharedStream<MuxedEncodedStream<P>>>,
    sink: ChannelSink<RoutingMessage>,
    _connector: PhantomData<S>,
}

impl<P, S> RoutingServer<P, S>
where
    P: Protocol + Send,
    P::Message: Identify + Send,
    P::SinkHalf: Send,
    P::StreamHalf: Identify + Send,
    P::Codec: Send,
    S: SessionConnector<Item = P> + Send,
{
    /// Creates a new `RoutingServer` instance.
    ///
    /// It sets up the necessary stream/sink multiplexers and spawns a background controller
    /// to handle session management based on commands from the client.
    ///
    /// # Inputs
    ///
    /// * `connector: S` - A `SessionConnector` that the server will use to establish
    ///   outbound connections on behalf of the client (e.g., `TcpPayloadFactory`).
    pub async fn new(connector: S) -> Self {
        let streams = SharedStream::new(MuxedEncodedStream::new(P::codec()));
        let sinks = DemuxedDecodedSink::new(P::codec());

        let (sink_tx_ctrl, ctrl_rx_sink) = mpsc::channel(1);
        let (ctrl_tx_stream, stream_rx_ctrl) = mpsc::unbounded_channel();

        let token = CancellationToken::new();

        let controller = Controller {
            rx: ctrl_rx_sink,
            tx: Some(ctrl_tx_stream),
            stream_token: token.clone(),
            streams: streams.clone(),
            sinks,
            connector,
            connecting: FuturesUnordered::new(),
            pending: HashMap::new(),
        };

        controller.into_background();

        Self {
            stream: ChannelStream::new(stream_rx_ctrl, streams, None, Some(token)),
            sink: ChannelSink::new(sink_tx_ctrl),
            _connector: PhantomData,
        }
    }
}

impl<P, S> Protocol for RoutingServer<P, S>
where
    P: Protocol,
    P::Message: Identify,
    S: SessionConnector<Item = P>,
{
    type Message = RoutingMessage;
    type Codec = RoutingCodec;
    type StreamHalf = ChannelStream<RoutingMessage, SharedStream<MuxedEncodedStream<P>>>;
    type SinkHalf = ChannelSink<RoutingMessage>;

    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
        (self.stream, self.sink)
    }

    fn codec() -> Self::Codec {
        RoutingCodec::new()
    }
}

type BoxedConnectFut<P> = Box<dyn Future<Output = (u64, io::Result<P>)> + Send>;

pub struct Controller<P, S>
where
    P: Protocol,
    P::Message: Identify,
    S: SessionConnector<Item = P>,
{
    /// For incoming messages from the outer router sink.
    rx: mpsc::Receiver<ChannelCommand<RoutingMessage>>,
    /// For outgoing messages to the outer router stream.
    /// The option is so we can drop it when we want to close writing.
    tx: Option<mpsc::UnboundedSender<RoutingMessage>>,
    /// Token that triggers when the outer router stream closes.
    stream_token: CancellationToken,
    /// The inner stream side of the internal router.
    streams: SharedStream<MuxedEncodedStream<P>>,
    /// The inner sink side of the internal router.
    sinks: DemuxedDecodedSink<P>,
    /// For handling connection attempts.
    connector: S,
    /// In-progress connection attempts.
    connecting: FuturesUnordered<Pin<BoxedConnectFut<P>>>,
    /// In-progress sessions not added to the internal router yet.
    pending: HashMap<u64, PendingSession<P>>,
}

#[derive(Debug, Eq, PartialEq, Clone)]
enum ControllerError {
    StreamSendFailed,
    StreamSenderDropped,
    SinkSendFailed,
    SinkFlushFailed,
    SinkCloseFailed,
}

enum PendingSession<P: Protocol> {
    Connecting,
    Connected(P),
}

impl<P, S> Controller<P, S>
where
    P: Protocol + Send + 'static,
    P::Message: Identify + Send,
    P::SinkHalf: Send,
    P::StreamHalf: Identify + Send,
    P::Codec: Send,
    S: SessionConnector<Item = P> + Send + 'static,
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

                // Check if our internal router stream is done.
                _ = self.stream_token.cancelled(), if self.tx.is_some() => {
                    // Tell the server we are done writing.
                    let _ = self.send_stream(Command::ShutWrite);
                    // Drop the channel to close out the outer stream (and this branch).
                    self.tx.take();
                }

                // Check if any of our pending connections are ready.
                result = self.connecting.next(), if !self.connecting.is_empty() => {
                    if let Some(res) = result {
                        // If sending a connect response failed, and the stream
                        // and sink is closed, don't wait for other connections.
                        if let Err(e) = self.process_connect_result(res)
                            && self.tx.is_none() && self.rx.is_closed() && self.rx.is_empty() {
                            return Err(e);
                        }
                    }
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
        return self
            .sinks
            .send(payload.chunk)
            .await
            .map_err(|_| ControllerError::SinkSendFailed);
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
            ChannelCommand::Message(msg) => self.process_msg(msg).await,
            ChannelCommand::ExplicitFlush => self.flush_sink().await.map(|_| None),
            ChannelCommand::ExplicitClose => self.close_sink().await.map(|_| None),
        }
    }

    async fn process_msg(&mut self, msg: RoutingMessage) -> Result<Option<Data>, ControllerError> {
        // Servers do not take action on some message types.
        match msg.command {
            Command::Connect((sid, target)) => {
                let connect_fut = self.connector.connect(sid, target);
                self.connecting.push(Box::pin(connect_fut));
                self.pending.insert(sid, PendingSession::Connecting);
            }
            Command::ConnectOk(_) => {}
            Command::ConnectErr(_) => {}
            Command::Add(sid) => {
                // Add a connected session into the stream and sink aggregators.
                if let Some(pending) = self.pending.remove(&sid)
                    && let PendingSession::Connected(session) = pending
                    && self.sinks.try_reserve_id(sid)
                {
                    let (stream, sink) = session.into_split();
                    if self.sinks.try_add_with_reserved_id(sink, sid).is_ok() {
                        // Success.
                        self.streams.lock().await.add(stream);
                        return Ok(None);
                    } else {
                        // Remove that id we just reserved.
                        let _ = self.sinks.remove(&sid);
                    }
                }
                // Anything other than adding both the sink and stream.
                self.send_stream(Command::Remove(sid))?;
            }
            Command::Remove(sid) => {
                self.pending.remove(&sid);
                self.sinks.remove(&sid);
                self.streams.lock().await.remove(&sid);
            }
            Command::Forward(payload) => return Ok(Some(payload)),
            Command::ShutRead => {
                // The peer cannot write any more payload data, so we should
                // stop sending it to them.
                let mut streams = self.streams.lock().await;
                streams.clear();
                streams.set_end_method(EndMethod::Now);
            }
            Command::ShutWrite => {
                // The peer reached EOF and will stop sending us messages. We
                // expect no new streams. When our current streams end, we can
                // issue our EOF too.
                self.streams.lock().await.set_end_method(EndMethod::Empty);
                // We'll get no more payloads, so we can close our sinks.
                let _ = self.sinks.close().await;
            }
        }
        Ok(None)
    }

    fn process_connect_result(
        &mut self,
        result: (u64, Result<P, io::Error>),
    ) -> Result<(), ControllerError> {
        let (sid, conn_result) = result;

        if let Ok(session) = conn_result
            && let Some(pending) = self.pending.get_mut(&sid)
            && let PendingSession::Connecting = pending
        {
            *pending = PendingSession::Connected(session);
            self.send_stream(Command::ConnectOk(sid))
        } else {
            self.send_stream(Command::ConnectErr(sid))
        }
    }
}
