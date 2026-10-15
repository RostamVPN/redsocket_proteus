//! Application payload protocol module.
//!
//! Handles the transmission of application data streams by breaking them into
//! chunked messages that can be multiplexed over a single connection.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::net::{NetworkAddress, NetworkTarget};
use crate::{Protocol, SessionConnector};

mod codec;
mod message;
mod sink;
mod stream;

pub use codec::PayloadCodec;
use message::PayloadMessage;
use sink::PayloadSink;
use stream::PayloadStream;

/// A specialized [`Payload`] type alias configured specifically for TCP streams.
///
/// Simplifies the instantiation of the payload layer when wrapping standard TCP connections.
pub type TcpPayload = Payload<OwnedReadHalf, OwnedWriteHalf>;

/// The complete Payload protocol layer for a single session.
///
/// Combines a `PayloadStream` and `PayloadSink` to provide full-duplex data transfer.
pub struct Payload<R: AsyncRead, W: AsyncWrite> {
    stream: PayloadStream<R>,
    sink: PayloadSink<W>,
}

impl<R: AsyncRead, W: AsyncWrite> Payload<R, W> {
    /// Creates a new [`Payload`] protocol instance.
    ///
    /// This combines a `PayloadStream` and a `PayloadSink` to handle bidirectional
    /// payload data for a specific session.
    ///
    /// # Inputs
    ///
    /// * `id: u64` - The session identifier.
    /// * `src: R` - The source for reading data (e.g., a TCP stream half).
    /// * `dst: W` - The destination for writing data.
    /// * `parent_mss: usize` - The Maximum Segment Size from the parent protocol layer.
    pub fn new(id: u64, src: R, dst: W, parent_mss: usize) -> Self {
        Self {
            stream: PayloadStream::new(id, src, parent_mss),
            sink: PayloadSink::new(id, dst),
        }
    }
}

impl<R: AsyncRead, W: AsyncWrite> Protocol for Payload<R, W> {
    type Message = PayloadMessage;
    type Codec = PayloadCodec;
    type StreamHalf = PayloadStream<R>;
    type SinkHalf = PayloadSink<W>;

    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
        (self.stream, self.sink)
    }

    fn codec() -> Self::Codec {
        PayloadCodec::new()
    }
}

/// A factory for creating [`Payload`] instances over TCP streams.
///
/// Implements the [`SessionConnector`] trait for the server routing layer.
#[derive(Clone)]
pub struct TcpPayloadFactory {
    parent_mss: usize,
}

impl TcpPayloadFactory {
    /// Creates a new [`TcpPayloadFactory`].
    ///
    /// # Inputs
    ///
    /// * `parent_mss: usize` - The sessions that we create should create payload chunks using this mss value.
    pub fn new(parent_mss: usize) -> Self {
        Self { parent_mss }
    }
}

impl SessionConnector for TcpPayloadFactory {
    type Item = TcpPayload;

    fn connect(
        &self,
        id: u64,
        target: NetworkTarget,
    ) -> impl Future<Output = (u64, std::io::Result<Self::Item>)> + Send + 'static {
        // All data from self needs to be cloned so it doesn't move into the async block.
        let mss = self.parent_mss;
        async move {
            let result = match target.addr() {
                NetworkAddress::IpAddr(ip) => TcpStream::connect((ip, target.port())).await,
                NetworkAddress::Name(name) => TcpStream::connect((name, target.port())).await,
            };
            let result = result.map(|tcp_stream| {
                let (src, dst) = tcp_stream.into_split();
                Payload::new(id, src, dst, mss)
            });
            (id, result)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use tokio_test::assert_ok;

    use crate::FrameSize;
    use crate::proto::payload::Payload;
    use crate::proto::payload::codec::PayloadCodec;
    use crate::test::{TestNetwork, TestPayload};

    #[tokio::test]
    async fn valid_io_flow() {
        const SESSION_ID: u64 = 5;
        for (c_io, s_io, len) in TestPayload::iter() {
            let (c_r, c_w) = tokio::io::split(c_io);
            let client = Payload::new(SESSION_ID, c_r, c_w, PayloadCodec::mtu());

            let (s_r, s_w) = tokio::io::split(s_io);
            let server = Payload::new(SESSION_ID, s_r, s_w, PayloadCodec::mtu());

            let network = TestNetwork::new(client, server);
            let (c_to_s_result, s_to_c_result) = network.run().await;

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }
}
