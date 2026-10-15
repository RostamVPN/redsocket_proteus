//! Basic reliability protocol.
//!
//! Implements a reliable transport mechanism over unreliable channels using
//! sequence numbers, acknowledgments, and retransmissions. If implements a
//! variant of the Go-Back-N sliding window automatic repeat request (ARQ) protocol.

use std::sync::Arc;

use crate::Protocol;
use crate::util::{DecodedSink, EncodedStream};

mod codec;
mod message;
mod sink;
mod state;
mod stream;

pub use codec::ReliabilityCodec;
use futures::channel::oneshot;
use message::{Command, Data, DataCursor, ReliabilityMessage};
use sink::ReliabilitySink;
use state::SharedReliabilityState;
use stream::ReliabilityStream;
use tokio::sync::Mutex;

/// The Basic reliability protocol layer.
///
/// Wraps an unreliable transport layer to provide ordered, guaranteed delivery of data chunks.
pub struct Reliability<T: Protocol> {
    stream: ReliabilityStream<EncodedStream<T>>,
    sink: ReliabilitySink<DecodedSink<T>>,
    handle: ReliabilityHandle,
}

impl<T: Protocol> Reliability<T> {
    /// Creates a new `Reliability` protocol instance.
    ///
    /// It wraps the next protocol layer (`next`) and provides a reliable transport
    /// mechanism over it by managing sequence numbers, acknowledgments, and retransmissions.
    ///
    /// # Inputs
    ///
    /// * `next: T` - The next `Protocol` layer to wrap.
    pub fn new(next: T) -> Self {
        let (stream, sink) = next.into_split();

        let (tx, rx) = oneshot::channel();
        let state = SharedReliabilityState::new(Some(rx));

        Self {
            stream: ReliabilityStream::new(EncodedStream::new(stream, T::codec()), state.clone()),
            sink: ReliabilitySink::new(DecodedSink::new(sink, T::codec()), state.clone()),
            handle: ReliabilityHandle::new(tx),
        }
    }

    /// Returns a reference to a `ReliabilityHandle` which can be cheaply cloned
    /// and used to query the inner reliability state (e.g., to check if a
    /// graceful shutdown has been completed).
    pub fn handle(&self) -> &ReliabilityHandle {
        &self.handle
    }
}

impl<T: Protocol> Protocol for Reliability<T> {
    type Message = ReliabilityMessage;
    type Codec = ReliabilityCodec;
    type StreamHalf = ReliabilityStream<EncodedStream<T>>;
    type SinkHalf = ReliabilitySink<DecodedSink<T>>;

    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
        (self.stream, self.sink)
    }

    fn codec() -> Self::Codec {
        ReliabilityCodec::new()
    }
}

/// A cheaply cloneable handle used to query the inner reliability state.
///
/// Allows the application to dynamically check if the reliability protocol has
/// completed a graceful shutdown.
#[derive(Clone)]
pub struct ReliabilityHandle {
    // We are using a channel here because it allows us to transfer the receiver
    // across stacks during resumption such that the sender in the handle is
    // linked to the resumed version of the reliability protocol rather than the
    // temporary empty one.
    inner: Arc<Mutex<oneshot::Sender<()>>>,
}

impl ReliabilityHandle {
    fn new(tx: oneshot::Sender<()>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(tx)),
        }
    }

    /// Returns `true` if the reliability protocol has completed a graceful shutdown.
    pub async fn is_shutdown_complete(&mut self) -> bool {
        let done = { self.inner.lock().await.is_canceled() };
        log::trace!("Reliability protocol shutdown complete: {done}");
        done
    }
}

#[cfg(test)]
pub mod tests {
    use tokio_test::assert_ok;

    use crate::proto::reliability::Reliability;
    use crate::test::{TestIoProtocol, TestNetwork, TestPayload};

    #[tokio::test]
    async fn valid_io_flow() {
        // let _ = env_logger::try_init();
        for (c_io, s_io, len) in TestPayload::iter() {
            let client = Reliability::new(TestIoProtocol::from_mock(c_io));
            let server = Reliability::new(TestIoProtocol::from_mock(s_io));

            let mut c_handle = client.handle().clone();
            let mut s_handle = server.handle().clone();

            let network = TestNetwork::new(client, server);
            let (c_to_s_result, s_to_c_result) = network.run().await;

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
            assert!(c_handle.is_shutdown_complete().await);
            assert!(s_handle.is_shutdown_complete().await);
        }
    }
}
