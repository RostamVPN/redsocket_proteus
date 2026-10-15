//! Message framing protocol module.
//!
//! Encapsulates discrete messages into a continuous byte stream, adding length
//! headers and optional padding to delimit individual frames.

use crate::Protocol;
use crate::util::{DecodedSink, EncodedStream};

mod codec;
mod message;
mod sink;
mod stream;

pub use codec::FramingCodec;
use message::FramingMessage;
use sink::FramingSink;
use stream::FramingStream;

/// The message framing protocol layer.
///
/// Converts a continuous byte stream into discrete, delimited messages.
pub struct Framing<T: Protocol> {
    stream: FramingStream<EncodedStream<T>>,
    sink: FramingSink<DecodedSink<T>>,
}

impl<T: Protocol> Framing<T> {
    /// Creates a new [`Framing`] protocol instance.
    ///
    /// This layer is responsible for adding a framing structure (length, checksums)
    /// to messages from the next protocol layer, making them suitable for transport
    /// over a byte-stream-oriented network.
    ///
    /// # Inputs
    ///
    /// * `next: T` - The next [`Protocol`] layer to be wrapped.
    pub fn new(next: T) -> Self {
        let (stream, sink) = next.into_split();
        Self {
            stream: FramingStream::new(EncodedStream::new(stream, T::codec())),
            sink: FramingSink::new(DecodedSink::new(sink, T::codec())),
        }
    }
}

impl<T: Protocol> Protocol for Framing<T> {
    type Message = FramingMessage;
    type Codec = FramingCodec;
    type StreamHalf = FramingStream<EncodedStream<T>>;
    type SinkHalf = FramingSink<DecodedSink<T>>;

    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
        (self.stream, self.sink)
    }

    fn codec() -> Self::Codec {
        FramingCodec::new()
    }
}

#[cfg(test)]
pub mod tests {
    use tokio_test::assert_ok;

    use crate::proto::framing::Framing;
    use crate::test::{TestIoProtocol, TestNetwork, TestPayload};

    #[tokio::test]
    async fn valid_io_flow() {
        for (c_io, s_io, len) in TestPayload::iter() {
            let client = Framing::new(TestIoProtocol::from_mock(c_io));
            let server = Framing::new(TestIoProtocol::from_mock(s_io));

            let network = TestNetwork::new(client, server);
            let (c_to_s_result, s_to_c_result) = network.run().await;

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }
}
