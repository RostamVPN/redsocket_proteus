use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use pin_project_lite::pin_project;
use tokio_util::codec::Encoder;

use crate::Protocol;

pin_project! {
    /// A stream wrapper that applies a codec to outgoing items before transmission.
    ///
    /// Consumes messages from the given stream and encodes them into byte chunks,
    /// which are then streamed to a consumer through the [`Stream`] interface.
    pub struct EncodedStream<T: Protocol> {
        #[pin]
        stream: T::StreamHalf,
        encoder: T::Codec,
    }
}

impl<T: Protocol> EncodedStream<T> {
    /// Creates a new [`EncodedStream`].
    ///
    /// # Inputs
    ///
    /// * `stream: T::StreamHalf` - The source stream of protocol messages.
    /// * `encoder: T::Codec` - The codec used to encode messages into bytes.
    pub fn new(stream: T::StreamHalf, encoder: T::Codec) -> Self {
        Self { stream, encoder }
    }

    /// Consumes the [`EncodedStream`], returning the underlying message stream.
    pub fn into_inner(self) -> T::StreamHalf {
        self.stream
    }
}

impl<T: Protocol> Stream for EncodedStream<T> {
    type Item = Bytes;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        match this.stream.poll_next_unpin(cx) {
            Poll::Ready(Some(msg)) => {
                let mut buf = BytesMut::new();
                match this.encoder.encode(msg, &mut buf) {
                    Ok(()) => Poll::Ready(Some(buf.freeze())),
                    Err(_) => Poll::Ready(None),
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
