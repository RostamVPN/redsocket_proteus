use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use futures::StreamExt;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::codec::Encoder;

use crate::Protocol;

pin_project! {
    /// An adapter that implements [`AsyncRead`] by pulling messages from a Stream and encoding them into bytes.
    ///
    // Uses a Codec to encode the messages taken from the inner Stream into bytes
    // that are given to the caller through the [`AsyncRead`] interface.
    pub struct EncodedStreamReader<T: Protocol> {
        #[pin]
        stream: Option<T::StreamHalf>,
        encoder: T::Codec,
        buffer: BytesMut,
    }
}

impl<T: Protocol> EncodedStreamReader<T> {
    /// Creates a new [`EncodedStreamReader`].
    ///
    /// # Inputs
    ///
    /// * `stream: T::StreamHalf` - The source stream of protocol messages.
    /// * `encoder: T::Codec` - The codec to encode messages into bytes for the [`AsyncRead`] interface.
    pub fn new(stream: T::StreamHalf, encoder: T::Codec) -> Self {
        Self {
            stream: Some(stream),
            encoder,
            buffer: BytesMut::new(),
        }
    }

    /// Consumes the reader, returning the underlying message stream.
    pub fn into_inner(self) -> Option<T::StreamHalf> {
        self.stream
    }

    /// Clears the internal buffer of the reader.
    ///
    /// This is useful to discard any partially encoded but unsent data, for example,
    /// after a network connection is broken and needs to be resumed.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl<T: Protocol> AsyncRead for EncodedStreamReader<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // If we already have enough cached bytes to fill the ReadBuf, return quickly.
        if this.buffer.len() >= buf.remaining() {
            let at = buf.remaining();
            let bytes = this.buffer.split_to(at).freeze();
            buf.put_slice(&bytes);
            return Poll::Ready(Ok(()));
        }

        // Read as many messages as needed to fill the ReadBuf if we can.
        while let Some(mut stream) = this.stream.as_mut().as_pin_mut()
            && this.buffer.len() < buf.remaining()
        {
            match stream.poll_next_unpin(cx) {
                Poll::Ready(Some(msg)) => {
                    // Buffer the message for sending.
                    let result = this.encoder.encode(msg, this.buffer);
                    // Panics if the payload inside the message is larger than supported
                    // by the codec, which can be considered a programming error.
                    result.map_err(Into::into).unwrap()
                }
                Poll::Ready(None) => this.stream.set(None), // Stream is done, drop it.
                Poll::Pending => break,                     // Stream will reactivate later.
            }
        }

        if !this.buffer.is_empty() {
            // We may or may not be able to fill the ReadBuf, but we provide what we have.
            let at = this.buffer.len().min(buf.remaining());
            let bytes = this.buffer.split_to(at).freeze();
            buf.put_slice(&bytes);
            Poll::Ready(Ok(()))
        } else if this.stream.is_none() {
            // Stream is done, this is an EOF since we did not add to the ReadBuf.
            Poll::Ready(Ok(()))
        } else {
            // Stream will reactivate later.
            Poll::Pending
        }
    }
}
