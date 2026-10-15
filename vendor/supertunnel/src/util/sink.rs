use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt};
use pin_project_lite::pin_project;
use tokio_util::codec::Decoder;

use crate::Protocol;

pin_project! {
    /// A sink wrapper that applies a codec to decode incoming items before passing them forward.
    ///
    /// Takes byte chunks from a producer through the [`Sink`] interface, which are
    /// then encoded into messages and sent to the given sink.
    pub struct DecodedSink<T: Protocol> {
        #[pin]
        sink: T::SinkHalf,
        decoder: T::Codec,
    }
}

impl<T: Protocol> DecodedSink<T> {
    /// Creates a new [`DecodedSink`].
    ///
    /// # Inputs
    ///
    /// * `sink: T::SinkHalf` - The destination sink for decoded protocol messages.
    /// * `decoder: T::Codec` - The codec used to decode bytes into messages.
    pub fn new(sink: T::SinkHalf, decoder: T::Codec) -> Self {
        Self { sink, decoder }
    }

    /// Consumes the [`DecodedSink`], returning the underlying message sink.
    pub fn into_inner(self) -> T::SinkHalf {
        self.sink
    }
}

impl<T: Protocol> Sink<Bytes> for DecodedSink<T> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_ready_unpin(cx).map_err(Into::into)
    }

    fn start_send(self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let mut this = self.project();
        match this.decoder.decode(&mut BytesMut::from(bytes)) {
            Ok(Some(msg)) => this.sink.start_send_unpin(msg).map_err(Into::into),
            Ok(None) => Err(io::ErrorKind::InvalidData.into()),
            Err(e) => Err(e.into()),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_flush_unpin(cx).map_err(Into::into)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_close_unpin(cx).map_err(Into::into)
    }
}
