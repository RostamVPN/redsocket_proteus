use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::{Sink, SinkExt};
use pin_project_lite::pin_project;

use crate::proto::framing::FramingMessage;

pin_project! {
    /// A [`Sink`] for `FramingMessage`s that forwards payload bytes to the next layer protocol `T`.
    ///
    /// Removes length headers and optional padding before passing to the next protocol layer.
    pub struct FramingSink<T: Sink<Bytes>>
    where
        T::Error: Into<io::Error>
    {
        #[pin]
        sink: T
    }
}

impl<T: Sink<Bytes>> FramingSink<T>
where
    T::Error: Into<io::Error>,
{
    /// Creates a new `FramingSink`.
    ///
    /// It wraps an underlying sink and forwards the `data` part of each `FramingMessage` to it.
    ///
    /// # Inputs
    ///
    /// * `sink: T` - The underlying sink that consumes byte chunks.
    pub fn new(sink: T) -> Self {
        Self { sink }
    }
}

impl<T: Sink<Bytes>> Sink<FramingMessage> for FramingSink<T>
where
    T::Error: Into<io::Error>,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_ready_unpin(cx).map_err(Into::into)
    }

    fn start_send(self: Pin<&mut Self>, msg: FramingMessage) -> Result<(), Self::Error> {
        if msg.data.is_empty() {
            // Drop empty or padding-only frame messages.
            Ok(())
        } else {
            self.project()
                .sink
                .start_send_unpin(msg.data)
                .map_err(Into::into)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_flush_unpin(cx).map_err(Into::into)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_close_unpin(cx).map_err(Into::into)
    }
}
