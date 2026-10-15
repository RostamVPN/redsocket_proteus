use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use pin_project_lite::pin_project;

use crate::proto::framing::FramingMessage;

pin_project! {
    /// A `Stream` of `FramingMessage`s that takes payload bytes from the next layer protocol `T`
    /// and wraps them into new frame messages.
    pub struct FramingStream<T: Stream<Item = Bytes>> {
        #[pin]
        stream: T,
    }
}

impl<T: Stream<Item = Bytes>> FramingStream<T> {
    /// Creates a new `FramingStream`.
    ///
    /// It wraps an underlying stream of byte chunks and converts each chunk into a `FramingMessage`.
    ///
    /// # Inputs
    ///
    /// * `stream: T` - The underlying stream that provides byte chunks.
    pub fn new(stream: T) -> Self {
        Self { stream }
    }
}

impl<T: Stream<Item = Bytes>> Stream for FramingStream<T> {
    type Item = FramingMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.project().stream.poll_next_unpin(cx) {
            Poll::Ready(Some(data)) => Poll::Ready(Some(FramingMessage::new_data(data))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
