use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::Stream;
use pin_project_lite::pin_project;

use crate::proto::reliability::{ReliabilityMessage, SharedReliabilityState};

pin_project! {
    /// An asynchronous stream that outputs reliability messages.
    ///
    /// Interacts with the `SharedReliabilityState` to messages for streaming.
    pub struct ReliabilityStream<T: Stream<Item = Bytes>> {
        #[pin]
        stream: T,
        state: SharedReliabilityState,
        buffer: Option<Poll<Option<Bytes>>>,
    }
}

impl<T: Stream<Item = Bytes>> ReliabilityStream<T> {
    /// Creates a new `ReliabilityStream`.
    ///
    /// # Inputs
    ///
    /// * `stream: T` - The underlying stream that provides byte chunks from the next protocol layer.
    /// * `state: SharedReliabilityState` - The shared state manager for the reliability protocol.
    pub fn new(stream: T, state: SharedReliabilityState) -> Self {
        Self {
            stream,
            state,
            buffer: None,
        }
    }
}

impl<T: Stream<Item = Bytes>> Stream for ReliabilityStream<T> {
    type Item = ReliabilityMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = self.project();

        // Get the possibly available payload for the next message.
        // Importantly, if the buffered result is Pending, try poll_next again.
        let next_payload = match this.buffer.take() {
            Some(Poll::Ready(result)) => Poll::Ready(result),
            // Can be Some(Poll::Pending) or None.
            _ => this.stream.poll_next(cx),
        };

        // The state module returns the payload if it is not consumed.
        let (result, next_buffer) = this.state.poll_recv(cx, next_payload);

        *this.buffer = next_buffer;
        result
    }
}
