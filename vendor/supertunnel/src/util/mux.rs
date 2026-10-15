//! Stream Multiplexing.
//!
//! Provides utilities for combining multiple asynchronous data streams into
//! a single unified stream of messages.

use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};

use bytes::{Bytes, BytesMut};
use futures::stream::SelectAll;
use futures::{Stream, StreamExt};
use pin_project_lite::pin_project;
use tokio_util::codec::Encoder;

use crate::{Identify, Protocol};

pin_project! {
    /// A multiplexer that combines multiple independent message streams into one unified encoded stream.
    ///
    /// Consumes messages from the given stream and encodes them into byte chunks,
    /// which are then streamed to a consumer through the [`Stream`] interface.
    pub struct MuxedEncodedStream<T: Protocol>
    where
        T::Message: Identify
    {
        #[pin]
        streams: SelectAll<Pin<Box<T::StreamHalf>>>,
        encoder: T::Codec,
        waker: Option<Waker>,
        end_method: EndMethod
    }
}

/// Defines the termination condition for multiplexed components.
///
/// For example, components might terminate immediately, or after all sessions close.
#[derive(Debug)]
pub enum EndMethod {
    None,
    Now,
    Empty,
}

impl<T: Protocol> MuxedEncodedStream<T>
where
    T::Message: Identify,
{
    /// Creates a new, empty [`MuxedEncodedStream`].
    ///
    /// # Inputs
    ///
    /// * `encoder: T::Codec` - The codec used to encode messages from all contained streams.
    pub fn new(encoder: T::Codec) -> Self {
        Self {
            streams: SelectAll::new(),
            encoder,
            waker: None,
            end_method: EndMethod::None,
        }
    }

    /// Adds a new stream to the multiplexer.
    ///
    /// # Inputs
    ///
    /// * `stream: T::StreamHalf` - The stream to add to the [`SelectAll`] set.
    pub fn add(&mut self, stream: T::StreamHalf) {
        self.streams.push(Box::pin(stream));
        // Wake up in case the stream is ready.
        self.wake();
    }

    /// Returns the number of streams currently in the multiplexer.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Returns `true` if there are no streams in the multiplexer.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Removes all streams from the multiplexer.
    pub fn clear(&mut self) {
        self.streams.clear();
    }

    /// Defines the condition under which the multiplexed stream should terminate (return `None`).
    ///
    /// # Inputs
    ///
    /// * `end_method: EndMethod` - The termination condition (e.g., close when empty).
    pub fn set_end_method(&mut self, end_method: EndMethod) {
        self.end_method = end_method;
        // Wake up in case the end method is triggered.
        self.wake();
    }

    /// Store the latest waker so we can wake any pending tasks when async changes occur.
    fn set_waker(&mut self, cx: &mut Context) {
        match self.waker.as_mut() {
            Some(w) => w.clone_from(cx.waker()),
            None => self.waker = Some(cx.waker().clone()),
        }
    }

    /// Notify any waiting wakers that pending stream activity has now occurred.
    fn wake(&self) {
        // Wake the waker if one exists, without dropping our handle.
        if let Some(w) = self.waker.as_ref() {
            w.wake_by_ref()
        }
        // Instead, we could wake the waker and drop the handle to prevent multiple wake-ups.
        // self.waker.take().map(|w| w.wake());
    }
}

impl<T: Protocol> MuxedEncodedStream<T>
where
    T::Message: Identify,
    T::StreamHalf: Identify,
{
    /// Removes a stream from the multiplexer by its ID.
    ///
    /// # Inputs
    ///
    /// * `id: &u64` - The ID of the stream to remove.
    ///
    /// # Returns
    ///
    /// * `bool` - `true` if a stream with the given ID was found and removed.
    pub fn remove(&mut self, id: &u64) -> bool {
        let old_streams = std::mem::replace(&mut self.streams, SelectAll::new());
        let mut removed = false;

        for stream in old_streams.into_iter() {
            if &stream.id() == id {
                removed = true;
            } else {
                self.streams.push(stream);
            }
        }

        removed
    }
}

impl<T: Protocol> Stream for MuxedEncodedStream<T>
where
    T::Message: Identify,
{
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // Store the waker in case a new stream arrives while we are in a Pending state.
        self.set_waker(cx);

        if let EndMethod::Now = self.end_method {
            return Poll::Ready(None);
        }

        // Process the next message that is ready.
        // If all streams are pending, a wakeup should occur later.
        match ready!(self.streams.poll_next_unpin(cx)) {
            // A message is ready.
            Some(msg) => {
                let mut buf = BytesMut::new();
                match self.encoder.encode(msg, &mut buf) {
                    Ok(()) => Poll::Ready(Some(buf.freeze())),
                    Err(_) => Poll::Ready(None),
                }
            }
            // All streams are done; a wakeup will occur inside `add()`.
            None => match self.end_method {
                EndMethod::None => Poll::Pending,
                EndMethod::Now => Poll::Ready(None),
                EndMethod::Empty => Poll::Ready(None),
            },
        }
    }
}
