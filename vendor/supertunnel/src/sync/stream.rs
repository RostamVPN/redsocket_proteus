//! Synchronization tools for managing shared streams.
//!
//! Provides thread-safe, shared wrappers around asynchronous streams, enabling
//! concurrent access and dynamic replacement of underlying sources.

use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use pin_project_lite::pin_project;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tokio_util::sync::CancellationToken;

use crate::sync::PollMutex;

pin_project! {
    /// A thread-safe, pollable wrapper around an asynchronous stream.
    ///
    /// Allows concurrent tasks to safely pull items from a single source stream.
    pub struct SharedStream<T: Stream> {
        #[pin]
        stream: PollMutex<Pin<Box<T>>>,
    }
}

impl<T: Stream> SharedStream<T> {
    /// Creates a new [`SharedStream`] by wrapping a stream in a [`PollMutex`].
    ///
    /// # Inputs
    ///
    /// * `stream: T` - The stream to be shared.
    pub fn new(stream: T) -> Self {
        Self {
            stream: PollMutex::new(Box::pin(stream)),
        }
    }
}

impl<T: Stream> Stream for SharedStream<T> {
    type Item = T::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut locked_stream = ready!(self.project().stream.poll_lock(cx));
        locked_stream.poll_next_unpin(cx)
    }
}

impl<T: Stream> Clone for SharedStream<T> {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.clone(),
        }
    }
}

impl<T: Stream> Deref for SharedStream<T> {
    type Target = PollMutex<Pin<Box<T>>>;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<T: Stream> DerefMut for SharedStream<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

pin_project! {
    /// A shared stream wrapper that allows the underlying stream to be hot-swapped at runtime.
    pub struct SharedReplaceableStream<T: Stream> {
        stream: PollMutex<Option<Pin<Box<T>>>>,
    }
}

impl<T: Stream> SharedReplaceableStream<T> {
    /// Creates a new [`SharedReplaceableStream`] by wrapping a stream in a [`PollMutex`].
    ///
    /// # Inputs
    ///
    /// * `stream: T` - The stream to be shared.
    pub fn new(stream: T) -> Self {
        Self {
            stream: PollMutex::new(Some(Box::pin(stream))),
        }
    }

    /// Asynchronously takes the inner stream out of the [`SharedReplaceableStream`], leaving [`None`] in its place.
    ///
    /// # Returns
    ///
    /// * `Option<Pin<Box<T>>>` - The inner stream, if it existed.
    pub async fn take_inner(&mut self) -> Option<Pin<Box<T>>> {
        self.stream.lock().await.take()
    }

    /// Asynchronously replaces the inner stream with a new one.
    ///
    /// # Inputs
    ///
    /// * `value: Pin<Box<T>>` - The new stream to insert.
    ///
    /// # Returns
    ///
    /// * `Option<Pin<Box<T>>>` - The old stream that was replaced.
    pub async fn replace_inner(&mut self, value: Pin<Box<T>>) -> Option<Pin<Box<T>>> {
        self.stream.lock().await.replace(value)
    }
}

impl<T: Stream> Stream for SharedReplaceableStream<T> {
    type Item = T::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut locked_option = ready!(self.project().stream.poll_lock(cx));
        match locked_option.as_mut() {
            Some(stream) => stream.poll_next_unpin(cx),
            None => Poll::Ready(None),
        }
    }
}

impl<T: Stream> Clone for SharedReplaceableStream<T> {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.clone(),
        }
    }
}

pin_project! {
    /// A composite stream that prioritizes items from an internal channel before falling back to an underlying stream.
    pub struct ChannelStream<T, U> {
        channel: UnboundedReceiver<T>,
        #[pin]
        next: U,
        next_toggle: Option<WatchStream<bool>>,
        next_closed: Option<CancellationToken>,
        is_eof_channel: bool,
        is_eof_next: bool,
        poll_next: bool,
    }
}

impl<T, U> ChannelStream<T, U> {
    /// Creates a new [`ChannelStream`] that streams events from the given channel and next [`Stream`].
    ///
    /// # Inputs
    ///
    /// * `channel: UnboundedReceiver<T>` - The channel to poll for items first.
    /// * `next: U` - The underlying stream to poll for items if the channel is pending.
    /// * `next_toggle: Option<watch::Receiver<bool>>` - A flag that controls when to poll the next stream.
    /// * `next_closed: Option<CancellationToken>` - A token for notifying when the next stream has ended (returned `Poll::Ready(None)`).
    pub fn new(
        channel: UnboundedReceiver<T>,
        next: U,
        next_toggle: Option<watch::Receiver<bool>>,
        next_closed: Option<CancellationToken>,
    ) -> Self {
        let next_toggle = next_toggle.map(WatchStream::new);
        Self {
            channel,
            next,
            next_toggle,
            next_closed,
            is_eof_channel: false,
            is_eof_next: false,
            poll_next: true, // In case toggle is None.
        }
    }
}

impl<T, U> Stream for ChannelStream<T, U>
where
    T: From<Bytes>,
    U: Stream<Item = Bytes>,
{
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // We need to make sure either the channel, toggle, or next stream will wake
        // the waker if we return Poll::Pending, otherwise we risk a deadlock.

        if !*this.is_eof_channel {
            match this.channel.poll_recv(cx) {
                Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                Poll::Ready(None) => *this.is_eof_channel = true,
                Poll::Pending => {}
            }
        }

        if !*this.is_eof_next {
            // If the channel is closed, then we must poll the stream until it
            // also closes to prevent a possible deadlock. We do poll the stream
            // by default. But in case the toggle is off, then we make sure we
            // will wake back up when the toggle flips back to on.
            while let Some(watch_rx) = this.next_toggle {
                match watch_rx.poll_next_unpin(cx) {
                    Poll::Ready(Some(val)) => *this.poll_next = val,
                    Poll::Ready(None) => *this.next_toggle = None,
                    Poll::Pending => break, // Waker is registered!
                }
            }

            if *this.poll_next || this.next_toggle.is_none() {
                match this.next.poll_next_unpin(cx).map(|o| o.map(|b| T::from(b))) {
                    Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                    Poll::Ready(None) => {
                        *this.is_eof_next = true;
                        // Notify that the next stream has closed.
                        if let Some(token) = this.next_closed {
                            token.cancel();
                        }
                    }
                    Poll::Pending => {}
                }
            }
        }

        if *this.is_eof_channel && *this.is_eof_next {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}
