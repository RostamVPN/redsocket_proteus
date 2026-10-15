//! Synchronization tools for managing shared sinks.
//!
//! Provides thread-safe wrappers around asynchronous sinks, allowing multiple
//! tasks to send data into a single destination securely.

use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};

use bytes::Bytes;
use futures::{Sink, SinkExt};
use pin_project_lite::pin_project;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::PollSender;

use crate::sync::PollMutex;

pin_project! {
    /// A thread-safe, pollable wrapper around an asynchronous sink.
    ///
    /// Allows multiple concurrent tasks to safely push items into a single destination sink.
    pub struct SharedSink<T: Sink<Bytes>> {
        #[pin]
        sink: PollMutex<Pin<Box<T>>>,
        buffer: Option<Bytes>,
    }
}

impl<T: Sink<Bytes>> SharedSink<T> {
    #[allow(dead_code)]
    /// Creates a new [`SharedSink`] by wrapping a sink in a [`PollMutex`].
    ///
    /// # Inputs
    ///
    /// * `sink: T` - The sink to be shared.
    pub fn new(sink: T) -> Self {
        Self {
            sink: PollMutex::new(Box::pin(sink)),
            buffer: None,
        }
    }
}

impl<T: Sink<Bytes>> Sink<Bytes> for SharedSink<T>
where
    T::Error: Into<io::Error>,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        let mut locked_sink = ready!(this.sink.poll_lock(cx));

        if let Some(msg) = this.buffer.take() {
            locked_sink.start_send_unpin(msg).map_err(Into::into)?;
        }

        locked_sink.poll_ready_unpin(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, msg: Bytes) -> Result<(), Self::Error> {
        if self.buffer.is_none() {
            *self.as_mut().project().buffer = Some(msg);
        } else {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        // Do a best-effort send while ignoring Pending signals. If the send
        // cannot complete now, we'll poll again in the next call to
        // `poll_ready()` or `poll_flush()`.
        let mut cx = Context::from_waker(Waker::noop());
        if let Poll::Ready(result) = self.as_mut().poll_ready(&mut cx) {
            result
        } else {
            Ok(())
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        let mut locked_sink = ready!(this.sink.poll_lock(cx));

        if let Some(msg) = this.buffer.take() {
            locked_sink.start_send_unpin(msg).map_err(Into::into)?;
        }

        locked_sink.poll_flush_unpin(cx).map_err(Into::into)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        let mut locked_sink = ready!(this.sink.poll_lock(cx));

        if let Some(msg) = this.buffer.take() {
            locked_sink.start_send_unpin(msg).map_err(Into::into)?;
        }

        locked_sink.poll_close_unpin(cx).map_err(Into::into)
    }
}

impl<T: Sink<Bytes>> Clone for SharedSink<T> {
    fn clone(&self) -> Self {
        Self {
            sink: self.sink.clone(),
            buffer: None,
        }
    }
}

impl<T: Sink<Bytes>> Deref for SharedSink<T> {
    type Target = PollMutex<Pin<Box<T>>>;

    fn deref(&self) -> &Self::Target {
        &self.sink
    }
}

impl<T: Sink<Bytes>> DerefMut for SharedSink<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sink
    }
}

/// A command that allows the channel to propagate flush and close signals to the receiver.
#[derive(Debug)]
pub enum ChannelCommand<T> {
    Message(T),
    ExplicitFlush,
    ExplicitClose,
}

#[derive(Debug)]
enum ShutdownState {
    Idle,
    SendingSignal,
    Finalizing,
}

/// An adapter that implements the [`Sink`] trait by sending items into an mpsc channel.
pub struct ChannelSink<T> {
    channel: PollSender<ChannelCommand<T>>,
    flush_state: ShutdownState,
    close_state: ShutdownState,
}

impl<T: Send> ChannelSink<T> {
    /// Creates a new [`ChannelSink`] by wrapping a channel in a [`PollSender`].
    ///
    /// # Inputs
    ///
    /// * `channel: Sender<T>` - The channel into which sinked items will be sent.
    pub fn new(channel: Sender<ChannelCommand<T>>) -> Self {
        Self {
            channel: PollSender::new(channel),
            flush_state: ShutdownState::Idle,
            close_state: ShutdownState::Idle,
        }
    }
}

impl<T: Send> Sink<T> for ChannelSink<T> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let result = ready!(self.channel.poll_ready_unpin(cx));
        Poll::Ready(result.map_err(|_| io::ErrorKind::BrokenPipe.into()))
    }

    fn start_send(mut self: Pin<&mut Self>, msg: T) -> Result<(), Self::Error> {
        let result = self.channel.send_item(ChannelCommand::Message(msg));
        result.map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        loop {
            match self.flush_state {
                ShutdownState::Idle => {
                    // Make sure the channel has capacity for our flush signal before sending it.
                    ready!(self.channel.poll_ready_unpin(cx))
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;

                    self.channel
                        .send_item(ChannelCommand::ExplicitFlush)
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;

                    self.flush_state = ShutdownState::SendingSignal;
                }
                ShutdownState::SendingSignal => {
                    // Flush the channel so the receiver gets the signal.
                    ready!(self.channel.poll_flush_unpin(cx))
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;

                    self.flush_state = ShutdownState::Finalizing;
                }
                ShutdownState::Finalizing => {
                    // Reset state back to idle for subsequent flushes.
                    self.flush_state = ShutdownState::Idle;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        loop {
            match self.close_state {
                ShutdownState::Idle => {
                    // Make sure the channel has capacity for our close signal before sending it.
                    ready!(self.channel.poll_ready_unpin(cx))
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;

                    self.channel
                        .send_item(ChannelCommand::ExplicitClose)
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;

                    self.close_state = ShutdownState::SendingSignal;
                }
                ShutdownState::SendingSignal => {
                    // Flush the channel so the receiver gets the signal.
                    ready!(self.channel.poll_flush_unpin(cx))
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;

                    self.close_state = ShutdownState::Finalizing;
                }
                ShutdownState::Finalizing => {
                    // Do the underlying close operation on the PollSender.
                    let result = ready!(self.channel.poll_close_unpin(cx));
                    return Poll::Ready(result.map_err(|_| io::ErrorKind::BrokenPipe.into()));
                }
            }
        }
    }
}
