use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};

use bytes::Bytes;
use futures::{Sink, SinkExt};
use pin_project_lite::pin_project;

use crate::proto::reliability::{ReliabilityMessage, SharedReliabilityState};

pin_project! {
    /// An asynchronous sink that ingests reliable messages for transmission.
    ///
    /// Feeds outgoing data into the `SharedReliabilityState` for sequencing and potential retransmission.
    pub struct ReliabilitySink<T: Sink<Bytes>>
    where
        T::Error: Into<io::Error>
    {
        #[pin]
        sink: T,
        state: SharedReliabilityState,
        send_buf: Option<SendTask>,
        close_buf: Option<CloseTask>,
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SendTask {
    SinkReady,
    StateSend(ReliabilityMessage),
    SinkReadyThenSend(Bytes),
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum CloseTask {
    CloseState,
    CloseSink,
    Closed,
}

impl<T: Sink<Bytes>> ReliabilitySink<T>
where
    T::Error: Into<io::Error>,
{
    /// Creates a new `ReliabilitySink`.
    ///
    /// # Inputs
    ///
    /// * `sink: T` - The underlying sink that consumes encoded byte chunks for the next protocol layer.
    /// * `state: SharedReliabilityState` - The shared state manager for the reliability protocol.
    pub fn new(sink: T, state: SharedReliabilityState) -> Self {
        Self {
            sink,
            state,
            send_buf: None,
            close_buf: None,
        }
    }

    fn poll_send_inner(self: &mut Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut this = self.as_mut().project();

        // If we are Pending, return early but leave send_buf intact for the next poll.
        let result = if let Some(send_task) = this.send_buf.as_ref() {
            match send_task {
                SendTask::StateSend(msg) => {
                    if let Some(payload) = ready!(this.state.poll_send(cx, msg)) {
                        *this.send_buf = Some(SendTask::SinkReadyThenSend(payload));
                        return self.poll_send_inner(cx);
                    }
                    Ok(())
                }
                SendTask::SinkReady => ready!(this.sink.poll_ready(cx)),
                SendTask::SinkReadyThenSend(bytes) => {
                    match ready!(this.sink.as_mut().poll_ready(cx)) {
                        Ok(()) => this.sink.start_send(bytes.clone()),
                        Err(e) => Err(e),
                    }
                }
            }
        } else {
            Ok(())
        };

        // Remove the task if it successfully completed.
        if result.is_ok() {
            *this.send_buf = None;
        }

        Poll::from(result.map_err(Into::into))
    }

    fn error_if_closed(self: &Pin<&mut Self>) -> io::Result<()> {
        if self.close_buf.is_some() {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

impl<T: Sink<Bytes>> Sink<ReliabilityMessage> for ReliabilitySink<T>
where
    T::Error: Into<io::Error>,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.error_if_closed()?;

        if self.send_buf.is_none() {
            *self.as_mut().project().send_buf = Some(SendTask::SinkReady);
        }

        self.as_mut().poll_send_inner(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, msg: ReliabilityMessage) -> Result<(), Self::Error> {
        self.error_if_closed()?;

        if self.send_buf.is_none() {
            *self.as_mut().project().send_buf = Some(SendTask::StateSend(msg));
        } else {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        // Do a best-effort send while ignoring Pending signals. If the send
        // cannot complete now, we'll poll again in the next call to
        // `poll_ready()` or `poll_flush()`.
        let mut cx = Context::from_waker(Waker::noop());
        if let Poll::Ready(result) = self.as_mut().poll_send_inner(&mut cx) {
            result
        } else {
            Ok(())
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.error_if_closed()?;
        ready!(self.as_mut().poll_send_inner(cx))?;
        self.project().sink.poll_flush_unpin(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        // Ensure a flush has completed before setting the close task.
        if self.close_buf.is_none() {
            ready!(self.as_mut().poll_send_inner(cx))?;
            *self.as_mut().project().close_buf = Some(CloseTask::CloseState);
        }

        let mut this = self.as_mut().project();

        // We set the close task above, so now we can safely unwrap it.
        match this.close_buf.as_ref().unwrap() {
            CloseTask::CloseState => {
                ready!(this.state.poll_close(cx))?;
                *this.close_buf = Some(CloseTask::CloseSink);
                self.poll_close(cx)
            }
            CloseTask::CloseSink => {
                ready!(this.sink.poll_close_unpin(cx).map_err(Into::into))?;
                *this.close_buf = Some(CloseTask::Closed);
                Ok(()).into()
            }
            CloseTask::Closed => Ok(()).into(),
        }
    }
}
