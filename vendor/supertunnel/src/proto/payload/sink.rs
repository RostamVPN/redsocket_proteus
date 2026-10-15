use std::io::{self, Cursor};
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker, ready};

use bytes::{Buf, Bytes};
use futures::Sink;
use pin_project_lite::pin_project;
use tokio::io::AsyncWrite;
use tokio_util::io::poll_write_buf;

use crate::Identify;
use crate::proto::payload::PayloadMessage;

pin_project! {
    /// An asynchronous [`Sink`] that consumes `PayloadMessage` instances.
    ///
    /// Writes the extracted payload data to an underlying asynchronous writer `T`.
    pub struct PayloadSink<T: AsyncWrite>
    {
        id: u64,
        #[pin]
        writer: T,
        buf: Option<Cursor<Bytes>>,
    }
}

impl<T: AsyncWrite> PayloadSink<T> {
    /// Creates a new `PayloadSink`.
    ///
    /// # Inputs
    ///
    /// * `id: u64` - The session ID, used for identifying the sink but not included in the outgoing data.
    /// * `writer: T` - The asynchronous writer where payload data will be sent.
    pub fn new(id: u64, writer: T) -> Self {
        Self {
            id,
            writer,
            buf: None,
        }
    }

    fn poll_write_inner(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let mut this = self.project();

        if let Some(mut cursor) = this.buf.take() {
            while cursor.has_remaining() {
                match poll_write_buf(pin!(&mut this.writer), cx, &mut cursor) {
                    Poll::Ready(Ok(_n)) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        *this.buf = Some(cursor);
                        return Poll::Pending;
                    }
                };
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite> Identify for PayloadSink<T> {
    fn id(&self) -> u64 {
        self.id
    }
}

impl<T: AsyncWrite> Sink<PayloadMessage> for PayloadSink<T> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.as_mut().poll_write_inner(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, msg: PayloadMessage) -> Result<(), Self::Error> {
        if self.buf.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        // This is best-effort here, so ignore any Pending result.
        let mut cx = Context::from_waker(Waker::noop());

        if msg.data.is_empty() {
            // The application stream sent us an EOF, so we are done writing.
            let _ = self.as_mut().poll_close(&mut cx);
            // Return an error to signal to the caller that we're done.
            Err(io::ErrorKind::UnexpectedEof.into())
        } else {
            // Process the new payload.
            *self.as_mut().project().buf = Some(Cursor::new(msg.data));

            if let Poll::Ready(result) = self.as_mut().poll_write_inner(&mut cx) {
                result
            } else {
                Ok(())
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_ready(cx))?;
        self.project().writer.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.project().writer.poll_shutdown(cx)
    }
}
