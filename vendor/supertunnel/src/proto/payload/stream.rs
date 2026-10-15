use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use futures::Stream;
use pin_project_lite::pin_project;
use tokio::io::AsyncRead;
use tokio_util::io::poll_read_buf;

use crate::proto::payload::{PayloadCodec, PayloadMessage};
use crate::{FrameSize, Identify};

pin_project! {
    /// An asynchronous [`Stream`] that produces `PayloadMessage` instances.
    ///
    /// Reads from an underlying asynchronous reader `R` and chunks payload data according to the MSS.
    pub struct PayloadStream<T: AsyncRead> {
        id: u64,
        #[pin]
        reader: T,
        mss: usize,
        is_eof: bool
    }
}

impl<T: AsyncRead> PayloadStream<T> {
    /// Creates a new `PayloadStream`.
    ///
    /// # Inputs
    ///
    /// * `id: u64` - The session ID for messages produced by this stream.
    /// * `reader: T` - The asynchronous reader to pull payload data from.
    /// * `parent_mss: usize` - The Maximum Segment Size of the parent protocol layer, used to calculate the MSS for this layer.
    pub fn new(id: u64, reader: T, parent_mss: usize) -> Self {
        Self {
            id,
            reader,
            mss: PayloadCodec::mss(parent_mss),
            is_eof: false,
        }
    }
}

impl<T: AsyncRead> Identify for PayloadStream<T> {
    fn id(&self) -> u64 {
        self.id
    }
}

impl<T: AsyncRead> Stream for PayloadStream<T> {
    type Item = PayloadMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.is_eof {
            Poll::Ready(None)
        } else {
            let this = self.project();
            let mut buf = BytesMut::with_capacity(*this.mss);

            match poll_read_buf(this.reader, cx, &mut buf) {
                Poll::Ready(Ok(0)) => Poll::Ready(None),
                Poll::Ready(Ok(len)) => {
                    // If we get EoF, we forward the signal with an empty message but
                    // will close the stream on the next call to `poll_next`.
                    if len == 0 {
                        *this.is_eof = true;
                    }

                    let msg = PayloadMessage::new(*this.id, buf.freeze());
                    Poll::Ready(Some(msg))
                }
                Poll::Ready(Err(_e)) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}
