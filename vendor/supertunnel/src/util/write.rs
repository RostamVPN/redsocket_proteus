use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::BytesMut;
use futures::SinkExt;
use pin_project_lite::pin_project;
use tokio::io::AsyncWrite;
use tokio_util::codec::Decoder;

use crate::Protocol;

pin_project! {
    /// An adapter that implements [`AsyncWrite`] by decoding bytes into messages and feeding a Sink.
    ///
    // Uses a Codec to decode the bytes taken from the caller through the [`AsyncWrite`] interface
    // into messages that are passed to an inner Sink for processing.
    pub struct DecodedSinkWriter<T: Protocol> {
        #[pin]
        sink: T::SinkHalf,
        decoder: T::Codec,
        buffer: BytesMut,
    }
}

impl<T: Protocol> DecodedSinkWriter<T> {
    /// Creates a new [`DecodedSinkWriter`].
    ///
    /// # Inputs
    ///
    /// * `sink: T::SinkHalf` - The destination sink for decoded protocol messages.
    /// * `decoder: T::Codec` - The codec used to decode bytes from the [`AsyncWrite`] interface into messages.
    pub fn new(sink: T::SinkHalf, decoder: T::Codec) -> Self {
        Self {
            sink,
            decoder,
            buffer: BytesMut::new(),
        }
    }

    /// Consumes the [`DecodedSinkWriter`], returning the underlying message sink.
    pub fn into_inner(self) -> T::SinkHalf {
        self.sink
    }

    /// Clears the internal buffer of the writer.
    ///
    /// This is useful for resetting state after a connection interruption to prevent
    /// processing partial, stale data.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    fn send_all_from_buffer(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut this = self.project();
        loop {
            // Check if the sink is ready to accept a new message.
            match this.sink.poll_ready_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    // Try to decode a message from our buffer.
                    match this.decoder.decode(this.buffer) {
                        // A message was decoded, send it to the sink.
                        Ok(Some(msg)) => match this.sink.start_send_unpin(msg) {
                            Ok(()) => continue, // Success, try again.
                            Err(e) => return Poll::Ready(Err(e.into())),
                        },
                        // Need more bytes to decode a full message.
                        Ok(None) => return Poll::Ready(Ok(())),
                        // An error occurred during decoding.
                        Err(e) => return Poll::Ready(Err(e.into())),
                    }
                }
                // The sink has an error.
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                // Sink not ready yet, try again later.
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<T: Protocol> AsyncWrite for DecodedSinkWriter<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Don't accept any new bytes until all buffered messages are sent.
        match self.as_mut().send_all_from_buffer(cx) {
            Poll::Ready(Ok(())) => {
                // Now we processed all buffered messages, and we need more
                // bytes to decode the next full message.
                self.as_mut().project().buffer.extend_from_slice(buf);

                // Loop to send all messages now available in our buffer.
                match self.as_mut().send_all_from_buffer(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // The inner sink is not ready yet. Do not keep any buf
                        // data that we didn't use yet to avoid buffer bloat.
                        if self.buffer.len() < buf.len() {
                            // Partial write. Return the amount of buf that we consumed.
                            let consumed = buf.len() - self.buffer.len();
                            // The bytes we did not consume will be rewritten.
                            self.as_mut().project().buffer.clear();
                            Poll::Ready(Ok(consumed))
                        } else {
                            // Zero write. The entire buf will be rewritten.
                            let len_without_buf = self.buffer.len() - buf.len();
                            self.as_mut().project().buffer.truncate(len_without_buf);
                            // Return Pending so we wake up when our inner
                            // stream becomes unblocked.
                            Poll::Pending
                        }
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Flush our own buffer first, returning on error.
        ready!(self.as_mut().send_all_from_buffer(cx))?;
        // Then flush the inner sink.
        self.project().sink.poll_flush_unpin(cx).map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Flush our own buffer first, returning on error.
        ready!(self.as_mut().send_all_from_buffer(cx))?;
        // Then close the inner sink.
        self.project().sink.poll_close_unpin(cx).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use futures::sink::Sink;
    use futures::stream::Pending;
    use tokio::io::AsyncWrite;
    use tokio_util::codec::{Decoder, Encoder};

    use crate::util::DecodedSinkWriter;
    use crate::{FrameSize, Protocol};

    #[derive(Clone)]
    struct DummyCodec;

    impl Decoder for DummyCodec {
        type Item = Bytes;
        type Error = std::io::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            // Scan for the newline character
            if let Some(pos) = src.iter().position(|&b| b == b'\n') {
                // Split the line before the newline, and remove the newline character itself
                let line = src.split_to(pos).freeze();
                src.advance(1); // Discard the '\n'
                Ok(Some(line))
            } else {
                // No newline found yet; wait for more data to be written
                Ok(None)
            }
        }
    }

    impl Encoder<Bytes> for DummyCodec {
        type Error = std::io::Error;

        fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
            dst.extend_from_slice(&item);
            dst.put_u8(b'\n');
            Ok(())
        }
    }

    impl FrameSize for DummyCodec {
        fn mtu() -> usize {
            unimplemented!()
        }

        fn mss(_target_mtu: usize) -> usize {
            unimplemented!()
        }
    }

    struct DummySink {
        is_ready: Arc<Mutex<bool>>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl DummySink {
        fn set_ready(&mut self, is_ready: bool) {
            *self.is_ready.lock().unwrap() = is_ready;
        }

        fn ready(&self) -> bool {
            *self.is_ready.lock().unwrap()
        }
    }

    impl Sink<Bytes> for DummySink {
        type Error = std::io::Error;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.ready() {
                Poll::Ready(Ok(()))
            } else {
                *self.waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        fn start_send(mut self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            self.as_mut().set_ready(false);
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.poll_ready(cx)
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct DummyProtocol;

    impl Protocol for DummyProtocol {
        type Codec = DummyCodec;
        type Message = Bytes;
        type SinkHalf = DummySink;
        type StreamHalf = Pending<Bytes>;

        fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
            unimplemented!()
        }

        fn codec() -> Self::Codec {
            unimplemented!()
        }
    }

    fn encode_n_messages(n: usize) -> Bytes {
        let mut buf = BytesMut::new();
        for _ in 0..n {
            assert!(DummyCodec.encode(Bytes::from("message"), &mut buf).is_ok());
        }
        buf.freeze()
    }

    #[test]
    fn test_decoded_sink_writer_backpressure() {
        let is_ready = Arc::new(Mutex::new(true));
        let waker_store = Arc::new(Mutex::new(None));

        let mock_sink = DummySink {
            is_ready: is_ready.clone(),
            waker: waker_store.clone(),
        };

        let writer = DecodedSinkWriter::<DummyProtocol>::new(mock_sink, DummyCodec);
        let mut task = tokio_test::task::spawn(writer);

        // We write two messages where the sink becomes blocked after the first.
        let payload = encode_n_messages(2);
        let poll_res = task.enter(|cx, mut writer| Pin::new(&mut writer).poll_write(cx, &payload));

        // We should have written one...
        assert!(poll_res.is_ready(), "Expected initial write to be Ready");
        let Poll::Ready(Ok(write_len)) = poll_res else {
            panic!("Expected initial write to be Ready");
        };

        // but not both. Otherwise the other message gets stuck in the buffer if
        // we never call write again.
        assert!(write_len < payload.len());

        let _captured_waker = waker_store
            .lock()
            .unwrap()
            .take()
            .expect("Inner sink did not capture a waker! Writer failed to poll inner sink.");

        assert!(
            !task.is_woken(),
            "Task was prematurely woken before sink unblocked"
        )
    }
}
