//! Testing utilities.
//!
//! Provides mock I/O streams, test networks, and payload generators to simulate
//! various network conditions and validate protocol behavior.

use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, Stream};
use itertools::Itertools;
use pin_project_lite::pin_project;
use rand::distr::{Alphanumeric, Distribution};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_test::io::{Builder, Mock};
use tokio_util::codec::{BytesCodec, Decoder, Encoder, FramedRead, FramedWrite};

use crate::net::NetworkTarget;
use crate::util::{DecodedSinkWriter, EncodedStreamReader};
use crate::{FrameSize, Identify, Protocol, SessionConnector};

/// A simulated network environment for testing protocol stacks.
///
/// Encapsulates both client and server protocol layers, allowing for in-memory
/// bidirectional data transfer without binding to actual network sockets.
pub struct TestNetwork<C: Protocol, S: Protocol> {
    client: C,
    server: S,
}

impl<C: Protocol, S: Protocol> TestNetwork<C, S> {
    /// Creates a new [`TestNetwork`] with a client and server protocol stack.
    ///
    /// # Inputs
    ///
    /// * `client: C` - The client-side protocol stack.
    /// * `server: S` - The server-side protocol stack.
    pub fn new(client: C, server: S) -> Self {
        Self { client, server }
    }

    fn into_pinned_parts(
        self,
    ) -> (
        Pin<Box<impl AsyncRead>>,
        Pin<Box<impl AsyncWrite>>,
        Pin<Box<impl AsyncRead>>,
        Pin<Box<impl AsyncWrite>>,
    ) {
        let (c_stream, c_sink) = self.client.into_split();
        let (s_stream, s_sink) = self.server.into_split();

        let c_net_src = EncodedStreamReader::<C>::new(c_stream, C::codec());
        let c_net_dst = DecodedSinkWriter::<C>::new(c_sink, C::codec());
        let s_net_src = EncodedStreamReader::<S>::new(s_stream, S::codec());
        let s_net_dst = DecodedSinkWriter::<S>::new(s_sink, S::codec());

        (
            Box::pin(c_net_src),
            Box::pin(c_net_dst),
            Box::pin(s_net_src),
            Box::pin(s_net_dst),
        )
    }

    /// Runs the test network, simulating a bidirectional data transfer between client and server.
    ///
    /// This function uses `tokio::io::copy` to move data between the two protocol stacks until
    /// both directions have completed. It waits for both transfers to finish, even if one fails.
    ///
    /// # Returns
    ///
    /// * `(io::Result<usize>, io::Result<usize>)` - A tuple containing the
    ///   results of the two transfers: (client-to-server, server-to-client).
    ///   Each result is the number of bytes copied or an `io::Error`.
    pub async fn run(self) -> (io::Result<usize>, io::Result<usize>) {
        let (mut c_net_src, mut c_net_dst, mut s_net_src, mut s_net_dst) = self.into_pinned_parts();

        let (res1, res2) = tokio::join!(
            crate::io::yielding_copy(&mut c_net_src, &mut s_net_dst, None),
            crate::io::yielding_copy(&mut s_net_src, &mut c_net_dst, None)
        );
        (res1.map_err(Into::into), res2.map_err(Into::into))
    }
}

impl<C: Protocol, S: Protocol> TestNetwork<C, S>
where
    C: 'static,
    S: 'static,
    <C as Protocol>::StreamHalf: Send,
    <S as Protocol>::StreamHalf: Send,
    <C as Protocol>::SinkHalf: Send,
    <S as Protocol>::SinkHalf: Send,
    <C as Protocol>::Codec: Send,
    <S as Protocol>::Codec: Send,
{
    /// Runs the test network in spawned tasks, allowing for parallel execution of transfers.
    ///
    /// This is useful for tests where the client and server might block each other if run
    /// in a single-threaded `join!`. It returns the results once both tasks have completed.
    ///
    /// # Returns
    ///
    /// * `(io::Result<usize>, io::Result<usize>)` - A tuple containing the
    ///   results of the two transfers: (client-to-server, server-to-client).
    pub async fn run_spawn(self) -> (io::Result<usize>, io::Result<usize>) {
        let (mut c_net_src, mut c_net_dst, mut s_net_src, mut s_net_dst) = self.into_pinned_parts();

        let mut set = JoinSet::new();

        let c_to_s =
            set.spawn(async move { tokio::io::copy(&mut c_net_src, &mut s_net_dst).await });
        let s_to_c =
            set.spawn(async move { tokio::io::copy(&mut s_net_src, &mut c_net_dst).await });

        let mut c_to_s_result = Err(io::Error::other("Join result missing"));
        let mut s_to_c_result = Err(io::Error::other("Join result missing"));

        while let Some(join_res) = set.join_next_with_id().await {
            match join_res {
                Ok((id, task_res)) => {
                    if id == c_to_s.id() {
                        c_to_s_result = task_res;
                    } else if id == s_to_c.id() {
                        s_to_c_result = task_res;
                    }
                }
                Err(e) => {
                    if e.id() == c_to_s.id() {
                        c_to_s_result = Err(e.into());
                    } else if e.id() == s_to_c.id() {
                        s_to_c_result = Err(e.into());
                    }
                }
            }
        }

        (
            c_to_s_result.map(|n| n as usize),
            s_to_c_result.map(|n| n as usize),
        )
    }
}

/// A mock I/O protocol instance for testing purposes.
///
/// Implements asynchronous reading and writing over an underlying mock stream.
pub struct TestIoProtocol {
    reader: Pin<Box<dyn AsyncRead + Send + Sync>>,
    writer: Pin<Box<dyn AsyncWrite + Send + Sync>>,
    id: u64,
}

impl TestIoProtocol {
    /// Creates a [`TestIoProtocol`] from a `tokio_test::io::Mock` stream.
    ///
    /// # Inputs
    ///
    /// * `io: Mock` - The mock I/O stream to use for reading and writing.
    pub fn from_mock(io: Mock) -> Self {
        let (r, w) = tokio::io::split(io);
        Self {
            reader: Box::pin(r),
            writer: Box::pin(w),
            id: 0,
        }
    }

    /// Creates a [`TestIoProtocol`] from any objects implementing [`AsyncRead`] and [`AsyncWrite`].
    ///
    /// # Inputs
    ///
    /// * `reader: impl AsyncRead + Send + Sync + 'static` - The reader half.
    /// * `writer: impl AsyncWrite + Send + Sync + 'static` - The writer half.
    pub fn from_io(
        reader: impl AsyncRead + Send + Sync + 'static,
        writer: impl AsyncWrite + Send + Sync + 'static,
    ) -> Self {
        Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
            id: 0,
        }
    }

    /// Sets the ID for the protocol and returns ownership.
    ///
    /// # Inputs
    ///
    /// * `id: u64` - The session ID to assign.
    pub fn with_id(mut self, id: u64) -> Self {
        self.set_id(id);
        self
    }

    /// Sets the ID for the protocol.
    ///
    /// # Inputs
    ///
    /// * `id: u64` - The session ID to assign.
    pub fn set_id(&mut self, id: u64) {
        self.id = id;
    }
}

impl Protocol for TestIoProtocol {
    type Message = TestMessage;
    type StreamHalf = TestHalf<FramedRead<Pin<Box<dyn AsyncRead + Send + Sync>>, BytesCodec>>;
    type SinkHalf = TestHalf<FramedWrite<Pin<Box<dyn AsyncWrite + Send + Sync>>, BytesCodec>>;
    type Codec = TestCodec;

    fn into_split(self) -> (Self::StreamHalf, Self::SinkHalf) {
        let stream = FramedRead::new(self.reader, BytesCodec::new());
        let stream = TestHalf::new(stream, self.id);
        let sink = FramedWrite::new(self.writer, BytesCodec::new());
        let sink = TestHalf::new(sink, self.id);
        (stream, sink)
    }

    fn codec() -> Self::Codec {
        TestCodec::new()
    }
}

/// A standardized message format for testing protocol boundaries.
///
/// Contains an identifier and a payload to track data integrity across the test network.
#[derive(Debug)]
pub struct TestMessage {
    id: u64,
    payload: Bytes,
}

impl TestMessage {
    /// Creates a new [`TestNetwork`] with a client and server protocol stack.
    ///
    /// # Inputs
    ///
    /// * `client: C` - The client-side protocol stack.
    /// * `server: S` - The server-side protocol stack.
    pub fn new(id: u64, payload: Bytes) -> Self {
        Self { id, payload }
    }
}

impl Identify for TestMessage {
    fn id(&self) -> u64 {
        self.id
    }
}

pin_project! {
    /// A wrapper around a read or write half of a test stream.
    ///
    /// Used to isolate stream and sink operations during concurrent testing.
    pub struct TestHalf<T> {
        #[pin]
        inner: T,
        id: u64,
    }
}

impl<T> TestHalf<T> {
    /// Creates a new [`TestHalf`] around a protocol stack stream or sink.
    ///
    /// # Inputs
    ///
    /// * `inner: T` - The inner stream or sink half object used for testing.
    /// * `id: u64` - A unique identifier to use for the object.
    pub fn new(inner: T, id: u64) -> Self {
        Self { inner, id }
    }
}

impl<T> Identify for TestHalf<T> {
    fn id(&self) -> u64 {
        self.id
    }
}

impl<T, V> Stream for TestHalf<T>
where
    T: Stream<Item = Result<BytesMut, V>>,
{
    type Item = TestMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let id = self.id;
        let result = match self.project().inner.poll_next(cx) {
            // Converts the ready Result item into an Option<TestMessage>.
            Poll::Ready(Some(x)) => Poll::Ready(x.ok().map(|b| TestMessage::new(id, b.freeze()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        };
        log::trace!("TestHalfStream: poll_next: {result:?}");
        result
    }
}

impl<T, V> Sink<TestMessage> for TestHalf<T>
where
    T: Sink<Bytes, Error = V>,
    V: std::fmt::Debug,
{
    type Error = V;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let result = self.project().inner.poll_ready(cx);
        log::trace!("TestHalfSink: poll_ready: {result:?}");
        result
    }

    fn start_send(self: Pin<&mut Self>, item: TestMessage) -> Result<(), Self::Error> {
        // Unwrap the test message into the inner item for the inner sink.
        log::trace!("TestHalfSink: sending message: {item:?}");
        let result = self.project().inner.start_send(item.payload);
        log::trace!("TestHalfSink: start_send: {result:?}");
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let result = self.project().inner.poll_flush(cx);
        log::trace!("TestHalfSink: poll_flush: {result:?}");
        result
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let result = self.project().inner.poll_close(cx);
        log::trace!("TestHalfSink: poll_close: {result:?}");
        result
    }
}

/// A basic codec for encoding and decoding [`TestMessage`] instances.
#[derive(Clone, Debug, Default)]
pub struct TestCodec;

impl TestCodec {
    /// Creates a new [`TestCodec`].
    pub fn new() -> Self {
        Self
    }

    /// The maximum number of bytes of overhead added by the codec to any
    /// message carrying payload bytes. This helps us calculate how many payload
    /// bytes to add to each message to enforce an mtu.
    const fn max_header_len() -> usize {
        // This *must* be kept synchronized with our encoding scheme.
        // For session id (8) and length (2) fields.
        8 + 2
    }

    pub fn encode_str(data: &'static str) -> Bytes {
        let msg = TestMessage::new(0, Bytes::from(data));
        let mut buf = BytesMut::new();
        assert!(Self.encode(msg, &mut buf).is_ok());
        buf.freeze()
    }
}

impl FrameSize for TestCodec {
    /// The maximum number of bytes that can be transmitted for a single
    /// message, based on the current encoding scheme.
    fn mtu() -> usize {
        u16::MAX as usize // 2^16 = 65536 bytes
    }

    /// The maximum supported length of a payload that ensures the full message
    /// length can be encoded to fit within `target_mtu`.
    fn mss(target_mtu: usize) -> usize {
        let mtu = target_mtu.min(Self::mtu());
        mtu.checked_sub(Self::max_header_len()).unwrap()
    }
}

impl Encoder<TestMessage> for TestCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: TestMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if msg.payload.len() > Self::mss(Self::mtu()) {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        dst.reserve(Self::max_header_len() + msg.payload.len());
        dst.put_u64(msg.id);
        dst.put_u16(u16::try_from(msg.payload.len()).unwrap());
        dst.put(msg.payload);
        Ok(())
    }
}

impl Decoder for TestCodec {
    type Item = TestMessage;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut reader = Cursor::new(src as &BytesMut);

        if reader.remaining() >= 10 {
            let id = reader.get_u64();
            let len = reader.get_u16() as usize;
            if reader.remaining() >= len {
                // We have everything, skip up to the payload.
                src.advance(10);
                // Zero-copy from the src buf.
                let payload = src.split_to(len).freeze();
                Ok(Some(TestMessage::new(id, payload)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

/// A mock session connector for test environments.
///
/// Supplies pre-configured [`TestIoProtocol`] instances to simulate successful outbound connections.
#[derive(Default)]
pub struct TestConnector {
    connections: Arc<Mutex<Vec<TestIoProtocol>>>,
}

impl TestConnector {
    /// Creates a new [`TestConnector`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes a connected `TestIoProtocol` instance to the connector's pool.
    ///
    /// This instance will be used to satisfy a future `connect` call.
    ///
    /// # Inputs
    ///
    /// * `connected: TestIoProtocol` - The protocol instance to make available.
    pub async fn push(&mut self, connected: TestIoProtocol) {
        self.connections.lock().await.push(connected);
    }
}

impl SessionConnector for TestConnector {
    type Item = TestIoProtocol;

    fn connect(
        &self,
        id: u64,
        _target: NetworkTarget,
    ) -> impl Future<Output = (u64, std::io::Result<Self::Item>)> + Send + 'static {
        // All data from self needs to be cloned so it doesn't move into the async block.
        let connections = self.connections.clone();
        async move {
            let result = if let Some(mut session) = connections.lock().await.pop() {
                session.set_id(id);
                Ok(session)
            } else {
                Err(io::ErrorKind::AddrInUse.into())
            };
            (id, result)
        }
    }
}

/// A utility for generating varied payload sizes and data patterns.
///
/// Useful for stress-testing protocol boundaries, framing logic, and reliability mechanisms.
pub struct TestPayload;

impl TestPayload {
    /// Returns an iterator of predefined payload lengths for testing.
    pub fn len_iter() -> impl Iterator<Item = usize> {
        [
            1, 10, 100, 1_000, 1_500, 2_000, 5_000, 10_000, 100_000, 1_000_000, 10_000_000,
        ]
        .into_iter()
    }

    /// Returns an iterator that generates a variety of mock I/O scenarios for testing.
    ///
    /// This includes a simple handshake, single-chunk transfers, interleaved data, and bursty traffic patterns.
    pub fn iter() -> impl Iterator<Item = (Mock, Mock, usize)> {
        let mut v = vec![Self::simple_handshake()];
        for len in Self::len_iter() {
            v.push(Self::one_chunk(len));
            v.push(Self::interleaved(len));
            v.push(Self::bursty(len, 5));
            v.push(Self::bursty(len, 10));
        }
        v.into_iter()
    }

    /// Generates a `Bytes` object of a specified length with random alphanumeric characters.
    ///
    /// For performance, payloads larger than 1MB are filled with repeating characters after the first 1MB.
    ///
    /// # Inputs
    ///
    /// * `len: usize` - The desired length of the `Bytes` object.
    ///
    /// # Panics
    ///
    /// * Panics if the generated buffer length does not match the requested length.
    pub fn bytes(len: usize) -> Bytes {
        let mut rng = rand::rng();
        let mut buf = BytesMut::with_capacity(len);
        let cutoff = 1_000_000;

        // Slower: every byte is a different random character.
        for _ in 0..len.min(cutoff) {
            buf.put_u8(Alphanumeric.sample(&mut rng) as u8);
        }

        // Faster: all bytes are the same random character.
        if len > cutoff {
            buf.put_bytes(Alphanumeric.sample(&mut rng), len - cutoff);
        }

        assert_eq!(buf.len(), len);

        buf.freeze()
    }

    fn simple_handshake() -> (Mock, Mock, usize) {
        let c_io = Builder::new()
            .read(b"Hello")
            .write(b"World")
            .read(b"CFIN!")
            .write(b"SFIN!")
            .build();
        let s_io = Builder::new()
            .write(b"Hello")
            .read(b"World")
            .write(b"CFIN!")
            .read(b"SFIN!")
            .build();
        (c_io, s_io, 10)
    }

    fn one_chunk(len: usize) -> (Mock, Mock, usize) {
        let c_bytes = Self::bytes(len);
        let s_bytes = Self::bytes(len);
        let c_io = Builder::new().read(&c_bytes).write(&s_bytes).build();
        let s_io = Builder::new().read(&s_bytes).write(&c_bytes).build();
        (c_io, s_io, len)
    }

    fn interleaved(len: usize) -> (Mock, Mock, usize) {
        Self::bursty(len, 1)
    }

    fn bursty(len: usize, burst_size: usize) -> (Mock, Mock, usize) {
        let c_bytes = Self::bytes(len);
        let s_bytes = Self::bytes(len);

        let mut c_builder = Builder::new();
        let mut s_builder = Builder::new();

        const CHUNK_SIZE: usize = 65536;
        let c_chunks = c_bytes.chunks(CHUNK_SIZE);
        let s_chunks = s_bytes.chunks(CHUNK_SIZE);

        let zipped = c_chunks.zip(s_chunks);

        // A burst is a chunk of the bytes chunks.
        for burst in &zipped.into_iter().chunks(burst_size) {
            let (c_burst, s_burst): (Vec<_>, Vec<_>) = burst.unzip();

            for chunk in &c_burst {
                c_builder.read(chunk);
            }
            for chunk in &s_burst {
                s_builder.read(chunk);
            }

            for chunk in &c_burst {
                s_builder.write(chunk);
            }
            for chunk in &s_burst {
                c_builder.write(chunk);
            }
        }

        (c_builder.build(), s_builder.build(), len)
    }
}
