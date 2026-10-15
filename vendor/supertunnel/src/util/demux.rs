//! Stream Demultiplexing.
//!
//! Provides utilities for taking a unified stream of messages and routing
//! them to dynamically allocated, distinct asynchronous sinks.

use std::collections::hash_map::Entry;
use std::collections::hash_set::Drain;
use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};

use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt};
use pin_project_lite::pin_project;
use rand::Rng;
use tokio_util::codec::Decoder;

use crate::{Identify, Protocol};

pin_project! {
    /// A demultiplexer that reads a unified stream of messages and routes them to specific internal Sinks by ID.
    ///
    /// Takes byte chunks from a producer through the [`Sink`] interface, which are
    /// then encoded into messages and sent to the given sink.
    pub struct DemuxedDecodedSink<T: Protocol>
    where
        T::Message: Identify
    {
        #[pin]
        sinks: HashMap<u64, Pin<Box<T::SinkHalf>>>,
        // Sink ids that have been reserved for future insertion.
        reserved: HashSet<u64>,
        // Sinks to which we have sent messages and are pending a flush.
        dirty: HashSet<u64>,
        // Removed sinks that haven't been reported yet.
        removed: HashSet<u64>,
        buffer: Option<BufTask<T::Message>>,
        decoder: T::Codec,
        waker: Option<Waker>,
    }
}

enum BufTask<T: Identify> {
    // Check that the sink with this id in our map is ready.
    Ready(u64),
    // Check that the sink with this msg is ready, then send it.
    ReadyAndSend(T),
}

impl<T: Identify> BufTask<T> {
    fn id(&self) -> u64 {
        match self {
            BufTask::Ready(id) => *id,
            BufTask::ReadyAndSend(msg) => msg.id(),
        }
    }
}

impl<T: Protocol> DemuxedDecodedSink<T>
where
    T::Message: Identify,
{
    /// Creates a new, empty [`DemuxedDecodedSink`].
    ///
    /// # Inputs
    ///
    /// * `decoder: T::Codec` - The codec used to decode incoming bytes into messages.
    pub fn new(decoder: T::Codec) -> Self {
        Self {
            sinks: HashMap::new(),
            reserved: HashSet::new(),
            dirty: HashSet::new(),
            removed: HashSet::new(),
            buffer: None,
            decoder,
            waker: None,
        }
    }

    fn is_available(&self, id: &u64) -> bool {
        !self.sinks.contains_key(id) && !self.reserved.contains(id) && !self.dirty.contains(id)
    }

    fn generate_id(&self) -> u64 {
        let mut rng = rand::rng();
        loop {
            let id = rng.next_u64();
            if id > 0 && self.is_available(&id) {
                return id;
            }
        }
    }

    /// Adds a new sink to the demultiplexer and assigns it a randomly generated, unique ID.
    ///
    /// # Inputs
    ///
    /// * `sink: T::SinkHalf` - The sink to be added.
    ///
    /// # Returns
    ///
    /// * `u64` - The unique ID assigned to the added sink.
    pub fn add(&mut self, sink: T::SinkHalf) -> u64 {
        let id = self.generate_id();
        let old = self.sinks.insert(id, Box::pin(sink));
        assert!(old.is_none());
        self.wake();
        id
    }

    /// Reserves a unique, randomly generated ID for a future sink.
    ///
    /// # Returns
    ///
    /// * `u64` - The reserved ID.
    pub fn reserve_id(&mut self) -> u64 {
        let id = self.generate_id();
        self.reserved.insert(id);
        id
    }

    /// Attempts to reserve a specific ID.
    ///
    /// # Inputs
    ///
    /// * `id: u64` - The ID to reserve.
    ///
    /// # Returns
    ///
    /// * `bool` - `true` if the ID was available and has been reserved.
    pub fn try_reserve_id(&mut self, id: u64) -> bool {
        if self.is_available(&id) {
            self.reserved.insert(id)
        } else {
            false
        }
    }

    /// Adds a sink using a previously reserved ID.
    ///
    /// # Inputs
    ///
    /// * `sink: T::SinkHalf` - The sink to add.
    /// * `id: u64` - The reserved ID to use.
    ///
    /// # Returns
    ///
    /// * `Result<(), T::SinkHalf>` - `Ok(())` on success. On failure (e.g., ID not reserved),
    ///   returns `Err(sink)` with the original sink.
    pub fn try_add_with_reserved_id(
        &mut self,
        sink: T::SinkHalf,
        id: u64,
    ) -> Result<(), T::SinkHalf> {
        if let Entry::Vacant(e) = self.sinks.entry(id)
            && self.reserved.contains(&id)
        {
            e.insert(Box::pin(sink));
            self.reserved.remove(&id);
            self.wake();
            Ok(())
        } else {
            Err(sink)
        }
    }

    /// Removes a sink from the demultiplexer by its ID.
    ///
    /// # Inputs
    ///
    /// * `id: &u64` - The ID of the sink to remove.
    ///
    /// # Returns
    ///
    /// * `bool` - `true` if a sink with the given ID was found and removed.
    pub fn remove(&mut self, id: &u64) -> bool {
        let mut removed = false;
        if self.sinks.contains_key(id) {
            self.sinks.remove(id);
            self.removed.insert(*id);
            removed = true;
        }
        self.reserved.remove(id);
        self.dirty.remove(id);
        removed
    }

    /// Returns an iterator over the IDs of sinks that have been removed since the last drain.
    /// This allows external components to react to sink removals, e.g., to shut down a
    /// remote source of sink messages.
    pub fn drain_removed(&mut self) -> Drain<'_, u64> {
        self.removed.drain()
    }

    /// Removes all sinks from the demultiplexer.
    pub fn clear(&mut self) {
        self.sinks.clear();
        self.dirty.clear();
        self.removed.clear();
    }

    /// Returns the number of active sinks.
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// Returns `true` if there are no active sinks.
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
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

    fn poll_ready_inner(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        id: &u64,
    ) -> Poll<Result<(), io::Error>> {
        if let Some(sink) = self.as_mut().project().sinks.get_mut().get_mut(id) {
            match ready!(sink.poll_ready_unpin(cx)) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => {
                    self.remove(id);
                    Poll::Ready(Err(e.into()))
                }
            }
        } else {
            Poll::Ready(Err(std::io::ErrorKind::NotFound.into()))
        }
    }

    fn start_send_inner(mut self: Pin<&mut Self>, msg: T::Message) -> Result<(), io::Error> {
        let id = msg.id();
        if let Some(sink) = self.as_mut().project().sinks.get_mut().get_mut(&id) {
            match sink.start_send_unpin(msg) {
                Ok(()) => {
                    self.dirty.insert(id); // Is now flushable.
                    Ok(())
                }
                Err(e) => {
                    self.remove(&id);
                    Err(e.into())
                }
            }
        } else {
            log::debug!("NOT FOUND ID {id}");
            Err(std::io::ErrorKind::NotFound.into())
        }
    }
}

impl<T: Protocol> Sink<Bytes> for DemuxedDecodedSink<T>
where
    T::Message: Identify,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.set_waker(cx);

        if let Some(task) = self.buffer.take() {
            let id = task.id();

            // Check readiness for both task types.
            if self.as_mut().poll_ready_inner(cx, &id).is_pending() {
                self.buffer = Some(task);
                return Poll::Pending;
            }

            // Ready now, send if needed.
            if let BufTask::ReadyAndSend(msg) = task {
                // Send buffered message, then it needs to be ready again.
                if self.as_mut().start_send_inner(msg).is_ok()
                    && self.as_mut().poll_ready_inner(cx, &id).is_pending()
                {
                    self.buffer = Some(BufTask::Ready(id));
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        if self.buffer.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        match self.decoder.decode(&mut BytesMut::from(bytes)) {
            Ok(Some(msg)) => {
                self.buffer = Some(BufTask::ReadyAndSend(msg));
                // Best effort, at least start the send process now.
                let mut cx = Context::from_waker(Waker::noop());
                let _ = self.as_mut().poll_ready(&mut cx);
                Ok(())
            }
            Ok(None) => Err(io::ErrorKind::InvalidData.into()),
            Err(e) => Err(e.into()),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.set_waker(cx);
        ready!(self.as_mut().poll_ready(cx))?;

        for id in self.dirty.drain().collect::<Vec<u64>>() {
            if let Some(sink) = self.as_mut().project().sinks.get_mut().get_mut(&id) {
                match sink.poll_flush_unpin(cx) {
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(_)) => {
                        self.as_mut().remove(&id);
                    }
                    Poll::Pending => {
                        self.dirty.insert(id);
                    }
                };
            };
        }

        if self.dirty.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.set_waker(cx);
        ready!(self.as_mut().poll_flush(cx))?;

        for id in self.sinks.keys().copied().collect::<Vec<u64>>() {
            if let Some(sink) = self.as_mut().project().sinks.get_mut().get_mut(&id)
                && sink.poll_close_unpin(cx).is_pending()
            {
                continue;
            }
            self.remove(&id);
        }

        if self.sinks.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
