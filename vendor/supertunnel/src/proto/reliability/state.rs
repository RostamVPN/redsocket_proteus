use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use bytes::Bytes;
use futures::channel::oneshot;
use tokio::time::{Instant, Sleep};

use crate::proto::reliability::{Command, Data, DataCursor, ReliabilityMessage};
use crate::sync::PollMutex;

/// A thread-safe wrapper around the core reliability state machine.
///
/// Allows concurrent access from both the read and write halves of the reliability protocol.
pub struct SharedReliabilityState {
    inner: PollMutex<ReliabilityState>,
}

impl Default for SharedReliabilityState {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SharedReliabilityState {
    /// Creates a new `SharedReliabilityState` instance, wrapping the core `ReliabilityState` in a [`PollMutex`].
    pub fn new(rx: Option<oneshot::Receiver<()>>) -> Self {
        Self {
            inner: PollMutex::new(ReliabilityState::new(rx)),
        }
    }

    /// Polls for the next outgoing `ReliabilityMessage` to send.
    ///
    /// This function attempts to lock the shared state and determines the next message to produce,
    /// which could be a data-carrying message, an acknowledgment, or a control message.
    ///
    /// # Inputs
    ///
    /// * `cx: &mut Context` - The task context.
    /// * `payload: Poll<Option<Bytes>>` - The result of polling the underlying data source.
    ///
    /// # Returns
    ///
    /// * `(Poll<Option<ReliabilityMessage>>, Option<Poll<Option<Bytes>>>)` - A tuple where the first
    ///   element is the polled message and the second is the payload if it was not consumed.
    pub fn poll_recv(
        &mut self,
        cx: &mut Context,
        payload: Poll<Option<Bytes>>,
    ) -> (
        Poll<Option<ReliabilityMessage>>,
        Option<Poll<Option<Bytes>>>,
    ) {
        match self.inner.poll_lock(cx) {
            Poll::Ready(mut state) => state.poll_recv(cx, payload),
            Poll::Pending => (Poll::Pending, Some(payload)),
        }
    }

    /// Polls the shared state to process an incoming message and get the resulting payload.
    ///
    /// This is called by the `ReliabilitySink` to process a message received from the peer.
    ///
    /// # Inputs
    ///
    /// * `cx: &mut Context` - The task context.
    /// * `msg: &ReliabilityMessage` - The incoming message to process.
    ///
    /// # Returns
    ///
    /// * `Poll<Option<Bytes>>` - Returns `Poll::Ready(Some(bytes))` if the message contained a
    ///   `Forward` command with data. Otherwise, returns `Poll::Ready(None)` or `Poll::Pending`.
    pub fn poll_send(&mut self, cx: &mut Context, msg: &ReliabilityMessage) -> Poll<Option<Bytes>> {
        let mut state = ready!(self.inner.poll_lock(cx));
        state.send(msg).into()
    }

    /// Polls to close the shared state.
    ///
    /// Marks the session as closed and may queue a `Reset` message to inform the peer.
    ///
    /// # Inputs
    ///
    /// * `cx: &mut Context` - The task context.
    ///
    /// # Returns
    ///
    /// * `Poll<io::Result<()>>` - Returns `Poll::Ready(Ok(()))` on success.
    pub fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut state = ready!(self.inner.poll_lock(cx));
        state.close().into()
    }

    /// Returns `true` if the reliability protocol has completed a graceful shutdown.
    pub async fn is_shutdown_complete(&mut self) -> bool {
        let guard = self.inner.lock().await;
        log::debug!(
            "Checking if shut down: local={:?}, peer={:?}",
            guard.local,
            guard.peer
        );
        guard.local.shut() && (guard.peer.shut() || guard.peer.shutting())
    }
}

impl Clone for SharedReliabilityState {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// The state needed to implement our turbo session protocol that needs to be
/// shared across the session reader and writer forwarding directions.
#[derive(Default)]
struct ReliabilityState {
    /// The stream's waker if it is waiting for us to produce a message.
    stream_waker: Option<Waker>,
    /// The current phase of the protocol in the local->peer direction.
    local: LocalState,
    /// The current phase of the protocol in the peer->local direction.
    peer: PeerState,
    /// The cursor of written and acknowledged data. Data before this cursor was
    /// written and acked, data at and after this cursor was not yet acked.
    write_ack: DataCursor,
    /// The write cursor for the next data we send to the peer.
    write: DataCursor,
    /// The final value of the write cursor once we reached EOF on the source.
    write_end: Option<DataCursor>,
    /// Marks the most recent value of our read cursor that we sent as a read
    /// acknowledgement to the peer.
    read_ack: DataCursor,
    /// The read cursor for data we have successfully received from the peer.
    /// Points to the next write value we expect from the peer.
    read: DataCursor,
    /// The final value of the read cursor.
    read_end: Option<DataCursor>,
    /// A queue for outgoing control messages.
    control_q: VecDeque<Command>,
    /// A queue for outgoing data, gets turned into Command::Forward.
    data_q: VecDeque<Bytes>,
    /// A queue for processing retransmissions.
    retransmit_q: RetransmitQueue,
    /// Drop the receiver to signal that we completed our graceful shutdown.
    shutdown: Option<oneshot::Receiver<()>>,
}

// Governs our outgoing data stream and egress, sending behavior.
#[derive(Default, Debug)]
enum LocalState {
    #[default]
    Open,
    // We have detected an EOF signal on our source and have transmitted all
    // available data. We sent the peer a Shut command and are waiting for
    // a ShutAck acknowledgement that the Shut command was received.
    Shutting(Timer),
    // We are done sending data, and all data and shutdown is acknowledged.
    Shut,
}

impl LocalState {
    fn set(&mut self, new: LocalState) {
        log::debug!("Setting LocalState {:?} -> {:?}", self, new);
        *self = new;
    }
    fn open(&self) -> bool {
        matches!(self, LocalState::Open)
    }
    fn shutting(&self) -> bool {
        matches!(self, LocalState::Shutting(_))
    }
    fn shut(&self) -> bool {
        matches!(self, LocalState::Shut)
    }
    fn as_shutting_mut(&mut self) -> Option<&mut Timer> {
        match self {
            LocalState::Shutting(timer) => Some(timer),
            _ => None,
        }
    }
}

// Governs our incoming data stream and ingress, receiving behavior.
#[derive(Default, Debug)]
enum PeerState {
    #[default]
    Open,
    // We detected a lost message and asked the peer to retransmit from an
    // earlier sequence number. We are waiting for them to restart the stream
    // starting at the lost sequence number.
    Rewinding(DataCursor, Timer),
    // We received a Shut command from the peer. The peer does not intend to
    // send any more new data. We have sent a ShutAck acknowledgement. We are
    // lingering in case they don't receive the ShutAck, in that case they will
    // retransmit the Shut command and we will respond with another ShutAck and
    // reset our Linger timer.
    Shutting(Timer),
    // After receiving a Shut, we have lingered a full period after sending our
    // most recent ShutAck. We now assume they have received the ShutAck.
    Shut,
}

impl PeerState {
    fn set(&mut self, new: PeerState) {
        log::debug!("Setting PeerState {:?} -> {:?}", self, new);
        *self = new;
    }
    fn open(&self) -> bool {
        matches!(self, PeerState::Open)
    }
    fn rewinding(&self) -> bool {
        matches!(self, PeerState::Rewinding(_, _))
    }
    fn shutting(&self) -> bool {
        matches!(self, PeerState::Shutting(_))
    }
    fn shut(&self) -> bool {
        matches!(self, PeerState::Shut)
    }
    fn as_rewinding(&self) -> Option<(&DataCursor, &Timer)> {
        match self {
            PeerState::Rewinding(cursor, timer) => Some((cursor, timer)),
            _ => None,
        }
    }
    fn as_rewinding_mut(&mut self) -> Option<(&mut DataCursor, &mut Timer)> {
        match self {
            PeerState::Rewinding(cursor, timer) => Some((cursor, timer)),
            _ => None,
        }
    }
    pub fn as_shutting_mut(&mut self) -> Option<&mut Timer> {
        match self {
            PeerState::Shutting(linger) => Some(linger),
            _ => None,
        }
    }
}

impl ReliabilityState {
    fn new(rx: Option<oneshot::Receiver<()>>) -> Self {
        Self {
            shutdown: rx,
            ..Default::default()
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        payload: Poll<Option<Bytes>>,
    ) -> (
        Poll<Option<ReliabilityMessage>>,
        Option<Poll<Option<Bytes>>>,
    ) {
        // Always store the latest waker.
        self.set_waker(cx);

        if self.is_payload_next() {
            let result = self.poll_recv_with_payload(cx, payload);
            (result, None)
        } else {
            let result = self.poll_recv_inner(cx);
            (result, Some(payload))
        }
    }

    /// Returns `true` if we want to add payload to the next outgoing message,
    /// `false` otherwise. This informs the caller to read from the source
    /// prior to calling `poll_next()` to provide any available bytes.
    fn is_payload_next(&self) -> bool {
        if self.control_q.is_empty() && self.data_q.is_empty() && self.retransmit_q.is_ready_empty()
        {
            self.local.open() && !self.peer.rewinding()
        } else {
            false
        }
    }

    fn poll_recv_with_payload(
        &mut self,
        cx: &mut Context,
        payload: Poll<Option<Bytes>>,
    ) -> Poll<Option<ReliabilityMessage>> {
        // Should not be called unless is_payload_next() is true.
        assert!(self.is_payload_next());

        // We asked the stream to try reading a payload first and give us the result.
        // The message we return next depends on if a payload is ready or not.
        match payload {
            Poll::Ready(mut opt) => match opt.take() {
                // Forward along the payload.
                Some(bytes) => self.data_q.push_back(bytes),
                // Reader got Error/EOF, so we are done sending payloads now.
                None => {
                    if self.data_q.is_empty() {
                        self.write_end.get_or_insert(self.write);
                    }
                    // Shut down after all written data is acked.
                    self.process_ack(self.write_ack);
                }
            },
            // Already handled in poll_recv_inner().
            Poll::Pending => {}
        };

        // Construct and return any ready messages, or handle Pending logic.
        self.poll_recv_inner(cx)
    }

    fn poll_recv_inner(&mut self, cx: &mut Context) -> Poll<Option<ReliabilityMessage>> {
        // Poll our timers to ensure the new waker gets registered.
        self.poll_timers(cx);

        // Select which message to send.
        if let Some(cmd) = self.control_q.pop_front() {
            assert!(!matches!(cmd, Command::Forward(_)));
            Poll::Ready(Some(self.prepare_control(cmd)))
        } else if let Some(msg) = self.retransmit_q.pop() {
            Poll::Ready(Some(self.prepare_message_ack(msg)))
        } else if let Some(data) = self.data_q.pop_front() {
            Poll::Ready(Some(self.prepare_data(data)))
        } else if self.read_ack < self.read {
            Poll::Ready(Some(self.prepare_control(Command::Acknowledge)))
        } else if self.local.shut() && self.peer.shut() {
            log::debug!("Clearing and returning EOF now");
            self.retransmit_q.clear();
            self.control_q.clear();
            self.data_q.clear();
            self.shutdown.take();
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn poll_timers(&mut self, cx: &mut Context) {
        // Data retransmission timer.
        if self.local.open() && self.retransmit_q.poll(cx).is_ready() {
            log::trace!("Retransmit(Data) timer expired.");
            self.retransmit_q.retransmit_all();
            let _ = self.retransmit_q.poll(cx); // Registers the waker after reset.
        }

        // Rewind retransmission timer.
        if let Some((_, timer)) = self.peer.as_rewinding_mut()
            && timer.poll(cx).is_ready()
        {
            log::trace!("Retransmit(Rewind) timer expired.");
            self.control_q.push_back(Command::Rewind);
            timer.reset();
            let _ = timer.poll(cx); // Registers the waker after reset.
        }

        // Shut retransmission timer.
        if let Some(timer) = self.local.as_shutting_mut()
            && timer.poll(cx).is_ready()
        {
            log::trace!("Retransmit(Shut) timer expired.");
            self.control_q.push_back(Command::Shut);
            timer.reset();
            let _ = timer.poll(cx); // Registers the waker after reset.
        }

        // Last ShutAck Linger timer.
        if let Some(linger) = self.peer.as_shutting_mut()
            && linger.poll(cx).is_ready()
        {
            log::trace!("Linger timer expired.");
            self.peer.set(PeerState::Shut);
        }
    }

    fn prepare_control(&mut self, cmd: Command) -> ReliabilityMessage {
        let write = match &cmd {
            Command::RewindAck => self.write_ack,
            _ => self.write,
        };
        let msg = ReliabilityMessage::new(write, self.read, cmd);
        self.prepare_message_ack(msg)
    }

    fn prepare_data(&mut self, data: Bytes) -> ReliabilityMessage {
        let msg = ReliabilityMessage::new(self.write, self.read, Command::Forward(data.into()));
        self.write += 1;
        self.retransmit_q.push(&msg);
        self.prepare_message_ack(msg)
    }

    fn prepare_message_ack(&mut self, mut msg: ReliabilityMessage) -> ReliabilityMessage {
        // This message satisfies any request to send an ack.
        msg.read = self.read;
        self.read_ack = self.read;
        log::debug!("[{:?}-{:?}]: sending {msg:?}", self.local, self.peer);
        msg
    }

    fn send(&mut self, msg: &ReliabilityMessage) -> Option<Bytes> {
        log::debug!("[{:?}-{:?}]: receiving {msg:?}", self.local, self.peer);
        let mut maybe_bytes = None;

        // Always process acknowledgements.
        self.process_ack(msg.read);

        // Handle out-of-band control commands even if rewinding.
        match &msg.command {
            Command::Rewind => {
                if msg.read >= self.write_ack && msg.read < self.write {
                    self.process_rwd(msg.read);
                }
            }
            Command::RewindAck => self.process_rwd_ack(msg.write),
            Command::Reset => self.process_reset(),
            Command::ShutAck1 => self.process_shut_ack1(msg.read),
            Command::ShutAck2 => self.process_shut_ack2(msg.read),
            _ => {
                let mut process_exact_next_message = false;

                if self.peer.rewinding() {
                    if msg.write == self.read {
                        // Implicitly recover from Rewind.
                        self.process_rwd_ack(msg.write);
                        process_exact_next_message = true;
                    }
                } else {
                    if msg.write == self.read {
                        process_exact_next_message = true;
                    } else if msg.write > self.read {
                        // This is the first time we've seen a gap, so we trigger the rewind.
                        log::debug!(
                            "Detected lost message: expected {} got {}",
                            self.read,
                            msg.write,
                        );
                        self.handle_lost_message_signal(self.read);
                    } else {
                        // This is a duplicate packet from the past (msg.write < self.read).
                        log::trace!("Received duplicate sequence {}; dropping.", msg.write);
                        // Force-send another Ack in case our previous was dropped.
                        if self.peer.open() {
                            self.read_ack = self.read_ack.min(self.read - 1);
                        }
                    }
                }

                if process_exact_next_message {
                    match &msg.command {
                        Command::Forward(payload) => maybe_bytes = self.process_fwd(payload),
                        Command::Shut => self.process_shut(),
                        Command::Acknowledge => {} // Already handled.
                        _ => unreachable!("Control commands should be handled above"),
                    }
                }
            }
        }

        // Wake the stream side if messages are ready.
        if self.need_stream_wakeup() {
            self.wake();
        }
        log::trace!("[{:?}-{:?}]: done receiving", self.local, self.peer);
        maybe_bytes
    }

    fn need_stream_wakeup(&self) -> bool {
        !self.retransmit_q.is_ready_empty()
            || !self.control_q.is_empty()
            || !self.data_q.is_empty()
            || self.read_ack < self.read // Need to send an ack.
            || (self.local.shut() && self.peer.shut())
    }

    fn set_waker(&mut self, cx: &mut Context) {
        match self.stream_waker.as_mut() {
            Some(w) => w.clone_from(cx.waker()),
            None => self.stream_waker = Some(cx.waker().clone()),
        }
        self.retransmit_q.set_waker(cx);
        if let Some((_, timer)) = self.peer.as_rewinding_mut() {
            timer.set_waker(cx);
        }
        if let Some(linger) = self.peer.as_shutting_mut() {
            linger.set_waker(cx);
        }
        if let Some(timer) = self.local.as_shutting_mut() {
            timer.set_waker(cx);
        }
    }

    fn wake(&self) {
        if let Some(waker) = self.stream_waker.as_ref() {
            waker.wake_by_ref()
        }
        // self.waker.take().map(|w| w.wake());
    }

    fn close(&mut self) -> io::Result<()> {
        // The sink will not call send() anymore, so we will never get another message.
        log::debug!(
            "The sink issued a shutdown while in [{:?}-{:?}]",
            self.local,
            self.peer
        );
        let was_open = self.local.open() || self.peer.open();

        // Our protocol requires bidirectional communication. A shutdown means
        // the other end closed, thinking a graceful shutdown has occurred.
        // Treat this as a RESET, immediately setting both sides to shut.
        self.process_reset();

        if was_open {
            log::debug!("Shutdown called while open, queuing a final Reset message");
            // It's possible that data still needed to be transferred.
            self.control_q.push_back(Command::Reset);
        }

        // Wake the stream side to send the reset and/or signal the local EOF.
        self.wake();
        Ok(())
    }

    fn handle_lost_message_signal(&mut self, missing: DataCursor) {
        // Initiate the remote to rewind it's write cursor. Avoid sending
        // multiple rewind messages for the same lost message.
        if self.peer.open()
            || self
                .peer
                .as_rewinding()
                .is_some_and(|(prev, _)| missing < *prev)
        {
            self.peer.set(PeerState::Rewinding(
                missing,
                Timer::from(TimerKind::RetransmitRewind),
            ));
            self.control_q.push_front(Command::Rewind);
        }
    }

    fn process_fwd(&mut self, payload: &Data) -> Option<Bytes> {
        // OK if we are open. If we are rewinding, we wait until synchronized.
        // If we are shutting or shut, we drop the stale retransmits.
        if self.peer.open() {
            // Valid payload, advance the read cursor.
            self.read += 1;
            // Return the payload bytes so they get written.
            Some(payload.chunk.clone())
        } else {
            None
        }
    }

    fn process_ack(&mut self, ack: DataCursor) {
        // Ack sequence numbers are monotonically increasing.
        self.write_ack = self.write_ack.max(ack);

        // Clear retransmit queue of any messages already acked.
        self.retransmit_q.acknowledge(self.write_ack);

        // Transition to the shutting state if we got EOF and everything is acked now.
        if self.local.open() && self.write_end.is_some_and(|x| self.write_ack == x) {
            assert!(self.retransmit_q.is_pending_empty());
            self.local
                .set(LocalState::Shutting(Timer::from(TimerKind::RetransmitShut)));
            self.control_q.push_back(Command::Shut);
        }
    }

    fn process_rwd(&mut self, missing: DataCursor) {
        if !self.local.shut() {
            if self.retransmit_q.negative_acknowledge(missing) {
                log::debug!(
                    "Rewind request for sequence {} approved. Queuing RewindAck.",
                    missing
                );
                self.control_q.push_front(Command::RewindAck);
            } else {
                log::warn!(
                    "Cannot complete rewind request for {}, closing now",
                    missing
                );
                let _ = self.close();
            }
        }
    }

    fn process_rwd_ack(&mut self, rwd_write: DataCursor) {
        // We detected that the peer completed our rewind request.
        if self.peer.rewinding() {
            if rwd_write == self.read {
                log::debug!("Rewind synchronized. Resuming normal operations.");
                self.peer.set(PeerState::Open);
                self.control_q.retain(|cmd| cmd != &Command::Rewind);
            } else {
                log::trace!(
                    "Ignoring stale RewindAck, expected {} got {rwd_write}.",
                    self.read
                );
            }
        } else {
            log::trace!("Ignoring RewindAck in non-rewinding state {:?}", self.peer);
        }
    }

    fn process_shut(&mut self) {
        log::debug!("Processing shut from peer in state {:?}", self.peer);
        match &mut self.peer {
            PeerState::Open => {
                // Store the final position of the read cursor.
                self.read_end.get_or_insert(self.read);
                self.peer
                    .set(PeerState::Shutting(Timer::from(TimerKind::Linger)));
                self.queue_shut_ack();
            }
            PeerState::Rewinding(_, _) => {} // Ignore until Rewind is synchronized.
            PeerState::Shutting(linger) => {
                linger.reset();
                self.queue_shut_ack();
            }
            PeerState::Shut => self.queue_shut_ack(),
        }
    }

    fn queue_shut_ack(&mut self) {
        if self.local.shut() {
            log::debug!("Local is {:?}, queuing ShutAck2", self.local);
            // Signals that I already got their ShutAck too.
            self.control_q.push_back(Command::ShutAck2);
            if self.peer.shutting() {
                // If we get an EOF on the network connection now because the
                // other end is done, consider it a graceful shutdown.
                self.shutdown.take();
            }
        } else {
            log::debug!("Local is {:?}, queuing ShutAck1", self.local);
            // Signals that I did not get their ShutAck yet.
            self.control_q.push_back(Command::ShutAck1);
        }
    }

    fn process_shut_ack1(&mut self, shut_read: DataCursor) {
        if self.local.shutting() && shut_read == self.write {
            self.local.set(LocalState::Shut);
            self.control_q.retain(|cmd| cmd != &Command::Shut);
        }
    }

    fn process_shut_ack2(&mut self, shut_read: DataCursor) {
        if self.local.shutting() && self.peer.shutting() && shut_read == self.write {
            // In addition to acking my Shut, this also acks the ShutAck I
            // previously sent. So I can stop lingering because they will never
            // need the ShutAck retransmitted.
            self.peer.set(PeerState::Shut);
        }
        self.process_shut_ack1(shut_read);
    }

    fn process_reset(&mut self) {
        self.write_end.get_or_insert(self.write);
        self.read_end.get_or_insert(self.read);
        self.local.set(LocalState::Shut);
        self.peer.set(PeerState::Shut);
        self.retransmit_q.clear();
        self.control_q.clear();
        self.data_q.clear();
        self.read_ack = self.read; // No more acks.
    }
}

struct RetransmitQueue {
    /// Min-heap holding messages we already sent but have not yet been acknowledged.
    pending: BinaryHeap<Reverse<ReliabilityMessage>>,
    /// Messages we have determined need to be retransmitted.
    ready: BinaryHeap<Reverse<ReliabilityMessage>>,
    /// A clock to track when we should attempt a fast retransmit.
    timer: Timer,
    waker: Option<Waker>,
}

impl RetransmitQueue {
    fn set_waker(&mut self, cx: &mut Context) {
        match self.waker.as_mut() {
            Some(w) => w.clone_from(cx.waker()),
            None => self.waker = Some(cx.waker().clone()),
        }
        let _ = self.poll(cx);
    }

    fn _wake(&self) {
        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref()
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<()> {
        self.timer.poll(cx)
    }

    fn is_ready_empty(&self) -> bool {
        self.ready.is_empty()
    }

    fn is_pending_empty(&self) -> bool {
        self.pending.is_empty()
    }

    fn push(&mut self, msg: &ReliabilityMessage) {
        assert!(matches!(msg.command, Command::Forward(_)));
        if self.pending.is_empty() {
            self.timer.reset();
        }
        self.pending.push(Reverse(msg.clone()));
    }

    fn pop(&mut self) -> Option<ReliabilityMessage> {
        self.ready.pop().map(|Reverse(msg)| msg)
    }

    fn retransmit_all(&mut self) {
        // Start over retransmitting all pending messages.
        self.ready = self.pending.clone();
        // New retransmissions need time to traverse the network.
        self.timer.reset();
    }

    fn clear(&mut self) {
        self.pending.clear();
        self.ready.clear();
        self.timer.disable();
    }

    fn acknowledge(&mut self, write_ack: DataCursor) {
        while let Some(Reverse(msg)) = self.pending.peek() {
            if msg.write < write_ack {
                self.pending.pop();
                if self.pending.is_empty() {
                    self.timer.disable();
                } else {
                    self.timer.reset();
                }
            } else {
                break;
            }
        }
        while let Some(Reverse(msg)) = self.ready.peek() {
            if msg.write < write_ack {
                self.ready.pop();
            } else {
                break;
            }
        }
    }

    fn negative_acknowledge(&mut self, missing: DataCursor) -> bool {
        // All messages before missing are ACKed.
        self.acknowledge(missing);

        // Retransmit if we have the missing message.
        if self
            .pending
            .peek()
            .is_some_and(|Reverse(msg)| msg.write == missing)
        {
            self.retransmit_all();
            true
        } else {
            false
        }
    }
}

impl Default for RetransmitQueue {
    fn default() -> Self {
        let mut timer = Timer::from(TimerKind::RetransmitData);
        timer.disable();
        Self {
            pending: Default::default(),
            ready: Default::default(),
            timer,
            waker: None,
        }
    }
}

enum TimerKind {
    RetransmitRewind,
    RetransmitShut,
    RetransmitData,
    Linger,
}

impl TimerKind {
    #[cfg(not(test))]
    fn period(&self) -> Duration {
        match self {
            TimerKind::RetransmitRewind => Duration::from_millis(300),
            TimerKind::RetransmitShut => Duration::from_millis(300),
            TimerKind::RetransmitData => Duration::from_millis(3_000),
            TimerKind::Linger => Duration::from_millis(1_000),
        }
    }

    #[cfg(test)]
    fn period(&self) -> Duration {
        match self {
            TimerKind::RetransmitRewind => Duration::from_millis(10),
            TimerKind::RetransmitShut => Duration::from_millis(10),
            TimerKind::RetransmitData => Duration::from_millis(30),
            TimerKind::Linger => Duration::from_millis(100),
        }
    }
}

impl From<TimerKind> for Timer {
    fn from(kind: TimerKind) -> Self {
        Timer::new(kind.period())
    }
}

struct Timer {
    sleep: Pin<Box<Sleep>>,
    period: Duration,
    waker: Option<Waker>,
}

impl Timer {
    fn new(period: Duration) -> Self {
        Self {
            sleep: Box::pin(tokio::time::sleep(period)),
            period,
            waker: None,
        }
    }

    fn set_waker(&mut self, cx: &mut Context) {
        match self.waker.as_mut() {
            Some(w) => w.clone_from(cx.waker()),
            None => self.waker = Some(cx.waker().clone()),
        }
        let _ = self.poll(cx);
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref()
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<()> {
        if self.sleep.as_mut().poll(cx).is_ready()
            || tokio::time::Instant::now() > self.sleep.deadline()
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn reset(&mut self) {
        self.sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + self.period);
        self.wake();
    }

    fn disable(&mut self) {
        let far_duration = Duration::from_hours(24 * 365 * 10); // 10 years
        self.sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + far_duration);
    }
}

impl std::fmt::Debug for Timer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dur = self
            .sleep
            .deadline()
            .saturating_duration_since(Instant::now());
        write!(f, "Timer({dur:?})")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::PollFn;
    use std::task::{Context, Poll, Waker, ready};
    use std::time::Duration;

    use bytes::Bytes;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use tokio_test::task::Spawn;
    use tokio_test::{assert_ready, assert_ready_eq};

    use crate::proto::reliability::message::{Command, Data, ReliabilityMessage};
    use crate::proto::reliability::state::{
        LocalState, PeerState, ReliabilityState, SharedReliabilityState, Timer, TimerKind,
    };
    use crate::test::TestPayload;

    fn payload() -> Bytes {
        TestPayload::bytes(32)
    }

    struct Node<'a> {
        state: SharedReliabilityState,
        _cx: Context<'a>,
        payloads: VecDeque<Bytes>,
        sent: VecDeque<Bytes>,
        received: VecDeque<Bytes>,
        is_shut: bool,
    }

    impl<'a> Node<'a> {
        fn new(n_payoads: usize) -> Self {
            let mut payloads = VecDeque::new();

            for _ in 0..n_payoads {
                payloads.push_back(payload());
            }

            Self {
                state: SharedReliabilityState::new(None),
                // TODO: It would be better to remove this and pass a context
                // directly to the functions that need it.
                _cx: Context::from_waker(Waker::noop()),
                payloads,
                sent: VecDeque::new(),
                received: VecDeque::new(),
                is_shut: false,
            }
        }

        fn next_payload(&mut self) -> Poll<Option<Bytes>> {
            if let Some(data) = self.payloads.pop_front() {
                self.sent.push_back(data.clone());
                Poll::Ready(Some(data))
            } else {
                if self.is_shut {
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            }
        }

        fn shut(&mut self) {
            self.is_shut = true;
        }

        fn get_msg(
            &self,
            payload: Poll<Option<Bytes>>,
        ) -> Spawn<PollFn<impl FnMut(&mut Context) -> Poll<Option<ReliabilityMessage>>>> {
            let mut shared = self.state.clone();
            tokio_test::task::spawn(std::future::poll_fn(move |cx| {
                let (result, _) = shared.poll_recv(cx, payload.clone());
                result
            }))
        }

        fn put_msg(
            &self,
            msg: &ReliabilityMessage,
        ) -> Spawn<PollFn<impl FnMut(&mut Context) -> Poll<Option<Bytes>>>> {
            let mut shared = self.state.clone();
            tokio_test::task::spawn(std::future::poll_fn(move |cx| shared.poll_send(cx, msg)))
        }

        fn get_msg2(&mut self) -> Poll<Option<ReliabilityMessage>> {
            let poll_data = self.next_payload();

            let (poll_msg, returned_data) = self.state.poll_recv(&mut self._cx, poll_data);

            if let Some(Poll::Ready(Some(data))) = returned_data {
                self.sent.pop_back();
                self.payloads.push_front(data);
            }

            poll_msg
        }

        fn get_msg2_assert<F>(&mut self, condition: F) -> ReliabilityMessage
        where
            F: Fn(&ReliabilityMessage) -> bool,
        {
            let Poll::Ready(Some(msg)) = self.get_msg2() else {
                panic!("Expected ready message");
            };
            assert!(condition(&msg));
            msg
        }

        fn put_msg2(&mut self, msg: ReliabilityMessage) -> Poll<()> {
            if let Some(data) = ready!(self.state.poll_send(&mut self._cx, &msg)) {
                self.received.push_back(data);
            }
            Poll::Ready(())
        }

        fn close(&self) -> Spawn<PollFn<impl FnMut(&mut Context) -> Poll<std::io::Result<()>>>> {
            let mut shared = self.state.clone();
            tokio_test::task::spawn(std::future::poll_fn(move |cx| shared.poll_close(cx)))
        }

        async fn assert_local_state<F>(&mut self, condition: F)
        where
            F: Fn(&LocalState) -> bool,
        {
            assert!(condition(&self.state.inner.lock().await.local));
        }

        async fn assert_peer_state<F>(&mut self, condition: F)
        where
            F: Fn(&PeerState) -> bool,
        {
            assert!(condition(&self.state.inner.lock().await.peer));
        }

        async fn assert_both_open(&mut self) {
            let guard = self.state.inner.lock().await;
            assert!(guard.local.open());
            assert!(guard.peer.open());
        }

        async fn assert_both_shutting(&mut self) {
            let guard = self.state.inner.lock().await;
            assert!(guard.local.shutting());
            assert!(guard.peer.shutting());
        }

        async fn assert_both_shut(&mut self) {
            let guard = self.state.inner.lock().await;
            assert!(guard.local.shut());
            assert!(guard.peer.shut());
        }

        async fn check_both_shut(&mut self) -> bool {
            let guard = self.state.inner.lock().await;
            guard.local.shut() && guard.peer.shut()
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq)]
    enum Drop {
        None,
        Forward,
        Rewind,
        Ack,
        Shut,
        ShutAck,
    }

    impl Drop {
        fn matches(&self, msg: &ReliabilityMessage) -> bool {
            match self {
                Drop::None => false,
                Drop::Forward => matches!(msg.command, Command::Forward(_)),
                Drop::Rewind => matches!(msg.command, Command::Rewind),
                Drop::Ack => matches!(msg.command, Command::Acknowledge),
                Drop::Shut => matches!(msg.command, Command::Shut),
                Drop::ShutAck => matches!(msg.command, Command::ShutAck1 | Command::ShutAck2),
            }
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq)]
    enum StepResult {
        Dropped,
        Fowarded,
        Pending,
        Eof,
    }

    struct NodePair<'a> {
        local: Node<'a>,
        remote: Node<'a>,
        rng: StdRng,
    }

    impl<'a> NodePair<'a> {
        fn new(n_payloads_local: usize, n_paylaods_remote: usize, seed: u64) -> Self {
            Self {
                local: Node::new(n_payloads_local),
                remote: Node::new(n_paylaods_remote),
                rng: StdRng::seed_from_u64(seed),
            }
        }

        fn step(src: &mut Node, dst: &mut Node, drop: Drop) -> StepResult {
            match src.get_msg2() {
                Poll::Ready(Some(msg)) => {
                    if drop.matches(&msg) {
                        StepResult::Dropped
                    } else {
                        let _ = dst.put_msg2(msg);
                        StepResult::Fowarded
                    }
                }
                Poll::Ready(None) => StepResult::Eof,
                Poll::Pending => StepResult::Pending,
            }
        }

        fn drain(src: &mut Node, dst: &mut Node, drop: Drop) {
            let mut drop_next = drop;
            loop {
                match Self::step(src, dst, drop_next) {
                    StepResult::Dropped => drop_next = Drop::None,
                    StepResult::Fowarded => continue,
                    StepResult::Pending => return,
                    StepResult::Eof => return,
                }
            }
        }

        fn drain_local(&mut self, drop: Drop) {
            Self::drain(&mut self.local, &mut self.remote, drop);
        }

        fn drain_remote(&mut self, drop: Drop) {
            Self::drain(&mut self.remote, &mut self.local, drop);
        }

        // Transfer messages between Local and Remote under randomized drop
        // scenarios. Automatically advances virtual time to fire RTO timers if
        // both channels are idle.
        async fn drain_chaos(&mut self, drop_percentage: u8) {
            assert!(
                drop_percentage <= 100,
                "Drop percentage must be between 0 and 100"
            );
            let mut idle_cycles = 0;
            let max_idle_allowed = 100; // Hard boundary to identify infinite loops / deadlocks

            loop {
                let mut activity = false;

                // Local -> Remote direction.
                if let Poll::Ready(Some(msg)) = self.local.get_msg2() {
                    activity = true;
                    if self.rng.random_range(0..100) >= drop_percentage {
                        let _ = self.remote.put_msg2(msg);
                    } else {
                        log::warn!("Chaos [Local->Remote]: Dropped {:?}", msg.command);
                    }
                }

                // Remote -> Local direction.
                if let Poll::Ready(Some(msg)) = self.remote.get_msg2() {
                    activity = true;
                    if self.rng.random_range(0..100) >= drop_percentage {
                        let _ = self.local.put_msg2(msg);
                    } else {
                        log::warn!("Chaos [Remote->Local]: Dropped {:?}", msg.command);
                    }
                }

                if activity {
                    idle_cycles = 0;
                } else {
                    idle_cycles += 1;

                    // If both ends successfully converged to a complete close, exit.
                    if self.local.check_both_shut().await && self.remote.check_both_shut().await {
                        break;
                    }

                    if idle_cycles > max_idle_allowed {
                        panic!("Deadlock detected! Both nodes went idle without finishing.");
                    }

                    // No active messages were produced. Advance virtual clock to fire RTO timers.
                    tokio::time::sleep(TimerKind::RetransmitData.period()).await;

                    // Wake both tasks manually to simulate background timer triggers.
                    // self.local.state.inner.lock().await.wake();
                    // self.remote.state.inner.lock().await.wake();
                }
                tokio::task::yield_now().await;
            }
        }

        fn sync(&mut self) {
            loop {
                let local = Self::step(&mut self.local, &mut self.remote, Drop::None);
                let remote = Self::step(&mut self.remote, &mut self.local, Drop::None);
                if matches!(local, StepResult::Pending | StepResult::Eof)
                    && matches!(remote, StepResult::Pending | StepResult::Eof)
                {
                    return;
                }
                // tokio::task::yield_now().await;
            }
        }

        async fn shut_and_sync_to_eof(&mut self) {
            self.local.shut();
            self.remote.shut();
            self.sync();
            loop {
                let local = Self::step(&mut self.local, &mut self.remote, Drop::None);
                let remote = Self::step(&mut self.remote, &mut self.local, Drop::None);
                if local == StepResult::Eof && remote == StepResult::Eof {
                    return;
                }
                tokio::time::sleep(TimerKind::Linger.period()).await;
                tokio::task::yield_now().await;
            }
        }

        async fn assert_all_open(&mut self) {
            self.local.assert_both_open().await;
            self.remote.assert_both_open().await;
        }

        async fn assert_all_shutting(&mut self) {
            self.local.assert_both_shutting().await;
            self.remote.assert_both_shutting().await;
        }

        async fn assert_all_shut(&mut self) {
            self.local.assert_both_shut().await;
            self.remote.assert_both_shut().await;
        }

        fn assert_transfer(src: &mut Node, dst: &mut Node) {
            assert_eq!(src.sent.len(), dst.received.len());
            while let Some(l_data) = src.sent.pop_front()
                && let Some(r_data) = dst.received.pop_front()
            {
                assert_eq!(l_data, r_data);
            }
        }

        fn assert_transfers(&mut self) {
            Self::assert_transfer(&mut self.local, &mut self.remote);
            Self::assert_transfer(&mut self.remote, &mut self.local);
        }
    }

    #[tokio::test]
    async fn new_default() {
        let ts = ReliabilityState::default();
        assert!(ts.local.open());
        assert!(ts.peer.open());
    }

    #[tokio::test]
    async fn new_wants_payload() {
        let ts = ReliabilityState::default();
        assert!(ts.is_payload_next());
    }

    async fn wakeup_on_msg(remote_msg: ReliabilityMessage) {
        let node = Node::new(0);

        // Local payload is pending, outgoing message is pending.
        let mut out_task = node.get_msg(Poll::Pending);
        assert_eq!(out_task.poll(), Poll::Pending);
        assert!(!out_task.is_woken());

        // When remote message arrives, outgoing message is ready.
        let _ = node.put_msg(&remote_msg).await;
        assert!(out_task.is_woken());
    }

    #[tokio::test]
    async fn wakeup_for_ack() {
        wakeup_on_msg(ReliabilityMessage::forward(0, 0, payload())).await
    }

    #[tokio::test]
    async fn wakeup_for_reset() {
        wakeup_on_msg(ReliabilityMessage::reset(0, 0)).await
    }

    #[tokio::test]
    async fn wakeup_on_close() {
        let node = Node::new(0);
        let mut out_task = node.get_msg(Poll::Pending);
        assert_eq!(out_task.poll(), Poll::Pending);
        assert!(!out_task.is_woken());
        let _ = node.close().await;
        assert!(out_task.is_woken());
    }

    #[tokio::test]
    async fn timer_pending_no_wakeup() {
        let mut timer = Timer::new(Duration::from_hours(1));

        let mut task = tokio_test::task::spawn(std::future::poll_fn(move |cx| timer.poll(cx)));
        assert!(task.poll().is_pending()); // register waker

        assert!(!task.is_woken());
        assert!(task.poll().is_pending());
    }

    #[tokio::test]
    async fn timer_wakeup_on_ready() {
        let step = Duration::from_millis(1);
        let mut timer = Timer::new(step);

        let mut task = tokio_test::task::spawn(std::future::poll_fn(move |cx| timer.poll(cx)));
        let _ = task.poll(); // register waker

        tokio::time::sleep(step).await;
        assert!(task.is_woken());
        assert!(task.poll().is_ready());
    }

    #[tokio::test]
    async fn timer_expired_ready() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let step = Duration::from_millis(1);
        let mut timer = Timer::new(step);

        tokio::time::sleep(step).await;
        assert!(timer.poll(&mut cx).is_ready());
    }

    #[tokio::test]
    async fn timer_expired_ready_new_context() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let step = Duration::from_millis(1);
        let mut timer = Timer::new(step);
        let _ = timer.poll(&mut cx);

        tokio::time::sleep(step).await;

        let waker2 = Waker::noop();
        let mut cx2 = Context::from_waker(waker2);
        assert!(timer.poll(&mut cx2).is_ready());
    }

    #[tokio::test]
    async fn timer_reset_pending() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let step = Duration::from_hours(1);
        let mut timer = Timer::new(step);
        assert!(timer.poll(&mut cx).is_pending());

        timer.reset();
        assert!(timer.poll(&mut cx).is_pending());
    }

    #[tokio::test]
    async fn timer_pending_reset_ready() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let step = Duration::from_millis(1);
        let mut timer = Timer::new(step);
        assert!(timer.poll(&mut cx).is_pending());

        timer.reset();
        assert!(timer.poll(&mut cx).is_pending());

        tokio::time::sleep(step).await;
        assert!(timer.poll(&mut cx).is_ready());
    }

    #[tokio::test]
    async fn timer_ready_reset_ready() {
        let step = Duration::from_millis(1);
        let mut timer = Timer::new(step);

        for _ in 0..3 {
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            assert!(timer.poll(&mut cx).is_pending());
            tokio::time::sleep(step).await;
            assert!(timer.poll(&mut cx).is_ready());
            timer.reset();
        }
    }

    fn assert_ready_command(result: Poll<Option<ReliabilityMessage>>, cmd: Command) {
        let maybe_msg = assert_ready!(result);
        assert!(maybe_msg.is_some());
        let msg = maybe_msg.unwrap();
        assert_eq!(msg.command, cmd);
    }

    fn assert_ready_payload(result: Poll<Option<ReliabilityMessage>>, data: Bytes) {
        assert_ready_command(result, Command::Forward(Data { chunk: data }));
    }

    #[tokio::test]
    async fn sequential_forward() {
        let mut node = Node::new(10);
        while let Some(data) = node.payloads.pop_front() {
            let result = node.get_msg(Poll::Ready(Some(data.clone()))).poll();
            assert_ready_payload(result, data.clone());
        }
    }

    #[tokio::test]
    async fn cumulative_ack_with_payload() {
        let node = Node::new(0);
        for w_cursor in 0..10 {
            node.put_msg(&ReliabilityMessage::forward(w_cursor, 0, payload()))
                .await;
        }
        // Ack all 10 packets while including payload of our own.
        let data = payload();
        let result = node.get_msg(Poll::Ready(Some(data.clone()))).poll();
        assert_ready_eq!(result, Some(ReliabilityMessage::forward(0, 10, data)));
    }

    #[tokio::test]
    async fn cumulative_ack_without_payload() {
        let node = Node::new(0);
        for w_cursor in 0..10 {
            node.put_msg(&ReliabilityMessage::forward(w_cursor, 0, payload()))
                .await;
        }
        // Ack all 10 packets even with no payload present.
        let result = node.get_msg(Poll::Pending).poll();
        assert_ready_eq!(result, Some(ReliabilityMessage::acknowledge(0, 10)));
    }

    #[tokio::test]
    async fn consecutive_shut() {
        // Maybe if i send an ack again after the ShutAck, stop lingering.
        let mut pair = NodePair::new(10, 10, 0);

        // Forward and ack all data.
        pair.drain_local(Drop::None);
        pair.drain_remote(Drop::None);
        pair.sync();

        pair.assert_all_open().await;

        // Local->Remote: Shut
        pair.local.shut();
        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);
        pair.local
            .assert_local_state(|s| matches!(s, LocalState::Shutting(_)))
            .await;
        pair.remote
            .assert_peer_state(|s| matches!(s, PeerState::Shutting(_)))
            .await;

        // Remote->Local: ShutAck
        NodePair::step(&mut pair.remote, &mut pair.local, Drop::None);

        // Remote->Local: Shut
        pair.remote.shut();
        NodePair::step(&mut pair.remote, &mut pair.local, Drop::None);
        pair.remote
            .assert_local_state(|s| matches!(s, LocalState::Shutting(_)))
            .await;
        pair.local
            .assert_peer_state(|s| matches!(s, PeerState::Shutting(_)))
            .await;

        // Local->Remote: ShutAck
        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);

        pair.shut_and_sync_to_eof().await;
        pair.assert_all_shut().await;
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn simultaneous_shut() {
        let mut pair = NodePair::new(10, 10, 0);
        pair.sync();

        pair.local.shut();
        pair.remote.shut();

        // Both send a Shut into the network.
        let local_shut_msg = pair
            .local
            .get_msg2_assert(|msg| msg.command == Command::Shut);
        let remote_shut_msg = pair
            .remote
            .get_msg2_assert(|msg| msg.command == Command::Shut);

        // The network delivers to each side at the same time.
        assert!(pair.remote.put_msg2(local_shut_msg).is_ready());
        assert!(pair.local.put_msg2(remote_shut_msg).is_ready());

        pair.assert_all_shutting().await;

        // Both send a ShutAck into the network.
        let local_ack_msg = pair
            .local
            .get_msg2_assert(|msg| msg.command == Command::ShutAck1);
        let remote_ack_msg = pair
            .remote
            .get_msg2_assert(|msg| msg.command == Command::ShutAck1);

        // The network delivers to each side at the same time.
        assert!(pair.remote.put_msg2(local_ack_msg).is_ready());
        assert!(pair.local.put_msg2(remote_ack_msg).is_ready());

        pair.shut_and_sync_to_eof().await;
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn rewind_first() {
        let mut pair = NodePair::new(10, 0, 0);

        // Drop first message.
        assert_eq!(
            NodePair::step(&mut pair.local, &mut pair.remote, Drop::Forward),
            StepResult::Dropped
        );

        // Gap is detected on second message.
        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);

        // Now in rewind state.
        pair.remote
            .assert_peer_state(|s| matches!(s, PeerState::Rewinding(_, _)))
            .await;

        // Transfers should complete without shutting.
        pair.sync();
        pair.assert_transfers();
    }

    fn last_data_dropped_setup<'a>() -> NodePair<'a> {
        let mut pair = NodePair::new(10, 0, 0);

        // Send the first n-1 messages.
        for _ in 0..9 {
            NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);
        }
        // Ack them.
        pair.drain_remote(Drop::None);

        // Drop the last message.
        assert_eq!(
            NodePair::step(&mut pair.local, &mut pair.remote, Drop::Forward),
            StepResult::Dropped
        );

        pair.sync();
        pair
    }

    #[tokio::test]
    #[should_panic]
    async fn last_data_dropped_without_timeout() {
        // The lost message will never be detected.
        let mut pair = last_data_dropped_setup();
        pair.sync();
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn last_data_dropped_with_timeout() {
        let mut pair = last_data_dropped_setup();

        // The sender is waiting for an ack that will never come, because it was
        // dropped. The receiver hasn't detected the lost message yet, so it
        // does not know to ask for a Rewind. The sender implicitly detects the
        // loss event after a timeout and retransmits the lost data message.
        tokio::time::sleep(TimerKind::RetransmitData.period()).await;

        // Transfers should now complete without shutting.
        pair.sync();
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn simultaneous_rewind() {
        let mut pair = NodePair::new(10, 10, 0);

        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);
        NodePair::step(&mut pair.remote, &mut pair.local, Drop::None);

        assert_eq!(
            NodePair::step(&mut pair.local, &mut pair.remote, Drop::Forward),
            StepResult::Dropped
        );
        assert_eq!(
            NodePair::step(&mut pair.remote, &mut pair.local, Drop::Forward),
            StepResult::Dropped
        );

        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);
        NodePair::step(&mut pair.remote, &mut pair.local, Drop::None);

        pair.sync();
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn rewind_dropped() {
        let mut pair = NodePair::new(10, 0, 0);

        // Forward and ack.
        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);
        NodePair::step(&mut pair.remote, &mut pair.local, Drop::None);

        // Drop forward and then drop rewind.
        assert_eq!(
            NodePair::step(&mut pair.local, &mut pair.remote, Drop::Forward),
            StepResult::Dropped
        );
        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);
        assert_eq!(
            NodePair::step(&mut pair.remote, &mut pair.local, Drop::Rewind),
            StepResult::Dropped
        );

        pair.sync();
        tokio::time::sleep(TimerKind::RetransmitRewind.period()).await;
        pair.sync();

        pair.assert_all_open().await;
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn ack_dropped() {
        let mut pair = NodePair::new(1, 0, 0);

        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);
        assert_eq!(
            NodePair::step(&mut pair.remote, &mut pair.local, Drop::Ack),
            StepResult::Dropped
        );

        pair.sync();
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn first_shut_dropped() {
        let mut pair = NodePair::new(1, 0, 0);

        pair.sync();
        pair.local.shut();

        assert_eq!(
            NodePair::step(&mut pair.local, &mut pair.remote, Drop::Shut),
            StepResult::Dropped
        );

        pair.sync();
        tokio::time::sleep(TimerKind::RetransmitShut.period()).await;
        pair.sync();

        pair.local
            .assert_local_state(|s| matches!(s, LocalState::Shut))
            .await;
        pair.remote
            .assert_peer_state(|s| matches!(s, PeerState::Shutting(_)))
            .await;

        pair.assert_transfers();
    }

    #[tokio::test]
    async fn first_shut_ack_dropped() {
        let mut pair = NodePair::new(1, 0, 0);

        pair.sync();
        pair.local.shut();
        NodePair::step(&mut pair.local, &mut pair.remote, Drop::None);

        assert_eq!(
            NodePair::step(&mut pair.remote, &mut pair.local, Drop::ShutAck),
            StepResult::Dropped
        );

        pair.sync();
        tokio::time::sleep(TimerKind::RetransmitShut.period()).await;
        pair.sync();

        pair.local
            .assert_local_state(|s| matches!(s, LocalState::Shut))
            .await;
        pair.remote
            .assert_peer_state(|s| matches!(s, PeerState::Shutting(_)))
            .await;
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn second_shut_dropped() {
        let mut pair = NodePair::new(1, 1, 0);

        pair.sync();
        pair.local.shut();
        pair.sync();
        pair.remote.shut();

        assert_eq!(
            NodePair::step(&mut pair.remote, &mut pair.local, Drop::Shut),
            StepResult::Dropped
        );

        pair.shut_and_sync_to_eof().await;
        pair.assert_all_shut().await;
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn second_shut_ack_dropped() {
        let mut pair = NodePair::new(1, 1, 0);

        pair.sync();
        pair.local.shut();
        pair.sync();
        pair.remote.shut();
        NodePair::step(&mut pair.remote, &mut pair.local, Drop::None);

        assert_eq!(
            NodePair::step(&mut pair.local, &mut pair.remote, Drop::ShutAck),
            StepResult::Dropped
        );

        pair.shut_and_sync_to_eof().await;
        pair.assert_all_shut().await;
        pair.assert_transfers();
    }

    async fn chaos_test(n_local: usize, n_remote: usize, seed: u64, drop_perc: u8) {
        let mut pair = NodePair::new(n_local, n_remote, seed);

        // Initiate shutdown sequences early to test overlapped teardown + drop recovery.
        pair.local.shut();
        pair.remote.shut();

        // Run with the given message drop percentage.
        pair.drain_chaos(drop_perc).await;

        // Verify that we ended in the correct terminal states.
        pair.assert_all_shut().await;

        // Ensure 100% data integrity with no missing or scrambled bytes.
        pair.assert_transfers();
    }

    #[tokio::test]
    async fn chaos_5_percent_drop() {
        // let _ = env_logger::try_init();
        chaos_test(1000, 1000, 50505, 5).await;
    }

    #[tokio::test]
    async fn chaos_5_percent_drop_asym1() {
        // let _ = env_logger::try_init();
        chaos_test(10, 100, 10100, 5).await;
    }

    #[tokio::test]
    async fn chaos_5_percent_drop_asym2() {
        // let _ = env_logger::try_init();
        chaos_test(100, 10, 10010, 5).await;
    }

    #[tokio::test]
    async fn chaos_30_percent_drop() {
        // let _ = env_logger::try_init();
        chaos_test(80, 80, 303030, 30).await;
    }

    #[tokio::test]
    async fn chaos_60_percent_drop() {
        // let _ = env_logger::try_init();
        chaos_test(40, 40, 606060, 60).await;
    }

    #[tokio::test]
    async fn chaos_90_percent_drop() {
        // let _ = env_logger::try_init();
        chaos_test(20, 20, 909090, 90).await;
    }

    #[tokio::test]
    async fn chaos_95_percent_drop() {
        // let _ = env_logger::try_init();
        chaos_test(10, 10, 959595, 95).await;
    }
}
