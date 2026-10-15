// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Standalone, synchronous Noise transport FRAMING state machine.

use snow::TransportState;

/// Maximum size of a single Noise transport message (ciphertext incl. tag).
/// snow refuses to write/read messages larger than this.
const MAX_NOISE_MSG: usize = 65535;

/// ChaChaPoly authentication tag length appended by Noise to every message.
const TAG_LEN: usize = 16;

/// Maximum plaintext we place in a single frame so that the resulting
/// ciphertext (plaintext + 16B tag) still fits under `MAX_NOISE_MSG`.
const MAX_PLAINTEXT_PER_FRAME: usize = MAX_NOISE_MSG - TAG_LEN;

/// Number of bytes in the length prefix.
const LEN_PREFIX: usize = 2;

#[derive(Debug)]
pub enum NoiseError {
    /// snow decrypt failed (AEAD tag mismatch, out-of-order nonce, etc.).
    Decrypt(String),
    /// snow encrypt failed.
    Encrypt(String),
    /// A frame declared a ciphertext length that cannot be valid (0 or > cap).
    BadLength(usize),
}

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoiseError::Decrypt(e) => write!(f, "noise decrypt failed: {e}"),
            NoiseError::Encrypt(e) => write!(f, "noise encrypt failed: {e}"),
            NoiseError::BadLength(n) => write!(f, "invalid frame ciphertext length: {n}"),
        }
    }
}

impl std::error::Error for NoiseError {}

/// Synchronous, push-based Noise transport framer.
pub struct NoiseFramer {
    session: TransportState,
    carry: Vec<u8>,
}

impl NoiseFramer {
    /// Build from an already-handshaked transport state.
    pub fn new(session: TransportState) -> Self {
        Self {
            session,
            carry: Vec::new(),
        }
    }

    /// Stats inbound ciphertext bytes.
    pub fn feed_inbound(&mut self, data: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.carry.extend_from_slice(data);

        let mut out = Vec::new();
        let mut consumed = 0usize;

        loop {
            let remaining = &self.carry[consumed..];

            if remaining.len() < LEN_PREFIX {
                break;
            }

            let ct_len = u16::from_be_bytes([remaining[0], remaining[1]]) as usize;

            if !(TAG_LEN..=MAX_NOISE_MSG).contains(&ct_len) {
                return Err(NoiseError::BadLength(ct_len));
            }

            let frame_total = LEN_PREFIX + ct_len;

            if remaining.len() < frame_total {
                break;
            }

            let ciphertext = &remaining[LEN_PREFIX..frame_total];

            let mut plaintext = vec![0u8; ct_len];
            let n = self
                .session
                .read_message(ciphertext, &mut plaintext)
                .map_err(|e| NoiseError::Decrypt(e.to_string()))?;
            plaintext.truncate(n);
            out.extend_from_slice(&plaintext);

            consumed += frame_total;
        }

        if consumed > 0 {
            self.carry.drain(..consumed);
        }

        Ok(out)
    }

    /// Encrypt `plaintext` into framed outbound bytes: one or more `[u16 len][ct]`
    /// frames.
    pub fn frame_outbound(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = Vec::new();

        let mut chunks = plaintext.chunks(MAX_PLAINTEXT_PER_FRAME);

        let mut wrote_any = false;

        for chunk in chunks.by_ref() {
            self.write_frame(chunk, &mut out)?;
            wrote_any = true;
        }
        if !wrote_any {
            self.write_frame(&[], &mut out)?;
        }

        Ok(out)
    }

    /// Encrypt one plaintext chunk and append its `[u16 len][ct]` frame to `out`.
    fn write_frame(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), NoiseError> {
        debug_assert!(chunk.len() <= MAX_PLAINTEXT_PER_FRAME);
        let mut ciphertext = vec![0u8; chunk.len() + TAG_LEN];
        let n = self
            .session
            .write_message(chunk, &mut ciphertext)
            .map_err(|e| NoiseError::Encrypt(e.to_string()))?;
        ciphertext.truncate(n);

        out.extend_from_slice(&(n as u16).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real handshaked NK pair — framing is only meaningful against actual AEAD
    /// state, and a mock would not catch nonce-ordering mistakes.
    fn pair() -> (NoiseFramer, NoiseFramer) {
        let params: snow::params::NoiseParams =
            "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let kp = snow::Builder::new(params.clone())
            .generate_keypair()
            .unwrap();
        let mut init = snow::Builder::new(params.clone())
            .remote_public_key(&kp.public)
            .build_initiator()
            .unwrap();
        let mut resp = snow::Builder::new(params)
            .local_private_key(&kp.private)
            .build_responder()
            .unwrap();
        let mut a = [0u8; 2048];
        let n = init.write_message(&[], &mut a).unwrap();
        let mut b = [0u8; 2048];
        resp.read_message(&a[..n], &mut b).unwrap();
        let n = resp.write_message(&[], &mut b).unwrap();
        let mut c = [0u8; 2048];
        init.read_message(&b[..n], &mut c).unwrap();
        (
            NoiseFramer::new(init.into_transport_mode().unwrap()),
            NoiseFramer::new(resp.into_transport_mode().unwrap()),
        )
    }

    #[test]
    fn a_frame_round_trips() {
        let (mut tx, mut rx) = pair();
        let wire = tx.frame_outbound(b"hello framer").unwrap();
        assert_eq!(rx.feed_inbound(&wire).unwrap(), b"hello framer");
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let (mut tx, mut rx) = pair();
        let wire = tx.frame_outbound(&[]).unwrap();
        assert_eq!(rx.feed_inbound(&wire).unwrap(), Vec::<u8>::new());
    }

    /// TCP splits wherever it likes. A frame cut mid-length-prefix or mid-
    /// ciphertext must be carried and completed, exactly once.
    #[test]
    fn a_frame_split_at_every_offset_reassembles() {
        let payload: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
        for split in 1..(2 + 16 + payload.len()) {
            let (mut tx, mut rx) = pair();
            let wire = tx.frame_outbound(&payload).unwrap();
            if split >= wire.len() {
                break;
            }
            let mut got = rx.feed_inbound(&wire[..split]).unwrap();
            got.extend(rx.feed_inbound(&wire[split..]).unwrap());
            assert_eq!(got, payload, "split at {split}");
        }
    }

    #[test]
    fn several_frames_in_one_read_decrypt_in_order() {
        let (mut tx, mut rx) = pair();
        let mut wire = tx.frame_outbound(b"one").unwrap();
        wire.extend(tx.frame_outbound(b"two").unwrap());
        wire.extend(tx.frame_outbound(b"three").unwrap());
        assert_eq!(rx.feed_inbound(&wire).unwrap(), b"onetwothree");
    }

    /// Plaintext larger than one Noise message must be split across frames by the
    /// sender and rejoined transparently by the receiver.
    #[test]
    fn oversized_plaintext_is_split_and_rejoined() {
        let big: Vec<u8> = (0..(MAX_PLAINTEXT_PER_FRAME * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let (mut tx, mut rx) = pair();
        let wire = tx.frame_outbound(&big).unwrap();
        assert!(wire.len() > MAX_NOISE_MSG, "expected multiple frames");
        assert_eq!(rx.feed_inbound(&wire).unwrap(), big);
    }

    #[test]
    fn a_partial_frame_yields_nothing_yet_and_is_not_lost() {
        let (mut tx, mut rx) = pair();
        let wire = tx.frame_outbound(b"patience").unwrap();
        assert!(rx.feed_inbound(&wire[..1]).unwrap().is_empty());
        assert!(rx.feed_inbound(&wire[1..3]).unwrap().is_empty());
        assert_eq!(rx.feed_inbound(&wire[3..]).unwrap(), b"patience");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut tx, mut rx) = pair();
        let mut wire = tx.frame_outbound(b"authentic").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;
        assert!(rx.feed_inbound(&wire).is_err(), "AEAD tag forgery accepted");
    }

    #[test]
    fn frames_replayed_out_of_order_are_rejected() {
        let (mut tx, mut rx) = pair();
        let first = tx.frame_outbound(b"first").unwrap();
        let second = tx.frame_outbound(b"second").unwrap();

        assert!(
            rx.feed_inbound(&second).is_err(),
            "out-of-order frame accepted"
        );
        let _ = first;
    }
}
