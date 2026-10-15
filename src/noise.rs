// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Noise NK Transport — Noise_NK_25519_ChaChaPoly_BLAKE2s.

use snow::{Builder, TransportState};

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;
/// Stack scratch for the handshake reply we generate. `Noise_NK`'s msg2 with an
/// empty payload is `e || tag` = 48 bytes; 1 KiB is 20x headroom and, unlike
/// [`MAX_NOISE_MSG`], is not a per-session heap allocation.
const MSG2_SCRATCH: usize = 1024;

pub struct NoiseSession {
    transport: TransportState,
}

pub struct NoiseHandshake {
    state: snow::HandshakeState,
}

impl NoiseHandshake {
    pub fn new_responder(server_private_key: &[u8; 32]) -> anyhow::Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let state = builder
            .local_private_key(server_private_key)
            .build_responder()?;
        Ok(Self { state })
    }

    /// Try each candidate key until one decrypts msg1 (key rotation). snow consumes
    /// the handshake state on a failed read, so each attempt builds a fresh
    /// responder. Returns the winning handshake + msg2.
    pub fn process_msg1_multi(
        msg1: &[u8],
        keys: &[[u8; 32]],
    ) -> anyhow::Result<(NoiseHandshake, Vec<u8>)> {
        let mut last_err = anyhow::anyhow!("no keys configured");
        for (i, key) in keys.iter().enumerate() {
            match Self::new_responder(key).and_then(|mut h| {
                let msg2 = h.process_msg1(msg1)?;
                Ok((h, msg2))
            }) {
                Ok(ok) => {
                    if i > 0 {
                        log::debug!("[Noise] handshake succeeded with extra key #{}", i);
                    }
                    return Ok(ok);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err.context("all keys failed to decrypt msg1"))
    }

    pub fn process_msg1(&mut self, msg1: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut read_buf = vec![0u8; msg1.len()];
        self.state
            .read_message(msg1, &mut read_buf)
            .map_err(|e| anyhow::anyhow!("Noise handshake msg1 read failed: {}", e))?;

        let mut msg2_buf = [0u8; MSG2_SCRATCH];
        match self.state.write_message(&[], &mut msg2_buf) {
            Ok(len) => Ok(msg2_buf[..len].to_vec()),

            Err(snow::Error::Input) => {
                let mut big = vec![0u8; MAX_NOISE_MSG];
                let len = self
                    .state
                    .write_message(&[], &mut big)
                    .map_err(|e| anyhow::anyhow!("Noise handshake msg2 write failed: {}", e))?;
                big.truncate(len);
                Ok(big)
            }
            Err(e) => Err(anyhow::anyhow!("Noise handshake msg2 write failed: {}", e)),
        }
    }

    pub fn into_transport(self) -> anyhow::Result<NoiseSession> {
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| anyhow::anyhow!("Noise into_transport failed: {}", e))?;
        Ok(NoiseSession { transport })
    }
}

impl NoiseSession {
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(ciphertext, &mut plaintext)
            .map_err(|e| anyhow::anyhow!("Noise decrypt failed: {}", e))?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let len = self
            .transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|e| anyhow::anyhow!("Noise encrypt failed: {}", e))?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// Consume the session, yielding the raw snow transport state.
    pub fn into_transport_state(self) -> snow::TransportState {
        self.transport
    }
}

pub fn generate_keypair() -> anyhow::Result<([u8; 32], [u8; 32])> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    let mut private = [0u8; 32];
    let mut public = [0u8; 32];
    private.copy_from_slice(&keypair.private);
    public.copy_from_slice(&keypair.public);
    Ok((private, public))
}

pub fn pubkey_from_private(privkey: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*privkey);
    let public = PublicKey::from(&secret);
    *public.as_bytes()
}
