// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RedSocket HTTP-Standalone — the server as a library crate.

pub mod config;
pub mod control;
pub mod stats;
pub mod http;
pub mod shed;

#[cfg_attr(target_os = "linux", path = "iouring_relay.rs")]
#[cfg_attr(not(target_os = "linux"), path = "iouring_relay_stub.rs")]
pub mod iouring_relay;
pub mod messaging;
pub mod metrics;
pub mod mux;
pub mod noise;
pub mod noise_framer;
pub mod noise_proxy;
pub mod noise_stream;
pub mod protection;
pub mod proteus_carrier;
pub mod proxy;
pub mod proxy_protocol;
pub mod valkey;
pub mod ws;
pub mod ws_codec;
