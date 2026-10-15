// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RedSocket behind Proteus — the server as a library crate.

pub mod config;
pub mod control;
pub mod messaging;
pub mod metrics;
pub mod mux;
pub mod noise;
pub mod noise_proxy;
pub mod noise_stream;
pub mod protection;
pub mod proteus_carrier;
pub mod proxy;
pub mod proxy_protocol;
pub mod shed;
pub mod stats;
pub mod valkey;
