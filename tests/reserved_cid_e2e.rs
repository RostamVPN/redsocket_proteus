// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A capability hello whose cid is not a plain hex id gets no capability, on a
//! server with the features ON. Its own binary: it enables protection in the
//! process, which `legacy_server_e2e` must not see.

use e2e_harness::*;
use redsocket_http::{messaging, protection};

/// A capability hello whose cid is not a plain hex id must not be given any
/// capability: `broadcast` and `*` are mailbox names, and a cid becomes a
/// Valkey key component the moment a cap is on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reserved_or_malformed_cids_get_no_capability() {
    redsocket_http::proxy::init_destination_policy(Some(&[]), &[]);
    let signer = protection::fixture::Signer::new();
    protection::set_caps_wanted(true);
    protection::init(
        &redsocket_http::config::ProtectionConfig {
            enabled: true,
            pubkey: signer.pubkey_hex(),
            ..Default::default()
        },
        &[],
    )
    .unwrap();
    protection::install_raw(&protection::fixture::build(
        &signer,
        "2026-10-11",
        &[],
        &[],
        &["evil.example"],
    ))
    .unwrap();
    let server = start_server().await;
    let echo = start_echo("127.0.0.1:0").await;
    for cid in [
        "broadcast",
        "*",
        "4f2a9c1e8b7d3a60:last",
        "",
        "CAFEBABE00000000",
        "cid-x",
    ] {
        let hello = format!("MUX2|Asia/Dubai|rostam||{cid}||blk1,msg1");
        let mut c = MuxClient::connect(&server, &hello).await.unwrap();

        let mut s = c.request(&trimmed("127.0.0.1", echo.port())).await.unwrap();
        expect_ok(&mut s)
            .await
            .unwrap_or_else(|e| panic!("cid {cid:?}: {e}"));
        expect_echo(&mut s).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), c.inbound.recv())
                .await
                .is_err(),
            "cid {cid:?} must not get a control stream"
        );
    }

    assert_eq!(messaging::ack_streams(), 0);
    let mut m = String::new();
    protection::prometheus(&mut m);
    assert!(m.contains("verdict=\"block\"} 0"), "nothing judged: {m}");
}
