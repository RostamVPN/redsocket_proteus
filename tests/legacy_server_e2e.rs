// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! What a capable client sees from a server that does not have — or has not
//! enabled — protection and messaging: exactly the legacy bytes. No verdict
//! byte, no `0xC0` stream, the trailing flags byte ignored.

use e2e_harness::*;
use redsocket_http::{messaging, protection};

async fn assert_legacy_bytes(server: &Server) {
    let echo = start_echo("127.0.0.1:0").await;
    let mut cap = MuxClient::connect(
        server,
        "MUX2|Asia/Dubai|rostam||ca9000000000000a||blk1,msg1",
    )
    .await
    .unwrap();

    let mut s = cap
        .request(&flagged("127.0.0.1", echo.port(), 0x01))
        .await
        .unwrap();
    expect_ok(&mut s)
        .await
        .expect("the SOCKS OK must be the first byte: no verdict");
    expect_echo(&mut s).await.unwrap();
    let mut s = cap
        .request(&trimmed("127.0.0.1", echo.port()))
        .await
        .unwrap();
    expect_ok(&mut s).await.unwrap();
    expect_echo(&mut s).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), cap.inbound.recv())
            .await
            .is_err(),
        "a server without the features must not open a control stream"
    );
}

/// Neither `[protection]` nor `[messaging]`: the hello's caps are never read,
/// which is the same code a `dcfa399` build runs for every hello.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn features_off_is_the_pre_branch_behaviour() {
    redsocket_http::proxy::init_destination_policy(Some(&[]), &[]);
    assert!(!protection::caps_wanted());
    let server = start_server().await;
    assert_legacy_bytes(&server).await;
    let mut m = String::new();
    protection::prometheus(&mut m);
    assert!(m.is_empty(), "protection off exports nothing: {m}");
    assert_eq!(messaging::ack_streams(), 0);
}

/// The real pre-branch binary:
/// `REDSOCKET_BASELINE_BIN=/path/to/dcfa399/redsocket-http cargo test --test
/// legacy_server_e2e -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_cap_client_against_the_pre_branch_binary() {
    let bin = std::env::var("REDSOCKET_BASELINE_BIN").expect("REDSOCKET_BASELINE_BIN");
    let ext = start_external_server(&bin).await;
    assert_legacy_bytes(&ext.server).await;
}
