// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The fail-open hazard, made visible: `[protection]` on, no bundle ever
//! installed (Valkey down, bad cert, slow fetch).

use e2e_harness::*;
use redsocket_http::config::ProtectionConfig;
use redsocket_http::messaging::{self, CONTROL_MAGIC};
use redsocket_http::protection::{self, fixture, Verdict};
use tokio::io::AsyncReadExt;

async fn read_ctl<S: tokio::io::AsyncRead + Unpin>(s: &mut S, what: &str) -> messaging::Msg {
    let body = tokio::time::timeout(std::time::Duration::from_secs(5), messaging::read_frame(s))
        .await
        .unwrap_or_else(|_| panic!("no control frame within 5s while waiting for: {what}"))
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_bundle_means_enabled_false_not_silent_clear() {
    redsocket_http::proxy::init_destination_policy(Some(&[]), &[]);
    let signer = fixture::Signer::new();
    protection::set_caps_wanted(true);
    protection::init(
        &ProtectionConfig {
            enabled: true,
            pubkey: signer.pubkey_hex(),
            ..Default::default()
        },
        &[],
    )
    .unwrap();
    assert!(protection::current().is_none());
    assert_eq!(protection::status(), (false, None, None));

    let server = start_server().await;
    let echo = start_echo("127.0.0.1:0").await;
    let mut cap = MuxClient::connect(
        &server,
        "MUX2|Asia/Dubai|rostam||ca9000000000000a||blk1,msg1",
    )
    .await
    .unwrap();
    let mut ctl = cap.next_inbound().await.expect("the control stream");
    let mut magic = [0u8; 1];
    ctl.read_exact(&mut magic).await.unwrap();
    assert_eq!(magic[0], CONTROL_MAGIC);
    let status = read_ctl(&mut ctl, "status").await;
    assert_eq!(status.kind, "protection");
    assert_eq!(status.payload["enabled"], false, "nothing is being checked");
    assert!(status.payload["list_version"].is_null());
    assert!(status.payload["feed_date"].is_null());

    let mut s = cap
        .request(&trimmed("127.0.0.1", echo.port()))
        .await
        .unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    expect_ok(&mut s).await.unwrap();
    expect_echo(&mut s).await.unwrap();

    let mut s = cap.request(&trimmed("evil.example", 443)).await.unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    drop(s);
    let mut m = String::new();
    protection::prometheus(&mut m);
    assert!(m.contains("redsocket_protection_bundle_loaded 0"), "{m}");
    assert!(m.contains("redsocket_protection_unchecked_total 2"), "{m}");

    protection::install_raw(&fixture::build(
        &signer,
        "2026-10-11",
        &[],
        &[],
        &["evil.example"],
    ))
    .unwrap();
    let m = read_ctl(&mut ctl, "enabled:true").await;
    assert_eq!(m.payload["enabled"], true);
    assert_eq!(m.payload["feed_date"], "2026-10-11");
    assert!(m.payload["list_version"].is_string());
    let mut s = cap.request(&trimmed("evil.example", 443)).await.unwrap();
    assert!(read_verdict(&mut s).await.unwrap().is_block());
}
