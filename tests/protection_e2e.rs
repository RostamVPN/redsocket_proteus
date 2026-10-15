// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exit-side protection, end to end: a real listener, a real MUX2 carrier, a
//! fixture bundle, and the verdict bytes a capable client sees — next to a
//! legacy client that must see exactly what it saw before.

use e2e_harness::*;
use redsocket_http::config::ProtectionConfig;
use redsocket_http::messaging::{self, CONTROL_MAGIC};
use redsocket_http::protection::{self, fixture, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn read_ctl<S: tokio::io::AsyncRead + Unpin>(s: &mut S, what: &str) -> messaging::Msg {
    let body = tokio::time::timeout(std::time::Duration::from_secs(5), messaging::read_frame(s))
        .await
        .unwrap_or_else(|_| panic!("no control frame within 5s while waiting for: {what}"))
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

const BLOCK: u16 = 0x0001;
const NOTIFY: u16 = 0x0002;
const CONTROLLER: u16 = 0x0010;
const RATING: u16 = 0x0100;
const SCANNER: u16 = 0x0200;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdicts_on_mux2_and_legacy_untouched() {
    redsocket_http::proxy::init_destination_policy(Some(&[]), &[]);

    let signer = fixture::Signer::new();
    let cfg = ProtectionConfig {
        enabled: true,
        pubkey: signer.pubkey_hex(),
        brands: vec!["rostam".into()],
        ..Default::default()
    };
    protection::set_caps_wanted(true);
    protection::init(&cfg, &[]).unwrap();

    let raw = fixture::build(
        &signer,
        "2026-10-11",
        &[(
            ip4("198.51.100.0"),
            ip4("198.51.100.255"),
            BLOCK | CONTROLLER | RATING,
        )],
        &[(ip6("::1"), ip6("::1"), NOTIFY | SCANNER)],
        &["evil.example"],
    );
    protection::install_raw(&raw).unwrap();
    assert_eq!(protection::current().unwrap().feed_date, "2026-10-11");

    let echo4 = start_echo("127.0.0.1:0").await;
    let echo6 = start_echo("[::1]:0").await;
    let server = start_server().await;

    let mut legacy = MuxClient::connect(&server, "MUX2|Asia/Tehran|||cid-legacy|")
        .await
        .unwrap();
    let mut s = legacy
        .request(&trimmed("127.0.0.1", echo4.port()))
        .await
        .unwrap();
    expect_ok(&mut s)
        .await
        .expect("legacy: OK first, no verdict byte");
    expect_echo(&mut s).await.unwrap();

    let mut s = legacy.request(&trimmed("::1", echo6.port())).await.unwrap();
    expect_ok(&mut s)
        .await
        .expect("legacy to a listed address: untouched");
    expect_echo(&mut s).await.unwrap();

    let mut m = String::new();
    protection::prometheus(&mut m);
    assert!(m.contains("verdict=\"clear\"} 0"), "{m}");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), legacy.inbound.recv())
            .await
            .is_err(),
        "no caps, no control stream"
    );
    drop(legacy);

    let mut cap = MuxClient::connect(
        &server,
        "MUX2|Asia/Dubai|rostam||ca9000000000000a||blk1",
    )
    .await
    .unwrap();

    let mut ctl = cap.next_inbound().await.expect("the control stream");
    let mut magic = [0u8; 1];
    ctl.read_exact(&mut magic).await.unwrap();
    assert_eq!(magic[0], CONTROL_MAGIC);

    let status = read_ctl(&mut ctl, "status").await;
    assert_eq!(status.kind, "protection");
    assert_eq!(status.payload["enabled"], true);
    assert_eq!(status.payload["feed_date"], "2026-10-11");
    assert!(status.payload["list_version"].is_string());
    messaging::write_frame(&mut ctl, br#"{"since":0}"#)
        .await
        .unwrap();

    let mut s = cap
        .request(&trimmed("127.0.0.1", echo4.port()))
        .await
        .unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    expect_ok(&mut s).await.unwrap();
    expect_echo(&mut s).await.unwrap();

    let mut s = cap.request(&trimmed("evil.example", 443)).await.unwrap();
    assert_eq!(
        read_verdict(&mut s).await.unwrap(),
        Verdict::Block {
            bits: BLOCK,
            reason: "domain".into()
        }
    );
    expect_eof(&mut s).await.unwrap();

    let mut s = cap
        .request(&trimmed("WWW.Evil.Example.", 443))
        .await
        .unwrap();
    assert!(read_verdict(&mut s).await.unwrap().is_block());
    expect_eof(&mut s).await.unwrap();

    let mut s = cap.request(&trimmed("198.51.100.7", 80)).await.unwrap();
    assert_eq!(
        read_verdict(&mut s).await.unwrap(),
        Verdict::Block {
            bits: BLOCK | CONTROLLER | RATING,
            reason: "controller,rating_malicious".into()
        }
    );
    expect_eof(&mut s).await.unwrap();

    let mut s = cap.request(&trimmed("::1", echo6.port())).await.unwrap();
    assert_eq!(
        read_verdict(&mut s).await.unwrap(),
        Verdict::Notify {
            bits: NOTIFY | SCANNER,
            reason: "scanner".into()
        }
    );
    expect_ok(&mut s).await.unwrap();
    expect_echo(&mut s).await.unwrap();

    let mut s = cap.request(&trimmed("a..b", 443)).await.unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    expect_eof(&mut s).await.unwrap();

    let mut s = cap
        .request(&flagged("::1", echo6.port(), 0x01))
        .await
        .unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    expect_ok(&mut s).await.unwrap();
    expect_echo(&mut s).await.unwrap();

    let mut s = cap
        .request(&flagged("::1", echo6.port(), 0x00))
        .await
        .unwrap();
    assert!(matches!(
        read_verdict(&mut s).await.unwrap(),
        Verdict::Notify { .. }
    ));
    expect_ok(&mut s).await.unwrap();

    let mut s = cap
        .request(&flagged("::1", echo6.port(), 0x02))
        .await
        .unwrap();
    expect_eof(&mut s).await.unwrap();

    let mut s = cap.request(&trimmed("_rs.ping", 0)).await.unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    expect_ok(&mut s).await.unwrap();
    s.write_all(&[1, 2, 3, 4, 5, 6, 7, 8]).await.unwrap();
    s.flush().await.unwrap();
    let mut echo = [0u8; 8];
    tokio::io::AsyncReadExt::read_exact(&mut s, &mut echo)
        .await
        .unwrap();
    assert_eq!(echo, [1, 2, 3, 4, 5, 6, 7, 8]);

    let mut other = MuxClient::connect(&server, "MUX2|Asia/Dubai|other||c0e4000000000000||blk1")
        .await
        .unwrap();
    let mut octl = other
        .next_inbound()
        .await
        .expect("a non-enrolled brand that announced caps is acknowledged too");
    octl.read_exact(&mut magic).await.unwrap();
    assert_eq!(magic[0], CONTROL_MAGIC);
    assert_eq!(read_ctl(&mut octl, "status").await.payload["enabled"], true);
    assert_eq!(messaging::ack_streams(), 2);
    let mut s = other.request(&trimmed("::1", echo6.port())).await.unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    expect_ok(&mut s).await.unwrap();
    expect_echo(&mut s).await.unwrap();

    let mut m = String::new();
    protection::prometheus(&mut m);
    assert!(m.contains("redsocket_protection_bundle_loaded 1"), "{m}");
    assert!(
        m.contains("verdicts_total{brand=\"rostam\",verdict=\"block\"} 3"),
        "{m}"
    );
    assert!(
        m.contains("verdicts_total{brand=\"rostam\",verdict=\"notify\"} 2"),
        "{m}"
    );

    assert!(
        m.contains("verdicts_total{brand=\"rostam\",verdict=\"clear\"} 1"),
        "{m}"
    );
    assert!(
        m.contains("redsocket_protection_user_allowed_total 1"),
        "{m}"
    );
    assert!(m.contains("feed_date=\"2026-10-11\""), "{m}");

    let mut bad = fixture::build(&signer, "2026-10-12", &[], &[], &[]);
    bad.v4.push(0);
    assert!(protection::install_raw(&bad).is_err());
    assert_eq!(protection::current().unwrap().feed_date, "2026-10-11");
    let good = fixture::build(&signer, "2026-10-12", &[], &[], &["other.example"]);
    protection::install_raw(&good).unwrap();
    assert_eq!(protection::current().unwrap().feed_date, "2026-10-12");

    let mut s = cap.request(&trimmed("198.51.100.7", 80)).await.unwrap();
    assert_eq!(
        read_verdict(&mut s).await.unwrap(),
        Verdict::Clear,
        "old list must be gone"
    );
    drop(s);
    let mut s = cap.request(&trimmed("x.other.example", 443)).await.unwrap();
    assert!(read_verdict(&mut s).await.unwrap().is_block());

    let m = read_ctl(&mut ctl, "protection switch").await;
    assert_eq!(m.kind, "protection");
    assert_eq!(m.seq, 0);
    assert_eq!(m.payload["enabled"], true);
    assert_eq!(m.payload["feed_date"], "2026-10-12");
    assert_ne!(m.payload["list_version"], status.payload["list_version"]);

    messaging::write_frame(
        &mut ctl,
        br#"{"rules":{"allow":["other.example"],"deny":[],"categories_off":0}}"#,
    )
    .await
    .unwrap();
    let mut cleared = false;
    for _ in 0..40 {
        let mut s = cap.request(&trimmed("x.other.example", 443)).await.unwrap();
        if read_verdict(&mut s).await.unwrap() == Verdict::Clear {
            cleared = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(cleared, "rules on the ack stream must apply without Valkey");
    drop(octl);
    drop(other);
}
