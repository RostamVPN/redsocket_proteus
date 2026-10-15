// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Mailbox messaging, end to end.

use e2e_harness::fake_valkey::FakeValkey;
use e2e_harness::*;
use redsocket_http::config::ProtectionConfig;
use redsocket_http::messaging::{self, Msg, CONTROL_MAGIC};
use redsocket_http::protection::{self, fixture, Verdict};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

const BLOCK: u16 = 0x0001;
const CONTROLLER: u16 = 0x0010;
const PHISHING: u16 = 0x0040;

async fn read_msg<S: AsyncRead + Unpin>(s: &mut S, what: &str) -> Msg {
    let body = tokio::time::timeout(std::time::Duration::from_secs(5), messaging::read_frame(s))
        .await
        .unwrap_or_else(|_| panic!("no frame within 5s while waiting for: {what}"))
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn send_up<S: AsyncWrite + Unpin>(s: &mut S, json: serde_json::Value) {
    messaging::write_frame(s, json.to_string().as_bytes())
        .await
        .unwrap();
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn msg1_tunnels_get_replay_live_acks_and_rules() {
    let _ = env_logger::builder().is_test(true).try_init();
    redsocket_http::proxy::init_destination_policy(Some(&[]), &[]);
    let vk = FakeValkey::start().await;

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
    protection::install_raw(&fixture::build(
        &signer,
        "2026-10-11",
        &[
            (ip4("192.0.2.0"), ip4("192.0.2.255"), BLOCK | CONTROLLER),
            (ip4("198.51.100.0"), ip4("198.51.100.255"), BLOCK | PHISHING),
        ],
        &[],
        &["allowed.example", "later.example"],
    ))
    .unwrap();

    let cid = "a1a2a3a4a5a6a7a8";
    vk.mailbox_put(
        &format!("msg:{cid}"),
        1,
        1000,
        "notice",
        serde_json::json!({"title": "one"}),
    );
    vk.mailbox_put(
        &format!("msg:{cid}"),
        2,
        1001,
        "notice",
        serde_json::json!({"title": "two"}),
    );
    vk.mailbox_put(
        &format!("msg:{cid}"),
        3,
        1002,
        "notice",
        serde_json::json!({"title": "three"}),
    );
    vk.set(&format!("msg:{cid}:last"), "1");

    vk.set(&format!("msg:{cid}:seq"), "4");
    vk.mailbox_put(
        "msg:broadcast",
        1,
        100,
        "notice",
        serde_json::json!({"title": "old"}),
    );
    vk.mailbox_put(
        "msg:broadcast",
        2,
        200,
        "notice",
        serde_json::json!({"title": "ours", "brand": "rostam"}),
    );
    vk.mailbox_put(
        "msg:broadcast",
        3,
        300,
        "notice",
        serde_json::json!({"title": "theirs", "brand": "other"}),
    );
    vk.hset(&format!("cid:{cid}"), "state", "paid");
    vk.hset(&format!("cid:{cid}"), "tier", "pro");
    vk.hset(&format!("cid:{cid}"), "paid_until", "2027-01-01T00:00:00");
    vk.hset(&format!("rules:{cid}"), "allow", r#"["allowed.example"]"#);
    vk.hset(&format!("rules:{cid}"), "deny", r#"["denied.example"]"#);

    messaging::spawn(messaging::Config {
        valkey: redsocket_http::valkey::Config::plain(&vk.addr),
    });
    wait_for("the subscription link", || {
        messaging::stats().map(|s| s.connected[1]).unwrap_or(false)
    })
    .await;
    let server = start_server().await;
    let echo = start_echo("127.0.0.1:0").await;

    let mut legacy = MuxClient::connect(&server, "MUX2|Asia/Tehran|||cid-legacy|")
        .await
        .unwrap();
    let mut s = legacy
        .request(&trimmed("127.0.0.1", echo.port()))
        .await
        .unwrap();
    expect_ok(&mut s).await.unwrap();
    expect_echo(&mut s).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), legacy.inbound.recv())
            .await
            .is_err(),
        "the server must not open a stream toward a legacy client"
    );

    let mut blk = MuxClient::connect(
        &server,
        "MUX2|Asia/Dubai|rostam||b1c0000000000000||blk1",
    )
    .await
    .unwrap();
    let mut bctl = blk
        .next_inbound()
        .await
        .expect("blk1 alone gets the control stream");
    let mut magic = [0u8; 1];
    bctl.read_exact(&mut magic).await.unwrap();
    assert_eq!(magic[0], CONTROL_MAGIC);
    assert_eq!(
        read_msg(&mut bctl, "blk1 status").await.payload["enabled"],
        true
    );
    assert_eq!(
        messaging::stats().unwrap().tunnels,
        0,
        "an ack stream is not a mailbox tunnel"
    );
    assert_eq!(messaging::ack_streams(), 1);

    let mut cap = MuxClient::connect(
        &server,
        &format!("MUX2|Asia/Dubai|rostam||{cid}||blk1,msg1"),
    )
    .await
    .unwrap();
    let mut ctl = cap.next_inbound().await.expect("the control stream");
    let mut magic = [0u8; 1];
    ctl.read_exact(&mut magic).await.unwrap();
    assert_eq!(magic[0], CONTROL_MAGIC);

    let status = read_msg(&mut ctl, "status").await;
    assert_eq!((status.kind.as_str(), status.seq), ("protection", 0));
    assert_eq!(status.payload["enabled"], true);
    send_up(&mut ctl, serde_json::json!({"since": 150})).await;

    let m = read_msg(&mut ctl, "step 1").await;
    assert_eq!((m.seq, m.kind.as_str()), (2, "notice"));
    assert_eq!(m.scope.as_deref(), Some("cid"));
    let m = read_msg(&mut ctl, "step 2").await;
    assert_eq!((m.seq, m.payload["title"].as_str()), (3, Some("three")));

    let m = read_msg(&mut ctl, "step 3").await;
    assert_eq!((m.seq, m.payload["title"].as_str()), (2, Some("ours")));
    assert_eq!(m.scope.as_deref(), Some("broadcast"));

    let m = read_msg(&mut ctl, "step 4").await;
    assert_eq!(m.kind, "entitlement");
    assert_eq!(m.seq, 0);
    assert_eq!(m.payload["tier"], "pro");
    assert_eq!(m.payload["paid_until"], "2027-01-01T00:00:00");

    let mut s = cap.request(&trimmed("allowed.example", 443)).await.unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    drop(s);
    let mut s = cap.request(&trimmed("later.example", 443)).await.unwrap();
    assert!(read_verdict(&mut s).await.unwrap().is_block());
    drop(s);

    send_up(&mut ctl, serde_json::json!({"ack": 3})).await;
    wait_for("the ack to land", || {
        vk.get(&format!("msg:{cid}:last")).as_deref() == Some("3")
    })
    .await;
    send_up(&mut ctl, serde_json::json!({"ack": 2})).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(vk.get(&format!("msg:{cid}:last")).as_deref(), Some("3"));

    vk.mailbox_put(
        &format!("msg:{cid}"),
        4,
        1003,
        "notice",
        serde_json::json!({"title": "four"}),
    );
    vk.publish("msg", cid);
    let m = read_msg(&mut ctl, "step 5").await;
    assert_eq!((m.seq, m.payload["title"].as_str()), (4, Some("four")));

    vk.mailbox_put(
        "msg:broadcast",
        4,
        400,
        "notice",
        serde_json::json!({"title": "all"}),
    );
    vk.mailbox_put(
        "msg:broadcast",
        5,
        401,
        "notice",
        serde_json::json!({"title": "not ours", "brand": "other"}),
    );
    vk.mailbox_put(
        "msg:broadcast",
        6,
        402,
        "protection",
        serde_json::json!({"list_version": "2026-10-12"}),
    );
    vk.publish("msg", "*");
    let m = read_msg(&mut ctl, "step 6").await;
    assert_eq!((m.seq, m.payload["title"].as_str()), (4, Some("all")));
    let m = read_msg(&mut ctl, "step 7").await;
    assert_eq!((m.seq, m.kind.as_str()), (6, "protection"));

    send_up(&mut ctl, serde_json::json!({"ack": 6})).await;
    send_up(&mut ctl, serde_json::json!({"ack": 4})).await;
    wait_for("the per-cid ack", || {
        vk.get(&format!("msg:{cid}:last")).as_deref() == Some("4")
    })
    .await;

    send_up(
        &mut ctl,
        serde_json::json!({"rules": {"allow": ["later.example"], "deny": ["203.0.113.5"], "categories_off": PHISHING | CONTROLLER}}),
    )
    .await;
    wait_for("rules:<cid> to be written", || {
        vk.hget(&format!("rules:{cid}"), "allow").as_deref() == Some(r#"["later.example"]"#)
    })
    .await;
    assert_eq!(
        vk.hget(&format!("rules:{cid}"), "deny").as_deref(),
        Some(r#"["203.0.113.5"]"#)
    );
    assert_eq!(
        vk.hget(&format!("rules:{cid}"), "categories_off")
            .as_deref(),
        Some("80")
    );
    let m = read_msg(&mut ctl, "step 8").await;
    assert_eq!(m.kind, "rules");
    assert_eq!(m.seq, 5, "appended after the writer's seq 4");
    assert_eq!(m.payload["allow"][0], "later.example");
    assert_eq!(m.payload["categories_off"], 80);

    let before = vk.commands().len();
    send_up(
        &mut ctl,
        serde_json::json!({"rules": {"allow": ["later.example", "10.0.0.0/8"], "deny": [], "categories_off": 0}}),
    )
    .await;
    let many: Vec<String> = (0..201).map(|i| format!("h{i}.example")).collect();
    send_up(
        &mut ctl,
        serde_json::json!({"rules": {"allow": [], "deny": many, "categories_off": 0}}),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !vk.commands()[before..]
            .iter()
            .any(|c| c.starts_with("HSET rules:")),
        "{:?}",
        &vk.commands()[before..]
    );
    assert_eq!(messaging::stats().unwrap().rules_rejected, 2);
    assert_eq!(
        vk.hget(&format!("rules:{cid}"), "allow").as_deref(),
        Some(r#"["later.example"]"#)
    );

    messaging::RULES_INTERVAL_MS.store(1500, std::sync::atomic::Ordering::Relaxed);
    let before = vk.commands().len();
    send_up(
        &mut ctl,
        serde_json::json!({"rules": {"allow": ["later.example", "198.51.100.7"], "deny": ["203.0.113.5"], "categories_off": PHISHING | CONTROLLER}}),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !vk.commands()[before..]
            .iter()
            .any(|c| c.starts_with("HSET rules:")),
        "inside the window nothing is written yet"
    );

    let mut s = cap.request(&trimmed("198.51.100.7", 80)).await.unwrap();
    assert_eq!(read_verdict(&mut s).await.unwrap(), Verdict::Clear);
    drop(s);
    wait_for("the deferred write", || {
        vk.hget(&format!("rules:{cid}"), "allow").as_deref()
            == Some(r#"["later.example","198.51.100.7"]"#)
    })
    .await;
    let m = read_msg(&mut ctl, "deferred rules echo").await;
    assert_eq!(m.kind, "rules");
    assert_eq!(m.payload["allow"][1], "198.51.100.7");

    tokio::time::sleep(std::time::Duration::from_millis(1600)).await;
    send_up(
        &mut ctl,
        serde_json::json!({"rules": {"allow": ["later.example"], "deny": ["203.0.113.5"], "categories_off": PHISHING | CONTROLLER}}),
    )
    .await;
    wait_for("the restore write", || {
        vk.hget(&format!("rules:{cid}"), "allow").as_deref() == Some(r#"["later.example"]"#)
    })
    .await;
    let m = read_msg(&mut ctl, "restore rules echo").await;
    assert_eq!(m.kind, "rules");
    tokio::time::sleep(std::time::Duration::from_millis(1600)).await;

    let before = vk.commands().len();
    send_up(
        &mut ctl,
        serde_json::json!({"rules": {"allow": ["later.example"], "deny": ["203.0.113.5"], "categories_off": PHISHING | CONTROLLER}}),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !vk.commands()[before..]
            .iter()
            .any(|c| c.starts_with("HSET rules:") || c.starts_with("PUBLISH")),
        "unchanged rules must be a no-op: {:?}",
        &vk.commands()[before..]
    );

    let mut s = cap.request(&trimmed("198.51.100.7", 80)).await.unwrap();
    assert_eq!(
        read_verdict(&mut s).await.unwrap(),
        Verdict::Clear,
        "phishing switched off"
    );
    drop(s);
    let mut s = cap.request(&trimmed("192.0.2.9", 80)).await.unwrap();
    assert!(
        read_verdict(&mut s).await.unwrap().is_block(),
        "controller cannot be switched off"
    );
    drop(s);
    let mut s = cap.request(&trimmed("later.example", 443)).await.unwrap();
    assert_eq!(
        read_verdict(&mut s).await.unwrap(),
        Verdict::Clear,
        "the new rule applies"
    );
    drop(s);

    let mut s = cap.request(&trimmed("203.0.113.5", 443)).await.unwrap();
    assert_eq!(
        read_verdict(&mut s).await.unwrap(),
        Verdict::Clear,
        "deny is never enforced here"
    );
    drop(s);

    vk.xadd(
        "cid:events",
        &[
            ("cid", cid),
            ("prev", "paid"),
            ("state", "throttle"),
            ("tier", "free"),
            ("paid_until", ""),
        ],
    );
    let m = read_msg(&mut ctl, "step 9").await;
    assert_eq!(m.kind, "entitlement");
    assert_eq!(m.payload["state"], "throttle");
    assert_eq!(m.payload["tier"], "free");

    vk.xadd(
        "cid:events",
        &[("cid", "someone-else"), ("state", "banned")],
    );

    protection::install_raw(&fixture::build(&signer, "2026-10-13", &[], &[], &[])).unwrap();
    let m = read_msg(&mut ctl, "step 10").await;
    assert_eq!(m.kind, "protection");
    assert_eq!(m.payload["enabled"], true);
    assert_eq!(m.payload["feed_date"], "2026-10-13");
    assert_eq!(
        m.payload["list_version"],
        protection::current_version().unwrap(),
        "list_version is the installed bundle's sha256(meta)"
    );

    let st = messaging::stats().unwrap();
    assert_eq!(st.tunnels, 1);
    assert!(st.sent[0] >= 2, "entitlement sent: {}", st.sent[0]);
    assert!(
        st.sent[1] >= 4,
        "protection sent (statuses + switch): {}",
        st.sent[1]
    );
    assert_eq!(st.sent[2], 3, "rules sent");
    assert!(st.sent[3] >= 5, "notices sent: {}", st.sent[3]);
    assert_eq!(st.acks, 2);
    assert_eq!(st.rules, 3);
    let mut text = String::new();
    messaging::prometheus(&mut text);
    assert!(
        text.contains("redsocket_messaging_sent_total{type=\"rules\"} 3"),
        "{text}"
    );

    let mut fresh = MuxClient::connect(
        &server,
        "MUX2|Asia/Dubai|rostam||f4e5000000000000||msg1",
    )
    .await
    .unwrap();
    let mut fctl = fresh.next_inbound().await.unwrap();
    fctl.read_exact(&mut magic).await.unwrap();
    assert_eq!(read_msg(&mut fctl, "fresh status").await.kind, "protection");
    send_up(&mut fctl, serde_json::json!({"since": 0})).await;
    let before = vk.commands().len();
    send_up(
        &mut fctl,
        serde_json::json!({"rules": {"allow": [], "deny": [], "categories_off": 0}}),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !vk.commands()[before..]
            .iter()
            .any(|c| c.starts_with("HSET rules:f4e5000000000000")),
        "{:?}",
        &vk.commands()[before..]
    );
    assert!(vk.hget("rules:f4e5000000000000", "allow").is_none());
    drop(fctl);
    drop(fresh);

    let st = messaging::stats().unwrap();
    assert!(
        st.rules_throttled >= 1,
        "the repeated set was throttled: {}",
        st.rules_throttled
    );
    let rejected_before = st.rules_rejected;
    let big = vec![b'x'; messaging::MAX_UPSTREAM + 1];
    tokio::io::AsyncWriteExt::write_all(&mut ctl, &(big.len() as u16).to_le_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut ctl, &big)
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut ctl).await.unwrap();
    wait_for("the oversize drop to be counted", || {
        messaging::stats().unwrap().rules_rejected == rejected_before + 1
    })
    .await;

    vk.mailbox_put(
        &format!("msg:{cid}"),
        20,
        1005,
        "notice",
        serde_json::json!({"title": "still here"}),
    );
    vk.publish("msg", cid);
    let m = read_msg(&mut ctl, "notice after the dropped frame").await;
    assert_eq!(
        (m.seq, m.payload["title"].as_str()),
        (20, Some("still here"))
    );

    let mut seqc = MuxClient::connect(
        &server,
        "MUX2|Asia/Dubai|rostam||5e9c000000000000||msg1",
    )
    .await
    .unwrap();
    let mut sctl = seqc.next_inbound().await.unwrap();
    sctl.read_exact(&mut magic).await.unwrap();
    let st_msg = read_msg(&mut sctl, "seq status").await;
    assert_eq!(
        (st_msg.kind.as_str(), st_msg.scope.as_deref()),
        ("protection", Some("cid"))
    );
    send_up(
        &mut sctl,
        serde_json::json!({"since": 0, "broadcast_seq": 5}),
    )
    .await;
    let m = read_msg(&mut sctl, "broadcast above seq 5").await;
    assert_eq!(
        (m.seq, m.kind.as_str(), m.scope.as_deref()),
        (6, "protection", Some("broadcast"))
    );
    assert!(
        vk.commands().iter().any(|c| c.starts_with(&format!(
            "EXPIRE msg:{cid}:last {}",
            messaging::COUNTER_TTL_SECS
        ))),
        "msg:<cid>:last carries a TTL"
    );
    assert!(
        vk.commands().iter().any(|c| c.starts_with(&format!(
            "EXPIRE msg:{cid}:seq {}",
            messaging::COUNTER_TTL_SECS
        ))),
        "msg:<cid>:seq carries a TTL"
    );
    drop(sctl);
    drop(seqc);

    drop(ctl);
    drop(cap);
    wait_for("unregister", || {
        messaging::stats().map(|s| s.tunnels == 0).unwrap_or(false)
    })
    .await;
    let _ = (&mut blk, &mut legacy);
}
