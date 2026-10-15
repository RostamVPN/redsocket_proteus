// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The reloader against a fake valkey-main.

use base64::Engine;
use e2e_harness::fake_valkey::FakeValkey;
use redsocket_http::config::ProtectionConfig;
use redsocket_http::protection::{self, fixture, RawBundle, Source};
use redsocket_http::valkey;

fn sha(d: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(d))
}

/// Write a bundle the way `valkey_load.sh` does, with the given `version`.
fn publish(vk: &FakeValkey, raw: &RawBundle, version: &str) {
    let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
    vk.hset(
        "protection:bundle",
        "meta",
        std::str::from_utf8(&raw.meta).unwrap(),
    );
    vk.hset("protection:bundle", "sig", &b64(&raw.sig));
    vk.hset("protection:bundle", "v4", &b64(&raw.v4));
    vk.hset("protection:bundle", "v6", &b64(&raw.v6));
    vk.hset("protection:bundle", "domains", &b64(&raw.domains_gz));
    vk.hset("protection:bundle", "version", version);
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

fn metric(name: &str) -> u64 {
    let mut m = String::new();
    protection::prometheus(&mut m);
    m.lines()
        .find(|l| l.starts_with(name) && l.as_bytes().get(name.len()) == Some(&b' '))
        .and_then(|l| l.rsplit(' ').next()?.parse().ok())
        .unwrap_or_else(|| panic!("no metric {name} in:\n{m}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_and_mismatched_bundles_are_refused() {
    let _ = env_logger::builder().is_test(true).try_init();
    let vk = FakeValkey::start().await;
    let signer = fixture::Signer::new();
    protection::init(
        &ProtectionConfig {
            enabled: true,
            pubkey: signer.pubkey_hex(),
            ..Default::default()
        },
        &[],
    )
    .unwrap();

    let day1 = fixture::assemble_at(
        &signer,
        "2026-10-11",
        "2026-10-12T03:31:00Z",
        fixture::v4_bin(&[]),
        fixture::v6_bin(&[]),
        fixture::domains_gz(&["one.example"]),
    );
    publish(&vk, &day1, &sha(&day1.meta));
    protection::spawn_reloader(Source::Valkey(valkey::Config::plain(&vk.addr)));
    wait_for("day one to load", || protection::current().is_some()).await;
    assert_eq!(
        protection::current_version().as_deref(),
        Some(sha(&day1.meta).as_str())
    );
    assert_eq!(
        metric("redsocket_protection_reloads_total{outcome=\"ok\"}"),
        1
    );

    let old = fixture::assemble_at(
        &signer,
        "2026-10-10",
        "2026-10-11T03:31:00Z",
        fixture::v4_bin(&[]),
        fixture::v6_bin(&[]),
        fixture::domains_gz(&["zero.example"]),
    );
    publish(&vk, &old, &sha(&old.meta));
    protection::request_reload();
    wait_for("the stale refusal", || {
        metric("redsocket_protection_reloads_total{outcome=\"stale\"}") == 1
    })
    .await;
    assert_eq!(
        protection::current_version().as_deref(),
        Some(sha(&day1.meta).as_str())
    );
    assert!(protection::current().unwrap().domain_hit("one.example"));

    let day2 = fixture::assemble_at(
        &signer,
        "2026-10-12",
        "2026-10-13T03:31:00Z",
        fixture::v4_bin(&[]),
        fixture::v6_bin(&[]),
        fixture::domains_gz(&["two.example"]),
    );
    publish(&vk, &day2, "2026-10-12");
    protection::request_reload();
    wait_for("the mismatch refusal", || {
        metric("redsocket_protection_reloads_total{outcome=\"mismatch\"}") == 1
    })
    .await;
    assert_eq!(
        protection::current_version().as_deref(),
        Some(sha(&day1.meta).as_str())
    );

    publish(&vk, &day2, &sha(&day2.meta));
    protection::request_reload();
    wait_for("day two to load", || {
        protection::current_version().as_deref() == Some(sha(&day2.meta).as_str())
    })
    .await;
    assert!(protection::current().unwrap().domain_hit("two.example"));
    assert!(!protection::current().unwrap().domain_hit("one.example"));
    assert_eq!(
        metric("redsocket_protection_reloads_total{outcome=\"ok\"}"),
        2
    );
    assert_eq!(
        metric("redsocket_protection_reloads_total{outcome=\"failed\"}"),
        0
    );

    protection::request_reload();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        metric("redsocket_protection_reloads_total{outcome=\"ok\"}"),
        2
    );
}
