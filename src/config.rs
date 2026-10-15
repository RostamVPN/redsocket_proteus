// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Configuration — TOML-based config for the HTTP-standalone server.

use crate::proxy_protocol::PpMode;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub private_key: String,
    pub public_key: String,
    #[serde(default)]
    pub extra_private_keys: Vec<String>,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub stats: StatsConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub shed: ShedConfig,
    /// Exit-side malware protection (`src/protection.rs`). Off by default: with it
    /// off nothing is parsed, looked up or allocated per tunnel.
    #[serde(default)]
    pub protection: ProtectionConfig,
    /// Mailbox messaging over the tunnel (`src/messaging.rs`). Off by default.
    #[serde(default)]
    pub messaging: MessagingConfig,
    #[serde(default)]
    pub egress_ips: Vec<String>,
    /// Try a destination's IPv6 address before its IPv4 one, so a node with cheap
    /// or free IPv6 transit keeps dual-stack traffic off the metered side.
    #[serde(default)]
    pub prefer_ipv6: bool,
    /// Destinations refused before any connect is attempted.
    #[serde(default)]
    pub deny_cidrs: Option<Vec<String>>,
    /// Carve-outs, checked before deny_cidrs, so one internal range can be
    /// reachable without opening the rest of private space.
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    #[serde(default)]
    pub valkey: Option<ValkeyConfig>,
    /// `[proteus]` — a dedicated listener whose wire format is a Proteus protocol
    /// specification wrapped around the HTTP Upgrade carrier. Absent = none.
    #[serde(default)]
    pub proteus: Option<ProteusConfig>,
}

/// One Proteus-wrapped carrier: the PSF is compiled once at start-up and every
/// accepted connection runs the interpreter in front of `http::serve_stream`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProteusConfig {
    pub bind: String,
    /// Path to the protocol specification file.
    pub psf: String,
    /// More listen addresses for the same PSF.
    #[serde(default)]
    pub extra_binds: Vec<String>,
}

/// `[protection]` — the exit-side malware check. Which tunnels are checked is
/// decided per tunnel by the client's META (`brands` AND the `blk1` cap); this
/// section only says whether the module exists and where its list comes from.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectionConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Ed25519 public key (64 hex chars) that signs the bundle's `meta.json`.
    #[serde(default)]
    pub pubkey: String,
    /// META `app` values whose `blk1` tunnels are checked. Everything else is
    /// untouched.
    #[serde(default = "default_brands")]
    pub brands: Vec<String>,
    /// Names never judged: exact, or `*.suffix`. Seeded with the app's own
    /// control plane so a bundle can never cut a client off from its cashier or
    /// config fronts.
    #[serde(default = "default_allow_hosts")]
    pub allow_hosts: Vec<String>,
    /// Overrides on the bundle's bit table: names here block whatever their `kind`
    /// says. Empty (the default) lets the bundle decide, so a reason bit the
    /// pipeline adds is a block bit the day it ships.
    #[serde(default)]
    pub block_bits: Vec<String>,
    /// Names here only notify, whatever their `kind` says. Empty = none.
    #[serde(default)]
    pub notify_bits: Vec<String>,
    /// Write one debug line per block naming the destination host, port and client
    /// address. Off: a production node at debug level records no destinations (§9's
    /// promise); the counters are the operational signal.
    #[serde(default)]
    pub debug_log_destinations: bool,
    /// How often to look for a newer bundle (SIGHUP and a `protection` mailbox
    /// message reload immediately).
    #[serde(default = "default_reload_secs")]
    pub reload_secs: u64,
    /// Load the bundle from this directory (`v4.bin`, `v6.bin`, `domains.txt.gz`,
    /// `meta.json`, `meta.sig`) instead of Valkey. Lab and test use; production
    /// pulls `protection:bundle` from Valkey.
    #[serde(default)]
    pub bundle_dir: String,
    /// The Valkey holding `protection:bundle`. Absent = the `[messaging]`
    /// connection.
    #[serde(default)]
    pub valkey: Option<crate::valkey::Config>,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pubkey: String::new(),
            brands: default_brands(),
            allow_hosts: default_allow_hosts(),
            block_bits: Vec::new(),
            notify_bits: Vec::new(),
            debug_log_destinations: false,
            reload_secs: default_reload_secs(),
            bundle_dir: String::new(),
            valkey: None,
        }
    }
}

fn default_brands() -> Vec<String> {
    vec!["rostam".to_string()]
}
fn default_allow_hosts() -> Vec<String> {
    ["rostam.app", "*.rostam.app", "*.cloudfront.net", "*.amazonaws.com"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_reload_secs() -> u64 {
    300
}

/// `[messaging]` — Valkey hash mailboxes delivered over a yamux control stream
/// to tunnels that announce the `msg1` cap. Off by default.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MessagingConfig {
    #[serde(default)]
    pub enabled: bool,
    /// valkey-main: the instance holding `msg:*`, `rules:*` and the cashier's
    /// `cid:*` ledger.
    #[serde(default)]
    pub valkey: Option<crate::valkey::Config>,
}

/// Load shedding: refuse NEW tunnels with a 503 as memory runs out, so clients
/// fail over to another node instead of every tunnel here dying at once when
/// the OOM killer arrives.
#[derive(Debug, Deserialize)]
pub struct ShedConfig {
    /// Off means accept until the process dies, which is the old behaviour.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Percent of the memory limit at which to start refusing.
    #[serde(default = "default_shed_high")]
    pub high_pct: u64,
    /// Percent at which to resume. Must be below `high_pct`; the gap is what stops
    /// the node flapping between accepting and refusing.
    #[serde(default = "default_shed_low")]
    pub low_pct: u64,
    /// Seconds between memory samples.
    #[serde(default = "default_shed_interval")]
    pub interval_secs: u64,
}

impl Default for ShedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            high_pct: default_shed_high(),
            low_pct: default_shed_low(),
            interval_secs: default_shed_interval(),
        }
    }
}

fn default_shed_high() -> u64 {
    crate::shed::DEFAULT_HIGH_PCT
}
fn default_shed_low() -> u64 {
    crate::shed::DEFAULT_LOW_PCT
}
fn default_shed_interval() -> u64 {
    2
}

/// Stats / telemetry configuration. All stats are independently toggleable.
#[derive(Debug, Deserialize)]
pub struct StatsConfig {
    #[serde(default)]
    pub valkey: Option<ValkeyConfig>,
    #[serde(default = "default_true")]
    pub cids: bool,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            valkey: None,
            cids: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValkeyConfig {
    pub addr: String,
    pub password: String,
    pub ca_file: String,
    pub server_name: String,
}

#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    #[serde(default = "default_http_bind")]
    pub bind: String,
    #[serde(default)]
    pub extra_binds: Vec<String>,
    #[serde(default)]
    pub proxy_protocol: PpMode,
    #[serde(default)]
    pub socket_sndbuf: usize,
    #[serde(default)]
    pub socket_rcvbuf: usize,
    /// Hosts allowed to receive a 101. EMPTY MEANS ALLOW ANY, which is what the
    /// fleet runs and why this defaults off — but on a dedicated endpoint it is the
    /// difference between a probe oracle and a 404. See http.rs.
    #[serde(default)]
    pub allowed_upgrade_hosts: Vec<String>,
    /// Same-port Proteus: one PSF whose clients share `bind` and `extra_binds`
    /// with plain HTTP clients. Absent = every connection is HTTP.
    #[serde(default)]
    pub proteus_psf: Option<String>,
    /// Same-port Proteus with several PSFs, told apart by the fixed bytes their
    /// first client message opens with; at most one may have none.
    #[serde(default)]
    pub proteus_psfs: Vec<String>,
}

impl HttpConfig {
    /// Every same-port PSF, `proteus_psf` first.
    pub fn same_port_psfs(&self) -> Vec<String> {
        self.proteus_psf
            .iter()
            .chain(self.proteus_psfs.iter())
            .cloned()
            .collect()
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: default_http_bind(),
            extra_binds: Vec::new(),
            proxy_protocol: PpMode::Disabled,
            socket_sndbuf: 0,
            socket_rcvbuf: 0,
            allowed_upgrade_hosts: Vec::new(),
            proteus_psf: None,
            proteus_psfs: Vec::new(),
        }
    }
}

fn default_http_bind() -> String {
    "0.0.0.0:80".to_string()
}

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    /// Where to serve Prometheus metrics. Defaults to loopback.
    #[serde(default = "default_metrics_bind")]
    pub bind: String,

    /// Required before `bind` may be anything but loopback.
    #[serde(default)]
    pub allow_public: bool,
}

impl MetricsConfig {
    /// The address to actually bind, after the loopback guard.
    pub fn effective_bind(&self) -> (String, bool) {
        if self.allow_public || Self::is_loopback(&self.bind) {
            return (self.bind.clone(), false);
        }
        let port = self.bind.rsplit(':').next().unwrap_or("9090");
        (format!("127.0.0.1:{port}"), true)
    }

    /// Loopback by address, not by string match — `0.0.0.0`, `::`, a public IP and
    /// a hostname all correctly fail this.
    fn is_loopback(bind: &str) -> bool {
        use std::net::{IpAddr, SocketAddr};
        if let Ok(sa) = bind.parse::<SocketAddr>() {
            return sa.ip().is_loopback();
        }

        let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        host.parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    }
}

/// Relay buffer tuning. Per-tunnel heap footprint is dominated by the two relay
/// buffers (c2t 64KB + t2c 32KB = 96KB/conn). Starting them small and growing
/// on demand cuts idle-tunnel RSS sharply at ~700k-conn scale.
#[derive(Debug, Deserialize)]
pub struct RelayConfig {
    /// Initial size (bytes) of both relay buffers. 0 = current behavior (allocate
    /// full 64KB/32KB up front). When >0, buffers start at this size and grow on
    /// demand up to the protocol caps (65535 c2t, 32768 t2c).
    #[serde(default)]
    pub initial_buffer: usize,

    /// I/O backend for the single-stream tunnel relay hot loop. "epoll" (default) =
    /// the proven tokio/epoll relay, byte-for-byte unchanged. "iouring" =
    /// experimental io_uring relay (single-stream path only; MUX2 is unaffected).
    #[serde(default = "default_io_backend")]
    pub io_backend: String,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            initial_buffer: 0,
            io_backend: default_io_backend(),
        }
    }
}

fn default_io_backend() -> String {
    "epoll".to_string()
}

impl RelayConfig {
    /// True only when io_backend is explicitly set to the io_uring path.
    pub fn use_iouring(&self) -> bool {
        self.io_backend.eq_ignore_ascii_case("iouring")
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            bind: default_metrics_bind(),
            allow_public: false,
        }
    }
}

fn default_metrics_bind() -> String {
    "127.0.0.1:9090".to_string()
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config {}: {}", path, e))?;
        let config: Config =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("Failed to parse config: {}", e))?;

        if config.private_key.len() != 64 {
            anyhow::bail!(
                "private_key must be 64 hex chars (32 bytes), got {}",
                config.private_key.len()
            );
        }
        if config.public_key.len() != 64 {
            anyhow::bail!(
                "public_key must be 64 hex chars (32 bytes), got {}",
                config.public_key.len()
            );
        }
        for (i, k) in config.extra_private_keys.iter().enumerate() {
            if k.len() != 64 {
                anyhow::bail!(
                    "extra_private_keys[{i}] must be 64 hex chars, got {}",
                    k.len()
                );
            }
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
private_key = "aa"
public_key  = "bb"
"#;

    fn parse(s: &str) -> Config {
        toml::from_str(s).unwrap_or_else(|e| panic!("config rejected: {e}"))
    }

    #[test]
    fn a_minimal_config_parses_with_the_cid_stats_on() {
        assert!(parse(MINIMAL).stats.cids);
    }

    #[test]
    fn the_cid_stats_can_be_turned_off() {
        let c = parse(&format!("{MINIMAL}
[stats]
cids = false
"));
        assert!(!c.stats.cids);
    }

    /// The production cutover procedure depends on this: the new binary is deployed
    /// against the *existing* config file, which carries sections for subsystems
    /// this binary knows nothing about.
    #[test]
    fn unknown_sections_and_keys_are_ignored() {
        let c = parse(&format!(
            "{MINIMAL}
some_future_scalar = 42

[tls]
cert = \"/x\"

[mqtt]
broker = \"tcp://x:1883\"

[postgres]
dsn = \"postgres://x\"

[clickhouse]
url = \"http://x:8123\"

[datadog]
api_key = \"x\"

[stats]
cids = true
unknown_stats_flag = true
"
        ));
        assert!(c.stats.cids, "known keys still applied alongside unknown ones");
        assert_eq!(c.private_key, "aa");
    }

    #[test]
    fn relay_initial_buffer_defaults_to_zero_meaning_full_buffers() {
        assert_eq!(parse(MINIMAL).relay.initial_buffer, 0);
        let c = parse(&format!("{MINIMAL}\n[relay]\ninitial_buffer = 16384\n"));
        assert_eq!(c.relay.initial_buffer, 16384);
    }

    #[test]
    fn the_host_gate_defaults_to_empty_which_is_fail_open() {
        assert!(
            parse(MINIMAL).http.allowed_upgrade_hosts.is_empty(),
            "default changed — the probe gate's fail-open posture moved"
        );
        let c = parse(&format!(
            "{MINIMAL}\n[http]\nallowed_upgrade_hosts = [\"a.example\", \"b.example\"]\n"
        ));
        assert_eq!(c.http.allowed_upgrade_hosts.len(), 2);
    }

    /// Both new sections must default OFF so that deploying this binary against an
    /// unchanged config is a no-op.
    #[test]
    fn protection_and_messaging_default_off_with_seeded_lists() {
        let c = parse(MINIMAL);
        assert!(!c.protection.enabled);
        assert!(!c.messaging.enabled);
        assert_eq!(c.protection.brands, vec!["rostam"]);
        assert_eq!(
            c.protection.allow_hosts,
            vec!["rostam.app", "*.rostam.app", "*.cloudfront.net", "*.amazonaws.com"],
            "the app's own control plane is exempt by default"
        );
        assert!(
            c.protection.block_bits.is_empty(),
            "the bundle's kinds decide by default"
        );
        assert!(c.protection.notify_bits.is_empty());
        assert!(c.protection.valkey.is_none());
        let c = parse(&format!(
            "{MINIMAL}\n[protection]\nenabled = true\npubkey = \"ab\"\nbrands = [\"x\"]\n\
             allow_hosts = []\n\
             [protection.valkey]\naddr = \"127.0.0.1:6379\"\ntls = false\n\
             [messaging]\nenabled = true\n"
        ));
        assert!(c.protection.enabled && c.messaging.enabled);
        assert_eq!(c.protection.brands, vec!["x"]);
        assert!(
            c.protection.allow_hosts.is_empty(),
            "an explicit empty list overrides the seeded default"
        );
        assert!(!c.protection.valkey.as_ref().unwrap().tls);
    }

    #[test]
    fn prefer_ipv6_defaults_off() {
        assert!(!parse(MINIMAL).prefer_ipv6);
        assert!(parse(&format!("{MINIMAL}\nprefer_ipv6 = true\n")).prefer_ipv6);
    }

    #[test]
    fn egress_ips_and_ignore_lists_default_empty() {
        let c = parse(MINIMAL);
        assert!(c.egress_ips.is_empty());
        assert!(
            c.stats.valkey.is_none(),
            "no valkey block means no stats shipping"
        );
    }

    /// Like `[protection]` and `[messaging]`: absent means no Proteus listener,
    /// so an unchanged config starts an unchanged server.
    #[test]
    fn the_proteus_section_is_absent_by_default_and_parses_when_given() {
        assert!(parse(MINIMAL).proteus.is_none());
        let c = parse(&format!(
            "{MINIMAL}\n[proteus]\nbind = \"0.0.0.0:443\"\npsf = \"proteus/tls_mimic.psf\"\n"
        ));
        let p = c.proteus.expect("section present");
        assert_eq!(p.bind, "0.0.0.0:443");
        assert_eq!(p.psf, "proteus/tls_mimic.psf");
        assert!(p.extra_binds.is_empty());
        let c = parse(&format!(
            "{MINIMAL}\n[proteus]\nbind = \"0.0.0.0:443\"\npsf = \"x.psf\"\n\
             extra_binds = [\"[::]:443\"]\n"
        ));
        assert_eq!(c.proteus.unwrap().extra_binds, vec!["[::]:443"]);
    }

    #[test]
    fn same_port_psfs_default_empty_and_merge_the_single_and_list_forms() {
        assert!(parse(MINIMAL).http.same_port_psfs().is_empty());
        let c = parse(&format!("{MINIMAL}\n[http]\nproteus_psf = \"a.psf\"\n"));
        assert_eq!(c.http.same_port_psfs(), vec!["a.psf"]);
        let c = parse(&format!(
            "{MINIMAL}\n[http]\nproteus_psf = \"a.psf\"\nproteus_psfs = [\"b.psf\", \"c.psf\"]\n"
        ));
        assert_eq!(c.http.same_port_psfs(), vec!["a.psf", "b.psf", "c.psf"]);
    }

    #[test]
    fn a_malformed_config_is_an_error_not_a_default() {
        assert!(toml::from_str::<Config>("private_key = 12345").is_err());
        assert!(toml::from_str::<Config>("[[[broken").is_err());
    }
}

#[cfg(test)]
mod metrics_bind_tests {
    use super::MetricsConfig;

    fn cfg(bind: &str, allow: bool) -> MetricsConfig {
        MetricsConfig {
            bind: bind.to_string(),
            allow_public: allow,
        }
    }

    /// The default must be loopback.
    #[test]
    fn the_default_bind_is_loopback() {
        assert!(MetricsConfig::is_loopback(&super::default_metrics_bind()));
    }

    /// Every way of saying "not loopback" must be clamped without the flag.
    #[test]
    fn public_binds_are_clamped_without_the_flag() {
        for b in [
            "0.0.0.0:9090",
            "[::]:9090",
            "172.32.36.171:9090",
            "192.168.1.5:9999",
        ] {
            let (eff, clamped) = cfg(b, false).effective_bind();
            assert!(clamped, "{b} should have been clamped");
            assert!(
                MetricsConfig::is_loopback(&eff),
                "{b} clamped to non-loopback {eff}"
            );
        }
    }

    /// The port must survive clamping, or scrapers break for a reason nobody will
    /// connect to this.
    #[test]
    fn clamping_keeps_the_port() {
        let (eff, _) = cfg("0.0.0.0:9999", false).effective_bind();
        assert_eq!(eff, "127.0.0.1:9999");
    }

    /// Loopback in any spelling is left alone.
    #[test]
    fn loopback_is_never_clamped() {
        for b in [
            "127.0.0.1:9090",
            "[::1]:9090",
            "localhost:9090",
            "127.0.0.5:9090",
        ] {
            let (eff, clamped) = cfg(b, false).effective_bind();
            assert!(!clamped, "{b} should not be clamped");
            assert_eq!(eff, b);
        }
    }

    /// The flag is the only thing that permits it, and it must actually work.
    #[test]
    fn the_explicit_flag_permits_a_public_bind() {
        let (eff, clamped) = cfg("0.0.0.0:9090", true).effective_bind();
        assert!(!clamped);
        assert_eq!(eff, "0.0.0.0:9090");
    }
}
