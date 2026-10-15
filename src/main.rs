// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RedSocket behind Proteus — the Noise NK tunnel, reachable only through a PSF.

use redsocket_http::{
    config, messaging, metrics, noise, noise_proxy, protection, proteus_carrier, proxy, shed,
    stats,
};

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("REDSOCKET_GIT"),
    " ",
    env!("REDSOCKET_BUILD_DATE"),
    ")"
);

#[derive(Parser)]
#[command(name = "redsocket-http", version = VERSION, about = "RedSocket tunnel behind a Proteus carrier")]
struct Cli {
    /// Path to config file.
    #[arg(long, default_value = "/etc/redsocket/config.toml")]
    config: String,

    /// Override the Proteus listen address (e.g., "0.0.0.0:443").
    #[arg(long)]
    bind: Option<String>,

    /// Override private key (hex, 64 chars).
    #[arg(long)]
    private_key: Option<String>,

    /// Override public key (hex, 64 chars).
    #[arg(long)]
    public_key: Option<String>,

    /// Generate a new keypair and print it.
    #[arg(long)]
    keygen: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    if cli.keygen {
        let (priv_key, pub_key) = noise::generate_keypair()?;
        println!("private_key = \"{}\"", hex::encode(priv_key));
        println!("public_key  = \"{}\"", hex::encode(pub_key));
        return Ok(());
    }

    let config = config::Config::load(&cli.config)?;

    let private_key_hex = cli.private_key.as_deref().unwrap_or(&config.private_key);
    let public_key_hex = cli.public_key.as_deref().unwrap_or(&config.public_key);
    let bind_addr = cli.bind.as_deref().unwrap_or(&config.proteus.bind);

    config::check_private_key("private_key", private_key_hex)?;

    let private_key_bytes = {
        let bytes = hex::decode(private_key_hex)
            .map_err(|e| anyhow::anyhow!("private_key hex decode: {}", e))?;
        if bytes.len() != 32 {
            anyhow::bail!("private_key not 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };

    let mut all_keys: Vec<[u8; 32]> = vec![private_key_bytes];
    for (i, k) in config.extra_private_keys.iter().enumerate() {
        let bytes = hex::decode(k)
            .map_err(|e| anyhow::anyhow!("extra_private_keys[{}] hex decode: {}", i, e))?;
        if bytes.len() != 32 {
            anyhow::bail!("extra_private_keys[{}] not 32 bytes", i);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        all_keys.push(arr);
    }
    if all_keys.len() > 1 {
        log::info!(
            "  extra keys:     {} rotation key(s) accepted",
            all_keys.len() - 1
        );
    }
    let server_keys: std::sync::Arc<Vec<[u8; 32]>> = std::sync::Arc::new(all_keys);

    let derived_pub = noise::pubkey_from_private(&private_key_bytes);
    let derived_pub_hex = hex::encode(derived_pub);
    if derived_pub_hex != public_key_hex {
        log::warn!(
            "[CONFIG] public_key mismatch: config={} derived={} — using derived",
            public_key_hex,
            derived_pub_hex
        );
    }
    let pubkey_hex = if derived_pub_hex == public_key_hex {
        public_key_hex.to_string()
    } else {
        derived_pub_hex
    };

    let dispatch = std::sync::Arc::new(proteus_carrier::Dispatch::load(&config.proteus.psfs)?);

    log::info!("═══ RedSocket Proteus v{} ═══", VERSION);
    log::info!("  bind:           {}", bind_addr);
    log::info!("  proteus psfs:   {}", dispatch.describe());
    log::info!("  proxy_protocol: {:?}", config.proteus.proxy_protocol);
    log::info!("  pubkey:         {}", pubkey_hex);
    let (metrics_bind_eff, metrics_clamped) = config.metrics.effective_bind();
    if metrics_clamped {
        log::warn!(
            "[METRICS] refusing to bind {} — that is not loopback and metrics.allow_public is \
             false. Serving on {} instead. These counters describe tunnel volume and node load \
             on a port reachable from Iran; set metrics.allow_public = true only if you have \
             deliberately firewalled it.",
            config.metrics.bind,
            metrics_bind_eff
        );
    } else if !metrics_bind_eff.starts_with("127.") && !metrics_bind_eff.starts_with("[::1]") {
        log::warn!(
            "[METRICS] serving on {} — NON-LOOPBACK, permitted by metrics.allow_public = true",
            metrics_bind_eff
        );
    }
    log::info!("  metrics:        {}", metrics_bind_eff);
    log::info!("══════════════════════════════════");

    let metrics_bind = metrics_bind_eff.clone();
    tokio::spawn(async move {
        if let Err(e) = run_metrics_endpoint(&metrics_bind).await {
            log::error!("[METRICS] Endpoint error: {}", e);
        }
    });

    stats::init_hostname();
    proxy::init_resolver();
    proxy::init_destination_policy(config.deny_cidrs.as_deref(), &config.allow_cidrs);
    proxy::init_egress(config.prefer_ipv6).await;
    metrics::init_egress_pool(&config.egress_ips);
    stats::set_flags(stats::StatsFlags { cids: config.stats.cids });

    let vk = config.stats.valkey.as_ref().or(config.valkey.as_ref());
    if let Some(vk) = vk {
        match std::fs::read_to_string(&vk.ca_file) {
            Ok(ca_pem) => stats::spawn(stats::Config {
                addr: vk.addr.clone(),
                password: vk.password.clone(),
                ca_pem,
                server_name: vk.server_name.clone(),
            }),
            Err(e) => log::error!(
                "[STATS] cannot read CA file {}: {} — stats disabled",
                vk.ca_file,
                e
            ),
        }
    }

    let egress: std::sync::Arc<[String]> = config.egress_ips.clone().into();
    if !egress.is_empty() {
        log::info!("  egress_ips:     {:?}", egress);
    }
    log::info!(
        "  socket bufs:    snd={} rcv={} (0=autotune)",
        config.proteus.socket_sndbuf,
        config.proteus.socket_rcvbuf
    );
    if config.shed.enabled {
        shed::spawn(
            config.shed.high_pct,
            config.shed.low_pct,
            std::time::Duration::from_secs(config.shed.interval_secs.max(1)),
        );
        log::info!(
            "[SHED] closing new connections above {}% of the memory limit, accepting again below \
             {}% (sampled every {}s). Clients rotate to another node; established tunnels are \
             never touched.",
            config.shed.high_pct,
            config.shed.low_pct,
            config.shed.interval_secs.max(1)
        );
    } else {
        log::warn!(
            "[SHED] disabled — this node will accept new tunnels until it runs out of memory, \
             and the OOM killer takes every established tunnel with it"
        );
    }

    protection::set_caps_wanted(config.protection.enabled || config.messaging.enabled);
    if let Some(vk) = &config.protection.valkey {
        vk.validate("protection.valkey")?;
    }
    if let Some(vk) = &config.messaging.valkey {
        vk.validate("messaging.valkey")?;
    }
    if config.protection.enabled {
        protection::init(&config.protection, &config.egress_ips)?;
        let source = if !config.protection.bundle_dir.is_empty() {
            protection::Source::Dir(config.protection.bundle_dir.clone().into())
        } else {
            let vk = config
                .protection
                .valkey
                .clone()
                .or_else(|| config.messaging.valkey.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "[protection] enabled but neither bundle_dir nor a [protection.valkey] \
                         / [messaging.valkey] connection is configured"
                    )
                })?;
            protection::Source::Valkey(vk)
        };
        log::info!("  protection:     on, bundle from {:?}", source);
        protection::spawn_reloader(source);
    }
    if config.messaging.enabled {
        match config.messaging.valkey.clone() {
            Some(vk) => {
                messaging::spawn(messaging::Config { valkey: vk });
                log::info!("  messaging:      on");
            }
            None => anyhow::bail!("[messaging] enabled but [messaging.valkey] is not configured"),
        }
    }

    noise_proxy::set_initial_relay_buffer(config.relay.initial_buffer);
    log::info!(
        "  relay bufs:     initial={} (0=full 64K/32K; grows to cap on demand)",
        config.relay.initial_buffer
    );

    let listener = proteus_carrier::listen(bind_addr)?;
    for extra in &config.proteus.extra_binds {
        let extra_listener = proteus_carrier::listen(extra)?;
        let dispatch = dispatch.clone();
        let keys = server_keys.clone();
        let pp = config.proteus.proxy_protocol;
        let eg = egress.clone();
        let snd = config.proteus.socket_sndbuf;
        let rcv = config.proteus.socket_rcvbuf;
        log::info!("  extra bind:     {}", extra);
        tokio::spawn(proteus_carrier::run(
            extra_listener,
            dispatch,
            keys,
            pp,
            eg,
            snd,
            rcv,
        ));
    }
    proteus_carrier::run(
        listener,
        dispatch,
        server_keys,
        config.proteus.proxy_protocol,
        egress,
        config.proteus.socket_sndbuf,
        config.proteus.socket_rcvbuf,
    )
    .await;

    Ok(())
}

async fn run_metrics_endpoint(bind: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    log::info!("[METRICS] Listening on {}", bind);

    loop {
        let (mut stream, _peer) = proteus_carrier::accept(&listener).await;
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                .await;

            let body = prometheus_text();
            let content_type = "text/plain; version=0.0.4";

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: {}\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-store\r\n\
                 \r\n{}",
                content_type,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

fn prometheus_text() -> String {
    let mut out = String::with_capacity(4096);

    out.push_str("# HELP redsocket_uptime_seconds Server uptime\n");
    out.push_str(&format!("redsocket_uptime_seconds {}\n", uptime_secs()));

    out.push_str("# HELP redsocket_active_relays Active relay connections\n");
    out.push_str(&format!(
        "redsocket_active_relays {}\n",
        metrics::active_relays()
    ));

    out.push_str("# HELP redsocket_total_connections Total connections\n");
    out.push_str(&format!(
        "redsocket_total_connections {}\n",
        metrics::total_connections()
    ));

    out.push_str("# HELP redsocket_egress_v4 Egress connections over IPv4\n");
    out.push_str(&format!("redsocket_egress_v4 {}\n", metrics::egress_v4()));

    out.push_str("# HELP redsocket_egress_v6 Egress connections over IPv6\n");
    out.push_str(&format!("redsocket_egress_v6 {}\n", metrics::egress_v6()));

    out.push_str("# HELP redsocket_egress_refused_unroutable Destinations refused before any connect: no resolved address is routable from an exit\n");
    out.push_str("# TYPE redsocket_egress_refused_unroutable counter\n");
    out.push_str(&format!(
        "redsocket_egress_refused_unroutable {}\n",
        metrics::egress_refused_unroutable()
    ));

    out.push_str("# HELP redsocket_prefer_ipv6 1 when egress prefers IPv6\n");
    out.push_str(&format!(
        "redsocket_prefer_ipv6 {}\n",
        u8::from(proxy::prefer_ipv6())
    ));

    let pool = metrics::egress_pool_counts();
    if !pool.is_empty() {
        out.push_str("# HELP redsocket_egress_ip_connects Successful connects per exit IP\n");
        for (ip, ok, _) in &pool {
            out.push_str(&format!(
                "redsocket_egress_ip_connects{{ip=\"{}\"}} {}\n",
                ip, ok
            ));
        }
        out.push_str("# HELP redsocket_egress_ip_failures Failed connects per exit IP\n");
        for (ip, _, fail) in &pool {
            out.push_str(&format!(
                "redsocket_egress_ip_failures{{ip=\"{}\"}} {}\n",
                ip, fail
            ));
        }
    }

    let (v4_up, v4_down, v6_up, v6_down) = metrics::egress_bytes();
    out.push_str("# HELP redsocket_egress_bytes_v4_up Bytes to IPv4 destinations\n");
    out.push_str(&format!("redsocket_egress_bytes_v4_up {}\n", v4_up));
    out.push_str("# HELP redsocket_egress_bytes_v4_down Bytes from IPv4 destinations\n");
    out.push_str(&format!("redsocket_egress_bytes_v4_down {}\n", v4_down));
    out.push_str("# HELP redsocket_egress_bytes_v6_up Bytes to IPv6 destinations\n");
    out.push_str(&format!("redsocket_egress_bytes_v6_up {}\n", v6_up));
    out.push_str("# HELP redsocket_egress_bytes_v6_down Bytes from IPv6 destinations\n");
    out.push_str(&format!("redsocket_egress_bytes_v6_down {}\n", v6_down));

    out.push_str("# HELP redsocket_bytes_up Total bytes uploaded\n");
    out.push_str(&format!(
        "redsocket_bytes_up {}\n",
        metrics::total_bytes_up()
    ));

    out.push_str("# HELP redsocket_bytes_down Total bytes downloaded\n");
    out.push_str(&format!(
        "redsocket_bytes_down {}\n",
        metrics::total_bytes_down()
    ));

    {
        let (shedding, pct, refused) = shed::stats();
        out.push_str("# HELP redsocket_shedding 1 while refusing new tunnels for memory\n");
        out.push_str("# TYPE redsocket_shedding gauge\n");
        out.push_str(&format!("redsocket_shedding {}\n", u8::from(shedding)));
        out.push_str("# HELP redsocket_mem_pct memory used as a percent of the enforced limit\n");
        out.push_str("# TYPE redsocket_mem_pct gauge\n");
        out.push_str(&format!("redsocket_mem_pct {}\n", pct));
        out.push_str("# HELP redsocket_shed_refused_total new connections closed for memory\n");
        out.push_str("# TYPE redsocket_shed_refused_total counter\n");
        out.push_str(&format!("redsocket_shed_refused_total {}\n", refused));
    }
    out.push_str("# HELP redsocket_hs_ok Noise handshake successes\n");
    out.push_str(&format!(
        "redsocket_hs_ok {}\n",
        metrics::handshake_successes()
    ));

    out.push_str("# HELP redsocket_hs_fail Noise handshake failures\n");
    out.push_str(&format!(
        "redsocket_hs_fail {}\n",
        metrics::handshake_failures()
    ));

    let (active_tunnels, total_tunnels) = (metrics::active_tunnels(), metrics::total_tunnels());
    out.push_str("# HELP redsocket_active_tunnels Active tunnels\n");
    out.push_str(&format!("redsocket_active_tunnels {}\n", active_tunnels));
    out.push_str("# HELP redsocket_total_tunnels Total tunnels created\n");
    out.push_str(&format!("redsocket_total_tunnels {}\n", total_tunnels));

    protection::prometheus(&mut out);
    messaging::prometheus(&mut out);

    if let Some(kb) = rss_kb() {
        out.push_str("# HELP redsocket_rss_bytes Resident set size\n");
        out.push_str(&format!("redsocket_rss_bytes {}\n", kb * 1024));
    }

    out
}

fn uptime_secs() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs()
}

/// Resident set size in KiB, straight from procfs. `None` off Linux.
fn rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
}
