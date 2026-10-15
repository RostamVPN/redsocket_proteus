# Userspace TCP + DPDK Research for RedSocket

Research summary for building a Rust userspace TCP stack with DPDK for a censorship tunnel
targeting ~500K concurrent users (Iran deployment context).

---

## 1. Existing DPDK + userspace TCP projects

### mTCP (KAIST)
- Repo: https://github.com/mtcp-stack/mtcp
- Paper: "mTCP: a Highly Scalable User-level TCP Stack for Multicore Systems", NSDI'14
  (Jeong et al.) — https://www.usenix.org/system/files/conference/nsdi14/nsdi14-paper-jeong.pdf
- Design: per-core TCP threads, RSS for flow→core affinity, batched packet I/O + batched
  flow-level events, lock-free SPSC queues between app thread and TCP thread, per-core
  memory pools in hugepages, hash-bucketed retransmit timers.
- Results: 25x Linux for short transactions, ~0.3M→ multi-M TPS on 8 cores.
- Reputation: **fast but buggy / not robust** (F-Stack issue #26: "mTCP is not robust and
  buggy (we have tested it with dpdk)"). Fine as a design reference; risky as a base.

### F-Stack (Tencent)
- Repo: https://github.com/F-Stack/f-stack
- FreeBSD 11/13 TCP/IP stack ported to userspace on DPDK. POSIX-like API + coroutine
  (micro-thread) API; Nginx/Redis ports exist. Multi-process model (one app instance per
  process, shares NIC via primary/secondary DPDK processes).
- Pros: mature, full-featured TCP (congestion control, sysctl tooling), production use at
  Tencent. Cons: multi-process model is awkward ("can't run multiple different apps at the
  same time"); can underperform kernel stack at low connection counts; C codebase.

### Seastar (ScyllaDB)
- Repo: https://github.com/scylladb/seastar
- C++ share-nothing thread-per-core framework with its own native TCP/IP stack on DPDK.
  Futures/promises, per-core memory allocator, zero-copy, I/O scheduler.
- Proven at scale in ScyllaDB. Native stack is simpler than FreeBSD's; reported WAN
  robustness issues (same F-Stack thread). C++ — not directly usable for a Rust project,
  but the architecture (share-nothing, message passing between shards) is the gold
  standard pattern to copy.

### Demikernel / Catnip (Microsoft)
- Repo: https://github.com/microsoft/demikernel
- SOSP'21 paper: "The Demikernel Datapath OS Architecture for Microsecond-scale
  Datacenter Systems". Catnip is the DPDK Rust LibOS (Catnap = Windows, Catpow = Linux
  libOS). PDESched: explicit coroutine scheduling, zero-copy, ~13µs latency.
- **Rust + DPDK, research-grade.** Good architectural reference for async Rust on DPDK;
  not production-hardened (papers note small-scale deployments only).

### VPP host stack (FD.io)
- https://github.com/FDio/vpp — full userspace TCP (session layer + transport), VCL
  POSIX-like shim. High performance but the session layer is historically the buggiest
  part; complexity is enormous. Lesson: don't reinvent VPP; its failure mode was
  coupling session management to a graph-node packet-processing model with
  process/worker handoff bugs.

### Comparisons worth reading
- Tempesta blog "User space TCP?" — https://tempesta-tech.com/blog/user-space-tcp/
  (argues ported kernel stacks ≠ automatically faster; benchmark skepticism on F-Stack).
- ATC'25 paper "Opening Up Kernel-Bypass TCP Stacks" — https://www.usenix.org/system/files/atc25-awamoto.pdf
  (taxonomy + reproducibility study of mTCP/F-Stack/Demikernel; good recent survey).

---

## 2. Rust DPDK crates — production readiness

| Crate | Status | Notes |
|---|---|---|
| `dpdk-sys` (crates.io) | **Stale** | Bindgen FFI for DPDK **18.05** (2018). Unusable against modern DPDK 22/23/24 LTS without regenerating. |
| `codilime/rust-dpdk` (~103★) | Semi-maintained | Safe-ish wrappers; small community. Good API design study, not battle-tested at scale. |
| **NetBricks** (netsys/netbricks) | **Unmaintained** | OSDI'16 paper (Panda et al., 400+ citations): https://www.usenix.org/system/files/conference/osdi16/osdi16-panda.pdf. Proved Rust+DPDK zero-cost NFV with compile-time-checked packet parsing. Build broken on modern DPDK; read the paper, don't reuse the code. |
| `youyuanwu/rust-dpdk-net` | Active, small | **Most relevant existing work**: DPDK + smoltcp + tokio/axum/tonic stack in Rust with async/await. Clean layering (dpdk-net-sys FFI → smoltcp → async runtime → axum/tonic). Worth cloning and benchmarking as a reference architecture. |
| smoltcp | Maintained, production (embedded) | https://github.com/smoltcp-rs/smoltcp. Single-threaded by design (`Interface` owns sockets; not `Sync`). Community report: **50 Gbps on a single EPYC Milan core** when bolted to DPDK. For multi-core: one `Interface` + socket set per worker, flows pinned by RSS. |

**Verdict:** there is no mature, general-purpose Rust DPDK framework. The pragmatic
path (and what rust-dpdk-net demonstrates) is: own bindgen-generated `dpdk-sys` against
a pinned modern DPDK LTS (23.11+), a thin safe wrapper, and smoltcp (or a custom minimal
TCP) per worker. This matches what Demikernel/Catnip did.

---

## 3. Multi-worker lock-free architecture patterns

Canonical pattern (mTCP, Seastar, VPP, F-Stack all converge here):

1. **RSS at the NIC**: `rte_eth_rss_conf` with `RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP` hashes
   4-tuples to N RX queues; one RX/TX queue pair per worker core → flow-to-core affinity,
   no locks on the data path. For a *proxy/tunnel*, also look at **symmetric RSS** (or
   rte_flow rules) so both directions of a flow land on the same worker — VPP's
   "bidirectional RSS" discussion (lists.fd.io vpp-dev topic 108411130) is exactly this
   problem.
2. **rte_flow / Flow Director** for exceptions: steer tunnel-control traffic or specific
   ports to dedicated queues (e.g., Noise handshake core vs. data cores).
3. **Share-nothing workers**: per-core flow tables, socket buffers, mempools
   (`rte_mempool` per lcore cache), hugepages for TLB. Cross-core only via SPSC/MPMC
   lock-free rings (`rte_ring`) — e.g., control-plane → worker config updates.
4. **Batching everywhere**: burst RX/TX (32–64 pkts), batch flow events up to the app,
   batch app writes down — mTCP's core insight, amortizes everything.
5. **Run-to-completion vs pipeline**: for a tunnel (fixed, small processing graph),
   run-to-completion per flow on one core beats pipeline stages (avoids handoff rings).
   VPP uses pipeline + worker handoff; that handoff (via `session layer`) is where many
   of its bugs and cache misses live. **Recommendation: run-to-completion, RSS-pinned.**
6. **Timers**: hash-bucketed retransmit/TIME_WAIT timers per worker (mTCP §3.2.2),
   driven by `rte_timer` or manual TSC-based wheels. No global timer wheel.
7. **CPU isolation**: isolcpus + nohz_full + RCU-nocbs on worker cores; NUMA-local
   mempools (`socket_id` on `rte_pktmbuf_pool_create`); pin IRQs away from workers.

---

## 4. Noise/WireGuard termination in userspace

### Cloudflare BoringTun — https://github.com/cloudflare/boringtun
- Userspace WireGuard (Noise_IKpsk2) in Rust; deployed on millions of 1.1.1.1 mobile
  clients and thousands of Cloudflare servers. Blog: https://blog.cloudflare.com/boringtun-userspace-wireguard-rust/
- **Key architectural fact: boringtun is deliberately split** — the library implements
  only the Noise handshake + ChaCha20-Poly1305/BLAKE2s/X25519 crypto and the
  encapsulation/decapsulation state machine (Tunn: `encapsulate()`/`decapsulate()`
  operate on byte buffers). **It owns no sockets, no timers, no threads.** The embedding
  app (boringtun-cli, Cloudflare's stack, or RedSocket) provides packet I/O and calls
  `update_timers()`.
- This is *exactly* the right shape for a DPDK integration: per-worker `Tunn` instances
  in the flow table, crypto inline in the run-to-completion loop, zero copies between
  decrypt and TCP reassembly where possible. Noise handshakes are cheap enough (X25519
  ~50µs) to run on data cores; only pin them to a separate core if handshake floods are
  a concern (they are, under censorship-driven reconnect storms — rate-limit instead).

### Lessons from wireguard-go (why BoringTun exists)
- wireguard-go's TUN/TAP + GC + goroutine-per-peer overhead made it far slower than the
  kernel module. BoringTun fixed this with buffer-oriented API + Rust ownership.
  Same lesson applies: **don't let the crypto layer own I/O**, and don't copy buffers
  between "NIC layer", "crypto layer", "TCP layer" — one mbuf chain end-to-end.

### Rust crates
- `snow` (Noise framework, pure Rust, maintained) — for a custom Noise pattern
  (e.g., Noise_NK/IK with probe-resistant tweaks) rather than WireGuard's fixed pattern.
- `x25519-dalek`, `chacha20poly1305`, `blake2` — if hand-rolling. Consider
  AES-GCM with AES-NI vs ChaCha20-Poly1305 on server CPUs (AES-NI usually wins on
  Xeon/EPYC; ChaCha wins on mobile).
- Per-session crypto state must live in the per-worker flow table (session locality =
  cache locality); never share session state across cores — rekeying races are the
  classic bug (WireGuard handles this with keypair rotation epochs + `keepalive`;
  boringtun's `Tunn` is explicitly `!Sync`).

---

## 5. Lessons from failures / pitfalls

**VPP session layer / host stack**
- Session-layer bugs historically dominate VPP host-stack issues: worker-handoff races
  (session owned by wrong worker after RSS rebalance), accept-queue backpressure
  deadlocks, TIME_WAIT table exhaustion, VCL fork/pthread interactions. Root cause:
  cross-core session mobility + a POSIX emulation layer. **Takeaway: pin sessions to
  workers permanently; if the NIC can't guarantee symmetric RSS, do SW re-distribution
  via rte_ring at ingress and eat one hop — never migrate live session state.**
- VPP's complexity budget: its TCP took years to reach interop robustness. A minimal
  tunnel TCP (you control both ends or one end) can skip huge swaths (no ECN, no
  SACK-blocks edge cases initially, one congestion control).

**mTCP**: correctness under WAN conditions (loss/reorder) is where research stacks
break; F-Stack chose FreeBSD's stack explicitly for this. If RedSocket tunnels TCP over
your own reliable transport, you sidestep most of this — only the *outer* leg needs a
real TCP stack (if any).

**F-Stack multi-process model**: DPDK primary/secondary process coupling makes crashes
correlated and upgrades painful (hugepage/ mempool format coupling). **Takeaway: single
process, multiple threads (Seastar-style), not F-Stack-style multi-process.**

**DPDK general pitfalls**
- Pin DPDK to an LTS (23.11.x); API churn between releases breaks bindgen crates.
- Hugepage exhaustion on crash (memfd/hugetlbfs leaks) — use `--huge-unlink` or in-memory mode.
- NIC compatibility: RSS toeplitz key control, symmetric RSS needs specific NICs
  (i40e/ice/mlx5 OK; some ixgbe firmware quirks). Mellanox mlx5 is the path of least
  resistance (also does flow steering + crypto offload).
- vfio vs igb_uio: prefer vfio (IOMMU) for security on a censorship-resistance box.
- Watchdog/livelock: pure polling burns cores at idle; `rte_eth_rx_burst` empty-loop
  backoff or interrupt mode (`rte_epoll`) for low-traffic periods — matters at 500K
  mostly-idle tunnel users.
- MTU/jumbo + tunnel overhead: account for Noise encapsulation expansion in MSS clamping.
- Tempesta's critique stands: don't assume userspace stack beats kernel at low
  concurrency; the win is at high CPS / high pps. Benchmark honestly per workload.

---

## 6. Recommendations for RedSocket

1. **Architecture**: single Rust process, Seastar-style share-nothing workers; one
   RSS queue pair per core; run-to-completion; symmetric RSS (or ingress SW steering)
   so each tunnel session lives on one core forever.
2. **Stack**: own bindgen `*-sys` against DPDK 23.11 LTS + thin safe wrapper;
   smoltcp per worker for the outer TCP leg (proven: 50 Gbps/core reports; rust-dpdk-net
   shows the async integration) — or a minimal custom TCP if the inner protocol is your
   own reliable transport. Study rust-dpdk-net and Demikernel/Catnip first.
3. **Crypto**: boringtun-style split — Noise/`snow` state machine per session, inline in
   the worker loop, no I/O ownership, `!Sync` per-session state, mbuf-chain zero-copy
   decrypt→reassembly.
4. **Interop safety**: censorship targets mean hostile middleboxes — RST injection,
   reordering, fragmentation games. Fuzz the TCP reassembly path (mTCP's reputation is
   your warning) and make the stack conservative on ingress parsing.
5. **Read first**: mTCP NSDI'14 paper (batching + per-core design), NetBricks OSDI'16
   (Rust zero-copy abstractions), Demikernel SOSP'21 (async Rust datapath), ATC'25
   "Opening Up Kernel-Bypass TCP Stacks" (modern survey), VPP session-layer wiki
   (what NOT to do).
