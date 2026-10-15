# DPDK / High-Performance Proxy Architecture Study

Research for RedSocket Rust replacement of VPP plugin (crashes with multiple workers).
Goal: 10Gbps+ DPDK throughput. Sources: Cloudflare, Katran, GLB, Envoy, DPDK docs.

---

## 1. Cloudflare — kernel+XDP path (NOT DPDK), TLS/HTTP at line rate

Cloudflare's edge is the canonical "line-rate TLS+HTTP" design, and it deliberately
**does not use DPDK**. Their lesson: the Linux kernel path with XDP/eBPF can hit
10/25/100G line rates while keeping the whole kernel ecosystem (iptables, sockets,
stats). Key architecture:

**Inbound packet path (per server):**
1. Router does ECMP → spreads each IP across ≥16 machines.
2. **XDP eBPF stage 1**: volumetric L3 DoS drop (L4Drop) — drops attack packets at driver level.
3. **XDP stage 2**: L4 load balancing — `XDP_TX`/redirect rebalances non-attack packets across machines; gives fine-grained balancing and graceful server drain, working around ECMP's broken rehash-on-change.
4. Normal kernel stack: iptables firewall (L7 mitigations: connlimit, hashlimit, ipset, xt_bpf), then socket dispatch.
5. Application: NGINX "protocol server" — one worker process per core, does TLS termination + HTTP/1/2 + QUIC. eBPF sockmap (`SO_ATTACH_BPF`, `SK_SKB` veredict) does **in-kernel TCP splicing** to bypass userspace for proxying.
6. UDP socket defense: single UDP socket + eBPF socket filter keeping per-IP rate state in a BPF map (instead of 30k sockets for 30k IPs).

**Patterns to steal:**
- Do cheap stateless work (drop, hash-forward) in the earliest possible stage; only let real connections touch the heavy stack.
- Per-core workers with `SO_REUSEPORT`; never share connection state between workers.
- Graceful upgrade: control individual workers (Cloudflare patched NGINX to restart workers one at a time) — relevant to RedSocket's multi-worker crash problem: process isolation beats thread isolation for blast radius.
- eBPF lessons: verifier counting bug ("eBPF can't count"), lack of race-free token bucket until `bpf_spin_lock` (Feb 2019).

**Numbers:** XDP drop path handles ~10M+ pps per core class workloads; production edge servers saturate 25G/100G NICs with the kernel path. NGINX workers scale ~linearly with cores for TLS when using kTLS / session cache sharding.

---

## 2. Katran (Meta) — L4 LB with XDP/eBPF (also not DPDK)

Design principles (from engineering.fb.com post + repo):

- **Forwarding plane entirely in XDP**: BPF program runs per RX queue; uses only **per-CPU BPF maps** → completely lockless → **scales linearly with NIC RX queues**.
- **Maglev consistent hashing** for backend selection; connection consistency without per-flow state in the LB. A shared QUIC-connection-id based routing for new flows.
- **Encap, not NAT**: Katran encapsulates packets (IPIP/GUE) to backends, so it only sees inbound traffic — return traffic goes direct-to-client (DSR). LB CPU cost ~halved vs full-NAT.
- No busy loop: XDP is interrupt/NAPI-driven, unlike DPDK poll-mode — Facebook explicitly cites eliminating DPDK-style idle polling as a win.
- "Generic XDP" mode supported at a performance cost (runs after skb allocation; ~30-50% slower).

**Numbers:** Handles all of Facebook's PoP L4 traffic; line-rate 10G+ per server with a fraction of the cores a DPDK box needs idle. Per-queue scaling is documented as linear.

**Takeaway for RedSocket:** per-CPU state + encapsulation + stateless consistent hashing is how you avoid the shared-table lock that is almost certainly what kills your VPP plugin with multiple workers.

---

## 3. GLB Director (GitHub) — the actual DPDK L4 LB design

github/glb-director, rewritten in DPDK after the first version couldn't hit line rate.

**Architecture:**
- Split director/proxy tiers. **Director is completely flow-stateless** — the single source of truth for connection state is the Linux TCP stack on the proxy (HAProxy) hosts.
- **Rendezvous (highest-random-weight) hashing** computed up front into a forwarding table → picks primary + secondary proxy per flow. On proxy add/remove, 1/N flows get a new primary and the old primary becomes secondary ("second chance" forwarding via a custom iptables module `glb-redirect` on the proxies).
- **GUE (Generic UDP Encapsulation)** inside the datacenter to carry the original packet to the proxy; proxies decap in kernel. Fou/gue tunnel + direct server return.
- **Flow bifurcation**: bonded NIC pair shared between DPDK and Linux — SR-IOV VF + rte_flow rules steer GLB-destined IPs to the DPDK process; everything else stays on the kernel PF. This means **no dedicated NICs**, servers provisioned normally.
- DPDK side: classic run-to-completion, one lcore per RX queue, hugepage mbuf pools, lockless `rte_hash` / LPM table lookups for the forwarding table. Table updates via RCU-style swap (build new table, atomic pointer swap, free old after grace period).

**Numbers:** NIC line rate (10G+) on commodity NICs/CPUs; director tier scales trivially by adding servers behind ECMP.

**Takeaway for RedSocket:**
- Stateless fast path + hash-table-swap updates = zero locks in packet path.
- Flow bifurcation is the clean way to run DPDK on only *your* traffic while Linux keeps the rest — directly applicable to RedSocket's HTTP upgrade use case.

---

## 4. Envoy + XDP/DPDK — integration patterns (and why Envoy itself stays in kernel)

Envoy core deliberately does **not** use DPDK. The measured reasons (relevant to a Rust rewrite):

- DPDK poll-mode threads burn 100% CPU even idle; Envoy's event-driven epoll model is far more efficient at sub-saturation loads.
- Full kernel bypass loses: iptables/conntrack, TCP congestion control maturity, kTLS, socket stats, tcpdump.
- At L7, per-packet cost is dominated by TLS crypto + header parsing, not the kernel stack — kernel bypass saves ~1-2µs/packet while a TLS handshake costs ~1ms of CPU. ROI is poor.

**Actual integration patterns in the wild:**
1. **XDP/eBPF in front of Envoy** (Cilium): XDP does L4 LB / DDoS drop / kube-proxy replacement; only policy-relevant flows reach Envoy via a sidecar-less socket redirect (`bpf_sk_assign` / sockmap). Cilium 1.8: ~3.6M req/s, maxed a 10M pps generator on the drop path.
2. **Kernel acceleration for Envoy**: kTLS offload, `SO_REUSEPORT`, `TCP_FASTOPEN`, io_uring (experimental).
3. **DPDK-adjacent L7 proxies** (when kernel bypass *is* used): separate the fast path (DPDK, TCP reassembly, flow table) from the slow path (L7 in userspace over the reassembled stream) — e.g. F-Stack (DPDK + FreeBSD stack + NGINX), DPVS (iqiyi, DPDK LVS derivative, ~20M+ pps). Pattern: DPDK carries a *full userspace TCP stack*, L7 app sits on top via a socket shim.
4. **AF_XDP**: the middle ground — packets steered into userspace rings without full driver bypass; keeps kernel driver, gets ~70-80% of DPDK pps with interrupt-driven wakeups. Good fit for a Rust proxy: `xsk` rings map naturally onto async Rust / per-core runtimes (glommio/tokio-uring style).

**Takeaway for RedSocket:** for TLS+HTTP at 10Gbps you don't need full DPDK; you need (a) per-core run-to-completion workers, (b) zero shared mutable state on the hot path, (c) batching, (d) kTLS or userspace TLS with per-core session caches. AF_XDP or XDP-redirect are the lower-risk options; DPDK is justified mainly for the L4/encap fast path (GLB-style).

---

## 5. Common pitfalls and fixes

### Memory fragmentation
- DPDK mbuf pools are **fixed-size, per-lcore cached** (`rte_mempool` with per-core cache of ~512 mbufs) specifically to make alloc/free O(1) and lock-free in the common case. Never malloc in the packet path.
- Fragmentation comes from mixing sizes: use multiple mempools per packet size class (jumbo vs standard) rather than variable-size allocation.
- Hugepages (2M/1G) must be reserved at boot; on NUMA systems allocate per-socket (`--socket-mem`) or some nodes starve. DPDK docs note >1GB/page-size systems may not fully allocate.
- Long-running proxies: session/connection objects should come from slab/arena allocators per worker, never a global allocator — glibc malloc arenas under multithreaded churn are a classic fragmentation + contention double-whammy. In Rust: per-worker `bumpalo`/slab arenas, or `mimalloc` with per-thread heaps.

### Lock contention
- The Katran/GLB rule: **no shared mutable state in the fast path. Period.** Per-CPU/per-queue tables + RCU-swap for updates.
- If you must share: shard the flow table by hash (256+ shards, one lock each) — but prefer RCU (`arc-swap` / `left-right` in Rust) so readers never block.
- Watch out for "hidden" locks: global stats counters (use per-CPU counters aggregated on read), logger flushes, DNS resolution, metrics registries. Each is a convoy point.
- False sharing: two hot per-core counters on the same 64B cache line = lock-like slowdown with no lock. Pad per-core structs to `#[repr(align(64))]` / `cache_line_aligned`.

### Cache misses
- Structure-of-arrays for flow tables; keep the hot lookup key + next hop in one cache line (GLB keeps forwarding entries to 64B).
- Batch RX (32-64 packets), then batch the *same stage* across the burst before moving on — keeps I-cache and the stage's data hot. This is VPP's own vector-processing insight; your Rust replacement should keep it.
- Prefetch next packet's header while processing current (`rte_prefetch0` / `_mm_prefetch`).
- NUMA: pin worker to the core's local node, allocate that worker's pools/buffers on the same node; a remote-NUMA LLC miss is ~2-3x local.
- Measure with `perf stat -e cache-misses,LLC-load-misses` — target <1% LLC miss on the hot loop; PacketFlow cites 85% LLC-miss reduction from NUMA-aware hugepages + cache-aligned structs alone.

### Multi-worker crashes (your current VPP bug class)
Typical root causes in this exact situation:
1. Shared flow/session table mutated by workers without proper RCU grace period → use-after-free. Fix: epoch-based reclamation (crossbeam-epoch) or `left-right`.
2. Mempool shared across lcores without cache → contention and, with bugs, double-free. Fix: per-lcore pools or pool-per-worker.
3. RX queue not 1:1 with worker → two workers touching one ring. Fix: RSS flow-director rules pinning flows to queues, one queue per worker, exactly like Katran/GLB.
4. Control-plane config update racing the datapath. Fix: RCU table swap (GLB pattern), never in-place mutation.

---

## Recommended pattern for the RedSocket Rust replacement

- **L4 fast path (10Gbps)**: DPDK (or AF_XDP for lower risk), run-to-completion, one worker thread per RX queue, per-worker mbuf pools, RSS+flow-director so each flow lands on exactly one worker — zero cross-worker traffic.
- **State**: flow table sharded per worker (no sharing); config/forwarding tables swapped RCU-style from control plane (GLB pattern). Epoch reclamation via crossbeam-epoch.
- **L7 (TLS+HTTP)**: same-worker handoff (flow never migrates cores) with userspace TLS (rustls) or kTLS; per-worker session ticket cache — Cloudflare's per-core NGINX worker model.
- **Batching**: VPP-style vector processing — bursts of 32-64, stage-at-a-time.
- **Memory**: per-worker arenas for connection state, 64B-aligned hot structs, hugepages on local NUMA node.
- **Backpressure/idle**: DPDK `rte_power_monitor` (UMWAIT) or interrupt mode if idle-CPU burn matters.
