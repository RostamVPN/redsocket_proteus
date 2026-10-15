# RedSocket mlx5 Userspace TCP Stack — Architecture Recommendation

**Scope:** a from-scratch Rust + DPDK userspace TCP terminator ("redtcp") on a Mellanox
ConnectX-5 (MT27800, `mlx5_core`) SR-IOV VF, sized for **600K–1M concurrent connections**
at **<8 KB/conn userspace RAM**, replacing the kernel-TCP tunnel server that currently
burns ~65 KB/conn and is RAM-bound at ~1.5M conns on a 110 GB box.

Workload per connection: terminate TCP :80 → HTTP `Upgrade` → `Noise_NK_25519_ChaChaPoly_BLAKE2s`
→ SOCKS5 `CONNECT` → relay to a kernel-side egress socket. Per-core run-to-completion, RSS
flow-pinned, one core never touches another core's connection.

> This doc supersedes the ixgbe-specific assumptions in
> `references/dpdk-transport-analysis.md` §3 and `docs/dpdk-proxy-architecture-study.md`.
> mlx5 is a fundamentally different beast from ixgbe: **no `vfio-pci`, no driver unbind,
> a bifurcated verbs datapath, and hardware flow steering (DR/DV) that ixgbe's Flow
> Director can't touch.** Everything about device setup changes.

---

## 0. Verdict up front (opinionated)

1. **BUILD a custom minimal TCP ("redtcp"). Do not adapt smoltcp, mTCP, TLDK, F-Stack, or
   Seastar's stack.** The reason is singular and decisive: **every one of those stacks owns
   its own socket buffers and copies payload into them.** Your entire memory thesis (10×
   density, <8 KB/conn) depends on the mbuf being the buffer end-to-end. A stack that copies
   RX payload into a per-socket ring buffer cannot be squeezed under 8 KB/conn without
   forking its buffer manager — at which point you've rewritten it. Steal *layout ideas*
   (TLDK's `tle_tcp_stream`, Seastar's share-nothing shards); write the code.
2. **mlx5 bifurcated path, SR-IOV VF, no `vfio-pci`.** Bind nothing. Create a VF, leave it on
   `mlx5_core`, DPDK attaches via `librte_net_mlx5` over `libibverbs`/`libmlx5`. The PF keeps
   carrying live host traffic on the kernel. This is exactly GLB's "flow bifurcation" but the
   mlx5 way (verbs, not `vfio` + a second NIC).
3. **Plain Toeplitz RSS is sufficient for flow→core pinning; symmetric RSS is *not* required
   for a pure terminator** (you generate the reply on the same core you received on — you own
   TX). Configure symmetric only if egress ever moves onto DPDK (phase 2). Recipe included.
4. **Zero-copy RX = store `NonNull<rte_mbuf>` in the per-conn reassembly list; gather-copy
   only when a Noise frame straddles mbuf boundaries** (~10–15 % of frames). Idle connections
   hold **zero** mbufs — this is what makes <8 KB/conn real.
5. **The real remaining memory term is the kernel egress socket, not redtcp.** redtcp gets you
   to ~600–900 B/conn userspace. The egress kernel TCP socket is ~8–12 KB/conn kernel RAM and
   is now the dominant cost. Address it (buffer clamping now; userspace egress in phase 2) or
   the 10× target slips to ~4–5×. Budget table §7 is honest about this.

---

## 1. mlx5 bifurcated driver — device setup (the part that is *not* like ixgbe)

### 1.1 Why there is no `vfio-pci` and no unbind

ixgbe/i40e/ice DPDK PMDs are **exclusive**: you unbind the PCI function from the kernel driver
and bind it to `vfio-pci` (or `igb_uio`), and the kernel loses the interface entirely. That is
impossible here — the PF carries live production traffic and must stay on the kernel.

mlx5 is a **bifurcated driver**. The DPDK `mlx5` PMD does *not* own the PCI function. The device
stays bound to `mlx5_core` (kernel). DPDK drives the datapath through the **RDMA verbs stack**
(`libibverbs` + the `libmlx5` provider, i.e. rdma-core), using **DevX**/**Direct Rules (DR)** to
program hardware queues and steering rules. Control (link, stats, the netdev) stays with the
kernel; the DPDK process gets its own hardware RX/TX queues and its own steering rules on the
same silicon. Kernel and DPDK coexist on the function. No `iommu=pt` juggling to hand the whole
device to a userspace process, no `vfio` group, no device disappearing from `ip link`.

**Consequence for provisioning:** you do not "give a NIC to DPDK." You create a **VF**, leave it
on `mlx5_core`, and point DPDK at the VF's PCI BDF. The PF and all other VFs are untouched.

### 1.2 SR-IOV VF creation (16 idle VFs already present)

```bash
# PF is e.g. enp175s0f0 at 0000:af:00.0. Confirm VF count and pick an idle one.
cat /sys/class/net/enp175s0f0/device/sriov_numvfs        # -> 16 (already provisioned)
lspci -d 15b3: | grep -i virtual                         # ConnectX-5 VF BDFs, e.g. af:00.2 ...

# Give the chosen VF a deterministic MAC and (optionally) a VLAN, from the PF side.
# The eSwitch forwards frames to this VF by destination MAC (legacy SR-IOV mode).
ip link set enp175s0f0 vf 0 mac 52:54:00:re:d5:0c
ip link set enp175s0f0 vf 0 spoofchk off                 # DPDK will source the carrier VIP MAC
ip link set enp175s0f0 vf 0 trust on                     # needed for some rte_flow / promisc ops
```

The VF appears as its own PCI function (`0000:af:00.2`) and its own netdev on the host. Leave
that netdev **down and unconfigured on the kernel** — DPDK will attach to the PCI function.
Do **not** unbind it from `mlx5_core`; the mlx5 PMD needs the kernel driver present to open the
verbs device.

### 1.3 Getting *carrier* traffic onto the VF (the bifurcation itself)

Two mechanisms, pick per how you own addressing:

- **Legacy SR-IOV (recommended, simplest):** the embedded switch (eSwitch) steers frames to a VF
  by **destination MAC** (and VLAN, if set). Put the **carrier VIP on the DPDK VF**: assign the
  VF a dedicated MAC (above), and have redtcp **answer ARP for the VIP** from DPDK (a 30-line ARP
  responder on the VF). The kernel PF keeps the host's management IP and all other traffic. Clean
  split, zero rte_flow needed for the coarse steer. This is the mlx5 analogue of "dual-port split"
  from the ixgbe doc — except it's one physical port shared via SR-IOV, not two ports.

- **switchdev + representors (if the VIP must share the PF's MAC/subnet):** put the PF eSwitch in
  `switchdev` mode (`devlink dev eswitch set pci/0000:af:00.0 mode switchdev`), which spawns a VF
  **representor** port. You then install `rte_flow` rules on the representor that match
  `dst=VIP, tcp dport=80` and action `port_id`→the VF (or `RTE_FLOW_ACTION_TYPE_QUEUE` inside the
  VF). Everything unmatched falls through to the kernel. This is exactly GLB's rte_flow
  bifurcation, done on mlx5's hardware steering engine. More flexible, more moving parts. Use only
  if you can't dedicate a MAC/VIP to the VF.

Start with legacy SR-IOV + VIP-on-VF + DPDK ARP responder. It is the least code and the least
that can go wrong on a production host with a live PF.

### 1.4 Host dependencies (rdma-core / ibverbs) — the actual package list

The mlx5 PMD `dlopen`s the ibverbs glue at runtime (or links directly, depending on build). You
need the RDMA userspace stack and the kernel RDMA modules — **not** `vfio-pci`.

Kernel modules (usually already loaded on a ConnectX host):
```bash
lsmod | grep -E 'mlx5_core|mlx5_ib|ib_uverbs|ib_core'   # all four should be present
ls /dev/infiniband/                                      # uverbs0, rdma_cm, issm... must exist
```
If `mlx5_ib` / `ib_uverbs` are missing, `modprobe mlx5_ib ib_uverbs` — this exposes the
`/dev/infiniband/uverbsN` char devices the PMD opens. The DPDK process needs read/write on those
(run as root, or grant the `rdma` cgroup / device ACLs).

Userspace packages (Debian/Ubuntu names; upstream rdma-core ≥ 27 is fine, MLNX_OFED also works):
```
libibverbs1  libibverbs-dev  ibverbs-providers   # provides libmlx5 provider .so
librdmacm1   librdmacm-dev
rdma-core                                          # devlink/ibv_devinfo tooling
pkgconf / pkg-config                               # DPDK meson finds libibverbs via pkg-config
```
Verify the provider is visible before touching DPDK:
```bash
ibv_devinfo            # must list mlx5_0 (PF) and the VF's verbs device, transport IB/RoCE
ibv_devices
```

DPDK build: with meson, mlx5 auto-enables when `libibverbs`/`libmlx5` are found. Confirm:
```bash
meson configure build | grep -i mlx5          # net/mlx5 should be in the enabled drivers
# or check the built tree:
ls build/drivers/ | grep mlx5                 # librte_net_mlx5.so, librte_common_mlx5.so
```
Optional but recommended: build with `-Denable_drivers=common/mlx5,net/mlx5,...` to keep the
binary lean, and set `MLX5_GLUE`/`ib_glue` behavior only if you deliberately want the dlopen
indirection (default static link is fine and simpler for a pinned deploy).

**Pin DPDK to a modern LTS: 23.11.x.** mlx5 DevX/DR support and RSS-hash-function control are
mature there; API churn between LTS lines breaks bindgen `dpdk-sys`. (Same rule as the ixgbe doc,
sharper here because mlx5's rte_flow surface moves fast.)

### 1.5 EAL args for the mlx5 VF

```
dpdk-app \
  -l 2-9 \                          # 8 worker lcores (isolate these, see §5)
  -n 4 \                            # memory channels (match the socket)
  -a 0000:af:00.2,dv_flow_en=1,mprq_en=1,rxqs_min_mprq=1,txq_inline_mpw=1 \
  --socket-mem=8192,0 \            # 8 GB hugepages on the NIC-local NUMA node only
  --proc-type=primary \
  --file-prefix=redtcp \           # isolate hugepage files from any other DPDK proc
  --                                # app args below
```

Key mlx5 devargs (the ones that matter for this workload), passed inline on `-a <BDF>,...`:

| Devarg | Value | Why |
|---|---|---|
| `dv_flow_en` | `1` | Use Direct Rules (DR) flow engine — required for efficient rte_flow/RSS steering on mlx5. |
| `mprq_en` | `1` | **Multi-Packet RQ**: multiple packets share one large RX buffer (strided RQ). Big memory + PPS win at high conn counts with small packets (HTTP/Noise frames are small). |
| `rxqs_min_mprq` | `1` | Enable MPRQ even with few rxqs. |
| `mprq_log_stride_num` / `mprq_log_stride_size` | tune | Controls strides per MPRQ buffer; size to your typical frame (~256–512 B strides for small Noise frames). |
| `txq_inline_mpw` / `txq_inline_min` | tune | Inline small TX payloads into the WQE (avoids a DMA gather for tiny ACK/small-frame TX). |
| `rxq_cqe_comp_en` | `1` | CQE compression — shrinks completion-queue memory and PCIe traffic at high queue depths. Real memory saver at 1M conns. |
| `rxq_pkt_pad_en` | `0` | Don't pad; we control alignment. |

Notes:
- `-a` (allowlist) the **VF BDF only**. Never allowlist the PF — you'd fight the kernel for it.
- `--socket-mem` (not `-m`) so hugepages come from the **NIC-local NUMA node**. Check
  `cat /sys/bus/pci/devices/0000:af:00.0/numa_node`; put all lcores, mempools, and the conn arena
  on that node. Cross-NUMA DMA on mlx5 at 10G+ is a 20–30 % tax (same as ixgbe).
- Hugepages: 2 MB pages are fine and easier to reserve at runtime; 1 GB pages help TLB at 1M
  conns but need boot-time reservation. Start 2 MB, measure TLB misses (`perf stat -e dTLB-load-misses`).
- No `vfio` args, no `--vdev`, no `igb_uio`. The device is a real PCI function on `mlx5_core`.

### 1.6 RSS / flow steering into the VF's queues

Two independent steering layers — don't conflate them:

1. **eSwitch → VF (coarse, done in §1.3):** dest-MAC (legacy) or rte_flow-on-representor
   (switchdev) puts *carrier frames* onto the VF. This is not RSS; it's device→VF selection.

2. **Inside the VF: RSS across the VF's RX queues → cores (fine).** The VF has its own set of RX
   queues (one per worker lcore). Configure RSS so a given ingress 4-tuple always lands on the
   same queue → same core → the conn lives on exactly one core forever.

RSS config for the VF (DPDK `rte_eth_dev_configure` + `rte_eth_rss_conf`):

```rust
let rss_conf = rte_eth_rss_conf {
    rss_key: TOEPLITZ_KEY.as_ptr() as *mut u8,   // 40-byte key; fixed, see below
    rss_key_len: 40,
    rss_hf: (RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP) as u64,
};
/* mode = RTE_ETH_MQ_RX_RSS; nb_rx_queues = nb_workers (e.g. 8). */
/* mlx5 RETA is programmable and sized generously; even split across 8 queues is exact */
/* (mlx5 indirection table is a power-of-two you set — pick 128 or 256, divisible by 8). */
```

- **Plain Toeplitz is enough for a terminator.** RSS guarantees all packets of one ingress flow
  hash to one queue. You reply on that same core (you own TX), so you never need the *return*
  direction to co-hash. Do **not** install symmetric RSS for a pure terminator — it buys nothing
  and can mildly worsen distribution.
- **Symmetric Toeplitz — only if egress moves to DPDK (phase 2).** mlx5 supports
  `RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ` as an rte_flow RSS-action hash function. If you ever
  terminate *both* legs on DPDK and want a bidirectional flow's two directions on the same core,
  use a symmetric key (the classic repeating pattern `0x6d 0x5a 0x6d 0x5a …` for all 40 bytes)
  **and** request the symmetric hash function via an `rte_flow` RSS action (not just
  `rss_conf`, which on mlx5 defaults to asymmetric Toeplitz). Until then: skip it.
- **mlx5 does RSS via `rte_flow` under the hood (DR).** With `dv_flow_en=1` you can also express
  RSS as an explicit `rte_flow` rule (`RTE_FLOW_ACTION_TYPE_RSS`) scoped to `tcp dport 80`, which
  is cleaner than the global `rss_conf` if you want non-carrier stray traffic on the VF handled
  differently. Keep the global `rss_conf` for simplicity unless you need per-rule RSS.

**Per-core queue ownership:** lcore *i* owns RX queue *i* and TX queue *i* exclusively.
`rte_eth_rx_burst(port, i, ...)` and `rte_eth_tx_burst(port, i, ...)` are called only from lcore
*i*. No locks, no cross-core rings on the hot path. This is the whole architecture.

---

## 2. Custom TCP for 1M connections — data structures

### 2.1 Connection identity and the flow table

Per core (share-nothing), the flow table maps a 4-tuple to a slab index:

```
FlowKey = { saddr: u32|u128, daddr: u32|u128, sport: u16, dport: u16 }   // v4 packs to 12B
FlowMap: open-addressing hash  FlowKey -> ConnId(u32)
Slab<Tcb>: Vec-backed arena; ConnId is the index. Free list = intrusive u32 stack.
```

- Use an **open-addressing (Swiss/Robin-Hood) table**, not `std::HashMap` and not a chaining map:
  no per-entry heap node, one cache line per probe, predictable memory. `hashbrown`'s raw table
  (`RawTable<(FlowKey, ConnId)>`) is the pragmatic Rust choice; it's the same SwissTable `HashMap`
  is built on, but lets you control hashing and store the compact tuple inline.
- **Load factor ≤ 0.6.** At 1M/8 cores = 125K conns/core, size each table for ~256K slots.
  Slot = `(FlowKey 12B + ConnId 4B) = 16B` → 256K × 16B = **4 MB/core**, 32 MB/box for the index.
- `ConnId(u32)` (not a pointer) survives arena growth and is cheap to stash in timer wheels and
  cross-core telemetry rings. Dereferences are `&mut slab[id.0 as usize]` — bounds-elided in the
  hot loop after one check.
- **The dport is constant (80)** and the daddr is the VIP — you can drop them from the key and
  hash only `(saddr, sport)`, shrinking the key to 6 B (v4). Micro-optimization; do it after
  correctness.

### 2.2 The TCB — engineered for <8 KB/conn (it's actually ~320 B)

The whole 8 KB budget is not spent on TCP state — a tight TCB is a few hundred bytes. The budget
exists so that **transient mbufs on active conns** fit. Layout (v4, `#[repr(C)]`, one goal:
keep the hot fields in the first 1–2 cache lines):

```
struct Tcb {                                   // ~ bytes
  /* --- hot: touched every segment (cache line 0) --- */
  state:        u8,                            //   1   LISTEN dropped; we start at SYN_RCVD
  flags:        u8,                            //   1   (ts_ok, sack_ok, is_evade, ...)
  snd_una:      u32, snd_nxt: u32, snd_wnd: u32,  // 12
  rcv_nxt:      u32, rcv_wnd: u32,             //   8
  ts_recent:    u32, ts_ecr: u32,             //   8
  srtt:         u32, rttvar: u32, rto:  u32,  //  12   (fixed-point ms)
  cwnd:         u32, ssthresh: u32,           //   8
  /* --- reassembly: pointers, not payload (cache line 0/1) --- */
  reasm_head:   Option<NonNull<rte_mbuf>>,    //   8   in-order-pending chain head
  ooo_root:     u32,                          //   4   index into a per-core OOO interval pool (-1 = none)
  reasm_bytes:  u32,                          //   4   cap this (e.g. 256 KB) → RST on abuse
  /* --- timers: intrusive wheel links, no per-conn timer object --- */
  rto_deadline: u32, ka_deadline: u32,        //   8   TSC-tick expiries
  wheel_next:   u32, wheel_prev:  u32,        //   8   intrusive doubly-linked list in a bucket
  /* --- identity / bookkeeping (cold-ish) --- */
  key:          FlowKey,                       //  12   for hash verification on probe hit
  egress_fd:    i32,                           //   4   kernel egress socket (or ConnId in ph2)
  /* --- session pointers (cold until handshake done) --- */
  noise:        Box<NoiseXport>,               //   8   see §2.3 (heap; or inline arena slot)
  /* padding to 64B multiple */
}                                              // ≈ 128–160 B core; round to 192 B slotted
```

- **1M TCBs × ~192 B = ~192 MB** for the whole box's connection state. Trivial.
- Do **not** put SACK scoreboards, reassembly buffers, or per-conn scratch in the TCB. SACK
  blocks: keep a **bounded 4-entry** array inline (`[SackBlock; 4]`, 32 B) — RFC 2018 only needs
  a handful; 4 covers the common loss patterns and caps memory. Anything beyond that, drop and
  rely on retransmit. No dynamic scoreboard per conn.
- **Congestion control: NewReno with SACK-based loss detection.** CUBIC is +40 B of state and
  more code; start Reno-with-SACK (it's the "you need real CC because clients cross the public
  Internet via CloudFront" requirement from the ixgbe doc), swap to CUBIC only if throughput
  under loss demands it. BBR is a research rabbit hole — skip.
- `noise: Box<NoiseXport>` is a heap pointer today; in the tuned build, carve the Noise transport
  state from a **second per-core slab** so it's `ConnId`-indexed too (no `Box`, no malloc in the
  accept path — the fragmentation lesson from the abandoned slab experiment and the
  "85GB RSS is normal" incident).

### 2.3 Noise transport state — the second-biggest per-conn term

`snow`'s `TransportState` is convenient but carries the full handshake apparatus and cipher
objects (~600 B–1 KB). For 1M conns that's ~1 GB you don't need after the handshake completes.

- **Handshake:** use `snow` (or the existing `src/noise.rs`) for the `Noise_NK` handshake — it's
  cold, runs once per conn, correctness matters more than size. `x25519-dalek` + `chacha20poly1305`
  + `blake2` underneath.
- **Transport (steady state):** after handshake, extract the two ChaCha20-Poly1305 keys + nonces
  into a **compact hand-rolled `NoiseXport`**:
  ```
  struct NoiseXport { k_send: [u8;32], k_recv: [u8;32], n_send: u64, n_recv: u64 } // 80 B
  ```
  Encrypt/decrypt with `chacha20poly1305` directly (in-place; the crate supports detached AAD).
  **80 B vs ~800 B** is a ~720 MB saving at 1M conns. This is the single highest-leverage memory
  optimization after "don't copy payload."
- Per-core scratch for plaintext output (one `[u8; 65 KB+16]` per core, **not** per conn).

### 2.4 Timer wheels for RTO / keepalive at 1M conns

**Never a timer object per connection, never a `BinaryHeap` of (deadline, conn).** Both are the
classic O(n log n) scalability killers (the repo already hit this class of bug with per-read
timeouts in the tokio version).

Design: **one hierarchical timing wheel per core**, intrusive.

- **Granularity 10 ms tick** (matches RTO resolution needs; keepalive is coarse).
- **Two or three levels** (Linux-style cascading wheel): level 0 = 256 buckets × 10 ms (~2.5 s
  span) for RTO/delayed-ACK; level 1 = 64 buckets × 2.5 s (~2.5 min) for keepalive/idle; level 2
  optional for TIME_WAIT (see below).
- **Buckets are intrusive doubly-linked lists of `ConnId`.** The link pointers live *in the TCB*
  (`wheel_next`/`wheel_prev`, §2.2) — **zero per-timer allocation**. Arming a timer = unlink +
  relink into the target bucket, O(1). Cancelling = unlink, O(1).
- **A connection is in at most one timer wheel slot at a time** for its dominant timer. RTO and
  keepalive are mutually exclusive phases in practice (you're either waiting on an ACK or idle),
  so one intrusive link pair per TCB suffices. Delayed-ACK is a separate, very short single-shot;
  handle it with a per-core "pending delayed-ACK" ring drained each tick rather than the wheel.
- **Tick cost is O(conns firing this tick), not O(total conns).** At 1M mostly-idle tunnel conns,
  a tick touches a handful of buckets. This is the property that makes 1M conns tractable.
- **TIME_WAIT** at 600K+ churning conns can be 100K+ entries. Do **not** hold a full TCB in
  TIME_WAIT. Move the conn to a **compact TIME_WAIT record** (`{key, snd_nxt, rcv_nxt, expiry}`,
  ~24 B) in a bounded per-core LRU ring, free the TCB slab slot immediately. Cap the ring; on
  overflow, recycle oldest (RFC-permissible under memory pressure). This is a mempool-budgeted
  structure, never heap.

Drive the wheel from the run-to-completion loop: after each RX burst, read the TSC, advance the
wheel to `now`, process expired buckets. No `rte_timer` callbacks needed (they add indirection);
a hand-rolled TSC wheel is simpler and faster and you control it entirely.

### 2.5 Per-core run-to-completion loop (the shape)

```
loop {
  let n = rte_eth_rx_burst(port, qid, &mut burst, 32);
  rte_prefetch0(next_mbuf_headers);                    // prefetch stage-ahead
  for m in &burst[..n] {
    let (eth, ip, tcp, payload_mbuf) = parse_in_place(m);   // pointer arithmetic, no copy
    let cid = flow_map.get_or_syn(key_of(ip, tcp));         // SYN → new Tcb from slab
    let tcb = &mut slab[cid];
    match tcb.on_segment(ip, tcp, payload_mbuf) {           // TCP state machine, mbuf-native
      Deliver(sg) => pump_to_egress(tcb, sg),               // Noise decrypt → kernel egress
      Nothing => {}
    }
  }
  advance_timer_wheel(rdtsc());                              // O(firing)
  drain_egress_to_client();                                 // t2c: read kernel egress → encrypt → TX
  tx_flush(port, qid);                                      // batched rte_eth_tx_burst
}
```

No `Arc`, no `Mutex`, no cross-core anything on this path. Global counters become per-core
`#[repr(align(64))]` cells folded by a separate metrics thread (false-sharing rule).

---

## 3. Zero-copy receive — mbuf-native reassembly

The rule from `dpdk-transport-analysis.md` §2 stands and is the load-bearing wall of the memory
budget. Restating with mlx5 specifics:

- **In-order data:** the mbuf(s) delivered by `rte_eth_rx_burst` *are* the receive buffer. Advance
  `rcv_nxt`, chain the mbuf onto `reasm_head`, and expose a scatter-gather cursor to the Noise
  layer. **No copy.**
- **Out-of-order segments:** hold them as `NonNull<rte_mbuf>` in a per-core **interval structure**
  keyed by sequence number. Do **not** copy into a linear per-conn buffer. Options: a small
  per-conn intrusive sorted list (OOO runs are usually short — 1–4 gaps), or a shared per-core
  interval pool indexed by `ooo_root` in the TCB. Cap total OOO bytes per conn (`reasm_bytes`,
  e.g. 256 KB) → RST on abuse (censorship-adjacent hostile middleboxes will try to exhaust you).
- **Gather only when a Noise frame straddles mbufs.** Noise frames are length-prefixed and
  ≤ 65535+16 B. `chacha20poly1305` needs contiguous ciphertext:
  - **Fast path (~85–90 %):** whole frame in one mbuf's data → decrypt in place inside the mbuf.
  - **Slow path (~10–15 %):** frame spans 2+ mbufs → gather-copy *just that frame* into the
    per-core `frame_scratch` (bounded, mempool-backed), decrypt there. Bounded, per-core, cheap.
- **mlx5 MPRQ interaction:** with `mprq_en=1`, multiple small packets share one large RX buffer
  (strided). The PMD hands you mbufs that reference regions of the shared buffer; refcounting
  (`rte_mbuf` `refcnt`) keeps the backing buffer alive while your reassembly list holds a stride.
  **This is a memory win** at 1M small-frame conns (fewer, larger backing allocations) but means
  your "hold the mbuf" reassembly must respect refcounts — free the mbuf (drop the stride ref)
  the moment the byte range is consumed by Noise, or MPRQ buffers won't recycle and the mempool
  starves. Test this explicitly; it's the one mlx5-specific footgun in the zero-copy path.
- **TX:** encrypt into an mbuf region; use **TSO** (`RTE_ETH_TX_OFFLOAD_TCP_TSO`, which mlx5
  supports) to hand the NIC one chained mbuf with `tso_segsz` set → ~4× fewer TX descriptors. Set
  `txq_inline_*` devargs so tiny frames (bare ACKs, small Noise frames) inline into the WQE and
  skip a DMA gather. This is the "3 cores vs 8 cores at 10G" lever from the ixgbe doc; it applies
  identically on mlx5.

---

## 4. Steal vs build — the survey with a verdict

| Candidate | Language | Buffer model | Scale evidence | Verdict for redtcp |
|---|---|---|---|---|
| **smoltcp** | Rust | Copies into per-socket ring `Vec<u8>`; `SocketSet` poll is O(active) | ~2–4 Gbps/core on DPDK; SocketSet not built for 600K | **Reject (data plane).** Copy model + O(n) poll defeat both memory and scale goals. Keep for control-plane / a differential test oracle. |
| **mTCP** (KAIST) | C | `mtcp_read` copies into your buffer; zero-copy RX experimental only | 10G, millions of conns *in the paper* | **Reject.** Dead C (~2019), no real Rust bindings, "not robust/buggy" per F-Stack. Read the NSDI'14 paper for the per-core+batching design, use nothing. |
| **TLDK** (DPDK's `libtle_l4p`) | C | App-driven; per-stream `tle_tcp_stream`; closer to zero-copy than most | Part of DPDK ecosystem; lightly maintained | **Adapt *ideas*, not code.** TLDK is the closest philosophical match (a *library* you drive, no threads, per-lcore contexts, BSD-socket optional). Study `tle_tcp_stream`'s compact TCB layout and its event model. FFI to C reintroduces the buffer-copy boundary and a second memory manager. Fallback base only if custom TCP slips badly. |
| **F-Stack** (Tencent) | C | Full FreeBSD socket buffers (mbuf→sockbuf copy) | **Proven: 10G+, millions of conns in prod at Tencent** | **Reject as base; keep as the escape hatch.** It's "mTCP-but-alive" and battle-tested, but multi-process DPDK model, C, and FreeBSD sockbuf copies blow the <8 KB budget. If redtcp correctness under WAN loss proves too costly to reach, F-Stack is the proven fallback — accept the memory hit. |
| **Seastar native stack** (ScyllaDB) | C++ | Own zero-copy `packet`/`fragment` model, share-nothing shards | Proven at ScyllaDB scale; native stack less WAN-hardened | **Steal the architecture, not the code.** Share-nothing thread-per-core + message-passing-between-shards is *the* gold-standard pattern and it's already your design. C++ rules out reuse. |
| **Demikernel / Catnip** (Microsoft) | Rust | Zero-copy LibOS, explicit coroutine sched | Research-grade, small scale (SOSP'21) | **Read it, don't ship it.** Best reference for *Rust*-on-DPDK zero-copy datapath structure. Not production-hardened, not sized for 1M conns. |
| **VPP host stack** | C | Own buffer manager; session layer | Your prior path; crashes 7+ workers | **Exit, don't return.** The reason this project exists. |

**Verdict, stated plainly:** **BUILD redtcp.** Every mature option copies RX payload into a
socket buffer it owns, which is fundamentally incompatible with the mbuf-native, <8 KB/conn thesis
— adapting any of them means forking its buffer manager, i.e. rewriting the hard 30 %. The passive,
single-port, single-role TCP you need is a *much smaller* state machine than any general stack
(~4–6 K lines Rust, same order as the existing Noise+HTTP+SOCKS code). What you steal:

- **`dpdk-sys`**: own bindgen against DPDK 23.11, mlx5 PMD built in (see `references/dpdk-ffi-bindgen-pitfalls.md`).
- **Crypto**: `snow` for the cold handshake; hand-rolled `NoiseXport` + `chacha20poly1305` for the
  hot transport path (§2.3).
- **Data structures**: `hashbrown` raw table for the flow map; custom intrusive timer wheel and
  slab arena (no crate is a good enough fit and the code is small).
- **Layout ideas**: TLDK's `tle_tcp_stream` compactness, Seastar's shard model, Demikernel's Rust
  datapath structuring.
- **Correctness harness**: a **pcap-replay differential oracle** — drive kernel TCP *and* redtcp
  with the same captured 4-tuple traffic, assert byte-identical egress. smoltcp can serve as a
  second oracle for edge cases. This is the mitigation for the one real risk (TCP correctness
  under loss/reorder/hostile middleboxes).

---

## 5. Core / NUMA / isolation layout (mlx5-specific notes)

- **NIC-local NUMA only.** `cat /sys/bus/pci/devices/0000:af:00.0/numa_node` → put all worker
  lcores, all mempools (`socket_id`), the conn slab, the Noise slab, and the timer wheels on that
  node. mlx5 verbs objects (CQs, WQs) are allocated by the PMD from the EAL heap on the socket you
  give it — `--socket-mem=X,0` (or `0,X`) forces the right node.
- **Isolate worker cores:** `isolcpus=`, `nohz_full=`, `rcu_nocbs=` on the worker range; pin the
  metrics/telemetry thread and the egress-relay threads to *other* cores. mlx5's bifurcated model
  means the **kernel is still handling PF interrupts** — keep those IRQs off the isolated worker
  cores (`irqaffinity=`, and check `/proc/interrupts` for `mlx5_comp*` on the VF).
- **Poll vs idle:** pure poll burns cores. At 1M *mostly-idle* tunnel conns this matters for power.
  mlx5 supports Rx interrupts via the verbs event channel — you can drop to interrupt/epoll mode
  during idle troughs (`rte_eth_dev_rx_intr_enable`) and re-arm polling under load. Simpler first
  cut: `rte_pause()` backoff on empty bursts, never sleep (sleeping kills the reconnect ramp at
  100K conn/s churn — the ixgbe doc's warning holds).
- **CQE compression** (`rxq_cqe_comp_en=1`) is the mlx5 knob that most reduces PCIe + completion
  memory at high queue depth — leave it on.

---

## 6. Egress — the honest bottleneck for the 10× goal

The task's memory thesis is 65 KB/conn → target ~6.5 KB (10×). redtcp gets the **ingress** side to
~600–900 B userspace. But the **egress** leg is still a **kernel TCP socket** (SOCKS5 CONNECT to
the target), and that carries the second half of the current 65 KB:

- Kernel `tcp_sock` + `sk_buff` overhead + autotuned `SO_SNDBUF`/`SO_RCVBUF` ≈ **8–16 KB/conn
  kernel RAM** at default tuning. Autotuning grows these under load — this is likely a big chunk
  of today's 65 KB.
- **Phase-1 mitigation (cheap):** clamp egress buffers hard. `sysctl net.ipv4.tcp_rmem`/`tcp_wmem`
  low mins, or per-socket `setsockopt(SO_RCVBUF/SO_SNDBUF)` to ~4 KB each with explicit userspace
  flow control (you already relay through per-core scratch; backpressure via the SPSC ring depth).
  Realistic floor ~8–10 KB/conn kernel. Gets you to roughly **~5–6×** density, not 10×.
- **Phase-2 (the real 10×):** move egress onto the **same redtcp stack** on a second VF (active
  open this time). Then egress is also mbuf-native (~600 B userspace, zero kernel socket). This is
  where symmetric RSS (§1.6) becomes relevant — you'd want the egress return traffic to co-hash to
  the core that owns the conn. Deferred until the ingress stack is proven; it doubles the TCP
  correctness surface (active open, connect timeouts, more CC edge cases).

**Recommendation:** ship phase-1 (ingress DPDK, egress kernel with clamped buffers), measure real
per-conn RSS, then decide if phase-2 egress-on-DPDK is worth the correctness surface. Be explicit
with stakeholders that **10× requires phase-2**; phase-1 alone is ~5–6×, still a large win over the
current RAM-bound ceiling.

---

## 7. Memory budget table

### 7.1 Per-connection, steady-state (idle conn, no in-flight data)

| Term | Bytes/conn | Notes |
|---|---:|---|
| TCB core (slab) | 192 | §2.2, rounded to 64 B multiple |
| Flow-map slot (amortized @ 0.6 load) | ~27 | 16 B slot / 0.6 |
| Noise transport (`NoiseXport`, slab) | 80 | §2.3; vs ~800 B if you keep `snow` — **don't** |
| Timer-wheel links | 0 | intrusive in TCB |
| OOO interval root | 0 (idle) | only active conns allocate OOO nodes |
| Reassembly mbufs | 0 (idle) | **the whole point** — idle conns hold no payload |
| Egress binding (userspace side) | 8 | `egress_fd` / ConnId; kernel socket counted below |
| Telemetry | ~0 | off-path per-core rings, drop-on-full |
| **redtcp userspace subtotal** | **~310** | comfortably < 8 KB |
| Kernel egress socket (phase-1, clamped) | ~8,000–10,000 | **dominant term**, see §6 |
| **Total per-conn (phase-1)** | **~8.3–10.3 KB** | ≈ **6–8× improvement** over 65 KB |
| **Total per-conn (phase-2, egress on DPDK)** | **~700** | ≈ **90× improvement**; the real 10×+ |

### 7.2 Whole-box aggregate at 1M conns (8 workers, NIC-local NUMA)

| Pool | Size | Notes |
|---|---:|---|
| TCB slab (1M × 192 B) | ~192 MB | fixed, arena, never freed to OS |
| Noise slab (1M × 80 B) | ~80 MB | fixed arena |
| Flow-map index (8 × 256K × 16 B) | ~32 MB | per-core Swiss tables |
| Timer wheels (8 × buckets) | ~few MB | intrusive; scales with *active* timers |
| TIME_WAIT rings (bounded) | ~24 B × cap | e.g. 8 × 64K × 24 B ≈ 12 MB |
| **RX mbuf pool** (MPRQ backing) | ~1–2 GB | sized to *active* conns × in-flight, not total; MPRQ shares buffers |
| TX mbuf pool | ~0.5–1 GB | TSO chains |
| Per-core frame_scratch (8 × ~80 KB) | ~0.6 MB | gather + plaintext scratch |
| Hugepages reserved (`--socket-mem`) | 8 GB/node | headroom over the above; mlx5 verbs objects live here |
| **redtcp userspace total** | **~2–4 GB** | for **all 1M conns** — vs ~110 GB kernel-bound today |
| Kernel egress sockets (phase-1) | ~8–10 GB | the remaining large term (§6) |

The mbuf pool is sized by **concurrent in-flight bytes** (active fraction × BDP), *not* by total
conn count — this is why 1M idle-heavy tunnel conns fit in single-digit GB. Size the RX pool for
your measured active fraction with headroom; MPRQ + CQE-compression keep it lean.

---

## 8. Prioritized build order

1. **`dpdk-sys` + mlx5 bring-up.** bindgen against DPDK 23.11 with net/mlx5 built; EAL init on the
   VF (§1.5); confirm `rte_eth_rx_burst` sees carrier frames (VIP-on-VF + ARP responder). This is
   the highest-risk *setup* step because mlx5's verbs/rdma-core deps are unlike anything the
   ixgbe-era docs assumed. **Gate: a tcpdump-equivalent (`rte_pdump`) showing SYNs arriving on the
   VF queues while the PF still carries host traffic.**
2. **RSS → per-core queue pinning** (§1.6); verify a fixed 4-tuple always lands on the same lcore.
3. **Flow map + TCB slab + SYN/SYN-ACK/handshake** — passive open only, no data yet.
4. **mbuf-native reassembly + SG cursor + Noise transport** (§2.3, §3); fast-path in-mbuf decrypt,
   slow-path gather. Watch the **MPRQ refcount footgun** (§3).
5. **Timer wheel** (RTO/keepalive/TIME_WAIT) (§2.4); NewReno + SACK.
6. **Egress relay to kernel socket** with clamped buffers (§6, phase-1).
7. **pcap-replay differential harness** vs kernel TCP — the correctness gate before any live cutover.
8. **Feature-flag cutover** (`--transport=dpdk` vs `--transport=kernel`) behind a `trait CarrierIo`
   so rollback is a config flip (honors the repo's "rollback first" rule).
9. *(Phase-2, later)* egress-on-DPDK + symmetric RSS for the true 10×+.

---

## 9. mlx5-specific pitfalls (the ones that will actually bite)

- **rdma-core version skew.** The PMD, `libmlx5`, and the kernel `mlx5_ib` must be compatible.
  Mixing distro rdma-core with a MLNX_OFED kernel module (or vice-versa) produces cryptic
  `mlx5_glue` init failures. Verify `ibv_devinfo` works *before* DPDK. Pin the combo.
- **`/dev/infiniband/uverbsN` permissions.** DPDK opens these; running non-root needs device ACLs
  or the `rdma` cgroup. Silent EAL failures here look like "no mlx5 device found."
- **VF trust / spoofchk.** DPDK sources the VIP MAC from the VF; if `spoofchk on` (default), the
  eSwitch drops it. `spoofchk off` + `trust on` on the VF (§1.2).
- **MPRQ stride refcounting** (§3) — the #1 zero-copy footgun; leaks starve the mempool.
- **RSS default is asymmetric on mlx5.** `rss_conf` gives Toeplitz-asymmetric. Symmetric requires
  the explicit `rte_flow` RSS-action hash function *and* a symmetric key — don't assume a symmetric
  key alone does it (§1.6).
- **switchdev vs legacy eSwitch mode is a reboot-class change on some firmware.** Decide early
  (§1.3); legacy + VIP-on-VF avoids it entirely.
- **Don't allowlist the PF.** `-a` the VF BDF only; the PF stays kernel-owned and live.
- **CQE compression + timestamp offload interaction:** if you later need RX HW timestamps (you
  probably don't — TSC is fine for RTO), CQE compression can strip them. Leave compression on,
  use TSC for timers.

---

## 10. One-paragraph executive summary

Create an SR-IOV VF on the ConnectX-5, leave it on `mlx5_core`, and attach DPDK's bifurcated
`mlx5` PMD to the VF's PCI BDF via rdma-core/ibverbs — **no `vfio-pci`, no unbind, the PF stays
kernel-live**. Steer carrier traffic to the VF by dedicating the VIP's MAC to it (DPDK answers
ARP); inside the VF, plain Toeplitz RSS pins each 4-tuple to one core for lock-free
run-to-completion. **Build a custom minimal TCP ("redtcp"), not smoltcp/mTCP/TLDK/F-Stack/Seastar
— all of them copy RX payload into socket buffers they own, which defeats the <8 KB/conn thesis.**
Hold RX payload as `rte_mbuf` pointers in a per-core reassembly list (gather-copy only when a Noise
frame straddles mbufs); keep a ~192 B TCB in a slab arena, an 80 B hand-rolled Noise transport
state, an intrusive per-core hierarchical timer wheel (no per-conn timer objects), and a bounded
TIME_WAIT ring. That puts redtcp's userspace footprint at **~2–4 GB for all 1M connections**; the
remaining large term is the **kernel egress socket** (~8–10 KB/conn), which caps phase-1 at ~5–6×
density — the true 10×+ requires moving egress onto the same stack (phase-2), where symmetric RSS
finally earns its place.
