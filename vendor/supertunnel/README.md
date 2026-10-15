# supertunnel

A modular, asynchronous networking framework designed for building stateful TCP
tunnels that make network disruptions transparent to application streams.

Super Tunnel enables you to route application connections through a proxy server
while adding resiliency features that enable your tunnels to survive network
disconnections. Specifically, you can build resilient tunnels by stacking Super
Tunnel's framing, reliability, session resumption, and stream multiplexing
layers with your own security protocol implementation.


```text
========================== CLIENT SIDE ==========================
+-------------+     +--------------+     +-------------------+
| Client Apps | <-> | Super Tunnel | <-> | Security Protocol |
+-------------+     +--------------+     +-------------------+
                                                   |
                                           ==================
                                             Internet (TCP)
                                           ==================
                                                   |
+-------------+     +--------------+     +-------------------+
| App Targets | <-> | Super Tunnel | <-> | Security Protocol |
+-------------+     +--------------+     +-------------------+
========================== SERVER SIDE ==========================
```

> [!CAUTION]
> Super Tunnel is experimental and not recommended for security-critical applications.

SuperTunnel is designed to be composed with a security protocol that provides
security features such as encryption and resistance to network traffic analysis.
SuperTunnel itself does NOT provide security; it provides stateful session
resumption and stream multiplexing features while allowing you to focus on
developing strong security protocols.

## Using SuperTunnel

Easily add SuperTunnel to your project

    cargo add supertunnel

To get started using SuperTunnel

  1. See the [rustdoc documentation](https://docs.rs/supertunnel/latest) ([unformatted here](src/lib.rs))
  2. See the source code of our reference implementations, summarized below.

### For Protocol Integrators

If your goal is to integrate SuperTunnel into your existing applications
without writing custom protocol logic, you can leverage the pre-built layers
provided in the [`proto` module](src/proto).

The best way to understand how to wire these layers together is to review the
internal source code of the [reference implementation examples](examples/):
  * See [examples/client.rs](examples/client.rs) for establishing a multiplexed
    outbound tunnel.
  * See [examples/server.rs](examples/server.rs) for accepting, demultiplexing,
    and routing inbound tunnel connections.

### For Protocol Implementors

SuperTunnel is designed to be extensible. You can write your own protocol
layers by implementing our `Protocol` trait and injecting them anywhere in
a SuperTunnel stack.

To see how the SuperTunnel constructs can be applied in concrete
implementations, you can study the internal source code of the [reference
implementation protocols](src/proto) provided in this library.

## Demo

The `examples` demonstrate how to use SuperTunnel to establish a tunnel between
a client and a server. The client runs a SOCKSv5 server and listens for incoming
connections (e.g., from a web browser), and then proxies connection attempts and
payloads through the tunnel to the server.

> [!CAUTION]
> This example is for demonstration purposes only. It does not implement encryption
> or obfuscation of any kind.

> [!WARNING]
> User data being transferred through this example tunnel will be readable by a
> network observer, unless it is encrypted before being sent into the tunnel
> (e.g., by a web browser/server using TLS).

> [!WARNING]
> Super Tunnel control metadata is sent in plain text and will be readable by a
> network observer unless the tunneled traffic is composed with an external
> encrypting or obfuscating proxy.

Run the server:

    RUST_LOG=info cargo run --example server -- --listen 127.0.0.1:8080

Run the client to create a tunnel to the server:

    RUST_LOG=info cargo run --example client -- --connect 127.0.0.1:8080 --listen 127.0.0.1:1080

Then point a browser at the socks server listening on `127.0.0.1:1080`.

To demo session resumption, insert a doomed proxy between the client and server
(and make sure the client connects to the doomed port `8888`):

    RUST_LOG=info cargo run --example doomed -- --connect 127.0.0.1:8080 --listen 127.0.0.1:8888 --timeout 30

## Development notes

Debug build (also used for tests):

    cargo build

Release build (optimized):

    cargo build --release

Run tests:

    cargo test

Maintain standard code formatting:

    cargo +nightly fmt -- --config-path rustfmt-nightly.toml

Maintain clippy standards:

    cargo clippy --all-targets -- -Dwarnings
