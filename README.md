# tailcat.rs

A Rust re-implementation of [tailcat](https://github.com/tailscale/tailcat),
"Tailscale without Tailscale, by Tailscale": netcat over Tailscale's data
plane (WireGuard® encryption, DERP relays, NAT traversal) with no control
plane, no account, and no root.

It speaks the same wire protocols as the Go implementation. A Rust client
can connect to a Go server and the other way around, tailcat addresses
and key files are interchangeable, and CI tests all of that against
upstream's Go build.

It also adds **`tailcat-device`**, a WireGuard mesh overlay on a real TUN
interface, built for running distributed systems (like a k3s cluster)
across a matrix of GitHub Actions runners.

| Crate | What it is |
|---|---|
| [`crates/tailcat`](crates/tailcat) | The library: keys and addresses, DERP client and server, disco NAT traversal, a WireGuard engine, a userspace TCP/IP stack, `Server`/`Client`, and SSH/SFTP/exec services. |
| [`crates/tailcat-cli`](crates/tailcat-cli) | The `tailcat` command, with upstream's subcommands and flags: pipe, `serve`, `forward`, `browse`, `ssh`, `cp`, `ls`, `recv`, `perf`, `ping`, `socks`, `parse`, `resolve`, `genkey`, and more. |
| [`crates/tailcat-device`](crates/tailcat-device) | The `tailcat-device` command and library: a symmetric WireGuard mesh on a TUN device, with peers from node records in files or GitHub Actions run artifacts. |

## Contents

- [Install](#install)
- [Usage](#usage)
- [Key management](#key-management)
- [The Rust library](#the-rust-library)
- [tailcat-device: a mesh overlay](#tailcat-device-a-mesh-overlay)
- [How it works](#how-it-works)
- [Compatibility with Go tailcat](#compatibility-with-go-tailcat)
- [Troubleshooting](#troubleshooting)
- [Development and testing](#development-and-testing)
- [Security](#security)

## Install

With Nix (the flake's only input is nixpkgs):

```sh
nix run github:tailscale-insiders/tailcat.rs -- --help
nix build github:tailscale-insiders/tailcat.rs   # result/bin/{tailcat,tailcat-device}
```

With Cargo (Rust 1.88 or later):

```sh
cargo install --git https://github.com/tailscale-insiders/tailcat.rs tailcat-cli tailcat-device
```

Linux and macOS are built and tested in CI. The library has no
platform-specific networking beyond UDP sockets; the SSH server's PTY
support and `tailcat-device`'s TUN handling are Unix-specific.

## Usage

### Pipe stdin/stdout between two machines

The server prints its ephemeral address:

```sh
$ tailcat
# Selected bootstrap relay region 303, Frankfurt
# 🐈 Server listening with new address: tcpGFwWCDmwXLBy...
```

The client pipes into it; the server prints what arrives and exits:

```sh
$ echo hello | tailcat tcpGFwWCDmwXLBy...
```

### Expose local ports

```sh
$ tailcat serve 8080,8443              # or: tailcat serve all
$ tailcat tcXXXX 8080 < request.http   # on the client
```

A port mapping proxies somewhere other than the same port on localhost:
another local port (`8080:80`) or a host on the server's network
(`5555:10.2.200.213:5555`, `5555:[fd7a::1]:5555` for IPv6), without
exposing the whole network the way `exit-node` does.

### Forward local ports to a server

```sh
$ tailcat forward tcXXXX 18080:8080 3306
$ tailcat forward --bind=0.0.0.0 tcXXXX 18080:8080
$ tailcat forward tcXXXX 13306:192.168.1.10:3306   # through an exit-node server
$ tailcat browse tcXXXX                           # forward 0:80 and open a browser
```

A local port of 0 asks the OS for a free port; each listener prints its
address.

### SSH

A server that accepts keys from authorized_keys files, literal key lines,
or GitHub accounts (fetched once at startup):

```sh
$ tailcat serve --ssh-authorized-keys=~/.ssh/authorized_keys,alice@github ssh
$ tailcat ssh tcXXXX
$ tailcat ssh root@tcXXXX uptime
```

Or with no SSH-level authentication at all, where the tunnel identity is
the only gate (the address is then a credential; see [Security](#security)):

```sh
$ tailcat serve no-auth-ssh
```

`tailcat ssh` runs the system `ssh` with a ProxyCommand that runs tailcat
itself. Served processes get the peer's node key in `$TAILCAT_PEER_KEY`
and its tailcat IP:port in `$TAILCAT_REMOTE_ADDR`.

### Run a command per connection

Like inetd, with the connection as the command's stdin and stdout:

```sh
$ tailcat serve exec -- /usr/bin/fortune
```

With `ssh` or `no-auth-ssh`, the command after `--` instead replaces the
shell for every session, like OpenSSH's `ForceCommand` (the client's
command arrives in `$SSH_ORIGINAL_COMMAND`):

```sh
$ tailcat serve --ssh-authorized-keys=alice@github ssh -- ./deploy.sh
```

### Send and receive files

```sh
$ tailcat recv ~/inbox                 # a write-only drop box
$ tailcat cp report.pdf tcXXXX:        # on the sender

$ tailcat serve files                  # the current directory, read-only
$ tailcat serve --files=/pub:rw files  # read-write
$ tailcat ls -l tcXXXX
$ tailcat cp -r tcXXXX:photos ./photos
```

File services speak SFTP (so stock `sftp` and `scp` work too) and confine
every path to the served directory with openat-style lookups: neither
`..` nor symlinks escape it. Drop boxes (`:wo`, and `:wo+` with
`--accept-dirs`) store uploads under fresh names and let senders list or
read nothing.

### Measure throughput

```sh
$ tailcat serve perf
$ tailcat perf tcXXXX
# path: direct via 203.0.113.7:41641, rtt 1.2ms
TCP, client -> server, 1 stream, 10s
[   1.0s]  sent   38.5 MB    308 Mbit/s  rtt 9.92ms
...
sent         122 MB in    3.0s    325 Mbit/s
received     122 MB in    3.0s    325 Mbit/s
rtt under load  min 5.92ms  avg 12.58ms  max 19.75ms  (15 samples)
```

`--reverse`, `--bidir`, `--udp` (with loss, reordering and jitter),
`--parallel`, `--bytes`, and `--json` are supported. Tests refuse to run
through a DERP relay unless `--via-derp` is given, and never through
Tailscale's shared relays.

### Other commands

```sh
$ tailcat ping --until-direct tcXXXX   # pong in 1.2ms via 203.0.113.7:41641
$ tailcat socks tcXXXX curl http://server.tailcat:8081/
$ tailcat socks curl http://tcXXXX:8081/   # addresses work as hostnames
$ tailcat serve exit-node                  # clients reach the server's network (TCP and UDP)
$ tailcat parse tcXXXX                     # decode an address to JSON
$ tailcat resolve tcXXXX                   # embed the DERP region for offline use
$ tailcat printpub                         # the client key that would be used
$ tailcat readme                           # this document
```

A DNS name whose `tailcat=` TXT record holds an address works anywhere an
address does. `TAILCAT_ADDR_FILE` makes a server write its address to a
file (or, with a `tcp:` prefix, send it to a TCP address),
`TAILCAT_STATUS_FILE` makes it keep its status, with each client's path
(direct or DERP), as JSON in a file, and `TAILCAT_DERPMAP_URL` sets the
default `--derpmap-url`. With `-v`, clients and servers log each change
of path at info level. A server forgets a client that has nothing open
and has been silent for 10 minutes (`TAILCAT_IDLE_CLIENT_TIMEOUT`, `0`
for never), and lets it back in as soon as it sends again.

## Key management

A server address contains the server's WireGuard public key, a separate
path-discovery key, a WireGuard pre-shared key, and its DERP region.

- **Ephemeral keys** (the default): every server run makes a fresh key and
  an address nobody has seen, which dies with the process.
- **Saved keys**: `tailcat genkey` saves a key so the address survives
  restarts. The name `default` is magic: server mode uses it once it
  exists (`--key=new` forces an ephemeral key).

```sh
$ tailcat genkey --key=default --fixed-region
$ tailcat genkey --client --key=client-default   # prints the key for --allow
$ tailcat serve --allow=nodekey:cfb6bf...ddfd16 22
$ tailcat genkey --list
$ tailcat genkey --delete --key=default
```

Keys live in `$CONFIG/tailcat/keys/<name>.private.json` (for example
`~/.config/tailcat/keys` on Linux), the same files and format as the Go
tailcat, so both implementations share them. The SSH host key is shared
the same way.

`genkey --region` pins a region by ID, code or name (`--region=list`
lists them), or names your own DERP servers by hostname
(`--region=derp.example.com`), whose details then ride in the address.

## The Rust library

```toml
[dependencies]
tailcat = { git = "https://github.com/tailscale-insiders/tailcat.rs" }
```

A server that answers every TCP port:

```rust
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> tailcat::Result<()> {
    let server = tailcat::Server::builder()
        .on_tcp(|port| {
            Some(tailcat::handler(move |mut c: tailcat::TcpStream| async move {
                let _ = c.write_all(format!("hello from port {port}\n").as_bytes()).await;
            }))
        })
        .start()
        .await?;
    println!("{}", server.tailcat_addr());
    std::future::pending::<()>().await;
    Ok(())
}
```

And a client, which brings the tunnel up on first use:

```rust
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::args().nth(1).expect("tailcat address");
    let client = tailcat::Client::new(addr);
    let mut c = client.dial_tcp_port(80).await?;
    let mut s = String::new();
    c.read_to_string(&mut s).await?;
    print!("{s}");
    Ok(())
}
```

Other pieces of the `Server` API: `allow_client` (with `KeySet`),
`on_udp`, `on_tcp_forward`/`on_udp_forward` (exit nodes), `listen_tcp` and
`listen_udp`, `served_tcp_ports`, `peer_key`, `disconnect_client`,
`status`, `drain_tcp`, `exec_conn_handler`, and (with the default `ssh`
feature) `ssh_conn_handler`. `Client` has `ping`, `disco_ping`,
`dial_tcp` (any address through an exit node; IPv4 rides the NAT64
prefix), `dial_udp_port`, `dial_udp`, and `drain_tcp`.

The lower layers are public too, for building other topologies (as
`tailcat-device` does): `derp` (client and a small server),
`magicsock` (path selection), `wg` (the WireGuard engine), `netstack`,
`disco`, `stun`, `netcheck`, `addr`, and `key`.

## tailcat-device: a mesh overlay

tailcat connects one client to one server through a userspace network
stack, forwarding individual ports. Distributed systems like Kubernetes
instead need routable node addresses. `tailcat-device` gives every node
in a group a TUN interface with an overlay IP and routes packets to all
the others: directly when NAT traversal succeeds, through DERP otherwise.

- **One engine per node**, with a real TUN device and one WireGuard peer
  per mesh member.
- **A symmetric mesh**: every peer is known in advance from its node
  record, so there is no join handshake.
- **One overlay IP per node**, by default `100.64.<attempt>.<index>`,
  routed as a /32, plus optional extra routes per node (for example a pod
  CIDR).
- **Records, not a coordinator**: each node makes its key locally and
  publishes only a public record; the private key never leaves the node.

```sh
# On each node:
tailcat-device init --index 3            # writes tailcat-device.key and node-1-3.json
# ...publish node-1-3.json where the others can read it, then:
sudo tailcat-device up --records ./records --nodes 5
```

A node record:

```json
{
  "index": 3,
  "nodekey": "nodekey:9c8d…",
  "discokey": "discokey:51e2…",
  "overlay_ip": "100.64.1.3",
  "derp_region": 303,
  "os": "Linux",
  "arch": "X64",
  "run_id": "18034567890",
  "run_attempt": "1",
  "jwt": "eyJ…"
}
```

`derp` may embed a whole region instead of `derp_region` (for your own
relays), `routes` adds prefixes, and `endpoints` lists known UDP
endpoints.

### On a GitHub Actions matrix

`--github` reads peers from the current run's artifacts. Only jobs in a
run can upload to it, so within a run a record is admitted just by being
there. With `init --oidc`, each record also carries a GitHub OIDC token
whose audience is `tailcat-device:` plus the SHA-256 of the node key,
binding the key to the repository, ref, and run. `--scope branch` or
`--scope pr` admit records from other runs of the workflow, which must
carry a token that checks out: signature, issuer, expiry, audience, then
`repository_id` and `ref`. A token is checked wherever a record has one,
and its expiry as of when GitHub says the record was uploaded, so a node
whose job starts long after its peers' still admits them.

```yaml
jobs:
  node:
    runs-on: ubuntu-latest
    permissions: { contents: read, actions: read, id-token: write }
    strategy:
      matrix: { index: [0, 1, 2] }
    steps:
      - run: tailcat-device init --index ${{ matrix.index }} --oidc
      - uses: actions/upload-artifact@v7
        with:
          path: node-${{ github.run_attempt }}-${{ matrix.index }}.json
          archive: false
          retention-days: 1
      - run: sudo -E tailcat-device up --github --nodes 3 --ready-file ready &
        env: { GITHUB_TOKEN: "${{ github.token }}" }
      # ...wait for ./ready, then use 100.64.<attempt>.<index> addresses
```

This repository's CI runs exactly this ([`ci.yml`](.github/workflows/ci.yml),
the `mesh` job): three runners find each other through artifacts and
ping each other over the overlay. The trust boundary is GitHub's: whoever
can run code in the workflow run. No secret passes through GitHub, and
since every peer's key is attested, the WireGuard pre-shared key is off.

## How it works

### Tailcat addresses

An address is `tc` followed by the unpadded base64url encoding of a CBOR
map with single-character keys:

| Key | Field |
|---|---|
| `p` | the server's WireGuard public key (32 bytes) |
| `k` | a separate path-discovery ("disco") public key (32 bytes) |
| `q` | a WireGuard pre-shared key (32 random bytes) |
| `r` | embedded DERP regions: maps of `i` (ID), `c` (code), `m` (name), `N` (nodes: `n` name, `h` host, `t` cert name, `4`/`6` IPs, `s` STUN port, `d` DERP port, `x` insecure for tests) |
| `i` | a region ID in the DERP map (`https://tailcat.dev/derpmap.json` by default) |

The disco key is derived from the node private key with HMAC-SHA256, so
the two public keys can't be linked: disco frames carry the disco key in
cleartext on the local network, while the node key is the unguessable
part of the address. The Rust encoder produces byte-for-byte the same
addresses as the Go one.

### Connection flow

1. **The server starts.** It makes or loads its keys, picks the
   lowest-latency DERP region (STUN probes, falling back to HTTPS timing),
   connects to that relay over TLS, and prints its address.
2. **The client parses the address**, generates an ephemeral key (or uses
   `client-default`), and connects to the same relay.
3. **Meow.** The client sends a "meow" packet over DERP announcing its
   node and disco keys. The server checks its allow hook, adds the
   client as a WireGuard peer, and answers "meowed".
4. **WireGuard.** The client handshakes (Noise IK, with the address's
   pre-shared key mixed in), initially through the relay.
5. **NAT traversal.** Both sides advertise their UDP endpoints (local
   interface addresses, and the public address STUN reports) in disco
   CallMeMaybe messages over DERP. Each pings the other's endpoints; a pong
   over UDP proves a path, and simultaneous pings open stateful NATs.
   Traffic moves to the best direct path and falls back to DERP whenever
   pongs stop. The timing constants (3 s heartbeats, 6.5 s trust, 5 s
   ping spacing) are Tailscale's; a lost path also starts a STUN round at
   once, so a NAT that remapped us is noticed in about a second (see
   [DIVERGENCES.md](DIVERGENCES.md)).
6. **Data.** Each side terminates TCP and UDP in a userspace IPv6 stack
   (smoltcp for TCP), addressed `fd7a:115c:a1e0::/48` plus the first 80
   bits of the node key, with a 1280-byte MTU. The server's packet filter
   admits only its served ports (and forwarded destinations for exit
   nodes), refusing a client's connection to any other; the client
   accepts no inbound connections at all.

### Building blocks

| Piece | Implementation |
|---|---|
| WireGuard | [boringtun](https://github.com/cloudflare/boringtun)'s Noise implementation, driven per peer by `tailcat::wg`, with peers found by static key on handshake and by receiver index afterwards |
| DERP | `tailcat::derp`: an HTTP-upgraded TLS client (rustls with ring) that reconnects with backoff, and a server for local relays and tests |
| Disco and paths | `tailcat::magicsock`: pings, pongs, CallMeMaybe, STUN, endpoint discovery, and best-path selection |
| TCP/IP | [smoltcp](https://github.com/smoltcp-rs/smoltcp) for TCP, with UDP flows demultiplexed directly |
| SSH and SFTP | [russh](https://github.com/Eugeny/russh) and russh-sftp, with PTYs via `openpty`, and [cap-std](https://github.com/bytecodealliance/cap-std) confining file services |

## Compatibility with Go tailcat

Tested in CI against nixpkgs' build of Go tailcat (0.6.0), in both
directions:

| | Status |
|---|---|
| Addresses and key files | Interchangeable; addresses re-encode byte-identically. The SSH host key uses the same file and format. |
| Pipe, ports, exec, allowlists | Interoperate. |
| DERP (including the Go DERP server and Tailscale's relays) | Interoperates. |
| NAT traversal | Direct paths form Rust↔Go, Go↔Rust, and Rust↔Rust. |
| SSH, `ls`, `cp`, drop boxes | Interoperate, with OpenSSH clients too. |
| `perf` | The wire format follows upstream's (unreleased) `perf`; Rust↔Rust is tested. |
| UDP through exit nodes | Supported; Go servers before 0.7.0 forward only TCP. |

Deliberate behavioral differences are listed in
[DIVERGENCES.md](DIVERGENCES.md).

Not ported: the js/wasm browser demo, and Windows-specific pieces
(PowerShell sessions, cmd.exe quoting is ported but untested).

The local development relay works the same way as upstream's:
`TS_DEBUG_TAILCAT_LOCAL_DERP=1 tailcat` starts a relay on loopback and
embeds it in the address (with `InsecureForTests`, since its certificate
is self-signed). `tailcat dev-derp` runs one standalone.

## Troubleshooting

**Which path is in use?** `tailcat ping --until-direct <addr>` waits for
a direct path and says which. With `-v`, clients and servers log each
change of path ("path is now direct", "direct path ... lost; now over
DERP"). A server started with `TAILCAT_STATUS_FILE=<path>` keeps each
client's path in that file as JSON.

**Stuck on DERP.** Traffic still flows through the relay, only slower.
Hole punching can't find a direct path when:

- *Either side is behind a hard NAT* (endpoint-dependent mapping, as in
  many carrier-grade and corporate NATs): each destination gets its own
  public port, and the one STUN reports isn't the one the peer would
  have to use. Tailscale works around this with port-mapping protocols
  (UPnP, NAT-PMP, PCP). tailcat doesn't, and neither does Go tailcat,
  which is built without Tailscale's port mapper.
- *A router accepts unsolicited packets from the internet without
  forwarding them to a host.* That sounds more open, but on Linux-based
  routers the first hole-punching packet from the peer lands on the
  router itself. Conntrack then holds its 4-tuple, so the host's own
  packets toward the peer leave from a different port, and the router
  in effect becomes a hard NAT toward that peer. Whether the path forms
  depends on which side pings first (see
  [DIVERGENCES.md](DIVERGENCES.md)). A real DMZ or port forward to the
  host avoids this.
- *UDP is blocked.* DERP runs over TCP (HTTPS) and carries everything.

**Connection refused.** A client gets "connection refused" when the
server doesn't serve that port, or when the local service a proxied port
points at isn't listening (the server says which on stderr).

**After a long idle.** A server forgets clients that have nothing open
and have been silent for 10 minutes (`TAILCAT_IDLE_CLIENT_TIMEOUT`). They
get back in on their own as soon as they send, after about a second's
delay.

## Development and testing

```sh
nix develop                  # cargo, rustc, clippy, rustfmt, and Go tailcat
cargo test --workspace       # unit tests and in-process end-to-end tests
nix flake check              # build + tests, clippy, rustfmt, Go interop, NAT VM test
```

The tests, from the inside out:

- **Unit tests** pin wire formats against upstream's (addresses from
  upstream's README, STUN and disco layouts) and exercise the netstack,
  DERP relay, and SFTP path handling.
- **End-to-end tests** (`crates/tailcat/tests/e2e.rs`) run servers and
  clients in one process over a local relay: TCP, UDP, RSTs for unserved
  ports, allowlists, and listeners.
- **The mesh test** (`crates/tailcat-device/tests/mesh.rs`) routes IPv4
  packets between three overlay nodes on in-memory devices.
- **[`tests/interop.sh`](tests/interop.sh)** runs every pairing of the
  Rust and Go binaries over a loopback relay (a Nix check, so it runs in
  the build sandbox).
- **[`tests/device-netns.sh`](tests/device-netns.sh)** puts three
  `tailcat-device` nodes in Linux network namespaces with real TUN
  devices, and checks pings, a TCP transfer, and direct paths.
- **[`tests/nat.nix`](tests/nat.nix)** is a NixOS VM test (a Nix check
  on Linux, needing KVM): a relay on a simulated internet and hosts behind
  two NAT routers whose behavior it switches at runtime. It checks hole
  punching through easy NATs and to a DMZ host, DERP fallback behind hard
  NATs, behind a router letting in unsolicited packets (which makes Linux
  NAT hard) and with UDP blocked, failover and recovery mid-transfer, NAT
  rebinding, a relay outage, a relay connection that silently stops
  carrying anything (noticed by the client, and by the relay when the
  client never comes back), Go↔Rust direct paths, and a `tailcat-device` mesh
  across the NATs. `nix run .#checks.x86_64-linux.nat.driverInteractive` boots it to
  poke at by hand.
- **[`tests/live.sh`](tests/live.sh)** repeats the interop tests over
  Tailscale's public relays and waits for direct paths.
- **The `mesh` CI job** runs `tailcat-device` across a matrix of three
  GitHub Actions runners, with peers from run artifacts.

## Security

- A server address is normally a secret: it holds the WireGuard
  pre-shared key, and knowing it is what lets a client connect. Publishing
  one (for example in a DNS TXT record) is only safe when the server
  authenticates clients some other way: `--allow` at the tunnel layer, or
  `--ssh-authorized-keys` at the SSH layer. Never publish a `no-auth-ssh`
  server's address. `tailcat ssh` to a DNS name first probes whether a
  stranger could log in, and refuses to connect if so.
- The public tailcat relays are run by Tailscale, free and rate-limited,
  with no uptime promise; you can run your own DERP server and name it in
  the address instead.
- Report vulnerabilities in the protocol itself upstream, per
  [tailcat's SECURITY.md](https://github.com/tailscale/tailcat/blob/main/SECURITY.md).

This project, like upstream, makes no API, CLI, or wire-format stability
promises.

## License

BSD 3-Clause, like upstream tailcat. WireGuard is a registered trademark
of Jason A. Donenfeld.
