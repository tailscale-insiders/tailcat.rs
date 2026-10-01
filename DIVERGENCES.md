# Divergences from Go tailcat

tailcat.rs aims to interoperate with [Go tailcat](https://github.com/tailscale/tailcat)
and to behave the same way by default. This file lists the places where it
deliberately behaves differently, and why. Each entry says what Go does,
what tailcat.rs does, and whether the difference is visible to a Go peer.

Wire formats (addresses, key files, DERP, disco, WireGuard) don't diverge;
anything here is local behavior.

## A proxied backend that refuses refuses the client

When `serve` proxies a port (`serve 7`, `serve 8080:host:80`, or an exit
node), Go tailcat accepts the client's connection first and then dials
the backend (`net.Dial` in `cmd/tailcat`). If the backend isn't
listening, the client sees a clean close and exits 0.

tailcat.rs dials the backend first, while the client's SYN waits
unanswered, and accepts the connection only once the dial succeeds. If
the dial fails, the client gets a RST and reports "connection refused"
(exit 1). The server prints the failure on stderr. Tailscale's own
netstack forwarder works the same way.

Visible to Go clients: yes. A Go client sees a refusal where it used to
see an empty connection.

## SSH sessions get SSH_CLIENT, SSH_CONNECTION and SSH_TTY

Go tailcat gives SSH sessions only SHELL, USER, HOME and a fixed PATH
(plus TERM and the locale variables the client sends).

tailcat.rs also sets the variables OpenSSH's sshd sets: `SSH_CLIENT`
(`client-ip client-port server-port`), `SSH_CONNECTION`
(`client-ip client-port server-ip server-port`), and, with a PTY,
`SSH_TTY`. The addresses are the tunnel's (tailcat IPv6) addresses.
Clients can't override them.

Many scripts use these to detect a remote session. NixOS's
`/etc/bashrc` also needs them: it sets up a non-interactive shell's PATH
only when it sees `SSH_CLIENT`. Without them, `tailcat ssh host cat`
against a NixOS server fails with "command not found", because the fixed
PATH has no `/run/current-system/sw/bin`.

Visible to Go clients: yes, in the session's environment.

## Path visibility: TAILCAT_STATUS_FILE and path-change logs

Go tailcat reports paths only through `TAILCAT_STATUS_LOOP=1`, which
prints its internal status struct every 5 seconds. tailcat.rs keeps that
variable, printing its own debug representation, which isn't the same
text as Go's.

tailcat.rs adds:

- `TAILCAT_STATUS_FILE=<path>` (server mode): the server's status as
  JSON, rewritten atomically every 2 seconds. It includes each client's
  direct path or DERP region, handshake age and byte counts, with the
  same field names as `tailcat-device --status-file`.
- Info-level logs (shown with `-v`) whenever the path to a peer in use
  changes: a direct path found, moved to another address, or lost to
  DERP. These appear on both clients and servers.

Visible to Go peers: no.

## Unserved ports refuse instead of hanging

When a server serves only some ports (`serve 80`), Go tailcat's packet
filter silently drops a client's SYN to any other port, so the client's
dial waits out its 10 s timeout ("Dial: timed out").

tailcat.rs answers such a SYN with a RST, so the client gets "connection
refused" right away. Only authenticated clients get this far; SYNs from
anyone else are still dropped silently. Silence would hide nothing from
a client that already holds the server's address and keys.

Visible to Go clients: yes. A Go client sees a refusal instead of a
timeout.

# Known differences that aren't deliberate

## Which side's hole-punching ping goes out first

A Rust server sends its CallMeMaybe before its "meowed" ack
(`crates/tailcat/src/server.rs`), so a client pings the server's
endpoints before the server pings the client's. A Go server sends its
CallMeMaybe later, from a goroutine, so with Go on both sides the server
usually pings first. The order is a race in Go and fixed in Rust.

It matters only behind a router that accepts unsolicited WAN packets
without forwarding them to a host. Linux delivers such a packet to the
router itself, and conntrack keeps its 4-tuple. If the peer's ping
arrives before the host behind that router has pinged out, the host's
own flow toward the peer is remapped to a port the peer never learns,
and the path stays on DERP. So against a server behind such a router,
Go↔Go usually goes direct and Rust (either side) stays on DERP. Against
a client behind one, Rust goes direct. When both routers are permissive,
whoever pings first loses, in Go too. Any fixed order fixes one case and
breaks the other. The `permissive` and `dmz` scenarios in
`tests/nat.nix` cover this.
