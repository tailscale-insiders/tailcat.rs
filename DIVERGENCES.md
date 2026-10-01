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

## A quiet relay connection gets pinged

Go tailcat (like Tailscale's DERP client) notices a relay connection
that stopped carrying anything only through its 120 s read deadline or
TCP keepalive. That happens when a NAT or firewall starts dropping the
connection without a reset. Go pings the relay only after a network
change. Until then, an idle server behind such a NAT is unreachable for
about two minutes, and a relayed session times out.

tailcat.rs pings a relay it hasn't heard from in 20 s. If no frame of any
kind arrives within 10 s more, it drops the connection and redials. In
the NAT VM test this brings recovery from about 125–130 s down to about
25–30 s. The cost is one small frame about every 20 s per idle relay
connection. Relays already answer these pings, Go's included.

Visible to Go peers: no. Visible to relays: one ping frame per idle
period.

## A relay that keeps closing connections is redialed less often

Go tailcat (through Tailscale's magicsock) resets its wait before
redialing a relay whenever a frame arrives, including the server info
that ends a login. A relay that takes logins and then closes the
connection, for example while overloaded or behind a misbehaving load
balancer, is redialed after about 10 ms each time, as fast as TLS
handshakes complete.

tailcat.rs resets the wait only when a connection that lasted at least
10 s ends. After a failed dial, or a connection that ended sooner, the
wait doubles from 100 ms up to 5 s. Such a relay is then dialed once
every 5 s. A login also counts as connected only once the relay's
server info arrives, so a rejected login backs off the same way, as
Go's does.

Visible to Go peers: no. Visible to relays: fewer reconnects.

## The development relay lets go of clients that vanished

Go tailcat's local development relay (`TS_DEBUG_TAILCAT_LOCAL_DERP`)
listens with Go's default socket options. A client whose connection
stops carrying anything without a reset, because its NAT forgot the
connection or its machine went away, stays registered as long as TCP
keeps retransmitting the relay's keepalives. Packets sent to that client
are dropped without a "peer gone" answer.

tailcat.rs's relay (`TS_DEBUG_TAILCAT_LOCAL_DERP` and `tailcat
dev-derp`) sets `TCP_USER_TIMEOUT` to 15 s on each connection, as
Tailscale's derper does. A keepalive that goes unacknowledged that long
closes the connection. It doesn't use a read timeout, because idle
clients (Go's in particular) send nothing. In the NAT VM test, the relay
lets go of such a client 75 s after its connection went silent, at most
one keepalive interval plus the timeout. Without the option it took
about 1020 s.

Visible to Go peers: only to clients of a tailcat.rs relay, which hear
sooner that a vanished peer is gone.

## Idle clients are forgotten, and let back in

A Go tailcat server keeps every client that ever joined as a WireGuard
and path-discovery peer until the server exits. So a long-running server
that sees many client keys grows without bound.

A tailcat.rs server forgets a client that has nothing open and has sent
nothing for 10 minutes. `TAILCAT_IDLE_CLIENT_TIMEOUT` (or
`ServerBuilder::idle_client_timeout`) changes the timeout, and `0` means
never. The server keeps a small record of each forgotten client (up to
4096): its keys and the last direct address it used. The client is let
back in, without the allow hook being asked again, as soon as it sends:

- a WireGuard handshake;
- real traffic over DERP;
- real traffic from that last address.

The server then starts a new WireGuard session with it right away.
Keepalives and disco pings don't count, since they mean the client has
nothing to send. `disconnect_client` also clears that record.

Go clients never re-announce themselves, so this is the only way they
get back in. Their first connection after a long silence takes about a
second longer, one TCP SYN retransmit. Rust clients get back in the same
way.

Visible to Go clients: only that one-second delay after a long idle
period.

## Faster path recovery

Go tailcat re-STUNs only on its timer, and pings a peer back at most
every 5 s per endpoint. tailcat.rs also:

- re-STUNs at once (at most every 2 s) when a direct path in use is lost,
  or when a pong shows the peer now sees us at a different address, so a
  NAT that remaps us is noticed within a second or so instead of
  20–26 s;
- stops trusting a path to an endpoint the peer no longer advertises;
- while no path is trusted, pings a peer back on its ping if we last
  pinged that endpoint at least 1 s ago (rather than 5 s).

In the NAT VM test, a rebinding NAT kept traffic on DERP for 9–11 s
after the old path was declared dead. Now it's 0–0.6 s. Recovery after
UDP is unblocked went from 0.1–6.9 s to 0.9 s.

Visible to Go peers: a few more disco pings and CallMeMaybes around a
path change.

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
a client behind one, Rust goes direct. (These are tendencies: the
order is still a race, and Rust occasionally goes direct against a
permissive server.) When both routers are permissive, whoever pings
first loses, in Go too. Any fixed order fixes one case and
breaks the other. The `permissive` and `dmz` scenarios in
`tests/nat.nix` cover this.
