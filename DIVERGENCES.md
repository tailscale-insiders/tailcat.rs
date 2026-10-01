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
