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
