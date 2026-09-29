#!/usr/bin/env bash
# Rust <-> Go interop over Tailscale's public tailcat DERP relays: real
# TLS, netcheck region selection, STUN, and NAT traversal to a direct
# path. Needs the internet.
#
#   tests/live.sh <rust tailcat> <go tailcat>

set -euo pipefail

# Each implementation's binary is in the variable of its name, so "${!c}"
# is client $c's.
# shellcheck disable=SC2034
rust=${1:?usage: live.sh <rust tailcat> <go tailcat>} go=${2:?usage: live.sh <rust tailcat> <go tailcat>}
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/lib.sh"
start_wait=300

# serve <name> <server command...>: like start, showing the server's
# first log lines (its region).
serve() {
	start "$@"
	head -2 "$work/$1.log"
}

for pair in "rust go" "go rust" "rust rust"; do
	read -r s c <<<"$pair"
	serve "pipe-$s" "${!s}"
	msg="hello over the internet from $c"
	if echo "$msg" | timeout 60 "${!c}" "$addr" 2>"$work/client.log" && sleep 0.5 && grep -qx "$msg" "$work/pipe-$s.out"; then
		pass "pipe: $c client -> $s server"
	else
		fail "pipe: $c client -> $s server: $(tail -3 "$work/client.log")"
	fi
	stop
	serve "ping-$s" "${!s}" serve 80
	if timeout 60 "${!c}" ping --until-direct --timeout=30s "$addr"; then
		pass "direct path: $c client -> $s server"
	else
		fail "direct path: $c client -> $s server"
	fi
	stop
done

finish live
