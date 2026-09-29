#!/usr/bin/env bash
# Rust <-> Go interop over Tailscale's public tailcat DERP relays: real
# TLS, netcheck region selection, STUN, and NAT traversal to a direct
# path. Needs the internet.
#
#   tests/live.sh <rust tailcat> <go tailcat>

set -euo pipefail

RS=${1:?usage: live.sh <rust tailcat> <go tailcat>}
GO=${2:?usage: live.sh <rust tailcat> <go tailcat>}
work=$(mktemp -d)
export HOME="$work/home"
mkdir -p "$HOME"
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT
failures=0

start() {
	local name=$1
	shift
	rm -f "$work/addr"
	TAILCAT_ADDR_FILE="$work/addr" "$@" >"$work/$name.out" 2>"$work/$name.log" &
	pids+=($!)
	server_pid=$!
	for _ in $(seq 300); do
		[ -s "$work/addr" ] && break
		sleep 0.1
	done
	[ -s "$work/addr" ] || { echo "server $name did not start:"; cat "$work/$name.log"; exit 1; }
	addr=$(cat "$work/addr")
	head -2 "$work/$name.log"
}

stop() {
	kill "$server_pid" 2>/dev/null || true
	wait "$server_pid" 2>/dev/null || true
}

for pair in "rust:$RS go:$GO" "go:$GO rust:$RS" "rust:$RS rust:$RS"; do
	read -r s c <<<"$pair"
	sn=${s%%:*} sb=${s#*:} cn=${c%%:*} cb=${c#*:}
	start "pipe-$sn" "$sb"
	msg="hello over the internet from $cn"
	if echo "$msg" | timeout 60 "$cb" "$addr" 2>"$work/client.log" && sleep 0.5 && grep -qx "$msg" "$work/pipe-$sn.out"; then
		echo "ok   pipe: $cn client -> $sn server"
	else
		echo "FAIL pipe: $cn client -> $sn server: $(tail -3 "$work/client.log")"
		failures=$((failures + 1))
	fi
	stop
	start "ping-$sn" "$sb" serve 80
	if timeout 60 "$cb" ping --until-direct --timeout=30s "$addr"; then
		echo "ok   direct path: $cn client -> $sn server"
	else
		echo "FAIL direct path: $cn client -> $sn server"
		failures=$((failures + 1))
	fi
	stop
done

[ "$failures" -eq 0 ] || { echo "$failures live test(s) failed"; exit 1; }
echo "all live tests passed"
