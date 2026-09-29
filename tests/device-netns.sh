#!/usr/bin/env bash
# End-to-end test of tailcat-device on real TUN interfaces: three Linux
# network namespaces on a bridge, a local DERP relay in the root
# namespace, and a mesh between them. Needs root (or CAP_NET_ADMIN),
# iproute2, ping, and Python 3 (for a tiny TCP transfer check).
#
#   sudo tests/device-netns.sh <tailcat> <tailcat-device>

set -euo pipefail

TC=${1:?usage: device-netns.sh <tailcat> <tailcat-device>}
DEV=${2:?usage: device-netns.sh <tailcat> <tailcat-device>}
N=3
work=$(mktemp -d)
pids=()

cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	for i in $(seq 0 $((N - 1))); do ip netns del "tcd$i" 2>/dev/null || true; done
	ip link del tcd-br 2>/dev/null || true
	iptables -D FORWARD -i tcd-br -o tcd-br -j ACCEPT 2>/dev/null || true
	if [ "${keep:-}" != 1 ]; then rm -rf "$work"; fi
}
trap cleanup EXIT

dump_logs() {
	for f in "$work"/*.log; do
		echo "=== $f"
		tail -40 "$f"
	done
}

ip link add tcd-br type bridge
ip addr add 10.99.0.1/24 dev tcd-br
ip link set tcd-br up
# Docker (present on GitHub's runners) loads br_netfilter and drops
# forwarded packets, which would include bridged traffic between the
# namespaces: exactly the direct paths this test wants to see.
sysctl -qw net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true
iptables -I FORWARD -i tcd-br -o tcd-br -j ACCEPT 2>/dev/null || true
for i in $(seq 0 $((N - 1))); do
	ns=tcd$i
	ip netns add "$ns"
	ip link add "tcdv$i" type veth peer name "tcdp$i"
	ip link set "tcdp$i" master tcd-br up
	ip link set "tcdv$i" netns "$ns"
	ip -n "$ns" addr add "10.99.0.$((i + 10))/24" dev "tcdv$i"
	ip -n "$ns" link set "tcdv$i" up
	ip -n "$ns" link set lo up
done

# The relay: DERP over TLS and STUN, reachable from every namespace.
"$TC" dev-derp --derp 10.99.0.1:0 --stun 10.99.0.1:3478 --region-file "$work/region.json" >/dev/null 2>"$work/derp.log" &
pids+=($!)
for _ in $(seq 100); do [ -s "$work/region.json" ] && break; sleep 0.1; done
[ -s "$work/region.json" ] || { echo "relay didn't start"; cat "$work/derp.log"; exit 1; }

mkdir -p "$work/records"
for i in $(seq 0 $((N - 1))); do
	ip netns exec "tcd$i" "$DEV" init --index "$i" --attempt 1 --region-file "$work/region.json" \
		--key "$work/key$i" --out "$work/records/node-1-$i.json" >/dev/null
done

for i in $(seq 0 $((N - 1))); do
	ip netns exec "tcd$i" "$DEV" up --key "$work/key$i" --records "$work/records" --nodes "$N" --wait 60s \
		--tun tcd0 --status-file "$work/status$i.json" --ready-file "$work/ready$i" --status-interval 5s \
		2>"$work/node$i.log" &
	pids+=($!)
done

for i in $(seq 0 $((N - 1))); do
	for _ in $(seq 600); do [ -e "$work/ready$i" ] && break; sleep 0.1; done
	if [ ! -e "$work/ready$i" ]; then
		echo "node $i never became ready"
		dump_logs
		exit 1
	fi
done
echo "ok   all $N nodes ready"

# Every node pings every other over the overlay.
for i in $(seq 0 $((N - 1))); do
	for j in $(seq 0 $((N - 1))); do
		[ "$i" = "$j" ] && continue
		if ip netns exec "tcd$i" ping -c 3 -i 0.2 -W 2 "100.64.1.$j" >/dev/null; then
			echo "ok   ping node $i -> 100.64.1.$j"
		else
			echo "FAIL ping node $i -> 100.64.1.$j"
			dump_logs
			exit 1
		fi
	done
done

# A TCP transfer across the overlay.
ip netns exec tcd1 python3 -c '
import socket, hashlib
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("100.64.1.1", 9000)); s.listen(1)
c, _ = s.accept(); h = hashlib.sha256(); n = 0
while True:
    b = c.recv(65536)
    if not b: break
    h.update(b); n += len(b)
open("'"$work"'/received", "w").write("%d %s" % (n, h.hexdigest()))
' &
listener=$!
sleep 0.5
head -c 4000000 /dev/urandom >"$work/payload"
ip netns exec tcd0 python3 -c '
import socket
s = socket.create_connection(("100.64.1.1", 9000), timeout=30)
s.sendall(open("'"$work"'/payload", "rb").read()); s.close()
'
wait "$listener"
want="4000000 $(sha256sum "$work/payload" | cut -d" " -f1)"
if [ "$(cat "$work/received")" = "$want" ]; then
	echo "ok   4 MB TCP transfer node 0 -> node 1"
else
	echo "FAIL TCP transfer: got '$(cat "$work/received")', want '$want'"
	dump_logs
	exit 1
fi

# The namespaces share a LAN, so the nodes should find direct paths.
sleep 6
direct=$(python3 -c '
import json, sys
n = 0
for i in range('"$N"'):
    for p in json.load(open("'"$work"'/status%d.json" % i)):
        n += p["direct"] is not None
print(n)')
echo "     $direct of $((N * (N - 1))) peer paths are direct"
if [ "$direct" -lt 1 ]; then
	echo "FAIL no direct paths formed"
	dump_logs
	exit 1
fi
echo "ok   direct paths formed"
echo "all device tests passed"
