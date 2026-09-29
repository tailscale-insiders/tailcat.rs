#!/usr/bin/env bash
# Interop tests between the Rust tailcat and the upstream Go tailcat,
# over a loopback DERP relay (TS_DEBUG_TAILCAT_LOCAL_DERP), so they run
# offline, including inside the Nix build sandbox.
#
#   tests/interop.sh <rust tailcat> <go tailcat>
#
# Every test runs a server with one implementation and a client with the
# other (and Rust with itself), and checks what arrives.

set -euo pipefail

RS=${1:?usage: interop.sh <rust tailcat> <go tailcat>}
GO=${2:?usage: interop.sh <rust tailcat> <go tailcat>}
work=$(mktemp -d)
export HOME="$work/home"
mkdir -p "$HOME"
# Build sandboxes don't set USER, and Go's os/user needs it without cgo
# (nixpkgs' Go tailcat is built without cgo).
USER=${USER:-$(id -un)}
export USER
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

failures=0
pass() { echo "ok   $*"; }
fail() {
	echo "FAIL $*" | tr "\r" " "
	failures=$((failures + 1))
}

# start <name> <server command...>: runs a server with a local relay and
# waits for its address, which it leaves in $addr.
start() {
	local name=$1
	shift
	rm -f "$work/addr"
	TS_DEBUG_TAILCAT_LOCAL_DERP=1 TAILCAT_ADDR_FILE="$work/addr" "$@" >"$work/$name.out" 2>"$work/$name.log" &
	pids+=($!)
	server_pid=$!
	for _ in $(seq 150); do
		[ -s "$work/addr" ] && break
		sleep 0.1
	done
	if [ ! -s "$work/addr" ]; then
		echo "server $name did not start:"
		cat "$work/$name.log"
		exit 1
	fi
	addr=$(cat "$work/addr")
}

stop() {
	kill "$server_pid" 2>/dev/null || true
	wait "$server_pid" 2>/dev/null || true
}

impls=("rust:$RS" "go:$GO")

# The stdin/stdout pipe, both directions, every pairing.
for s in "${impls[@]}"; do
	for c in "${impls[@]}"; do
		sn=${s%%:*} sb=${s#*:} cn=${c%%:*} cb=${c#*:}
		[ "$sn" = go ] && [ "$cn" = go ] && continue
		start "pipe-$sn" "$sb"
		msg="hello from $cn to $sn"
		if echo "$msg" | timeout 60 "$cb" "$addr" >/dev/null 2>"$work/client.log"; then
			sleep 0.5
			if grep -qx "$msg" "$work/pipe-$sn.out"; then
				pass "pipe: $cn client -> $sn server"
			else
				fail "pipe: $cn client -> $sn server: server got '$(cat "$work/pipe-$sn.out")'"
			fi
		else
			fail "pipe: $cn client -> $sn server: client failed: $(tail -3 "$work/client.log")"
		fi
		stop
	done
done

# The exec service, with the peer's key in the environment.
for c in "${impls[@]}"; do
	cn=${c%%:*} cb=${c#*:}
	start exec "$RS" serve exec -- sh -c 'tr a-z A-Z; echo "key=${TAILCAT_PEER_KEY%%:*}"'
	out=$(echo shout | timeout 60 "$cb" "$addr" 7 2>"$work/client.log" || true)
	if [ "$out" = "$(printf 'SHOUT\nkey=nodekey')" ]; then
		pass "exec: $cn client -> rust server"
	else
		fail "exec: $cn client -> rust server: got '$out' $(tail -3 "$work/client.log")"
	fi
	stop
done

# An allowlist keeps strangers out.
"$RS" genkey --client --key="$work/allowed.private.json" >"$work/allowed.pub" 2>/dev/null
for s in "${impls[@]}"; do
	sn=${s%%:*} sb=${s#*:}
	start "allow-$sn" "$sb" serve --allow="$(cat "$work/allowed.pub")" 1
	for c in "${impls[@]}"; do
		cn=${c%%:*} cb=${c#*:}
		if echo stranger | timeout 30 "$cb" --key=new "$addr" 1 >/dev/null 2>&1; then
			fail "allow: $cn stranger admitted by $sn server"
		else
			pass "allow: $cn stranger rejected by $sn server"
		fi
	done
	stop
done

# Parsing each other's addresses.
start parse "$GO"
if "$RS" parse "$addr" | grep -q '"ServerPublic": "nodekey:'; then
	pass "parse: rust parses a go address"
else
	fail "parse: rust parses a go address"
fi
stop
start parse "$RS"
if "$GO" parse "$addr" | grep -q '"ServerPublic": "nodekey:'; then
	pass "parse: go parses a rust address"
else
	fail "parse: go parses a rust address"
fi
stop

# Key files are interchangeable.
"$GO" genkey --client --key="$work/goclient.private.json" >"$work/goclient.pub" 2>/dev/null
if [ "$("$RS" --key="$work/goclient.private.json" printpub)" = "$(cat "$work/goclient.pub")" ]; then
	pass "keys: rust reads a go client key"
else
	fail "keys: rust reads a go client key"
fi
"$RS" genkey --client --key="$work/rsclient.private.json" >"$work/rsclient.pub" 2>/dev/null
if [ "$("$GO" --key="$work/rsclient.private.json" printpub)" = "$(cat "$work/rsclient.pub")" ]; then
	pass "keys: go reads a rust client key"
else
	fail "keys: go reads a rust client key"
fi

# SSH, if an OpenSSH client is available.
if command -v ssh >/dev/null; then
	for s in "${impls[@]}"; do
		sn=${s%%:*} sb=${s#*:}
		start "ssh-$sn" "$sb" serve no-auth-ssh
		for c in "${impls[@]}"; do
			cn=${c%%:*} cb=${c#*:}
			out=$(timeout 60 "$cb" ssh "$addr" 'echo ssh-ok; exit 3' 2>"$work/client.log") && code=0 || code=$?
			if [ "$out" = ssh-ok ] && [ "$code" = 3 ]; then
				pass "ssh: $cn client -> $sn server"
			else
				fail "ssh: $cn client -> $sn server: out='$out' exit=$code $(tail -3 "$work/client.log")"
			fi
		done
		stop
	done
fi

# File service: a Rust server, read with both clients' ls.
mkdir -p "$work/pub/sub"
echo one >"$work/pub/one.txt"
start files "$RS" serve --files="$work/pub" files
for c in "${impls[@]}"; do
	cn=${c%%:*} cb=${c#*:}
	if timeout 60 "$cb" ls "$addr" 2>"$work/client.log" | grep -q '^one.txt$'; then
		pass "files: $cn ls of a rust file server"
	else
		fail "files: $cn ls of a rust file server: $(tail -3 "$work/client.log")"
	fi
done
stop

echo
if [ "$failures" -gt 0 ]; then
	echo "$failures interop test(s) failed"
	exit 1
fi
echo "all interop tests passed"
