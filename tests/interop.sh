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

# Each implementation's binary is in the variable of its name, so "${!c}"
# is client $c's.
# shellcheck disable=SC2034
rust=${1:?usage: interop.sh <rust tailcat> <go tailcat>} go=${2:?usage: interop.sh <rust tailcat> <go tailcat>}
impls=(rust go)
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/lib.sh"
# Servers run a relay of their own; clients ignore this.
export TS_DEBUG_TAILCAT_LOCAL_DERP=1
# Build sandboxes don't set USER, and Go's os/user needs it without cgo
# (nixpkgs' Go tailcat is built without cgo).
USER=${USER:-$(id -un)}
export USER

# The stdin/stdout pipe, both directions, every pairing.
for s in "${impls[@]}"; do
	for c in "${impls[@]}"; do
		[ "$s" = go ] && [ "$c" = go ] && continue
		start "pipe-$s" "${!s}"
		msg="hello from $c to $s"
		if ! echo "$msg" | timeout 60 "${!c}" "$addr" >/dev/null 2>"$work/client.log"; then
			fail "pipe: $c client -> $s server: client failed: $(tail -3 "$work/client.log")"
		elif has_line "$work/pipe-$s.out" "$msg"; then
			pass "pipe: $c client -> $s server"
		else
			fail "pipe: $c client -> $s server: server got '$(cat "$work/pipe-$s.out")'"
		fi
		stop
	done
done

# The exec service, with the peer's key in the environment.
for c in "${impls[@]}"; do
	start exec "$rust" serve exec -- sh -c 'tr a-z A-Z; echo "key=${TAILCAT_PEER_KEY%%:*}"'
	out=$(echo shout | timeout 60 "${!c}" "$addr" 7 2>"$work/client.log" || true)
	if [ "$out" = "$(printf 'SHOUT\nkey=nodekey')" ]; then
		pass "exec: $c client -> rust server"
	else
		fail "exec: $c client -> rust server: got '$out' $(tail -3 "$work/client.log")"
	fi
	stop
done

# The client exits once the server is done, even with stdin still open.
start exec-done "$rust" serve exec -- echo done
mkfifo "$work/open-stdin"
sleep 120 >"$work/open-stdin" &
holder=$!
out=$(timeout 30 "$rust" "$addr" 7 <"$work/open-stdin" 2>"$work/client.log") && code=0 || code=$?
kill "$holder" 2>/dev/null || true
if [ "$code" = 0 ] && [ "$out" = done ]; then
	pass "exec: rust client exits with stdin open"
else
	fail "exec: rust client exits with stdin open: exit=$code out='$out' $(tail -3 "$work/client.log")"
fi
stop

# The one-shot server serves its first connection and refuses the rest,
# which would otherwise interleave with it on stdout.
start oneshot "$rust"
mkfifo "$work/first-stdin"
timeout 60 "$rust" "$addr" <"$work/first-stdin" >/dev/null 2>"$work/first.log" &
first=$!
exec 3>"$work/first-stdin"
echo first >&3
for _ in $(seq 150); do
	grep -qx first "$work/oneshot.out" && break
	sleep 0.1
done
if echo second | timeout 30 "$rust" "$addr" >/dev/null 2>"$work/client.log"; then
	fail "one-shot: a second connection was accepted"
else
	pass "one-shot: a second connection is refused"
fi
exec 3>&-
wait "$first" && code=0 || code=$?
for _ in $(seq 100); do
	kill -0 "$server_pid" 2>/dev/null || break
	sleep 0.1
done
if kill -0 "$server_pid" 2>/dev/null; then
	fail "one-shot: server still running after its connection closed"
	stop
elif ! wait "$server_pid"; then
	fail "one-shot: server failed: $(tail -3 "$work/oneshot.log")"
elif [ "$code" = 0 ] && [ "$(cat "$work/oneshot.out")" = first ]; then
	pass "one-shot: the first connection is served"
else
	fail "one-shot: the first connection is served: client exit=$code, server got '$(cat "$work/oneshot.out")'"
fi

# A proxied port with nothing listening on it refuses the client.
start refused "$rust" serve 1
for c in "${impls[@]}"; do
	name="serve: $c client -> rust server with nothing on the port is refused"
	if echo x | timeout 30 "${!c}" "$addr" 1 >/dev/null 2>"$work/client.log"; then
		fail "$name: the client succeeded"
	elif grep -qi "refused" "$work/client.log"; then
		pass "$name"
	else
		fail "$name: $(tail -3 "$work/client.log")"
	fi
	# A port the server doesn't serve refuses too, well before the
	# client's 10s dial timeout.
	name="serve: $c client -> rust server's unserved port is refused"
	if echo x | timeout 8 "${!c}" "$addr" 2 >/dev/null 2>"$work/client.log"; then
		fail "$name: the client succeeded"
	elif grep -qi "refused" "$work/client.log"; then
		pass "$name"
	else
		fail "$name: $(tail -3 "$work/client.log")"
	fi
done
stop

# SIGTERM stops a server as cleanly as Ctrl-C.
start term "$rust" serve 1
kill -TERM "$server_pid"
if wait "$server_pid"; then
	pass "serve: exits cleanly on SIGTERM"
else
	fail "serve: exits cleanly on SIGTERM: exit=$?"
fi

# An allowlist keeps strangers out.
"$rust" genkey --client --key="$work/allowed.private.json" >"$work/allowed.pub" 2>/dev/null
allow=--allow=$(cat "$work/allowed.pub")
for s in "${impls[@]}"; do
	start "allow-$s" "${!s}" serve "$allow" 1
	for c in "${impls[@]}"; do
		if echo stranger | timeout 30 "${!c}" --key=new "$addr" 1 >/dev/null 2>&1; then
			fail "allow: $c stranger admitted by $s server"
		else
			pass "allow: $c stranger rejected by $s server"
		fi
	done
	stop
	# The allowed key gets in (with the one-shot server, the first
	# connection is written to its stdout).
	for c in "${impls[@]}"; do
		start "allowed-$s" "${!s}" serve "$allow"
		if echo "friend of $c" | timeout 60 "${!c}" --key="$work/allowed.private.json" "$addr" >/dev/null 2>"$work/client.log" &&
			has_line "$work/allowed-$s.out" "friend of $c"; then
			pass "allow: $c allowed key admitted by $s server"
		else
			fail "allow: $c allowed key admitted by $s server: $(tail -3 "$work/client.log")"
		fi
		stop
	done
done

# Each parses the other's addresses and reads the other's key files.
for a in "${impls[@]}"; do
	for b in "${impls[@]}"; do
		[ "$a" = "$b" ] && continue
		start "parse-$a" "${!a}"
		if "${!b}" parse "$addr" | grep -q '"ServerPublic": "nodekey:'; then
			pass "parse: $b parses a $a address"
		else
			fail "parse: $b parses a $a address"
		fi
		stop
		"${!a}" genkey --client --key="$work/$a-client.private.json" >"$work/$a-client.pub" 2>/dev/null
		if [ "$("${!b}" --key="$work/$a-client.private.json" printpub)" = "$(cat "$work/$a-client.pub")" ]; then
			pass "keys: $b reads a $a client key"
		else
			fail "keys: $b reads a $a client key"
		fi
	done
done

# SSH, if an OpenSSH client is available.
if command -v ssh >/dev/null; then
	for s in "${impls[@]}"; do
		start "ssh-$s" "${!s}" serve no-auth-ssh
		for c in "${impls[@]}"; do
			out=$(timeout 60 "${!c}" ssh "$addr" 'echo ssh-ok; exit 3' 2>"$work/client.log") && code=0 || code=$?
			if [ "$out" = ssh-ok ] && [ "$code" = 3 ]; then
				pass "ssh: $c client -> $s server"
			else
				fail "ssh: $c client -> $s server: out='$out' exit=$code $(tail -3 "$work/client.log")"
			fi
		done
		stop
	done
fi

# File service: a Rust server, read with both clients' ls.
mkdir -p "$work/pub/sub"
echo one >"$work/pub/one.txt"
start files "$rust" serve --files="$work/pub" files
for c in "${impls[@]}"; do
	if timeout 60 "${!c}" ls "$addr" 2>"$work/client.log" | grep -q '^one.txt$'; then
		pass "files: $c ls of a rust file server"
	else
		fail "files: $c ls of a rust file server: $(tail -3 "$work/client.log")"
	fi
done
stop

finish interop
