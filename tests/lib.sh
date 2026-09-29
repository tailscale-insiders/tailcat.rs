# shellcheck shell=bash disable=SC2034
# Shared by interop.sh and live.sh: a scratch $work directory and $HOME,
# background servers that are killed on exit, and pass/fail tallies.

# How long start waits for a server's address, in tenths of a second.
start_wait=150

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
pass() { echo "ok   $*"; }
fail() {
	echo "FAIL $*" | tr "\r" " "
	failures=$((failures + 1))
}

# finish <kind>: reports the tally, failing if any test failed.
finish() {
	echo
	if [ "$failures" -gt 0 ]; then
		echo "$failures $1 test(s) failed"
		exit 1
	fi
	echo "all $1 tests passed"
}

# start <name> <server command...>: runs a server in the background and
# waits for its address, which it leaves in $addr.
start() {
	local name=$1
	shift
	rm -f "$work/addr"
	TAILCAT_ADDR_FILE="$work/addr" "$@" >"$work/$name.out" 2>"$work/$name.log" &
	server_pid=$!
	pids+=("$server_pid")
	for _ in $(seq "$start_wait"); do
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

# stop: stops the last server started.
stop() {
	kill "$server_pid" 2>/dev/null || true
	wait "$server_pid" 2>/dev/null || true
}
