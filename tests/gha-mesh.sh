#!/usr/bin/env bash
# Steps of one node of the GitHub Actions mesh test (see ci.yml). The
# node runs tailcat-device with peers from this run's artifacts; it must
# stay up across steps, so `start` leaves it running in the background.
#
#   tests/gha-mesh.sh start <tailcat-device> <nodes>   # after the record is uploaded
#   tests/gha-mesh.sh check <index> <nodes>            # ping every other node
#   tests/gha-mesh.sh wait-done <nodes>                # after uploading done-<attempt>-<index>
#   tests/gha-mesh.sh stop                             # print logs, stop the node
#
# Needs sudo (for the TUN device) and GITHUB_TOKEN (read by both
# tailcat-device and gh) with `actions: read`.

set -euo pipefail

state=${RUNNER_TEMP:-/tmp}/tailcat-mesh
mkdir -p "$state"
attempt=${GITHUB_RUN_ATTEMPT:-1}

case ${1:-} in
start)
	dev=${2:?} nodes=${3:?}
	# A ready file from an earlier node would pass the check below before
	# this one is up.
	sudo rm -f "$state/ready" "$state/status.json"
	sudo -E nohup "$dev" up --key tailcat-device.key --github --nodes "$nodes" --wait 8m \
		--tun tcmesh0 --status-file "$state/status.json" --ready-file "$state/ready" --status-interval 10s \
		>"$state/node.log" 2>&1 &
	echo $! >"$state/pid"
	for _ in $(seq 600); do
		[ -e "$state/ready" ] && exit 0
		if ! sudo kill -0 "$(cat "$state/pid")" 2>/dev/null; then
			echo "tailcat-device exited:"
			cat "$state/node.log"
			exit 1
		fi
		sleep 1
	done
	echo "never became ready:"
	cat "$state/node.log"
	exit 1
	;;
check)
	index=${2:?} nodes=${3:?}
	failed=0
	for j in $(seq 0 $((nodes - 1))); do
		[ "$j" = "$index" ] && continue
		ip="100.64.$attempt.$j"
		if ping -c 5 -i 0.3 -W 3 "$ip"; then
			echo "ok   node $index -> node $j ($ip)"
		else
			echo "FAIL node $index -> node $j ($ip)"
			failed=1
		fi
	done
	exit $failed
	;;
wait-done)
	nodes=${2:?}
	# A node that leaves early would fail its peers' pings, so wait for
	# every node's done marker.
	for _ in $(seq 120); do
		n=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/artifacts?per_page=100" \
			--jq "[.artifacts[].name | select(startswith(\"done-$attempt-\"))] | length")
		echo "$n of $nodes nodes done"
		[ "$n" -ge "$nodes" ] && exit 0
		sleep 5
	done
	echo "timed out waiting for the other nodes"
	exit 1
	;;
stop)
	if [ -e "$state/pid" ]; then sudo kill "$(cat "$state/pid")" 2>/dev/null || true; fi
	echo "=== node log"
	cat "$state/node.log" 2>/dev/null || true
	echo "=== status"
	cat "$state/status.json" 2>/dev/null || true
	;;
*)
	echo "usage: gha-mesh.sh start|check|wait-done|stop ..." >&2
	exit 2
	;;
esac
