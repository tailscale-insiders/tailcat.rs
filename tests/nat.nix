# A NixOS VM test of tailcat and tailcat-device across simulated NATs.
#
#               "internet" (vlan 1, 203.0.113.0/24)
#      relay .10          router-a .2           router-b .3
#      DERP + STUN            |                      |
#      derpmap (HTTP)    LAN A (vlan 2)         LAN B (vlan 3)
#                       192.168.1.0/24         192.168.2.0/24
#                     alice .10, carol .11        bob .10
#
# The routers NAT their LANs onto the internet, and `nat-mode` switches
# how at runtime: an endpoint-independent mapping (the common home
# router), an endpoint-dependent one (a "hard", symmetric NAT), UDP
# blocked entirely, a fresh port range (the NAT forgetting its
# mappings, like a router reboot), a firewall letting everything in, or
# a DMZ host that unsolicited packets are forwarded to. Nothing routes
# between the LANs except through the NATs, so a direct path exists only
# if NAT traversal punches one.
#
#   nix build .#checks.x86_64-linux.nat -L
#   nix run .#checks.x86_64-linux.nat.driverInteractive   # to poke at it
{ pkgs, tailcat }:
let
  inherit (pkgs) lib;

  relayIp = "203.0.113.10";
  derpmapUrl = "http://${relayIp}/derpmap.json";

  # nat-mode <easy|hard|block-udp|rebind|permissive|dmz HOST>: replaces
  # the router's NAT rules and forgets every existing mapping.
  natMode = pkgs.writeShellApplication {
    name = "nat-mode";
    runtimeInputs = [ pkgs.nftables pkgs.conntrack-tools ];
    text = ''
      masq="oifname \"eth1\" masquerade" drop_udp="" dnat="" wan_in="iifname \"eth1\" drop"
      case "''${1:?usage: nat-mode <easy|hard|block-udp|rebind|permissive|dmz HOST>}" in
        # Linux keeps the source port when it can: one public port per
        # private socket, whatever the destination.
        easy) ;;
        # A new random public port for every destination.
        hard) masq="oifname \"eth1\" masquerade fully-random" ;;
        block-udp) drop_udp="meta l4proto udp drop" ;;
        # Mappings from a different port range than before.
        rebind) masq="oifname \"eth1\" meta l4proto { tcp, udp } masquerade to :40000-40999" ;;
        # An easy NAT whose firewall lets in what the LAN didn't ask for.
        # That isn't endpoint-independent filtering: Linux has no mapping
        # to forward an unsolicited packet along, so it delivers it to
        # the router itself, and conntrack keeps its 4-tuple. A
        # hole-punching ping that arrives before the LAN host's own ping
        # has gone out then pushes that host's mapping toward the pinger
        # to another port, one the pinger never learns: an easy NAT
        # turned hard, for whichever peer pings first.
        permissive) wan_in="" ;;
        # Endpoint-independent filtering for one LAN host (a router's
        # "DMZ host"): unsolicited UDP from the internet goes to HOST, at
        # the port it was sent to.
        dmz) dnat="iifname \"eth1\" meta l4proto udp dnat to ''${2:?usage: nat-mode dmz HOST}" ;;
        *) echo "unknown mode $1" >&2; exit 2 ;;
      esac
      nft -f - <<EOF
      table ip tcnat
      delete table ip tcnat
      table ip tcnat {
        chain prerouting {
          type nat hook prerouting priority dstnat; policy accept;
          $dnat
        }
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
          $masq
        }
        chain forward {
          type filter hook forward priority filter; policy accept;
          $drop_udp
          # Nothing from the internet gets in unless it answers a flow
          # from the LAN, or is for the DMZ host.
          iifname "eth1" ct state established,related accept
          iifname "eth1" ct status dnat accept
          $wan_in
        }
        # Nor into the router itself (see permissive above).
        chain input {
          type filter hook input priority filter; policy accept;
          iifname "eth1" ct state established,related accept
          $wan_in
        }
      }
      EOF
      conntrack -F 2>/dev/null || true
      echo "NAT mode: $*"
    '';
  };

  # Addresses are set by hand, IPv4 only, and the QEMU user-mode NIC
  # (eth0) is left unconfigured (the test checks it stays down), so the
  # only paths between machines are the ones drawn above. It can't be
  # removed: the vlan NICs' renaming to eth1, eth2 relies on it holding
  # eth0.
  iface = address: {
    ipv4.addresses = lib.mkForce [{ inherit address; prefixLength = 24; }];
    ipv6.addresses = lib.mkForce [ ];
  };
  base = {
    networking.useDHCP = false;
  };

  router = lanVlan: wan: lan: {
    imports = [ base ];
    virtualisation.vlans = [ 1 lanVlan ]; # eth1 is the WAN, eth2 the LAN
    networking.interfaces.eth1 = iface wan;
    networking.interfaces.eth2 = iface lan;
    networking.firewall.enable = false;
    networking.nftables.enable = true;
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
    environment.systemPackages = [ natMode pkgs.conntrack-tools ];
    systemd.services.nat-mode = {
      wantedBy = [ "multi-user.target" ];
      after = [ "nftables.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${lib.getExe natMode} easy";
      };
    };
  };

  host = lanVlan: address: gateway: {
    imports = [ base ];
    virtualisation.vlans = [ lanVlan ];
    virtualisation.cores = 2;
    networking.interfaces.eth1 = iface address;
    networking.defaultGateway = { address = gateway; interface = "eth1"; };
    # The host firewall stays on, as on a real machine: inbound UDP gets
    # through only as the answer to a ping the host sent itself.
    networking.firewall.trustedInterfaces = [ "tcd0" ];
    environment.systemPackages = [ tailcat pkgs.curl pkgs.jq ];
  };
in
pkgs.testers.runNixOSTest {
  name = "tailcat-nat";

  nodes = {
    relay = {
      imports = [ base ];
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1 = iface relayIp;
      networking.firewall.allowedTCPPorts = [ 80 443 ];
      networking.firewall.allowedUDPPorts = [ 3478 ];
      environment.systemPackages = [ tailcat ];
      # A DERP relay and STUN server, and a DERP map naming it as region 1.
      systemd.services.derp = {
        wantedBy = [ "multi-user.target" ];
        path = [ tailcat pkgs.jq ];
        serviceConfig.StateDirectory = "derp";
        script = ''
          cd /var/lib/derp
          rm -f region.json
          mkdir -p www
          tailcat dev-derp --derp 0.0.0.0:443 --stun 0.0.0.0:3478 \
            --advertise ${relayIp} --region-file region.json >/dev/null &
          while [ ! -s region.json ]; do sleep 0.1; done
          jq '{Regions: {"1": .}}' region.json >www/derpmap.json.new
          mv www/derpmap.json.new www/derpmap.json
          wait
        '';
      };
      systemd.services.derpmap-http = {
        wantedBy = [ "multi-user.target" ];
        after = [ "derp.service" ];
        serviceConfig.ExecStart = "${lib.getExe pkgs.python3} -m http.server 80 --directory /var/lib/derp/www";
      };
    };

    router_a = router 2 "203.0.113.2" "192.168.1.1";
    router_b = router 3 "203.0.113.3" "192.168.2.1";
    alice = host 2 "192.168.1.10" "192.168.1.1";
    carol = host 2 "192.168.1.11" "192.168.1.1";
    bob = host 3 "192.168.2.10" "192.168.2.1";
  };

  testScript = ''
    import itertools
    import json
    import re
    import shlex
    import time
    from datetime import timedelta

    RUST = "${tailcat}/bin/tailcat"
    GO = "${pkgs.tailcat}/bin/tailcat"
    DEVICE = "${tailcat}/bin/tailcat-device"
    # What every tailcat runs with (Go's os/user needs USER without cgo).
    ENV = {"HOME": "/root", "USER": "root", "PATH": "/run/current-system/sw/bin", "TAILCAT_DERPMAP_URL": "${derpmapUrl}", "RUST_LOG": "tailcat=info"}
    ENV_PREFIX = "env " + " ".join(f"{k}={v}" for k, v in ENV.items())
    hosts = [alice, carol, bob]
    units = itertools.count()


    def nat(router, mode):
        router.succeed(f"nat-mode {mode}")


    def run(machine, *argv, timeout=60):
        return machine.succeed(f"{ENV_PREFIX} timeout {timeout} {shlex.join(argv)}")


    class Server:
        """A tailcat server running as a transient systemd unit."""

        def __init__(self, machine, *argv, impl=RUST):
            self.machine = machine
            self.unit = f"tc-{next(units)}"
            addr_file = f"/tmp/{self.unit}.addr"
            self.status_file = f"/tmp/{self.unit}.status.json"
            env = dict(ENV, TAILCAT_ADDR_FILE=addr_file, TAILCAT_STATUS_FILE=self.status_file)
            setenv = " ".join(f"--setenv={k}={v}" for k, v in env.items())
            machine.succeed(f"systemd-run --unit={self.unit} {setenv} {shlex.join([impl, *argv])}")
            try:
                machine.wait_for_file(addr_file, timeout=timedelta(seconds=60))
            except Exception:
                machine.log(self.log())
                raise
            self.addr = machine.succeed(f"cat {addr_file}").strip()

        def log(self):
            return self.machine.succeed(f"journalctl -o cat -u {self.unit}")

        def via(self):
            """How the server's status file says its busiest peer is reached."""
            rc, out = self.machine.execute(f"cat {self.status_file}")
            peers = json.loads(out)["peers"] if rc == 0 else []
            if not peers:
                return None
            p = max(peers, key=lambda p: p["rx_bytes"])
            return f"Direct({p['direct']})" if p["direct"] else "Derp"

        def wait_via(self, pattern, timeout=60):
            def check(_):
                via = self.via()
                self.machine.log(f"{self.unit}: peer via {via}")
                return via is not None and re.fullmatch(pattern, via) is not None

            try:
                retry(check, timeout=timedelta(seconds=timeout))
            except Exception:
                dump_nat()
                raise

        def stop(self):
            self.machine.succeed(f"systemctl stop {self.unit} || true")


    def ping(client, server, *flags, impl=RUST, timeout=60):
        return run(client, impl, "ping", *flags, server.addr, timeout=timeout)


    def dump_nat():
        for r in (router_a, router_b):
            r.log(r.execute("conntrack -L -p udp 2>&1")[1])


    def ping_direct(client, server, impl=RUST, timeout=30):
        """Pings until a direct path; returns the pong's path."""
        try:
            out = ping(client, server, "--until-direct", f"--timeout={timeout}s", impl=impl, timeout=timeout + 15)
        except Exception:
            dump_nat()
            server.machine.log(server.log())
            raise
        return out.strip().splitlines()[-1].split(" via ")[-1]


    def no_direct(client, server, timeout=20):
        client.fail(f"{ENV_PREFIX} timeout {timeout + 15} {RUST} ping --until-direct --timeout={timeout}s {server.addr}")


    def shout(client, server, impl=RUST):
        """A round trip through a server running `serve exec -- tr a-z A-Z`."""
        out = client.succeed(f"echo meow | {ENV_PREFIX} timeout 60 {impl} {server.addr} 7")
        assert out.strip() == "MEOW", f"exec round trip: got {out!r}"


    def start_transfer(client, server, seconds):
        """Starts a slow upload to a `sha256sum` exec server, lasting about `seconds`."""
        client.succeed("rm -f /tmp/sent /tmp/got")
        script = (
            f"for i in $(seq {seconds * 4}); do head -c 16384 /dev/urandom; sleep 0.25; done"
            f" | tee /tmp/sent | {RUST} {server.addr} 7 >/tmp/got"
        )
        unit = f"xfer-{next(units)}"
        setenv = " ".join(f"--setenv={k}={v}" for k, v in ENV.items())
        client.succeed(f"systemd-run --unit={unit} {setenv} sh -c {shlex.quote(script)}")


    def finish_transfer(client, timeout=120):
        client.wait_until_succeeds("test -s /tmp/got", timeout=timedelta(seconds=timeout))
        want = client.succeed("sha256sum </tmp/sent").split()[0]
        got = client.succeed("cat /tmp/got").split()[0]
        size = int(client.succeed("stat -c %s /tmp/sent"))
        assert got == want, f"transfer corrupted: sent {want}, server hashed {got}"
        client.log(f"{size} bytes arrived intact")


    start_all()
    relay.wait_for_unit("derpmap-http.service")
    relay.wait_for_open_port(443)
    relay.wait_for_open_port(80)
    for r in (router_a, router_b):
        r.wait_for_unit("nat-mode.service")
    for m in machines:
        m.fail("ip -4 addr show dev eth0 | grep -q inet")
    for h in hosts:
        h.wait_for_unit("multi-user.target")
        h.wait_until_succeeds("curl -sf ${derpmapUrl} | jq -e '.Regions[\"1\"]'", timeout=timedelta(seconds=60))

    # The internet can't reach into a LAN, and the LANs can't reach each other.
    relay.fail("ping -c 1 -W 1 192.168.1.10")
    alice.fail("ping -c 1 -W 1 192.168.2.10")
    alice.succeed("ping -c 1 -W 1 ${relayIp}")

    with subtest("same LAN: alice and carol talk directly over the LAN"):
        s = Server(carol, "serve", "exec", "--", "tr", "a-z", "A-Z")
        via = ping_direct(alice, s)
        assert via.startswith("192.168.1.11:"), f"expected the LAN path, got {via}"
        shout(alice, s)
        s.wait_via(r"Direct\(192\.168\.1\.10:\d+\)")
        s.stop()

    with subtest("easy NATs on both sides: hole punching finds a direct path"):
        s = Server(bob, "serve", "perf", "exec", "--", "tr", "a-z", "A-Z")
        via = ping_direct(alice, s)
        assert via.startswith("203.0.113.3:"), f"expected bob's router's public address, got {via}"
        shout(alice, s)
        s.wait_via(r"Direct\(203\.0\.113\.2:\d+\)")
        # perf refuses to run relayed, so this passing means a direct path.
        out = run(alice, RUST, "perf", "--time=3s", s.addr)
        alice.log(out)
        out = run(alice, RUST, "perf", "--udp", "--time=2s", s.addr)
        assert " 0 lost" in out, out
        s.stop()

    with subtest("hard NATs on both sides: traffic is relayed through DERP"):
        nat(router_a, "hard")
        nat(router_b, "hard")
        s = Server(bob, "serve", "perf", "exec", "--", "tr", "a-z", "A-Z")
        no_direct(alice, s)
        assert "via DERP(" in ping(alice, s)
        shout(alice, s)
        assert s.via() == "Derp", s.via()
        # perf only runs relayed when told to.
        out = alice.fail(f"{ENV_PREFIX} timeout 60 {RUST} perf --time=2s --timeout=5s {s.addr} 2>&1")
        assert "refusing to run a throughput test through a DERP relay" in out, out
        run(alice, RUST, "perf", "--via-derp", "--time=2s", "--timeout=5s", s.addr)
        s.stop()

    with subtest("a hard NAT on one side: traffic still flows"):
        nat(router_a, "hard")
        nat(router_b, "easy")
        s = Server(bob, "serve", "exec", "--", "tr", "a-z", "A-Z")
        shout(alice, s)
        rc, out = alice.execute(f"{ENV_PREFIX} timeout 40 {RUST} ping --until-direct --timeout=25s {s.addr}")
        alice.log(f"hard NAT behind alice, easy NAT behind bob: ping exit {rc}: {out.strip()}")
        s.stop()

    with subtest("a router letting in unsolicited packets is hard to the peer that pings it first"):
        nat(router_a, "easy")
        nat(router_b, "permissive")
        s = Server(bob, "serve", "exec", "--", "tr", "a-z", "A-Z")
        shout(alice, s)
        # The server's CallMeMaybe reaches alice before the meowed ack,
        # so alice usually pings bob before bob (who learns her endpoints
        # only from her CallMeMaybe, after the ack) pings her. A Go server
        # sends its CallMeMaybe later, from a goroutine, so with Go on
        # both sides bob's ping usually wins the race and the path is
        # found; with either side Rust, alice's usually wins. With both
        # routers permissive, whoever pings first loses, in Go too. It's
        # a race all the same, so either outcome passes; staying on DERP
        # must come from the remapping below.
        rc, out = alice.execute(f"{ENV_PREFIX} timeout 35 {RUST} ping --until-direct --timeout=20s {s.addr} 2>&1")
        alice.log(f"permissive router behind bob: ping --until-direct exit {rc}: {out.strip()}")
        if rc != 0:
            # alice's first ping to bob landed on bob's router and stayed
            # in its conntrack table, so bob's flow to alice left from
            # another port than the one STUN saw, and alice's router
            # dropped it.
            flows = router_b.succeed("conntrack -L -p udp -s 192.168.2.10 -d 203.0.113.2 2>/dev/null")
            router_b.log(flows)
            ports = re.findall(r"sport=(\d+) dport=\d+ .*src=203\.0\.113\.2 dst=203\.0\.113\.3 sport=\d+ dport=(\d+)", flows)
            assert ports and all(a != b for a, b in ports), f"expected bob's flow to alice remapped: {flows}"
        s.stop()

        # alice's own permissive router does no harm: her first ping
        # opened her mapping toward bob before his arrived.
        nat(router_a, "permissive")
        nat(router_b, "easy")
        s = Server(bob, "serve", "exec", "--", "tr", "a-z", "A-Z")
        via = ping_direct(alice, s)
        assert via.startswith("203.0.113.3:"), via
        s.stop()

    with subtest("a DMZ host, with endpoint-independent filtering: hole punching finds a direct path"):
        nat(router_a, "easy")
        nat(router_b, "dmz 192.168.2.10")
        s = Server(bob, "serve", "exec", "--", "tr", "a-z", "A-Z")
        via = ping_direct(alice, s)
        assert via.startswith("203.0.113.3:"), via
        shout(alice, s)
        s.stop()

    with subtest("UDP blocked at alice's router: DERP over TCP carries everything"):
        nat(router_a, "block-udp")
        nat(router_b, "easy")
        s = Server(bob, "serve", "exec", "--", "tr", "a-z", "A-Z")
        shout(alice, s)
        assert "via DERP(" in ping(alice, s)
        no_direct(alice, s, timeout=15)
        s.stop()

    with subtest("a direct path that breaks mid-transfer falls back to DERP, then recovers"):
        nat(router_a, "easy")
        nat(router_b, "easy")
        s = Server(bob, "serve", "exec", "--", "sha256sum")
        start_transfer(alice, s, seconds=75)
        s.wait_via(r"Direct\(203\.0\.113\.2:\d+\)", timeout=30)
        nat(router_a, "block-udp")
        s.wait_via("Derp", timeout=30)
        nat(router_a, "easy")
        s.wait_via(r"Direct\(203\.0\.113\.2:\d+\)", timeout=60)
        finish_transfer(alice)
        s.stop()

    with subtest("alice's NAT forgets its mappings mid-transfer and picks new ports"):
        nat(router_a, "easy")
        nat(router_b, "easy")
        s = Server(bob, "serve", "exec", "--", "sha256sum")
        start_transfer(alice, s, seconds=75)
        s.wait_via(r"Direct\(203\.0\.113\.2:\d+\)", timeout=30)
        nat(router_a, "rebind")
        # The new path is from the new port range.
        s.wait_via(r"Direct\(203\.0\.113\.2:40\d\d\d\)", timeout=60)
        finish_transfer(alice)
        s.stop()

    with subtest("relay outage: direct paths survive it, and servers reconnect after"):
        nat(router_a, "easy")
        nat(router_b, "easy")
        s = Server(bob, "serve", "exec", "--", "sha256sum")
        start_transfer(alice, s, seconds=30)
        s.wait_via(r"Direct\(203\.0\.113\.2:\d+\)", timeout=30)
        relay.systemctl("stop derp.service")
        finish_transfer(alice)
        relay.systemctl("start derp.service")
        relay.wait_for_open_port(443)
        # With hard NATs, a new client reaches the same server only through
        # the relay, which the server must have reconnected to.
        nat(router_a, "hard")
        nat(router_b, "hard")
        alice.wait_until_succeeds(
            f"echo again | {ENV_PREFIX} timeout 30 {RUST} {s.addr} 7 | grep -q .", timeout=timedelta(seconds=120)
        )
        s.stop()

    with subtest("a relay connection that silently stops carrying anything: the server redials"):
        nat(router_a, "hard")
        nat(router_b, "hard")
        s = Server(bob, "serve", "exec", "--", "tr", "a-z", "A-Z")
        shout(alice, s)
        # Bob's router drops, without a reset, everything on his relay
        # connection, as a NAT or firewall that forgot it would. Bob is
        # idle, so only his relay client's pings can tell.
        pid = bob.succeed(f"systemctl show -p MainPID --value {s.unit}").strip()
        conn = bob.succeed(f"ss -Htnp state established dst ${relayIp}:443 | grep 'pid={pid},'")
        port = conn.split()[2].rsplit(":", 1)[1]
        router_b.succeed(
            "nft add table inet blackhole"
            " && nft add chain inet blackhole drops '{ type filter hook forward priority -5; policy accept; }'"
            f" && nft add rule inet blackhole drops ip saddr 192.168.2.10 tcp sport {port} drop"
            f" && nft add rule inet blackhole drops ip daddr 192.168.2.10 tcp dport {port} drop"
        )
        start = time.monotonic()
        # Well before the 130s a read timeout alone would take.
        alice.wait_until_succeeds(
            f"echo again | {ENV_PREFIX} timeout 10 {RUST} {s.addr} 7 | grep -q AGAIN", timeout=timedelta(seconds=60)
        )
        alice.log(f"bob reachable again {time.monotonic() - start:.1f}s after his relay connection went silent")
        router_b.succeed("nft delete table inet blackhole")
        s.stop()

    with subtest("Go and Rust tailcat find direct paths to each other across NATs"):
        nat(router_a, "easy")
        nat(router_b, "easy")
        go_server = Server(bob, "serve", "1", impl=GO)
        via = ping_direct(alice, go_server)
        assert via.startswith("203.0.113.3:"), via
        go_server.stop()

        rust_server = Server(bob, "serve", "exec", "--", "tr", "a-z", "A-Z")
        via = ping_direct(alice, rust_server, impl=GO)
        assert via.startswith("203.0.113.3:"), via
        shout(alice, rust_server, impl=GO)
        rust_server.stop()

    with subtest("tailcat-device: a mesh across both NATs"):
        nat(router_a, "easy")
        nat(router_b, "easy")
        region = relay.succeed("cat /var/lib/derp/region.json")
        records = {}
        for i, h in enumerate(hosts):
            h.succeed(f"mkdir -p /root/mesh/records && echo {shlex.quote(region)} >/root/mesh/region.json")
            h.succeed(
                f"cd /root/mesh && {DEVICE} init --index {i} --region-file region.json"
                f" --key key --out records/node-1-{i}.json"
            )
            records[i] = h.succeed(f"cat /root/mesh/records/node-1-{i}.json")
        for h in hosts:
            for i, rec in records.items():
                h.succeed(f"echo {shlex.quote(rec)} >/root/mesh/records/node-1-{i}.json")
            h.succeed(
                f"systemd-run --unit=mesh {DEVICE} up --key /root/mesh/key --records /root/mesh/records"
                " --nodes 3 --wait 60s --tun tcd0 --status-file /root/mesh/status.json"
                " --ready-file /root/mesh/ready --status-interval 2s"
            )
        for h in hosts:
            h.wait_for_file("/root/mesh/ready", timeout=timedelta(seconds=90))
        for i, h in enumerate(hosts):
            for j in range(len(hosts)):
                if i != j:
                    h.succeed(f"ping -c 3 -i 0.2 -W 2 100.64.1.{j}")
        # Every pair finds a direct path: over the LAN, or punched through the NATs.
        for h in hosts:
            h.wait_until_succeeds(
                "jq -e 'all(.[]; .direct != null)' /root/mesh/status.json", timeout=timedelta(seconds=60)
            )
            h.log(h.succeed("jq -c '.[] | {index, direct}' /root/mesh/status.json"))

        # A hard NAT in front of bob: his peers fall back to DERP and stay reachable.
        nat(router_b, "hard")
        for i, h in enumerate(hosts):
            for j in range(len(hosts)):
                if i != j:
                    h.wait_until_succeeds(f"ping -c 1 -W 2 100.64.1.{j}", timeout=timedelta(seconds=60))
  '';
}
