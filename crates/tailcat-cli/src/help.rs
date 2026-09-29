//! Long help texts, ported from the Go implementation.

/// The project README, printed by `tailcat readme` so that people (and
/// agents) with only the binary can learn to use it.
pub const README: &str = include_str!("../../../README.md");

pub const ROOT: &str = r#"Server mode, accept one connection (any port), write to stdout:

	tailcat

Server mode, given ports (see "tailcat serve --help" for more):

	tailcat serve 22,80,443,8000-8999

Server mode, all ports:

	tailcat serve all

Server mode, certain ports and auth-free SSH:

	tailcat serve 80,no-auth-ssh

Server mode, SSH requiring an authorized public key:

	tailcat serve --ssh-authorized-keys=alice@github ssh

Server mode, exit node (clients can reach the server's whole network):

	tailcat serve exit-node

Server mode, receive files into a directory (a write-only drop box
served to "tailcat cp"; see also serve's files service):

	tailcat recv ~/inbox

Client mode, to default port 1 for stdin/stdout pipe:

	echo hello | tailcat <tc-addr>

Client mode to an explicit port:

	echo "GET / HTTP/1.1..." | tailcat <tc-addr> 80

Anywhere a <tc-addr> argument is accepted, a DNS name whose
"tailcat=" TXT record contains one may be used instead:

	tailcat ssh example.com

But beware: a tailcat address is normally a secret, and a DNS TXT
record is public, so a server named in DNS must authenticate its
clients some other way: --allow at the tunnel layer, or the ssh
service's --ssh-authorized-keys. Never publish a no-auth-ssh server's
address; that gives a shell to anyone who reads the TXT record.

Client mode, ping. Each pong reports whether it arrived via a DERP
relay or a direct path. --until-direct keeps pinging (bounded by
--timeout, default 10s) until a direct path works:

	tailcat ping <tc-addr>
	tailcat ping --until-direct <tc-addr>

Client mode, ssh:

	tailcat ssh [user@]<tc-addr>
	tailcat ssh [user@]<tc-addr> <command> [args...]

Client mode, ssh to specific IP:port via the tailcat address's exit node:

	tailcat ssh -p 10.0.0.1:22 <tc-addr>

Client mode, copy files to or from a server:

	tailcat cp foo.txt <tc-addr>:
	tailcat cp -r <tc-addr>:dir ./dir

Client mode, list the files a server offers:

	tailcat ls [-l] <tc-addr>[:path]

Client mode, forward local TCP ports to a tailcat server:

	tailcat forward [--bind=<addr>] <tc-addr> <[local:]remote> ...

Client mode, run an ephemeral SOCKS5 proxy and pass its address as
'all_proxy' environment variable to a child process. Destination
hostnames that are themselves tailcat addresses are dialed as tailcat
servers, so the <tc-addr> argument is optional:

	tailcat socks [--listen=<addr:port>] [<tc-addr>] [<cmd> [args...]]
	tailcat socks <tc-addr> curl http://server.tailcat:8081/
	tailcat socks curl http://<tc-addr>:8081/

Parse a tailcat address and print its encoded fields as JSON:

	tailcat parse <tc-addr>

Resolve a short tailcat address into a longer self-contained one with
embedded DERP server info (see also serve's --full-address flag):

	tailcat resolve <tc-addr>

Print the public key of the client key that would be used (see --key):

	tailcat printpub

Generate and save a persistent server key and print its tailcat
address. The key name "default" is magic: server mode uses it
automatically once it exists:

	tailcat genkey --key=default

Generate and save a persistent client key and print its public key,
for use in a server's --allow list. Client modes automatically use
the key named "client-default" when it exists:

	tailcat genkey --client --key=client-default

List or delete saved keys:

	tailcat genkey --list
	tailcat genkey --delete --key=<name>

Print the full documentation (the project README) with more examples:

	tailcat readme

Environment:

	TAILCAT_ADDR_FILE: in server mode, write the tailcat address to the
	given file path or, with a "tcp:" prefix, send it to that TCP
	address.

	TAILCAT_DERPMAP_URL: the default value of the --derpmap-url flag.

	TS_DEBUG_TAILCAT_LOCAL_DERP: in server mode, run a local DERP relay
	(with a self-signed certificate) and embed it in the address; for
	tests and offline use."#;

pub const SERVE: &str = r#"Run a tailcat server, printing its tailcat address for clients to
connect to. Running tailcat with no arguments is the same as running
"tailcat serve" with no arguments.

The arguments are port numbers, port ranges, port mappings, and
service names, either as separate arguments or comma-separated.
Ports are proxied to the same port on localhost. A port mapping
"port:target" proxies a port elsewhere instead: to a different port
on localhost ("8080:80") or to a host:port on the server's network
("5555:10.2.200.213:5555", or "5555:[fd7a::1]:5555" for IPv6).
Service names are:

	all          serve all ports
	exit-node    run an exit node for all addresses
	ssh          SSH server requiring a public key listed by
	             --ssh-authorized-keys
	no-auth-ssh  auth-free SSH server (the tunnel provides identity;
	             the served process gets the peer's node key in
	             $TAILCAT_PEER_KEY)
	files        file server for SFTP clients like scp and sftp,
	             rooted in the --files directory (default: the
	             current directory, read-only)
	exec         run the command given after "--" for each
	             connection to any port not otherwise served, with
	             the connection as the command's stdin and stdout
	             (like inetd); its stderr is the server's
	perf         accept throughput and latency tests from
	             "tailcat perf", on TCP and UDP port 5201

With no arguments, the server accepts a single connection on any
port, writes it to stdout, and exits.

A command after "--" implies the exec service, unless the ssh or
no-auth-ssh service is also given: then SSH sessions run only that
command in place of a shell (like OpenSSH's ForceCommand), with a
PTY if the client asks for one. Such a server offers no shell, no
client-chosen command, and no SFTP. The client's requested command,
if any, is passed to the command in $SSH_ORIGINAL_COMMAND.

The command in either form gets the peer's node key in
$TAILCAT_PEER_KEY (in --allow's format), and its tailcat IP:port in
$TAILCAT_REMOTE_ADDR.

Examples:

	tailcat serve
	tailcat serve 22,80,443,8000-8999
	tailcat serve all
	tailcat serve 5555:10.2.200.213:5555
	tailcat serve 80,no-auth-ssh
	tailcat serve --ssh-authorized-keys=alice@github ssh
	tailcat serve exit-node
	tailcat serve files
	tailcat serve exec -- /usr/bin/fortune
	tailcat serve --ssh-authorized-keys=alice@github ssh -- ./deploy.sh
	tailcat serve --files=/pub:rw files
	tailcat serve --key=default --allow=nodekey:... 22

Environment:

	TAILCAT_ADDR_FILE: write the tailcat address to the given file
	path or, with a "tcp:" prefix, send it to that TCP address."#;

pub const RECV: &str = r#"Run a server that receives files into the given directory (default:
the current directory), printing the tailcat address senders use. It's
shorthand for a write-only file server:

	tailcat serve --files=<dir>:wo files

The sender copies files in with:

	tailcat cp foo.txt <tc-addr>:

Write-only means senders can't make directories, list or read the
directory, touch existing files, or learn whether a requested filename
already exists. Each upload is saved under a new name containing a UTC
timestamp and random suffix. To accept directory trees instead, use
the less-private --accept-dirs flag."#;

pub const PING: &str = r#"Examples:

	tailcat ping <tc-addr>
	tailcat ping --until-direct <tc-addr>
	tailcat ping --until-direct --timeout=30s <tc-addr>

Each pong reports whether it arrived via a DERP relay or a direct
path:

	pong in 42.1ms via DERP(sfo)
	pong in 1.2ms via 203.0.113.7:41641

The --until-direct flag keeps pinging (bounded by --timeout) until a
direct path works, exiting non-zero if none does, so scripts can use
it to verify NAT traversal."#;

pub const SOCKS: &str = r#"Examples:

	tailcat socks
	tailcat socks <tc-addr>
	tailcat socks --listen=1080 <tc-addr>
	tailcat socks curl http://<tc-addr>:8081/
	tailcat socks <tc-addr> curl http://server.tailcat:8081/
	tailcat socks <tc-addr> curl https://example.com/

With a <cmd>, the SOCKS5 proxy runs for the life of that command,
which is started with the proxy's address in its all_proxy
environment variable. With no <cmd>, the proxy runs by itself and
prints its address.

A hostname that is itself a tailcat address names a tailcat server to
dial. The magic hostname "server.tailcat" means the server named by
the <tc-addr> argument. Any other hostname or IP is reached through
the <tc-addr> server acting as an exit node, which works only if the
server runs with --serve=exit-node."#;

#[cfg(feature = "ssh")]
pub const SSH: &str = r#"Examples:

	tailcat ssh <tc-addr>
	tailcat ssh root@<tc-addr>
	tailcat ssh <tc-addr> uptime
	tailcat ssh example.com
	tailcat ssh -p 2222 <tc-addr>
	tailcat ssh -p 10.0.0.1:22 <tc-addr>

This execs the system ssh client with a ProxyCommand that runs
tailcat itself. A DNS-named destination is first probed the way a
stranger would connect (a fresh client key and no SSH credentials);
if the server lets that stranger log in, tailcat refuses to connect.
--skip-dns-safety-check skips the probe."#;

#[cfg(feature = "ssh")]
pub const CP: &str = r#"Remote paths are written <tc-addr>:[path], like scp's host:path.
Paths are relative to the server's served directory ("tailcat serve
files"), or to the remote home directory for a full SSH server.

	tailcat cp foo.txt <tc-addr>:
	tailcat cp <tc-addr>:foo.txt copy.txt
	tailcat cp -r ./photos <tc-addr>:photos

The copying is done by the system scp, with the connection routed
through tailcat."#;

#[cfg(feature = "ssh")]
pub const LS: &str = r#"List the files a tailcat server offers, speaking SFTP directly (no ssh
or sftp binary is involved):

	tailcat ls <tc-addr>
	tailcat ls -l <tc-addr>:photos"#;

pub const FORWARD: &str = r#"Listen on local TCP ports and forward connections to a tailcat server.

A mapping with one port uses the same local and remote port. A mapping
with local:remote uses different local and remote ports. A local port
of 0 asks the operating system for a free port. A mapping with a
remote IP address and port requires the server to be an exit node:

	tailcat forward <tc-addr> 8080
	tailcat forward --bind=0.0.0.0 <tc-addr> 18080:8080
	tailcat forward <tc-addr> 0:8080
	tailcat forward <tc-addr> 13306:192.168.1.10:3306"#;

pub const GENKEY: &str = r#"Examples:

	tailcat genkey --key=default
	tailcat genkey --client --key=client-default
	tailcat genkey --key=default --fixed-region
	tailcat genkey --key=default --region=nyc
	tailcat genkey --key=default --region=derp.example.com
	tailcat genkey --region=list
	tailcat genkey --list
	tailcat genkey --delete --key=<name>

By default genkey generates and saves a server key and prints its
tailcat address. The key name "default" is magic: server mode loads it
automatically once it exists. With --client, genkey generates a client
identity key and prints its public key, for use in a server's --allow
list; client modes automatically load "client-default"."#;
