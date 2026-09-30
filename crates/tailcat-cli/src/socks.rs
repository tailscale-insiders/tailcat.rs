//! `tailcat socks`: a SOCKS5 proxy (CONNECT and UDP ASSOCIATE) that
//! dials through tailcat servers.
//!
//! Destinations route by hostname: a hostname that is itself a tailcat
//! address names the server to dial; `server.tailcat` (or an empty host)
//! means the server from the command line; anything else is reached
//! through that server as an exit node.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tailcat::{Addr, Client, NodePrivate};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::Global;
use crate::args::ListenArg;

/// Where a SOCKS destination should be dialed.
#[derive(Debug, PartialEq)]
pub enum Target {
    /// A port on the command line's server.
    Server(u16),
    /// A port on the server named by a tailcat address hostname.
    Addr(Addr, u16),
    /// An address reached through the command line's server as an exit node.
    Via(SocketAddr),
}

/// Classifies a SOCKS destination host and port, resolving ordinary
/// hostnames locally (preferring IPv4, which rides the NAT64 mapping).
pub async fn classify(host: &str, port: u16) -> Result<Target> {
    if host.is_empty() || host == "server.tailcat" {
        return Ok(Target::Server(port));
    }
    if host.starts_with("tc") && !host.contains('.') {
        let a = Addr::new(host);
        if a.parse().is_ok() {
            return Ok(Target::Addr(a, port));
        }
    }
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let mut addrs = tokio::net::lookup_host((host, port)).await?;
            let first = addrs.next().ok_or_else(|| anyhow!("no addresses found for {host:?}"))?;
            std::iter::once(first).chain(addrs).find(SocketAddr::is_ipv4).unwrap_or(first).ip()
        }
    };
    Ok(Target::Via(SocketAddr::new(ip.to_canonical(), port)))
}

/// Dials tailcat servers on behalf of the proxy.
struct Dialer {
    g: Global,
    key: NodePrivate,
    default: Option<Client>,
    clients: Mutex<HashMap<Addr, Client>>,
}

impl Dialer {
    /// The client that dials `t`.
    fn client(&self, t: &Target) -> Result<Client> {
        match t {
            Target::Addr(a, _) => {
                let mut clients = self.clients.lock().unwrap();
                let c = clients
                    .entry(a.clone())
                    .or_insert_with(|| crate::client::new_client(&self.g, a.clone(), self.key.clone()));
                Ok(c.clone())
            }
            _ => self.default.clone().ok_or_else(|| {
                anyhow!(
                    "no tailcat address argument was given to \"tailcat socks\"; only tailcat address hostnames can be dialed"
                )
            }),
        }
    }

    async fn dial_tcp(&self, t: &Target) -> Result<tailcat::TcpStream> {
        let c = self.client(t)?;
        Ok(match *t {
            Target::Server(p) | Target::Addr(_, p) => c.dial_tcp_port(p).await?,
            Target::Via(dst) => c.dial_tcp(dst).await?,
        })
    }

    async fn dial_udp(&self, t: &Target) -> Result<tailcat::UdpConn> {
        let c = self.client(t)?;
        Ok(match *t {
            Target::Server(p) | Target::Addr(_, p) => c.dial_udp_port(p).await?,
            Target::Via(dst) => c.dial_udp(dst).await?,
        })
    }
}

pub async fn socks_mode(g: &Global, listen: &ListenArg, mut args: Vec<String>) -> Result<ExitCode> {
    // The address argument is optional: tailcat address hostnames are
    // dialed directly, so a fixed server is only needed for
    // server.tailcat and exit-node destinations.
    let addr = match args.first() {
        Some(first) if Addr::new(first.as_str()).parse().is_ok() => Some(Addr::new(args.remove(0))),
        Some(first) if first.contains('.') && crate::serve::which(first).is_none() => {
            Some(crate::addrarg::tailcat_addr_arg(&args.remove(0)).await?)
        }
        _ => None,
    };
    let key = crate::keys::client_key(g)?;
    let default = addr.map(|a| crate::client::new_client(g, a, key.clone()));
    if let Some(c) = &default {
        let pi = c.ping().await.map_err(|e| anyhow!("tailcat Ping: {e}"))?;
        tracing::debug!("got ping: {pi:?}");
    }
    let dialer = Arc::new(Dialer { g: g.clone(), key, default, clients: Mutex::default() });
    let ln = TcpListener::bind(listen.to_string()).await?;
    let socks_addr = format!("socks5h://{}", ln.local_addr()?);
    let serve = tokio::spawn(serve(ln, dialer));
    let Some((cmd, cmd_args)) = args.split_first() else {
        eprintln!("SOCKS running at {socks_addr}");
        serve.await?;
        bail!("SOCKS5 server exited");
    };
    tracing::debug!("SOCKS running at {socks_addr}");
    let status = tokio::process::Command::new(cmd).args(cmd_args).env("all_proxy", &socks_addr).status().await?;
    Ok(ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8))
}

async fn serve(ln: TcpListener, dialer: Arc<Dialer>) {
    loop {
        let (c, peer) = crate::util::accept(|| ln.accept()).await;
        let d = dialer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(c, d).await {
                tracing::debug!("socks5: {peer}: {e}");
            }
        });
    }
}

/// How long to wait for a TCP connection or UDP flow to open, including
/// resolving its destination. It's also WireGuard's handshake retransmit
/// interval, so be generous.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

const REP_SUCCESS: u8 = 0;
const REP_HOST_UNREACHABLE: u8 = 4;
const REP_COMMAND_NOT_SUPPORTED: u8 = 7;
const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 8;

async fn reply(c: &mut TcpStream, rep: u8, bound: SocketAddr) -> std::io::Result<()> {
    let mut b = vec![5, rep, 0];
    put_addr(&mut b, &bound.ip().to_string(), bound.port());
    c.write_all(&b).await
}

/// Appends a SOCKS address (ATYP, address, port): an IP address, or
/// else a domain name.
fn put_addr(b: &mut Vec<u8>, host: &str, port: u16) {
    match host.parse() {
        Ok(IpAddr::V4(v4)) => {
            b.push(1);
            b.extend(v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            b.push(4);
            b.extend(v6.octets());
        }
        Err(_) => {
            b.extend([3, host.len() as u8]);
            b.extend(host.as_bytes());
        }
    }
    b.extend(port.to_be_bytes());
}

/// Reads a SOCKS address (ATYP, address, port) from `r`.
async fn read_addr<R: AsyncRead + Unpin>(r: &mut R) -> Result<(String, u16)> {
    let mut b = vec![r.read_u8().await?];
    let len = match b[0] {
        1 => 4,
        3 => {
            b.push(r.read_u8().await?);
            b[1] as usize
        }
        4 => 16,
        atyp => bail!("unsupported address type {atyp}"),
    };
    let start = b.len();
    b.resize(start + len + 2, 0);
    r.read_exact(&mut b[start..]).await?;
    let (addr, _) = parse_addr(&b).ok_or_else(|| anyhow!("bad hostname"))?;
    Ok(addr)
}

/// Parses a SOCKS address, returning it and the rest of the input.
fn parse_addr(b: &[u8]) -> Option<((String, u16), &[u8])> {
    let (host, rest) = match *b.first()? {
        1 => (IpAddr::from(<[u8; 4]>::try_from(b.get(1..5)?).ok()?).to_string(), &b[5..]),
        3 => {
            let n = *b.get(1)? as usize;
            (String::from_utf8(b.get(2..2 + n)?.to_vec()).ok()?, &b[2 + n..])
        }
        4 => (IpAddr::from(<[u8; 16]>::try_from(b.get(1..17)?).ok()?).to_string(), &b[17..]),
        _ => return None,
    };
    let (port, rest) = rest.split_first_chunk()?;
    Some(((host, u16::from_be_bytes(*port)), rest))
}

async fn handle(mut c: TcpStream, d: Arc<Dialer>) -> Result<()> {
    // Greeting: we offer "no authentication".
    if c.read_u8().await? != 5 {
        bail!("not SOCKS5");
    }
    let n = c.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    c.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        c.write_all(&[5, 0xff]).await?;
        bail!("no acceptable auth method");
    }
    c.write_all(&[5, 0]).await?;

    let mut hdr = [0u8; 3];
    c.read_exact(&mut hdr).await?;
    let cmd = hdr[1];
    let zero = SocketAddr::from(([0, 0, 0, 0], 0));
    let (host, port) = match read_addr(&mut c).await {
        Ok(a) => a,
        Err(e) => {
            reply(&mut c, REP_ADDR_TYPE_NOT_SUPPORTED, zero).await?;
            return Err(e);
        }
    };
    match cmd {
        1 => {
            let dial = tokio::time::timeout(DIAL_TIMEOUT, async { d.dial_tcp(&classify(&host, port).await?).await });
            let remote = match dial.await.unwrap_or_else(|_| Err(anyhow!("dial {host}:{port}: timed out"))) {
                Ok(r) => r,
                Err(e) => {
                    reply(&mut c, REP_HOST_UNREACHABLE, zero).await?;
                    return Err(e);
                }
            };
            reply(&mut c, REP_SUCCESS, zero).await?;
            let _ = c.set_nodelay(true);
            crate::serve::proxy_and_drain(remote, c).await;
            Ok(())
        }
        3 => {
            let client = UdpClient::new(&host, port, c.peer_addr()?);
            udp_associate(c, d, client).await
        }
        _ => {
            reply(&mut c, REP_COMMAND_NOT_SUPPORTED, zero).await?;
            bail!("unsupported command {cmd}");
        }
    }
}

/// The datagrams for each destination (host, port)'s tunnel flow, which
/// queue while it opens.
type Flows = HashMap<(String, u16), mpsc::Sender<Vec<u8>>>;

/// How many datagrams a flow queues while it opens.
const FLOW_QUEUE: usize = 64;

/// The client's UDP address, where replies go, once it has sent from it.
type ClientAddr = Arc<Mutex<Option<SocketAddr>>>;

/// Where a UDP association's client sends from, which is the only source
/// the relay may take datagrams from (RFC 1928 §7): the address in its
/// request, with the control connection's IP standing in for an
/// unspecified one (or a hostname), and the first datagram's port for
/// port 0.
#[derive(Debug, PartialEq)]
struct UdpClient {
    ip: IpAddr,
    /// 0 until the first datagram, if the request gave none.
    port: u16,
}

impl UdpClient {
    fn new(host: &str, port: u16, control_peer: SocketAddr) -> UdpClient {
        let ip = match host.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
            Ok(ip) if !ip.is_unspecified() => ip,
            _ => control_peer.ip().to_canonical(),
        };
        UdpClient { ip, port }
    }

    /// Whether a datagram from `from` is the client's. The first one
    /// fixes the port, if the request didn't.
    fn admit(&mut self, from: SocketAddr) -> bool {
        if from.ip().to_canonical() != self.ip || self.port != 0 && from.port() != self.port {
            return false;
        }
        self.port = from.port();
        true
    }
}

/// Relays datagrams between the client and tunnel UDP flows for as long
/// as the control connection stays open.
async fn udp_associate(mut c: TcpStream, d: Arc<Dialer>, mut client: UdpClient) -> Result<()> {
    let local_ip = c.local_addr()?.ip();
    let sock = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    reply(&mut c, REP_SUCCESS, sock.local_addr()?).await?;
    let client_addr: ClientAddr = Arc::default();
    // Each flow's task, so they end with the association.
    let mut flow_tasks = tokio::task::JoinSet::new();
    let relay = async {
        let mut flows = Flows::new();
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
            while flow_tasks.try_join_next().is_some() {}
            // Anyone who can reach the relay can send to it; only the
            // client may use it, and have the replies.
            if !client.admit(from) {
                continue;
            }
            *client_addr.lock().unwrap() = Some(from);
            // RSV(2), FRAG(1): fragments aren't supported.
            if n < 4 || buf[2] != 0 {
                continue;
            }
            let Some((dst, payload)) = parse_addr(&buf[3..n]) else { continue };
            let tx = match flows.get(&dst) {
                Some(tx) if !tx.is_closed() => tx.clone(),
                // No flow yet, or it failed to open or closed: open one.
                // That can take a DNS lookup and a tunnel handshake; don't
                // hold up other flows meanwhile.
                _ => {
                    let (tx, rx) = mpsc::channel(FLOW_QUEUE);
                    let (d, sock, ca) = (d.clone(), sock.clone(), client_addr.clone());
                    flow_tasks.spawn(udp_flow(d, dst.clone(), rx, sock, ca));
                    flows.insert(dst, tx.clone());
                    tx
                }
            };
            // A full queue drops the datagram, as UDP may.
            let _ = tx.try_send(payload.to_vec());
        }
    };
    // The association ends when the control connection closes.
    let mut sink = [0u8; 64];
    tokio::select! {
        _ = relay => {}
        _ = async { while c.read(&mut sink).await.is_ok_and(|n| n > 0) {} } => {}
    }
    flow_tasks.shutdown().await;
    Ok(())
}

/// Opens the tunnel flow to `dst`, sends it the datagrams from `rx` in
/// order, and relays its replies to the client, wrapped with the
/// destination's address, until it closes.
async fn udp_flow(
    d: Arc<Dialer>,
    dst: (String, u16),
    mut rx: mpsc::Receiver<Vec<u8>>,
    sock: Arc<UdpSocket>,
    client_addr: ClientAddr,
) {
    let dial = tokio::time::timeout(DIAL_TIMEOUT, async { d.dial_udp(&classify(&dst.0, dst.1).await?).await });
    let f = match dial.await.unwrap_or_else(|_| Err(anyhow!("timed out"))) {
        Ok(f) => f,
        Err(e) => {
            // Dropping `rx` has the next datagram try again.
            tracing::debug!("socks5: UDP to {}: {e}", crate::util::join_host_port(&dst.0, dst.1));
            return;
        }
    };
    let send = async {
        while let Some(p) = rx.recv().await {
            let _ = f.send(&p).await;
        }
    };
    let recv = async {
        let mut b = vec![0u8; 65535];
        while let Ok(n) = f.recv(&mut b).await {
            let Some(to) = *client_addr.lock().unwrap() else { continue };
            let mut out = vec![0, 0, 0];
            put_addr(&mut out, &dst.0, dst.1);
            out.extend_from_slice(&b[..n]);
            let _ = sock.send_to(&out, to).await;
        }
    };
    // The flow closed; the next datagram opens another.
    tokio::select! {
        _ = send => {}
        _ = recv => {}
    }
}

#[cfg(test)]
mod model_tests;

#[cfg(test)]
mod tests {
    use tailcat::derp::server::DevDerp;
    use tailcat::{DerpRegion, PrivateKey, Server, UdpConn, udp_handler};
    use tokio::time::timeout;

    use super::*;

    const ADDR: &str = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu";

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    pub(super) fn global() -> Global {
        Global { key: Default::default(), verbose: false, json: false, derpmap_url: String::new() }
    }

    /// Echoes a UDP flow's datagrams back to it.
    async fn echo(c: UdpConn) {
        let mut b = [0u8; 2048];
        while let Ok(n) = c.recv(&mut b).await {
            let _ = c.send(&b[..n]).await;
        }
    }

    /// A tailcat server in `dev`'s region that echoes every UDP flow.
    pub(super) async fn udp_echo_server(dev: &DevDerp) -> Server {
        Server::builder().region(dev.region.clone()).on_udp(|_| Some(udp_handler(echo))).start().await.unwrap()
    }

    /// A tailcat address in `region` that no server has.
    fn unserved_addr(region: &DerpRegion) -> Addr {
        let mut ghost = PrivateKey::generate().public;
        (ghost.region, ghost.region_id) = (vec![region.clone()], 0);
        ghost.addr()
    }

    /// A greeting that offers "no authentication", then a request for
    /// command `cmd` with the address `host:port`.
    pub(super) fn request(cmd: u8, host: &str, port: u16) -> Vec<u8> {
        let mut b = vec![5, 1, 0, 5, cmd, 0];
        put_addr(&mut b, host, port);
        b
    }

    /// A datagram for the relay: a UDP request header for `host:port`,
    /// then `payload`.
    pub(super) fn datagram(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0, 0, 0];
        put_addr(&mut b, host, port);
        b.extend_from_slice(payload);
        b
    }

    /// Opens a UDP association through `proxy` for the client at
    /// `client`, and returns its control connection and relay address.
    pub(super) async fn udp_associate_via(proxy: SocketAddr, client: SocketAddr) -> (TcpStream, SocketAddr) {
        let mut ctrl = TcpStream::connect(proxy).await.unwrap();
        ctrl.write_all(&request(3, &client.ip().to_string(), client.port())).await.unwrap();
        let mut rep = [0u8; 12];
        ctrl.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REP_SUCCESS);
        let ip: [u8; 4] = rep[6..10].try_into().unwrap();
        let port = u16::from_be_bytes([rep[10], rep[11]]);
        (ctrl, SocketAddr::from((ip, port)))
    }

    async fn target(host: &str, port: u16) -> Target {
        classify(host, port).await.unwrap()
    }

    fn via(s: &str) -> Target {
        Target::Via(addr(s))
    }

    #[tokio::test]
    async fn classifies_destinations() {
        assert_eq!(target("server.tailcat", 80).await, Target::Server(80));
        assert_eq!(target("", 80).await, Target::Server(80));
        assert_eq!(target(ADDR, 81).await, Target::Addr(Addr::new(ADDR), 81));
        assert_eq!(target("10.1.2.3", 22).await, via("10.1.2.3:22"));
        assert_eq!(target("::ffff:10.1.2.3", 22).await, via("10.1.2.3:22"));
        assert_eq!(target("fd7a::1", 22).await, via("[fd7a::1]:22"));
        assert_eq!(target("localhost", 22).await, via("127.0.0.1:22"));
    }

    #[test]
    fn udp_header_addrs() {
        let b = [3, 3, b'a', b'b', b'c', 0, 53, 9, 9];
        let ((h, p), rest) = parse_addr(&b).unwrap();
        assert_eq!((h.as_str(), p, rest), ("abc", 53, &[9u8, 9][..]));
        // Truncated or unknown addresses don't parse.
        for bad in [&[][..], &[1, 1, 2, 3, 4, 0], &[3, 5, b'a', 0, 1], &[4; 17], &[2, 0, 0], &[3, 1, 0xff, 0, 1]] {
            assert!(parse_addr(bad).is_none(), "{bad:?} parsed");
        }
    }

    #[test]
    fn udp_clients() {
        let ctrl = addr("127.0.0.1:4000");
        // An unspecified address (or a hostname) means the control
        // connection's IP, and port 0 the first datagram's port.
        for host in ["0.0.0.0", "::", "localhost"] {
            let mut c = UdpClient::new(host, 0, ctrl);
            assert!(!c.admit(addr("10.0.0.1:5000")), "{host}: another IP admitted");
            assert!(c.admit(addr("127.0.0.1:5000")), "{host}: the client wasn't admitted");
            assert!(c.admit(addr("[::ffff:127.0.0.1]:5000")), "{host}: the mapped client wasn't admitted");
            assert!(!c.admit(addr("127.0.0.1:5001")), "{host}: another port admitted after the first datagram");
        }
        // A specific address is the only one admitted.
        let mut c = UdpClient::new("::ffff:10.0.0.1", 5000, ctrl);
        assert_eq!(c, UdpClient { ip: "10.0.0.1".parse().unwrap(), port: 5000 });
        assert!(!c.admit(addr("127.0.0.1:5000")));
        assert!(!c.admit(addr("10.0.0.1:5001")));
        assert!(c.admit(addr("10.0.0.1:5000")));
    }

    #[tokio::test]
    async fn addrs_round_trip() {
        for (host, port) in [("10.1.2.3", 80), ("fd7a:115c:a1e0::1", 443), ("example.com", 53)] {
            let mut b = Vec::new();
            put_addr(&mut b, host, port);
            b.push(7);
            assert_eq!(parse_addr(&b), Some(((host.to_string(), port), &[7][..])));
            assert_eq!(read_addr(&mut &b[..]).await.unwrap(), (host.to_string(), port));
        }
        assert!(read_addr(&mut &[9u8, 0, 0][..]).await.is_err());
        assert!(read_addr(&mut &[1u8, 1, 2][..]).await.is_err());
    }

    /// Runs the proxy with no default server and returns its address.
    async fn proxy() -> SocketAddr {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = ln.local_addr().unwrap();
        let d = Dialer { g: global(), key: NodePrivate::generate(), default: None, clients: Mutex::default() };
        tokio::spawn(serve(ln, Arc::new(d)));
        a
    }

    async fn roundtrip(a: SocketAddr, send: &[u8], want: usize) -> Vec<u8> {
        let mut c = TcpStream::connect(a).await.unwrap();
        c.write_all(send).await.unwrap();
        let mut got = vec![0; want];
        c.read_exact(&mut got).await.unwrap();
        got
    }

    #[tokio::test]
    async fn handshakes() {
        let a = proxy().await;
        // Only "no authentication" is acceptable.
        assert_eq!(roundtrip(a, &[5, 1, 2], 2).await, [5, 0xff]);
        let ok_reply = |rep| vec![5, 0, 5, rep, 0, 1, 0, 0, 0, 0, 0, 0];
        // BIND isn't supported.
        let bind = request(2, "127.0.0.1", 80);
        assert_eq!(roundtrip(a, &bind, 12).await, ok_reply(REP_COMMAND_NOT_SUPPORTED));
        // Nor are unknown address types.
        let bad_atyp = [5, 1, 0, 5, 1, 0, 9];
        assert_eq!(roundtrip(a, &bad_atyp, 12).await, ok_reply(REP_ADDR_TYPE_NOT_SUPPORTED));
        // Without a server argument, only tailcat address hostnames can
        // be dialed.
        let connect = request(1, "server.tailcat", 80);
        assert_eq!(roundtrip(a, &connect, 12).await, ok_reply(REP_HOST_UNREACHABLE));
    }

    /// Sends `msg` to `to` every half second until a reply comes back,
    /// and returns the reply. The first datagrams can be lost while the
    /// tunnel comes up.
    async fn send_until_answered(u: &UdpSocket, msg: &[u8], to: SocketAddr) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        loop {
            u.send_to(msg, to).await.unwrap();
            if let Ok(Ok((n, _))) = timeout(Duration::from_millis(500), u.recv_from(&mut buf)).await {
                return buf[..n].to_vec();
            }
        }
    }

    /// A UDP flow that's slow to open doesn't hold up another flow's
    /// datagrams.
    #[tokio::test]
    async fn slow_udp_flows_dont_stall_others() {
        let dev = DevDerp::start_local().await.unwrap();
        let echo = udp_echo_server(&dev).await;
        let echo_addr = echo.tailcat_addr();
        // No server has this address, so opening a flow to it waits for
        // an answer that never comes.
        let ghost_addr = unserved_addr(&dev.region);
        assert!(echo_addr.as_str().len() < 256);
        assert!(ghost_addr.as_str().len() < 256);
        let (_ctrl, relay) = udp_associate_via(proxy().await, addr("0.0.0.0:0")).await;
        let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        u.send_to(&datagram(ghost_addr.as_str(), 7, b"lost"), relay).await.unwrap();
        let want = datagram(echo_addr.as_str(), 7, b"echo");
        let echoed = timeout(Duration::from_secs(8), send_until_answered(&u, &want, relay)).await;

        assert_eq!(echoed.expect("the echo flow was held up"), want);
    }
}
