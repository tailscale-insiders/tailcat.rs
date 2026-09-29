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

use crate::Global;

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
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
            let first = addrs.first().ok_or_else(|| anyhow!("no addresses found for {host:?}"))?;
            addrs.iter().find(|a| a.is_ipv4()).unwrap_or(first).ip()
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
            Target::Addr(a, _) => Ok(self
                .clients
                .lock()
                .unwrap()
                .entry(a.clone())
                .or_insert_with(|| crate::client::new_client(&self.g, a.clone(), self.key.clone()))
                .clone()),
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

/// Normalizes --listen: a bare port means localhost; a bare host means
/// an OS-assigned port; ":1080" means all interfaces.
pub fn normalize_listen(s: &str) -> String {
    if let Ok(p) = s.parse::<u16>() {
        return format!("127.0.0.1:{p}");
    }
    // Before the ":port" check, which "::1" would otherwise match.
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("[{s}]:0");
    }
    if let Some(port) = s.strip_prefix(':') {
        return format!("0.0.0.0:{}", if port.is_empty() { "0" } else { port });
    }
    if crate::util::split_host_port(s).is_ok() {
        return s.to_string();
    }
    if let Some(h) = s.strip_suffix(':') {
        return format!("{h}:0");
    }
    format!("{s}:0")
}

pub async fn socks_mode(g: &Global, listen: &str, mut args: Vec<String>) -> Result<ExitCode> {
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
    let ln = TcpListener::bind(normalize_listen(listen)).await?;
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
    while let Ok((c, peer)) = ln.accept().await {
        let d = dialer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(c, d).await {
                tracing::debug!("socks5: {peer}: {e}");
            }
        });
    }
}

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
            // The socks5 dial timeout is also WireGuard's handshake
            // retransmit interval, so be generous.
            let dial = tokio::time::timeout(Duration::from_secs(15), async {
                d.dial_tcp(&classify(&host, port).await?).await
            });
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
        3 => udp_associate(c, d).await,
        _ => {
            reply(&mut c, REP_COMMAND_NOT_SUPPORTED, zero).await?;
            bail!("unsupported command {cmd}");
        }
    }
}

/// Tunnel UDP flows by destination (host, port).
type Flows = HashMap<(String, u16), Arc<tailcat::UdpConn>>;

/// Relays datagrams between the client and tunnel UDP flows for as long
/// as the control connection stays open.
async fn udp_associate(mut c: TcpStream, d: Arc<Dialer>) -> Result<()> {
    let local_ip = c.local_addr()?.ip();
    let sock = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    reply(&mut c, REP_SUCCESS, sock.local_addr()?).await?;
    let flows: Arc<Mutex<Flows>> = Arc::default();
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    let relay = {
        let sock = sock.clone();
        let flows = flows.clone();
        async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
                // RSV(2), FRAG(1): fragments aren't supported.
                if n < 4 || buf[2] != 0 {
                    continue;
                }
                let Some((dst, payload)) = parse_addr(&buf[3..n]) else { continue };
                *client_addr.lock().unwrap() = Some(from);
                let existing = flows.lock().unwrap().get(&dst).cloned();
                let flow = match existing {
                    Some(f) => f,
                    None => {
                        let Ok(t) = classify(&dst.0, dst.1).await else { continue };
                        let Ok(f) = d.dial_udp(&t).await else { continue };
                        let f = Arc::new(f);
                        flows.lock().unwrap().insert(dst.clone(), f.clone());
                        // Replies from this flow go back to the client,
                        // wrapped with the destination's address.
                        let (f2, sock2, ca) = (f.clone(), sock.clone(), client_addr.clone());
                        tokio::spawn(async move {
                            let mut b = vec![0u8; 65535];
                            while let Ok(n) = f2.recv(&mut b).await {
                                let Some(to) = *ca.lock().unwrap() else { continue };
                                let mut out = vec![0, 0, 0];
                                put_addr(&mut out, &dst.0, dst.1);
                                out.extend_from_slice(&b[..n]);
                                let _ = sock2.send_to(&out, to).await;
                            }
                        });
                        f
                    }
                };
                let _ = flow.send(payload).await;
            }
        }
    };
    // The association ends when the control connection closes.
    let mut sink = [0u8; 64];
    tokio::select! {
        _ = relay => {}
        _ = async { while c.read(&mut sink).await.is_ok_and(|n| n > 0) {} } => {}
    }
    for f in flows.lock().unwrap().values() {
        f.close();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu";

    #[tokio::test]
    async fn classifies_destinations() {
        assert_eq!(classify("server.tailcat", 80).await.unwrap(), Target::Server(80));
        assert_eq!(classify("", 80).await.unwrap(), Target::Server(80));
        assert_eq!(classify(ADDR, 81).await.unwrap(), Target::Addr(Addr::new(ADDR), 81));
        assert_eq!(classify("10.1.2.3", 22).await.unwrap(), Target::Via("10.1.2.3:22".parse().unwrap()));
        assert_eq!(classify("::ffff:10.1.2.3", 22).await.unwrap(), Target::Via("10.1.2.3:22".parse().unwrap()));
        assert_eq!(classify("fd7a::1", 22).await.unwrap(), Target::Via("[fd7a::1]:22".parse().unwrap()));
        assert_eq!(classify("localhost", 22).await.unwrap(), Target::Via("127.0.0.1:22".parse().unwrap()));
    }

    #[test]
    fn listen_addrs() {
        assert_eq!(normalize_listen("1080"), "127.0.0.1:1080");
        assert_eq!(normalize_listen(":1080"), "0.0.0.0:1080");
        assert_eq!(normalize_listen(":"), "0.0.0.0:0");
        assert_eq!(normalize_listen("127.0.0.1:0"), "127.0.0.1:0");
        assert_eq!(normalize_listen("0.0.0.0"), "0.0.0.0:0");
        assert_eq!(normalize_listen("localhost:"), "localhost:0");
        assert_eq!(normalize_listen("[::1]:5"), "[::1]:5");
        assert_eq!(normalize_listen("::1"), "[::1]:0");
        assert_eq!(normalize_listen("fd7a::1"), "[fd7a::1]:0");
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
        let g = Global { key: None, verbose: false, json: false, derpmap_url: String::new() };
        let d = Dialer { g, key: NodePrivate::generate(), default: None, clients: Mutex::default() };
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
        let bind = [5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80];
        assert_eq!(roundtrip(a, &bind, 12).await, ok_reply(REP_COMMAND_NOT_SUPPORTED));
        // Nor are unknown address types.
        assert_eq!(roundtrip(a, &[5, 1, 0, 5, 1, 0, 9], 12).await, ok_reply(REP_ADDR_TYPE_NOT_SUPPORTED));
        // Without a server argument, only tailcat address hostnames can
        // be dialed.
        let connect = [&[5, 1, 0, 5, 1, 0, 3, 14][..], b"server.tailcat", &[0, 80]].concat();
        assert_eq!(roundtrip(a, &connect, 12).await, ok_reply(REP_HOST_UNREACHABLE));
    }
}
