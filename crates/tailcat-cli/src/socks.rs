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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    Ok(Target::Via(SocketAddr::new(ip, port)))
}

/// Dials tailcat servers on behalf of the proxy.
struct Dialer {
    g: Global,
    key: NodePrivate,
    default: Option<Client>,
    clients: Mutex<HashMap<String, Client>>,
}

impl Dialer {
    fn client_for(&self, a: &Addr) -> Client {
        let mut m = self.clients.lock().unwrap();
        m.entry(a.as_str().to_string())
            .or_insert_with(|| crate::client::new_client(&self.g, a.clone(), self.key.clone()))
            .clone()
    }

    fn default_client(&self) -> Result<&Client> {
        self.default
            .as_ref()
            .ok_or_else(|| anyhow!("no tailcat address argument was given to \"tailcat socks\"; only tailcat address hostnames can be dialed"))
    }

    async fn dial_tcp(&self, t: &Target) -> Result<tailcat::TcpStream> {
        Ok(match t {
            Target::Server(p) => self.default_client()?.dial_tcp_port(*p).await?,
            Target::Addr(a, p) => self.client_for(a).dial_tcp_port(*p).await?,
            Target::Via(dst) => self.default_client()?.dial_tcp(*dst).await?,
        })
    }

    async fn dial_udp(&self, t: &Target) -> Result<tailcat::UdpConn> {
        Ok(match t {
            Target::Server(p) => self.default_client()?.dial_udp_port(*p).await?,
            Target::Addr(a, p) => self.client_for(a).dial_udp_port(*p).await?,
            Target::Via(dst) => self.default_client()?.dial_udp(*dst).await?,
        })
    }
}

/// Normalizes --listen: a bare port means localhost; a bare host means
/// an OS-assigned port; ":1080" means all interfaces.
pub fn normalize_listen(s: &str) -> String {
    if let Ok(p) = s.parse::<u16>() {
        return format!("127.0.0.1:{p}");
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
    if s.contains(':') && s.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("[{s}]:0");
    }
    format!("{s}:0")
}

pub async fn socks_mode(g: &Global, listen: &str, mut args: Vec<String>) -> Result<ExitCode> {
    // The address argument is optional: tailcat address hostnames are
    // dialed directly, so a fixed server is only needed for
    // server.tailcat and exit-node destinations.
    let mut addr: Option<Addr> = None;
    if let Some(first) = args.first().cloned() {
        if Addr::new(first.clone()).parse().is_ok() {
            addr = Some(Addr::new(first));
            args.remove(0);
        } else if first.contains('.') && crate::serve::which(&first).is_none() {
            addr = Some(crate::addrarg::tailcat_addr_arg(&first).await?);
            args.remove(0);
        }
    }
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
    if args.is_empty() {
        eprintln!("SOCKS running at {socks_addr}");
        serve.await?;
        bail!("SOCKS5 server exited");
    }
    tracing::debug!("SOCKS running at {socks_addr}");
    let status = tokio::process::Command::new(&args[0]).args(&args[1..]).env("all_proxy", &socks_addr).status().await?;
    Ok(ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8))
}

async fn serve(ln: TcpListener, dialer: Arc<Dialer>) {
    loop {
        let Ok((c, peer)) = ln.accept().await else { return };
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
    put_addr(&mut b, &bound);
    c.write_all(&b).await
}

fn put_addr(b: &mut Vec<u8>, a: &SocketAddr) {
    match a.ip() {
        IpAddr::V4(v4) => {
            b.push(1);
            b.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            b.push(4);
            b.extend_from_slice(&v6.octets());
        }
    }
    b.extend_from_slice(&a.port().to_be_bytes());
}

/// Reads a SOCKS address (ATYP, address, port) from `r`.
async fn read_addr<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<(String, u16)> {
    let atyp = r.read_u8().await?;
    let host = match atyp {
        1 => {
            let mut a = [0u8; 4];
            r.read_exact(&mut a).await?;
            IpAddr::from(a).to_string()
        }
        3 => {
            let n = r.read_u8().await? as usize;
            let mut h = vec![0u8; n];
            r.read_exact(&mut h).await?;
            String::from_utf8(h).map_err(|_| anyhow!("bad hostname"))?
        }
        4 => {
            let mut a = [0u8; 16];
            r.read_exact(&mut a).await?;
            IpAddr::from(a).to_string()
        }
        _ => bail!("unsupported address type {atyp}"),
    };
    let port = r.read_u16().await?;
    Ok((host, port))
}

/// Parses a SOCKS address from a UDP datagram, returning it and the
/// rest of the datagram.
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
    let port = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
    Some(((host, port), &rest[2..]))
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
            let dial = async {
                let t = classify(&host, port).await?;
                d.dial_tcp(&t).await
            };
            let remote = match tokio::time::timeout(Duration::from_secs(15), dial).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    reply(&mut c, REP_HOST_UNREACHABLE, zero).await?;
                    return Err(e);
                }
                Err(_) => {
                    reply(&mut c, REP_HOST_UNREACHABLE, zero).await?;
                    bail!("dial {host}:{port}: timed out");
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
                        let (f2, sock2, ca, dst2) = (f.clone(), sock.clone(), client_addr.clone(), dst.clone());
                        tokio::spawn(async move {
                            let mut b = vec![0u8; 65535];
                            while let Ok(n) = f2.recv(&mut b).await {
                                let Some(to) = *ca.lock().unwrap() else { continue };
                                let mut out = vec![0, 0, 0];
                                match dst2.0.parse::<IpAddr>() {
                                    Ok(ip) => put_addr(&mut out, &SocketAddr::new(ip, dst2.1)),
                                    Err(_) => {
                                        out.push(3);
                                        out.push(dst2.0.len() as u8);
                                        out.extend_from_slice(dst2.0.as_bytes());
                                        out.extend_from_slice(&dst2.1.to_be_bytes());
                                    }
                                }
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
        _ = async { while let Ok(n) = c.read(&mut sink).await { if n == 0 { break } } } => {}
    }
    for f in flows.lock().unwrap().values() {
        f.close();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn classifies_destinations() {
        assert_eq!(classify("server.tailcat", 80).await.unwrap(), Target::Server(80));
        assert_eq!(classify("", 80).await.unwrap(), Target::Server(80));
        let a = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu";
        assert_eq!(classify(a, 81).await.unwrap(), Target::Addr(Addr::new(a), 81));
        assert_eq!(classify("10.1.2.3", 22).await.unwrap(), Target::Via("10.1.2.3:22".parse().unwrap()));
        assert_eq!(classify("::ffff:10.1.2.3", 22).await.unwrap(), Target::Via("10.1.2.3:22".parse().unwrap()));
    }

    #[test]
    fn listen_addrs() {
        assert_eq!(normalize_listen("1080"), "127.0.0.1:1080");
        assert_eq!(normalize_listen(":1080"), "0.0.0.0:1080");
        assert_eq!(normalize_listen("127.0.0.1:0"), "127.0.0.1:0");
        assert_eq!(normalize_listen("0.0.0.0"), "0.0.0.0:0");
    }

    #[test]
    fn udp_header_addrs() {
        let b = [3, 3, b'a', b'b', b'c', 0, 53, 9, 9];
        let ((h, p), rest) = parse_addr(&b).unwrap();
        assert_eq!((h.as_str(), p, rest), ("abc", 53, &[9u8, 9][..]));
    }
}
