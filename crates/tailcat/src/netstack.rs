//! A userspace TCP/IP stack, so tunnel traffic terminates inside the
//! process with no TUN device: TCP runs on smoltcp, and UDP flows are
//! demultiplexed here directly.
//!
//! IP packets from the tunnel go in through [`Stack::inject`]; packets
//! the stack emits go to the output callback given to [`Stack::new`].
//! Inbound TCP connections and UDP flows are offered to policy callbacks
//! that decide, per flow, whether to accept, reset or drop them.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::{AnySocket, tcp};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket, UdpRepr,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tracing::trace;

const TCP_BUFFER: usize = 512 << 10;
const UDP_QUEUE: usize = 512;
/// How long an accepted connection may take to complete its handshake.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an accepted socket may wait for its SYN: the SYN didn't
/// take, or the handshake was reset.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(2);
/// Abort a connection whose peer stops answering for this long.
const TCP_TIMEOUT: Duration = Duration::from_secs(120);
/// Probe an idle connection this often: smoltcp's timeout counts from
/// the last segment received, so an idle peer would look like a dead one.
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);
/// The ephemeral port range for outbound flows.
const EPHEMERAL: std::ops::RangeInclusive<u16> = 32768..=60999;

/// What to do with a new inbound TCP connection.
pub enum TcpDecision {
    /// Complete the handshake and pass the connection to this function.
    Accept(Box<dyn FnOnce(TcpStream) + Send>),
    /// Answer with a RST.
    Reset,
    /// Drop the SYN silently.
    Drop,
}

/// Decides the fate of inbound TCP SYNs, given (source, destination).
pub type TcpPolicy = Arc<dyn Fn(SocketAddr, SocketAddr) -> TcpDecision + Send + Sync>;

/// Decides whether to accept a new inbound UDP flow, given (source,
/// destination); accepted flows are handed to the returned function.
pub type UdpPolicy = Arc<dyn Fn(SocketAddr, SocketAddr) -> Option<Box<dyn FnOnce(UdpConn) + Send>> + Send + Sync>;

/// Where the stack sends the IP packets it emits.
pub type Output = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// Stack configuration.
pub struct StackConfig {
    /// The stack's own addresses.
    pub addrs: Vec<IpAddr>,
    /// Accept connections to any destination address (for exit nodes).
    pub any_ip: bool,
    pub mtu: usize,
}

#[derive(Default)]
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct RxToken(Vec<u8>);
struct TxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl phy::Device for QueueDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxToken(p), TxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

type FlowKey = (SocketAddr, SocketAddr); // (local, remote)

struct PendingAccept {
    flow: FlowKey,
    handler: Box<dyn FnOnce(TcpStream) + Send>,
    since: tokio::time::Instant,
}

/// How a TCP connection ended.
#[derive(Clone, Copy, Debug, PartialEq)]
enum End {
    /// The peer sent a FIN: a clean end of stream.
    Fin,
    /// The peer sent a RST.
    Reset,
    /// We aborted it, or the stack was closed.
    Aborted,
    /// The peer stopped answering.
    TimedOut,
}

impl End {
    /// The error to report once the data received is used up, if any.
    fn error(self) -> Option<io::Error> {
        let (kind, msg) = match self {
            End::Fin => return None,
            End::Reset => (io::ErrorKind::ConnectionReset, "connection reset by peer"),
            End::Aborted => (io::ErrorKind::ConnectionAborted, "connection aborted"),
            End::TimedOut => (io::ErrorKind::TimedOut, "connection timed out"),
        };
        Some(io::Error::new(kind, msg))
    }
}

struct State {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueueDevice,
    /// Inbound connections still completing their handshake.
    accepting: HashMap<SocketHandle, PendingAccept>,
    /// Every TCP socket's 4-tuple, to route SYN retransmits correctly.
    tuples: HashMap<FlowKey, SocketHandle>,
    /// How connections ended, where the socket's state doesn't say: a
    /// closed socket may have had a FIN, a RST or an abort.
    ends: HashMap<SocketHandle, End>,
    /// Sockets no longer referenced by a TcpStream, and since when;
    /// they're removed once they finish closing.
    orphans: Vec<(SocketHandle, tokio::time::Instant)>,
    udp: HashMap<FlowKey, mpsc::Sender<Vec<u8>>>,
    next_port: u16,
    closed: bool,
    /// When the stack started: smoltcp's time zero.
    epoch: tokio::time::Instant,
}

impl State {
    /// smoltcp's clock. It runs on tokio's, so tests can pause it.
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    /// Picks the next free ephemeral port on `local_ip`.
    fn alloc_port(&mut self, local_ip: IpAddr) -> u16 {
        loop {
            let p = self.next_port;
            self.next_port = if p >= *EPHEMERAL.end() { *EPHEMERAL.start() } else { p + 1 };
            let local = SocketAddr::new(local_ip, p);
            if !self.tuples.keys().chain(self.udp.keys()).any(|(l, _)| *l == local) {
                return p;
            }
        }
    }

    fn tcp_sockets(&self) -> impl Iterator<Item = &tcp::Socket<'static>> {
        self.sockets.iter().filter_map(|(_, s)| tcp::Socket::downcast(s))
    }

    /// How the connection on socket `h` ended, if its receive side has.
    fn end(&self, h: SocketHandle) -> Option<End> {
        match self.sockets.get::<tcp::Socket>(h).state() {
            tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait => Some(End::Fin),
            // smoltcp closes a socket by itself only on a RST, which
            // `ingress` records, or when the peer times out.
            tcp::State::Closed => Some(self.ends.get(&h).copied().unwrap_or(End::TimedOut)),
            _ => None,
        }
    }

    /// Feeds the queued packets to smoltcp one at a time, recording how
    /// connections end. A smoltcp socket in Listen takes a SYN from any
    /// peer, so an accepted socket waits closed, listens only while its
    /// own flow's SYN is processed, and is closed again if it's still
    /// listening afterwards (or back to listening, after a RST).
    fn ingress(&mut self, now: smoltcp::time::Instant) {
        while let Some(pkt) = self.device.rx.front() {
            let flow = tcp_flow(pkt);
            let h = flow.and_then(|(key, _)| self.tuples.get(&key).copied());
            if let (Some(((local, _), true)), Some(h)) = (flow, h)
                && self.accepting.contains_key(&h)
            {
                let s = self.sockets.get_mut::<tcp::Socket>(h);
                if s.state() == tcp::State::Closed && s.listen(local).is_ok() {
                    self.ends.remove(&h);
                }
            }
            let before = h.map(|h| self.sockets.get::<tcp::Socket>(h).state());
            self.iface.poll_ingress_single(now, &mut self.device, &mut self.sockets);
            let (Some(h), Some(before)) = (h, before) else { continue };
            let s = self.sockets.get_mut::<tcp::Socket>(h);
            match s.state() {
                tcp::State::Listen => s.close(),
                tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait => {
                    self.ends.entry(h).or_insert(End::Fin);
                }
                tcp::State::Closed if before != tcp::State::Closed => {
                    self.ends.entry(h).or_insert(End::Reset);
                }
                _ => {}
            }
        }
    }
}

/// The source, destination, protocol and payload of an IP packet.
fn parse_ip(pkt: &[u8]) -> Option<(IpAddr, IpAddr, IpProtocol, &[u8])> {
    let (src, dst, proto, off): (IpAddr, IpAddr, _, _) = match pkt.first().map(|b| b >> 4) {
        Some(6) => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            (ip.src_addr().into(), ip.dst_addr().into(), ip.next_header(), 40)
        }
        Some(4) => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            (ip.src_addr().into(), ip.dst_addr().into(), ip.next_header(), ip.header_len() as usize)
        }
        _ => return None,
    };
    Some((src, dst, proto, &pkt[off.min(pkt.len())..]))
}

/// A TCP segment's flow, and whether it's a connection's opening SYN.
fn tcp_flow(pkt: &[u8]) -> Option<(FlowKey, bool)> {
    let (src, dst, IpProtocol::Tcp, body) = parse_ip(pkt)? else { return None };
    let tcp = TcpPacket::new_checked(body).ok()?;
    let key = (SocketAddr::new(dst, tcp.dst_port()), SocketAddr::new(src, tcp.src_port()));
    Some((key, tcp.syn() && !tcp.ack() && !tcp.rst()))
}

fn socket_addr(ep: smoltcp::wire::IpEndpoint) -> SocketAddr {
    SocketAddr::new(ep.addr.into(), ep.port)
}

struct Shared {
    state: Mutex<State>,
    /// Wakes the poll loop.
    wake: Arc<Notify>,
    /// Signaled after each poll, for drain waiters.
    polled: Notify,
    out: Output,
    tcp_policy: Option<TcpPolicy>,
    udp_policy: Option<UdpPolicy>,
    addrs: Vec<IpAddr>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
}

/// A userspace TCP/IP stack.
#[derive(Clone)]
pub struct Stack {
    shared: Arc<Shared>,
}

impl Stack {
    /// Creates a stack and starts its poll loop.
    pub fn new(cfg: StackConfig, out: Output, tcp_policy: Option<TcpPolicy>, udp_policy: Option<UdpPolicy>) -> Stack {
        let mut device = QueueDevice { mtu: cfg.mtu, ..Default::default() };
        let mut icfg = IfaceConfig::new(HardwareAddress::Ip);
        icfg.random_seed = rand::random();
        let mut iface = Interface::new(icfg, &mut device, smoltcp::time::Instant::ZERO);
        iface.update_ip_addrs(|addrs| {
            for &a in &cfg.addrs {
                let _ = addrs.push(IpCidr::new(a.into(), if a.is_ipv4() { 32 } else { 128 }));
            }
        });
        // With Medium::Ip, egress just needs some route to exist.
        for &a in &cfg.addrs {
            let _ = match a {
                IpAddr::V4(v4) => iface.routes_mut().add_default_ipv4_route(v4),
                IpAddr::V6(v6) => iface.routes_mut().add_default_ipv6_route(v6),
            };
        }
        iface.set_any_ip(cfg.any_ip);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                iface,
                sockets: SocketSet::new(Vec::new()),
                device,
                accepting: HashMap::new(),
                tuples: HashMap::new(),
                ends: HashMap::new(),
                orphans: Vec::new(),
                udp: HashMap::new(),
                next_port: rand::Rng::gen_range(&mut rand::thread_rng(), EPHEMERAL),
                closed: false,
                epoch: tokio::time::Instant::now(),
            }),
            wake: Arc::new(Notify::new()),
            polled: Notify::new(),
            out,
            tcp_policy,
            udp_policy,
            addrs: cfg.addrs,
        });
        tokio::spawn(poll_loop(Arc::downgrade(&shared)));
        Stack { shared }
    }

    /// The stack's own addresses.
    pub fn addrs(&self) -> &[IpAddr] {
        &self.shared.addrs
    }

    /// Feeds an IP packet from the tunnel into the stack.
    pub fn inject(&self, pkt: Vec<u8>) {
        let Some((src, dst, proto, body)) = parse_ip(&pkt) else { return };
        match proto {
            IpProtocol::Udp => return self.inject_udp(body, src, dst),
            IpProtocol::Tcp | IpProtocol::Icmp | IpProtocol::Icmpv6 => {}
            _ => return trace!("netstack: dropping protocol {proto}"),
        }
        let mut st = self.shared.lock();
        if st.closed {
            return;
        }
        if proto == IpProtocol::Tcp {
            let Ok(tcp) = TcpPacket::new_checked(body) else { return };
            let (s, d) = (SocketAddr::new(src, tcp.src_port()), SocketAddr::new(dst, tcp.dst_port()));
            if !st.tuples.contains_key(&(d, s)) {
                if !tcp.syn() || tcp.ack() {
                    // Not part of any connection we know; let smoltcp RST it
                    // unless it's itself a RST.
                    if tcp.rst() {
                        return;
                    }
                } else {
                    // The policy may block briefly; don't hold the lock.
                    drop(st);
                    let decision = self.shared.tcp_policy.as_ref().map_or(TcpDecision::Reset, |p| p(s, d));
                    st = self.shared.lock();
                    if st.closed {
                        return;
                    }
                    match decision {
                        TcpDecision::Drop => return,
                        TcpDecision::Reset => {} // smoltcp answers unmatched SYNs with RST
                        TcpDecision::Accept(handler) => {
                            if d.port() == 0 {
                                return;
                            }
                            // The socket stays closed until the poll loop
                            // gets to this SYN; see State::ingress.
                            if !st.tuples.contains_key(&(d, s)) {
                                let h = st.sockets.add(new_tcp_socket());
                                st.tuples.insert((d, s), h);
                                let pa = PendingAccept { flow: (d, s), handler, since: tokio::time::Instant::now() };
                                st.accepting.insert(h, pa);
                            }
                        }
                    }
                }
            }
        }
        st.device.rx.push_back(pkt);
        drop(st);
        self.shared.wake.notify_one();
    }

    fn inject_udp(&self, body: &[u8], src: IpAddr, dst: IpAddr) {
        let Ok(udp) = UdpPacket::new_checked(body) else { return };
        let (s, d) = (SocketAddr::new(src, udp.src_port()), SocketAddr::new(dst, udp.dst_port()));
        let data = udp.payload().to_vec();
        let st = self.shared.lock();
        if st.closed {
            return;
        }
        if let Some(tx) = st.udp.get(&(d, s)) {
            // A full queue drops the datagram.
            let _ = tx.try_send(data);
            return;
        }
        // The policy may block briefly; don't hold the lock.
        drop(st);
        let Some(handler) = self.shared.udp_policy.as_ref().and_then(|p| p(s, d)) else { return };
        let mut st = self.shared.lock();
        // The stack may have closed meanwhile, or another datagram opened
        // the flow.
        if st.closed {
            return;
        }
        if let Some(tx) = st.udp.get(&(d, s)) {
            let _ = tx.try_send(data);
            return;
        }
        let (tx, rx) = mpsc::channel(UDP_QUEUE);
        let _ = tx.try_send(data);
        let conn = UdpConn::new(self.shared.clone(), d, s, &tx, rx);
        st.udp.insert((d, s), tx);
        drop(st);
        handler(conn);
    }

    /// Opens a TCP connection from `local_ip` to `remote`.
    pub async fn dial_tcp(&self, local_ip: IpAddr, remote: SocketAddr) -> io::Result<TcpStream> {
        let (h, local) = {
            let mut st = self.shared.lock();
            if st.closed {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "stack closed"));
            }
            let local = SocketAddr::new(local_ip, st.alloc_port(local_ip));
            let mut sock = new_tcp_socket();
            sock.connect(st.iface.context(), remote, local)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("connect: {e}")))?;
            let h = st.sockets.add(sock);
            st.tuples.insert((local, remote), h);
            (h, local)
        };
        self.shared.wake.notify_one();
        let stream = TcpStream { shared: self.shared.clone(), handle: h, local, remote };
        std::future::poll_fn(|cx| stream.poll_connected(cx)).await?;
        Ok(stream)
    }

    /// Opens a connected UDP flow from `local_ip` to `remote`.
    pub fn dial_udp(&self, local_ip: IpAddr, remote: SocketAddr) -> io::Result<UdpConn> {
        let mut st = self.shared.lock();
        if st.closed {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "stack closed"));
        }
        let local = SocketAddr::new(local_ip, st.alloc_port(local_ip));
        let (tx, rx) = mpsc::channel(UDP_QUEUE);
        let conn = UdpConn::new(self.shared.clone(), local, remote, &tx, rx);
        st.udp.insert((local, remote), tx);
        Ok(conn)
    }

    /// Waits until every TCP connection has finished closing, or until
    /// `timeout`. The whole TCP stack lives in this process, so exiting
    /// right after closing a connection can lose its final FIN or ACK;
    /// call this before exiting.
    pub async fn drain_tcp(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.shared.polled.notified();
            // A closed socket may still have unsent data: it was reset or
            // aborted, and will never send it.
            let busy = self.shared.lock().tcp_sockets().any(tcp::Socket::is_active);
            if !busy {
                // Let the final ACK make it out through the tunnel.
                tokio::time::sleep(Duration::from_millis(50)).await;
                return true;
            }
            // The poll loop runs at least every second; waking it here too
            // would keep the two running back to back.
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return false;
            }
        }
    }

    /// Stops the stack, aborting every connection.
    pub fn close(&self) {
        let mut guard = self.shared.lock();
        let st = &mut *guard;
        st.closed = true;
        for (h, s) in st.sockets.iter_mut() {
            if let Some(s) = tcp::Socket::downcast_mut(s) {
                abort(s, h, &mut st.ends);
            }
        }
        st.udp.clear();
        drop(guard);
        self.shared.wake.notify_one();
    }
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    let mut s =
        tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUFFER]), tcp::SocketBuffer::new(vec![0; TCP_BUFFER]));
    s.set_timeout(Some(TCP_TIMEOUT.into()));
    s.set_keep_alive(Some(TCP_KEEPALIVE.into()));
    s.set_nagle_enabled(false);
    s.set_ack_delay(Some(smoltcp::time::Duration::from_millis(5)));
    s
}

/// Aborts the connection on socket `h` with a RST, and remembers that we
/// did.
fn abort(s: &mut tcp::Socket<'static>, h: SocketHandle, ends: &mut HashMap<SocketHandle, End>) {
    if s.is_open() {
        ends.entry(h).or_insert(End::Aborted);
    }
    s.abort();
}

async fn poll_loop(shared: Weak<Shared>) {
    loop {
        let Some(sh) = shared.upgrade() else { return };
        let (out, delay, accepted, closed) = {
            let mut guard = sh.lock();
            let st = &mut *guard;
            let t = st.now();
            st.iface.poll_maintenance(t);
            st.ingress(t);
            while st.iface.poll_egress(t, &mut st.device, &mut st.sockets) == PollResult::SocketStateChanged {}

            // Hand off inbound connections that finished their handshake,
            // and give up on ones that never did. A socket only ever
            // connects to its own flow's peer, but check: the handler
            // trusts peer_addr() as the peer's identity.
            let sockets = &st.sockets;
            let (accepted, dead): (Vec<_>, Vec<_>) = st
                .accepting
                .extract_if(|&h, pa| match sockets.get::<tcp::Socket>(h).state() {
                    tcp::State::SynReceived => pa.since.elapsed() > ACCEPT_TIMEOUT,
                    tcp::State::Closed | tcp::State::Listen => pa.since.elapsed() > LISTEN_TIMEOUT,
                    _ => true,
                })
                .partition(|(h, pa)| {
                    let s = sockets.get::<tcp::Socket>(*h);
                    matches!(s.state(), tcp::State::Established | tcp::State::CloseWait)
                        && (s.local_endpoint().map(socket_addr), s.remote_endpoint().map(socket_addr))
                            == (Some(pa.flow.0), Some(pa.flow.1))
                });
            for (h, _) in dead {
                st.sockets.get_mut::<tcp::Socket>(h).abort();
                st.orphans.push((h, tokio::time::Instant::now()));
            }

            // Reap closed sockets nobody holds any more, and abort ones that
            // take too long to close: a live peer that never sends its FIN
            // would keep one in FIN-WAIT-2 forever.
            let State { sockets, tuples, ends, orphans, .. } = st;
            orphans.retain(|&(h, since)| {
                let s = sockets.get_mut::<tcp::Socket>(h);
                // An aborted socket keeps its peer until it has sent the RST.
                let done = s.state() == tcp::State::TimeWait
                    || s.state() == tcp::State::Closed && s.remote_endpoint().is_none();
                if done {
                    sockets.remove(h);
                    tuples.retain(|_, v| *v != h);
                    ends.remove(&h);
                } else if since.elapsed() > TCP_TIMEOUT {
                    s.abort();
                }
                !done
            });

            let delay = st.iface.poll_delay(st.now(), &st.sockets);
            (std::mem::take(&mut st.device.tx), delay, accepted, st.closed)
        };
        out.into_iter().for_each(|p| (sh.out)(p));
        for (h, pa) in accepted {
            let (local, remote) = pa.flow;
            (pa.handler)(TcpStream { shared: sh.clone(), handle: h, local, remote });
        }
        sh.polled.notify_waiters();
        if closed {
            return;
        }
        // Wake at least every second, for the timeouts smoltcp doesn't know.
        let delay = delay.map_or(Duration::from_secs(1), |d| Duration::from(d).min(Duration::from_secs(1)));
        let wake = sh.wake.clone();
        drop(sh);
        if delay.is_zero() {
            tokio::task::yield_now().await;
        } else {
            let _ = tokio::time::timeout(delay, wake.notified()).await;
        }
    }
}

/// A TCP connection through the tunnel. It implements tokio's
/// `AsyncRead` and `AsyncWrite`; `poll_shutdown` half-closes (sends a
/// FIN) and leaves the read side open.
pub struct TcpStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
    local: SocketAddr,
    remote: SocketAddr,
}

impl TcpStream {
    /// The local address (ours).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The remote address (the peer's).
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    fn with<R>(&self, f: impl FnOnce(&mut tcp::Socket<'static>) -> R) -> R {
        f(self.shared.lock().sockets.get_mut::<tcp::Socket>(self.handle))
    }

    /// Runs `f` on the socket and how its connection ended, if it has.
    fn with_end<R>(&self, f: impl FnOnce(&mut tcp::Socket<'static>, Option<End>) -> R) -> R {
        let mut st = self.shared.lock();
        let end = st.end(self.handle);
        f(st.sockets.get_mut::<tcp::Socket>(self.handle), end)
    }

    /// Runs `f` on the socket, then wakes the poll loop.
    fn with_wake<R>(&self, f: impl FnOnce(&mut tcp::Socket<'static>) -> R) -> R {
        let r = self.with(f);
        self.shared.wake.notify_one();
        r
    }

    fn poll_connected(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_end(|s, end| match s.state() {
            tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
            tcp::State::Closed | tcp::State::TimeWait => {
                // A RST in answer to our SYN: nobody's listening.
                let refused = || io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
                Poll::Ready(Err(end.filter(|&e| e != End::Reset).and_then(End::error).unwrap_or_else(refused)))
            }
            _ => {
                s.register_send_waker(cx.waker());
                s.register_recv_waker(cx.waker());
                Poll::Pending
            }
        })
    }

    /// Half-closes the connection: sends a FIN after any queued data.
    pub fn close_write(&self) {
        self.with_wake(|s| s.close());
    }

    /// Aborts the connection with a RST.
    pub fn abort(&self) {
        let mut guard = self.shared.lock();
        let st = &mut *guard;
        abort(st.sockets.get_mut::<tcp::Socket>(self.handle), self.handle, &mut st.ends);
        drop(guard);
        self.shared.wake.notify_one();
    }

    /// Waits until everything sent has been acknowledged and, if the
    /// peer already closed its side, our FIN too (up to `timeout`).
    pub async fn drain(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.shared.polled.notified();
            // A reset or aborted connection keeps its unsent data, but
            // will never send it.
            let done = self.with(|s| {
                s.state() == tcp::State::Closed
                    || s.send_queue() == 0
                        && !matches!(s.state(), tcp::State::FinWait1 | tcp::State::Closing | tcp::State::LastAck)
            });
            if done || tokio::time::timeout_at(deadline, notified).await.is_err() {
                return;
            }
        }
    }
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TcpStream({} -> {})", self.local, self.remote)
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut st = self.shared.lock();
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        if s.is_open() {
            s.close();
        }
        st.orphans.push((self.handle, tokio::time::Instant::now()));
        drop(st);
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let n = ready!(self.with_end(|s, end| {
            if s.can_recv() {
                Poll::Ready(s.recv_slice(buf.initialize_unfilled()).map_err(io::Error::other))
            } else if !s.may_recv() {
                // EOF, if the peer closed the connection rather than
                // resetting it or timing out.
                Poll::Ready(end.and_then(End::error).map_or(Ok(0), Err))
            } else {
                s.register_recv_waker(cx.waker());
                Poll::Pending
            }
        }))?;
        if n > 0 {
            buf.advance(n);
            // Reading opened the receive window; tell the peer.
            self.shared.wake.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let n = ready!(self.with_end(|s, end| {
            if s.can_send() {
                Poll::Ready(s.send_slice(data).map_err(io::Error::other))
            } else if !s.may_send() {
                let closed = || io::Error::new(io::ErrorKind::BrokenPipe, "connection closed");
                Poll::Ready(Err(end.and_then(End::error).unwrap_or_else(closed)))
            } else {
                s.register_send_waker(cx.waker());
                Poll::Pending
            }
        }))?;
        self.shared.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close_write();
        Poll::Ready(Ok(()))
    }
}

/// A connected UDP flow through the tunnel: each send is one datagram,
/// and each receive returns one datagram.
pub struct UdpConn {
    shared: Arc<Shared>,
    local: SocketAddr,
    remote: SocketAddr,
    /// The flow's sender. The flow table holds its only strong
    /// reference, so it's gone once the flow is out of the table.
    tx: mpsc::WeakSender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    idle_timeout: Mutex<Option<Duration>>,
    last_activity: Mutex<Instant>,
    closed: AtomicBool,
}

fn flow_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "UDP flow closed")
}

impl UdpConn {
    fn new(
        shared: Arc<Shared>,
        local: SocketAddr,
        remote: SocketAddr,
        tx: &mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        UdpConn {
            shared,
            local,
            remote,
            tx: tx.downgrade(),
            rx: tokio::sync::Mutex::new(rx),
            idle_timeout: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            closed: AtomicBool::new(false),
        }
    }

    /// Closes the flow after `d` without a successful send or receive.
    pub fn set_idle_timeout(&self, d: Option<Duration>) {
        *self.idle_timeout.lock().unwrap() = d;
    }

    /// Shortens the idle timeout to `d`, if it's longer or unset.
    pub(crate) fn limit_idle_timeout(&self, d: Duration) {
        let mut t = self.idle_timeout.lock().unwrap();
        *t = Some(t.map_or(d, |t| t.min(d)));
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    /// Whether the flow was closed, or the stack was.
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed) || self.tx.strong_count() == 0
    }

    /// The local address (the flow's destination, for inbound flows).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The remote address (the flow's source, for inbound flows).
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Receives one datagram into `buf`, truncating it if it's too big.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.rx.lock().await;
        let msg = loop {
            if self.is_closed() {
                return Err(flow_closed());
            }
            let idle = *self.idle_timeout.lock().unwrap();
            let Some(idle) = idle else { break rx.recv().await };
            let deadline = *self.last_activity.lock().unwrap() + idle;
            if let Ok(m) = tokio::time::timeout_at(deadline.into(), rx.recv()).await {
                break m;
            }
            // A send may have pushed the deadline back while we waited.
            if self.last_activity.lock().unwrap().elapsed() >= idle {
                self.close();
                return Err(io::Error::new(io::ErrorKind::TimedOut, "UDP flow idle"));
            }
        };
        let msg = msg.ok_or_else(flow_closed)?;
        self.touch();
        let n = msg.len().min(buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        Ok(n)
    }

    /// Sends one datagram.
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        if self.is_closed() {
            return Err(flow_closed());
        }
        if data.len() > 65507 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"));
        }
        let pkt = build_udp(self.local, self.remote, data)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mismatched address families"))?;
        (self.shared.out)(pkt);
        self.touch();
        Ok(data.len())
    }

    /// Closes the flow; later receives and sends fail.
    pub fn close(&self) {
        // Only once: by the next close (or the drop), a new flow may
        // have taken the 4-tuple.
        if !self.closed.swap(true, Ordering::Relaxed) {
            self.shared.lock().udp.remove(&(self.local, self.remote));
        }
    }
}

impl Drop for UdpConn {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Debug for UdpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UdpConn({} <-> {})", self.local, self.remote)
    }
}

/// Builds an IP/UDP packet with a valid checksum, or `None` if `src` and
/// `dst` are of different address families.
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    if src.is_ipv4() != dst.is_ipv4() {
        return None;
    }
    let (s, d) = (IpAddress::from(src.ip()), IpAddress::from(dst.ip()));
    let ip = IpRepr::new(s, d, IpProtocol::Udp, 8 + payload.len(), 64);
    let caps = ChecksumCapabilities::default();
    let mut buf = vec![0u8; ip.buffer_len()];
    ip.emit(&mut buf[..], &caps);
    let mut udp = UdpPacket::new_unchecked(&mut buf[ip.header_len()..]);
    UdpRepr { src_port: src.port(), dst_port: dst.port() }.emit(
        &mut udp,
        &s,
        &d,
        payload.len(),
        |b| b.copy_from_slice(payload),
        &caps,
    );
    Some(buf)
}

/// A boxed future, for handler signatures.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[cfg(test)]
mod model_tests;
#[cfg(test)]
mod tcp_model_tests;

#[cfg(test)]
mod udp_model_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn back_to_back(
        a_ip: IpAddr,
        b_ip: IpAddr,
        tcp_policy: Option<TcpPolicy>,
        udp_policy: Option<UdpPolicy>,
    ) -> (Stack, Stack) {
        let (to_b_tx, mut to_b_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (to_a_tx, mut to_a_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let b = Stack::new(
            StackConfig { addrs: vec![b_ip], any_ip: false, mtu: 1280 },
            Arc::new(move |p| {
                let _ = to_a_tx.send(p);
            }),
            tcp_policy,
            udp_policy,
        );
        let a = Stack::new(
            StackConfig { addrs: vec![a_ip], any_ip: false, mtu: 1280 },
            Arc::new(move |p| {
                let _ = to_b_tx.send(p);
            }),
            None,
            None,
        );
        let (a2, b2) = (a.clone(), b.clone());
        tokio::spawn(async move {
            while let Some(p) = to_b_rx.recv().await {
                b2.inject(p);
            }
        });
        tokio::spawn(async move {
            while let Some(p) = to_a_rx.recv().await {
                a2.inject(p);
            }
        });
        (a, b)
    }

    fn udp_echo() -> UdpPolicy {
        Arc::new(|_src, _dst| {
            Some(Box::new(|c: UdpConn| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    while let Ok(n) = c.recv(&mut buf).await {
                        c.send(&buf[..n]).await.unwrap();
                    }
                });
            }))
        })
    }

    /// Two stacks wired back to back: a client dials a server.
    #[tokio::test]
    async fn tcp_and_udp_between_two_stacks() {
        let a_ip: IpAddr = "fd7a:115c:a1e0::1".parse().unwrap();
        let b_ip: IpAddr = "fd7a:115c:a1e0::2".parse().unwrap();
        let tcp_policy: TcpPolicy = Arc::new(|_src, dst| match dst.port() {
            80 => TcpDecision::Accept(Box::new(|mut s: TcpStream| {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    s.read_to_end(&mut buf).await.unwrap();
                    s.write_all(b"got: ").await.unwrap();
                    s.write_all(&buf).await.unwrap();
                    s.shutdown().await.unwrap();
                    s.drain(Duration::from_secs(5)).await;
                });
            })),
            82 => TcpDecision::Drop,
            _ => TcpDecision::Reset,
        });
        let (a, _b) = back_to_back(a_ip, b_ip, Some(tcp_policy), Some(udp_echo()));

        let mut c = a.dial_tcp(a_ip, SocketAddr::new(b_ip, 80)).await.unwrap();
        assert_eq!(c.peer_addr(), SocketAddr::new(b_ip, 80));
        assert_eq!(c.local_addr().ip(), a_ip);
        let big = vec![b'x'; 300_000];
        c.write_all(&big).await.unwrap();
        c.shutdown().await.unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), 5 + big.len());
        assert!(got.starts_with(b"got: x"));

        let refused = a.dial_tcp(a_ip, SocketAddr::new(b_ip, 81)).await;
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);

        // A dropped SYN gets no answer at all.
        let dropped = tokio::time::timeout(Duration::from_millis(500), a.dial_tcp(a_ip, SocketAddr::new(b_ip, 82)));
        assert!(dropped.await.is_err(), "dropped SYN was answered");

        let u = a.dial_udp(a_ip, SocketAddr::new(b_ip, 53)).unwrap();
        u.send(b"ping").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), u.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"ping");
        drop(c);
        assert!(a.drain_tcp(Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn udp_over_ipv4_and_idle_timeout() {
        let a_ip: IpAddr = "100.64.0.1".parse().unwrap();
        let b_ip: IpAddr = "100.64.0.2".parse().unwrap();
        let (a, _b) = back_to_back(a_ip, b_ip, None, Some(udp_echo()));
        let u = a.dial_udp(a_ip, SocketAddr::new(b_ip, 7)).unwrap();
        u.send(b"v4").await.unwrap();
        let mut buf = [0u8; 1];
        // Datagrams too big for the buffer are truncated.
        let n = tokio::time::timeout(Duration::from_secs(5), u.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"v");

        u.set_idle_timeout(Some(Duration::from_millis(100)));
        let err = tokio::time::timeout(Duration::from_secs(5), u.recv(&mut buf)).await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(u.send(b"late").await.unwrap_err().kind(), io::ErrorKind::NotConnected);

        let mixed = a.dial_udp(a_ip, "[::1]:7".parse().unwrap()).unwrap();
        assert_eq!(mixed.send(b"x").await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn build_udp_checksums() {
        for (src, dst) in [("10.0.0.1:1000", "10.0.0.2:2000"), ("[fd00::1]:1000", "[fd00::2]:2000")] {
            let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
            let pkt = build_udp(src, dst, b"payload").unwrap();
            let caps = ChecksumCapabilities::default();
            let (ip_len, s, d) = if src.is_ipv4() {
                let ip = Ipv4Packet::new_checked(&pkt[..]).unwrap();
                assert!(ip.verify_checksum());
                (ip.header_len() as usize, ip.src_addr().into(), ip.dst_addr().into())
            } else {
                let ip = Ipv6Packet::new_checked(&pkt[..]).unwrap();
                (40, ip.src_addr().into(), ip.dst_addr().into())
            };
            assert_eq!((IpAddr::from(s), IpAddr::from(d)), (src.ip(), dst.ip()));
            let udp = UdpPacket::new_checked(&pkt[ip_len..]).unwrap();
            let repr = UdpRepr::parse(&udp, &s, &d, &caps).unwrap();
            assert_eq!((repr.src_port, repr.dst_port), (1000, 2000));
            assert_eq!(udp.payload(), b"payload");
        }
        assert!(build_udp("10.0.0.1:1".parse().unwrap(), "[::1]:1".parse().unwrap(), b"").is_none());
    }
}
