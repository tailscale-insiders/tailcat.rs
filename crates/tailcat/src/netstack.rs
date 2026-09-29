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
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, IpVersion, Ipv4Packet, Ipv4Repr,
    Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket, UdpRepr,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tracing::trace;

const TCP_BUFFER: usize = 512 << 10;
const UDP_QUEUE: usize = 512;
/// How long an accepted connection may take to complete its handshake.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Abort a connection whose peer stops acknowledging data for this long.
const TCP_TIMEOUT: Duration = Duration::from_secs(120);

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
    handler: Box<dyn FnOnce(TcpStream) + Send>,
    since: std::time::Instant,
}

struct State {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueueDevice,
    /// Inbound connections still completing their handshake.
    accepting: HashMap<SocketHandle, PendingAccept>,
    /// Every TCP socket's 4-tuple, to route SYN retransmits correctly.
    tuples: HashMap<FlowKey, SocketHandle>,
    /// Sockets no longer referenced by a TcpStream; they're removed once
    /// they finish closing.
    orphans: Vec<SocketHandle>,
    udp: HashMap<FlowKey, mpsc::Sender<Vec<u8>>>,
    next_port: u16,
    closed: bool,
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

/// A userspace TCP/IP stack.
#[derive(Clone)]
pub struct Stack {
    shared: Arc<Shared>,
}

fn now() -> smoltcp::time::Instant {
    smoltcp::time::Instant::now()
}

fn to_ip(a: IpAddress) -> IpAddr {
    match a {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6),
    }
}

fn from_ip(a: IpAddr) -> IpAddress {
    match a {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    }
}

fn sock(ep: IpEndpoint) -> SocketAddr {
    SocketAddr::new(to_ip(ep.addr), ep.port)
}

impl Stack {
    /// Creates a stack and starts its poll loop.
    pub fn new(cfg: StackConfig, out: Output, tcp_policy: Option<TcpPolicy>, udp_policy: Option<UdpPolicy>) -> Stack {
        let mut device = QueueDevice { mtu: cfg.mtu, ..Default::default() };
        let mut icfg = IfaceConfig::new(HardwareAddress::Ip);
        icfg.random_seed = rand::random();
        let mut iface = Interface::new(icfg, &mut device, now());
        iface.update_ip_addrs(|addrs| {
            for a in &cfg.addrs {
                let len = if a.is_ipv4() { 32 } else { 128 };
                let _ = addrs.push(IpCidr::new(from_ip(*a), len));
            }
        });
        // With Medium::Ip, egress just needs some route to exist.
        for a in &cfg.addrs {
            match a {
                IpAddr::V4(v4) => {
                    let _ = iface.routes_mut().add_default_ipv4_route(*v4);
                }
                IpAddr::V6(v6) => {
                    let _ = iface.routes_mut().add_default_ipv6_route(*v6);
                }
            }
        }
        iface.set_any_ip(cfg.any_ip);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                iface,
                sockets: SocketSet::new(Vec::new()),
                device,
                accepting: HashMap::new(),
                tuples: HashMap::new(),
                orphans: Vec::new(),
                udp: HashMap::new(),
                next_port: 32768 + (rand::random::<u16>() % 28000),
                closed: false,
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
        if pkt.is_empty() {
            return;
        }
        match pkt[0] >> 4 {
            6 => self.inject_v6(pkt),
            4 => self.inject_v4(pkt),
            _ => {}
        }
    }

    fn inject_v6(&self, pkt: Vec<u8>) {
        let Ok(ip) = Ipv6Packet::new_checked(&pkt[..]) else { return };
        let src = IpAddr::V6(ip.src_addr());
        let dst = IpAddr::V6(ip.dst_addr());
        let proto = ip.next_header();
        self.inject_transport(pkt, src, dst, proto, 40, IpVersion::Ipv6);
    }

    fn inject_v4(&self, pkt: Vec<u8>) {
        let Ok(ip) = Ipv4Packet::new_checked(&pkt[..]) else { return };
        let src = IpAddr::V4(ip.src_addr());
        let dst = IpAddr::V4(ip.dst_addr());
        let proto = ip.next_header();
        let off = ip.header_len() as usize;
        self.inject_transport(pkt, src, dst, proto, off, IpVersion::Ipv4);
    }

    fn inject_transport(&self, pkt: Vec<u8>, src: IpAddr, dst: IpAddr, proto: IpProtocol, off: usize, ver: IpVersion) {
        let body = &pkt[off.min(pkt.len())..];
        match proto {
            IpProtocol::Tcp => {
                let Ok(tcp) = TcpPacket::new_checked(body) else { return };
                let s = SocketAddr::new(src, tcp.src_port());
                let d = SocketAddr::new(dst, tcp.dst_port());
                let is_syn = tcp.syn() && !tcp.ack();
                let mut st = self.shared.state.lock().unwrap();
                if st.closed {
                    return;
                }
                if is_syn && !st.tuples.contains_key(&(d, s)) {
                    let decision = match &self.shared.tcp_policy {
                        Some(p) => {
                            // The policy may block briefly; don't hold the lock.
                            drop(st);
                            let dec = p(s, d);
                            st = self.shared.state.lock().unwrap();
                            dec
                        }
                        None => TcpDecision::Reset,
                    };
                    match decision {
                        TcpDecision::Drop => return,
                        TcpDecision::Reset => {} // smoltcp answers unmatched SYNs with RST
                        TcpDecision::Accept(handler) => {
                            if !st.tuples.contains_key(&(d, s)) {
                                let mut sock = new_tcp_socket();
                                if sock.listen(IpListenEndpoint { addr: Some(from_ip(dst)), port: d.port() }).is_err() {
                                    return;
                                }
                                let h = st.sockets.add(sock);
                                st.tuples.insert((d, s), h);
                                st.accepting.insert(h, PendingAccept { handler, since: std::time::Instant::now() });
                            }
                        }
                    }
                } else if !is_syn && !st.tuples.contains_key(&(d, s)) {
                    // Not part of any connection we know; let smoltcp RST it
                    // unless it's itself a RST.
                    if tcp.rst() {
                        return;
                    }
                }
                st.device.rx.push_back(pkt);
                drop(st);
                self.shared.wake.notify_one();
            }
            IpProtocol::Udp => {
                let Ok(udp) = UdpPacket::new_checked(body) else { return };
                let s = SocketAddr::new(src, udp.src_port());
                let d = SocketAddr::new(dst, udp.dst_port());
                let data = udp.payload().to_vec();
                let existing = self.shared.state.lock().unwrap().udp.get(&(d, s)).cloned();
                if let Some(tx) = existing {
                    if tx.try_send(data).is_err() && tx.is_closed() {
                        self.shared.state.lock().unwrap().udp.remove(&(d, s));
                    }
                    return;
                }
                let Some(policy) = &self.shared.udp_policy else { return };
                let Some(handler) = policy(s, d) else { return };
                let (tx, rx) = mpsc::channel(UDP_QUEUE);
                let _ = tx.try_send(data);
                self.shared.state.lock().unwrap().udp.insert((d, s), tx);
                handler(UdpConn::new(self.shared.clone(), d, s, rx));
            }
            IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                let _ = ver;
                let mut st = self.shared.state.lock().unwrap();
                st.device.rx.push_back(pkt);
                drop(st);
                self.shared.wake.notify_one();
            }
            _ => trace!("netstack: dropping protocol {proto}"),
        }
    }

    fn alloc_port(st: &mut State, local_ip: IpAddr) -> u16 {
        loop {
            let p = st.next_port;
            st.next_port = if st.next_port >= 60999 { 32768 } else { st.next_port + 1 };
            let in_use = st.tuples.keys().any(|(l, _)| l.ip() == local_ip && l.port() == p)
                || st.udp.keys().any(|(l, _)| l.ip() == local_ip && l.port() == p);
            if !in_use {
                return p;
            }
        }
    }

    /// Opens a TCP connection from `local_ip` to `remote`.
    pub async fn dial_tcp(&self, local_ip: IpAddr, remote: SocketAddr) -> io::Result<TcpStream> {
        let h = {
            let mut st = self.shared.state.lock().unwrap();
            let port = Self::alloc_port(&mut st, local_ip);
            let mut sock = new_tcp_socket();
            let State { iface, .. } = &mut *st;
            sock.connect(
                iface.context(),
                IpEndpoint::new(from_ip(remote.ip()), remote.port()),
                IpListenEndpoint { addr: Some(from_ip(local_ip)), port },
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("connect: {e}")))?;
            let h = st.sockets.add(sock);
            st.tuples.insert((SocketAddr::new(local_ip, port), remote), h);
            h
        };
        self.shared.wake.notify_one();
        let stream = TcpStream::new(self.shared.clone(), h);
        std::future::poll_fn(|cx| stream.poll_connected(cx)).await?;
        Ok(stream)
    }

    /// Opens a connected UDP flow from `local_ip` to `remote`.
    pub fn dial_udp(&self, local_ip: IpAddr, remote: SocketAddr) -> io::Result<UdpConn> {
        let mut st = self.shared.state.lock().unwrap();
        let port = Self::alloc_port(&mut st, local_ip);
        let local = SocketAddr::new(local_ip, port);
        let (tx, rx) = mpsc::channel(UDP_QUEUE);
        st.udp.insert((local, remote), tx);
        Ok(UdpConn::new(self.shared.clone(), local, remote, rx))
    }

    /// Waits until every TCP connection has finished closing, or until
    /// `timeout`. The whole TCP stack lives in this process, so exiting
    /// right after closing a connection can lose its final FIN or ACK;
    /// call this before exiting.
    pub async fn drain_tcp(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.shared.polled.notified();
            let busy = {
                let st = self.shared.state.lock().unwrap();
                st.sockets.iter().any(|(_, s)| match s {
                    smoltcp::socket::Socket::Tcp(t) => {
                        !matches!(t.state(), tcp::State::Closed | tcp::State::TimeWait | tcp::State::Listen)
                            || t.send_queue() > 0
                    }
                    #[allow(unreachable_patterns)]
                    _ => false,
                })
            };
            if !busy {
                // Let the final ACK make it out through the tunnel.
                tokio::time::sleep(Duration::from_millis(50)).await;
                return true;
            }
            self.shared.wake.notify_one();
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return false;
            }
        }
    }

    /// Stops the stack, aborting every connection.
    pub fn close(&self) {
        let mut st = self.shared.state.lock().unwrap();
        st.closed = true;
        let handles: Vec<SocketHandle> = st.sockets.iter().map(|(h, _)| h).collect();
        for h in handles {
            st.sockets.get_mut::<tcp::Socket>(h).abort();
        }
        st.udp.clear();
        drop(st);
        self.shared.wake.notify_one();
    }
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    let mut s =
        tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUFFER]), tcp::SocketBuffer::new(vec![0; TCP_BUFFER]));
    s.set_timeout(Some(smoltcp::time::Duration::from_secs(TCP_TIMEOUT.as_secs())));
    s.set_nagle_enabled(false);
    s.set_ack_delay(Some(smoltcp::time::Duration::from_millis(5)));
    s
}

async fn poll_loop(shared: Weak<Shared>) {
    loop {
        let Some(sh) = shared.upgrade() else { return };
        let (out, delay, accepted, closed) = {
            let mut guard = sh.state.lock().unwrap();
            let st = &mut *guard;
            st.iface.poll(now(), &mut st.device, &mut st.sockets);

            // Hand off inbound connections that finished their handshake,
            // and give up on ones that never did.
            let mut accepted = Vec::new();
            let mut dead = Vec::new();
            for (h, pa) in st.accepting.iter() {
                let s = st.sockets.get::<tcp::Socket>(*h);
                match s.state() {
                    tcp::State::Established | tcp::State::CloseWait => accepted.push(*h),
                    tcp::State::SynReceived => {
                        if pa.since.elapsed() > ACCEPT_TIMEOUT {
                            dead.push(*h);
                        }
                    }
                    tcp::State::Listen => {
                        // The SYN didn't take (or the handshake was reset).
                        if pa.since.elapsed() > Duration::from_secs(2) {
                            dead.push(*h);
                        }
                    }
                    _ => dead.push(*h),
                }
            }
            let accepted: Vec<(SocketHandle, PendingAccept)> =
                accepted.into_iter().map(|h| (h, st.accepting.remove(&h).unwrap())).collect();
            for h in dead {
                st.accepting.remove(&h);
                st.sockets.get_mut::<tcp::Socket>(h).abort();
                st.orphans.push(h);
            }

            // Reap closed sockets nobody holds any more.
            let mut keep = Vec::new();
            for h in std::mem::take(&mut st.orphans) {
                let s = st.sockets.get::<tcp::Socket>(h);
                if matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    st.sockets.remove(h);
                    st.tuples.retain(|_, v| *v != h);
                } else {
                    keep.push(h);
                }
            }
            st.orphans = keep;

            let out: Vec<Vec<u8>> = st.device.tx.drain(..).collect();
            let delay = st.iface.poll_delay(now(), &st.sockets);
            (out, delay, accepted, st.closed)
        };
        for p in out {
            (sh.out)(p);
        }
        for (h, pa) in accepted {
            (pa.handler)(TcpStream::new(sh.clone(), h));
        }
        sh.polled.notify_waiters();
        if closed {
            return;
        }
        let delay = delay.map(|d| Duration::from_micros(d.total_micros())).unwrap_or(Duration::from_secs(1));
        let wake = sh.wake.clone();
        drop(sh);
        if !delay.is_zero() {
            let _ = tokio::time::timeout(delay, wake.notified()).await;
        } else {
            tokio::task::yield_now().await;
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
    fn new(shared: Arc<Shared>, handle: SocketHandle) -> Self {
        let (local, remote) = {
            let mut st = shared.state.lock().unwrap();
            let s = st.sockets.get_mut::<tcp::Socket>(handle);
            let local = s.local_endpoint().map(sock);
            let remote = s.remote_endpoint().map(sock);
            let tuple = st.tuples.iter().find(|(_, h)| **h == handle).map(|(k, _)| *k);
            (
                local.or(tuple.map(|t| t.0)).unwrap_or_else(|| SocketAddr::from(([0u8; 16], 0))),
                remote.or(tuple.map(|t| t.1)).unwrap_or_else(|| SocketAddr::from(([0u8; 16], 0))),
            )
        };
        TcpStream { shared, handle, local, remote }
    }

    /// The local address (ours).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The remote address (the peer's).
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    fn with<R>(&self, f: impl FnOnce(&mut tcp::Socket<'static>) -> R) -> R {
        let mut st = self.shared.state.lock().unwrap();
        f(st.sockets.get_mut::<tcp::Socket>(self.handle))
    }

    fn poll_connected(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with(|s| match s.state() {
            tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
            tcp::State::Closed | tcp::State::TimeWait => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused")))
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
        self.with(|s| s.close());
        self.shared.wake.notify_one();
    }

    /// Aborts the connection with a RST.
    pub fn abort(&self) {
        self.with(|s| s.abort());
        self.shared.wake.notify_one();
    }

    /// Waits until everything sent has been acknowledged and, if the
    /// peer already closed its side, our FIN too (up to `timeout`).
    pub async fn drain(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.shared.polled.notified();
            let done = self.with(|s| {
                s.send_queue() == 0
                    && !matches!(s.state(), tcp::State::FinWait1 | tcp::State::Closing | tcp::State::LastAck)
            });
            if done {
                return;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
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
        let mut st = self.shared.state.lock().unwrap();
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        if s.is_open() {
            s.close();
        }
        st.orphans.push(self.handle);
        drop(st);
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let r = self.with(|s| {
            if s.can_recv() {
                match s.recv_slice(buf.initialize_unfilled()) {
                    Ok(n) => {
                        buf.advance(n);
                        Poll::Ready(Ok(true))
                    }
                    Err(e) => Poll::Ready(Err(io::Error::other(e.to_string()))),
                }
            } else if !s.may_recv() {
                match s.state() {
                    tcp::State::Closed if !s.is_open() => Poll::Ready(Ok(false)),
                    _ => Poll::Ready(Ok(false)),
                }
            } else {
                s.register_recv_waker(cx.waker());
                Poll::Pending
            }
        });
        match r {
            Poll::Ready(Ok(true)) => {
                // Reading opened the receive window; tell the peer.
                self.shared.wake.notify_one();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let r = self.with(|s| {
            if s.can_send() {
                Poll::Ready(s.send_slice(data).map_err(|e| io::Error::other(e.to_string())))
            } else if !s.may_send() {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "connection closed")))
            } else {
                s.register_send_waker(cx.waker());
                Poll::Pending
            }
        });
        if let Poll::Ready(Ok(_)) = r {
            self.shared.wake.notify_one();
        }
        r
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
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    idle_timeout: Mutex<Option<Duration>>,
    last_activity: Mutex<std::time::Instant>,
    closed: std::sync::atomic::AtomicBool,
}

impl UdpConn {
    fn new(shared: Arc<Shared>, local: SocketAddr, remote: SocketAddr, rx: mpsc::Receiver<Vec<u8>>) -> Self {
        UdpConn {
            shared,
            local,
            remote,
            rx: tokio::sync::Mutex::new(rx),
            idle_timeout: Mutex::new(None),
            last_activity: Mutex::new(std::time::Instant::now()),
            closed: Default::default(),
        }
    }

    /// Closes the flow after `d` without a successful send or receive.
    pub fn set_idle_timeout(&self, d: Option<Duration>) {
        *self.idle_timeout.lock().unwrap() = d;
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = std::time::Instant::now();
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
        loop {
            if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "UDP flow closed"));
            }
            let idle = *self.idle_timeout.lock().unwrap();
            let msg = match idle {
                None => rx.recv().await,
                Some(d) => {
                    let deadline = *self.last_activity.lock().unwrap() + d;
                    match tokio::time::timeout_at(deadline.into(), rx.recv()).await {
                        Ok(m) => m,
                        Err(_) => {
                            if self.last_activity.lock().unwrap().elapsed() >= d {
                                self.close();
                                return Err(io::Error::new(io::ErrorKind::TimedOut, "UDP flow idle"));
                            }
                            continue;
                        }
                    }
                }
            };
            let Some(msg) = msg else {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "UDP flow closed"));
            };
            self.touch();
            let n = msg.len().min(buf.len());
            buf[..n].copy_from_slice(&msg[..n]);
            return Ok(n);
        }
    }

    /// Sends one datagram.
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "UDP flow closed"));
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
        self.closed.store(true, std::sync::atomic::Ordering::Relaxed);
        self.shared.state.lock().unwrap().udp.remove(&(self.local, self.remote));
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

/// Builds an IP/UDP packet with a valid checksum.
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp = UdpRepr { src_port: src.port(), dst_port: dst.port() };
    let udp_len = 8 + payload.len();
    let caps = smoltcp::phy::ChecksumCapabilities::default();
    match (src.ip(), dst.ip()) {
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let ip = Ipv6Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let mut buf = vec![0u8; 40 + udp_len];
            let mut pkt = Ipv6Packet::new_unchecked(&mut buf[..]);
            ip.emit(&mut pkt);
            let mut u = UdpPacket::new_unchecked(&mut buf[40..]);
            udp.emit(
                &mut u,
                &IpAddress::Ipv6(s),
                &IpAddress::Ipv6(d),
                payload.len(),
                |b| b.copy_from_slice(payload),
                &caps,
            );
            Some(buf)
        }
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let ip = Ipv4Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let mut buf = vec![0u8; 20 + udp_len];
            let mut pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
            ip.emit(&mut pkt, &caps);
            let mut u = UdpPacket::new_unchecked(&mut buf[20..]);
            udp.emit(
                &mut u,
                &IpAddress::Ipv4(s),
                &IpAddress::Ipv4(d),
                payload.len(),
                |b| b.copy_from_slice(payload),
                &caps,
            );
            Some(buf)
        }
        _ => None,
    }
}

/// A boxed future, for handler signatures.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Two stacks wired back to back: a client dials a server.
    #[tokio::test]
    async fn tcp_and_udp_between_two_stacks() {
        let a_ip: IpAddr = "fd7a:115c:a1e0::1".parse().unwrap();
        let b_ip: IpAddr = "fd7a:115c:a1e0::2".parse().unwrap();
        let (to_b_tx, mut to_b_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (to_a_tx, mut to_a_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let tcp_policy: TcpPolicy = Arc::new(|_src, dst| {
            if dst.port() != 80 {
                return TcpDecision::Reset;
            }
            TcpDecision::Accept(Box::new(|mut s: TcpStream| {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    s.read_to_end(&mut buf).await.unwrap();
                    s.write_all(b"got: ").await.unwrap();
                    s.write_all(&buf).await.unwrap();
                    s.shutdown().await.unwrap();
                    s.drain(Duration::from_secs(5)).await;
                });
            }))
        });
        let udp_policy: UdpPolicy = Arc::new(|_src, _dst| {
            Some(Box::new(|c: UdpConn| {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    while let Ok(n) = c.recv(&mut buf).await {
                        c.send(&buf[..n]).await.unwrap();
                    }
                });
            }))
        });
        let b = Stack::new(
            StackConfig { addrs: vec![b_ip], any_ip: false, mtu: 1280 },
            Arc::new(move |p| {
                let _ = to_a_tx.send(p);
            }),
            Some(tcp_policy),
            Some(udp_policy),
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

        let mut c = a.dial_tcp(a_ip, SocketAddr::new(b_ip, 80)).await.unwrap();
        let big = vec![b'x'; 300_000];
        c.write_all(&big).await.unwrap();
        c.shutdown().await.unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), 5 + big.len());
        assert!(got.starts_with(b"got: x"));

        let refused = a.dial_tcp(a_ip, SocketAddr::new(b_ip, 81)).await;
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);

        let u = a.dial_udp(a_ip, SocketAddr::new(b_ip, 53)).unwrap();
        u.send(b"ping").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), u.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"ping");
        drop(c);
        assert!(a.drain_tcp(Duration::from_secs(5)).await);
    }
}
