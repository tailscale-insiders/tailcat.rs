//! Model-based tests of inbound TCP handling, driven by Hegel. Remote
//! peers send raw SYN, ACK, data, FIN and RST segments to the stack in
//! generated orders, and every connection handed to a handler is checked
//! against the peer it is really connected to, the policy's decision for
//! it, and what that peer sent.

use std::collections::HashSet;
use std::task::Waker;

use hegel::TestCase;
use hegel::generators as gs;
use smoltcp::wire::{TcpControl, TcpRepr, TcpSeqNumber};

use super::*;

const PORTS: [u16; 2] = [80, 81];

fn local_ip() -> IpAddr {
    "fd7a:115c:a1e0::1".parse().unwrap()
}

/// The policy refuses every connection from this address.
fn denied_ip() -> IpAddr {
    "fd7a:115c:a1e0::bad".parse().unwrap()
}

/// Two remote endpoints on an allowed address and one on the denied one.
fn remotes() -> [SocketAddr; 3] {
    let allowed: IpAddr = "fd7a:115c:a1e0::2".parse().unwrap();
    [SocketAddr::new(allowed, 1000), SocketAddr::new(allowed, 1001), SocketAddr::new(denied_ip(), 1000)]
}

/// A raw TCP segment.
pub(super) fn segment(
    src: SocketAddr,
    dst: SocketAddr,
    control: TcpControl,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    payload: &[u8],
) -> Vec<u8> {
    let repr = TcpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
        control,
        seq_number: seq,
        ack_number: ack,
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    };
    let (s, d) = (IpAddress::from(src.ip()), IpAddress::from(dst.ip()));
    let ip = IpRepr::new(s, d, IpProtocol::Tcp, repr.buffer_len(), 64);
    let caps = ChecksumCapabilities::default();
    let mut buf = vec![0u8; ip.buffer_len()];
    ip.emit(&mut buf[..], &caps);
    repr.emit(&mut TcpPacket::new_unchecked(&mut buf[ip.header_len()..]), &s, &d, &caps);
    buf
}

/// A remote's side of one connection attempt, and what the stack handed
/// the policy's handler for it.
struct Conn {
    remote: SocketAddr,
    port: u16,
    isn: TcpSeqNumber,
    /// The stack's initial sequence number, once its SYN-ACK arrives.
    server_isn: Option<TcpSeqNumber>,
    /// Whether the stack has sent its FIN.
    server_fin: bool,
    /// Whether the remote has completed the handshake.
    established: bool,
    /// The payload the remote has sent.
    sent: Vec<u8>,
    /// Whether the remote has sent a FIN, and whether it has sent a RST.
    fin: bool,
    reset: bool,
    /// The connection handed to the handler, until the handler drops it.
    stream: Option<TcpStream>,
    /// What reading `stream` returned: the data, then how it ended.
    received: Vec<u8>,
    end: Option<Result<(), io::ErrorKind>>,
}

impl Conn {
    /// The sequence number of the remote's next segment.
    fn seq(&self) -> TcpSeqNumber {
        self.isn + 1 + self.sent.len() + usize::from(self.fin)
    }

    /// The acknowledgment number the remote sends.
    fn ack(&self) -> Option<TcpSeqNumber> {
        self.server_isn.map(|isn| isn + 1 + usize::from(self.server_fin))
    }

    fn local(&self) -> SocketAddr {
        SocketAddr::new(local_ip(), self.port)
    }

    /// Reads whatever `stream` has, without waiting.
    fn read(&mut self) {
        let Some(s) = &mut self.stream else { return };
        let mut cx = Context::from_waker(Waker::noop());
        while self.end.is_none() {
            let mut buf = [0u8; 64];
            let mut rb = ReadBuf::new(&mut buf);
            match Pin::new(&mut *s).poll_read(&mut cx, &mut rb) {
                Poll::Ready(Ok(())) if rb.filled().is_empty() => self.end = Some(Ok(())),
                Poll::Ready(Ok(())) => self.received.extend_from_slice(rb.filled()),
                Poll::Ready(Err(e)) => self.end = Some(Err(e.kind())),
                Poll::Pending => break,
            }
        }
    }
}

struct Net {
    rt: tokio::runtime::Runtime,
    stack: Stack,
    out: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Handed-off connections, with the remote the policy decided on.
    accepted: Arc<Mutex<Vec<(SocketAddr, TcpStream)>>>,
    conns: Vec<Conn>,
    /// The attempt in progress for each (remote, local port), as an
    /// index into `conns`.
    live: HashMap<(SocketAddr, u16), usize>,
    next_isn: i32,
}

impl Net {
    fn new() -> Net {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _guard = rt.enter();
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let accepted: Arc<Mutex<Vec<(SocketAddr, TcpStream)>>> = Arc::default();
        let (o, a) = (out.clone(), accepted.clone());
        let policy: TcpPolicy = Arc::new(move |src, _dst| {
            if src.ip() == denied_ip() {
                return TcpDecision::Reset;
            }
            let a = a.clone();
            TcpDecision::Accept(Box::new(move |s| a.lock().unwrap().push((src, s))))
        });
        let stack = Stack::new(
            StackConfig { addrs: vec![local_ip()], any_ip: false, mtu: 1280 },
            Arc::new(move |p| o.lock().unwrap().push(p)),
            Some(policy),
            None,
        );
        Net { rt, stack, out, accepted, conns: Vec::new(), live: HashMap::new(), next_isn: 1000 }
    }

    /// Injects a segment and lets the stack handle it.
    fn send(&mut self, pkt: Vec<u8>) {
        self.stack.inject(pkt);
        self.settle();
    }

    /// Lets the poll loop run, applies the stack's replies to the
    /// remotes' state, takes the handler's new connections, and reads
    /// what they have.
    fn settle(&mut self) {
        self.rt.block_on(async {
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
        });
        for p in std::mem::take(&mut *self.out.lock().unwrap()) {
            let ip = Ipv6Packet::new_checked(&p[..]).unwrap();
            let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else { continue };
            let key = (SocketAddr::new(IpAddr::from(ip.dst_addr()), tcp.dst_port()), tcp.src_port());
            if tcp.rst() {
                self.live.remove(&key);
                continue;
            }
            let Some(c) = self.live.get(&key).map(|&i| &mut self.conns[i]) else { continue };
            if tcp.syn() && tcp.ack() {
                c.server_isn = Some(tcp.seq_number());
            }
            if tcp.fin() {
                c.server_fin = true;
            }
        }
        for (decided_for, s) in std::mem::take(&mut *self.accepted.lock().unwrap()) {
            // The latest attempt on the flow the policy decided on.
            let port = s.local_addr().port();
            let c = self
                .conns
                .iter_mut()
                .rev()
                .find(|c| (c.remote, c.port) == (decided_for, port))
                .unwrap_or_else(|| panic!("{s:?} was accepted for {decided_for}, which never connected"));
            assert!(c.stream.is_none() && c.end.is_none(), "{decided_for} -> {port} was accepted twice");
            c.stream = Some(s);
        }
        self.conns.iter_mut().for_each(Conn::read);
    }

    fn draw_flow(&self, tc: &TestCase) -> (SocketAddr, u16) {
        let r = remotes()[tc.draw(gs::integers::<usize>().max_value(remotes().len() - 1))];
        let port = PORTS[tc.draw(gs::integers::<usize>().max_value(PORTS.len() - 1))];
        (r, port)
    }

    fn live(&self, flow: (SocketAddr, u16)) -> Option<&Conn> {
        self.live.get(&flow).map(|&i| &self.conns[i])
    }

    /// Sends a SYN from `r` to `port`: a new attempt, or a retransmit.
    fn syn(&mut self, r: SocketAddr, port: u16) {
        let i = match self.live.get(&(r, port)) {
            Some(&i) => i,
            None => {
                self.next_isn += 1000;
                self.conns.push(Conn {
                    remote: r,
                    port,
                    isn: TcpSeqNumber(self.next_isn),
                    server_isn: None,
                    server_fin: false,
                    established: false,
                    sent: Vec::new(),
                    fin: false,
                    reset: false,
                    stream: None,
                    received: Vec::new(),
                    end: None,
                });
                self.live.insert((r, port), self.conns.len() - 1);
                self.conns.len() - 1
            }
        };
        let c = &self.conns[i];
        self.send(segment(r, c.local(), TcpControl::Syn, c.isn, None, &[]));
    }

    /// Sends an ACK (completing the handshake, the first time), with a
    /// FIN or some data if given.
    fn ack(&mut self, flow: (SocketAddr, u16), control: TcpControl, payload: &[u8]) {
        let Some(&i) = self.live.get(&flow) else { return };
        let c = &mut self.conns[i];
        let Some(ack) = c.ack() else { return };
        let pkt = segment(c.remote, c.local(), control, c.seq(), Some(ack), payload);
        c.established = true;
        c.sent.extend_from_slice(payload);
        c.fin |= control == TcpControl::Fin;
        self.send(pkt);
    }

    /// Sends a RST, ending the attempt.
    fn rst(&mut self, flow: (SocketAddr, u16)) {
        let Some(i) = self.live.remove(&flow) else { return };
        let c = &mut self.conns[i];
        c.reset = true;
        let pkt = segment(c.remote, c.local(), TcpControl::Rst, c.seq(), None, &[]);
        self.send(pkt);
    }
}

/// Where a stream's smoltcp socket is really connected, if it is.
fn actual_remote(s: &TcpStream) -> Option<SocketAddr> {
    s.with(|sock| sock.remote_endpoint()).map(socket_addr)
}

#[hegel::state_machine]
impl Net {
    /// A remote opens a connection (or retransmits its SYN).
    #[rule]
    fn open(&mut self, tc: TestCase) {
        let (r, port) = self.draw_flow(&tc);
        self.syn(r, port);
    }

    /// A remote that got a SYN-ACK completes the handshake (or acks the
    /// stack's FIN).
    #[rule]
    fn complete(&mut self, tc: TestCase) {
        let flow = self.draw_flow(&tc);
        self.ack(flow, TcpControl::None, &[]);
    }

    /// A connected remote sends some data.
    #[rule]
    fn data(&mut self, tc: TestCase) {
        let flow = self.draw_flow(&tc);
        let payload = tc.draw(gs::binary().min_size(1).max_size(16));
        if self.live(flow).is_some_and(|c| c.established && !c.fin) {
            self.ack(flow, TcpControl::Psh, &payload);
        }
    }

    /// A connected remote closes its side.
    #[rule]
    fn fin(&mut self, tc: TestCase) {
        let flow = self.draw_flow(&tc);
        if self.live(flow).is_some_and(|c| c.established && !c.fin) {
            self.ack(flow, TcpControl::Fin, &[]);
        }
    }

    /// A remote gives up on a connection with a RST.
    #[rule]
    fn reset(&mut self, tc: TestCase) {
        let flow = self.draw_flow(&tc);
        self.rst(flow);
    }

    /// A handler drops its connection.
    #[rule]
    fn drop_stream(&mut self, tc: TestCase) {
        let held: Vec<usize> = (0..self.conns.len()).filter(|&i| self.conns[i].stream.is_some()).collect();
        if held.is_empty() {
            return;
        }
        let i = held[tc.draw(gs::integers::<usize>().max_value(held.len() - 1))];
        self.conns[i].stream = None;
        self.settle();
    }

    /// Every accepted connection reports the peer it's really connected
    /// to, and that peer is the one the policy accepted.
    #[invariant(always_run)]
    fn accepted_connections_match_their_peers(&self, _: TestCase) {
        for c in &self.conns {
            let Some(s) = &c.stream else { continue };
            let Some(actual) = actual_remote(s) else { continue };
            assert_ne!(actual.ip(), denied_ip(), "the policy refused {actual}, but its connection was accepted");
            assert_eq!(actual, c.remote, "the policy decided on {}, but the connection is from {actual}", c.remote);
            assert_eq!(s.peer_addr(), actual, "peer_addr() is wrong");
        }
    }

    /// Handlers read exactly what their peer sent, and then a clean end
    /// of stream if the peer closed the connection, or an error if it
    /// reset it.
    #[invariant(always_run)]
    fn reads_match_what_was_sent(&self, _: TestCase) {
        for c in &self.conns {
            let flow = format!("{} -> {}", c.remote, c.port);
            assert!(c.sent.starts_with(&c.received), "{flow} read {:?}, but sent {:?}", c.received, c.sent);
            match c.end {
                Some(Ok(())) => {
                    assert!(c.fin, "{flow} read EOF, but never sent a FIN");
                    assert_eq!(c.received, c.sent, "{flow} read EOF before all its data");
                }
                Some(Err(kind)) => {
                    assert!(c.reset && !c.fin, "{flow} read error {kind:?}, but wasn't reset");
                    assert_eq!(kind, io::ErrorKind::ConnectionReset, "{flow} was reset");
                }
                None if c.stream.is_some() && c.fin => panic!("{flow} sent a FIN, but reads don't end"),
                None if c.stream.is_some() && c.reset => panic!("{flow} was reset, but reads don't fail"),
                None => {}
            }
        }
    }

    /// The flow table agrees with where each socket is really connected.
    #[invariant(always_run)]
    fn tuples_match_sockets(&self, _: TestCase) {
        let st = self.stack.shared.lock();
        for (&(local, remote), &h) in &st.tuples {
            let s = st.sockets.get::<tcp::Socket>(h);
            if let Some(ep) = s.remote_endpoint() {
                let actual = socket_addr(ep);
                assert_eq!(actual, remote, "socket for {remote} -> {local} is connected to {actual}");
            }
        }
    }

    /// Every socket has exactly one flow, and sockets that finished
    /// closing are removed once nobody holds them.
    #[invariant(always_run)]
    fn sockets_are_reaped(&self, _: TestCase) {
        let st = self.stack.shared.lock();
        let held: HashSet<SocketHandle> = self.conns.iter().filter_map(|c| Some(c.stream.as_ref()?.handle)).collect();
        let live: HashSet<SocketHandle> = st.sockets.iter().map(|(h, _)| h).collect();
        for (h, s) in st.sockets.iter() {
            let flows: Vec<_> = st.tuples.iter().filter(|&(_, &v)| v == h).map(|(k, _)| k).collect();
            assert_eq!(flows.len(), 1, "socket {h} has flows {flows:?}");
            let state = tcp::Socket::downcast(s).unwrap().state();
            if matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
                assert!(
                    held.contains(&h) || st.accepting.contains_key(&h),
                    "{state} socket for {flows:?} is left over"
                );
            }
        }
        assert!(st.tuples.values().all(|h| live.contains(h)), "a flow's socket was removed");
        assert!(st.ends.keys().all(|h| live.contains(h)), "a removed socket's end is kept");
    }
}

#[hegel::test(test_cases = 300)]
fn inbound_tcp_state_machine(tc: TestCase) {
    hegel::stateful::machine(Net::new()).steps(30).run(tc);
}

/// The shortest path to the bug the state machine found, with the second
/// connection coming from an address the policy refuses: after a RST
/// sent the first flow's socket back to Listen, it took the refused
/// peer's SYN.
#[test]
fn refused_peer_cannot_take_over_a_listening_socket() {
    let mut net = Net::new();
    let [a, _, bad] = remotes();
    net.syn(a, 80);
    net.rst((a, 80));
    net.syn(bad, 80);
    net.ack((bad, 80), TcpControl::None, &[]);
    let accepted: Vec<_> =
        net.conns.iter().filter_map(|c| Some((c.remote, actual_remote(c.stream.as_ref()?)))).collect();
    assert!(accepted.iter().all(|(_, actual)| *actual != Some(bad)), "refused peer {bad} was accepted: {accepted:?}");
}

/// A connection the peer resets must not read as a clean end of stream:
/// callers that copy until EOF would otherwise report a truncated
/// transfer as complete. A connection the peer closes still does.
#[test]
fn reset_is_not_eof() {
    let mut net = Net::new();
    let [a, b, _] = remotes();
    for r in [a, b] {
        net.syn(r, 80);
        net.ack((r, 80), TcpControl::None, &[]);
        net.ack((r, 80), TcpControl::Psh, b"partial");
    }
    net.rst((a, 80));
    net.ack((b, 80), TcpControl::Fin, &[]);
    let ends: Vec<_> = net.conns.iter().map(|c| (c.remote, c.received.clone(), c.end)).collect();
    assert_eq!(
        ends,
        [(a, b"partial".to_vec(), Some(Err(io::ErrorKind::ConnectionReset))), (b, b"partial".to_vec(), Some(Ok(()))),]
    );
}
