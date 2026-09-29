//! Model-based tests of inbound TCP handling, driven by Hegel. Remote
//! peers send raw SYN, ACK and RST segments to the stack in generated
//! orders, and every connection handed to a handler is checked against
//! the peer it is really connected to and the policy's decision for it.

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

/// A raw TCP segment with no payload.
fn segment(
    src: SocketAddr,
    dst: SocketAddr,
    control: TcpControl,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
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
        payload: &[],
    };
    let (s, d) = (IpAddress::from(src.ip()), IpAddress::from(dst.ip()));
    let ip = IpRepr::new(s, d, IpProtocol::Tcp, repr.buffer_len(), 64);
    let caps = ChecksumCapabilities::default();
    let mut buf = vec![0u8; ip.buffer_len()];
    ip.emit(&mut buf[..], &caps);
    repr.emit(&mut TcpPacket::new_unchecked(&mut buf[ip.header_len()..]), &s, &d, &caps);
    buf
}

/// A remote's side of one connection attempt.
struct Attempt {
    isn: TcpSeqNumber,
    /// The stack's initial sequence number, once its SYN-ACK arrives.
    server_isn: Option<TcpSeqNumber>,
}

struct Net {
    rt: tokio::runtime::Runtime,
    stack: Stack,
    out: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Handed-off connections, with the remote the policy decided on.
    accepted: Arc<Mutex<Vec<(SocketAddr, TcpStream)>>>,
    attempts: HashMap<(SocketAddr, u16), Attempt>,
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
        Net { rt, stack, out, accepted, attempts: HashMap::new(), next_isn: 1000 }
    }

    /// Injects a segment, lets the poll loop run, and applies the
    /// stack's replies to the remotes' state.
    fn send(&mut self, pkt: Vec<u8>) {
        self.stack.inject(pkt);
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
                self.attempts.remove(&key);
            } else if tcp.syn()
                && tcp.ack()
                && let Some(a) = self.attempts.get_mut(&key)
            {
                a.server_isn = Some(tcp.seq_number());
            }
        }
    }

    fn draw_flow(&self, tc: &TestCase) -> (SocketAddr, SocketAddr) {
        let r = remotes()[tc.draw(gs::integers::<usize>().max_value(remotes().len() - 1))];
        let port = PORTS[tc.draw(gs::integers::<usize>().max_value(PORTS.len() - 1))];
        (r, SocketAddr::new(local_ip(), port))
    }
}

/// Where a stream's smoltcp socket is really connected, if it is.
fn actual_remote(s: &TcpStream) -> Option<SocketAddr> {
    s.with(|sock| sock.remote_endpoint()).map(|ep| SocketAddr::new(IpAddr::from(ep.addr), ep.port))
}

#[hegel::state_machine]
impl Net {
    /// A remote opens a connection (or retransmits its SYN).
    #[rule]
    fn syn(&mut self, tc: TestCase) {
        let (r, l) = self.draw_flow(&tc);
        let isn = match self.attempts.get(&(r, l.port())) {
            Some(a) => a.isn,
            None => {
                self.next_isn += 1000;
                let isn = TcpSeqNumber(self.next_isn);
                self.attempts.insert((r, l.port()), Attempt { isn, server_isn: None });
                isn
            }
        };
        self.send(segment(r, l, TcpControl::Syn, isn, None));
    }

    /// A remote that got a SYN-ACK completes the handshake.
    #[rule]
    fn ack(&mut self, tc: TestCase) {
        let (r, l) = self.draw_flow(&tc);
        let Some(Attempt { isn, server_isn: Some(server_isn) }) = self.attempts.get(&(r, l.port())) else {
            return;
        };
        let pkt = segment(r, l, TcpControl::None, *isn + 1, Some(*server_isn + 1));
        self.send(pkt);
    }

    /// A remote gives up on a connection with a RST.
    #[rule]
    fn rst(&mut self, tc: TestCase) {
        let (r, l) = self.draw_flow(&tc);
        let Some(a) = self.attempts.remove(&(r, l.port())) else { return };
        self.send(segment(r, l, TcpControl::Rst, a.isn + 1, None));
    }

    /// Every accepted connection reports the peer it's really connected
    /// to, and that peer is the one the policy accepted.
    #[invariant(always_run)]
    fn accepted_connections_match_their_peers(&self, _: TestCase) {
        for (decided_for, s) in self.accepted.lock().unwrap().iter() {
            let Some(actual) = actual_remote(s) else { continue };
            assert_ne!(actual.ip(), denied_ip(), "the policy refused {actual}, but its connection was accepted");
            assert_eq!(
                actual, *decided_for,
                "the policy decided on {decided_for}, but the connection is from {actual}"
            );
            assert_eq!(s.peer_addr(), actual, "peer_addr() is wrong");
        }
    }

    /// The flow table agrees with where each socket is really connected.
    #[invariant(always_run)]
    fn tuples_match_sockets(&self, _: TestCase) {
        let st = self.stack.shared.lock();
        for (&(local, remote), &h) in &st.tuples {
            let s = st.sockets.get::<tcp::Socket>(h);
            if let Some(ep) = s.remote_endpoint() {
                let actual = SocketAddr::new(IpAddr::from(ep.addr), ep.port);
                assert_eq!(actual, remote, "socket for {remote} -> {local} is connected to {actual}");
            }
        }
    }
}

#[hegel::test(test_cases = 300)]
#[ignore = "known bug: a socket reset back to Listen takes another peer's SYN"]
fn inbound_tcp_state_machine(tc: TestCase) {
    hegel::stateful::machine(Net::new()).steps(30).run(tc);
}

/// The shortest path to the bug the state machine finds, with the second
/// connection coming from an address the policy refuses: after a RST
/// sends the first flow's socket back to Listen, it takes the refused
/// peer's SYN.
#[test]
#[ignore = "known bug: a socket reset back to Listen takes another peer's SYN"]
fn refused_peer_cannot_take_over_a_listening_socket() {
    let mut net = Net::new();
    let [a, _, bad] = remotes();
    let l = SocketAddr::new(local_ip(), 80);
    net.attempts.insert((a, 80), Attempt { isn: TcpSeqNumber(1), server_isn: None });
    net.send(segment(a, l, TcpControl::Syn, TcpSeqNumber(1), None));
    net.send(segment(a, l, TcpControl::Rst, TcpSeqNumber(2), None));
    net.attempts.insert((bad, 80), Attempt { isn: TcpSeqNumber(100), server_isn: None });
    net.send(segment(bad, l, TcpControl::Syn, TcpSeqNumber(100), None));
    if let Some(server_isn) = net.attempts.get(&(bad, 80)).and_then(|a| a.server_isn) {
        net.send(segment(bad, l, TcpControl::None, TcpSeqNumber(101), Some(server_isn + 1)));
    }
    let accepted: Vec<_> =
        net.accepted.lock().unwrap().iter().map(|(p, s)| (*p, s.peer_addr(), actual_remote(s))).collect();
    assert!(
        accepted.iter().all(|(_, _, actual)| *actual != Some(bad)),
        "refused peer {bad} was accepted: (decided for, peer_addr, actual) = {accepted:?}"
    );
}

/// A connection the peer resets must not read as a clean end of stream:
/// callers that copy until EOF would otherwise report a truncated
/// transfer as complete.
#[test]
#[ignore = "known bug: a reset reads as a clean EOF"]
fn reset_is_not_eof() {
    let mut net = Net::new();
    let (r, l) = (remotes()[0], SocketAddr::new(local_ip(), 80));
    net.attempts.insert((r, 80), Attempt { isn: TcpSeqNumber(1), server_isn: None });
    net.send(segment(r, l, TcpControl::Syn, TcpSeqNumber(1), None));
    let server_isn = net.attempts[&(r, 80)].server_isn.expect("SYN-ACK");
    net.send(segment(r, l, TcpControl::None, TcpSeqNumber(2), Some(server_isn + 1)));
    let (_, mut s) = net.accepted.lock().unwrap().pop().expect("accepted");
    net.send(segment(r, l, TcpControl::Rst, TcpSeqNumber(2), None));
    let res = net.rt.block_on(async { tokio::io::AsyncReadExt::read(&mut s, &mut [0u8; 16]).await });
    assert!(res.is_err(), "a reset connection read as {res:?}");
}
