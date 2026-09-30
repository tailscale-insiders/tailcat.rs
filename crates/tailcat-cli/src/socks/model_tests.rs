//! Model-based tests of SOCKS UDP associations, driven by Hegel. A
//! SOCKS client sends bursts of datagrams through one proxy to echoing
//! flows on a tailcat server and to a destination that can't be dialed,
//! and opens new associations along the way. Each association's request
//! names the client's address, or leaves its IP or port unspecified, and
//! datagrams come from two local sockets: only the client's may use the
//! association (RFC 1928 §7). Every datagram the client sends to a flow
//! that opens must come back to it exactly once and in order, nothing
//! may come back to any other socket, and an association's tasks must
//! end with its control connection.

use std::mem;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

use hegel::TestCase;
use hegel::generators as gs;
use tailcat::Server;
use tailcat::derp::server::DevDerp;
use tokio::runtime::{self, Runtime};
use tokio::time::{Instant, sleep, timeout, timeout_at};

use super::tests::{datagram, global, udp_associate_via, udp_echo_server};
use super::*;

/// The proxy, a tailcat server that echoes every UDP flow, and the relay
/// they share, set up once for every test case.
struct World {
    rt: Runtime,
    proxy: SocketAddr,
    echo: Addr,
    _dev: DevDerp,
    _server: Server,
}

/// Brings `c`'s tunnel up, which can lose the first datagrams, and gives
/// the direct path to `server` a moment: a path switch mid-test could
/// reorder datagrams in flight.
async fn warm_up(c: &Client, server: &Server) {
    let u = c.dial_udp_port(9).await.unwrap();
    let mut buf = [0u8; 16];
    loop {
        u.send(b"up").await.unwrap();
        if let Ok(Ok(_)) = timeout(Duration::from_millis(500), u.recv(&mut buf)).await {
            break;
        }
    }
    let ms = c.magicsock().unwrap();
    for _ in 0..30 {
        if ms.peer_path(&server.public_key()).and_then(|p| p.direct()).is_some() {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Runs a proxy with no default server that dials `server` with `echo`,
/// and returns its address.
async fn proxy_to(server: &Server, echo: Client, key: NodePrivate) -> SocketAddr {
    let clients = Mutex::new(HashMap::from([(server.tailcat_addr(), echo)]));
    let d = Dialer { g: global(), key, default: None, clients };
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = ln.local_addr().unwrap();
    tokio::spawn(serve(ln, Arc::new(d)));
    proxy
}

fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let rt = runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let (dev, server, proxy) = rt.block_on(async {
            let dev = DevDerp::start_local().await.unwrap();
            let server = udp_echo_server(&dev).await;
            let key = NodePrivate::generate();
            let echo = crate::client::new_client(&global(), server.tailcat_addr(), key.clone());
            warm_up(&echo, &server).await;
            let proxy = proxy_to(&server, echo, key).await;
            (dev, server, proxy)
        });
        let echo = server.tailcat_addr();
        World { rt, proxy, echo, _dev: dev, _server: server }
    })
}

/// Echoing flows on two ports, and `server.tailcat`, which a proxy with
/// no server argument can't dial.
fn dsts(w: &World) -> [(String, u16); 3] {
    [(w.echo.to_string(), 1), (w.echo.to_string(), 2), ("server.tailcat".into(), 3)]
}

const UNDIALABLE: usize = 2;

/// The destinations whose flows open.
fn dialable() -> impl Iterator<Item = usize> {
    (0..3).filter(|&i| i != UNDIALABLE)
}

/// How many local sockets send datagrams to each association.
const SOCKETS: usize = 2;

/// The client address in a UDP ASSOCIATE request: an IP address
/// (unspecified, the one the sockets send from, or another), and a port
/// (0, or one of the association's sockets').
#[derive(Debug, Clone, Copy)]
struct Request {
    ip: IpAddr,
    socket: Option<usize>,
}

impl Request {
    const UNSPECIFIED: Request = Request { ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED), socket: None };

    fn draw(tc: &TestCase) -> Request {
        let ips = ["0.0.0.0", "127.0.0.1", "192.0.2.1"].map(|ip| ip.parse::<IpAddr>().unwrap());
        let ip = tc.draw(gs::sampled_from(&ips));
        let socket = tc.draw(gs::integers::<usize>().max_value(SOCKETS)).checked_sub(1);
        Request { ip, socket }
    }
}

struct Assoc {
    ctrl: TcpStream,
    relay: SocketAddr,
    socks: [UdpSocket; SOCKETS],
    /// The client address the request gave.
    want: SocketAddr,
}

/// `SOCKETS` local UDP sockets.
async fn bind_sockets() -> [UdpSocket; SOCKETS] {
    let mut socks = Vec::new();
    for _ in 0..SOCKETS {
        socks.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    }
    socks.try_into().unwrap()
}

async fn associate(proxy: SocketAddr, req: Request) -> Assoc {
    let socks = bind_sockets().await;
    let port = req.socket.map_or(0, |i| socks[i].local_addr().unwrap().port());
    let want = SocketAddr::new(req.ip, port);
    let (ctrl, relay) = udp_associate_via(proxy, want).await;
    Assoc { ctrl, relay, socks, want }
}

struct Socks {
    w: &'static World,
    dsts: [(String, u16); 3],
    assoc: Assoc,
    /// The socket the association took for the client's, once it has.
    client: Option<usize>,
    /// The sequence numbers the client sent to each destination, and
    /// those echoed back so far, in this association.
    sent: [Vec<u32>; 3],
    got: [Vec<u32>; 3],
    next: u32,
}

impl Socks {
    fn new(req: Request) -> Socks {
        let w = world();
        let assoc = w.rt.block_on(associate(w.proxy, req));
        Socks { w, dsts: dsts(w), assoc, client: None, sent: Default::default(), got: Default::default(), next: 0 }
    }

    /// Whether the association takes a datagram from socket `j`: only
    /// from the client's address, which is the request's, with the
    /// control connection's IP for an unspecified one and the first
    /// datagram's port for port 0.
    fn admits(&mut self, j: usize) -> bool {
        let a = &self.assoc;
        let from = a.socks[j].local_addr().unwrap();
        let ip = if a.want.ip().is_unspecified() { a.ctrl.local_addr().unwrap().ip() } else { a.want.ip() };
        let port = match (a.want.port(), self.client) {
            (0, Some(c)) => a.socks[c].local_addr().unwrap().port(),
            (0, None) => from.port(),
            (p, _) => p,
        };
        let ok = from == SocketAddr::new(ip, port);
        if ok {
            self.client = Some(j);
        }
        ok
    }

    /// Sends `n` datagrams to destination `i` from socket `j`.
    fn burst(&mut self, i: usize, j: usize, n: usize) {
        let (host, port) = self.dsts[i].clone();
        for _ in 0..n {
            let b = datagram(&host, port, &self.next.to_be_bytes());
            self.w.rt.block_on(self.assoc.socks[j].send_to(&b, self.assoc.relay)).unwrap();
            if self.admits(j) {
                self.sent[i].push(self.next);
            }
            self.next += 1;
        }
    }

    /// Checks that every datagram the client sent to a flow that opens
    /// comes back to it, and that nothing else comes back to anyone.
    fn check(&mut self) {
        self.collect(Duration::from_secs(3));
        for i in dialable() {
            assert_eq!(self.got[i], self.sent[i], "{:?}: datagrams lost", self.dsts[i]);
        }
        let stray = self.w.rt.block_on(first_to_receive(&self.assoc.socks, Duration::from_millis(50)));
        let (client, request) = (self.client, self.assoc.want);
        assert_eq!(stray, None, "a socket got a stray reply (client {client:?}, request {request})");
    }

    /// Reads echoes until every datagram the client sent to a flow that
    /// opens is back, or a deadline passes.
    fn collect(&mut self, deadline: Duration) {
        let Socks { w, dsts, assoc, client, sent, got, .. } = self;
        // Nothing was sent until the association had a client.
        let Some(client) = *client else { return };
        let sock = &assoc.socks[client];
        w.rt.block_on(async {
            let mut buf = [0u8; 2048];
            let end = Instant::now() + deadline;
            while !dialable().all(|i| got[i].len() == sent[i].len()) {
                let Ok(r) = timeout_at(end, sock.recv_from(&mut buf)).await else { return };
                let (n, from) = r.unwrap();
                assert_eq!(from, assoc.relay);
                let (dst, seq) = parse_echo(&buf[..n]);
                let i = dsts.iter().position(|d| *d == dst).expect("reply from an unknown destination");
                assert_ne!(i, UNDIALABLE, "a reply from a flow that can't open");
                got[i].push(seq);
                assert!(sent[i].starts_with(&got[i]), "{dst:?}: sent {:?}, got {:?}", sent[i], got[i]);
            }
        });
    }
}

/// An echoed datagram's destination and sequence number.
fn parse_echo(d: &[u8]) -> ((String, u16), u32) {
    assert!(d.len() > 3 && d[..3] == [0, 0, 0], "bad header {:?}", &d[..d.len().min(8)]);
    let (dst, payload) = parse_addr(&d[3..]).expect("bad reply address");
    (dst, u32::from_be_bytes(payload.try_into().unwrap()))
}

/// The index of the first of `socks` to receive a datagram within
/// `limit`, if any does.
async fn first_to_receive(socks: &[UdpSocket; SOCKETS], limit: Duration) -> Option<usize> {
    let [a, b] = socks;
    let (mut ba, mut bb) = ([0u8; 2048], [0u8; 2048]);
    let recv = async {
        tokio::select! {
            _ = a.recv_from(&mut ba) => 0,
            _ = b.recv_from(&mut bb) => 1,
        }
    };
    timeout(limit, recv).await.ok()
}

/// Whether `addr` can be bound again within two seconds, once nothing
/// holds it.
async fn frees_up(addr: SocketAddr) -> bool {
    for _ in 0..100 {
        if UdpSocket::bind(addr).await.is_ok() {
            return true;
        }
        sleep(Duration::from_millis(20)).await;
    }
    false
}

#[hegel::state_machine]
impl Socks {
    /// A burst of datagrams to one destination, from one socket.
    #[rule]
    fn send(&mut self, tc: TestCase) {
        let i = tc.draw(gs::integers::<usize>().max_value(self.dsts.len() - 1));
        let j = tc.draw(gs::integers::<usize>().max_value(SOCKETS - 1));
        let n = tc.draw(gs::integers::<usize>().min_value(1).max_value(4));
        self.burst(i, j, n);
    }

    /// Everything the client sent so far comes back to it.
    #[rule]
    fn settle(&mut self, _: TestCase) {
        self.check();
    }

    /// Closes the control connection, which ends the association and all
    /// its tasks, and opens another.
    #[rule]
    fn reassociate(&mut self, tc: TestCase) {
        let w = self.w;
        let new = w.rt.block_on(associate(w.proxy, Request::draw(&tc)));
        let old = mem::replace(&mut self.assoc, new);

        drop(old.ctrl);

        // The relay socket is free again once nothing holds it.
        let freed = w.rt.block_on(frees_up(old.relay));
        assert!(freed, "the association's relay outlived its control connection");
        (self.client, self.sent, self.got) = Default::default();
    }
}

#[hegel::test(test_cases = 50)]
fn udp_associate_state_machine(tc: TestCase) {
    let req = Request::draw(&tc);
    hegel::stateful::machine(Socks::new(req)).steps(12).run(tc);
}

/// Datagrams sent while a flow opens wait for it: a DNS client's A and
/// AAAA queries, say, go out back to back.
#[test]
fn datagrams_wait_for_their_flow_to_open() {
    let mut s = Socks::new(Request::UNSPECIFIED);
    s.burst(0, 0, 2);
    s.check();
}

/// Once the client has sent from its address, another local socket
/// can't use the association or take its replies.
#[test]
fn another_socket_cant_take_over_an_association() {
    let mut s = Socks::new(Request::UNSPECIFIED);
    s.burst(0, 0, 1);
    s.check();
    s.burst(1, 1, 1);
    s.burst(0, 0, 1);
    s.check();
}
