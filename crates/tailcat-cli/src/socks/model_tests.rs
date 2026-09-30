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

use std::sync::OnceLock;

use hegel::TestCase;
use hegel::generators as gs;
use tailcat::derp::server::DevDerp;

use super::*;

/// The proxy, a tailcat server that echoes every UDP flow, and the relay
/// they share, set up once for every test case.
struct World {
    rt: tokio::runtime::Runtime,
    proxy: SocketAddr,
    echo: Addr,
    _dev: DevDerp,
    _server: tailcat::Server,
}

fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let (dev, server, proxy) = rt.block_on(async {
            let dev = DevDerp::start_local().await.unwrap();
            let server = tailcat::Server::builder()
                .region(dev.region.clone())
                .on_udp(|_| {
                    Some(tailcat::udp_handler(|c: tailcat::UdpConn| async move {
                        let mut b = [0u8; 2048];
                        while let Ok(n) = c.recv(&mut b).await {
                            let _ = c.send(&b[..n]).await;
                        }
                    }))
                })
                .start()
                .await
                .unwrap();
            let g = Global { key: None, verbose: false, json: false, derpmap_url: String::new() };
            let key = NodePrivate::generate();
            let echo = crate::client::new_client(&g, server.tailcat_addr(), key.clone());
            // Bring the tunnel up, which can lose the first datagrams, and
            // give the direct path a moment: a path switch mid-test could
            // reorder datagrams in flight.
            let u = echo.dial_udp_port(9).await.unwrap();
            let mut buf = [0u8; 16];
            loop {
                u.send(b"up").await.unwrap();
                if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(500), u.recv(&mut buf)).await {
                    break;
                }
            }
            for _ in 0..30 {
                let ms = echo.magicsock().unwrap();
                if ms.peer_path(&server.public_key()).and_then(|p| p.direct()).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let clients = Mutex::new(HashMap::from([(server.tailcat_addr(), echo)]));
            let d = Dialer { g, key, default: None, clients };
            let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = ln.local_addr().unwrap();
            tokio::spawn(serve(ln, Arc::new(d)));
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
    const UNSPECIFIED: Request = Request { ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), socket: None };

    fn draw(tc: &TestCase) -> Request {
        let ips = ["0.0.0.0", "127.0.0.1", "192.0.2.1"].map(|ip| ip.parse::<IpAddr>().unwrap());
        let ip = ips[tc.draw(gs::integers::<usize>().max_value(ips.len() - 1))];
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

async fn associate(proxy: SocketAddr, req: Request) -> Assoc {
    let mut socks = Vec::new();
    for _ in 0..SOCKETS {
        socks.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    }
    let socks: [UdpSocket; SOCKETS] = socks.try_into().unwrap();
    let want = SocketAddr::new(req.ip, req.socket.map_or(0, |i| socks[i].local_addr().unwrap().port()));
    let mut ctrl = TcpStream::connect(proxy).await.unwrap();
    let mut b = vec![5, 1, 0, 5, 3, 0];
    put_addr(&mut b, &want.ip().to_string(), want.port());
    ctrl.write_all(&b).await.unwrap();
    let mut rep = [0u8; 12];
    ctrl.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], REP_SUCCESS);
    let relay = SocketAddr::from((<[u8; 4]>::try_from(&rep[6..10]).unwrap(), u16::from_be_bytes([rep[10], rep[11]])));
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
        for _ in 0..n {
            let mut b = vec![0, 0, 0];
            put_addr(&mut b, &self.dsts[i].0, self.dsts[i].1);
            b.extend(self.next.to_be_bytes());
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
        for i in 0..3 {
            if i != UNDIALABLE {
                assert_eq!(self.got[i], self.sent[i], "{:?}: datagrams lost", self.dsts[i]);
            }
        }
        let Socks { w, assoc, client, .. } = self;
        let [a, b] = &assoc.socks;
        let (mut ba, mut bb) = ([0u8; 2048], [0u8; 2048]);
        let stray = w.rt.block_on(async {
            let recv = async {
                tokio::select! {
                    _ = a.recv_from(&mut ba) => 0,
                    _ = b.recv_from(&mut bb) => 1,
                }
            };
            tokio::time::timeout(Duration::from_millis(50), recv).await
        });
        if let Ok(j) = stray {
            panic!("socket {j} got a stray reply (client {client:?}, request {})", assoc.want);
        }
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
            let done = |got: &[Vec<u32>; 3]| (0..3).all(|i| i == UNDIALABLE || got[i].len() == sent[i].len());
            let end = tokio::time::Instant::now() + deadline;
            while !done(got) {
                let Ok(r) = tokio::time::timeout_at(end, sock.recv_from(&mut buf)).await else { return };
                let (n, from) = r.unwrap();
                assert_eq!(from, assoc.relay);
                assert!(n > 3 && buf[..3] == [0, 0, 0], "bad header {:?}", &buf[..n.min(8)]);
                let (dst, payload) = parse_addr(&buf[3..n]).expect("bad reply address");
                let i = dsts.iter().position(|d| *d == dst).expect("reply from an unknown destination");
                assert_ne!(i, UNDIALABLE, "a reply from a flow that can't open");
                got[i].push(u32::from_be_bytes(payload.try_into().unwrap()));
                let k = got[i].len();
                assert!(k <= sent[i].len() && got[i] == sent[i][..k], "{dst:?}: sent {:?}, got {:?}", sent[i], got[i]);
            }
        });
    }
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
        let old = std::mem::replace(&mut self.assoc, w.rt.block_on(associate(w.proxy, Request::draw(&tc))));
        drop(old.ctrl);
        // The relay socket is free again once nothing holds it.
        w.rt.block_on(async {
            for _ in 0..100 {
                if UdpSocket::bind(old.relay).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("the association's relay outlived its control connection");
        });
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
