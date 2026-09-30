//! `tailcat perf` and the `perf` service: an iperf-like throughput and
//! latency test, wire-compatible with the Go implementation.
//!
//! The client opens a TCP control connection to [`PORT`] and sends a
//! hello line with the test parameters. Data flows on separate TCP
//! connections or UDP flows to the same port, one per stream. Control
//! messages are JSON lines; UDP datagrams carry a 32-byte header with
//! the test ID, stream, flags, sequence number and send time.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use clap::Args;
use serde::{Deserialize, Serialize};
use tailcat::{TcpStream, UdpConn};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::Global;

/// The TCP and UDP port of the perf service.
pub const PORT: u16 = 5201;

const DEFAULT_MAX_STREAMS: usize = 128;
const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(600);
const MAX_LENGTH: usize = 1 << 20;
const MAX_UDP_SIZE: usize = 65507;
const MIN_INTERVAL: Duration = Duration::from_millis(100);
const UDP_HEADER_LEN: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const REPORT_TIMEOUT: Duration = Duration::from_secs(15);
const TCP_GRACE: Duration = Duration::from_secs(5);
const UDP_GRACE: Duration = Duration::from_secs(2);
const OPENER_INTERVAL: Duration = Duration::from_millis(200);
const RTT_INTERVAL: Duration = Duration::from_millis(200);
const CTRL_BUF_SIZE: usize = 64 << 10;
const FIN_REPEAT: usize = 3;
const FLAG_OPEN: u8 = 1;
const FLAG_FIN: u8 = 2;
/// The default size of each TCP write.
const DEFAULT_TCP_LENGTH: usize = 128 << 10;

/// For `skip_serializing_if`: Go's `omitempty`.
fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// Go's time.Duration marshals to JSON as integer nanoseconds. Longer
/// durations than it holds (about 292 years) saturate at its maximum
/// rather than wrapping negative.
mod nanos {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let n = i64::deserialize(d)?;
        Ok(Duration::from_nanos(n.max(0) as u64))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    #[serde(rename = "up")]
    Upload,
    #[serde(rename = "down")]
    Download,
    #[serde(rename = "both")]
    Bidirectional,
}

/// Test parameters, chosen by the client and validated by the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Params {
    pub proto: Proto,
    #[serde(rename = "dir")]
    pub direction: Direction,
    #[serde(default, with = "nanos", skip_serializing_if = "is_zero")]
    pub duration: Duration,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes: i64,
    pub streams: usize,
    pub length: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bitrate: i64,
    #[serde(default, with = "nanos", skip_serializing_if = "is_zero")]
    pub interval: Duration,
}

impl Params {
    fn validate(&self, max_streams: usize, max_duration: Duration) -> Result<(), String> {
        if self.bytes < 0 {
            return Err("negative byte count".into());
        }
        if self.bytes == 0 && self.duration.is_zero() {
            return Err("a duration or byte count is required".into());
        }
        if max_duration > Duration::ZERO && self.bytes == 0 && self.duration > max_duration {
            return Err(format!(
                "duration {} exceeds the server's limit of {}",
                go_duration(self.duration),
                go_duration(max_duration)
            ));
        }
        if self.streams < 1 {
            return Err("at least one stream is required".into());
        }
        if max_streams > 0 && self.streams > max_streams {
            return Err(format!("{} streams exceeds the server's limit of {max_streams}", self.streams));
        }
        if self.length < 1 {
            return Err("a positive length is required".into());
        }
        match self.proto {
            Proto::Tcp if self.length > MAX_LENGTH => {
                return Err(format!("TCP length {} exceeds {MAX_LENGTH}", self.length));
            }
            Proto::Udp if self.length < UDP_HEADER_LEN => {
                return Err(format!("UDP length {} is smaller than the {UDP_HEADER_LEN}-byte header", self.length));
            }
            Proto::Udp if self.length > MAX_UDP_SIZE => {
                return Err(format!("UDP length {} exceeds {MAX_UDP_SIZE}", self.length));
            }
            _ => {}
        }
        if self.bitrate < 0 {
            return Err("negative bitrate".into());
        }
        if !self.interval.is_zero() && self.interval < MIN_INTERVAL {
            return Err(format!(
                "interval {} is shorter than {}",
                go_duration(self.interval),
                go_duration(MIN_INTERVAL)
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Interval {
    pub bytes: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub datagrams: i64,
}

impl Interval {
    /// The traffic between an earlier snapshot and this one.
    fn since(&self, earlier: &Interval) -> Interval {
        Interval { bytes: self.bytes - earlier.bytes, datagrams: self.datagrams - earlier.datagrams }
    }
}

/// What one side sent or received.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub bytes: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub datagrams: i64,
    #[serde(with = "nanos")]
    pub duration: Duration,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intervals: Vec<Interval>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reordered: i64,
    #[serde(default, with = "nanos", skip_serializing_if = "is_zero")]
    pub jitter: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rtt {
    #[serde(with = "nanos")]
    pub min: Duration,
    #[serde(with = "nanos")]
    pub avg: Duration,
    #[serde(with = "nanos")]
    pub max: Duration,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerfResult {
    pub params: Params,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_sent: Option<Stats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_received: Option<Stats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_sent: Option<Stats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_received: Option<Stats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt: Option<Rtt>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Message {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    params: Option<Params>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    stream: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    t: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stats: Option<Stats>,
}

impl Message {
    fn new(t: &str) -> Self {
        Message { typ: t.into(), ..Default::default() }
    }

    fn error(e: impl Into<String>) -> Self {
        Message { error: e.into(), ..Message::new("error") }
    }

    /// The message as a JSON line.
    fn line(&self) -> Vec<u8> {
        let mut b = serde_json::to_vec(self).expect("message serializes");
        b.push(b'\n');
        b
    }
}

/// Parses a hex test ID.
fn parse_id(s: &str) -> Option<[u8; 8]> {
    hex::decode(s).ok()?.try_into().ok()
}

fn unix_nanos() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct UdpHeader {
    id: [u8; 8],
    stream: u16,
    flags: u8,
    seq: u64,
    send_time: i64,
}

impl UdpHeader {
    /// Writes the header to the start of `b`.
    fn put(&self, b: &mut [u8]) {
        b[0..8].copy_from_slice(&self.id);
        b[8..10].copy_from_slice(&self.stream.to_be_bytes());
        b[10] = self.flags;
        b[11..16].fill(0);
        b[16..24].copy_from_slice(&self.seq.to_be_bytes());
        b[24..32].copy_from_slice(&self.send_time.to_be_bytes());
    }

    /// A header-only datagram.
    fn datagram(&self) -> [u8; UDP_HEADER_LEN] {
        let mut b = [0; UDP_HEADER_LEN];
        self.put(&mut b);
        b
    }

    fn parse(b: &[u8]) -> Option<UdpHeader> {
        let b: &[u8; UDP_HEADER_LEN] = b.get(..UDP_HEADER_LEN)?.try_into().ok()?;
        Some(UdpHeader {
            id: b[0..8].try_into().ok()?,
            stream: u16::from_be_bytes([b[8], b[9]]),
            flags: b[10],
            seq: u64::from_be_bytes(b[16..24].try_into().ok()?),
            send_time: i64::from_be_bytes(b[24..32].try_into().ok()?),
        })
    }
}

type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// A control connection speaking JSON lines.
struct Ctrl {
    rd: tokio::sync::Mutex<BufReader<BoxRead>>,
    wr: tokio::sync::Mutex<BoxWrite>,
}

impl Ctrl {
    fn new(rd: BufReader<BoxRead>, wr: BoxWrite) -> Self {
        Ctrl { rd: tokio::sync::Mutex::new(rd), wr: tokio::sync::Mutex::new(wr) }
    }

    async fn send(&self, m: &Message) -> std::io::Result<()> {
        let b = m.line();
        let mut w = self.wr.lock().await;
        w.write_all(&b).await?;
        w.flush().await
    }

    async fn recv(&self) -> std::io::Result<Message> {
        read_message(&mut *self.rd.lock().await).await
    }
}

async fn read_message<R: AsyncRead + Unpin>(br: &mut BufReader<R>) -> std::io::Result<Message> {
    let mut line = Vec::new();
    let n = br.take(CTRL_BUF_SIZE as u64).read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    if !line.ends_with(b"\n") {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "control line too long"));
    }
    serde_json::from_slice(&line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad control message: {e}")))
}

/// The sending half of a stream's connection.
enum SendSide {
    Tcp(BoxWrite),
    Udp(Arc<UdpConn>),
}

/// The receiving half of a stream's connection, with any datagram
/// already read from it.
enum RecvSide {
    Tcp(BoxRead),
    Udp(Arc<UdpConn>, Option<Vec<u8>>),
}

/// One stream's connection.
type StreamConn = (SendSide, RecvSide);

fn tcp_stream(rd: BoxRead, wr: BoxWrite) -> StreamConn {
    (SendSide::Tcp(wr), RecvSide::Tcp(rd))
}

fn udp_stream(c: UdpConn, pending: Option<Vec<u8>>) -> StreamConn {
    let c = Arc::new(c);
    (SendSide::Udp(c.clone()), RecvSide::Udp(c, pending))
}

#[derive(Default)]
struct RecvState {
    first: Option<Instant>,
    last: Option<Instant>,
    expect_seq: u64,
    reordered: i64,
    jitter: f64,
    last_transit: Option<i64>,
}

/// Flags that can be waited on.
#[derive(Clone, Default)]
struct Flag(watch::Sender<bool>);

impl Flag {
    fn set(&self) {
        self.0.send_replace(true);
    }
    fn is_set(&self) -> bool {
        *self.0.borrow()
    }
    async fn wait(&self) {
        let _ = self.0.subscribe().wait_for(|v| *v).await;
    }
}

/// Stats the peer reports once, and a flag for their arrival.
#[derive(Default)]
struct Report {
    stats: Mutex<Option<Stats>>,
    arrived: Flag,
}

impl Report {
    fn set(&self, s: Option<Stats>) {
        *self.stats.lock().unwrap() = s;
        self.arrived.set();
    }
    fn get(&self) -> Option<Stats> {
        self.stats.lock().unwrap().clone()
    }
}

/// One direction's running counters, and its final stats.
#[derive(Default)]
struct Tally {
    bytes: AtomicI64,
    datagrams: AtomicI64,
    intervals: Mutex<Vec<Interval>>,
    stats: Mutex<Option<Stats>>,
}

impl Tally {
    fn add(&self, bytes: usize, datagram: bool) {
        self.bytes.fetch_add(bytes as i64, Ordering::Relaxed);
        if datagram {
            self.datagrams.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> Interval {
        Interval { bytes: self.bytes.load(Ordering::Relaxed), datagrams: self.datagrams.load(Ordering::Relaxed) }
    }

    /// The totals and intervals so far.
    fn totals(&self) -> Stats {
        let Interval { bytes, datagrams } = self.snapshot();
        Stats { bytes, datagrams, intervals: self.intervals.lock().unwrap().clone(), ..Default::default() }
    }

    /// Records the final stats and returns them as sent to the peer,
    /// without intervals.
    fn finish(&self, s: Stats) -> Stats {
        *self.stats.lock().unwrap() = Some(s.clone());
        Stats { intervals: Vec::new(), ..s }
    }
}

/// Round-trip times of the control connection's pings.
#[derive(Default)]
struct RttTracker {
    stats: Option<Rtt>,
    sum: Duration,
    last: Duration,
}

impl RttTracker {
    fn record(&mut self, d: Duration) {
        self.sum += d;
        self.last = d;
        let r = self.stats.get_or_insert(Rtt { min: d, avg: d, max: d, count: 0 });
        r.min = r.min.min(d);
        r.max = r.max.max(d);
        r.count += 1;
        r.avg = self.sum / r.count as u32;
    }
}

type OnProgress = Box<dyn Fn(Progress) + Send + Sync>;

struct Test {
    p: Params,
    id: [u8; 8],
    is_server: bool,
    ctrl: Ctrl,
    streams: Vec<Mutex<Option<StreamConn>>>,
    attached: AtomicUsize,
    all_attached: Flag,
    ready: Flag,
    done: Flag,
    err: Mutex<Option<String>>,
    /// The peer's sender ("done") and receiver ("result") reports.
    peer_sent: Report,
    peer_received: Report,
    tx: Tally,
    rx: Tally,
    rtt: Mutex<RttTracker>,
    on_progress: Option<OnProgress>,
}

/// A client-side snapshot at the end of a reporting interval.
pub struct Progress {
    pub elapsed: Duration,
    pub sent: Interval,
    pub received: Interval,
    pub rtt: Duration,
}

impl Test {
    fn new(p: Params, id: [u8; 8], is_server: bool, ctrl: Ctrl, on_progress: Option<OnProgress>) -> Arc<Test> {
        Arc::new(Test {
            streams: (0..p.streams).map(|_| Mutex::default()).collect(),
            p,
            id,
            is_server,
            ctrl,
            attached: AtomicUsize::default(),
            all_attached: Flag::default(),
            ready: Flag::default(),
            done: Flag::default(),
            err: Mutex::default(),
            peer_sent: Report::default(),
            peer_received: Report::default(),
            tx: Tally::default(),
            rx: Tally::default(),
            rtt: Mutex::default(),
            on_progress,
        })
    }

    fn sends(&self) -> bool {
        self.p.direction != if self.is_server { Direction::Upload } else { Direction::Download }
    }

    fn receives(&self) -> bool {
        self.p.direction != if self.is_server { Direction::Download } else { Direction::Upload }
    }

    fn fail(&self, e: String) {
        let mut err = self.err.lock().unwrap();
        if !self.done.is_set() {
            *err = Some(e);
            self.done.set();
        }
    }

    fn err(&self) -> String {
        self.err.lock().unwrap().clone().unwrap_or_default()
    }

    /// Awaits every stream's task, in order. One that panicked fails the
    /// test and leaves `None` in its place, so the rest keep their
    /// stream's index.
    async fn join_streams<T>(&self, tasks: Vec<JoinHandle<T>>) -> Vec<Option<T>> {
        let mut out = Vec::with_capacity(tasks.len());
        for (i, t) in tasks.into_iter().enumerate() {
            out.push(match t.await {
                Ok(v) => Some(v),
                Err(e) => {
                    self.fail(format!("stream {i}: {e}"));
                    None
                }
            });
        }
        out
    }

    fn attach(&self, index: usize, c: StreamConn) -> bool {
        let mut slot = self.streams[index].lock().unwrap();
        if slot.is_some() {
            return false;
        }
        *slot = Some(c);
        if self.attached.fetch_add(1, Ordering::SeqCst) + 1 == self.streams.len() {
            self.all_attached.set();
        }
        true
    }

    fn peer_reported(&self) -> bool {
        (!self.receives() || self.peer_sent.arrived.is_set()) && (!self.sends() || self.peer_received.arrived.is_set())
    }

    async fn read_control(self: Arc<Self>) {
        loop {
            let m = tokio::select! {
                m = self.ctrl.recv() => m,
                _ = self.done.wait() => return,
            };
            let m = match m {
                Ok(m) => m,
                Err(e) => {
                    // Once the peer has sent every report we need, it may
                    // close the connection before we notice we're finished.
                    if !self.done.is_set() && !self.peer_reported() {
                        self.fail(format!("control connection: {e}"));
                    }
                    return;
                }
            };
            match m.typ.as_str() {
                "ping" => {
                    let _ = self.ctrl.send(&Message { t: m.t, ..Message::new("pong") }).await;
                }
                "pong" => {
                    let d = unix_nanos() - m.t;
                    self.rtt.lock().unwrap().record(Duration::from_nanos(d.max(0) as u64));
                }
                "ready" => self.ready.set(),
                "done" => self.peer_sent.set(m.stats),
                "result" => self.peer_received.set(m.stats),
                "error" => {
                    self.fail(format!("peer: {}", m.error));
                    return;
                }
                _ => {}
            }
        }
    }

    async fn send_openers(&self) -> std::io::Result<()> {
        for (i, s) in self.streams.iter().enumerate() {
            let conn = match &*s.lock().unwrap() {
                Some((SendSide::Udp(conn), _)) => conn.clone(),
                _ => continue,
            };
            conn.send(&UdpHeader { id: self.id, stream: i as u16, flags: FLAG_OPEN, ..Default::default() }.datagram())
                .await?;
        }
        Ok(())
    }

    async fn wait_ready(&self) -> Result<(), String> {
        let timeout = tokio::time::sleep(HANDSHAKE_TIMEOUT);
        tokio::pin!(timeout);
        if self.is_server {
            return tokio::select! {
                _ = self.all_attached.wait() => self.ctrl.send(&Message::new("ready")).await.map_err(|e| e.to_string()),
                _ = self.done.wait() => Err(self.err()),
                _ = &mut timeout => Err("timed out waiting for the client's streams to connect".into()),
            };
        }
        // UDP flows open on the server's side with their first datagram;
        // repeat the openers until it's ready, in case some are lost.
        let udp = self.p.proto == Proto::Udp;
        let mut openers = tokio::time::interval(OPENER_INTERVAL);
        loop {
            tokio::select! {
                biased;
                _ = self.ready.wait() => return Ok(()),
                _ = self.done.wait() => return Err(self.err()),
                _ = &mut timeout => return Err("timed out waiting for the server to be ready".into()),
                _ = openers.tick(), if udp => {
                    self.send_openers().await.map_err(|e| format!("opening UDP flow: {e}"))?;
                }
            }
        }
    }

    async fn run(self: Arc<Self>) -> Result<PerfResult, String> {
        tokio::spawn(self.clone().read_control());
        if let Err(e) = self.wait_ready().await {
            self.fail(e.clone());
            return Err(e);
        }
        let start = Instant::now();
        let stop = Flag::default();
        if !self.p.interval.is_zero() {
            tokio::spawn(self.clone().intervals(start, stop.clone()));
        }
        if !self.is_server {
            tokio::spawn(self.clone().pings(stop.clone()));
        }

        let (send_sides, recv_sides): (Vec<_>, Vec<_>) = self
            .streams
            .iter()
            .map(|s| s.lock().unwrap().take())
            .collect::<Option<_>>()
            .ok_or("stream not attached")?;
        let senders = async {
            if self.sends() {
                self.run_senders(start, send_sides).await
            } else {
                // Unused write sides stay open until the test ends, so the
                // peer doesn't see an early EOF.
                send_sides.into_iter().map(Some).collect()
            }
        };
        let receivers = async {
            if self.receives() {
                self.run_receivers(recv_sides).await;
            }
        };
        // Hold the (possibly half-closed) connections until the test ends.
        let (held, ()) = tokio::join!(senders, receivers);
        stop.set();

        // Wait for the peer's view of what it sent and received.
        let deadline = tokio::time::Instant::now() + REPORT_TIMEOUT;
        for (needed, report, what) in
            [(self.receives(), &self.peer_sent, "sender"), (self.sends(), &self.peer_received, "receiver")]
        {
            if needed {
                tokio::select! {
                    _ = report.arrived.wait() => {}
                    _ = self.done.wait() => {}
                    _ = tokio::time::sleep_until(deadline) => {
                        self.fail(format!("timed out waiting for the peer's {what} report"));
                    }
                }
            }
        }
        // Finish under the error lock, so a concurrent fail() either lands
        // first and is reported, or finds the test already done.
        let err = {
            let err = self.err.lock().unwrap();
            self.done.set();
            err.clone()
        };
        drop(held);
        if let Some(e) = err {
            return Err(e);
        }
        let mine = (self.tx.stats.lock().unwrap().clone(), self.rx.stats.lock().unwrap().clone());
        let peer = (self.peer_sent.get(), self.peer_received.get());
        let ((client_sent, client_received), (server_sent, server_received), rtt) =
            if self.is_server { (peer, mine, None) } else { (mine, peer, self.rtt.lock().unwrap().stats.clone()) };
        Ok(PerfResult { params: self.p.clone(), client_sent, server_received, server_sent, client_received, rtt })
    }

    async fn intervals(self: Arc<Self>, start: Instant, stop: Flag) {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + self.p.interval, self.p.interval);
        let (mut last_sent, mut last_recv) = (Interval::default(), Interval::default());
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = stop.wait() => return,
                _ = self.done.wait() => return,
            }
            let (sent, recv) = (self.tx.snapshot(), self.rx.snapshot());
            let (ds, dr) = (sent.since(&last_sent), recv.since(&last_recv));
            (last_sent, last_recv) = (sent, recv);
            if self.sends() {
                self.tx.intervals.lock().unwrap().push(ds.clone());
            }
            if self.receives() {
                self.rx.intervals.lock().unwrap().push(dr.clone());
            }
            if let Some(f) = &self.on_progress {
                let rtt = self.rtt.lock().unwrap().last;
                f(Progress { elapsed: start.elapsed(), sent: ds, received: dr, rtt });
            }
        }
    }

    async fn pings(self: Arc<Self>, stop: Flag) {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + RTT_INTERVAL, RTT_INTERVAL);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let _ = self.ctrl.send(&Message { t: unix_nanos(), ..Message::new("ping") }).await;
                }
                _ = stop.wait() => return,
                _ = self.done.wait() => return,
            }
        }
    }

    async fn run_senders(self: &Arc<Self>, start: Instant, sides: Vec<SendSide>) -> Vec<Option<SendSide>> {
        let tasks = sides.into_iter().enumerate().map(|(i, side)| {
            let t = self.clone();
            tokio::spawn(async move { t.send_stream(i, side, start).await })
        });
        let mut sides = self.join_streams(tasks.collect()).await;
        if self.done.is_set() {
            return sides;
        }
        let stats = Stats { duration: start.elapsed(), ..self.tx.totals() };
        let wire = self.tx.finish(stats);
        for (i, side) in sides.iter_mut().enumerate().filter_map(|(i, s)| Some((i, s.as_mut()?))) {
            let r = match side {
                SendSide::Tcp(w) => w.shutdown().await,
                SendSide::Udp(c) => {
                    let fin = UdpHeader {
                        id: self.id,
                        stream: i as u16,
                        flags: FLAG_FIN,
                        send_time: unix_nanos(),
                        ..Default::default()
                    };
                    let mut r = Ok(());
                    for _ in 0..FIN_REPEAT {
                        if let Err(e) = c.send(&fin.datagram()).await {
                            r = Err(e);
                        }
                    }
                    r
                }
            };
            if let Err(e) = r {
                self.fail(format!("stream {i}: ending: {e}"));
                return sides;
            }
        }
        if let Err(e) = self.ctrl.send(&Message { stats: Some(wire), ..Message::new("done") }).await {
            self.fail(format!("sending done: {e}"));
        }
        sides
    }

    async fn send_stream(&self, i: usize, mut side: SendSide, start: Instant) -> SendSide {
        let mut buf: Vec<u8> = (0..self.p.length).map(|i| i as u8).collect();
        let step =
            (self.p.bitrate > 0).then(|| Duration::from_secs_f64(self.p.length as f64 * 8.0 / self.p.bitrate as f64));
        let mut next: Option<tokio::time::Instant> = None;
        let mut sent: i64 = 0;
        let mut seq: u64 = 0;
        loop {
            let finished = if self.p.bytes > 0 { sent >= self.p.bytes } else { start.elapsed() >= self.p.duration };
            if finished || self.done.is_set() {
                return side;
            }
            if let Some(step) = step {
                let now = tokio::time::Instant::now();
                let at = *next.get_or_insert(now);
                if at > now {
                    tokio::time::sleep_until(at).await;
                }
                next = Some(at + step);
            }
            let mut n = buf.len();
            let r = match &mut side {
                SendSide::Udp(c) => {
                    UdpHeader { id: self.id, stream: i as u16, seq, send_time: unix_nanos(), ..Default::default() }
                        .put(&mut buf);
                    seq += 1;
                    c.send(&buf).await.map(|_| ())
                }
                SendSide::Tcp(w) => {
                    if self.p.bytes > 0 {
                        n = n.min((self.p.bytes - sent) as usize);
                    }
                    tokio::select! {
                        r = w.write_all(&buf[..n]) => r,
                        _ = self.done.wait() => return side,
                    }
                }
            };
            if let Err(e) = r {
                if !self.done.is_set() {
                    self.fail(format!("stream {i}: write: {e}"));
                }
                return side;
            }
            sent += n as i64;
            self.tx.add(n, matches!(side, SendSide::Udp(_)));
        }
    }

    async fn run_receivers(self: &Arc<Self>, sides: Vec<RecvSide>) {
        let tasks = sides.into_iter().enumerate().map(|(i, side)| {
            let t = self.clone();
            tokio::spawn(async move { t.recv_stream(i, side).await })
        });
        let states = self.join_streams(tasks.collect()).await;
        if self.done.is_set() {
            return;
        }
        let states: Vec<_> = states.into_iter().flatten().collect();
        let mut stats = self.rx.totals();
        let first = states.iter().filter_map(|s| s.first).min();
        let last = states.iter().filter_map(|s| s.last).max();
        if let (Some(f), Some(l)) = (first, last) {
            stats.duration = l - f;
        }
        stats.reordered = states.iter().map(|s| s.reordered).sum();
        if self.p.proto == Proto::Udp && !states.is_empty() {
            let j: f64 = states.iter().map(|s| s.jitter).sum::<f64>() / self.p.streams as f64;
            stats.jitter = Duration::from_nanos(j.max(0.0) as u64);
        }
        let wire = self.rx.finish(stats);
        if let Err(e) = self.ctrl.send(&Message { stats: Some(wire), ..Message::new("result") }).await {
            self.fail(format!("sending result: {e}"));
        }
    }

    /// Resolves once the peer said it's done sending and the grace
    /// period for in-flight data has passed.
    async fn grace_expired(&self) {
        self.peer_sent.arrived.wait().await;
        tokio::time::sleep(if self.p.proto == Proto::Udp { UDP_GRACE } else { TCP_GRACE }).await;
    }

    async fn recv_stream(&self, i: usize, side: RecvSide) -> RecvState {
        let mut st = RecvState::default();
        let res: std::io::Result<()> = async {
            match side {
                RecvSide::Tcp(mut rd) => {
                    let mut buf = vec![0u8; self.p.length.max(64 << 10)];
                    loop {
                        let n = tokio::select! {
                            r = rd.read(&mut buf) => r?,
                            _ = self.grace_expired() => return Ok(()),
                            _ = self.done.wait() => return Ok(()),
                        };
                        if n == 0 {
                            return Ok(());
                        }
                        self.count(&mut st, n, false);
                    }
                }
                RecvSide::Udp(conn, pending) => {
                    if pending.is_some_and(|p| self.process_datagram(&mut st, &p)) {
                        return Ok(());
                    }
                    let mut buf = vec![0u8; MAX_UDP_SIZE];
                    loop {
                        let n = tokio::select! {
                            r = conn.recv(&mut buf) => r?,
                            _ = self.grace_expired() => return Ok(()),
                            _ = self.done.wait() => return Ok(()),
                        };
                        if self.process_datagram(&mut st, &buf[..n]) {
                            return Ok(());
                        }
                    }
                }
            }
        }
        .await;
        if let Err(e) = res
            && !self.peer_sent.arrived.is_set()
            && !self.done.is_set()
        {
            self.fail(format!("stream {i}: read: {e}"));
        }
        st
    }

    fn count(&self, st: &mut RecvState, n: usize, datagram: bool) {
        let now = Instant::now();
        st.first.get_or_insert(now);
        st.last = Some(now);
        self.rx.add(n, datagram);
    }

    /// Accounts for one datagram, reporting whether it was a fin.
    fn process_datagram(&self, st: &mut RecvState, pkt: &[u8]) -> bool {
        let Some(h) = UdpHeader::parse(pkt) else { return false };
        if h.id != self.id {
            return false;
        }
        if h.flags & FLAG_FIN != 0 {
            return true;
        }
        if h.flags & FLAG_OPEN != 0 {
            return false;
        }
        self.count(st, pkt.len(), true);
        if h.seq < st.expect_seq {
            st.reordered += 1;
        } else {
            st.expect_seq = h.seq + 1;
        }
        // RFC 3550 interarrival jitter; clock offsets cancel out in the
        // difference of successive transit times.
        let transit = unix_nanos() - h.send_time;
        if let Some(last) = st.last_transit {
            let d = (transit - last).abs() as f64;
            st.jitter += (d - st.jitter) / 16.0;
        }
        st.last_transit = Some(transit);
        false
    }
}

/// The perf service: one test at a time.
#[derive(Default)]
pub struct Server {
    tests: Mutex<HashMap<[u8; 8], Arc<Test>>>,
}

impl Server {
    fn lookup(&self, id: [u8; 8], index: usize) -> Result<Arc<Test>, String> {
        let t = self.tests.lock().unwrap().get(&id).cloned().ok_or("unknown test")?;
        if index >= t.streams.len() {
            return Err(format!("stream index {index} out of range"));
        }
        Ok(t)
    }

    /// Serves one TCP connection to the perf port: a control connection
    /// starting a test, or a data stream of the running one.
    pub async fn handle_tcp(self: Arc<Self>, c: TcpStream) {
        let remote = c.peer_addr();
        let (rd, wr) = tokio::io::split(c);
        let mut br: BufReader<BoxRead> = BufReader::with_capacity(CTRL_BUF_SIZE, Box::new(rd));
        let wr: BoxWrite = Box::new(wr);
        let Ok(Ok(m)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_message(&mut br)).await else { return };
        match m.typ.as_str() {
            "hello" => self.run_test(Ctrl::new(br, wr), m, remote).await,
            "stream" => {
                let Some(id) = parse_id(&m.id) else { return };
                let t = match self.lookup(id, m.stream) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::debug!("perf: {remote}: data connection: {e}");
                        return;
                    }
                };
                // The BufReader may already hold data after the header.
                if t.attach(m.stream, tcp_stream(Box::new(br), wr)) {
                    t.done.wait().await;
                }
            }
            _ => {}
        }
    }

    /// Serves one UDP flow to the perf port, a data stream of the
    /// running test.
    pub async fn handle_udp(self: Arc<Self>, c: UdpConn) {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let Ok(Ok(n)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, c.recv(&mut buf)).await else { return };
        buf.truncate(n);
        let Some(h) = UdpHeader::parse(&buf) else { return };
        let t = match self.lookup(h.id, h.stream as usize) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!("perf: UDP flow: {e}");
                return;
            }
        };
        if t.attach(h.stream as usize, udp_stream(c, Some(buf))) {
            t.done.wait().await;
        }
    }

    async fn run_test(&self, ctrl: Ctrl, hello: Message, remote: std::net::SocketAddr) {
        let p = hello
            .params
            .ok_or_else(|| "hello without params".to_string())
            .and_then(|p| p.validate(DEFAULT_MAX_STREAMS, DEFAULT_MAX_DURATION).map(|()| p));
        let p = match p {
            Ok(p) => p,
            Err(e) => {
                let _ = ctrl.send(&Message::error(e)).await;
                return;
            }
        };
        let mut id = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        let t = Test::new(p, id, true, ctrl, None);
        let registered = {
            let mut tests = self.tests.lock().unwrap();
            tests.is_empty() && tests.insert(id, t.clone()).is_none()
        };
        if !registered {
            let _ = t.ctrl.send(&Message::error("the server is busy with another test")).await;
            return;
        }
        let res = async {
            t.ctrl.send(&Message { id: hex::encode(id), ..Message::new("ok") }).await.map_err(|e| e.to_string())?;
            let limit = DEFAULT_MAX_DURATION + HANDSHAKE_TIMEOUT + REPORT_TIMEOUT;
            tokio::time::timeout(limit, t.clone().run()).await.unwrap_or_else(|_| Err("test timed out".into()))
        }
        .await;
        t.done.set();
        self.tests.lock().unwrap().remove(&id);
        match res {
            Ok(r) => eprintln!("# perf test from {remote}: {}", perf_summary(&r)),
            Err(e) => tracing::debug!("perf: test from {remote} failed: {e}"),
        }
    }
}

/// Runs one test against a server.
async fn run_client(cl: &tailcat::Client, p: Params, on_progress: Option<OnProgress>) -> Result<PerfResult> {
    p.validate(0, Duration::ZERO).map_err(|e| anyhow!(e))?;
    let cc = cl.dial_tcp_port(PORT).await.map_err(|e| anyhow!("dialing control connection: {e}"))?;
    let (rd, wr) = tokio::io::split(cc);
    let ctrl = Ctrl::new(BufReader::with_capacity(CTRL_BUF_SIZE, Box::new(rd)), Box::new(wr));
    ctrl.send(&Message { params: Some(p.clone()), ..Message::new("hello") })
        .await
        .map_err(|e| anyhow!("sending hello: {e}"))?;
    let m = tokio::time::timeout(HANDSHAKE_TIMEOUT, ctrl.recv())
        .await
        .map_err(|_| anyhow!("reading hello reply: timed out"))?
        .map_err(|e| anyhow!("reading hello reply: {e}"))?;
    match m.typ.as_str() {
        "error" => bail!("server rejected the test: {}", m.error),
        "ok" => {}
        other => bail!("unexpected reply {other:?} to hello"),
    }
    let id = parse_id(&m.id).ok_or_else(|| anyhow!("server sent a malformed test ID"))?;
    let (proto, streams) = (p.proto, p.streams);
    let t = Test::new(p, id, false, ctrl, on_progress);
    for i in 0..streams {
        let sc = match proto {
            Proto::Tcp => {
                let mut dc = cl.dial_tcp_port(PORT).await.map_err(|e| anyhow!("dialing stream {i}: {e}"))?;
                let hdr = Message { id: m.id.clone(), stream: i, ..Message::new("stream") }.line();
                dc.write_all(&hdr).await.map_err(|e| anyhow!("stream {i}: sending header: {e}"))?;
                let (rd, wr) = tokio::io::split(dc);
                tcp_stream(Box::new(rd), Box::new(wr))
            }
            Proto::Udp => {
                let dc = cl.dial_udp_port(PORT).await.map_err(|e| anyhow!("dialing UDP stream {i}: {e}"))?;
                udp_stream(dc, None)
            }
        };
        t.attach(i, sc);
    }
    // Once done, the test's tasks drop their references to it, closing
    // its connections.
    let r = t.clone().run().await;
    t.done.set();
    r.map_err(|e| anyhow!(e))
}

// ---------------------------------------------------------------------
// The CLI command

#[derive(Args, Debug)]
pub struct PerfArgs {
    /// Test UDP instead of TCP.
    #[arg(long)]
    udp: bool,
    /// Have the server send to the client instead of the client sending to the server.
    #[arg(long)]
    reverse: bool,
    /// Send in both directions at once.
    #[arg(long)]
    bidir: bool,
    /// How long to send.
    #[arg(long = "time", default_value = "10s", value_parser = crate::util::parse_duration)]
    duration: Duration,
    /// Send this many bytes per stream instead of sending for --time, with an optional K, M, or G suffix
    /// (powers of 1000).
    #[arg(long)]
    bytes: Option<String>,
    /// Number of parallel streams.
    #[arg(long, default_value_t = 1)]
    parallel: usize,
    /// Bytes per TCP write or UDP datagram. If 0, 131072 for TCP and 1232 for UDP.
    #[arg(long, default_value_t = 0)]
    length: usize,
    /// Target bits per second per stream, with an optional K, M, or G suffix, or 0 for as fast as possible.
    /// If empty, as fast as possible for TCP and 1M for UDP.
    #[arg(long)]
    bitrate: Option<String>,
    /// How often to print progress; 0 disables progress lines.
    #[arg(long, default_value = "1s", value_parser = crate::util::parse_duration)]
    interval: Duration,
    /// How long to wait for a direct path before giving up (or, with --via-derp, running relayed).
    #[arg(long, default_value = "10s", value_parser = crate::util::parse_duration)]
    timeout: Duration,
    /// Run the test even if the path stays relayed through a DERP server, unless the relay is one of
    /// Tailscale's shared ones.
    #[arg(long)]
    via_derp: bool,
    addr: String,
}

/// Parses a number with an optional K, M, or G (powers of 1000) suffix.
fn parse_si(s: &str) -> Result<i64> {
    let (num, mult) = match s.char_indices().last() {
        Some((i, 'k' | 'K')) => (&s[..i], 1e3),
        Some((i, 'm' | 'M')) => (&s[..i], 1e6),
        Some((i, 'g' | 'G')) => (&s[..i], 1e9),
        _ => (s, 1.0),
    };
    let v: f64 = num.parse::<f64>()? * mult;
    if !v.is_finite() || v > i64::MAX as f64 || v < i64::MIN as f64 {
        bail!("out of range");
    }
    Ok(v as i64)
}

#[derive(Debug, Clone, Serialize)]
struct PathInfo {
    direct: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    endpoint: String,
    #[serde(rename = "derpRegion", skip_serializing_if = "String::is_empty")]
    derp_region: String,
    #[serde(with = "nanos")]
    rtt: Duration,
}

impl std::fmt::Display for PathInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.direct {
            write!(f, "direct via {}, rtt {}", self.endpoint, fmt_rtt(self.rtt))
        } else {
            write!(f, "relayed via DERP({}), rtt {}", self.derp_region, fmt_rtt(self.rtt))
        }
    }
}

async fn probe_path(cl: &tailcat::Client, timeout: Duration) -> tailcat::Result<PathInfo> {
    let r = cl.disco_ping(timeout).await?;
    Ok(PathInfo {
        direct: r.endpoint.is_some(),
        endpoint: r.endpoint.map(|e| e.to_string()).unwrap_or_default(),
        derp_region: if r.endpoint.is_some() { String::new() } else { crate::client::derp_region_name(&r) },
        rtt: r.latency,
    })
}

async fn wait_for_direct_path(cl: &tailcat::Client, timeout: Duration) -> Result<PathInfo> {
    let deadline = Instant::now() + timeout;
    loop {
        let t0 = Instant::now();
        let remaining = deadline.saturating_duration_since(t0).max(Duration::from_millis(1));
        let p = match tokio::time::timeout(remaining, probe_path(cl, remaining)).await {
            Ok(Ok(p)) => p,
            Ok(Err(tailcat::Error::Timeout(_))) | Err(_) => {
                bail!("no reply to pings after {}", go_duration(timeout))
            }
            Ok(Err(e)) => return Err(e.into()),
        };
        if p.direct || deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(500) {
            return Ok(p);
        }
        tokio::time::sleep(Duration::from_secs(1).saturating_sub(t0.elapsed())).await;
    }
}

fn shared_tailscale_derp(r: &tailcat::DerpRegion) -> Option<String> {
    r.nodes
        .iter()
        .find(|n| {
            let h = n.host_name.trim_end_matches('.').to_lowercase();
            h.ends_with(".ipn.dev") || h.ends_with(".tailscale.com")
        })
        .map(|n| n.host_name.clone())
}

pub async fn run(g: &Global, a: PerfArgs) -> Result<()> {
    if a.reverse && a.bidir {
        return Err(crate::usagef!("--reverse and --bidir are exclusive"));
    }
    let mut p = Params {
        proto: if a.udp { Proto::Udp } else { Proto::Tcp },
        direction: if a.bidir {
            Direction::Bidirectional
        } else if a.reverse {
            Direction::Download
        } else {
            Direction::Upload
        },
        duration: a.duration,
        bytes: 0,
        streams: a.parallel,
        length: a.length,
        bitrate: if a.udp { 1_000_000 } else { 0 },
        interval: a.interval,
    };
    if let Some(b) = &a.bytes {
        p.bytes = parse_si(b).ok().filter(|n| *n > 0).ok_or_else(|| crate::usagef!("invalid --bytes value {b:?}"))?;
        p.duration = Duration::ZERO;
    }
    if let Some(b) = &a.bitrate {
        p.bitrate =
            parse_si(b).ok().filter(|n| *n >= 0).ok_or_else(|| crate::usagef!("invalid --bitrate value {b:?}"))?;
    }
    if p.length == 0 {
        p.length = if a.udp { tailcat::MAX_UDP_PAYLOAD } else { DEFAULT_TCP_LENGTH };
    }
    if a.parallel < 1 {
        return Err(crate::usagef!("--parallel must be at least 1"));
    }
    if p.bytes == 0 && p.duration.is_zero() {
        return Err(crate::usagef!("--time must be positive"));
    }

    let addr = crate::addrarg::tailcat_addr_arg(&a.addr).await?;
    let cl = crate::client::new_client(g, addr, crate::keys::client_key(g)?);
    let before = wait_for_direct_path(&cl, a.timeout).await.map_err(|e| anyhow!("perf: {e}"))?;
    eprintln!("# path: {before}");
    if !before.direct {
        if !a.via_derp {
            bail!(
                "perf: no direct path to the server after {}; refusing to run a throughput test through a DERP relay (--via-derp allows it, for a relay you run yourself)",
                go_duration(a.timeout)
            );
        }
        if let Some(host) = cl.derp_region().as_ref().and_then(shared_tailscale_derp) {
            bail!(
                "perf: refusing to run a throughput test through Tailscale's shared DERP relay {host}; --via-derp is only for relays you run yourself"
            );
        }
    }
    if p.proto == Proto::Udp && p.length > tailcat::MAX_UDP_PAYLOAD {
        eprintln!(
            "# ⚠️ WARNING: {}-byte datagrams exceed the tunnel MTU's {}-byte payload and may not arrive",
            p.length,
            tailcat::MAX_UDP_PAYLOAD
        );
    }
    let progress: Option<OnProgress> = if !g.json && !p.interval.is_zero() {
        let pp = p.clone();
        Some(Box::new(move |pr: Progress| println!("{}", progress_line(&pp, &pr))))
    } else {
        None
    };
    if !g.json {
        println!("{}", describe(&p));
    }
    let res = tokio::select! {
        r = run_client(&cl, p, progress) => r.map_err(|e| anyhow!("perf: {e}"))?,
        _ = crate::forward::shutdown_signal() => bail!("perf: interrupted"),
    };
    let probe = tokio::time::timeout(Duration::from_secs(3), probe_path(&cl, Duration::from_secs(3)));
    // The test's connections close as it ends, but the TCP stack lives in
    // this process: let their last segments (in a download, the "result"
    // the server is waiting for) get out before exiting, or the server
    // waits out its report timeout, and is busy for new tests meanwhile.
    let (after, _) = tokio::join!(probe, cl.drain_tcp(Duration::from_secs(5)));
    let after = after.ok().and_then(|r| r.ok());
    if g.json {
        let mut v = serde_json::json!({ "path": before });
        if let Some(a) = &after {
            v["pathAfter"] = serde_json::to_value(a)?;
        }
        if let serde_json::Value::Object(m) = serde_json::to_value(&res)? {
            for (k, x) in m {
                v[k] = x;
            }
        }
        let mut buf = Vec::new();
        let fmt = serde_json::ser::PrettyFormatter::with_indent(b"\t");
        v.serialize(&mut serde_json::Serializer::with_formatter(&mut buf, fmt))?;
        println!("{}", String::from_utf8(buf)?);
        return Ok(());
    }
    for l in result_lines(&res) {
        println!("{l}");
    }
    if let Some(a) = after
        && a.direct != before.direct
    {
        eprintln!("# path changed during the test, now: {a}");
    }
    Ok(())
}

fn describe(p: &Params) -> String {
    let mut s = format!(
        "{}, {}, {} stream{}",
        if p.proto == Proto::Tcp { "TCP" } else { "UDP" },
        direction_name(p.direction),
        p.streams,
        if p.streams != 1 { "s" } else { "" }
    );
    if p.bytes > 0 {
        s += &format!(", {} per stream", fmt_bytes(p.bytes));
    } else {
        s += &format!(", {}", go_duration(p.duration));
    }
    if p.bitrate > 0 {
        s += &format!(", {} per stream", fmt_si(p.bitrate as f64, "bit/s"));
    }
    s
}

fn direction_name(d: Direction) -> &'static str {
    match d {
        Direction::Upload => "client -> server",
        Direction::Download => "server -> client",
        Direction::Bidirectional => "both directions",
    }
}

fn progress_line(p: &Params, pr: &Progress) -> String {
    let mut s = format!("[{:6.1}s]", pr.elapsed.as_secs_f64());
    if p.direction != Direction::Download {
        s += &format!("  sent {:>9} {:>13}", fmt_bytes(pr.sent.bytes), fmt_rate(pr.sent.bytes, p.interval));
    }
    if p.direction != Direction::Upload {
        s += &format!("  received {:>9} {:>13}", fmt_bytes(pr.received.bytes), fmt_rate(pr.received.bytes, p.interval));
    }
    if !pr.rtt.is_zero() {
        s += &format!("  rtt {}", fmt_rtt(pr.rtt));
    }
    s
}

fn result_lines(res: &PerfResult) -> Vec<String> {
    let udp = res.params.proto == Proto::Udp;
    // The sent and received lines of one direction.
    let pair = |indent: &str, sent: &Option<Stats>, recv: &Option<Stats>| {
        let (Some(sent), Some(recv)) = (sent, recv) else { return Vec::new() };
        let line = |what: &str, st: &Stats| {
            format!(
                "{indent}{what:<9} {:>9} in {:6.1}s {:>13}",
                fmt_bytes(st.bytes),
                st.duration.as_secs_f64(),
                fmt_rate(st.bytes, st.duration)
            )
        };
        let (mut s, mut r) = (line("sent", sent), line("received", recv));
        if udp {
            s += &format!("  {} datagrams", sent.datagrams);
            r += &format!(
                "  {} datagrams, {} lost ({:.1}%), {} reordered, jitter {}",
                recv.datagrams,
                sent.datagrams - recv.datagrams,
                loss_pct(sent, recv),
                recv.reordered,
                fmt_rtt(recv.jitter)
            );
        }
        vec![s, r]
    };
    let (up, down) = ((&res.client_sent, &res.server_received), (&res.server_sent, &res.client_received));
    let mut out = Vec::new();
    if res.params.direction == Direction::Bidirectional {
        out.push("client -> server:".to_string());
        out.extend(pair("  ", up.0, up.1));
        out.push("server -> client:".to_string());
        out.extend(pair("  ", down.0, down.1));
    } else {
        out.extend(pair("", up.0, up.1));
        out.extend(pair("", down.0, down.1));
    }
    if let Some(r) = &res.rtt {
        out.push(format!(
            "rtt under load  min {}  avg {}  max {}  ({} samples)",
            fmt_rtt(r.min),
            fmt_rtt(r.avg),
            fmt_rtt(r.max),
            r.count
        ));
    }
    out
}

/// The percentage of sent datagrams that weren't received.
fn loss_pct(sent: &Stats, recv: &Stats) -> f64 {
    if sent.datagrams > 0 { (sent.datagrams - recv.datagrams) as f64 / sent.datagrams as f64 * 100.0 } else { 0.0 }
}

/// The one-line summary the server prints per test.
fn perf_summary(res: &PerfResult) -> String {
    let udp = res.params.proto == Proto::Udp;
    let rate = |sent: &Option<Stats>, recv: &Option<Stats>| {
        let Some(recv) = recv else { return "?".to_string() };
        let mut s = fmt_rate(recv.bytes, recv.duration);
        if let (true, Some(sent)) = (udp, sent)
            && sent.datagrams > 0
        {
            s += &format!(" ({:.1}% lost)", loss_pct(sent, recv));
        }
        s
    };
    let proto = if udp { "UDP" } else { "TCP" };
    let up = || format!("client -> server {}", rate(&res.client_sent, &res.server_received));
    let down = || format!("server -> client {}", rate(&res.server_sent, &res.client_received));
    match res.params.direction {
        Direction::Upload => format!("{proto} {}", up()),
        Direction::Download => format!("{proto} {}", down()),
        Direction::Bidirectional => format!("{proto} {}, {}", up(), down()),
    }
}

/// Formats to three significant digits with an SI prefix and unit.
fn fmt_si(mut v: f64, unit: &str) -> String {
    const P: [&str; 5] = ["", "K", "M", "G", "T"];
    let mut i = 0;
    while v >= 1000.0 && i < P.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    let prec = if i == 0 || v >= 100.0 {
        0
    } else if v >= 10.0 {
        1
    } else {
        2
    };
    format!("{v:.prec$} {}{unit}", P[i])
}

fn fmt_bytes(n: i64) -> String {
    fmt_si(n as f64, "B")
}

fn fmt_rate(n: i64, d: Duration) -> String {
    if d.is_zero() {
        return "-".into();
    }
    fmt_si(n as f64 * 8.0 / d.as_secs_f64(), "bit/s")
}

/// Formats a round-trip time rounded to 10µs.
fn fmt_rtt(d: Duration) -> String {
    let n = d.as_nanos() as u64;
    go_duration(Duration::from_nanos((n + 5_000) / 10_000 * 10_000))
}

/// Formats a duration like Go's `time.Duration.String`.
pub fn go_duration(d: Duration) -> String {
    // v / 10^prec with its fractional digits, trailing zeros trimmed.
    fn decimal(v: u128, prec: u32, unit: &str) -> String {
        let div = 10u128.pow(prec);
        let frac = format!("{:0w$}", v % div, w = prec as usize);
        match frac.trim_end_matches('0') {
            "" => format!("{}{unit}", v / div),
            f => format!("{}.{f}{unit}", v / div),
        }
    }
    let n = d.as_nanos();
    match n {
        0 => "0s".into(),
        1..1_000 => format!("{n}ns"),
        1_000..1_000_000 => decimal(n, 3, "µs"),
        1_000_000..1_000_000_000 => decimal(n, 6, "ms"),
        _ => {
            let (secs, nanos) = (n / 1_000_000_000, n % 1_000_000_000);
            let (h, m) = (secs / 3600, secs % 3600 / 60);
            let sec = decimal(secs % 60 * 1_000_000_000 + nanos, 9, "s");
            match (h, m) {
                (0, 0) => sec,
                (0, m) => format!("{m}m{sec}"),
                (h, m) => format!("{h}h{m}m{sec}"),
            }
        }
    }
}

#[cfg(test)]
mod model_tests;

#[cfg(test)]
mod tests {
    use hegel::TestCase;
    use hegel::generators::{self as gs, Generator};
    use tokio::io::{duplex, split};

    use super::*;

    pub(super) const DIRECTIONS: [Direction; 3] = [Direction::Upload, Direction::Download, Direction::Bidirectional];

    #[test]
    fn go_durations() {
        assert_eq!(go_duration(Duration::from_secs(10)), "10s");
        assert_eq!(go_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(go_duration(Duration::from_micros(1230)), "1.23ms");
        assert_eq!(go_duration(Duration::from_micros(680)), "680µs");
        assert_eq!(go_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(fmt_rtt(Duration::from_nanos(1_234_567)), "1.23ms");
        // Cases checked against Go's time.Duration.String.
        assert_eq!(go_duration(Duration::ZERO), "0s");
        assert_eq!(go_duration(Duration::from_nanos(999)), "999ns");
        assert_eq!(go_duration(Duration::from_nanos(1_500)), "1.5µs");
        assert_eq!(go_duration(Duration::from_nanos(1_000_001)), "1.000001ms");
        assert_eq!(go_duration(Duration::from_nanos(1_000_000_001)), "1.000000001s");
        assert_eq!(go_duration(Duration::from_secs(600)), "10m0s");
        assert_eq!(go_duration(Duration::from_secs(3600)), "1h0m0s");
        assert_eq!(go_duration(Duration::from_millis(3_723_500)), "1h2m3.5s");
        assert_eq!(fmt_rtt(Duration::from_nanos(4_999)), "0s");
        assert_eq!(fmt_rtt(Duration::from_nanos(5_000)), "10µs");
    }

    #[test]
    fn si() {
        assert_eq!(fmt_si(1.18e9, "B"), "1.18 GB");
        assert_eq!(fmt_si(943e6, "bit/s"), "943 Mbit/s");
        assert_eq!(fmt_si(12.0, "B"), "12 B");
        assert_eq!(fmt_si(999.0, "B"), "999 B");
        assert_eq!(fmt_si(12_345.0, "B"), "12.3 KB");
        assert_eq!(fmt_si(2e15, "B"), "2000 TB");
        assert_eq!(fmt_rate(1_000_000, Duration::from_secs(8)), "1.00 Mbit/s");
        assert_eq!(fmt_rate(1, Duration::ZERO), "-");
        assert_eq!(parse_si("10M").unwrap(), 10_000_000);
        assert_eq!(parse_si("1.5G").unwrap(), 1_500_000_000);
        assert_eq!(parse_si("2k").unwrap(), 2_000);
        assert_eq!(parse_si("7").unwrap(), 7);
        assert!(parse_si("x").is_err());
        assert!(parse_si("").is_err());
        assert!(parse_si("M").is_err());
        assert!(parse_si("1e30G").is_err());
    }

    fn params() -> Params {
        Params {
            proto: Proto::Udp,
            direction: Direction::Bidirectional,
            duration: Duration::from_secs(10),
            bytes: 0,
            streams: 1,
            length: 1232,
            bitrate: 1_000_000,
            interval: Duration::from_secs(1),
        }
    }

    /// Validates `p` with the server's default limits.
    fn server_validate(p: &Params) -> Result<(), String> {
        p.validate(DEFAULT_MAX_STREAMS, DEFAULT_MAX_DURATION)
    }

    #[test]
    fn wire_formats() {
        let hello = Message { params: Some(params()), ..Message::new("hello") };
        assert_eq!(
            serde_json::to_string(&hello).unwrap(),
            r#"{"type":"hello","params":{"proto":"udp","dir":"both","duration":10000000000,"streams":1,"length":1232,"bitrate":1000000,"interval":1000000000}}"#
        );

        let h = UdpHeader { id: [1; 8], stream: 2, flags: FLAG_FIN, seq: 9, send_time: 42 };
        let b = h.datagram();
        assert_eq!(b[..11], [1, 1, 1, 1, 1, 1, 1, 1, 0, 2, FLAG_FIN]);
        let back = UdpHeader::parse(&b).unwrap();
        assert_eq!((back.id, back.stream, back.flags, back.seq, back.send_time), ([1; 8], 2, FLAG_FIN, 9, 42));
        assert!(UdpHeader::parse(&b[..31]).is_none());

        // Zero fields are omitted, like Go's omitempty.
        let stats = Stats { bytes: 5, duration: Duration::from_millis(1), ..Default::default() };
        let done = Message { stats: Some(stats), ..Message::new("done") };
        assert_eq!(serde_json::to_string(&done).unwrap(), r#"{"type":"done","stats":{"bytes":5,"duration":1000000}}"#);

        let ok: Message = serde_json::from_str(r#"{"type":"ok","id":"0102030405060708","extra":1}"#).unwrap();
        assert_eq!(parse_id(&ok.id), Some([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(parse_id("0102"), None);
        assert_eq!(Message::error("no").line(), b"{\"type\":\"error\",\"error\":\"no\"}\n");
    }

    /// Any duration, well past the ~292 years Go's time.Duration holds.
    fn draw_duration(tc: &TestCase) -> Duration {
        if tc.draw(gs::booleans()) {
            return tc.draw(gs::durations());
        }
        let secs = tc.draw(gs::integers::<u64>());
        let nanos = tc.draw(gs::integers::<u32>().max_value(999_999_999));
        Duration::new(secs, nanos)
    }

    /// Params survive the hello line, with durations saturating at Go's
    /// limit, and the server judges them as the client would.
    #[hegel::test]
    fn params_round_trip(tc: TestCase) {
        let p = Params {
            proto: tc.draw(gs::sampled_from(&[Proto::Tcp, Proto::Udp]).print_as_debug()),
            direction: tc.draw(gs::sampled_from(&DIRECTIONS).print_as_debug()),
            duration: draw_duration(&tc),
            bytes: tc.draw(gs::integers()),
            streams: tc.draw(gs::integers()),
            length: tc.draw(gs::integers()),
            bitrate: tc.draw(gs::integers()),
            interval: draw_duration(&tc),
        };
        let hello = Message { params: Some(p.clone()), ..Message::new("hello") };

        let back = serde_json::from_slice::<Message>(&hello.line()).unwrap().params.expect("params");

        let go_max = Duration::from_nanos(i64::MAX as u64);
        let want = Params { duration: p.duration.min(go_max), interval: p.interval.min(go_max), ..p.clone() };
        assert_eq!(back, want);
        let (judged, judged_back) = (server_validate(&p).is_ok(), server_validate(&back).is_ok());
        assert_eq!(judged_back, judged, "the server judges {back:?} differently from {p:?}");
    }

    #[hegel::test]
    fn udp_header_round_trip(tc: TestCase) {
        let h = UdpHeader {
            id: tc.draw(gs::integers::<u64>()).to_be_bytes(),
            stream: tc.draw(gs::integers()),
            flags: tc.draw(gs::integers()),
            seq: tc.draw(gs::integers()),
            send_time: tc.draw(gs::integers()),
        };
        let mut b = vec![0xff; UDP_HEADER_LEN + tc.draw(gs::integers::<usize>().max_value(64))];
        h.put(&mut b);
        assert_eq!(b[11..16], [0; 5], "reserved bytes aren't zero");
        assert_eq!(UdpHeader::parse(&b), Some(h));
        assert_eq!(UdpHeader::parse(&h.datagram()), Some(h));
    }

    #[test]
    fn validates_params() {
        assert!(server_validate(&params()).is_ok());
        let bad = |f: fn(&mut Params), want: &str| {
            let mut p = params();
            f(&mut p);
            let e = server_validate(&p).unwrap_err();
            assert!(e.contains(want), "{e:?} doesn't contain {want:?}");
        };
        bad(|p| p.bytes = -1, "negative byte count");
        bad(|p| p.duration = Duration::ZERO, "duration or byte count");
        bad(|p| p.duration = Duration::from_secs(601), "exceeds the server's limit of 10m0s");
        bad(|p| p.streams = 0, "at least one stream");
        bad(|p| p.streams = 129, "129 streams");
        bad(|p| p.length = 31, "smaller than the 32-byte header");
        bad(|p| p.length = MAX_UDP_SIZE + 1, "UDP length");
        bad(
            |p| {
                p.proto = Proto::Tcp;
                p.length = MAX_LENGTH + 1;
            },
            "TCP length",
        );
        bad(|p| p.bitrate = -1, "negative bitrate");
        bad(|p| p.interval = Duration::from_millis(50), "interval 50ms is shorter than 100ms");
        // A byte count lifts the duration limit, and clients have no limits.
        let mut p = params();
        (p.bytes, p.duration) = (1, Duration::from_secs(10_000));
        assert!(server_validate(&p).is_ok());
        p.streams = 1000;
        assert!(p.validate(0, Duration::ZERO).is_ok());
    }

    #[tokio::test]
    async fn control_lines() {
        let (a, b) = duplex(1 << 20);
        let (_ar, mut aw) = split(a);
        let mut br = BufReader::new(b);
        aw.write_all(&Message::new("ready").line()).await.unwrap();
        aw.write_all(b"not json\n").await.unwrap();
        aw.write_all(&vec![b' '; CTRL_BUF_SIZE + 1]).await.unwrap();

        assert_eq!(read_message(&mut br).await.unwrap().typ, "ready");
        let e = read_message(&mut br).await.unwrap_err();
        assert!(e.to_string().contains("bad control message"), "{e}");
        let e = read_message(&mut br).await.unwrap_err();
        assert!(e.to_string().contains("control line too long"), "{e}");
        drop(aw);
    }

    fn stats(bytes: i64, datagrams: i64, secs: u64) -> Option<Stats> {
        Some(Stats { bytes, datagrams, duration: Duration::from_secs(secs), ..Default::default() })
    }

    #[test]
    fn reports() {
        let res = PerfResult {
            params: params(),
            client_sent: stats(1_250_000, 1000, 10),
            server_received: stats(1_120_000, 900, 10),
            server_sent: stats(0, 0, 10),
            client_received: None,
            rtt: Some(Rtt {
                min: Duration::from_millis(1),
                avg: Duration::from_millis(2),
                max: Duration::from_millis(3),
                count: 4,
            }),
        };
        assert_eq!(
            result_lines(&res),
            [
                "client -> server:",
                "  sent        1.25 MB in   10.0s   1.00 Mbit/s  1000 datagrams",
                "  received    1.12 MB in   10.0s    896 Kbit/s  900 datagrams, 100 lost (10.0%), 0 reordered, jitter 0s",
                "server -> client:",
                "rtt under load  min 1ms  avg 2ms  max 3ms  (4 samples)",
            ]
        );
        assert_eq!(perf_summary(&res), "UDP client -> server 896 Kbit/s (10.0% lost), server -> client ?");

        let tcp_download = Params { proto: Proto::Tcp, direction: Direction::Download, ..params() };
        let res = PerfResult { params: tcp_download, ..res };
        assert_eq!(perf_summary(&res), "TCP server -> client ?");
        assert_eq!(describe(&res.params), "TCP, server -> client, 1 stream, 10s, 1.00 Mbit/s per stream");
        let p = Params { bytes: 5_000_000, streams: 2, bitrate: 0, ..params() };
        assert_eq!(describe(&p), "UDP, both directions, 2 streams, 5.00 MB per stream");
    }
}
