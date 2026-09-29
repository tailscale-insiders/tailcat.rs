//! `tailcat perf` and the `perf` service: an iperf-like throughput and
//! latency test, wire-compatible with the Go implementation.
//!
//! The client opens a TCP control connection to [`PORT`] and sends a
//! hello line with the test parameters. Data flows on separate TCP
//! connections or UDP flows to the same port, one per stream. Control
//! messages are JSON lines; UDP datagrams carry a 32-byte header with
//! the test ID, stream, flags, sequence number and send time.

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use clap::Args;
use serde::{Deserialize, Serialize};
use tailcat::{TcpStream, UdpConn};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::watch;

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

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

/// Go's time.Duration marshals to JSON as integer nanoseconds.
mod nanos {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(d.as_nanos() as i64)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let n = i64::deserialize(d)?;
        Ok(Duration::from_nanos(n.max(0) as u64))
    }
    pub fn is_zero(d: &Duration) -> bool {
        d.is_zero()
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Params {
    pub proto: Proto,
    #[serde(rename = "dir")]
    pub direction: Direction,
    #[serde(default, with = "nanos", skip_serializing_if = "nanos::is_zero")]
    pub duration: Duration,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes: i64,
    pub streams: usize,
    pub length: usize,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bitrate: i64,
    #[serde(default, with = "nanos", skip_serializing_if = "nanos::is_zero")]
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
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub datagrams: i64,
}

/// What one side sent or received.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub bytes: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub datagrams: i64,
    #[serde(with = "nanos")]
    pub duration: Duration,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intervals: Vec<Interval>,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub reordered: i64,
    #[serde(default, with = "nanos", skip_serializing_if = "nanos::is_zero")]
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
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    stream: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    t: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stats: Option<Stats>,
}

impl Message {
    fn new(t: &str) -> Self {
        Message { typ: t.into(), ..Default::default() }
    }
}

fn unix_nanos() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Default)]
struct UdpHeader {
    id: [u8; 8],
    stream: u16,
    flags: u8,
    seq: u64,
    send_time: i64,
}

impl UdpHeader {
    fn put(&self, b: &mut [u8]) {
        b[0..8].copy_from_slice(&self.id);
        b[8..10].copy_from_slice(&self.stream.to_be_bytes());
        b[10] = self.flags;
        b[11..16].fill(0);
        b[16..24].copy_from_slice(&self.seq.to_be_bytes());
        b[24..32].copy_from_slice(&(self.send_time as u64).to_be_bytes());
    }

    fn parse(b: &[u8]) -> Option<UdpHeader> {
        if b.len() < UDP_HEADER_LEN {
            return None;
        }
        Some(UdpHeader {
            id: b[0..8].try_into().ok()?,
            stream: u16::from_be_bytes([b[8], b[9]]),
            flags: b[10],
            seq: u64::from_be_bytes(b[16..24].try_into().ok()?),
            send_time: u64::from_be_bytes(b[24..32].try_into().ok()?) as i64,
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
        let mut b = serde_json::to_vec(m).expect("message serializes");
        b.push(b'\n');
        let mut w = self.wr.lock().await;
        w.write_all(&b).await?;
        w.flush().await
    }

    async fn recv(&self) -> std::io::Result<Message> {
        let mut rd = self.rd.lock().await;
        read_message(&mut rd).await
    }
}

async fn read_message<R: AsyncRead + Unpin>(br: &mut BufReader<R>) -> std::io::Result<Message> {
    let mut line = Vec::new();
    let n = (&mut *br).take(CTRL_BUF_SIZE as u64).read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    if !line.ends_with(b"\n") {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "control line too long"));
    }
    serde_json::from_slice(&line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad control message: {e}")))
}

/// One stream's connection.
enum StreamConn {
    Tcp { rd: Option<BoxRead>, wr: Option<BoxWrite> },
    Udp { conn: Arc<UdpConn>, pending: Option<Vec<u8>> },
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
#[derive(Clone)]
struct Flag(watch::Sender<bool>);

impl Flag {
    fn new() -> Self {
        Flag(watch::channel(false).0)
    }
    fn set(&self) {
        self.0.send_replace(true);
    }
    fn is_set(&self) -> bool {
        *self.0.borrow()
    }
    async fn wait(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|v| *v).await;
    }
}

struct Test {
    p: Params,
    id: Mutex<[u8; 8]>,
    is_server: bool,
    ctrl: Ctrl,
    streams: Vec<Mutex<Option<StreamConn>>>,
    attached: AtomicI64,
    all_attached: Flag,
    ready: Flag,
    peer_done: Flag,
    peer_result: Flag,
    done: Flag,
    err: Mutex<Option<String>>,
    peer_sent: Mutex<Option<Stats>>,
    peer_received: Mutex<Option<Stats>>,
    send_bytes: AtomicI64,
    send_datagrams: AtomicI64,
    recv_bytes: AtomicI64,
    recv_datagrams: AtomicI64,
    send_intervals: Mutex<Vec<Interval>>,
    recv_intervals: Mutex<Vec<Interval>>,
    rtt: Mutex<Option<(Rtt, Duration, Duration)>>, // (stats, sum, last)
    /// This side's final sender and receiver stats.
    sent: Mutex<Option<Stats>>,
    received: Mutex<Option<Stats>>,
    on_progress: Option<Box<dyn Fn(Progress) + Send + Sync>>,
}

/// A client-side snapshot at the end of a reporting interval.
pub struct Progress {
    pub elapsed: Duration,
    pub sent: Interval,
    pub received: Interval,
    pub rtt: Duration,
}

impl Test {
    fn new(p: Params, is_server: bool, ctrl: Ctrl) -> Arc<Test> {
        let n = p.streams;
        Arc::new(Test {
            p,
            id: Mutex::new([0; 8]),
            is_server,
            ctrl,
            streams: (0..n).map(|_| Mutex::new(None)).collect(),
            attached: AtomicI64::new(0),
            all_attached: Flag::new(),
            ready: Flag::new(),
            peer_done: Flag::new(),
            peer_result: Flag::new(),
            done: Flag::new(),
            err: Mutex::new(None),
            peer_sent: Mutex::new(None),
            peer_received: Mutex::new(None),
            send_bytes: AtomicI64::new(0),
            send_datagrams: AtomicI64::new(0),
            recv_bytes: AtomicI64::new(0),
            recv_datagrams: AtomicI64::new(0),
            send_intervals: Mutex::new(Vec::new()),
            recv_intervals: Mutex::new(Vec::new()),
            rtt: Mutex::new(None),
            sent: Mutex::new(None),
            received: Mutex::new(None),
            on_progress: None,
        })
    }

    fn id(&self) -> [u8; 8] {
        *self.id.lock().unwrap()
    }

    fn sends(&self) -> bool {
        if self.is_server { self.p.direction != Direction::Upload } else { self.p.direction != Direction::Download }
    }

    fn receives(&self) -> bool {
        if self.is_server { self.p.direction != Direction::Download } else { self.p.direction != Direction::Upload }
    }

    fn fail(&self, e: String) {
        let mut err = self.err.lock().unwrap();
        if !self.done.is_set() {
            *err = Some(e);
            self.done.set();
        }
    }

    fn attach(&self, index: usize, c: StreamConn) -> bool {
        let mut slot = self.streams[index].lock().unwrap();
        if slot.is_some() {
            return false;
        }
        *slot = Some(c);
        if self.attached.fetch_add(1, Ordering::SeqCst) + 1 == self.streams.len() as i64 {
            self.all_attached.set();
        }
        true
    }

    fn peer_reported(&self) -> bool {
        (!self.receives() || self.peer_done.is_set()) && (!self.sends() || self.peer_result.is_set())
    }

    fn record_rtt(&self, d: Duration) {
        let mut g = self.rtt.lock().unwrap();
        let (mut r, mut sum) = match g.take() {
            Some((r, sum, _)) => (r, sum),
            None => (Rtt { min: d, avg: d, max: d, count: 0 }, Duration::ZERO),
        };
        r.min = r.min.min(d);
        r.max = r.max.max(d);
        r.count += 1;
        sum += d;
        r.avg = sum / r.count as u32;
        *g = Some((r, sum, d));
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
                    self.record_rtt(Duration::from_nanos(d.max(0) as u64));
                }
                "ready" => self.ready.set(),
                "done" => {
                    *self.peer_sent.lock().unwrap() = m.stats;
                    self.peer_done.set();
                }
                "result" => {
                    *self.peer_received.lock().unwrap() = m.stats;
                    self.peer_result.set();
                }
                "error" => {
                    self.fail(format!("peer: {}", m.error));
                    return;
                }
                _ => {}
            }
        }
    }

    async fn send_openers(&self) -> std::io::Result<()> {
        let id = self.id();
        for (i, s) in self.streams.iter().enumerate() {
            let conn = match &*s.lock().unwrap() {
                Some(StreamConn::Udp { conn, .. }) => conn.clone(),
                _ => continue,
            };
            let mut buf = [0u8; UDP_HEADER_LEN];
            UdpHeader { id, stream: i as u16, flags: FLAG_OPEN, ..Default::default() }.put(&mut buf);
            conn.send(&buf).await?;
        }
        Ok(())
    }

    async fn wait_ready(&self) -> Result<(), String> {
        let timeout = tokio::time::sleep(HANDSHAKE_TIMEOUT);
        tokio::pin!(timeout);
        if self.is_server {
            tokio::select! {
                _ = self.all_attached.wait() => {
                    return self.ctrl.send(&Message::new("ready")).await.map_err(|e| e.to_string());
                }
                _ = self.done.wait() => return Err(self.err.lock().unwrap().clone().unwrap_or_default()),
                _ = &mut timeout => return Err("timed out waiting for the client's streams to connect".into()),
            }
        }
        let udp = self.p.proto == Proto::Udp;
        if udp {
            self.send_openers().await.map_err(|e| format!("opening UDP flow: {e}"))?;
        }
        let mut openers = tokio::time::interval(OPENER_INTERVAL);
        openers.tick().await;
        loop {
            tokio::select! {
                _ = self.ready.wait() => return Ok(()),
                _ = self.done.wait() => return Err(self.err.lock().unwrap().clone().unwrap_or_default()),
                _ = &mut timeout => return Err("timed out waiting for the server to be ready".into()),
                _ = openers.tick(), if udp => {
                    self.send_openers().await.map_err(|e| format!("opening UDP flow: {e}"))?;
                }
            }
        }
    }

    fn take_stream(&self, i: usize) -> Option<StreamConn> {
        self.streams[i].lock().unwrap().take()
    }

    async fn run(self: Arc<Self>) -> Result<PerfResult, String> {
        tokio::spawn(self.clone().read_control());
        if let Err(e) = self.wait_ready().await {
            self.fail(e.clone());
            return Err(e);
        }
        let start = Instant::now();
        let stop = Flag::new();
        if !self.p.interval.is_zero() {
            tokio::spawn(self.clone().intervals(start, stop.clone()));
        }
        if !self.is_server {
            tokio::spawn(self.clone().pings(stop.clone()));
        }

        // Split each stream into its send and receive sides.
        let mut send_sides = Vec::new();
        let mut recv_sides = Vec::new();
        for i in 0..self.streams.len() {
            match self.take_stream(i) {
                Some(StreamConn::Tcp { rd, wr }) => {
                    send_sides.push(SendSide::Tcp(wr));
                    recv_sides.push(RecvSide::Tcp(rd));
                }
                Some(StreamConn::Udp { conn, pending }) => {
                    send_sides.push(SendSide::Udp(conn.clone()));
                    recv_sides.push(RecvSide::Udp(conn, pending));
                }
                None => return Err("stream not attached".into()),
            }
        }
        let senders = {
            let t = self.clone();
            async move {
                if t.sends() {
                    t.run_senders(start, send_sides).await
                } else {
                    // Unused write sides stay open until the test ends, so the
                    // peer doesn't see an early EOF.
                    send_sides
                }
            }
        };
        let receivers = {
            let t = self.clone();
            async move {
                if t.receives() {
                    t.run_receivers(recv_sides).await;
                }
            }
        };
        // Hold the (possibly half-closed) connections until the test ends.
        let (held, _) = tokio::join!(senders, receivers);
        stop.set();

        // Wait for the peer's view of what it sent and received.
        let deadline = tokio::time::Instant::now() + REPORT_TIMEOUT;
        if self.receives() {
            tokio::select! {
                _ = self.peer_done.wait() => {}
                _ = self.done.wait() => {}
                _ = tokio::time::sleep_until(deadline) => self.fail("timed out waiting for the peer's sender report".into()),
            }
        }
        if self.sends() {
            tokio::select! {
                _ = self.peer_result.wait() => {}
                _ = self.done.wait() => {}
                _ = tokio::time::sleep_until(deadline) => self.fail("timed out waiting for the peer's receiver report".into()),
            }
        }
        let err = self.err.lock().unwrap().clone();
        self.done.set();
        drop(held);
        if let Some(e) = err {
            return Err(e);
        }
        let peer_sent = self.peer_sent.lock().unwrap().clone();
        let peer_received = self.peer_received.lock().unwrap().clone();
        let (sent, received) = (self.sent.lock().unwrap().clone(), self.received.lock().unwrap().clone());
        let rtt = self.rtt.lock().unwrap().as_ref().map(|r| r.0.clone());
        Ok(if self.is_server {
            PerfResult {
                params: self.p.clone(),
                server_sent: sent,
                server_received: received,
                client_sent: peer_sent,
                client_received: peer_received,
                rtt: None,
            }
        } else {
            PerfResult {
                params: self.p.clone(),
                client_sent: sent,
                client_received: received,
                server_sent: peer_sent,
                server_received: peer_received,
                rtt,
            }
        })
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
            let sent = Interval {
                bytes: self.send_bytes.load(Ordering::Relaxed),
                datagrams: self.send_datagrams.load(Ordering::Relaxed),
            };
            let recv = Interval {
                bytes: self.recv_bytes.load(Ordering::Relaxed),
                datagrams: self.recv_datagrams.load(Ordering::Relaxed),
            };
            let ds = Interval { bytes: sent.bytes - last_sent.bytes, datagrams: sent.datagrams - last_sent.datagrams };
            let dr = Interval { bytes: recv.bytes - last_recv.bytes, datagrams: recv.datagrams - last_recv.datagrams };
            last_sent = sent;
            last_recv = recv;
            if self.sends() {
                self.send_intervals.lock().unwrap().push(ds.clone());
            }
            if self.receives() {
                self.recv_intervals.lock().unwrap().push(dr.clone());
            }
            if let Some(f) = &self.on_progress {
                let rtt = self.rtt.lock().unwrap().as_ref().map(|r| r.2).unwrap_or_default();
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

    async fn run_senders(self: &Arc<Self>, start: Instant, sides: Vec<SendSide>) -> Vec<SendSide> {
        let mut tasks = Vec::new();
        for (i, side) in sides.into_iter().enumerate() {
            let t = self.clone();
            tasks.push(tokio::spawn(async move { t.send_stream(i, side, start).await }));
        }
        let mut sides = Vec::new();
        for t in tasks {
            if let Ok(s) = t.await {
                sides.push(s);
            }
        }
        if self.done.is_set() {
            return sides;
        }
        let stats = Stats {
            bytes: self.send_bytes.load(Ordering::Relaxed),
            datagrams: self.send_datagrams.load(Ordering::Relaxed),
            duration: start.elapsed(),
            intervals: self.send_intervals.lock().unwrap().clone(),
            ..Default::default()
        };
        *self.sent.lock().unwrap() = Some(stats.clone());
        let id = self.id();
        for (i, side) in sides.iter_mut().enumerate() {
            let r = match side {
                SendSide::Tcp(Some(w)) => w.shutdown().await,
                SendSide::Tcp(None) => Ok(()),
                SendSide::Udp(c) => {
                    let mut buf = [0u8; UDP_HEADER_LEN];
                    UdpHeader { id, stream: i as u16, flags: FLAG_FIN, send_time: unix_nanos(), ..Default::default() }
                        .put(&mut buf);
                    let mut r = Ok(());
                    for _ in 0..FIN_REPEAT {
                        if let Err(e) = c.send(&buf).await {
                            r = Err(e);
                        }
                    }
                    r.map(|_| ())
                }
            };
            if let Err(e) = r {
                self.fail(format!("stream {i}: ending: {e}"));
                return sides;
            }
        }
        let wire = Stats { intervals: Vec::new(), ..stats };
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
        let id = self.id();
        loop {
            if self.p.bytes > 0 {
                if sent >= self.p.bytes {
                    return side;
                }
            } else if start.elapsed() >= self.p.duration {
                return side;
            }
            if self.done.is_set() {
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
                    UdpHeader { id, stream: i as u16, seq, send_time: unix_nanos(), ..Default::default() }
                        .put(&mut buf);
                    seq += 1;
                    c.send(&buf).await.map(|_| ())
                }
                SendSide::Tcp(Some(w)) => {
                    if self.p.bytes > 0 && ((self.p.bytes - sent) as usize) < n {
                        n = (self.p.bytes - sent) as usize;
                    }
                    tokio::select! {
                        r = w.write_all(&buf[..n]) => r,
                        _ = self.done.wait() => return side,
                    }
                }
                SendSide::Tcp(None) => return side,
            };
            if let Err(e) = r {
                if !self.done.is_set() {
                    self.fail(format!("stream {i}: write: {e}"));
                }
                return side;
            }
            sent += n as i64;
            self.send_bytes.fetch_add(n as i64, Ordering::Relaxed);
            if matches!(side, SendSide::Udp(_)) {
                self.send_datagrams.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn run_receivers(self: &Arc<Self>, sides: Vec<RecvSide>) {
        let mut tasks = Vec::new();
        for (i, side) in sides.into_iter().enumerate() {
            let t = self.clone();
            tasks.push(tokio::spawn(async move { t.recv_stream(i, side).await }));
        }
        let mut states = Vec::new();
        for t in tasks {
            if let Ok(s) = t.await {
                states.push(s);
            }
        }
        if self.done.is_set() {
            return;
        }
        let mut stats = Stats {
            bytes: self.recv_bytes.load(Ordering::Relaxed),
            datagrams: self.recv_datagrams.load(Ordering::Relaxed),
            intervals: self.recv_intervals.lock().unwrap().clone(),
            ..Default::default()
        };
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
        *self.received.lock().unwrap() = Some(stats.clone());
        let wire = Stats { intervals: Vec::new(), ..stats };
        if let Err(e) = self.ctrl.send(&Message { stats: Some(wire), ..Message::new("result") }).await {
            self.fail(format!("sending result: {e}"));
        }
    }

    /// Resolves once the peer said it's done sending and the grace
    /// period for in-flight data has passed.
    async fn grace_expired(&self) {
        self.peer_done.wait().await;
        tokio::time::sleep(if self.p.proto == Proto::Udp { UDP_GRACE } else { TCP_GRACE }).await;
    }

    async fn recv_stream(&self, i: usize, side: RecvSide) -> RecvState {
        let mut st = RecvState::default();
        match side {
            RecvSide::Tcp(Some(mut rd)) => {
                let mut buf = vec![0u8; self.p.length.max(64 << 10)];
                loop {
                    let r = tokio::select! {
                        r = rd.read(&mut buf) => r,
                        _ = self.grace_expired() => return st,
                        _ = self.done.wait() => return st,
                    };
                    match r {
                        Ok(0) => return st,
                        Ok(n) => self.count(&mut st, n),
                        Err(e) => {
                            if !self.peer_done.is_set() && !self.done.is_set() {
                                self.fail(format!("stream {i}: read: {e}"));
                            }
                            return st;
                        }
                    }
                }
            }
            RecvSide::Tcp(None) => st,
            RecvSide::Udp(conn, pending) => {
                if let Some(p) = pending
                    && self.process_datagram(&mut st, &p)
                {
                    return st;
                }
                let mut buf = vec![0u8; MAX_UDP_SIZE];
                loop {
                    let r = tokio::select! {
                        r = conn.recv(&mut buf) => r,
                        _ = self.grace_expired() => return st,
                        _ = self.done.wait() => return st,
                    };
                    match r {
                        Ok(n) => {
                            if self.process_datagram(&mut st, &buf[..n]) {
                                return st;
                            }
                        }
                        Err(e) => {
                            if !self.peer_done.is_set() && !self.done.is_set() {
                                self.fail(format!("stream {i}: read: {e}"));
                            }
                            return st;
                        }
                    }
                }
            }
        }
    }

    fn count(&self, st: &mut RecvState, n: usize) {
        let now = Instant::now();
        st.first.get_or_insert(now);
        st.last = Some(now);
        self.recv_bytes.fetch_add(n as i64, Ordering::Relaxed);
    }

    /// Accounts for one datagram, reporting whether it was a fin.
    fn process_datagram(&self, st: &mut RecvState, pkt: &[u8]) -> bool {
        let Some(h) = UdpHeader::parse(pkt) else { return false };
        if h.id != self.id() {
            return false;
        }
        if h.flags & FLAG_FIN != 0 {
            return true;
        }
        if h.flags & FLAG_OPEN != 0 {
            return false;
        }
        self.count(st, pkt.len());
        self.recv_datagrams.fetch_add(1, Ordering::Relaxed);
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

enum SendSide {
    Tcp(Option<BoxWrite>),
    Udp(Arc<UdpConn>),
}

enum RecvSide {
    Tcp(Option<BoxRead>),
    Udp(Arc<UdpConn>, Option<Vec<u8>>),
}

/// The perf service: one test at a time.
#[derive(Default)]
pub struct Server {
    tests: Mutex<HashMap<[u8; 8], Arc<Test>>>,
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup(&self, id: [u8; 8], index: usize) -> Result<Arc<Test>, String> {
        let t = self.tests.lock().unwrap().get(&id).cloned().ok_or("unknown test")?;
        if index >= t.streams.len() {
            return Err(format!("stream index {index} out of range"));
        }
        Ok(t)
    }

    /// Serves one TCP connection to the perf port: a control connection
    /// starting a test, or a data stream of the running one.
    pub async fn handle_tcp(&self, c: TcpStream) {
        let remote = c.peer_addr();
        let (rd, wr) = tokio::io::split(c);
        let mut br: BufReader<BoxRead> = BufReader::with_capacity(CTRL_BUF_SIZE, Box::new(rd));
        let wr: BoxWrite = Box::new(wr);
        let m = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_message(&mut br)).await {
            Ok(Ok(m)) => m,
            _ => return,
        };
        match m.typ.as_str() {
            "hello" => self.run_test(br, wr, m, remote).await,
            "stream" => {
                let Ok(b) = hex::decode(&m.id) else { return };
                let Ok(id) = <[u8; 8]>::try_from(b.as_slice()) else { return };
                let t = match self.lookup(id, m.stream) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::debug!("perf: {remote}: data connection: {e}");
                        return;
                    }
                };
                // The BufReader may already hold data after the header.
                if !t.attach(m.stream, StreamConn::Tcp { rd: Some(Box::new(br)), wr: Some(wr) }) {
                    return;
                }
                t.done.wait().await;
            }
            _ => {}
        }
    }

    /// Serves one UDP flow to the perf port, a data stream of the
    /// running test.
    pub async fn handle_udp(&self, c: UdpConn) {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let n = match tokio::time::timeout(HANDSHAKE_TIMEOUT, c.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => return,
        };
        let Some(h) = UdpHeader::parse(&buf[..n]) else { return };
        let t = match self.lookup(h.id, h.stream as usize) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!("perf: UDP flow: {e}");
                return;
            }
        };
        let c = Arc::new(c);
        if !t.attach(h.stream as usize, StreamConn::Udp { conn: c.clone(), pending: Some(buf[..n].to_vec()) }) {
            return;
        }
        t.done.wait().await;
    }

    async fn run_test(&self, br: BufReader<BoxRead>, wr: BoxWrite, hello: Message, remote: std::net::SocketAddr) {
        let ctrl = Ctrl::new(br, wr);
        let Some(p) = hello.params else {
            let _ = ctrl.send(&Message { error: "hello without params".into(), ..Message::new("error") }).await;
            return;
        };
        if let Err(e) = p.validate(DEFAULT_MAX_STREAMS, DEFAULT_MAX_DURATION) {
            let _ = ctrl.send(&Message { error: e, ..Message::new("error") }).await;
            return;
        }
        let t = Test::new(p, true, ctrl);
        let mut id = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        *t.id.lock().unwrap() = id;
        let registered = {
            let mut tests = self.tests.lock().unwrap();
            tests.is_empty() && tests.insert(id, t.clone()).is_none()
        };
        if !registered {
            let _ = t
                .ctrl
                .send(&Message { error: "the server is busy with another test".into(), ..Message::new("error") })
                .await;
            return;
        }
        let res = async {
            t.ctrl.send(&Message { id: hex::encode(id), ..Message::new("ok") }).await.map_err(|e| e.to_string())?;
            let limit = DEFAULT_MAX_DURATION + HANDSHAKE_TIMEOUT + REPORT_TIMEOUT;
            match tokio::time::timeout(limit, t.clone().run()).await {
                Ok(r) => r,
                Err(_) => Err("test timed out".to_string()),
            }
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
async fn run_client(
    cl: &tailcat::Client,
    p: Params,
    on_progress: Option<Box<dyn Fn(Progress) + Send + Sync>>,
) -> Result<PerfResult> {
    p.validate(0, Duration::ZERO).map_err(|e| anyhow!(e))?;
    let cc = cl.dial_tcp_port(PORT).await.map_err(|e| anyhow!("dialing control connection: {e}"))?;
    let (rd, wr) = tokio::io::split(cc);
    let ctrl = Ctrl::new(BufReader::with_capacity(CTRL_BUF_SIZE, Box::new(rd)), Box::new(wr));
    let mut t = Test::new(p.clone(), false, ctrl);
    Arc::get_mut(&mut t).expect("unshared").on_progress = on_progress;
    t.ctrl
        .send(&Message { params: Some(p.clone()), ..Message::new("hello") })
        .await
        .map_err(|e| anyhow!("sending hello: {e}"))?;
    let m = tokio::time::timeout(HANDSHAKE_TIMEOUT, t.ctrl.recv())
        .await
        .map_err(|_| anyhow!("reading hello reply: timed out"))?
        .map_err(|e| anyhow!("reading hello reply: {e}"))?;
    match m.typ.as_str() {
        "error" => bail!("server rejected the test: {}", m.error),
        "ok" => {}
        other => bail!("unexpected reply {other:?} to hello"),
    }
    let id: [u8; 8] = hex::decode(&m.id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("server sent a malformed test ID"))?;
    *t.id.lock().unwrap() = id;
    for i in 0..p.streams {
        let sc = match p.proto {
            Proto::Tcp => {
                let mut dc = cl.dial_tcp_port(PORT).await.map_err(|e| anyhow!("dialing stream {i}: {e}"))?;
                let mut hdr = serde_json::to_vec(&Message { id: m.id.clone(), stream: i, ..Message::new("stream") })?;
                hdr.push(b'\n');
                dc.write_all(&hdr).await.map_err(|e| anyhow!("stream {i}: sending header: {e}"))?;
                let (rd, wr) = tokio::io::split(dc);
                StreamConn::Tcp { rd: Some(Box::new(rd)), wr: Some(Box::new(wr)) }
            }
            Proto::Udp => {
                let dc = cl.dial_udp_port(PORT).await.map_err(|e| anyhow!("dialing UDP stream {i}: {e}"))?;
                StreamConn::Udp { conn: Arc::new(dc), pending: None }
            }
        };
        t.attach(i, sc);
    }
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

fn parse_si(s: &str) -> Result<i64> {
    let (num, mult) = match s.chars().last() {
        Some('k' | 'K') => (&s[..s.len() - 1], 1e3),
        Some('m' | 'M') => (&s[..s.len() - 1], 1e6),
        Some('g' | 'G') => (&s[..s.len() - 1], 1e9),
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

async fn probe_path(cl: &tailcat::Client, timeout: Duration) -> Result<PathInfo> {
    let r = cl.disco_ping(timeout).await?;
    Ok(PathInfo {
        direct: r.endpoint.is_some(),
        endpoint: r.endpoint.map(|e| e.to_string()).unwrap_or_default(),
        derp_region: if r.endpoint.is_some() {
            String::new()
        } else if r.derp_region_code.is_empty() {
            r.derp_region_id.to_string()
        } else {
            r.derp_region_code
        },
        rtt: r.latency,
    })
}

async fn wait_for_direct_path(cl: &tailcat::Client, timeout: Duration) -> Result<PathInfo> {
    let deadline = Instant::now() + timeout;
    loop {
        let t0 = Instant::now();
        let remaining = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let p = match tokio::time::timeout(remaining, probe_path(cl, remaining)).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) if matches!(e.downcast_ref::<tailcat::Error>(), Some(tailcat::Error::Timeout(_))) => {
                bail!("no reply to pings after {}", go_duration(timeout))
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => bail!("no reply to pings after {}", go_duration(timeout)),
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

pub async fn run(g: &Global, a: PerfArgs) -> Result<ExitCode> {
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
        let n = parse_si(b).ok().filter(|n| *n > 0).ok_or_else(|| crate::usagef!("invalid --bytes value {b:?}"))?;
        p.bytes = n;
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
    let progress: Option<Box<dyn Fn(Progress) + Send + Sync>> = if !g.json && !p.interval.is_zero() {
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
    let after = tokio::time::timeout(Duration::from_secs(3), probe_path(&cl, Duration::from_secs(3)))
        .await
        .ok()
        .and_then(|r| r.ok());
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
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
        v.serialize(&mut ser)?;
        println!("{}", String::from_utf8(buf)?);
        return Ok(ExitCode::SUCCESS);
    }
    for l in result_lines(&res) {
        println!("{l}");
    }
    if let Some(a) = after
        && a.direct != before.direct
    {
        eprintln!("# path changed during the test, now: {a}");
    }
    Ok(ExitCode::SUCCESS)
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
    let mut out = Vec::new();
    let add = |indent: &str, sent: &Option<Stats>, recv: &Option<Stats>, out: &mut Vec<String>| {
        let (Some(sent), Some(recv)) = (sent, recv) else { return };
        let mut s = format!(
            "{indent}sent      {:>9} in {:6.1}s {:>13}",
            fmt_bytes(sent.bytes),
            sent.duration.as_secs_f64(),
            fmt_rate(sent.bytes, sent.duration)
        );
        let mut r = format!(
            "{indent}received  {:>9} in {:6.1}s {:>13}",
            fmt_bytes(recv.bytes),
            recv.duration.as_secs_f64(),
            fmt_rate(recv.bytes, recv.duration)
        );
        if udp {
            s += &format!("  {} datagrams", sent.datagrams);
            let lost = sent.datagrams - recv.datagrams;
            let pct = if sent.datagrams > 0 { lost as f64 / sent.datagrams as f64 * 100.0 } else { 0.0 };
            r += &format!(
                "  {} datagrams, {lost} lost ({pct:.1}%), {} reordered, jitter {}",
                recv.datagrams,
                recv.reordered,
                fmt_rtt(recv.jitter)
            );
        }
        out.push(s);
        out.push(r);
    };
    if res.params.direction == Direction::Bidirectional {
        out.push("client -> server:".to_string());
        add("  ", &res.client_sent, &res.server_received, &mut out);
        out.push("server -> client:".to_string());
        add("  ", &res.server_sent, &res.client_received, &mut out);
    } else {
        add("", &res.client_sent, &res.server_received, &mut out);
        add("", &res.server_sent, &res.client_received, &mut out);
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

/// The one-line summary the server prints per test.
fn perf_summary(res: &PerfResult) -> String {
    let udp = res.params.proto == Proto::Udp;
    let rate = |sent: &Option<Stats>, recv: &Option<Stats>| {
        let Some(recv) = recv else { return "?".to_string() };
        let mut s = fmt_rate(recv.bytes, recv.duration);
        if let (true, Some(sent)) = (udp, sent)
            && sent.datagrams > 0
        {
            s += &format!(" ({:.1}% lost)", (sent.datagrams - recv.datagrams) as f64 / sent.datagrams as f64 * 100.0);
        }
        s
    };
    let proto = if udp { "UDP" } else { "TCP" };
    match res.params.direction {
        Direction::Upload => format!("{proto} client -> server {}", rate(&res.client_sent, &res.server_received)),
        Direction::Download => format!("{proto} server -> client {}", rate(&res.server_sent, &res.client_received)),
        Direction::Bidirectional => format!(
            "{proto} client -> server {}, server -> client {}",
            rate(&res.client_sent, &res.server_received),
            rate(&res.server_sent, &res.client_received)
        ),
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
    if i == 0 {
        format!("{v:.0} {unit}")
    } else if v >= 100.0 {
        format!("{v:.0} {}{unit}", P[i])
    } else if v >= 10.0 {
        format!("{v:.1} {}{unit}", P[i])
    } else {
        format!("{v:.2} {}{unit}", P[i])
    }
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

fn fmt_rtt(d: Duration) -> String {
    let n = d.as_nanos() as u64;
    let rounded = (n + 5_000) / 10_000 * 10_000;
    go_duration(Duration::from_nanos(rounded))
}

/// Formats a duration like Go's `time.Duration.String`.
pub fn go_duration(d: Duration) -> String {
    let n = d.as_nanos();
    if n == 0 {
        return "0s".into();
    }
    fn frac(v: u128, prec: u32) -> (u128, String) {
        // Returns v / 10^prec and the fractional digits, trailing zeros trimmed.
        let div = 10u128.pow(prec);
        let (int, mut f) = (v / div, v % div);
        let mut digits = String::new();
        let mut printed = false;
        for _ in 0..prec {
            let dgt = f % 10;
            f /= 10;
            if printed || dgt != 0 {
                printed = true;
                digits.insert(0, char::from(b'0' + dgt as u8));
            }
        }
        (int, digits)
    }
    let with_frac = |int: u128, digits: String, unit: &str| {
        if digits.is_empty() { format!("{int}{unit}") } else { format!("{int}.{digits}{unit}") }
    };
    if n < 1_000 {
        return format!("{n}ns");
    }
    if n < 1_000_000 {
        let (i, f) = frac(n, 3);
        return with_frac(i, f, "µs");
    }
    if n < 1_000_000_000 {
        let (i, f) = frac(n, 6);
        return with_frac(i, f, "ms");
    }
    let (secs, f) = frac(n, 9);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let sec = with_frac(s, f, "s");
    if h > 0 {
        format!("{h}h{m}m{sec}")
    } else if m > 0 {
        format!("{m}m{sec}")
    } else {
        sec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_durations() {
        assert_eq!(go_duration(Duration::from_secs(10)), "10s");
        assert_eq!(go_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(go_duration(Duration::from_micros(1230)), "1.23ms");
        assert_eq!(go_duration(Duration::from_micros(680)), "680µs");
        assert_eq!(go_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(fmt_rtt(Duration::from_nanos(1_234_567)), "1.23ms");
    }

    #[test]
    fn si() {
        assert_eq!(fmt_si(1.18e9, "B"), "1.18 GB");
        assert_eq!(fmt_si(943e6, "bit/s"), "943 Mbit/s");
        assert_eq!(fmt_si(12.0, "B"), "12 B");
        assert_eq!(parse_si("10M").unwrap(), 10_000_000);
        assert_eq!(parse_si("1.5G").unwrap(), 1_500_000_000);
        assert!(parse_si("x").is_err());
    }

    #[test]
    fn wire_formats() {
        let p = Params {
            proto: Proto::Udp,
            direction: Direction::Bidirectional,
            duration: Duration::from_secs(10),
            bytes: 0,
            streams: 1,
            length: 1232,
            bitrate: 1_000_000,
            interval: Duration::from_secs(1),
        };
        let j = serde_json::to_string(&Message { params: Some(p), ..Message::new("hello") }).unwrap();
        assert_eq!(
            j,
            r#"{"type":"hello","params":{"proto":"udp","dir":"both","duration":10000000000,"streams":1,"length":1232,"bitrate":1000000,"interval":1000000000}}"#
        );
        let mut b = [0u8; 32];
        let h = UdpHeader { id: [1; 8], stream: 2, flags: FLAG_FIN, seq: 9, send_time: 42 };
        h.put(&mut b);
        let back = UdpHeader::parse(&b).unwrap();
        assert_eq!((back.stream, back.flags, back.seq, back.send_time), (2, FLAG_FIN, 9, 42));
    }
}
