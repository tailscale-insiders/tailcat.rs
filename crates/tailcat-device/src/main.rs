//! `tailcat-device`: join a WireGuard mesh overlay on a TUN interface.
//!
//!     tailcat-device init --index 3                  # key + node record
//!     tailcat-device up --records ./records --nodes 5
//!     tailcat-device up --github --nodes 5           # records from run artifacts

use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Args, Parser, Subcommand};
use tailcat::wg::IpNet;
use tailcat::{DerpMap, DerpNode, DerpRegion, FetchMode, FetchOptions, NodePrivate, RegionChoice};
use tailcat_args::RegionArg;
use tailcat_device::github::{self, GithubEnv, Scope};
use tailcat_device::record::{self, DeviceKey, NodeRecord};
use tailcat_device::source::{GithubSource, Source};
use tailcat_device::{Overlay, OverlayConfig};
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(
    name = "tailcat-device",
    version,
    about = "join a WireGuard mesh overlay on a TUN interface, using tailcat's DERP relays and NAT traversal"
)]
struct Cli {
    /// Log verbosely.
    #[arg(long, global = true)]
    verbose: bool,
    /// URL of the JSON DERP map.
    #[arg(long, global = true, env = "TAILCAT_DERPMAP_URL", default_value = tailcat::DEFAULT_DERP_MAP_URL)]
    derpmap_url: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate this node's key and write its public node record.
    Init(InitArgs),
    /// Bring up the overlay: create the TUN interface and add peers as their records appear.
    Up(UpArgs),
    /// Print this node's public record.
    Record {
        #[arg(long, default_value = "tailcat-device.key")]
        key: PathBuf,
    },
}

#[derive(Args)]
struct InitArgs {
    /// This node's index in the mesh (for example the matrix index).
    #[arg(long)]
    index: u32,
    /// The run attempt, part of the default overlay IP and record name.
    #[arg(long, env = "GITHUB_RUN_ATTEMPT", default_value = "1")]
    attempt: u32,
    /// The overlay network. The default IP is <prefix> + attempt*256 + index.
    #[arg(long, default_value = "100.64.0.0/16")]
    overlay_prefix: IpNet,
    /// An explicit overlay IP instead of the default.
    #[arg(long)]
    ip: Option<IpAddr>,
    /// Extra prefixes to route to this node (repeatable).
    #[arg(long = "route")]
    routes: Vec<IpNet>,
    /// Home DERP region: 'auto' (lowest latency), an ID, a region code or name, or comma-separated
    /// hostnames of your own DERP servers. 'list' lists the regions.
    #[arg(long, default_value = "auto")]
    region: RegionArg,
    /// A JSON file holding a DERP region to embed (for example from `tailcat dev-derp --region-file`).
    #[arg(long, conflicts_with = "region")]
    region_file: Option<PathBuf>,
    /// Where to write the private key file.
    #[arg(long, default_value = "tailcat-device.key")]
    key: PathBuf,
    /// Where to write the public record [default: node-<attempt>-<index>.json].
    #[arg(long)]
    out: Option<PathBuf>,
    /// Embed a GitHub OIDC token binding the key to this repository, ref and run.
    #[arg(long)]
    oidc: bool,
    /// The OIDC audience prefix; the audience is the prefix plus the hex SHA-256 of the node key.
    #[arg(long, default_value = "tailcat-device:")]
    oidc_audience_prefix: String,
    /// Overwrite an existing key file.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct UpArgs {
    /// The key file from `init`.
    #[arg(long, default_value = "tailcat-device.key")]
    key: PathBuf,
    /// Read peer records from every *.json file in this directory.
    #[arg(long, conflicts_with_all = ["record", "github"])]
    records: Option<PathBuf>,
    /// Read peer records from these files (repeatable).
    #[arg(long, conflicts_with = "github")]
    record: Vec<PathBuf>,
    /// Read peer records from this GitHub Actions run's artifacts (needs GITHUB_TOKEN with `actions: read`).
    #[arg(long)]
    github: bool,
    /// Which GitHub runs' records to admit.
    #[arg(long, value_enum, default_value = "run")]
    scope: Scope,
    /// Artifact name prefix [default: node-<attempt>- for run scope, node- otherwise].
    #[arg(long)]
    artifact_prefix: Option<String>,
    #[arg(long, default_value = "tailcat-device:")]
    oidc_audience_prefix: String,
    /// The number of nodes in the mesh, including this one; `up` fails if they don't all appear in time.
    #[arg(long)]
    nodes: Option<usize>,
    /// How long to wait for all --nodes records.
    #[arg(long, default_value = "5m", value_parser = parse_duration)]
    wait: Duration,
    /// The TUN interface name (on macOS, utunN or omitted).
    #[arg(long)]
    tun: Option<String>,
    #[arg(long, default_value_t = 1280)]
    mtu: u16,
    /// The overlay network, assigned to the interface.
    #[arg(long, default_value = "100.64.0.0/16")]
    overlay_prefix: IpNet,
    /// The UDP port for direct paths (0 picks one).
    #[arg(long, default_value_t = 0)]
    listen_port: u16,
    /// Relay everything through DERP; don't try direct paths.
    #[arg(long)]
    no_udp: bool,
    /// Write peer status JSON here, periodically.
    #[arg(long)]
    status_file: Option<PathBuf>,
    /// Create this file once every expected peer has answered a ping, and no other node has our address.
    #[arg(long)]
    ready_file: Option<PathBuf>,
    /// How often to log peer status.
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    status_interval: Duration,
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, unit) = s.split_at(s.find(|c: char| c.is_alphabetic()).unwrap_or(s.len()));
    let n: f64 = num.parse().map_err(|_| format!("invalid duration {s:?}"))?;
    let mult = match unit {
        "ms" => 0.001,
        "s" | "" => 1.0,
        "m" => 60.0,
        "h" => 3600.0,
        _ => return Err(format!("invalid duration unit in {s:?}")),
    };
    Duration::try_from_secs_f64(n * mult).map_err(|_| format!("invalid duration {s:?}"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let filter =
        if cli.verbose { "info,tailcat=debug,tailcat_device=debug" } else { "info,tailcat=warn,tailcat_device=info" };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with_writer(std::io::stderr)
        .try_init();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    let res = rt.block_on(async {
        match cli.cmd {
            Cmd::Init(a) => init(&cli.derpmap_url, a).await,
            Cmd::Up(a) => up(&cli.derpmap_url, a).await,
            Cmd::Record { key } => {
                println!("{}", serde_json::to_string_pretty(&DeviceKey::load(&key)?.record)?);
                Ok(())
            }
        }
    });
    // Dropping the runtime would wait for blocking tasks, such as a DNS
    // lookup for a DERP server that isn't answering.
    rt.shutdown_timeout(Duration::from_secs(1));
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tailcat-device: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn fetch_map(url: &str) -> Result<DerpMap> {
    tailcat::derpmap::fetch_derp_map(FetchOptions { url: Some(url), mode: FetchMode::Server, cache: None })
        .await
        .map_err(|e| anyhow!("fetching the DERP map: {e}"))
}

async fn init(derpmap_url: &str, a: InitArgs) -> Result<()> {
    // Fail early; saving the key checks again.
    ensure!(a.force || !a.key.exists(), "{} already exists; use --force to overwrite", a.key.display());
    let private = NodePrivate::generate();
    let overlay_ip = match a.ip {
        Some(ip) => ip,
        None => record::overlay_ip(&a.overlay_prefix, a.attempt, a.index)?,
    };
    let (derp_region, derp) = match &a.region_file {
        Some(f) => {
            let b = std::fs::read(f).with_context(|| format!("reading {}", f.display()))?;
            (0, Some(serde_json::from_slice(&b).with_context(|| format!("parsing {}", f.display()))?))
        }
        None => pick_region(derpmap_url, &a.region).await?,
    };
    let env = |k, default: &str| std::env::var(k).unwrap_or_else(|_| default.into());
    let mut record = NodeRecord {
        derp_region,
        derp,
        routes: a.routes,
        os: env("RUNNER_OS", std::env::consts::OS),
        arch: env("RUNNER_ARCH", std::env::consts::ARCH),
        run_id: github::RunId::given(&env("GITHUB_RUN_ID", "")),
        run_attempt: github::Attempt::given(&env("GITHUB_RUN_ATTEMPT", "")),
        ..NodeRecord::new(a.index, &private, overlay_ip)
    };
    if a.oidc {
        record.jwt = Some(github::mint_oidc(&record::audience_for(&a.oidc_audience_prefix, &record.nodekey)).await?);
    }
    let out = a.out.unwrap_or_else(|| format!("node-{}-{}.json", a.attempt, a.index).into());
    let k = DeviceKey { private, record };
    k.save(&a.key, a.force)?;
    if let Err(e) = k.record.write(&out) {
        // Without its record the key is no use; don't make the next try
        // need --force.
        let _ = std::fs::remove_file(&a.key);
        return Err(e);
    }
    eprintln!("# wrote key to {} and record to {}", a.key.display(), out.display());
    println!("{}", out.display());
    Ok(())
}

async fn up(derpmap_url: &str, a: UpArgs) -> Result<()> {
    // Handle signals from the start, not from the first time something
    // waits on them.
    let signal = shutdown_signal()?;
    // A ready file left by an earlier run would say we're ready too soon.
    let ready_file = a.ready_file.clone();
    let remove_ready = || match &ready_file {
        Some(f) => match std::fs::remove_file(f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).context(format!("removing {}", f.display())),
            _ => Ok(()),
        },
        None => Ok(()),
    };
    remove_ready()?;
    let res = tokio::select! {
        r = serve(derpmap_url, a) => r,
        () = signal => {
            info!("overlay: shutting down");
            Ok(())
        }
    };
    if let Err(e) = remove_ready() {
        warn!("{e:#}");
    }
    res
}

/// Closes the overlay when `serve` ends or is cancelled: the packet loop
/// holds a reference too, so dropping ours isn't enough.
struct CloseOnDrop(Arc<Overlay>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Runs the node until the packet loop fails or the peers don't all
/// appear in time; `up` cancels it on a signal.
async fn serve(derpmap_url: &str, a: UpArgs) -> Result<()> {
    let k = DeviceKey::load(&a.key)?;
    let mut source = if a.github {
        let env = GithubEnv::from_env()?;
        let prefix = a.artifact_prefix.unwrap_or_else(|| match a.scope {
            Scope::Run => format!("node-{}-", env.run_attempt),
            _ => "node-".into(),
        });
        Source::github(GithubSource::new(env, a.scope, prefix, a.oidc_audience_prefix))
    } else if let Some(d) = a.records {
        Source::dir(d)
    } else if !a.record.is_empty() {
        Source::files(a.record)
    } else {
        bail!("say where peer records come from: --records DIR, --record FILE, or --github");
    };
    // The DERP map is fetched now if our home region is in it, else the
    // first time a peer's is.
    let mut dm = if k.record.derp.is_none() { fetch_map(derpmap_url).await? } else { DerpMap::default() };
    let overlay = Overlay::start(OverlayConfig {
        key: k,
        derp_map: dm.clone(),
        listen_port: a.listen_port,
        overlay_prefix: a.overlay_prefix,
        enable_udp: !a.no_udp,
    })
    .await?;
    let _close = CloseOnDrop(overlay.clone());
    if !overlay.wait_derp(Duration::from_secs(15)).await {
        warn!("not yet connected to the home DERP region; continuing");
    }
    let me = overlay.record();
    let dev = open_tun(a.tun.as_deref(), me, &a.overlay_prefix, a.mtu)?;
    let runner = tokio::spawn(overlay.clone().run(dev));
    info!("overlay: {} is node {} at {}", me.nodekey, me.index, me.overlay_ip);

    let expected = a.nodes.map(|n| n.saturating_sub(1));
    // Poll quickly while nodes are joining, then back off: the GitHub API
    // is rate-limited per repository.
    let settled_poll = Duration::from_secs(if a.github { 30 } else { 5 });
    let membership = async {
        let mut last_poll: Option<Instant> = None;
        let mut ready = false;
        loop {
            let joining = !ready || expected.is_some_and(|n| overlay.peer_count() < n);
            let poll_every = if joining { Duration::from_secs(2) } else { settled_poll };
            if last_poll.is_none_or(|t| t.elapsed() >= poll_every) {
                last_poll = Some(Instant::now());
                match source.poll().await {
                    Ok(recs) => {
                        if dm.regions.is_empty() && recs.iter().any(|r| r.derp.is_none()) {
                            match fetch_map(derpmap_url).await {
                                Ok(m) => dm = m,
                                Err(e) => warn!("{e:#}; retrying next poll"),
                            }
                        }
                        overlay.sync(&recs, &dm);
                    }
                    Err(e) => warn!("polling records: {e:#}"),
                }
            }
            // Pings go by node key, so they're answered even when our run's
            // nodes send what's for our address to another node.
            if let Some(n) = expected
                && !ready
                && overlay.peer_count() >= n
                && !overlay.contested().iter().any(|(net, _)| *net == IpNet::host(me.overlay_ip))
                && all_reachable(&overlay).await
            {
                ready = true;
                info!("overlay: all {n} peers reachable");
                if let Some(f) = &a.ready_file
                    && let Err(e) = record::write_atomic(f, b"ready\n")
                {
                    warn!("{e:#}");
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    // Status is written on its own schedule, not held up by slow polls.
    let status = async {
        let mut last_log = Instant::now();
        loop {
            if last_log.elapsed() >= a.status_interval {
                last_log = Instant::now();
                log_status(&overlay);
            }
            if let Some(f) = &a.status_file {
                let j = serde_json::to_vec_pretty(&overlay.status()).expect("status serializes");
                if let Err(e) = record::write_atomic(f, &j) {
                    debug!("{e:#}");
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    let deadline = async {
        let Some(n) = expected else { return std::future::pending().await };
        tokio::time::sleep(a.wait).await;
        let have = overlay.peer_count();
        if have >= n {
            return std::future::pending().await;
        }
        anyhow!("only {have} of {n} peers appeared within {}s", a.wait.as_secs())
    };
    tokio::select! {
        r = runner => Err(match r {
            Ok(Ok(())) => anyhow!("the packet loop stopped"),
            Ok(Err(e)) => e,
            Err(e) => anyhow!("the packet loop panicked: {e}"),
        }),
        e = deadline => Err(e),
        _ = membership => unreachable!(),
        _ = status => unreachable!(),
    }
}

/// Pings every peer at once, driving path discovery; true if all answer.
async fn all_reachable(o: &Arc<Overlay>) -> bool {
    let mut pings = tokio::task::JoinSet::new();
    for p in o.status() {
        let o = o.clone();
        pings.spawn(async move { (o.ping(&p.nodekey, Duration::from_secs(3)).await, p) });
    }
    let mut ok = true;
    while let Some(res) = pings.join_next().await {
        match res {
            Ok((Ok(r), p)) => {
                info!(peer = p.index, "overlay: pong from {} in {:?} via {}", p.overlay_ip, r.latency, r.via)
            }
            _ => ok = false,
        }
    }
    ok
}

fn log_status(o: &Overlay) {
    for p in o.status() {
        let path = match p.direct {
            Some(a) => format!("direct {a}"),
            None => format!("DERP({})", p.derp_region),
        };
        info!(
            "peer {} {} via {path}, handshake {}, tx {} rx {}",
            p.index,
            p.overlay_ip,
            p.handshake_age_secs.map_or("never".into(), |s| format!("{s}s ago")),
            p.tx_bytes,
            p.rx_bytes
        );
    }
}

fn open_tun(name: Option<&str>, me: &NodeRecord, prefix: &IpNet, mtu: u16) -> Result<Arc<tun_rs::AsyncDevice>> {
    let mut b = tun_rs::DeviceBuilder::new().mtu(mtu);
    if let Some(n) = name {
        b = b.name(n);
    }
    b = match me.overlay_ip {
        IpAddr::V4(v4) => b.ipv4(v4, prefix.prefix_len, None),
        IpAddr::V6(v6) => b.ipv6(v6, prefix.prefix_len),
    };
    let dev = b.build_async().context("creating the TUN device (this needs root or CAP_NET_ADMIN)")?;
    if let Ok(n) = dev.name() {
        info!("overlay: TUN device {n} up with {}/{}", me.overlay_ip, prefix.prefix_len);
    }
    Ok(Arc::new(dev))
}

/// Resolves on SIGINT or SIGTERM. The handlers are installed now, before
/// the returned future is first polled.
#[cfg(unix)]
fn shutdown_signal() -> Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut int = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let mut term = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    Ok(async move {
        tokio::select! {
            _ = int.recv() => {}
            _ = term.recv() => {}
        }
    })
}

/// Resolves on Ctrl-C. The handler is installed now, before the returned
/// future is first polled.
#[cfg(not(unix))]
fn shutdown_signal() -> Result<impl Future<Output = ()>> {
    let ctrl_c = tokio::spawn(tokio::signal::ctrl_c());
    Ok(async move {
        let _ = ctrl_c.await;
    })
}

/// Picks the home region for `init`.
async fn pick_region(url: &str, region: &RegionArg) -> Result<(i32, Option<DerpRegion>)> {
    if let RegionArg::Choice(RegionChoice::Custom(hosts)) = region {
        let nodes =
            hosts.iter().map(|h| DerpNode { name: h.to_string().into(), host_name: h.clone(), ..Default::default() });
        let custom =
            DerpRegion { region_id: 900, region_code: "custom".into(), nodes: nodes.collect(), ..Default::default() };
        return Ok((0, Some(custom)));
    }
    let dm = fetch_map(url).await?;
    let id = match region {
        RegionArg::Choice(RegionChoice::Nearest) => tailcat::netcheck::pick_best_region(&dm)
            .await?
            .ok_or_else(|| anyhow!("couldn't find the nearest DERP region; pass --region"))?,
        RegionArg::Choice(c @ RegionChoice::Id(id)) => {
            c.find(&dm).ok_or_else(|| anyhow!("no DERP region {id} in the DERP map"))?
        }
        RegionArg::Choice(c @ RegionChoice::Named(n)) => {
            c.find(&dm).ok_or_else(|| anyhow!("no DERP region matching {n:?}"))?
        }
        RegionArg::List | RegionArg::Choice(RegionChoice::Custom(_)) => {
            for r in dm.regions.values() {
                eprintln!("  {:3} {} {}", r.region_id, r.region_code, r.region_name);
            }
            bail!("pass one of these DERP regions to --region");
        }
    };
    Ok((id, None))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    /// Parses `tailcat-device <args>`.
    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(["tailcat-device"].iter().chain(args))
    }

    #[test]
    fn durations() {
        let d = |s| parse_duration(s);
        assert_eq!(d("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(d("30"), Ok(Duration::from_secs(30)));
        assert_eq!(d("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(d("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(d("2h"), Ok(Duration::from_secs(7200)));
        for bad in ["", "s", "5d", "-1s", "1e999s"] {
            assert!(d(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn cli_parses() {
        Cli::command().debug_assert();
        let cli = parse(&["up", "--records", "d", "--nodes", "3", "--wait", "60s"]).unwrap();
        let Cmd::Up(a) = cli.cmd else { panic!("not up") };
        assert_eq!((a.records, a.nodes, a.wait), (Some("d".into()), Some(3), Duration::from_secs(60)));
        assert!(parse(&["up", "--records", "d", "--github"]).is_err(), "--records and --github conflict");
        let both_regions = parse(&["init", "--index", "0", "--region", "1", "--region-file", "f"]);
        assert!(both_regions.is_err(), "--region and --region-file conflict");
    }

    #[tokio::test]
    async fn custom_region_hostnames() {
        let hosts = "a.example,b.example".parse().unwrap();
        let (id, region) = pick_region("http://unused.invalid", &hosts).await.unwrap();
        let region = region.expect("a custom region");
        assert_eq!((id, region.region_id, region.nodes.len()), (0, 900, 2));
        assert_eq!(region.nodes[1].host_name, "b.example");
    }
}
