//! `tailcat-device`: join a WireGuard mesh overlay on a TUN interface.
//!
//!     tailcat-device init --index 3                  # key + node record
//!     tailcat-device up --records ./records --nodes 5
//!     tailcat-device up --github --nodes 5           # records from run artifacts

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use tailcat::wg::IpNet;
use tailcat::{DerpMap, DerpNode, DerpRegion, FetchMode, FetchOptions, NodePrivate};
use tailcat_device::github::{self, GithubEnv, Scope};
use tailcat_device::record::{self, DeviceKey, NodeRecord};
use tailcat_device::source::{GithubSource, Source};
use tailcat_device::{Overlay, OverlayConfig};
use tracing::{info, warn};

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
    Init {
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
        routes: Vec<String>,
        /// Home DERP region: 'auto' (lowest latency), an ID, a region code or name, or comma-separated
        /// hostnames of your own DERP servers.
        #[arg(long, default_value = "auto")]
        region: String,
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
    },
    /// Bring up the overlay: create the TUN interface and add peers as their records appear.
    Up {
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
        /// Create this file once every expected peer has answered a ping.
        #[arg(long)]
        ready_file: Option<PathBuf>,
        /// How often to log peer status.
        #[arg(long, default_value = "30s", value_parser = parse_duration)]
        status_interval: Duration,
    },
    /// Print this node's public record.
    Record {
        #[arg(long, default_value = "tailcat-device.key")]
        key: PathBuf,
    },
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
    Ok(Duration::from_secs_f64(n * mult))
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
    match rt.block_on(run(cli)) {
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

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init {
            index,
            attempt,
            overlay_prefix,
            ip,
            routes,
            region,
            region_file,
            key,
            out,
            oidc,
            oidc_audience_prefix,
            force,
        } => {
            if key.exists() && !force {
                bail!("{} already exists; use --force to overwrite", key.display());
            }
            let private = NodePrivate::generate();
            let overlay_ip = match ip {
                Some(ip) => ip,
                None => record::overlay_ip(&overlay_prefix, attempt, index)?,
            };
            let (derp_region, derp) = match region_file {
                Some(f) => {
                    let r: DerpRegion = serde_json::from_slice(&std::fs::read(&f)?)
                        .with_context(|| format!("parsing {}", f.display()))?;
                    (0, Some(r))
                }
                None => pick_region(&cli.derpmap_url, &region).await?,
            };
            let mut rec = NodeRecord {
                index,
                nodekey: private.public(),
                discokey: private.disco_private().public(),
                overlay_ip,
                derp_region,
                derp,
                routes,
                endpoints: Vec::new(),
                os: std::env::var("RUNNER_OS").unwrap_or_else(|_| std::env::consts::OS.into()),
                arch: std::env::var("RUNNER_ARCH").unwrap_or_else(|_| std::env::consts::ARCH.into()),
                run_id: std::env::var("GITHUB_RUN_ID").unwrap_or_default(),
                run_attempt: std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_default(),
                jwt: String::new(),
            };
            if oidc {
                rec.jwt = github::mint_oidc(&record::audience_for(&oidc_audience_prefix, &rec.nodekey)).await?;
            }
            let k = DeviceKey { private, record: rec.clone() };
            k.save(&key)?;
            let out = out.unwrap_or_else(|| PathBuf::from(format!("node-{attempt}-{index}.json")));
            rec.write(&out)?;
            eprintln!("# wrote key to {} and record to {}", key.display(), out.display());
            println!("{}", out.display());
            Ok(())
        }
        Cmd::Record { key } => {
            let k = DeviceKey::load(&key)?;
            println!("{}", serde_json::to_string_pretty(&k.record)?);
            Ok(())
        }
        Cmd::Up {
            key,
            records,
            record,
            github,
            scope,
            artifact_prefix,
            oidc_audience_prefix,
            nodes,
            wait,
            tun,
            mtu,
            overlay_prefix,
            listen_port,
            no_udp,
            status_file,
            ready_file,
            status_interval,
        } => {
            let k = DeviceKey::load(&key)?;
            let mut source = if github {
                let env = GithubEnv::from_env()?;
                let prefix = artifact_prefix.unwrap_or_else(|| match scope {
                    Scope::Run => format!("node-{}-", env.run_attempt),
                    _ => "node-".into(),
                });
                Source::Github(Box::new(GithubSource::new(env, scope, prefix, oidc_audience_prefix)))
            } else if let Some(d) = records {
                Source::Dir(d)
            } else if !record.is_empty() {
                Source::Files(record)
            } else {
                bail!("say where peer records come from: --records DIR, --record FILE, or --github");
            };
            let mut dm = DerpMap::default();
            let needs_map = k.record.derp.is_none();
            if needs_map {
                dm = fetch_map(&cli.derpmap_url).await?;
            }
            let overlay = Overlay::start(OverlayConfig {
                key: k.clone(),
                derp_map: dm.clone(),
                listen_port,
                overlay_prefix,
                enable_udp: !no_udp,
            })
            .await?;
            if !overlay.wait_derp(Duration::from_secs(15)).await {
                warn!("not yet connected to the home DERP region; continuing");
            }
            let dev = open_tun(tun.as_deref(), &k.record, &overlay_prefix, mtu)?;
            let mut runner = tokio::spawn(overlay.clone().run(dev));
            info!("overlay: {} is node {} at {}", k.record.nodekey, k.record.index, k.record.overlay_ip);

            let expected = nodes.map(|n| n.saturating_sub(1));
            let deadline = Instant::now() + wait;
            let mut last_status = Instant::now();
            let mut last_poll: Option<Instant> = None;
            let mut ready = false;
            // Poll quickly while nodes are joining, then back off: the
            // GitHub API is rate-limited per repository.
            let settled_poll = if github { Duration::from_secs(30) } else { Duration::from_secs(5) };
            let signal = shutdown_signal();
            tokio::pin!(signal);
            loop {
                let joining = expected.is_some_and(|n| overlay.peer_count() < n) || !ready;
                let poll_every = if joining { Duration::from_secs(2) } else { settled_poll };
                let poll_due = last_poll.is_none_or(|t| t.elapsed() >= poll_every);
                if poll_due {
                    last_poll = Some(Instant::now());
                }
                match if poll_due { source.poll().await } else { Ok(Vec::new()) } {
                    Ok(recs) => {
                        for r in &recs {
                            // Fetch the DERP map the first time a peer needs it.
                            if r.derp.is_none() && dm.regions.is_empty() {
                                dm = fetch_map(&cli.derpmap_url).await?;
                            }
                            if let Err(e) = overlay.add_peer(r, &dm) {
                                warn!("{e:#}");
                            }
                        }
                    }
                    Err(e) => warn!("polling records: {e:#}"),
                }
                let have = overlay.peer_count();
                if let Some(n) = expected {
                    if have < n && Instant::now() > deadline {
                        bail!("only {have} of {n} peers appeared within {}s", wait.as_secs());
                    }
                    if have >= n && !ready {
                        ready = all_reachable(&overlay).await;
                        if ready {
                            info!("overlay: all {n} peers reachable");
                            if let Some(f) = &ready_file {
                                std::fs::write(f, b"ready\n")?;
                            }
                        }
                    }
                }
                if last_status.elapsed() >= status_interval {
                    last_status = Instant::now();
                    log_status(&overlay);
                }
                if let Some(f) = &status_file {
                    let _ = std::fs::write(f, serde_json::to_vec_pretty(&overlay.status())?);
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                    _ = &mut signal => {
                        info!("overlay: shutting down");
                        overlay.close();
                        return Ok(());
                    }
                    r = &mut runner => {
                        return match r {
                            Ok(Ok(())) => Err(anyhow!("the packet loop stopped")),
                            Ok(Err(e)) => Err(e),
                            Err(e) => Err(anyhow!("the packet loop panicked: {e}")),
                        };
                    }
                }
            }
        }
    }
}

/// Pings every peer once, driving path discovery; true if all answer.
async fn all_reachable(o: &Arc<Overlay>) -> bool {
    let mut ok = true;
    for p in o.status() {
        match o.ping(&p.nodekey, Duration::from_secs(3)).await {
            Ok(r) => info!(peer = p.index, "overlay: pong from {} in {:?} via {}", p.overlay_ip, r.latency, r.via),
            Err(_) => ok = false,
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
            p.handshake_age_secs.map(|s| format!("{s}s ago")).unwrap_or_else(|| "never".into()),
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

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Picks the home region for `init`.
async fn pick_region(url: &str, region: &str) -> Result<(i32, Option<DerpRegion>)> {
    if region.contains('.') {
        let nodes =
            region.split(',').map(|h| DerpNode { name: h.into(), host_name: h.into(), ..Default::default() }).collect();
        return Ok((0, Some(DerpRegion { region_id: 900, region_code: "custom".into(), nodes, ..Default::default() })));
    }
    let dm = fetch_map(url).await?;
    if region == "auto" {
        let id = tailcat::netcheck::pick_best_region(&dm)
            .await?
            .ok_or_else(|| anyhow!("couldn't find the nearest DERP region; pass --region"))?;
        return Ok((id, None));
    }
    if let Ok(id) = region.parse::<i32>() {
        if !dm.regions.contains_key(&id) {
            bail!("no DERP region {id} in the DERP map");
        }
        return Ok((id, None));
    }
    let id = tailcat::derpmap::find_region(&dm, region).ok_or_else(|| anyhow!("no DERP region matching {region:?}"))?;
    Ok((id, None))
}
