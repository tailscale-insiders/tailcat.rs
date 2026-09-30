//! The `tailcat` command: netcat over Tailscale's data plane (WireGuard,
//! DERP, NAT traversal), without Tailscale's control plane.
//!
//! This is a Rust port of the Go `cmd/tailcat`, with the same
//! subcommands, flags, and output, built on the `tailcat` crate.

mod addrarg;
mod args;
mod cache;
mod client;
mod forward;
mod genkey;
mod help;
mod keys;
mod perf;
mod serve;
mod socks;
#[cfg(feature = "ssh")]
mod ssh;
mod util;

use std::process::ExitCode;

use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};

/// Flags accepted by every subcommand.
#[derive(Args, Debug, Clone)]
pub struct Global {
    /// 'new' for an ephemeral key. If empty, the default saved key is used if it exists ('default' in server
    /// mode, 'client-default' in client modes; see genkey), else an ephemeral key. Otherwise the path to a
    /// *.private.json or a name like 'foo' to read it from $CONFIG/tailcat/keys/foo.private.json
    #[arg(long, global = true, value_name = "KEY", default_value = "", hide_default_value = true)]
    pub key: args::KeyArg,
    /// Be verbose.
    #[arg(long, global = true)]
    pub verbose: bool,
    /// In server mode, write {"listenAddr": ...} JSON to stdout; with perf, write the results as JSON.
    #[arg(long, global = true)]
    pub json: bool,
    /// URL of the JSON DERP map used to resolve or auto-select a DERP region.
    #[arg(
        long,
        global = true,
        env = "TAILCAT_DERPMAP_URL",
        default_value = tailcat::DEFAULT_DERP_MAP_URL,
        value_name = "URL"
    )]
    pub derpmap_url: String,
}

/// Flags for server modes.
#[derive(Args, Debug, Clone, Default)]
pub struct ServeFlags {
    /// Comma-separated list of public keys to allow access to the server, or 'none' to allow no clients. If
    /// empty, all clients are allowed.
    #[arg(long, value_name = "KEYS")]
    pub allow: Option<args::AllowArg>,
    /// Print a longer tailcat address with embedded DERP server info instead of a reference to a DERP map
    /// region ID. This lets clients connect more quickly, without a DERP map fetch.
    #[arg(long)]
    pub full_address: bool,
    /// Directory to serve to SFTP clients (scp, sftp) with the 'files' service, with an optional :ro
    /// (read-only, the default), :rw (read-write), :wo (flat write-only drop box), or :wo+ (recursive
    /// write-only drop box) suffix. Giving --files implies the 'files' service.
    #[arg(long, value_name = "DIR[:MODE]")]
    pub files: Option<args::FilesArg>,
    /// Comma-separated SSH public key sources for the 'ssh' service: authorized_keys file paths, literal
    /// OpenSSH public key lines, or names like 'alice@github' (fetched from https://github.com/alice.keys).
    #[arg(long, value_name = "SOURCES")]
    pub ssh_authorized_keys: Option<args::AuthorizedKeysArg>,
    /// Include a WireGuard pre-shared key in the tailcat address (recommended). Set false only for shorter
    /// addresses and compatibility with tailcat clients v0.5.0 and earlier; this weakens security.
    #[arg(long, value_name = "BOOL", num_args = 0..=1, default_missing_value = "true", action = ArgAction::Set)]
    pub psk: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(
    name = "tailcat",
    about = "securely pipe or serve network connections over Tailscale's data plane (WireGuard®, NAT traversal), without Tailscale's control plane (central server, accounts)",
    long_about = None,
    after_long_help = help::ROOT,
    override_usage = "tailcat [flags] [<subcommand> [flags]] [args...]",
    disable_version_flag = true,
)]
struct Cli {
    #[command(flatten)]
    global: Global,
    /// Comma-separated list of port numbers, port ranges, or service names to serve (see "tailcat serve
    /// --help"). If empty, it accepts a single connection on any port, writes it to stdout, and exits.
    #[arg(long, value_name = "SPEC")]
    serve: Option<serve::PortSet>,
    #[command(flatten)]
    serve_flags: ServeFlags,
    /// Print the version.
    #[arg(long, hide = true)]
    version: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Client mode: <tc-addr> [<port>|<ip:port>]
    #[arg(value_name = "ARGS")]
    args: Vec<String>,
    /// Server mode: a command to run for each connection (the exec service).
    #[arg(last = true, value_name = "COMMAND")]
    exec: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// run a server (the default when tailcat is run with no arguments)
    #[command(
        after_long_help = help::SERVE,
        override_usage = "tailcat serve [flags] [<port,service,...> ...] [-- <command> [args...]]"
    )]
    Serve {
        #[command(flatten)]
        flags: ServeFlags,
        /// Ports, port ranges, port mappings, and service names.
        specs: Vec<serve::PortSet>,
        #[arg(last = true)]
        exec: Vec<String>,
    },
    /// ping a server, reporting DERP or direct paths
    #[command(after_long_help = help::PING)]
    Ping {
        /// Keep pinging until a pong arrives over a direct (non-DERP) path; exit non-zero if that doesn't happen
        /// before --timeout.
        #[arg(long)]
        until_direct: bool,
        /// Give up after this long.
        #[arg(long, default_value = "10s", value_parser = tailcat_args::parse_duration)]
        timeout: std::time::Duration,
        addr: String,
    },
    /// measure throughput and latency to a server (iperf-like)
    Perf(perf::PerfArgs),
    /// run a SOCKS5 proxy that dials tailcat servers
    #[command(after_long_help = help::SOCKS)]
    Socks {
        /// SOCKS5 proxy listen [address]:port; a bare port means localhost, a bare address means an OS-assigned
        /// port.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: args::ListenArg,
        /// [<tc-addr>] [<cmd> [args...]]
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// receive files: serve a directory as a write-only drop box
    #[command(after_long_help = help::RECV)]
    Recv {
        #[command(flatten)]
        flags: ServeFlags,
        /// Accept directory trees (tailcat cp -r), keeping requested file names when available. Senders can
        /// then make and stat directories and learn whether some names already exist in the drop box.
        #[arg(long)]
        accept_dirs: bool,
        dir: Option<String>,
    },
    /// connect the system ssh client through a tailcat server
    #[cfg(feature = "ssh")]
    #[command(after_long_help = help::SSH)]
    Ssh {
        /// Port number, or ip:port to reach via the server's exit node; a bare IP means port 22 on it.
        #[arg(short = 'p', default_value = "22")]
        port: args::SshTarget,
        /// Don't probe a DNS-named destination for whether its server gives SSH access to strangers.
        #[arg(long)]
        skip_dns_safety_check: bool,
        /// [user@]<tc-addr> [<command> [args...]]
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },
    /// copy files to or from a tailcat server, using the system scp
    #[cfg(feature = "ssh")]
    #[command(after_long_help = help::CP)]
    Cp {
        /// Recursively copy directories.
        #[arg(short = 'r')]
        recursive: bool,
        /// Preserve modification times and modes.
        #[arg(short = 'p')]
        preserve: bool,
        /// Port number of the server's SSH (file service) port.
        #[arg(short = 'P', default_value = "22")]
        port: args::SshTarget,
        args: Vec<String>,
    },
    /// list files on a tailcat server
    #[cfg(feature = "ssh")]
    #[command(after_long_help = help::LS)]
    Ls {
        /// Long listing: permissions, size, and modification time.
        #[arg(short = 'l')]
        long: bool,
        target: String,
    },
    /// forward local TCP ports to a tailcat server
    #[command(after_long_help = help::FORWARD)]
    Forward {
        /// Listen address; used as the local address when a mapping only specifies a port.
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Open a web browser to the local listener once it's listening; requires exactly one port mapping.
        #[arg(long)]
        open_browser: bool,
        addr: String,
        #[arg(required = true)]
        mappings: Vec<args::ForwardArg>,
    },
    /// open a web browser to a tailcat server's port 80
    Browse { addr: String },
    /// decode a tailcat address and print its fields as JSON
    Parse { addr: String },
    /// expand a short tailcat address to embed its DERP server info
    Resolve { addr: String },
    /// generate, list, or delete saved keys
    #[command(after_long_help = help::GENKEY)]
    Genkey(genkey::GenkeyArgs),
    /// print the public key of the client key that would be used
    Printpub,
    /// print the tailcat version
    Version,
    /// print the tailcat README (documentation with usage examples)
    Readme,
    /// run a local development DERP relay and STUN server (for tests)
    #[command(hide = true)]
    DevDerp {
        /// TCP address for DERP over TLS.
        #[arg(long, default_value = "127.0.0.1:0")]
        derp: std::net::SocketAddr,
        /// UDP address for STUN.
        #[arg(long, default_value = "127.0.0.1:0")]
        stun: std::net::SocketAddr,
        /// The IP address to advertise in the region.
        #[arg(long)]
        advertise: Option<std::net::IpAddr>,
        /// Write the region's JSON to this file once listening.
        #[arg(long)]
        region_file: Option<std::path::PathBuf>,
    },
}

/// A usage error: printed with the command's help.
#[derive(Debug)]
pub struct UsageError(String);

impl UsageError {
    pub fn new(msg: impl Into<String>) -> Self {
        UsageError(msg.into())
    }
}

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

/// Returns a usage error.
#[macro_export]
macro_rules! usagef {
    ($($t:tt)*) => { anyhow::Error::new($crate::UsageError::new(format!($($t)*))) };
}

/// The version: $TAILCAT_VERSION at build time, else the crate's.
const VERSION: &str = match option_env!("TAILCAT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

fn init_logging(verbose: bool) {
    let default = if verbose { "info,tailcat=debug,tailcat_cli=debug" } else { "off" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
    tailcat::set_verbose(verbose);
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    // The command after "--", like Go's splitExecArgs: None without a
    // separator, empty with one followed by nothing.
    let has_separator = argv.iter().skip(1).any(|a| a == "--");
    let cli = match Cli::try_parse_from(&argv) {
        Ok(c) => c,
        // --version anywhere, even where it's not otherwise valid.
        Err(_) if argv.iter().any(|a| a == "--version") => {
            println!("{VERSION}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { ExitCode::from(2) } else { ExitCode::SUCCESS };
        }
    };
    if cli.version {
        println!("{VERSION}");
        return ExitCode::SUCCESS;
    }
    init_logging(cli.global.verbose);

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(run(cli, has_separator)).unwrap_or_else(|e| {
        if e.is::<UsageError>() {
            let _ = Cli::command().print_help();
            eprintln!();
        }
        eprintln!("{e:#}");
        ExitCode::FAILURE
    })
}

/// Runs the command. Those that don't exit with a child's status succeed
/// unless they return an error.
async fn run(cli: Cli, has_separator: bool) -> anyhow::Result<ExitCode> {
    let g = &cli.global;
    let exec = |v: Vec<String>| has_separator.then_some(v);
    match cli.cmd {
        None if cli.args.first().is_some_and(|a| a == "help") => {
            let _ = Cli::command().print_long_help();
        }
        None if cli.args.is_empty() || cli.serve.is_some() => {
            if !cli.args.is_empty() {
                return Err(usagef!("no positional arguments are valid along with --serve"));
            }
            serve::server(g, &cli.serve_flags, cli.serve.unwrap_or_default(), exec(cli.exec)).await?;
        }
        None => {
            if has_separator {
                return Err(usagef!("a -- command is only valid in server mode"));
            }
            if cli.args.len() > 2 {
                return Err(usagef!("too many arguments; client mode takes <tc-addr> [<port>]"));
            }
            client::client_mode(g, &cli.args[0], cli.args.get(1).map(String::as_str)).await?;
        }
        Some(Cmd::Serve { flags, specs, exec: ex }) => {
            let spec = match (cli.serve, specs.is_empty()) {
                (Some(_), false) => {
                    return Err(usagef!("use either --serve or positional port/service arguments, not both"));
                }
                (serve, true) => serve.unwrap_or_default(),
                (None, false) => {
                    let mut all = serve::PortSet::default();
                    for s in specs {
                        all.merge(s).map_err(|e| anyhow::anyhow!("invalid port or service to serve: {e}"))?;
                    }
                    all
                }
            };
            serve::server(g, &flags, spec, exec(ex)).await?;
        }
        Some(Cmd::Ping { until_direct, timeout, addr }) => client::ping_mode(g, until_direct, timeout, &addr).await?,
        Some(Cmd::Perf(a)) => perf::run(g, a).await?,
        Some(Cmd::Socks { listen, args }) => return socks::socks_mode(g, &listen, args).await,
        Some(Cmd::Recv { mut flags, accept_dirs, dir }) => {
            if flags.files.is_some() {
                return Err(usagef!("recv takes the directory as an argument, not --files"));
            }
            let mode = if accept_dirs { args::FilesMode::WriteOnlyTree } else { args::FilesMode::WriteOnly };
            flags.files = Some(args::FilesArg::new(dir.unwrap_or_default(), mode));
            serve::server(g, &flags, serve::PortSet::default(), None).await?;
        }
        #[cfg(feature = "ssh")]
        Some(Cmd::Ssh { port, skip_dns_safety_check, args }) => {
            return ssh::ssh_mode(g, port, skip_dns_safety_check, args).await;
        }
        #[cfg(feature = "ssh")]
        Some(Cmd::Cp { recursive, preserve, port, args }) => {
            return ssh::cp_mode(g, recursive, preserve, port, args).await;
        }
        #[cfg(feature = "ssh")]
        Some(Cmd::Ls { long, target }) => return ssh::ls_mode(g, long, &target).await,
        Some(Cmd::Forward { bind, open_browser, addr, mappings }) => {
            if open_browser && mappings.len() != 1 {
                return Err(usagef!("--open-browser requires exactly one port mapping"));
            }
            forward::run_forward(g, &bind, &addr, &mappings, open_browser).await?;
        }
        Some(Cmd::Browse { addr }) => {
            let port_80 = args::ForwardArg::new(0, args::Dest::Port(80));
            forward::run_forward(g, "127.0.0.1", &addr, &[port_80], true).await?
        }
        Some(Cmd::Parse { addr }) => {
            let v = tailcat::Addr::new(addr).parse_raw_json()?;
            print!("{}", tailcat::addr::to_go_indented_json(&v));
        }
        Some(Cmd::Resolve { addr }) => {
            let a = addrarg::tailcat_addr_arg(&addr).await?;
            let opts = cache::fetch_options(g, tailcat::FetchMode::Client);
            let r = tokio::time::timeout(std::time::Duration::from_secs(10), a.resolve(opts))
                .await
                .map_err(|_| anyhow::anyhow!("timed out resolving the DERP region"))??;
            println!("{r}");
        }
        Some(Cmd::Genkey(a)) => genkey::genkey(g, a).await?,
        Some(Cmd::Printpub) => println!("{}", keys::client_key(g)?.public()),
        Some(Cmd::Version) => println!("{VERSION}"),
        Some(Cmd::Readme) => print!("{}", help::README),
        Some(Cmd::DevDerp { derp, stun, advertise, region_file }) => {
            let d = tailcat::derp::server::DevDerp::start(derp, stun, advertise).await?;
            let j = serde_json::to_string_pretty(&d.region)?;
            if let Some(f) = region_file {
                // Atomically: scripts poll for it.
                util::replace_private(&f, j.as_bytes())
                    .map_err(|e| anyhow::anyhow!("--region-file: {}: {e}", f.display()))?;
            }
            println!("{j}");
            eprintln!("# dev DERP relay running; press Ctrl-C to stop");
            forward::shutdown_signal().await;
        }
    }
    Ok(ExitCode::SUCCESS)
}
