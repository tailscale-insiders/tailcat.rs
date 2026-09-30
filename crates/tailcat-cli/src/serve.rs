//! Server mode: `tailcat`, `tailcat serve`, `tailcat recv`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tailcat::{
    Addr, ConnInfo, DerpRegion, FetchMode, KeySet, PortRange, PresharedKey, PrivateKey, Server, TcpHandler, TcpStream,
    UdpConn, handler, udp_handler,
};
use tokio::io::AsyncWriteExt;
use tracing::debug;

#[cfg(feature = "ssh")]
use crate::args::FilesArg;
use crate::args::KeyArg;
use crate::perf::PORT as PERF_PORT;
use crate::{Global, ServeFlags};

/// A service `serve` knows by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Service {
    Ssh,
    NoAuthSsh,
    Files,
    Exec,
    ExitNode,
    Perf,
}

impl Service {
    const ALL: [Service; 6] =
        [Service::Ssh, Service::NoAuthSsh, Service::Files, Service::Exec, Service::ExitNode, Service::Perf];

    /// Its name in a serve spec.
    pub fn name(self) -> &'static str {
        match self {
            Service::Ssh => "ssh",
            Service::NoAuthSsh => "no-auth-ssh",
            Service::Files => "files",
            Service::Exec => "exec",
            Service::ExitNode => "exit-node",
            Service::Perf => "perf",
        }
    }

    /// The service called `name`, if any.
    pub fn named(name: &str) -> Option<Service> {
        Service::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Whether it's served over SSH.
    fn needs_ssh(self) -> bool {
        matches!(self, Service::Ssh | Service::NoAuthSsh | Service::Files)
    }
}

/// The names a serve spec knows: "all", then the services'.
fn known_names() -> String {
    std::iter::once("all").chain(Service::ALL.map(Service::name)).collect::<Vec<_>>().join(", ")
}

/// A parsed serve spec.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PortSet {
    pub all: bool,
    pub ports: BTreeSet<u16>,
    pub services: BTreeSet<Service>,
    /// Mapped ports' targets, as dialable host:port.
    pub targets: BTreeMap<u16, String>,
}

impl PortSet {
    pub fn contains(&self, p: u16) -> bool {
        (self.all && p != 0) || self.ports.contains(&p)
    }

    pub fn is_empty(&self) -> bool {
        !self.all && self.ports.is_empty()
    }

    /// Serves `port` by proxying it to `target`, unless it's already
    /// mapped elsewhere.
    fn map_port(&mut self, port: u16, target: String) -> Result<()> {
        if let Some(prev) = self.targets.get(&port)
            && *prev != target
        {
            bail!("port {port} is mapped to both {prev} and {target}");
        }
        self.ports.insert(port);
        self.targets.insert(port, target);
        Ok(())
    }

    /// Adds what `other` serves, as a spec listing both would.
    pub fn merge(&mut self, other: PortSet) -> Result<()> {
        self.all |= other.all;
        self.ports.extend(other.ports);
        self.services.extend(other.services);
        for (port, target) in other.targets {
            self.map_port(port, target)?;
        }
        Ok(())
    }

    /// The TCP ports to admit: those served, plus `extra`. "all" covers
    /// every port but 0.
    fn tcp_ranges(&self, extra: impl IntoIterator<Item = u16>) -> Vec<PortRange> {
        if self.all {
            return vec![PortRange::new(1, u16::MAX)];
        }
        let ports: BTreeSet<u16> = self.ports.iter().copied().chain(extra).collect();
        PortRange::coalesce(ports)
    }
}

fn is_num(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parses a serve spec: comma-separated ports, port ranges, service
/// names, and mappings "port:target", where the target is a port on
/// localhost or a host:port elsewhere.
pub fn parse_port_set(s: &str) -> Result<PortSet> {
    let mut ps = PortSet::default();
    let s = s.trim();
    if s.is_empty() {
        return Ok(ps);
    }
    for r in s.split(',').map(str::trim) {
        if let Some(service) = Service::named(r) {
            if service.needs_ssh() && !cfg!(feature = "ssh") {
                bail!("SSH support not included in this build");
            }
            ps.services.insert(service);
            continue;
        }
        match r {
            "all" => ps.all = true,
            _ => {
                if let Some((port, target)) = r.split_once(':') {
                    let (port, target) = parse_port_target(port, target)?;
                    ps.map_port(port, target)?;
                    continue;
                }
                let (a, b) = match r.split_once('-') {
                    Some((a, b)) if is_num(a) && is_num(b) => (a, b),
                    _ if is_num(r) => (r, r),
                    _ => bail!("{r:?} is not a known named service (want one of: {})", known_names()),
                };
                let lo: u16 = a.parse().map_err(|_| anyhow!("{a:?} is not a valid port"))?;
                let hi: u16 = b.parse().map_err(|_| anyhow!("{b:?} is not a valid port number"))?;
                ps.ports.extend(lo.min(hi)..=lo.max(hi));
            }
        }
    }
    Ok(ps)
}

impl std::str::FromStr for PortSet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        parse_port_set(s)
    }
}

/// Parses the halves of a "port:target" mapping.
pub fn parse_port_target(port: &str, target: &str) -> Result<(u16, String)> {
    let mapping = format!("{port}:{target}");
    let p: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow!("{port:?} is not a valid port in mapping {mapping:?}"))?;
    if is_num(target) {
        target.parse::<u16>().map_err(|_| anyhow!("{target:?} is not a valid port in mapping {mapping:?}"))?;
        return Ok((p, format!("localhost:{target}")));
    }
    let (host, tport) = crate::util::split_host_port(target)
        .ok()
        .filter(|(h, _)| !h.is_empty())
        .ok_or_else(|| anyhow!("target {target:?} in mapping {mapping:?} is not a port or host:port"))?;
    if tport == 0 {
        bail!("\"0\" is not a valid port in mapping {mapping:?}");
    }
    Ok((p, crate::util::join_host_port(&host, tport)))
}

/// Removes region fields a printed address doesn't need, like Go's
/// clearUnnecessaryRegionFields.
fn clear_unnecessary_region_fields(r: &mut DerpRegion) {
    r.latitude = 0.0;
    r.longitude = 0.0;
    r.region_code = tailcat::RegionCode::Unset;
    r.nodes.truncate(1);
    for n in &mut r.nodes {
        n.can_port_80 = false;
        n.region_id = 0;
    }
}

fn env_bool(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1" | "true" | "TRUE" | "True" | "t"))
}

async fn proxy_to_local(target: String, c: TcpStream) {
    match crate::util::dial_local(&target).await {
        Ok(local) => {
            let _ = local.set_nodelay(true);
            proxy_and_drain(c, local).await;
        }
        Err(e) => debug!("error proxying to {target}: {e}"),
    }
}

/// Proxies until both directions finish, then lets our FIN be acked.
pub async fn proxy_and_drain(c: TcpStream, local: tokio::net::TcpStream) {
    let (mut cr, mut cw) = tokio::io::split(c);
    let (mut lr, mut lw) = local.into_split();
    let a = async {
        let _ = tokio::io::copy(&mut cr, &mut lw).await;
        let _ = lw.shutdown().await;
    };
    let b = async {
        let _ = tokio::io::copy(&mut lr, &mut cw).await;
        let _ = cw.shutdown().await;
    };
    tokio::join!(a, b);
    cr.unsplit(cw).drain(Duration::from_secs(5)).await;
}

async fn udp_forward_to(dst: SocketAddr, c: UdpConn) {
    let any = if dst.is_ipv4() { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() };
    let sock = async {
        let sock = tokio::net::UdpSocket::bind(SocketAddr::new(any, 0)).await?;
        sock.connect(dst).await?;
        std::io::Result::Ok(sock)
    };
    match sock.await {
        Ok(sock) => tailcat::proxy_packet_conns(&c, &sock, tailcat::DEFAULT_UDP_IDLE_TIMEOUT).await,
        Err(e) => debug!("error proxying to {dst}: {e}"),
    }
}

/// Runs a server until killed.
pub async fn server(g: &Global, flags: &ServeFlags, ps: PortSet, exec_args: Option<Vec<String>>) -> Result<()> {
    let mut services = ps.services.clone();
    let exec_args = match exec_args {
        Some(a) if a.is_empty() => bail!("no command given after --"),
        Some(mut a) => {
            a[0] = which(&a[0]).with_context(|| format!("exec command: {:?} not found", a[0]))?;
            if !services.contains(&Service::Ssh) && !services.contains(&Service::NoAuthSsh) {
                services.insert(Service::Exec);
            }
            Some(a)
        }
        None if services.contains(&Service::Exec) => bail!("the 'exec' service requires a command after --"),
        None => None,
    };
    if flags.files.is_some() {
        if !cfg!(feature = "ssh") {
            bail!("--files requires SSH support, not included in this build");
        }
        services.insert(Service::Files);
    }
    let has = |s: Service| services.contains(&s);
    let (ssh_auth, ssh_noauth, serve_perf, exit_node, serve_exec) =
        (has(Service::Ssh), has(Service::NoAuthSsh), has(Service::Perf), has(Service::ExitNode), has(Service::Exec));
    let ssh_shell = ssh_auth || ssh_noauth;
    let ssh_services = ssh_shell || has(Service::Files);
    if serve_perf && ps.contains(PERF_PORT) {
        bail!("port {PERF_PORT} is used by the 'perf' service and cannot also be proxied");
    }
    if ssh_auth && ssh_noauth {
        bail!("the 'ssh' and 'no-auth-ssh' services cannot be served together");
    }
    if ssh_auth && flags.ssh_authorized_keys.is_none() {
        bail!("the 'ssh' service requires --ssh-authorized-keys");
    }
    if ssh_noauth && flags.ssh_authorized_keys.is_some() {
        bail!("--ssh-authorized-keys cannot be used with the 'no-auth-ssh' service; use 'ssh' instead");
    }
    if flags.ssh_authorized_keys.is_some() && !ssh_auth {
        bail!("--ssh-authorized-keys requires the 'ssh' service");
    }
    if ssh_shell && exec_args.is_some() && has(Service::Files) {
        bail!("the 'files' service cannot be served with an SSH -- command, which allows nothing but that command");
    }
    #[cfg(feature = "ssh")]
    let authorized_keys = match &flags.ssh_authorized_keys {
        Some(src) => crate::ssh::load_authorized_keys(src).await.map_err(|e| anyhow!("--ssh-authorized-keys: {e}"))?,
        None => Vec::new(),
    };
    let one_shot_stdout = ps.is_empty() && services.is_empty();

    // A local development relay, embedded in the address.
    let dev_derp = if env_bool("TS_DEBUG_TAILCAT_LOCAL_DERP") {
        eprintln!("Local DERP mode.");
        Some(tailcat::derp::server::DevDerp::start_local().await?)
    } else {
        None
    };

    let key = crate::keys::chosen(g, "default")?;
    let key_file = crate::keys::key_file(&key)?;
    let new_key = key_file.is_none();
    let (private, mut ci) = match &key_file {
        None => {
            let k = PrivateKey::generate();
            (k.private, ConnInfo { region_id: -1, ..k.public })
        }
        Some(path) => {
            let k = crate::keys::load(path)?;
            (k.private, k.public)
        }
    };
    // Saved keys remember whether they use a PSK.
    let use_psk = flags.psk.unwrap_or(new_key || !ci.preshared_key.is_zero());
    if use_psk
        && ci.preshared_key.is_zero()
        && let Some(path) = &key_file
    {
        bail!("key file {} has no WireGuard pre-shared key", path.display());
    }
    let psk = if use_psk { ci.preshared_key } else { PresharedKey::default() };

    let (region, embed) = match &dev_derp {
        Some(d) => (d.region.clone(), true),
        None => {
            // A key with custom DERP hostnames has regions with no map ID,
            // so its address always embeds them.
            let embed = flags.full_address || !ci.region.is_empty();
            ci.expand(crate::cache::fetch_options(g, FetchMode::Server), None)
                .await
                .map_err(|e| anyhow!("Expand: {e}"))?;
            let mut reg = ci.region.swap_remove(0);
            clear_unnecessary_region_fields(&mut reg);
            eprintln!("# Selected bootstrap relay region {}, {}", reg.region_id, reg.region_name);
            (reg, embed)
        }
    };
    let conn_str = ConnInfo {
        server_public: private.public(),
        server_disco_public: private.disco_private().public(),
        preshared_key: psk,
        region: if embed { vec![region.clone()] } else { Vec::new() },
        region_id: if embed { 0 } else { region.region_id },
    }
    .addr();

    let mut b =
        Server::builder().key(private.clone()).preshared_key(psk).disable_preshared_key(!use_psk).region(region);

    // Outside the accept-one-connection mode (and exit-node and exec,
    // which accept any port), admit only the served ports.
    if !one_shot_stdout && !exit_node && !serve_exec {
        let extra = [ssh_services.then_some(22), serve_perf.then_some(PERF_PORT)];
        b = b.served_tcp_ports(ps.tcp_ranges(extra.into_iter().flatten()));
    }
    if serve_perf {
        b = b.served_udp_ports(vec![PortRange::single(PERF_PORT)]);
    }
    if let Some(allow) = &flags.allow {
        // An empty set allows no clients.
        b = b.allow_client(KeySet::from(allow.clone()).checker());
    }
    if exit_node {
        b = b
            .on_tcp_forward(|dst| Some(handler(move |c| proxy_to_local(dst.to_string(), c))))
            .on_udp_forward(|dst| Some(udp_handler(move |c| udp_forward_to(dst, c))));
    }

    // Handlers that need the server itself (for peer identity, draining)
    // get it through this cell, filled in after start. A client that
    // knows a saved key's address can connect before then, so handlers
    // wait for `ready` first.
    let me: Arc<OnceLock<Server>> = Arc::default();
    let (ready_tx, ready) = tokio::sync::watch::channel(false);

    #[cfg(feature = "ssh")]
    let ssh_handler = if ssh_services {
        let mut opts = tailcat::ssh::SshOptions { shell: ssh_shell, authorized_keys, ..Default::default() };
        if ssh_shell && let Some(a) = &exec_args {
            opts.exec = a.clone();
            eprintln!("# SSH sessions run only {}", a.join(" "));
        }
        if has(Service::Files) {
            let files = flags.files.clone().unwrap_or_default();
            let fs = file_service(&files)?;
            eprintln!("# Serving files from {} ({})", fs.dir.display(), files.mode.name());
            opts.files = Some(fs);
        }
        Some(tailcat::ssh::conn_handler(me.clone(), opts)?)
    } else {
        None
    };
    // Without SSH support, no SSH service gets past the checks above.
    #[cfg(not(feature = "ssh"))]
    let ssh_handler: Option<tailcat::TcpHandler> = None;

    let perf_srv = if serve_perf {
        let p = Arc::new(crate::perf::Server::default());
        let pu = p.clone();
        b = b.on_udp(move |port| {
            let pu = pu.clone();
            (port == PERF_PORT).then(|| udp_handler(move |c| pu.clone().handle_udp(c)))
        });
        eprintln!("# Accepting perf tests on TCP and UDP port {PERF_PORT}");
        Some(p)
    } else {
        None
    };

    let exec_cmd = exec_args.clone().filter(|_| serve_exec);
    if let Some(a) = &exec_cmd {
        eprintln!("# Running {} for each connection", a.join(" "));
    }
    for (port, t) in &ps.targets {
        eprintln!("# Proxying port {port} to {t}");
    }

    let ps = Arc::new(ps);
    let exec_h: Arc<OnceLock<TcpHandler>> = Arc::default();
    // The accept-one-connection mode serves the first connection only.
    let one_shot_taken = Arc::new(AtomicBool::new(false));
    let serves_exec = exec_cmd.is_some();
    b = b.on_tcp({
        let (me, exec_h) = (me.clone(), exec_h.clone());
        let route = move |port| {
            if port == 22
                && let Some(h) = &ssh_handler
            {
                return Some(h.clone());
            }
            if port == PERF_PORT
                && let Some(p) = &perf_srv
            {
                let p = p.clone();
                return Some(handler(move |c| p.clone().handle_tcp(c)));
            }
            if ps.contains(port) {
                let t = ps.targets.get(&port).cloned().unwrap_or_else(|| format!("localhost:{port}"));
                return Some(handler(move |c| proxy_to_local(t.clone(), c)));
            }
            if serves_exec {
                let exec_h = exec_h.clone();
                return Some(Arc::new(move |c| exec_h.get().expect("exec handler set at start")(c)) as TcpHandler);
            }
            if exit_node {
                // Being an exit node includes localhost's ports too.
                return Some(handler(move |c| proxy_to_local(format!("localhost:{port}"), c)));
            }
            if one_shot_stdout {
                // Refuse the rest, so they fail instead of being lost.
                if one_shot_taken.load(Ordering::Relaxed) {
                    return None;
                }
                let (me, taken) = (me.clone(), one_shot_taken.clone());
                return Some(handler(move |c| {
                    // Of connections that got this far at once, only the
                    // first to be established is served.
                    let first = !taken.swap(true, Ordering::Relaxed);
                    let me = me.clone();
                    async move {
                        if first {
                            one_shot(me, c).await;
                        } else {
                            c.abort();
                        }
                    }
                }));
            }
            None
        };
        move |port| route(port).map(|h| after_start(ready.clone(), h))
    });

    let s = b.start().await.map_err(|e| anyhow!("Server.Start: {e}"))?;
    let _ = me.set(s.clone());
    if let Some(a) = exec_cmd {
        let _ = exec_h.set(s.exec_conn_handler(a));
    }
    ready_tx.send_replace(true);
    if psk.is_zero() {
        if new_key {
            eprintln!("# ⚠️ WARNING: serving without a WireGuard PSK");
        } else {
            eprintln!("# ⚠️ WARNING: saved key {:?} is not using a WireGuard PSK", key.to_string());
        }
    }
    if ssh_noauth && flags.allow.is_none() {
        let gives = if exec_args.is_some() { "runs the command for" } else { "gives a shell to" };
        eprintln!(
            "# ⚠️ WARNING: no-auth-ssh {gives} anyone with this address; keep it secret (never in a DNS TXT record) or restrict clients with --allow"
        );
    }
    if let Some(d) = &dev_derp
        && !d.wait_for_client(&private.public(), Duration::from_secs(30)).await
    {
        bail!("timeout waiting for connection to local dev DERP");
    }
    announce(g, &key, &conn_str).await?;

    if std::env::var("TAILCAT_STATUS_LOOP").as_deref() == Ok("1") {
        tokio::spawn(async move {
            loop {
                eprintln!("status = {:?}", s.status());
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }
    let _keep = dev_derp;
    crate::forward::shutdown_signal().await;
    Ok(())
}

/// Holds `h` back until `ready`, when the cells handlers read the server
/// from are filled in.
fn after_start(ready: tokio::sync::watch::Receiver<bool>, h: TcpHandler) -> TcpHandler {
    handler(move |c| {
        let (mut ready, h) = (ready.clone(), h.clone());
        async move {
            if ready.wait_for(|r| *r).await.is_ok() {
                h(c).await;
            }
        }
    })
}

async fn announce(g: &Global, key: &KeyArg, conn_str: &Addr) -> Result<()> {
    if *key == KeyArg::New {
        eprintln!("# 🐈 Server listening with new address: {conn_str}");
    } else {
        eprintln!("# 🐈 Server listening with saved key {:?}: {conn_str}", key.to_string());
    }
    if g.json {
        println!("{}", serde_json::json!({ "listenAddr": conn_str.as_str() }));
    }
    match std::env::var("TAILCAT_ADDR_FILE") {
        Ok(v) if v.is_empty() => {}
        Ok(v) => match v.strip_prefix("tcp:") {
            Some(tcp) => {
                let mut c = tokio::net::TcpStream::connect(tcp)
                    .await
                    .map_err(|e| anyhow!("TAILCAT_ADDR_FILE tcp dial {tcp:?}: {e}"))?;
                c.write_all(format!("{conn_str}\n").as_bytes()).await?;
                c.shutdown().await?;
            }
            None => crate::util::replace_private(&v, conn_str.as_str().as_bytes())
                .map_err(|e| anyhow!("TAILCAT_ADDR_FILE: writing {v:?}: {e}"))?,
        },
        Err(_) => {}
    }
    Ok(())
}

/// The accept-one-connection mode: copy it to stdout and exit.
async fn one_shot(me: Arc<OnceLock<Server>>, mut c: TcpStream) {
    let mut out = tokio::io::stdout();
    if let Err(e) = tokio::io::copy(&mut c, &mut out).await {
        // Keep what did arrive.
        let _ = out.flush().await;
        eprintln!("{e}");
        std::process::exit(1);
    }
    let _ = out.flush().await;
    drop(out);
    // Close stdout so a downstream pipeline sees EOF now.
    close_stdout();
    let _ = c.shutdown().await;
    drop(c);
    // The client exits once it reads our EOF, which confirms delivery of
    // what it sent. The TCP stack is in this process, so wait for the
    // client to ack our FIN before exiting.
    if let Some(s) = me.get() {
        s.drain_tcp(Duration::from_secs(5)).await;
    }
    std::process::exit(0);
}

/// Closes this process's stdout.
#[cfg(unix)]
fn close_stdout() {
    unsafe {
        libc::close(1);
    }
}

/// Does nothing: stdout stays open until exit here.
#[cfg(not(unix))]
fn close_stdout() {}

/// Finds an executable in $PATH, like Go's exec.LookPath.
pub fn which(name: &str) -> Option<String> {
    if name.contains('/') {
        return std::path::Path::new(name).exists().then(|| name.to_string());
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(name);
        if is_executable(&p) {
            return Some(p.to_string_lossy().into_owned());
        }
        if let Some(p) = exe_in(&dir, name) {
            return Some(p.to_string_lossy().into_owned());
        }
    }
    None
}

/// `name` with the `.exe` extension in `dir`, if it exists.
#[cfg(windows)]
fn exe_in(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    let p = dir.join(format!("{name}.exe"));
    p.exists().then_some(p)
}

/// None: executables don't need an extension here.
#[cfg(not(windows))]
fn exe_in(_: &std::path::Path, _: &str) -> Option<std::path::PathBuf> {
    None
}

/// Reports whether `p` is a file with any execute bit set.
#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Reports whether `p` is a file: there are no execute bits here.
#[cfg(not(unix))]
fn is_executable(p: &std::path::Path) -> bool {
    p.is_file()
}

/// The file service --files asks for, once its directory checks out.
#[cfg(feature = "ssh")]
pub fn file_service(a: &FilesArg) -> Result<tailcat::ssh::FileService> {
    let abs = std::path::absolute(&a.dir)?;
    let md = std::fs::metadata(&abs).map_err(|e| anyhow!("--files: {}: {e}", abs.display()))?;
    if !md.is_dir() {
        return Err(crate::usagef!("--files: {} is not a directory", abs.display()));
    }
    Ok(tailcat::ssh::FileService { dir: abs, mode: a.mode.into() })
}

#[cfg(test)]
mod tests {
    use tailcat::Client;
    use tailcat::derp::server::DevDerp;
    use tokio::io::AsyncReadExt;
    use tokio::sync::watch;
    use tokio::time::{sleep, timeout};

    use super::*;

    #[test]
    fn port_sets() {
        let ps = parse_port_set("22, 80,8000-8002,exec").unwrap();
        assert_eq!(ps.ports, BTreeSet::from([22, 80, 8000, 8001, 8002]));
        assert!(ps.services.contains(&Service::Exec));

        let ps = parse_port_set("5555:10.2.200.213:5555,8080:80,9:[fd7a::1]:22").unwrap();
        assert_eq!(ps.targets[&5555], "10.2.200.213:5555");
        assert_eq!(ps.targets[&8080], "localhost:80");
        assert_eq!(ps.targets[&9], "[fd7a::1]:22");

        assert!(parse_port_set("all").unwrap().contains(443));
        assert_eq!(parse_port_set("9-7").unwrap().ports.len(), 3);
        assert!(parse_port_set("").unwrap().is_empty());
        for bad in ["bogus", "0:80", "80:host", "80:1,80:2"] {
            assert!(parse_port_set(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn port_set_edges() {
        // "all" admits every port but 0, and isn't a service.
        let ps = parse_port_set(" all , perf ").unwrap();
        assert!(ps.all);
        assert!(!ps.contains(0));
        assert!(ps.contains(65535));
        assert_eq!(ps.services, BTreeSet::from([Service::Perf]));
        assert_eq!(ps.tcp_ranges([22]), [PortRange::new(1, 65535)]);
        let ps = parse_port_set("80,81").unwrap();
        assert_eq!(ps.tcp_ranges([22, 82, 22]), [PortRange::single(22), PortRange::new(80, 82)]);
        // SSH services need SSH support.
        assert_eq!(parse_port_set("files").is_ok(), cfg!(feature = "ssh"));

        let ps = parse_port_set("exec,exit-node").unwrap();
        assert!(ps.is_empty());
        assert_eq!(ps.services.len(), 2);

        // Specs merge as one listing both would.
        let mut merged = parse_port_set("22,80:8080").unwrap();
        merged.merge(parse_port_set("perf,80:8080,443").unwrap()).unwrap();
        assert_eq!(merged, parse_port_set("22,80:8080,perf,443").unwrap());
        assert!(merged.merge(parse_port_set("80:9090").unwrap()).is_err(), "80 mapped twice");

        // The same mapping twice is fine; mapping a port also serves it.
        let ps = parse_port_set("80:8080,80:8080").unwrap();
        assert_eq!(ps.targets.len(), 1);
        assert!(ps.contains(80));

        for bad in ["65536", "1-65536", "80-", "-80", "a-b", "80:host:0", "80::22", "80:[::1]"] {
            assert!(parse_port_set(bad).is_err(), "{bad:?} parsed");
        }
    }

    /// A handler that notes in `ran` that it ran, then answers "ok".
    fn answer_ok(ran: Arc<AtomicBool>) -> TcpHandler {
        handler(move |mut c: TcpStream| {
            ran.store(true, Ordering::Relaxed);
            async move {
                let _ = c.write_all(b"ok").await;
                let _ = c.shutdown().await;
                c.drain(Duration::from_secs(5)).await;
            }
        })
    }

    /// A connection that arrives before the server is ready waits for it
    /// instead of reaching a handler whose server cells are still empty.
    #[tokio::test]
    async fn handlers_wait_for_start() {
        let dev = DevDerp::start_local().await.unwrap();
        let (ready_tx, ready) = watch::channel(false);
        let ran = Arc::new(AtomicBool::new(false));
        let h = after_start(ready, answer_ok(ran.clone()));
        let s = Server::builder().region(dev.region.clone()).on_tcp(move |_| Some(h.clone())).start().await.unwrap();
        let cl = Client::new(s.tailcat_addr());
        let mut c = timeout(Duration::from_secs(15), cl.dial_tcp_port(1)).await.expect("dial timed out").unwrap();

        sleep(Duration::from_millis(200)).await;
        assert!(!ran.load(Ordering::Relaxed), "the handler ran before the server was ready");

        ready_tx.send_replace(true);
        let mut got = String::new();
        timeout(Duration::from_secs(10), c.read_to_string(&mut got)).await.expect("read timed out").unwrap();
        assert_eq!(got, "ok");
    }

    #[test]
    fn finds_no_missing_executables() {
        assert!(which("definitely-not-a-tailcat-command").is_none());
        assert!(which("/definitely/not/a/path").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn finds_executables() {
        assert!(which("sh").is_some_and(|p| p.ends_with("/sh")));
        assert_eq!(which("/bin/sh").as_deref(), Some("/bin/sh"));
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn files_flags() {
        use std::{env, fs};

        use tailcat::ssh::FileServeMode as M;

        let service = |s: &str| file_service(&s.parse().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let svc = service(&format!("{}:wo+", dir.path().display())).unwrap();
        assert_eq!((svc.dir.as_path(), svc.mode), (dir.path(), M::WriteOnlyTree));
        assert_eq!(service(":rw").unwrap().dir, env::current_dir().unwrap());

        let file = dir.path().join("f");
        fs::write(&file, "").unwrap();
        let e = service(file.to_str().unwrap()).unwrap_err();
        assert!(e.is::<crate::UsageError>());

        let missing = dir.path().join("missing");
        assert!(service(missing.to_str().unwrap()).is_err());
    }
}
