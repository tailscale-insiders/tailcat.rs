//! Server mode: `tailcat`, `tailcat serve`, `tailcat recv`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tailcat::{
    Addr, ConnInfo, DerpRegion, FetchMode, FetchOptions, KeySet, NodePublic, PortRange, PresharedKey, PrivateKey, Server,
    TcpStream, UdpConn, handler, udp_handler,
};
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::cache::DiskDerpMapCache;
use crate::{Global, ServeFlags, usagef};

/// The services `serve` knows by name.
const SERVICES: &[&str] = &["all", "ssh", "no-auth-ssh", "files", "exec", "exit-node", "perf"];

/// A parsed serve spec.
#[derive(Debug, Default, PartialEq)]
pub struct PortSet {
    pub all: bool,
    pub ports: BTreeSet<u16>,
    pub services: BTreeSet<String>,
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

    fn sorted_ports(&self) -> Vec<u16> {
        if self.all { (1..=65535).collect() } else { self.ports.iter().copied().collect() }
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
    for r in s.split(',') {
        let r = r.trim();
        match r {
            "all" => {
                ps.all = true;
                continue;
            }
            "ssh" | "no-auth-ssh" | "files" if !cfg!(feature = "ssh") => {
                bail!("SSH support not included in this build");
            }
            "ssh" | "no-auth-ssh" | "files" | "exit-node" | "exec" | "perf" => {
                ps.services.insert(r.to_string());
                continue;
            }
            _ => {}
        }
        if let Some((port, target)) = r.split_once(':') {
            let (port, target) = parse_port_target(port, target)?;
            if let Some(prev) = ps.targets.get(&port) {
                if *prev != target {
                    bail!("port {port} is mapped to both {prev} and {target}");
                }
            }
            ps.ports.insert(port);
            ps.targets.insert(port, target);
            continue;
        }
        let (a, b) = match r.split_once('-') {
            Some((a, b)) if is_num(a) && is_num(b) => (a, b),
            _ if is_num(r) => (r, r),
            _ => bail!("{r:?} is not a known named service (want one of: {})", SERVICES.join(", ")),
        };
        let lo: u16 = a.parse().map_err(|_| anyhow!("{a:?} is not a valid port"))?;
        let hi: u16 = b.parse().map_err(|_| anyhow!("{b:?} is not a valid port number"))?;
        let (lo, hi) = if hi < lo { (hi, lo) } else { (lo, hi) };
        ps.ports.extend(lo..=hi);
    }
    Ok(ps)
}

/// Parses the halves of a "port:target" mapping.
pub fn parse_port_target(port: &str, target: &str) -> Result<(u16, String)> {
    let mapping = format!("{port}:{target}");
    let p: u16 = port.parse().ok().filter(|p| *p != 0).ok_or_else(|| anyhow!("{port:?} is not a valid port in mapping {mapping:?}"))?;
    if is_num(target) {
        let _: u16 = target.parse().map_err(|_| anyhow!("{target:?} is not a valid port in mapping {mapping:?}"))?;
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
    r.region_code.clear();
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
    let bind: SocketAddr = if dst.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            debug!("error proxying to {dst}: {e}");
            return;
        }
    };
    if let Err(e) = sock.connect(dst).await {
        debug!("error proxying to {dst}: {e}");
        return;
    }
    tailcat::proxy_packet_conns(&c, &sock, tailcat::DEFAULT_UDP_IDLE_TIMEOUT).await;
}

/// Runs a server until killed.
pub async fn server(g: &Global, flags: &ServeFlags, spec: String, exec_args: Option<Vec<String>>) -> Result<()> {
    let ps = parse_port_set(&spec).map_err(|e| anyhow!("invalid port or service to serve: {e}"))?;
    let mut services = ps.services.clone();
    let exec_args = match exec_args {
        Some(a) if a.is_empty() => bail!("no command given after --"),
        Some(mut a) => {
            let exe = which(&a[0]).with_context(|| format!("exec command: {:?} not found", a[0]))?;
            a[0] = exe;
            if !services.contains("ssh") && !services.contains("no-auth-ssh") {
                services.insert("exec".into());
            }
            Some(a)
        }
        None => {
            if services.contains("exec") {
                bail!("the 'exec' service requires a command after --");
            }
            None
        }
    };
    if flags.files.is_some() {
        if !cfg!(feature = "ssh") {
            bail!("--files requires SSH support, not included in this build");
        }
        services.insert("files".into());
    }
    let serve_perf = services.contains("perf");
    if serve_perf && ps.contains(crate::perf::PORT) {
        bail!("port {} is used by the 'perf' service and cannot also be proxied", crate::perf::PORT);
    }
    let ssh_auth = services.contains("ssh");
    let ssh_noauth = services.contains("no-auth-ssh");
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
    if (ssh_auth || ssh_noauth) && exec_args.is_some() && services.contains("files") {
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

    // Which key.
    let key_name = match g.key.as_deref() {
        None | Some("") => {
            if crate::keys::key_path("default")?.exists() { "default".to_string() } else { "new".to_string() }
        }
        Some(k) => k.to_string(),
    };
    let (private, mut ci) = if key_name == "new" {
        let k = PrivateKey::generate();
        let mut ci = k.public.clone();
        ci.region_id = -1;
        (k.private, ci)
    } else {
        let k = crate::keys::load(&key_name)?;
        (k.private, k.public)
    };
    let mut use_psk = flags.psk.unwrap_or(true);
    if key_name != "new" && ci.preshared_key.is_zero() && flags.psk.is_none() {
        // Saved keys remember whether they use a PSK.
        use_psk = false;
    }
    if use_psk && ci.preshared_key.is_zero() {
        bail!("key file {} has no WireGuard pre-shared key", crate::keys::key_path(&key_name)?.display());
    }
    if !use_psk {
        ci.preshared_key = PresharedKey::default();
    }
    let psk = ci.preshared_key;

    let (region, print_ci) = match &dev_derp {
        Some(d) => {
            let ci = ConnInfo { preshared_key: psk, region: vec![d.region.clone()], ..Default::default() };
            (d.region.clone(), ci)
        }
        None => {
            // A key with custom DERP hostnames has regions with no map ID,
            // so its address always embeds them.
            let embed = flags.full_address || !ci.region.is_empty();
            let cache = DiskDerpMapCache;
            ci.expand(FetchOptions { url: Some(&g.derpmap_url), mode: FetchMode::Server, cache: Some(&cache) }, None)
                .await
                .map_err(|e| anyhow!("Expand: {e}"))?;
            let mut reg = ci.region[0].clone();
            clear_unnecessary_region_fields(&mut reg);
            eprintln!("# Selected bootstrap relay region {}, {}", reg.region_id, reg.region_name);
            let print = if embed {
                ConnInfo { preshared_key: psk, region: vec![reg.clone()], ..Default::default() }
            } else {
                ConnInfo { preshared_key: psk, region_id: reg.region_id, ..Default::default() }
            };
            (reg, print)
        }
    };
    let print_ci = ConnInfo {
        server_public: private.public(),
        server_disco_public: private.disco_private().public(),
        ..print_ci
    };
    let conn_str = print_ci.addr();

    let mut b = Server::builder().key(private.clone()).preshared_key(psk).disable_preshared_key(!use_psk).region(region);

    let ssh_services = services.contains("ssh") || services.contains("no-auth-ssh") || services.contains("files");
    // Outside the accept-one-connection mode (and exit-node and exec,
    // which accept any port), admit only the served ports.
    if !one_shot_stdout && !services.contains("exit-node") && !services.contains("exec") {
        let mut ports = ps.sorted_ports();
        if ssh_services && !ps.contains(22) {
            ports.insert(0, 22);
        }
        if serve_perf {
            ports.push(crate::perf::PORT);
            ports.sort();
        }
        b = b.served_tcp_ports(PortRange::coalesce(&ports));
    }
    if serve_perf {
        b = b.served_udp_ports(vec![PortRange::single(crate::perf::PORT)]);
    }
    if let Some(allow) = &flags.allow {
        let set = KeySet::default();
        for ks in allow.split(',') {
            if ks == "none" {
                continue; // an empty set allows no clients
            }
            let k: NodePublic = ks.parse().map_err(|e| anyhow!("invalid key {ks:?} in --allow: {e}"))?;
            set.add(k);
        }
        b = b.allow_client(set.checker());
    }
    if services.contains("exit-node") {
        b = b
            .on_tcp_forward(|dst| Some(handler(move |c| proxy_to_local(dst.to_string(), c))))
            .on_udp_forward(|dst| Some(udp_handler(move |c| udp_forward_to(dst, c))));
    }

    // Handlers that need the server itself (for peer identity, draining)
    // get it through this cell, filled in after start.
    let me: Arc<OnceLock<Server>> = Arc::new(OnceLock::new());

    #[cfg(feature = "ssh")]
    let ssh_handler = if ssh_services {
        let mut opts = tailcat::ssh::SshOptions {
            shell: services.contains("ssh") || services.contains("no-auth-ssh"),
            authorized_keys,
            ..Default::default()
        };
        if opts.shell {
            if let Some(a) = &exec_args {
                opts.exec = a.clone();
                eprintln!("# SSH sessions run only {}", a.join(" "));
            }
        }
        if services.contains("files") {
            let (fs, mode_name) = parse_files_flag(flags.files.as_deref().unwrap_or(""))?;
            eprintln!("# Serving files from {} ({mode_name})", fs.dir.display());
            opts.files = Some(fs);
        }
        Some(tailcat::ssh::conn_handler(me.clone(), opts)?)
    } else {
        None
    };
    #[cfg(not(feature = "ssh"))]
    let ssh_handler: Option<tailcat::TcpHandler> = {
        if ssh_services {
            bail!("SSH server not supported in this build");
        }
        None
    };

    let perf_srv = if serve_perf {
        let p = Arc::new(crate::perf::Server::new());
        let pu = p.clone();
        b = b.on_udp(move |port| {
            if port != crate::perf::PORT {
                return None;
            }
            let pu = pu.clone();
            Some(udp_handler(move |c| {
                let pu = pu.clone();
                async move { pu.handle_udp(c).await }
            }))
        });
        eprintln!("# Accepting perf tests on TCP and UDP port {}", crate::perf::PORT);
        Some(p)
    } else {
        None
    };

    let exec_handler = match (&exec_args, services.contains("exec")) {
        (Some(a), true) => {
            eprintln!("# Running {} for each connection", a.join(" "));
            Some(a.clone())
        }
        _ => None,
    };
    for (port, t) in &ps.targets {
        eprintln!("# Proxying port {port} to {t}");
    }

    let exit_node = services.contains("exit-node");
    let ps = Arc::new(ps);
    let me2 = me.clone();
    let exec_h: Arc<OnceLock<tailcat::TcpHandler>> = Arc::new(OnceLock::new());
    let exec_h2 = exec_h.clone();
    b = b.on_tcp(move |port| {
        if port == 22 {
            if let Some(h) = &ssh_handler {
                return Some(h.clone());
            }
        }
        if port == crate::perf::PORT {
            if let Some(p) = &perf_srv {
                let p = p.clone();
                return Some(handler(move |c| {
                    let p = p.clone();
                    async move { p.handle_tcp(c).await }
                }));
            }
        }
        if ps.contains(port) {
            let t = ps.targets.get(&port).cloned().unwrap_or_else(|| format!("localhost:{port}"));
            return Some(handler(move |c| proxy_to_local(t.clone(), c)));
        }
        if let Some(h) = exec_h2.get() {
            return Some(h.clone());
        }
        if exit_node {
            // Being an exit node includes localhost's ports too.
            return Some(handler(move |c| proxy_to_local(format!("localhost:{port}"), c)));
        }
        if one_shot_stdout {
            let me = me2.clone();
            return Some(handler(move |c| one_shot(me.clone(), c)));
        }
        None
    });

    let s = b.start().await.map_err(|e| anyhow!("Server.Start: {e}"))?;
    let _ = me.set(s.clone());
    if let Some(a) = exec_handler {
        let _ = exec_h.set(s.exec_conn_handler(a));
    }
    if psk.is_zero() {
        if key_name == "new" {
            eprintln!("# ⚠️ WARNING: serving without a WireGuard PSK");
        } else {
            eprintln!("# ⚠️ WARNING: saved key {key_name:?} is not using a WireGuard PSK");
        }
    }
    if ssh_noauth && flags.allow.is_none() {
        if exec_args.is_some() {
            eprintln!("# ⚠️ WARNING: no-auth-ssh runs the command for anyone with this address; keep it secret (never in a DNS TXT record) or restrict clients with --allow");
        } else {
            eprintln!("# ⚠️ WARNING: no-auth-ssh gives a shell to anyone with this address; keep it secret (never in a DNS TXT record) or restrict clients with --allow");
        }
    }
    if let Some(d) = &dev_derp {
        if !d.wait_for_client(&private.public(), Duration::from_secs(30)).await {
            bail!("timeout waiting for connection to local dev DERP");
        }
    }
    announce(g, &key_name, &conn_str).await?;

    if std::env::var("TAILCAT_STATUS_LOOP").as_deref() == Ok("1") {
        let s2 = s.clone();
        tokio::spawn(async move {
            loop {
                eprintln!("status = {:?}", s2.status());
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }
    let _keep = dev_derp;
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn announce(g: &Global, key_name: &str, conn_str: &Addr) -> Result<()> {
    if key_name == "new" {
        eprintln!("# 🐈 Server listening with new address: {conn_str}");
    } else {
        eprintln!("# 🐈 Server listening with saved key {key_name:?}: {conn_str}");
    }
    if g.json {
        println!("{}", serde_json::json!({ "listenAddr": conn_str.as_str() }));
    }
    if let Ok(v) = std::env::var("TAILCAT_ADDR_FILE") {
        if !v.is_empty() {
            if let Some(tcp) = v.strip_prefix("tcp:") {
                let mut c = tokio::net::TcpStream::connect(tcp).await.map_err(|e| anyhow!("TAILCAT_ADDR_FILE tcp dial {tcp:?}: {e}"))?;
                c.write_all(format!("{conn_str}\n").as_bytes()).await?;
                c.shutdown().await?;
            } else {
                write_private(&v, conn_str.as_str().as_bytes())?;
            }
        }
    }
    Ok(())
}

fn write_private(path: &str, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
        Ok(())
    }
}

/// The accept-one-connection mode: copy it to stdout and exit.
async fn one_shot(me: Arc<OnceLock<Server>>, mut c: TcpStream) {
    let mut out = tokio::io::stdout();
    if let Err(e) = tokio::io::copy(&mut c, &mut out).await {
        eprintln!("{e}");
        std::process::exit(1);
    }
    let _ = out.flush().await;
    drop(out);
    // Close stdout so a downstream pipeline sees EOF now.
    #[cfg(unix)]
    unsafe {
        libc::close(1);
    }
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
        #[cfg(windows)]
        {
            let p = dir.join(format!("{name}.exe"));
            if p.exists() {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn is_executable(p: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// Parses --files: a directory with an optional :ro, :rw, :wo or :wo+ suffix.
#[cfg(feature = "ssh")]
pub fn parse_files_flag(v: &str) -> Result<(tailcat::ssh::FileService, &'static str)> {
    use tailcat::ssh::FileServeMode as M;
    let (dir, mode, name) = if let Some(d) = v.strip_suffix(":ro") {
        (d, M::ReadOnly, "read-only")
    } else if let Some(d) = v.strip_suffix(":rw") {
        (d, M::ReadWrite, "read-write")
    } else if let Some(d) = v.strip_suffix(":wo+") {
        (d, M::WriteOnlyTree, "recursive write-only")
    } else if let Some(d) = v.strip_suffix(":wo") {
        (d, M::WriteOnly, "flat write-only")
    } else {
        (v, M::ReadOnly, "read-only")
    };
    let dir = if dir.is_empty() { "." } else { dir };
    let abs = std::path::absolute(dir)?;
    let md = std::fs::metadata(&abs).map_err(|e| anyhow!("--files: {}: {e}", abs.display()))?;
    if !md.is_dir() {
        return Err(usagef!("--files: {} is not a directory", abs.display()));
    }
    Ok((tailcat::ssh::FileService { dir: abs, mode }, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_sets() {
        let ps = parse_port_set("22, 80,8000-8002,ssh").unwrap();
        assert_eq!(ps.ports.iter().copied().collect::<Vec<_>>(), vec![22, 80, 8000, 8001, 8002]);
        assert!(ps.services.contains("ssh"));
        let ps = parse_port_set("5555:10.2.200.213:5555,8080:80,9:[fd7a::1]:22").unwrap();
        assert_eq!(ps.targets[&5555], "10.2.200.213:5555");
        assert_eq!(ps.targets[&8080], "localhost:80");
        assert_eq!(ps.targets[&9], "[fd7a::1]:22");
        assert!(parse_port_set("bogus").is_err());
        assert!(parse_port_set("0:80").is_err());
        assert!(parse_port_set("80:host").is_err());
        assert!(parse_port_set("80:1,80:2").is_err());
        assert!(parse_port_set("all").unwrap().contains(443));
        assert_eq!(parse_port_set("9-7").unwrap().ports.len(), 3);
        assert!(parse_port_set("").unwrap().is_empty());
    }
}
