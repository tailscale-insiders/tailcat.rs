//! `tailcat ssh`, `tailcat cp`, `tailcat ls`, and loading the `ssh`
//! service's authorized keys.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::{Global, usagef};

const MAX_AUTHORIZED_KEYS_SIZE: usize = 1 << 20;

fn valid_github_user(u: &str) -> bool {
    let b = u.as_bytes();
    !b.is_empty()
        && b.len() <= 39
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

fn looks_like_ssh_public_key(s: &str) -> bool {
    let first = s.split_whitespace().next().unwrap_or("");
    first.starts_with("ssh-") || first.starts_with("ecdsa-") || first.starts_with("sk-")
}

/// Resolves a comma-separated list of authorized-key sources: literal
/// public key lines, authorized_keys files, or `user@github`.
pub async fn load_authorized_keys(list: &str) -> Result<Vec<String>> {
    let mut texts = Vec::new();
    for (i, source) in list.split(',').enumerate() {
        let n = i + 1;
        let source = source.trim();
        if source.is_empty() {
            bail!("source {n} is empty");
        }
        let text = if let Some(user) = source.strip_suffix("@github") {
            if !valid_github_user(user) {
                bail!("source {n}: invalid GitHub username {user:?}");
            }
            fetch_github_keys(user).await.map_err(|e| anyhow!("source {n} ({source}): {e}"))?
        } else {
            match read_limited(source) {
                Ok(t) => t,
                Err(file_err) => {
                    if tailcat::ssh::validate_authorized_keys(&[source.to_string()]).is_ok() {
                        source.to_string()
                    } else if looks_like_ssh_public_key(source) {
                        let e = tailcat::ssh::validate_authorized_keys(&[source.to_string()]).unwrap_err();
                        bail!("source {n}: invalid SSH public key: {e}");
                    } else {
                        bail!("source {n}: reading {source:?}: {file_err}");
                    }
                }
            }
        };
        tailcat::ssh::validate_authorized_keys(std::slice::from_ref(&text))
            .map_err(|e| anyhow!("source {n} ({source}): {e}"))?;
        texts.push(text);
    }
    tailcat::ssh::validate_authorized_keys(&texts)?;
    Ok(texts)
}

fn read_limited(path: &str) -> std::io::Result<String> {
    let b = std::fs::read(path)?;
    if b.len() > MAX_AUTHORIZED_KEYS_SIZE {
        return Err(std::io::Error::other(format!("file is larger than {MAX_AUTHORIZED_KEYS_SIZE} bytes")));
    }
    Ok(String::from_utf8_lossy(&b).into_owned())
}

async fn fetch_github_keys(user: &str) -> Result<String> {
    let res = tailcat::shared_client()
        .get(format!("https://github.com/{user}.keys"))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| anyhow!("fetching GitHub keys: {e}"))?;
    if !res.status().is_success() {
        bail!("fetching GitHub keys: {}", res.status());
    }
    let b = res.bytes().await.map_err(|e| anyhow!("reading GitHub keys: {e}"))?;
    if b.len() > MAX_AUTHORIZED_KEYS_SIZE {
        bail!("GitHub key list is larger than {MAX_AUTHORIZED_KEYS_SIZE} bytes");
    }
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Validates the -p value: a port, an IP (meaning port 22), or IP:port.
fn validated_ssh_port(v: &str) -> Result<String> {
    if let Ok(p) = v.parse::<u16>()
        && p != 0
    {
        return Ok(p.to_string());
    }
    if let Ok(ip) = v.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 22).to_string());
    }
    if let Ok(a) = v.parse::<SocketAddr>()
        && a.port() != 0
    {
        return Ok(a.to_string());
    }
    Err(usagef!("invalid port or IP:port {v:?}"))
}

/// A short, deterministic ssh destination name for an address: the real
/// address rides in the ProxyCommand, and long names overflow
/// ControlPath socket paths.
fn ssh_dest_host(addr: &str) -> String {
    let sum = Sha256::digest(addr.as_bytes());
    format!("tailcat-{}", hex::encode(&sum[..8]))
}

/// Quotes arguments for the POSIX shell that runs a ProxyCommand;
/// percent signs are doubled for OpenSSH's own token expansion.
fn proxy_command_join_unix(args: &[String]) -> Result<String> {
    let mut out = Vec::new();
    for a in args {
        if a.contains(['\r', '\n', '\0']) {
            bail!("ProxyCommand argument contains a control character: {a:?}");
        }
        let a = a.replace('%', "%%");
        out.push(format!("'{}'", a.replace('\'', "'\"'\"'")));
    }
    Ok(out.join(" "))
}

fn proxy_command_join_windows(args: &[String]) -> Result<String> {
    let mut out = Vec::new();
    for a in args {
        if a.contains(['"', '%', '!', '\r', '\n', '\0']) {
            bail!("ProxyCommand argument contains a character unsafe for cmd.exe: {a:?}");
        }
        let trailing = a.len() - a.trim_end_matches('\\').len();
        out.push(format!("\"{a}{}\"", "\\".repeat(trailing)));
    }
    Ok(out.join(" "))
}

fn ssh_proxy_command(g: &Global, addr: &str, port: &str) -> Result<String> {
    let exe = std::env::current_exe()?.to_string_lossy().into_owned();
    let mut args = vec![exe];
    if let Some(k) = g.key.as_deref().filter(|k| !k.is_empty()) {
        args.push(format!("--key={k}"));
    }
    if g.derpmap_url != tailcat::DEFAULT_DERP_MAP_URL {
        args.push(format!("--derpmap-url={}", g.derpmap_url));
    }
    args.push(addr.to_string());
    args.push(port.to_string());
    if cfg!(windows) { proxy_command_join_windows(&args) } else { proxy_command_join_unix(&args) }
}

fn exec_replace(argv: Vec<String>) -> Result<ExitCode> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&argv[0]).args(&argv[1..]).exec();
        bail!("failed to run {}: {err}", argv[0]);
    }
    #[cfg(not(unix))]
    {
        let st = std::process::Command::new(&argv[0]).args(&argv[1..]).status()?;
        Ok(ExitCode::from(st.code().unwrap_or(1) as u8))
    }
}

const SSH_OPTS: [&str; 8] = [
    "-o",
    "UpdateHostKeys no",
    "-o",
    "StrictHostKeyChecking no",
    "-o",
    "LogLevel ERROR",
    "-o",
    "UserKnownHostsFile /dev/null",
];

fn ssh_opts() -> Vec<String> {
    let mut v: Vec<String> = SSH_OPTS.iter().map(|s| s.to_string()).collect();
    if cfg!(windows) {
        v[7] = "UserKnownHostsFile NUL".into();
    }
    v
}

pub async fn ssh_mode(g: &Global, port: &str, skip_dns_check: bool, args: Vec<String>) -> Result<ExitCode> {
    let port = validated_ssh_port(port)?;
    let dst = &args[0];
    let (user, addr_str) = match dst.split_once('@') {
        Some((u, a)) => (Some(u.to_string()), a.to_string()),
        None => (None, dst.clone()),
    };
    let (addr, via_dns) = crate::addrarg::validated_addr(&addr_str).await?;
    if via_dns && !skip_dns_check {
        refuse_wide_open_dns(g, &addr_str, &addr, &port, user.as_deref()).await;
    }
    let ssh = crate::serve::which("ssh").ok_or_else(|| anyhow!("no ssh client found in $PATH"))?;
    let mut host = ssh_dest_host(addr.as_str());
    if let Some(u) = &user {
        host = format!("{u}@{host}");
    }
    let mut argv = vec![ssh];
    argv.extend(ssh_opts());
    argv.push("-o".into());
    argv.push(format!("ProxyCommand={}", ssh_proxy_command(g, addr.as_str(), &port)?));
    argv.push("--".into());
    argv.push(host);
    argv.extend(args[1..].iter().cloned());
    exec_replace(argv)
}

/// Splits an scp-style "host:path"; a one-character host or one with a
/// path separator stays local (a Windows drive, a relative path).
fn split_remote_arg(arg: &str) -> Option<(&str, &str)> {
    let i = arg.find(':')?;
    if i <= 1 || arg[..i].contains(['/', '\\']) {
        return None;
    }
    Some((&arg[..i], &arg[i + 1..]))
}

fn scp_supports_sftp_flag(scp: &str) -> bool {
    let out = std::process::Command::new(scp).args(["-s", "--"]).output();
    let msg = match out {
        Ok(o) => String::from_utf8_lossy(&[o.stdout, o.stderr].concat()).to_lowercase(),
        Err(_) => return false,
    };
    !msg.contains("unknown option -- s") && !msg.contains("illegal option -- s") && !msg.contains("invalid option -- s")
}

pub async fn cp_mode(g: &Global, recursive: bool, preserve: bool, port: &str, args: Vec<String>) -> Result<ExitCode> {
    if args.len() < 2 {
        return Err(usagef!("cp requires at least one source and a target"));
    }
    let port = validated_ssh_port(port)?;
    let mut addr: Option<String> = None;
    for a in &args {
        if let Some((host, _)) = split_remote_arg(a) {
            if let Some(prev) = &addr
                && prev != host
            {
                return Err(usagef!("all remote paths must name the same server ({prev:?} and {host:?} differ)"));
            }
            addr = Some(host.to_string());
        }
    }
    let Some(addr) = addr else {
        return Err(usagef!("no remote <tc-addr>:path argument; nothing to copy through tailcat"));
    };
    let (addr, _) = crate::addrarg::validated_addr(&addr).await?;
    let label = ssh_dest_host(addr.as_str());
    let scp_args: Vec<String> = args
        .iter()
        .map(|a| match split_remote_arg(a) {
            Some((_, path)) => format!("{label}:{path}"),
            None => a.clone(),
        })
        .collect();
    let scp = crate::serve::which("scp").ok_or_else(|| anyhow!("no scp found in $PATH"))?;
    let mut argv = vec![scp.clone()];
    if scp_supports_sftp_flag(&scp) {
        argv.push("-s".into());
    }
    argv.extend(ssh_opts());
    argv.push("-o".into());
    argv.push(format!("ProxyCommand={}", ssh_proxy_command(g, addr.as_str(), &port)?));
    if recursive {
        argv.push("-r".into());
    }
    if preserve {
        argv.push("-p".into());
    }
    argv.push("--".into());
    argv.extend(scp_args);
    exec_replace(argv)
}

struct AcceptAny;

impl russh::client::Handler for AcceptAny {
    type Error = russh::Error;
    // The WireGuard tunnel already authenticated the server by its node
    // key, so the SSH host key adds nothing.
    async fn check_server_key(&mut self, _: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn local_username() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "tailcat".into())
}

async fn dial(cl: &tailcat::Client, port: &str) -> Result<tailcat::TcpStream> {
    match port.parse::<SocketAddr>() {
        Ok(a) => Ok(cl.dial_tcp(a).await?),
        Err(_) => Ok(cl.dial_tcp_port(port.parse().map_err(|_| anyhow!("invalid port {port:?}"))?).await?),
    }
}

/// Reports whether the server at `addr` lets a stranger (a fresh node
/// key, no SSH credentials) log in.
async fn probe_stranger_ssh(g: &Global, addr: &tailcat::Addr, port: &str, user: Option<&str>) -> Result<bool> {
    let cl = crate::client::new_client(g, addr.clone(), tailcat::NodePrivate::generate());
    let conn = dial(&cl, port).await?;
    let cfg = Arc::new(russh::client::Config::default());
    let mut h = match russh::client::connect_stream(cfg, conn, AcceptAny).await {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    let user = user.map(String::from).unwrap_or_else(local_username);
    let open = matches!(h.authenticate_none(user).await, Ok(r) if r.success());
    let _ = h.disconnect(russh::Disconnect::ByApplication, "", "").await;
    Ok(open)
}

async fn refuse_wide_open_dns(g: &Global, dns_name: &str, addr: &tailcat::Addr, port: &str, user: Option<&str>) {
    let r = tokio::time::timeout(Duration::from_secs(10), probe_stranger_ssh(g, addr, port, user)).await;
    let open = match r {
        Ok(Ok(open)) => open,
        Ok(Err(e)) => {
            tracing::debug!("stranger probe of {dns_name} did not connect: {e}");
            false
        }
        Err(_) => false,
    };
    if !open {
        return;
    }
    eprintln!(
        r#"⚠️ WARNING: refusing to connect to {dns_name}: its SSH server is wide open.

The tailcat address in its DNS TXT record is public, and the server
accepted an SSH login from a freshly generated client key offering
no SSH credentials at all. Anyone on the internet who reads that DNS
record can get a shell.

If that's your server, stop running it now, and restart it only once
it requires client authentication:

  tailcat serve --allow=<client-nodekey> ...        (tunnel layer)
  tailcat serve --ssh-authorized-keys=<keys> ssh    (SSH layer)

Or, to connect anyway, re-run with --skip-dns-safety-check."#
    );
    std::process::exit(1);
}

pub async fn ls_mode(g: &Global, long: bool, target: &str) -> Result<ExitCode> {
    let (host, path) = match split_remote_arg(target) {
        Some((h, p)) => (h.to_string(), if p.is_empty() { ".".to_string() } else { p.to_string() }),
        None => (target.to_string(), ".".to_string()),
    };
    let addr = crate::addrarg::tailcat_addr_arg(&host).await?;
    let cl = crate::client::new_client(g, addr, crate::keys::client_key(g)?);
    let conn = tokio::time::timeout(Duration::from_secs(30), cl.dial_tcp_port(22))
        .await
        .map_err(|_| anyhow!("dialing server: timed out"))?
        .map_err(|e| anyhow!("dialing server: {e}"))?;
    let mut h = russh::client::connect_stream(Arc::new(russh::client::Config::default()), conn, AcceptAny)
        .await
        .map_err(|e| anyhow!("SSH handshake: {e}"))?;
    let ok = h.authenticate_none(local_username()).await.map(|r| r.success()).unwrap_or(false);
    if !ok {
        bail!("SSH handshake: the server requires authentication");
    }
    let ch = h.channel_open_session().await.map_err(|e| anyhow!("opening SFTP session: {e}"))?;
    ch.request_subsystem(true, "sftp").await.map_err(|e| anyhow!("opening SFTP session: {e}"))?;
    let sf = russh_sftp::client::SftpSession::new(ch.into_stream())
        .await
        .map_err(|e| anyhow!("opening SFTP session: {e}"))?;
    let md = sf.metadata(path.clone()).await.map_err(|e| anyhow!("{path}: {e}"))?;
    if !md.is_dir() {
        print_entry(long, &md, path.trim_start_matches("./"));
        return Ok(ExitCode::SUCCESS);
    }
    let mut entries: Vec<(String, russh_sftp::protocol::FileAttributes)> = sf
        .read_dir(path.clone())
        .await
        .map_err(|e| anyhow!("{path}: {e}"))?
        .map(|e| (e.file_name(), e.metadata()))
        .collect();
    entries.retain(|(n, _)| n != "." && n != "..");
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, md) in entries {
        print_entry(long, &md, &name);
    }
    let _ = sf.close().await;
    Ok(ExitCode::SUCCESS)
}

fn print_entry(long: bool, md: &russh_sftp::protocol::FileAttributes, name: &str) {
    let name = if md.is_dir() { format!("{name}/") } else { name.to_string() };
    if !long {
        println!("{name}");
        return;
    }
    let mode = md.permissions.unwrap_or(0);
    let kind = if md.is_dir() {
        'd'
    } else if mode & 0o170000 == 0o120000 {
        'L'
    } else {
        '-'
    };
    let mut perms = String::new();
    for shift in [6, 3, 0] {
        let b = (mode >> shift) & 7;
        perms.push(if b & 4 != 0 { 'r' } else { '-' });
        perms.push(if b & 2 != 0 { 'w' } else { '-' });
        perms.push(if b & 1 != 0 { 'x' } else { '-' });
    }
    let mtime = md.mtime.unwrap_or(0) as i64;
    println!("{kind}{perms} {:>12} {} {name}", md.size.unwrap_or(0), fmt_mtime(mtime));
}

/// Formats a modification time like Go's "Jan _2 15:04", or with the
/// year for files older than about six months (in UTC).
fn fmt_mtime(t: i64) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = t.div_euclid(86400);
    let rem = t.rem_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let month = MONTHS[(mo - 1) as usize];
    if now - t > 180 * 86400 {
        format!("{month} {d:>2}  {y}")
    } else {
        format!("{month} {d:>2} {:02}:{:02}", rem / 3600, (rem % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_args() {
        assert_eq!(split_remote_arg("tcX:foo"), Some(("tcX", "foo")));
        assert_eq!(split_remote_arg("C:\\x"), None);
        assert_eq!(split_remote_arg("./a:b"), None);
        assert_eq!(split_remote_arg("plain"), None);
    }

    #[test]
    fn quoting() {
        assert_eq!(
            proxy_command_join_unix(&["a b".into(), "it's".into(), "50%".into()]).unwrap(),
            "'a b' 'it'\"'\"'s' '50%%'"
        );
        assert!(proxy_command_join_unix(&["a\nb".into()]).is_err());
        assert_eq!(proxy_command_join_windows(&["C:\\x\\".into()]).unwrap(), "\"C:\\x\\\\\"");
    }

    #[test]
    fn ports_and_hosts() {
        assert_eq!(validated_ssh_port("22").unwrap(), "22");
        assert_eq!(validated_ssh_port("10.0.0.1").unwrap(), "10.0.0.1:22");
        assert_eq!(validated_ssh_port("[fd7a::1]:2222").unwrap(), "[fd7a::1]:2222");
        assert!(validated_ssh_port("0").is_err());
        assert!(ssh_dest_host("tcabc").starts_with("tailcat-"));
        assert_eq!(ssh_dest_host("tcabc").len(), "tailcat-".len() + 16);
        assert!(valid_github_user("bradfitz"));
        assert!(!valid_github_user("-x"));
    }
}
