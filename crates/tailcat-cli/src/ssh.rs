//! `tailcat ssh`, `tailcat cp`, `tailcat ls`, and loading the `ssh`
//! service's authorized keys.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use russh_sftp::client::SftpSession;
use sha2::{Digest, Sha256};
use tailcat::ssh::parse_authorized_keys;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::args::{AuthorizedKeysArg, KeyArg, KeySource, SshTarget};
use crate::{Global, usagef};

const MAX_AUTHORIZED_KEYS_SIZE: usize = 1 << 20;

fn looks_like_ssh_public_key(s: &str) -> bool {
    let first = s.split_whitespace().next().unwrap_or("");
    ["ssh-", "ecdsa-", "sk-"].iter().any(|p| first.starts_with(p))
}

/// Loads the keys from each of `list`'s sources: a GitHub user's, an
/// authorized_keys file's, or a literal public key line.
pub async fn load_authorized_keys(list: &AuthorizedKeysArg) -> Result<Vec<String>> {
    let mut texts = Vec::new();
    for (i, source) in list.0.iter().enumerate() {
        let n = i + 1;
        let text = match source {
            KeySource::Github(user) => {
                fetch_github_keys(user).await.map_err(|e| anyhow!("source {n} ({source}): {e}"))?
            }
            KeySource::Local(s) => match std::fs::read(s).and_then(|b| limited_text(&b, "file")) {
                Ok(t) => t,
                Err(file_err) => match parse_authorized_keys(std::slice::from_ref(s)) {
                    Ok(_) => s.clone(),
                    Err(e) if looks_like_ssh_public_key(s) => bail!("source {n}: invalid SSH public key: {e}"),
                    Err(_) => bail!("source {n}: reading {s:?}: {file_err}"),
                },
            },
        };
        parse_authorized_keys(std::slice::from_ref(&text)).map_err(|e| anyhow!("source {n} ({source}): {e}"))?;
        texts.push(text);
    }
    Ok(texts)
}

/// Decodes authorized keys text, refusing implausibly large inputs.
fn limited_text(b: &[u8], what: &str) -> std::io::Result<String> {
    if b.len() > MAX_AUTHORIZED_KEYS_SIZE {
        return Err(std::io::Error::other(format!("{what} is larger than {MAX_AUTHORIZED_KEYS_SIZE} bytes")));
    }
    Ok(String::from_utf8_lossy(b).into_owned())
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
    Ok(limited_text(&b, "GitHub key list")?)
}

/// A short, deterministic ssh destination name for an address: the real
/// address rides in the ProxyCommand, and long names overflow
/// ControlPath socket paths.
fn ssh_dest_host(addr: &str) -> String {
    format!("tailcat-{}", hex::encode(&Sha256::digest(addr.as_bytes())[..8]))
}

/// Quotes arguments for the shell that runs a ProxyCommand here.
#[cfg(not(windows))]
fn proxy_command_join(args: &[String]) -> Result<String> {
    proxy_command_join_unix(args)
}

/// Quotes arguments for the shell that runs a ProxyCommand here.
#[cfg(windows)]
fn proxy_command_join(args: &[String]) -> Result<String> {
    proxy_command_join_windows(args)
}

/// Where ssh should keep known hosts: nowhere.
#[cfg(not(windows))]
const NULL_DEVICE: &str = "/dev/null";
#[cfg(windows)]
const NULL_DEVICE: &str = "NUL";

/// Quotes arguments for the POSIX shell that runs a ProxyCommand;
/// percent signs are doubled for OpenSSH's own token expansion.
#[cfg(any(not(windows), test))]
fn proxy_command_join_unix(args: &[String]) -> Result<String> {
    let quoted: Result<Vec<_>> = args
        .iter()
        .map(|a| {
            if a.contains(['\r', '\n', '\0']) {
                bail!("ProxyCommand argument contains a control character: {a:?}");
            }
            Ok(format!("'{}'", a.replace('%', "%%").replace('\'', r#"'"'"'"#)))
        })
        .collect();
    Ok(quoted?.join(" "))
}

#[cfg(any(windows, test))]
fn proxy_command_join_windows(args: &[String]) -> Result<String> {
    let quoted: Result<Vec<_>> = args
        .iter()
        .map(|a| {
            if a.contains(['"', '%', '!', '\r', '\n', '\0']) {
                bail!("ProxyCommand argument contains a character unsafe for cmd.exe: {a:?}");
            }
            let trailing = a.len() - a.trim_end_matches('\\').len();
            Ok(format!("\"{a}{}\"", "\\".repeat(trailing)))
        })
        .collect();
    Ok(quoted?.join(" "))
}

/// The `-o` options for ssh and scp: skip host key checks (the tunnel
/// authenticates the server) and connect through `tailcat <addr> <port>`.
fn ssh_opts(g: &Global, addr: &str, port: SshTarget) -> Result<Vec<String>> {
    let mut proxy = vec![std::env::current_exe()?.to_string_lossy().into_owned()];
    if g.key != KeyArg::Default {
        proxy.push(format!("--key={}", g.key));
    }
    if g.derpmap_url != tailcat::DEFAULT_DERP_MAP_URL {
        proxy.push(format!("--derpmap-url={}", g.derpmap_url));
    }
    proxy.extend([addr.into(), port.to_string()]);
    let proxy = proxy_command_join(&proxy)?;
    Ok([
        "UpdateHostKeys no".into(),
        "StrictHostKeyChecking no".into(),
        "LogLevel ERROR".into(),
        format!("UserKnownHostsFile {NULL_DEVICE}"),
        format!("ProxyCommand={proxy}"),
    ]
    .into_iter()
    .flat_map(|o| ["-o".into(), o])
    .collect())
}

/// Replaces this process with `argv`, returning only if that fails.
#[cfg(unix)]
fn exec_replace(argv: Vec<String>) -> Result<ExitCode> {
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    let err = std::os::unix::process::CommandExt::exec(&mut cmd);
    bail!("failed to run {}: {err}", argv[0]);
}

/// Runs `argv` to completion, exiting as it did: processes can't be
/// replaced here.
#[cfg(not(unix))]
fn exec_replace(argv: Vec<String>) -> Result<ExitCode> {
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    Ok(ExitCode::from(cmd.status()?.code().unwrap_or(1) as u8))
}

pub async fn ssh_mode(g: &Global, port: SshTarget, skip_dns_check: bool, args: Vec<String>) -> Result<ExitCode> {
    let (dst, rest) = args.split_first().expect("clap requires a destination");
    let (user, addr_str) = dst.split_once('@').map_or((None, dst.as_str()), |(u, a)| (Some(u), a));
    let (addr, via_dns) = crate::addrarg::validated_addr(addr_str).await?;
    if via_dns && !skip_dns_check {
        refuse_wide_open_dns(g, addr_str, &addr, port, user).await;
    }
    let ssh = crate::serve::which("ssh").ok_or_else(|| anyhow!("no ssh client found in $PATH"))?;
    let host = ssh_dest_host(addr.as_str());
    let mut argv = vec![ssh];
    argv.extend(ssh_opts(g, addr.as_str(), port)?);
    argv.push("--".into());
    argv.push(user.map_or(host.clone(), |u| format!("{u}@{host}")));
    argv.extend_from_slice(rest);
    exec_replace(argv)
}

/// Splits an scp-style "host:path"; a one-character host or one with a
/// path separator stays local (a Windows drive, a relative path).
fn split_remote_arg(arg: &str) -> Option<(&str, &str)> {
    let (host, path) = arg.split_once(':')?;
    (host.len() > 1 && !host.contains(['/', '\\'])).then_some((host, path))
}

fn scp_supports_sftp_flag(scp: &str) -> bool {
    let Ok(o) = std::process::Command::new(scp).args(["-s", "--"]).output() else { return false };
    let msg = String::from_utf8_lossy(&[o.stdout, o.stderr].concat()).to_lowercase();
    !["unknown", "illegal", "invalid"].iter().any(|w| msg.contains(&format!("{w} option -- s")))
}

pub async fn cp_mode(
    g: &Global,
    recursive: bool,
    preserve: bool,
    port: SshTarget,
    args: Vec<String>,
) -> Result<ExitCode> {
    if args.len() < 2 {
        return Err(usagef!("cp requires at least one source and a target"));
    }
    let mut hosts = args.iter().filter_map(|a| split_remote_arg(a)).map(|(h, _)| h);
    let Some(addr) = hosts.next() else {
        return Err(usagef!("no remote <tc-addr>:path argument; nothing to copy through tailcat"));
    };
    if let Some(other) = hosts.find(|h| *h != addr) {
        return Err(usagef!("all remote paths must name the same server ({addr:?} and {other:?} differ)"));
    }
    let (addr, _) = crate::addrarg::validated_addr(addr).await?;
    let label = ssh_dest_host(addr.as_str());
    let scp = crate::serve::which("scp").ok_or_else(|| anyhow!("no scp found in $PATH"))?;
    let mut argv = vec![scp.clone()];
    if scp_supports_sftp_flag(&scp) {
        argv.push("-s".into());
    }
    argv.extend(ssh_opts(g, addr.as_str(), port)?);
    argv.extend(recursive.then(|| "-r".into()));
    argv.extend(preserve.then(|| "-p".into()));
    argv.push("--".into());
    argv.extend(args.iter().map(|a| match split_remote_arg(a) {
        Some((_, path)) => format!("{label}:{path}"),
        None => a.clone(),
    }));
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

/// Starts an SSH session over `conn` and tries logging in as `user`
/// with no credentials, reporting whether the server let us in.
async fn login_without_credentials(
    conn: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    user: String,
) -> Result<(russh::client::Handle<AcceptAny>, bool), russh::Error> {
    let mut h = russh::client::connect_stream(Arc::new(russh::client::Config::default()), conn, AcceptAny).await?;
    let ok = h.authenticate_none(user).await.is_ok_and(|r| r.success());
    Ok((h, ok))
}

async fn dial(cl: &tailcat::Client, port: SshTarget) -> Result<tailcat::TcpStream> {
    Ok(port.dial(cl).await?)
}

/// Reports whether the server at `addr` lets a stranger (a fresh node
/// key, no SSH credentials) log in.
async fn probe_stranger_ssh(g: &Global, addr: &tailcat::Addr, port: SshTarget, user: Option<&str>) -> Result<bool> {
    let cl = crate::client::new_client(g, addr.clone(), tailcat::NodePrivate::generate());
    let conn = dial(&cl, port).await?;
    let user = user.map_or_else(local_username, String::from);
    let Ok((h, open)) = login_without_credentials(conn, user).await else { return Ok(false) };
    let _ = h.disconnect(russh::Disconnect::ByApplication, "", "").await;
    Ok(open)
}

async fn refuse_wide_open_dns(g: &Global, dns_name: &str, addr: &tailcat::Addr, port: SshTarget, user: Option<&str>) {
    match tokio::time::timeout(Duration::from_secs(10), probe_stranger_ssh(g, addr, port, user)).await {
        Ok(Ok(true)) => {}
        Ok(Err(e)) => {
            tracing::debug!("stranger probe of {dns_name} did not connect: {e}");
            return;
        }
        _ => return,
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

/// How long `tailcat ls` waits for the SSH handshake and the SFTP
/// session to open. Each SFTP request after that has russh-sftp's own
/// timeout.
const SFTP_OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Logs in over `conn` with no credentials and opens an SFTP session,
/// giving up after `timeout`. The session lasts as long as the handle.
async fn open_sftp(
    conn: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    user: String,
    timeout: Duration,
) -> Result<(russh::client::Handle<AcceptAny>, SftpSession)> {
    let open = async {
        let (h, ok) = login_without_credentials(conn, user).await.map_err(|e| anyhow!("SSH handshake: {e}"))?;
        if !ok {
            bail!("SSH handshake: the server requires authentication");
        }
        let sftp_err = |e: &dyn std::fmt::Display| anyhow!("opening SFTP session: {e}");
        let ch = h.channel_open_session().await.map_err(|e| sftp_err(&e))?;
        ch.request_subsystem(true, "sftp").await.map_err(|e| sftp_err(&e))?;
        let sf = SftpSession::new(ch.into_stream()).await.map_err(|e| sftp_err(&e))?;
        Ok((h, sf))
    };
    tokio::time::timeout(timeout, open).await.map_err(|_| anyhow!("opening SFTP session: timed out"))?
}

pub async fn ls_mode(g: &Global, long: bool, target: &str) -> Result<ExitCode> {
    let (host, path) = split_remote_arg(target).unwrap_or((target, ""));
    let path = if path.is_empty() { "." } else { path };
    let addr = crate::addrarg::tailcat_addr_arg(host).await?;
    let cl = crate::client::new_client(g, addr, crate::keys::client_key(g)?);
    let conn = tokio::time::timeout(Duration::from_secs(30), cl.dial_tcp_port(22))
        .await
        .map_err(|_| anyhow!("dialing server: timed out"))?
        .map_err(|e| anyhow!("dialing server: {e}"))?;
    let (_h, sf) = open_sftp(conn, local_username(), SFTP_OPEN_TIMEOUT).await?;
    let md = sf.metadata(path).await.map_err(|e| anyhow!("{path}: {e}"))?;
    if !md.is_dir() {
        print_entry(long, &md, path.trim_start_matches("./"));
        return Ok(ExitCode::SUCCESS);
    }
    let mut entries: Vec<_> = sf
        .read_dir(path)
        .await
        .map_err(|e| anyhow!("{path}: {e}"))?
        .map(|e| (e.file_name(), e.metadata()))
        .filter(|(n, _)| n != "." && n != "..")
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, md) in entries {
        print_entry(long, &md, &name);
    }
    let _ = sf.close().await;
    Ok(ExitCode::SUCCESS)
}

fn print_entry(long: bool, md: &russh_sftp::protocol::FileAttributes, name: &str) {
    let slash = if md.is_dir() { "/" } else { "" };
    if !long {
        println!("{name}{slash}");
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
    let perms = tailcat::ssh::permission_string(mode);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let mtime = fmt_mtime(md.mtime.unwrap_or(0).into(), now);
    println!("{kind}{perms} {:>12} {mtime} {name}{slash}", md.size.unwrap_or(0));
}

/// Formats a modification time like Go's "Jan _2 15:04", or with the
/// year for files older than about six months (in UTC).
fn fmt_mtime(t: i64, now: i64) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let [y, mo, d, h, m, _] = tailcat::ssh::utc_civil(t);
    let month = MONTHS[mo as usize - 1];
    if now - t > 180 * 86400 { format!("{month} {d:>2}  {y}") } else { format!("{month} {d:>2} {h:02}:{m:02}") }
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;
    use std::fs;

    use tokio::io::duplex;
    use tokio::time::timeout;

    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE comment";

    #[test]
    fn remote_args() {
        assert_eq!(split_remote_arg("tcX:foo"), Some(("tcX", "foo")));
        assert_eq!(split_remote_arg("tcX:a:b"), Some(("tcX", "a:b")));
        assert_eq!(split_remote_arg("tcX:"), Some(("tcX", "")));
        assert_eq!(split_remote_arg("C:\\x"), None);
        assert_eq!(split_remote_arg(":x"), None);
        assert_eq!(split_remote_arg("./a:b"), None);
        assert_eq!(split_remote_arg("plain"), None);
    }

    fn join_unix<const N: usize>(args: [&str; N]) -> Result<String> {
        proxy_command_join_unix(&args.map(String::from))
    }

    fn join_windows<const N: usize>(args: [&str; N]) -> Result<String> {
        proxy_command_join_windows(&args.map(String::from))
    }

    #[test]
    fn quoting() {
        assert_eq!(join_unix(["a b", "it's", "50%"]).unwrap(), "'a b' 'it'\"'\"'s' '50%%'");
        assert!(join_unix(["a\nb"]).is_err());
        assert_eq!(join_windows(["C:\\x\\", "y"]).unwrap(), "\"C:\\x\\\\\" \"y\"");
        assert!(join_windows(["100%"]).is_err());
    }

    #[test]
    fn ports_and_hosts() {
        let host = ssh_dest_host("tcabc");
        assert!(host.starts_with("tailcat-"));
        assert_eq!(host.len(), "tailcat-".len() + 16);
    }

    #[test]
    fn mtimes() {
        let t = 1_700_000_000; // 2023-11-14 22:13:20 UTC
        assert_eq!(fmt_mtime(t, t + 60), "Nov 14 22:13");
        assert_eq!(fmt_mtime(t, t + 365 * 86400), "Nov 14  2023");
        assert_eq!(fmt_mtime(0, t), "Jan  1  1970");
    }

    /// `tailcat ls` gives up on a server that never answers, rather than
    /// hanging.
    #[tokio::test]
    async fn sftp_open_times_out() {
        let (conn, _server) = duplex(1 << 16);
        let open = open_sftp(conn, "u".into(), Duration::from_millis(100));
        let opened = timeout(Duration::from_secs(5), open).await.expect("open_sftp outlived its timeout");
        let Err(e) = opened else { panic!("a silent server let us in") };
        assert_eq!(e.to_string(), "opening SFTP session: timed out");
    }

    /// Why parsing or loading the authorized keys in `list` fails.
    async fn load_err(list: impl Display) -> String {
        match list.to_string().parse() {
            Ok(list) => load_authorized_keys(&list).await.unwrap_err().to_string(),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn authorized_key_sources() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("keys");
        fs::write(&file, format!("# mine\n{KEY}\n")).unwrap();
        let texts = load_authorized_keys(&format!("{KEY}, {}", file.display()).parse().unwrap()).await.unwrap();
        assert_eq!(texts, [KEY.to_string(), format!("# mine\n{KEY}\n")]);

        assert_eq!(load_err(format!("{KEY},")).await, "source 2 is empty");
        assert!(load_err("ssh-ed25519 AAAA").await.starts_with("source 1: invalid SSH public key"));
        assert!(load_err("/nonexistent/keys").await.starts_with("source 1: reading \"/nonexistent/keys\""));
        assert!(load_err("-x@github").await.contains("invalid GitHub username"));

        fs::write(&file, "# no keys\n").unwrap();
        assert!(load_err(file.display()).await.contains("no SSH public keys found"));

        fs::write(&file, vec![b'#'; MAX_AUTHORIZED_KEYS_SIZE + 1]).unwrap();
        assert!(load_err(file.display()).await.contains("file is larger than"));
    }
}
