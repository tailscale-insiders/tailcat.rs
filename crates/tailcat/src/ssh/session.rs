//! Per-connection SSH handling: authentication, sessions (shells and
//! commands over pipes or a PTY), and the SFTP subsystem.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;

use russh::keys::PublicKey;
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::Shared;

const INTERACTIVE_MOTD: &str = "🐈 Connected via tailcat SSH.\r\n";

#[derive(Clone, Debug)]
pub(crate) struct PtyReq {
    #[allow(dead_code)]
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub modes: Vec<(Pty, u32)>,
}

#[derive(Default)]
struct ChanState {
    channel: Option<Channel<Msg>>,
    pty: Option<PtyReq>,
    env: Vec<(String, String)>,
    winch: Option<mpsc::UnboundedSender<(u32, u32)>>,
}

pub(crate) struct ConnHandler {
    shared: Arc<Shared>,
    local: SocketAddr,
    remote: SocketAddr,
    channels: HashMap<ChannelId, ChanState>,
}

/// What a session runs.
pub(crate) struct Plan {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    /// If set, the environment is exactly `env` and the command runs here.
    pub dir: Option<String>,
    pub motd: bool,
}

type Writer = ChannelWriteHalf<Msg>;

impl ConnHandler {
    pub fn new(shared: Arc<Shared>, local: SocketAddr, remote: SocketAddr) -> Self {
        ConnHandler { shared, local, remote, channels: HashMap::new() }
    }

    fn key_allowed(&self, k: &PublicKey) -> bool {
        match &self.shared.allowed {
            None => true,
            Some(set) => k.to_bytes().map(|b| set.contains(&b)).unwrap_or(false),
        }
    }

    fn plan(&self, raw_cmd: &Option<String>, client_env: Vec<(String, String)>, pty: bool) -> Option<Plan> {
        let opts = &self.shared.opts;
        let peer_env = crate::exec::peer_env(self.local, self.remote, (self.shared.peer_lookup)(self.remote));
        if !opts.exec.is_empty() {
            let mut env: Vec<(String, String)> = std::env::vars().collect();
            env.extend(peer_env);
            env.extend(client_env);
            if let Some(raw) = raw_cmd {
                env.push(("SSH_ORIGINAL_COMMAND".into(), raw.clone()));
            }
            return Some(Plan { argv: opts.exec.clone(), env, dir: None, motd: false });
        }
        if !opts.shell {
            return None;
        }
        let user = current_user();
        let shell = login_shell(&user);
        let argv = match raw_cmd {
            None => vec![shell.clone(), "-l".into()],
            Some(c) => vec![shell.clone(), "-c".into(), c.clone()],
        };
        let mut env = vec![
            ("SHELL".to_string(), shell),
            ("USER".to_string(), user.name.clone()),
            ("HOME".to_string(), user.home.clone()),
            ("PATH".to_string(), default_path(&user)),
        ];
        env.extend(client_env);
        // The tunnel authenticated the peer by this key.
        env.extend(peer_env.into_iter().filter(|(k, _)| k == "TAILCAT_PEER_KEY"));
        Some(Plan { argv, env, dir: Some(user.home), motd: pty && raw_cmd.is_none() })
    }

    fn start(&mut self, id: ChannelId, raw_cmd: Option<String>, session: &mut Session) -> Result<(), russh::Error> {
        let Some(st) = self.channels.get_mut(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let Some(channel) = st.channel.take() else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let pty = st.pty.clone();
        let client_env = std::mem::take(&mut st.env);
        let (winch_tx, winch_rx) = mpsc::unbounded_channel();
        st.winch = Some(winch_tx);
        session.channel_success(id)?;
        let plan = self.plan(&raw_cmd, client_env, pty.is_some());
        tokio::spawn(async move {
            let (mut rd, wr) = channel.split();
            let code = match plan {
                None => {
                    let mut w = wr.make_writer_ext(Some(1));
                    let _ = w
                        .write_all(b"this tailcat server only offers file transfer (SFTP); shell and exec sessions are disabled\r\n")
                        .await;
                    let _ = w.flush().await;
                    1
                }
                Some(plan) => match pty {
                    #[cfg(unix)]
                    Some(p) => pty::run(&mut rd, &wr, plan, p, winch_rx).await,
                    _ => {
                        drop(winch_rx);
                        run_pipes(&mut rd, &wr, plan).await
                    }
                },
            };
            let _ = wr.exit_status(code).await;
            let _ = wr.eof().await;
            let _ = wr.close().await;
        });
        Ok(())
    }
}

/// Reports whether an environment variable from the client should be
/// accepted, like OpenSSH's default AcceptEnv.
fn accept_env(k: &str) -> bool {
    k == "TERM" || k == "LANG" || k.starts_with("LC_")
}

impl russh::server::Handler for ConnHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(if self.shared.allowed.is_none() { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey_offered(&mut self, _user: &str, k: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if self.key_allowed(k) { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, _user: &str, k: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if self.key_allowed(k) { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), ChanState { channel: Some(channel), ..Default::default() });
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(st) = self.channels.get_mut(&channel) {
            st.pty = Some(PtyReq { term: term.to_string(), cols, rows, modes: modes.to_vec() });
            if !term.is_empty() {
                st.env.push(("TERM".into(), term.to_string()));
            }
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        k: &str,
        v: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if accept_env(k) {
            if let Some(st) = self.channels.get_mut(&channel) {
                st.env.push((k.to_string(), v.to_string()));
            }
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(st) = self.channels.get_mut(&channel) {
            match &st.winch {
                Some(w) => {
                    let _ = w.send((cols, rows));
                }
                None => {
                    if let Some(p) = &mut st.pty {
                        p.cols = cols;
                        p.rows = rows;
                    }
                }
            }
        }
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.start(channel, None, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, Some(String::from_utf8_lossy(data).into_owned()), session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let opts = &self.shared.opts;
        let enabled = opts.exec.is_empty() && (opts.files.is_some() || opts.shell);
        if name != "sftp" || !enabled {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let Some(ch) = self.channels.get_mut(&channel).and_then(|st| st.channel.take()) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let fs = match super::sftp::Sftp::new(opts.files.clone()) {
            Ok(fs) => fs,
            Err(e) => {
                tracing::warn!("sftp session: {e}");
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        session.channel_success(channel)?;
        tokio::spawn(serve_sftp(ch, fs));
        Ok(())
    }
}

/// Serves SFTP on a channel, then reports exit status 0 as OpenSSH
/// servers do (scp treats a missing status as failure). The SFTP server
/// runs on one end of a pipe so we can tell when it finishes.
async fn serve_sftp(ch: Channel<Msg>, fs: super::sftp::Sftp) {
    let (mut rd, wr) = ch.split();
    let (ours, theirs) = tokio::io::duplex(256 << 10);
    russh_sftp::server::run(theirs, fs).await;
    let (mut from_sftp, mut to_sftp) = tokio::io::split(ours);
    let inbound = async {
        while let Some(m) = rd.wait().await {
            match m {
                ChannelMsg::Data { data } => {
                    if to_sftp.write_all(&data).await.is_err() {
                        break;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        let _ = to_sftp.shutdown().await;
    };
    let outbound = async {
        let mut w = wr.make_writer();
        let _ = tokio::io::copy(&mut from_sftp, &mut w).await;
        let _ = w.flush().await;
    };
    tokio::pin!(inbound);
    let mut in_done = false;
    tokio::pin!(outbound);
    loop {
        tokio::select! {
            _ = &mut inbound, if !in_done => in_done = true,
            _ = &mut outbound => break,
        }
    }
    let _ = wr.exit_status(0).await;
    let _ = wr.eof().await;
    let _ = wr.close().await;
}

/// Runs a command with pipes for stdio, returning its exit status.
async fn run_pipes(rd: &mut ChannelReadHalf, wr: &Writer, plan: Plan) -> u32 {
    let mut cmd = tokio::process::Command::new(&plan.argv[0]);
    cmd.args(&plan.argv[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(d) = &plan.dir {
        cmd.env_clear().current_dir(d);
    }
    cmd.envs(plan.env);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let mut w = wr.make_writer_ext(Some(1));
            let _ = w.write_all(format!("start: {e}\r\n").as_bytes()).await;
            let _ = w.flush().await;
            return 1;
        }
    };
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let mut out_w = wr.make_writer();
    let mut err_w = wr.make_writer_ext(Some(1));
    let input = async {
        while let Some(m) = rd.wait().await {
            match m {
                ChannelMsg::Data { data } => {
                    if let Some(s) = stdin.as_mut()
                        && s.write_all(&data).await.is_err()
                    {
                        stdin = None;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        drop(stdin.take());
    };
    let outputs = async {
        let o = async {
            let _ = tokio::io::copy(&mut stdout, &mut out_w).await;
            let _ = out_w.flush().await;
        };
        let e = async {
            let _ = tokio::io::copy(&mut stderr, &mut err_w).await;
            let _ = err_w.flush().await;
        };
        tokio::join!(o, e);
    };
    // Drain the output before waiting, so a fast command's output isn't
    // lost; the input side may still be waiting on the client.
    {
        tokio::pin!(input, outputs);
        let mut in_done = false;
        loop {
            tokio::select! {
                _ = &mut input, if !in_done => in_done = true,
                _ = &mut outputs => break,
            }
        }
    }
    exit_code(child.wait().await)
}

fn exit_code(status: std::io::Result<std::process::ExitStatus>) -> u32 {
    match status {
        Ok(s) => match s.code() {
            Some(c) => c as u32,
            None => {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(sig) = s.signal() {
                        return 128 + sig as u32;
                    }
                }
                255
            }
        },
        Err(_) => 1,
    }
}

#[cfg(unix)]
mod pty {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Stdio;

    use russh::{ChannelMsg, ChannelReadHalf, Pty};
    use tokio::io::AsyncWriteExt;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;

    use super::{INTERACTIVE_MOTD, Plan, PtyReq, Writer, exit_code};

    fn winsize(cols: u32, rows: u32) -> libc::winsize {
        libc::winsize {
            ws_row: rows.min(u16::MAX as u32) as u16,
            ws_col: cols.min(u16::MAX as u32) as u16,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }

    /// Applies the client's terminal modes to the PTY.
    fn apply_modes(fd: i32, modes: &[(Pty, u32)]) {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 {
                return;
            }
            for &(m, v) in modes {
                let on = v != 0;
                let set = |flags: &mut libc::tcflag_t, bit: libc::tcflag_t| {
                    if on { *flags |= bit } else { *flags &= !bit }
                };
                let cc = |t: &mut libc::termios, idx: usize| t.c_cc[idx] = v as libc::cc_t;
                match m {
                    Pty::VINTR => cc(&mut t, libc::VINTR),
                    Pty::VQUIT => cc(&mut t, libc::VQUIT),
                    Pty::VERASE => cc(&mut t, libc::VERASE),
                    Pty::VKILL => cc(&mut t, libc::VKILL),
                    Pty::VEOF => cc(&mut t, libc::VEOF),
                    Pty::VEOL => cc(&mut t, libc::VEOL),
                    Pty::VSTART => cc(&mut t, libc::VSTART),
                    Pty::VSTOP => cc(&mut t, libc::VSTOP),
                    Pty::VSUSP => cc(&mut t, libc::VSUSP),
                    Pty::VWERASE => cc(&mut t, libc::VWERASE),
                    Pty::VLNEXT => cc(&mut t, libc::VLNEXT),
                    Pty::VREPRINT => cc(&mut t, libc::VREPRINT),
                    Pty::IGNPAR => set(&mut t.c_iflag, libc::IGNPAR),
                    Pty::PARMRK => set(&mut t.c_iflag, libc::PARMRK),
                    Pty::INPCK => set(&mut t.c_iflag, libc::INPCK),
                    Pty::ISTRIP => set(&mut t.c_iflag, libc::ISTRIP),
                    Pty::INLCR => set(&mut t.c_iflag, libc::INLCR),
                    Pty::IGNCR => set(&mut t.c_iflag, libc::IGNCR),
                    Pty::ICRNL => set(&mut t.c_iflag, libc::ICRNL),
                    Pty::IXON => set(&mut t.c_iflag, libc::IXON),
                    Pty::IXANY => set(&mut t.c_iflag, libc::IXANY),
                    Pty::IXOFF => set(&mut t.c_iflag, libc::IXOFF),
                    Pty::IMAXBEL => set(&mut t.c_iflag, libc::IMAXBEL),
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    Pty::IUTF8 => set(&mut t.c_iflag, libc::IUTF8),
                    Pty::ISIG => set(&mut t.c_lflag, libc::ISIG),
                    Pty::ICANON => set(&mut t.c_lflag, libc::ICANON),
                    Pty::ECHO => set(&mut t.c_lflag, libc::ECHO),
                    Pty::ECHOE => set(&mut t.c_lflag, libc::ECHOE),
                    Pty::ECHOK => set(&mut t.c_lflag, libc::ECHOK),
                    Pty::ECHONL => set(&mut t.c_lflag, libc::ECHONL),
                    Pty::NOFLSH => set(&mut t.c_lflag, libc::NOFLSH),
                    Pty::TOSTOP => set(&mut t.c_lflag, libc::TOSTOP),
                    Pty::IEXTEN => set(&mut t.c_lflag, libc::IEXTEN),
                    Pty::ECHOCTL => set(&mut t.c_lflag, libc::ECHOCTL),
                    Pty::ECHOKE => set(&mut t.c_lflag, libc::ECHOKE),
                    Pty::OPOST => set(&mut t.c_oflag, libc::OPOST),
                    Pty::ONLCR => set(&mut t.c_oflag, libc::ONLCR),
                    Pty::OCRNL => set(&mut t.c_oflag, libc::OCRNL),
                    Pty::ONOCR => set(&mut t.c_oflag, libc::ONOCR),
                    Pty::ONLRET => set(&mut t.c_oflag, libc::ONLRET),
                    Pty::CS7 => set(&mut t.c_cflag, libc::CS7),
                    Pty::CS8 => set(&mut t.c_cflag, libc::CS8),
                    Pty::PARENB => set(&mut t.c_cflag, libc::PARENB),
                    Pty::PARODD => set(&mut t.c_cflag, libc::PARODD),
                    _ => {}
                }
            }
            libc::tcsetattr(fd, libc::TCSANOW, &t);
        }
    }

    async fn read_fd(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut g = fd.readable().await?;
            match g.try_io(|f| {
                let n = unsafe { libc::read(f.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
            }) {
                Ok(r) => return r,
                Err(_) => continue,
            }
        }
    }

    async fn write_fd(fd: &AsyncFd<OwnedFd>, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            let mut g = fd.writable().await?;
            match g.try_io(|f| {
                let n = unsafe { libc::write(f.as_raw_fd(), data.as_ptr().cast(), data.len()) };
                if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
            }) {
                Ok(Ok(n)) => data = &data[n..],
                Ok(Err(e)) => return Err(e),
                Err(_) => continue,
            }
        }
        Ok(())
    }

    /// Runs the command on a new pseudo-terminal.
    pub(super) async fn run(
        rd: &mut ChannelReadHalf,
        wr: &Writer,
        plan: Plan,
        req: PtyReq,
        mut winch: mpsc::UnboundedReceiver<(u32, u32)>,
    ) -> u32 {
        let (mut master, mut slave) = (-1, -1);
        let mut ws = winsize(req.cols, req.rows);
        // The winsize parameter is `*const` on Linux and `*mut` on macOS.
        let r = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::addr_of_mut!(ws),
            )
        };
        let mut err_w = wr.make_writer_ext(Some(1));
        if r != 0 {
            let _ = err_w.write_all(format!("pty open: {}\r\n", std::io::Error::last_os_error()).as_bytes()).await;
            return 1;
        }
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        apply_modes(slave.as_raw_fd(), &req.modes);

        let mut cmd = tokio::process::Command::new(&plan.argv[0]);
        cmd.args(&plan.argv[1..]);
        if let Some(d) = &plan.dir {
            cmd.env_clear().current_dir(d);
        }
        cmd.envs(plan.env);
        let (Ok(i), Ok(o), Ok(e)) = (slave.try_clone(), slave.try_clone(), slave.try_clone()) else {
            let _ = err_w.write_all(b"pty dup failed\r\n").await;
            return 1;
        };
        cmd.stdin(Stdio::from(i)).stdout(Stdio::from(o)).stderr(Stdio::from(e));
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn();
        drop(slave);
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                let _ = err_w.write_all(format!("start: {e}\r\n").as_bytes()).await;
                return 1;
            }
        };
        unsafe {
            let fl = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        let master = match AsyncFd::new(master) {
            Ok(m) => m,
            Err(e) => {
                let _ = err_w.write_all(format!("pty: {e}\r\n").as_bytes()).await;
                let _ = child.kill().await;
                return 1;
            }
        };
        let mut out_w = wr.make_writer();
        if plan.motd {
            let _ = out_w.write_all(INTERACTIVE_MOTD.as_bytes()).await;
        }
        let output = async {
            let mut buf = vec![0u8; 16 << 10];
            loop {
                match read_fd(&master, &mut buf).await {
                    Ok(0) | Err(_) => break, // EIO once the slave side is gone
                    Ok(n) => {
                        if out_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        let _ = out_w.flush().await;
                    }
                }
            }
        };
        let input = async {
            loop {
                tokio::select! {
                    m = rd.wait() => match m {
                        Some(ChannelMsg::Data { data }) => {
                            if write_fd(&master, &data).await.is_err() {
                                break;
                            }
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    },
                    Some((c, r)) = winch.recv() => {
                        let ws = winsize(c, r);
                        unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) };
                    }
                }
            }
            // Keep handling resizes until the session ends.
            while let Some((c, r)) = winch.recv().await {
                let ws = winsize(c, r);
                unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) };
            }
        };
        tokio::pin!(input, output);
        let mut in_done = false;
        let exited = loop {
            tokio::select! {
                _ = &mut input, if !in_done => in_done = true,
                _ = &mut output => break None,
                st = child.wait() => break Some(st),
            }
        };
        match exited {
            None => exit_code(child.wait().await),
            Some(st) => {
                // Collect what's left in the PTY buffer, briefly.
                let _ = tokio::time::timeout(std::time::Duration::from_millis(200), &mut output).await;
                exit_code(st)
            }
        }
    }
}

pub(crate) struct User {
    pub name: String,
    pub home: String,
    pub uid: u32,
}

pub(crate) fn current_user() -> User {
    #[cfg(unix)]
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            let name = std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned();
            let home = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
            return User { name, home, uid };
        }
        User {
            name: std::env::var("USER").unwrap_or_default(),
            home: std::env::var("HOME").unwrap_or_else(|_| "/".into()),
            uid,
        }
    }
    #[cfg(not(unix))]
    User {
        name: std::env::var("USERNAME").unwrap_or_default(),
        home: std::env::var("USERPROFILE").unwrap_or_default(),
        uid: 1,
    }
}

/// The user's login shell: from the directory service on macOS, else
/// $SHELL, else /bin/sh (as the Go implementation does).
fn login_shell(u: &User) -> String {
    if cfg!(windows) {
        return "powershell.exe".into();
    }
    if cfg!(target_os = "macos")
        && let Ok(out) =
            std::process::Command::new("dscl").args([".", "-read", &format!("/Users/{}", u.name), "UserShell"]).output()
        && let Some(s) = String::from_utf8_lossy(&out.stdout).strip_prefix("UserShell: ")
    {
        return s.trim().to_string();
    }
    std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into())
}

fn default_path(u: &User) -> String {
    if u.uid == 0 {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()
    } else {
        "/usr/local/bin:/usr/bin:/bin".into()
    }
}
