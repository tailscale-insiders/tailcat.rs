//! Per-connection SSH handling: authentication, sessions (shells and
//! commands over pipes or a PTY), and the SFTP subsystem.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::{env, future, io, mem};

use bytes::Bytes;
use russh::keys::PublicKey;
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::Shared;
use super::sftp::Sftp;

const INTERACTIVE_MOTD: &str = "🐈 Connected via tailcat SSH.\r\n";

pub(crate) struct PtyReq {
    pub cols: u32,
    pub rows: u32,
    pub modes: Vec<(Pty, u32)>,
}

#[derive(Default)]
struct ChanState {
    channel: Option<Channel<Msg>>,
    /// The requested PTY, until the session starts.
    pty: Option<PtyReq>,
    env: Vec<(String, String)>,
    /// Forwards window changes once the session has started.
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

impl Plan {
    fn command(self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.argv[0]);
        cmd.args(&self.argv[1..]);
        if let Some(d) = &self.dir {
            cmd.env_clear().current_dir(d);
        }
        cmd.envs(self.env);
        cmd
    }
}

type Writer = ChannelWriteHalf<Msg>;

impl ConnHandler {
    pub fn new(shared: Arc<Shared>, local: SocketAddr, remote: SocketAddr) -> Self {
        ConnHandler { shared, local, remote, channels: HashMap::new() }
    }

    fn key_allowed(&self, k: &PublicKey) -> bool {
        self.shared.allowed.as_ref().is_none_or(|set| k.to_bytes().is_ok_and(|b| set.contains(&b)))
    }

    fn plan(&self, raw_cmd: Option<String>, client_env: Vec<(String, String)>, pty: bool) -> Option<Plan> {
        let opts = &self.shared.opts;
        let peer = (self.shared.peer_lookup)(self.remote);
        if !opts.exec.is_empty() {
            // On top of our own environment, which the command inherits.
            let env = crate::exec::peer_env(self.local, self.remote, peer)
                .chain(ssh_env(self.local, self.remote))
                .chain(client_env)
                .chain(raw_cmd.map(|c| ("SSH_ORIGINAL_COMMAND".into(), c)))
                .collect();
            return Some(Plan { argv: opts.exec.clone(), env, dir: None, motd: false });
        }
        if !opts.shell {
            return None;
        }
        let user = current_user();
        let shell = login_shell(&user);
        let motd = pty && raw_cmd.is_none();
        let argv = match raw_cmd {
            None => vec![shell.clone(), "-l".into()],
            Some(c) => vec![shell.clone(), "-c".into(), c],
        };
        let mut env = vec![
            ("SHELL".to_string(), shell),
            ("USER".to_string(), user.name.clone()),
            ("HOME".to_string(), user.home.clone()),
            ("PATH".to_string(), default_path(&user).into()),
        ];
        env.extend(ssh_env(self.local, self.remote));
        env.extend(client_env);
        // The tunnel authenticated the peer by this key.
        env.extend(peer.map(|k| ("TAILCAT_PEER_KEY".into(), k.to_string())));
        Some(Plan { argv, env, dir: Some(user.home), motd })
    }

    fn start(&mut self, id: ChannelId, raw_cmd: Option<String>, session: &mut Session) -> Result<(), russh::Error> {
        let Some((channel, st)) = self.channels.get_mut(&id).and_then(|st| Some((st.channel.take()?, st))) else {
            return session.channel_failure(id);
        };
        let pty = st.pty.take();
        let client_env = mem::take(&mut st.env);
        let (winch_tx, winch_rx) = mpsc::unbounded_channel();
        st.winch = Some(winch_tx);
        session.channel_success(id)?;
        let plan = self.plan(raw_cmd, client_env, pty.is_some());
        tokio::spawn(async move {
            let (mut rd, wr) = channel.split();
            let code = match (plan, pty) {
                (None, _) => {
                    let msg =
                        "this tailcat server only offers file transfer (SFTP); shell and exec sessions are disabled";
                    say(&wr, format!("{msg}\r\n")).await;
                    1
                }
                (Some(plan), pty) => run_session(&mut rd, &wr, plan, pty, winch_rx).await,
            };
            finish(&wr, code).await;
        });
        Ok(())
    }
}

/// Reports whether an environment variable from the client should be
/// accepted, like OpenSSH's default AcceptEnv.
fn accept_env(k: &str) -> bool {
    k == "TERM" || k == "LANG" || k.starts_with("LC_")
}

fn verdict(ok: bool) -> Auth {
    if ok { Auth::Accept } else { Auth::reject() }
}

impl russh::server::Handler for ConnHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(verdict(self.shared.allowed.is_none()))
    }

    async fn auth_publickey_offered(&mut self, _user: &str, k: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(verdict(self.key_allowed(k)))
    }

    async fn auth_publickey(&mut self, _user: &str, k: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(verdict(self.key_allowed(k)))
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
            st.pty = Some(PtyReq { cols, rows, modes: modes.to_vec() });
            if !term.is_empty() {
                st.env.push(("TERM".into(), term.into()));
            }
        }
        session.channel_success(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        k: &str,
        v: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !accept_env(k) {
            return session.channel_failure(channel);
        }
        if let Some(st) = self.channels.get_mut(&channel) {
            st.env.push((k.into(), v.into()));
        }
        session.channel_success(channel)
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
            if let Some(w) = &st.winch {
                let _ = w.send((cols, rows));
            } else if let Some(p) = &mut st.pty {
                (p.cols, p.rows) = (cols, rows);
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
        if name != "sftp" || !(opts.files.is_some() || opts.shell) {
            return session.channel_failure(channel);
        }
        let fs = match Sftp::new(opts.files.clone()) {
            Ok(fs) => fs,
            Err(e) => {
                tracing::warn!("sftp session: {e}");
                return session.channel_failure(channel);
            }
        };
        let Some(ch) = self.channels.get_mut(&channel).and_then(|st| st.channel.take()) else {
            return session.channel_failure(channel);
        };
        session.channel_success(channel)?;
        tokio::spawn(serve_sftp(ch, fs));
        Ok(())
    }
}

/// Writes `msg` to the channel's stderr.
async fn say(wr: &Writer, msg: impl AsRef<[u8]>) {
    let mut w = wr.make_writer_ext(Some(1));
    let _ = w.write_all(msg.as_ref()).await;
    let _ = w.flush().await;
}

/// Reports the exit status and closes the channel.
async fn finish(wr: &Writer, code: u32) {
    let _ = wr.exit_status(code).await;
    let _ = wr.eof().await;
    let _ = wr.close().await;
}

/// What the client sends next on a channel.
enum Input {
    Data(Bytes),
    /// The client won't send more, but may still be reading.
    Eof,
    /// The channel closed, or the whole connection went away.
    Closed,
}

async fn next_input(rd: &mut ChannelReadHalf) -> Input {
    loop {
        match rd.wait().await {
            Some(ChannelMsg::Data { data }) => return Input::Data(data),
            Some(ChannelMsg::Eof) => return Input::Eof,
            Some(ChannelMsg::Close) | None => return Input::Closed,
            Some(_) => {}
        }
    }
}

/// Returns the next data the client sends, or `None` at its EOF.
async fn next_data(rd: &mut ChannelReadHalf) -> Option<Bytes> {
    match next_input(rd).await {
        Input::Data(data) => Some(data),
        Input::Eof | Input::Closed => None,
    }
}

/// Copies `r` to `w` until EOF or an error, then flushes.
async fn pump(mut r: impl AsyncRead + Unpin, mut w: impl AsyncWrite + Unpin) {
    let _ = tokio::io::copy(&mut r, &mut w).await;
    let _ = w.flush().await;
}

/// Runs `output` to completion while also driving `input`, which may
/// finish first (the client's EOF) or never (a client that keeps its
/// side open after a fast command's output is drained).
async fn drain<T>(output: impl Future<Output = T>, input: impl Future) -> T {
    let input = async {
        input.await;
        future::pending::<Infallible>().await
    };
    tokio::select! {
        r = output => r,
        never = input => match never {},
    }
}

/// Serves SFTP on a channel, then reports exit status 0 as OpenSSH
/// servers do (scp treats a missing status as failure). The SFTP server
/// runs on one end of a pipe so we can tell when it finishes.
async fn serve_sftp(ch: Channel<Msg>, fs: Sftp) {
    let (mut rd, wr) = ch.split();
    let (ours, theirs) = tokio::io::duplex(256 << 10);
    russh_sftp::server::run(theirs, fs).await;
    let (from_sftp, mut to_sftp) = tokio::io::split(ours);
    let inbound = async {
        while let Some(data) = next_data(&mut rd).await {
            if to_sftp.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = to_sftp.shutdown().await;
    };
    drain(pump(from_sftp, wr.make_writer()), inbound).await;
    finish(&wr, 0).await;
}

/// Runs a session's command, on a PTY if the client asked for one,
/// returning its exit status.
#[cfg(unix)]
async fn run_session(
    rd: &mut ChannelReadHalf,
    wr: &Writer,
    plan: Plan,
    pty: Option<PtyReq>,
    winch: mpsc::UnboundedReceiver<(u32, u32)>,
) -> u32 {
    match pty {
        Some(p) => pty::run(rd, wr, plan, p, winch).await,
        None => {
            drop(winch);
            run_pipes(rd, wr, plan).await
        }
    }
}

/// Runs a session's command with pipes for stdio, as there are no PTYs
/// here, returning its exit status.
#[cfg(not(unix))]
async fn run_session(
    rd: &mut ChannelReadHalf,
    wr: &Writer,
    plan: Plan,
    _pty: Option<PtyReq>,
    winch: mpsc::UnboundedReceiver<(u32, u32)>,
) -> u32 {
    drop(winch);
    run_pipes(rd, wr, plan).await
}

/// Runs a command with pipes for stdio, returning its exit status.
async fn run_pipes(rd: &mut ChannelReadHalf, wr: &Writer, plan: Plan) -> u32 {
    let mut cmd = plan.command();
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            say(wr, format!("start: {e}\r\n")).await;
            return 1;
        }
    };
    let stdin = child.stdin.take();
    let (stdout, stderr) = (child.stdout.take().expect("piped"), child.stderr.take().expect("piped"));
    // The input goes to the command until the client's EOF or the command
    // exits, even once its output is closed: `docker load >/dev/null 2>&1`
    // still reads all of it.
    let input = async move {
        let mut stdin = stdin;
        while let Some(data) = next_data(rd).await {
            if let Some(s) = &mut stdin
                && s.write_all(&data).await.is_err()
            {
                stdin = None;
            }
        }
    };
    // Drain the output before waiting, so a fast command's output isn't
    // lost; the input side may still be waiting on the client.
    let exited = async {
        tokio::join!(pump(stdout, wr.make_writer()), pump(stderr, wr.make_writer_ext(Some(1))));
        child.wait().await
    };
    exit_code(drain(exited, input).await)
}

fn exit_code(status: io::Result<ExitStatus>) -> u32 {
    let Ok(s) = status else { return 1 };
    if let Some(sig) = killed_by(&s) {
        return 128 + sig as u32;
    }
    s.code().map_or(255, |c| c as u32)
}

/// The signal that ended the process, if one did.
#[cfg(unix)]
fn killed_by(s: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    s.signal()
}

/// None: there are no signals here.
#[cfg(not(unix))]
fn killed_by(_: &ExitStatus) -> Option<i32> {
    None
}

#[cfg(unix)]
mod pty {
    use std::ffi::CStr;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use std::{mem, ptr};

    use russh::{ChannelReadHalf, Pty};
    use tokio::io::AsyncWriteExt;
    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;

    use super::{INTERACTIVE_MOTD, Input, Plan, PtyReq, Writer, drain, exit_code, next_input, say};

    /// The path of the terminal open on `fd`.
    fn tty_name(fd: RawFd) -> Option<String> {
        let mut buf = [0 as libc::c_char; 256];
        // SAFETY: ttyname_r writes a NUL-terminated name within `buf`.
        let r = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) };
        (r == 0).then(|| unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned())
    }

    /// Once the command exits, output stops when the terminal has had
    /// nothing to read for this long...
    const DRAIN_IDLE: Duration = Duration::from_millis(100);
    /// ...or after this much more, from background jobs still writing.
    const DRAIN_MAX: usize = 256 << 10;
    /// How long a command has to exit after the client hangs up before
    /// it's killed.
    const HANGUP_GRACE: Duration = Duration::from_secs(3);

    /// The terminal's UTF-8 input mode flag, where there is one.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const IUTF8: libc::tcflag_t = libc::IUTF8;
    /// No flag: setting or clearing it changes nothing.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const IUTF8: libc::tcflag_t = 0;

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
            let mut t: libc::termios = mem::zeroed();
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
                    Pty::IUTF8 => set(&mut t.c_iflag, IUTF8),
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

    async fn write_all(fd: &AsyncFd<File>, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n = fd.async_io(Interest::WRITABLE, |mut f| f.write(data)).await?;
            data = &data[n..];
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
        let r =
            unsafe { libc::openpty(&mut master, &mut slave, ptr::null_mut(), ptr::null_mut(), ptr::addr_of_mut!(ws)) };
        if r != 0 {
            say(wr, format!("pty open: {}\r\n", io::Error::last_os_error())).await;
            return 1;
        }
        let (master, slave) = unsafe { (File::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        apply_modes(slave.as_raw_fd(), &req.modes);

        let motd = plan.motd;
        let mut cmd = plan.command();
        if let Some(name) = tty_name(slave.as_raw_fd()) {
            cmd.env("SSH_TTY", name);
        }
        let (Ok(i), Ok(o), Ok(e)) = (slave.try_clone(), slave.try_clone(), slave.try_clone()) else {
            say(wr, "pty dup failed\r\n").await;
            return 1;
        };
        cmd.stdin(i).stdout(o).stderr(e);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // We keep `slave` open until the output is drained: some systems
        // (macOS) discard what's left in the terminal when the last slave
        // descriptor closes, as it does when the command exits.
        let mut child = match cmd.kill_on_drop(true).spawn() {
            Ok(c) => c,
            Err(e) => {
                say(wr, format!("start: {e}\r\n")).await;
                return 1;
            }
        };
        // The session leader's pid, which is also its process group's.
        let pid = child.id().expect("running") as libc::pid_t;
        unsafe {
            let fl = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        let master = match AsyncFd::new(master) {
            Ok(m) => m,
            Err(e) => {
                say(wr, format!("pty: {e}\r\n")).await;
                let _ = child.kill().await;
                return 1;
            }
        };
        let resize = |(c, r)| unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &winsize(c, r)) };
        let mut out_w = wr.make_writer();
        if motd {
            let _ = out_w.write_all(INTERACTIVE_MOTD.as_bytes()).await;
        }
        // Set once the command is reaped, and its pid may be reused.
        let reaped = AtomicBool::new(false);
        // Copies the terminal's output to the client until the command
        // exits and what it left is drained, returning its exit status.
        let output = async {
            let mut buf = vec![0u8; 16 << 10];
            let (mut status, mut budget) = (None, DRAIN_MAX);
            loop {
                let read = master.async_io(Interest::READABLE, |mut f| f.read(&mut buf));
                let r = if status.is_none() {
                    tokio::select! {
                        r = read => r,
                        st = child.wait() => {
                            reaped.store(true, Ordering::Relaxed);
                            status = Some(st);
                            continue;
                        }
                    }
                } else {
                    match tokio::time::timeout(DRAIN_IDLE, read).await {
                        Ok(r) => r,
                        Err(_) => break,
                    }
                };
                let Ok(n @ 1..) = r else { break };
                if out_w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                let _ = out_w.flush().await;
                if status.is_some() {
                    budget = budget.saturating_sub(n);
                    if budget == 0 {
                        break;
                    }
                }
            }
            let st = match status {
                Some(st) => st,
                None => child.wait().await,
            };
            reaped.store(true, Ordering::Relaxed);
            st
        };
        let input = async {
            loop {
                tokio::select! {
                    input = next_input(rd) => match input {
                        Input::Data(data) => {
                            let _ = write_all(&master, &data).await;
                        }
                        Input::Eof => {}
                        Input::Closed => break,
                    },
                    Some(ws) = winch.recv() => {
                        resize(ws);
                    }
                }
            }
            // The client is gone: hang up, as closing the terminal would,
            // signalling the session and the terminal's foreground job.
            if !reaped.load(Ordering::Relaxed) {
                let fg = unsafe { libc::tcgetpgrp(master.as_raw_fd()) };
                for pg in [pid, fg] {
                    if pg > 0 {
                        unsafe { libc::kill(-pg, libc::SIGHUP) };
                    }
                }
            }
            // A session leader that outlives the hangup has nobody to talk
            // to; its background jobs keep what they chose (as with nohup).
            tokio::time::sleep(HANGUP_GRACE).await;
            if !reaped.load(Ordering::Relaxed) {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        };
        let status = drain(output, input).await;
        drop(slave);
        exit_code(status)
    }
}

pub(crate) struct User {
    pub name: String,
    pub home: String,
    pub uid: u32,
}

/// The user this process runs as, from the password database, else the
/// environment.
#[cfg(unix)]
pub(crate) fn current_user() -> User {
    use std::ffi::CStr;

    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            let name = CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned();
            let home = CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
            return User { name, home, uid };
        }
        User { name: env::var("USER").unwrap_or_default(), home: env::var("HOME").unwrap_or_else(|_| "/".into()), uid }
    }
}

/// The user this process runs as, from the environment.
#[cfg(not(unix))]
pub(crate) fn current_user() -> User {
    User { name: env::var("USERNAME").unwrap_or_default(), home: env::var("USERPROFILE").unwrap_or_default(), uid: 1 }
}

/// The user's login shell: PowerShell.
#[cfg(windows)]
fn login_shell(_: &User) -> String {
    "powershell.exe".into()
}

/// The user's login shell: from the directory service, else $SHELL, else
/// /bin/sh (as the Go implementation does).
#[cfg(target_os = "macos")]
fn login_shell(u: &User) -> String {
    use std::process::Command;

    if let Ok(out) = Command::new("dscl").args([".", "-read", &format!("/Users/{}", u.name), "UserShell"]).output()
        && let Some(s) = String::from_utf8_lossy(&out.stdout).strip_prefix("UserShell: ")
    {
        return s.trim().to_string();
    }
    env_shell()
}

/// The user's login shell: $SHELL, else /bin/sh (as the Go
/// implementation does).
#[cfg(not(any(windows, target_os = "macos")))]
fn login_shell(_: &User) -> String {
    env_shell()
}

/// $SHELL, else /bin/sh.
#[cfg(not(windows))]
fn env_shell() -> String {
    env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into())
}

/// SSH_CLIENT and SSH_CONNECTION, as OpenSSH's sshd sets them. Scripts
/// check them to tell a remote session, and NixOS's /etc/bashrc to set
/// up a non-interactive shell's PATH.
fn ssh_env(local: SocketAddr, remote: SocketAddr) -> [(String, String); 2] {
    let (lip, lport, rip, rport) = (local.ip(), local.port(), remote.ip(), remote.port());
    [
        ("SSH_CLIENT".into(), format!("{rip} {rport} {lport}")),
        ("SSH_CONNECTION".into(), format!("{rip} {rport} {lip} {lport}")),
    ]
}

fn default_path(u: &User) -> &'static str {
    if u.uid == 0 {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    } else {
        "/usr/local/bin:/usr/bin:/bin"
    }
}

#[cfg(test)]
mod tests {
    use std::env::temp_dir;
    use std::fs;
    use std::process::Command;
    use std::time::Duration;

    use futures::future::join_all;
    use russh::client;
    use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key};
    use russh_sftp::client::SftpSession;
    use tokio::io::duplex;
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::key::{NodePrivate, NodePublic};
    use crate::ssh::{FileServeMode, FileService, SshOptions, pkcs8_ed25519_pem};

    type Conn = client::Handle<Client>;
    type ClientChannel = Channel<client::Msg>;

    fn test_key(seed: u8) -> PrivateKey {
        decode_secret_key(&pkcs8_ed25519_pem(&[seed; 32]), None).unwrap()
    }

    fn signer(seed: u8) -> PrivateKeyWithHashAlg {
        PrivateKeyWithHashAlg::new(Arc::new(test_key(seed)), None)
    }

    /// The tunnel identity of every test client.
    fn peer_key() -> NodePublic {
        NodePrivate::from_bytes([9; 32]).public()
    }

    struct Client;

    impl client::Handler for Client {
        type Error = russh::Error;
        async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// Serves `opts` on one end of an in-memory pipe, connecting a client
    /// to the other; the peer's tunnel identity is `peer_key()`.
    async fn connect(opts: SshOptions) -> Conn {
        connect_with(opts, client::Config::default()).await
    }

    async fn connect_with(opts: SshOptions, config: client::Config) -> Conn {
        let peer = peer_key();
        let shared = Arc::new(Shared::new(Arc::new(move |_| Some(peer)), opts, test_key(1)).unwrap());
        let (a, b) = duplex(1 << 16);
        let local = "[fd7a:115c:a1e0::1]:22".parse().unwrap();
        let remote = "[fd7a:115c:a1e0::2]:4242".parse().unwrap();
        tokio::spawn(shared.serve(a, local, remote));
        client::connect_stream(Arc::new(config), b, Client).await.unwrap()
    }

    async fn login(opts: SshOptions) -> Conn {
        login_with(opts, client::Config::default()).await
    }

    async fn login_with(opts: SshOptions, config: client::Config) -> Conn {
        let mut h = connect_with(opts, config).await;
        assert!(h.authenticate_none("u").await.unwrap().success());
        h
    }

    async fn open_session(h: &Conn) -> ClientChannel {
        h.channel_open_session().await.unwrap()
    }

    /// Opens a session that asks for the `name` subsystem.
    async fn open_subsystem(h: &Conn, name: &str) -> ClientChannel {
        let ch = open_session(h).await;
        ch.request_subsystem(true, name).await.unwrap();
        ch
    }

    async fn request_pty(ch: &ClientChannel) {
        ch.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    }

    /// Options offering the user's login shell.
    fn shell() -> SshOptions {
        SshOptions { shell: true, ..Default::default() }
    }

    /// Options forcing every session to run `script` with /bin/sh, which
    /// unlike the user's login shell every test machine has.
    fn sh(script: &str) -> SshOptions {
        SshOptions { exec: ["/bin/sh", "-c", script].map(String::from).to_vec(), ..Default::default() }
    }

    /// Parses the first complete line `pids <a> <b>…` in `out`.
    #[cfg(unix)]
    fn parse_pids(out: &str) -> Option<Vec<libc::pid_t>> {
        let i = out.find("pids ")?;
        let (line, _) = out[i..].split_once('\n')?;
        Some(line.split_whitespace().skip(1).map(|p| p.parse().unwrap()).collect())
    }

    /// Reads a channel's output until it holds a line `pids <a> <b>…`.
    #[cfg(unix)]
    async fn read_pids(ch: &mut ClientChannel) -> Vec<libc::pid_t> {
        let mut out = String::new();
        loop {
            let Some(msg) = ch.wait().await else { panic!("no pids in {out:?}") };
            if let ChannelMsg::Data { data } = msg {
                out.push_str(&String::from_utf8_lossy(&data));
            }
            if let Some(pids) = parse_pids(&out) {
                return pids;
            }
        }
    }

    /// Polls `cond` until it holds, reporting whether it did in time.
    async fn wait_for(within: Duration, cond: impl Fn() -> bool) -> bool {
        let poll = async {
            while !cond() {
                sleep(Duration::from_millis(20)).await;
            }
        };
        timeout(within, poll).await.is_ok()
    }

    /// Reports whether this machine (or sandbox) has PTYs.
    #[cfg(unix)]
    fn have_pty() -> bool {
        use std::ptr::null_mut;

        let (mut m, mut s) = (-1, -1);
        if unsafe { libc::openpty(&mut m, &mut s, null_mut(), null_mut(), null_mut()) } != 0 {
            return false;
        }
        unsafe { libc::close(m) + libc::close(s) == 0 }
    }

    /// Reports whether process `pid` is gone (reaped, not a zombie).
    #[cfg(unix)]
    fn is_gone(pid: libc::pid_t) -> bool {
        unsafe { libc::kill(pid, 0) != 0 }
    }

    #[derive(Debug, Default)]
    struct Output {
        out: String,
        err: String,
        code: Option<u32>,
    }

    /// Runs `cmd` on a prepared channel, sending `input` then EOF.
    async fn run(ch: ClientChannel, cmd: &str, input: &[u8]) -> Output {
        ch.exec(true, cmd).await.unwrap();
        run_started(ch, input).await
    }

    /// Sends `input` then EOF to a started session, and collects its output.
    async fn run_started(ch: ClientChannel, input: &[u8]) -> Output {
        ch.data(input).await.unwrap();
        ch.eof().await.unwrap();
        collect(ch).await
    }

    /// Collects a session's output until the channel closes.
    async fn collect(mut ch: ClientChannel) -> Output {
        let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
        while let Some(m) = ch.wait().await {
            match m {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => err.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                _ => {}
            }
        }
        let text = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
        Output { out: text(out), err: text(err), code }
    }

    /// Shell sessions run the user's login shell in their home, which a
    /// build sandbox's user may lack.
    fn have_shell() -> bool {
        let u = current_user();
        let status = Command::new(login_shell(&u)).args(["-c", "true"]).current_dir(&u.home).status();
        status.is_ok_and(|s| s.success())
    }

    /// Where `cmd` is on this process's PATH.
    fn which(cmd: &str) -> Option<String> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).map(|d| d.join(cmd)).find(|p| p.is_file()).map(|p| p.display().to_string())
    }

    fn pubkey_line(k: &PrivateKey) -> String {
        k.public_key().to_openssh().unwrap()
    }

    #[tokio::test]
    async fn authorized_keys_gate_logins() {
        let opts = SshOptions { authorized_keys: vec![pubkey_line(&test_key(2))], ..Default::default() };
        let mut h = connect(opts).await;
        assert!(!h.authenticate_none("u").await.unwrap().success());
        assert!(!h.authenticate_publickey("u", signer(3)).await.unwrap().success());
        assert!(h.authenticate_publickey("u", signer(2)).await.unwrap().success());
    }

    #[tokio::test]
    async fn no_keys_means_no_auth() {
        login(SshOptions::default()).await;
    }

    #[tokio::test]
    async fn shell_exec_over_pipes() {
        if !have_shell() {
            return;
        }
        let h = login(shell()).await;
        let ch = open_session(&h).await;
        ch.set_env(true, "LC_TEST", "yes").await.unwrap();
        ch.set_env(true, "EVIL", "no").await.unwrap();

        // Builtins only: sessions get a fixed PATH, which on some systems
        // (NixOS, a build sandbox) holds no coreutils.
        let script = "echo \"$TAILCAT_PEER_KEY $LC_TEST [$EVIL]\"; echo \"$SSH_CLIENT|$SSH_CONNECTION|$SSH_TTY\"; \
                      read -r l; echo \"$l\"; echo oops >&2; exit 3";
        let o = run(ch, script, b"in\n").await;

        let ssh = "fd7a:115c:a1e0::2 4242 22|fd7a:115c:a1e0::2 4242 fd7a:115c:a1e0::1 22|";
        assert_eq!(o.out, format!("{} yes []\n{ssh}\nin\n", peer_key()));
        assert_eq!(o.err, "oops\n");
        assert_eq!(o.code, Some(3));

        // A command killed by a signal reports 128 + the signal number.
        let o = run(open_session(&h).await, "kill -9 $$", b"").await;
        assert_eq!(o.code, Some(128 + 9));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_exec_on_a_pty() {
        if !have_shell() {
            return;
        }
        let h = login(shell()).await;
        let ch = open_session(&h).await;
        request_pty(&ch).await;
        // A resize before the session starts replaces the requested size.
        ch.window_change(100, 50, 0, 0).await.unwrap();

        // By absolute path, for the same reason.
        let (Some(stty), Some(tty)) = (which("stty"), which("tty")) else {
            return;
        };
        let script =
            format!("{stty} size; echo $TERM; {tty} -s && echo tty; [ \"$SSH_TTY\" = \"$({tty})\" ] && echo named");
        let o = run(ch, &script, b"").await;

        if o.err.starts_with("pty open:") || o.err.starts_with("start:") {
            return; // No PTYs in this sandbox.
        }
        assert_eq!(o.out, "50 100\r\nxterm\r\ntty\r\nnamed\r\n");
        assert_eq!(o.code, Some(0));
    }

    /// A command that closes its output before reading its input still
    /// gets all of it, and its exit status arrives.
    #[tokio::test]
    async fn pipes_feed_a_command_with_closed_output() {
        let h = login(sh("exec >/dev/null 2>&1; test \"$(wc -c)\" -eq 100000")).await;
        let ch = open_session(&h).await;
        ch.exec(true, "x").await.unwrap();
        // Let the command close its output first.
        sleep(Duration::from_millis(300)).await;

        let o = timeout(Duration::from_secs(10), run_started(ch, &[b'x'; 100_000])).await;

        assert_eq!(o.expect("the session hung").code, Some(0));
    }

    /// Ends a session by closing its channel, or by disconnecting.
    #[cfg(unix)]
    async fn hang_up(h: &Conn, ch: &ClientChannel, disconnect: bool) {
        if disconnect {
            h.disconnect(russh::Disconnect::ByApplication, "", "").await.unwrap();
        } else {
            ch.close().await.unwrap();
        }
    }

    /// Hanging up a PTY session, by closing its channel or by going away
    /// altogether, ends the command (and its background jobs), even one
    /// that ignores the hangup.
    #[cfg(unix)]
    #[tokio::test]
    async fn pty_sessions_end_when_the_client_goes() {
        if !have_pty() {
            return;
        }
        let dir = temp_dir().join(format!("tailcat-hup-{}", hex::encode(rand::random::<[u8; 8]>())));
        fs::create_dir(&dir).unwrap();
        // The background job notes its hangup in a file: once orphaned, it
        // may linger as a zombie where nothing reaps orphans. It reports
        // the shell's pid ($$ in a subshell) once it's ready.
        let with_job = |name: &str| {
            let marker = dir.join(name);
            let trap = format!("trap 'echo > {}; exit' HUP", marker.display());
            (format!("({trap}; echo pids $$; while :; do sleep 0.1; done) & wait"), Some(marker))
        };
        let ignores_hup = "trap '' HUP; echo pids $$; while :; do sleep 1; done".to_string();
        let cases = [(with_job("close"), false), (with_job("disconnect"), true), ((ignores_hup, None), false)];
        for ((script, marker), disconnect) in cases {
            let h = login(sh(&script)).await;
            let mut ch = open_session(&h).await;
            request_pty(&ch).await;
            ch.exec(true, "x").await.unwrap();
            let pids = timeout(Duration::from_secs(10), read_pids(&mut ch)).await.unwrap();

            hang_up(&h, &ch, disconnect).await;

            // Gone means reaped, by the session.
            let ended = wait_for(Duration::from_secs(10), || is_gone(pids[0])).await;
            assert!(ended, "{script:?} (disconnect: {disconnect}): shell still running");
            if let Some(m) = marker {
                assert!(wait_for(Duration::from_secs(10), || m.exists()).await, "{script:?}: no hangup for the job");
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Runs a PTY command that writes `size` bytes and exits, for a client
    /// that takes nothing until a second after.
    #[cfg(unix)]
    async fn slow_pty_output(size: usize) -> (usize, Output) {
        let config = client::Config { window_size: 2048, channel_buffer_size: 1, ..Default::default() };
        let script = format!("head -c {size} /dev/zero | tr '\\0' x; echo END");
        let h = login_with(sh(&script), config).await;
        let ch = open_session(&h).await;
        request_pty(&ch).await;
        ch.exec(true, "x").await.unwrap();
        // Take nothing while the command writes and exits.
        sleep(Duration::from_secs(1)).await;
        let o = timeout(Duration::from_secs(10), collect(ch)).await.unwrap();
        (size, o)
    }

    /// Output still in the PTY when the command exits reaches a client
    /// that's slow to take it.
    #[cfg(unix)]
    #[tokio::test]
    async fn pty_output_outlasts_the_command() {
        if !have_pty() {
            return;
        }
        // How much of the output is still on its way when the command
        // exits depends on the platform's PTY buffering, so try a few sizes.
        let sizes = [500, 1000, 2000, 3000, 4000, 6000, 8000];

        let runs = join_all(sizes.map(slow_pty_output)).await;

        for (size, o) in runs {
            let tail = &o.out[o.out.len().saturating_sub(20)..];
            assert_eq!(o.out.len(), size + "END\r\n".len(), "{size} bytes, got {} ending {tail:?}", o.out.len());
            assert!(o.out.ends_with("xEND\r\n"), "{tail:?}");
            assert_eq!(o.code, Some(0));
        }
    }

    #[tokio::test]
    async fn forced_command_gets_original_command() {
        let opts = SshOptions {
            // Both are overridden by the forced command.
            shell: true,
            files: Some(FileService { dir: "/".into(), mode: FileServeMode::ReadOnly }),
            ..sh("echo \"$SSH_ORIGINAL_COMMAND|$TAILCAT_REMOTE_ADDR\"; cat")
        };
        let h = login(opts).await;

        let o = run(open_session(&h).await, "ls -la /", b"piped\n").await;
        assert_eq!(o.out, "ls -la /|[fd7a:115c:a1e0::2]:4242\npiped\n");
        assert_eq!(o.code, Some(0));

        let mut sftp = open_subsystem(&h, "sftp").await;
        assert!(matches!(sftp.wait().await, Some(ChannelMsg::Failure)));
    }

    #[tokio::test]
    async fn file_service_refuses_shells_but_serves_sftp() {
        let files = FileService { dir: temp_dir(), mode: FileServeMode::ReadOnly };
        let h = login(SshOptions { files: Some(files), ..Default::default() }).await;

        let o = run(open_session(&h).await, "id", b"").await;
        assert!(o.err.contains("only offers file transfer"), "{o:?}");
        assert_eq!(o.code, Some(1));

        let mut unknown = open_subsystem(&h, "nope").await;
        assert!(matches!(unknown.wait().await, Some(ChannelMsg::Failure)));

        let ch = open_subsystem(&h, "sftp").await;
        let sftp = SftpSession::new(ch.into_stream()).await.unwrap();
        assert!(sftp.metadata(".").await.unwrap().is_dir());
        assert_eq!(sftp.canonicalize("../..").await.unwrap(), "/");
    }

    #[cfg(unix)]
    #[test]
    fn exit_codes() {
        let exit_7 = Command::new("/bin/sh").args(["-c", "exit 7"]).status();
        assert_eq!(exit_code(exit_7), 7);
        assert_eq!(exit_code(Err(io::Error::other("x"))), 1);
    }

    #[test]
    fn accepted_env() {
        for accepted in ["TERM", "LANG", "LC_ALL"] {
            assert!(accept_env(accepted), "{accepted}");
        }
        for refused in ["PATH", "LD_PRELOAD", "LANGUAGE"] {
            assert!(!accept_env(refused), "{refused}");
        }
    }
}
