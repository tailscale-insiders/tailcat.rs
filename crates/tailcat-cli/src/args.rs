//! How the command's flags spell things, parsed into the library's
//! types. Grammars `tailcat-device` shares are in `tailcat-args`.

use std::fmt;
#[cfg(feature = "ssh")]
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use tailcat::{KeySet, NodePublic};

/// An `--allow` list: comma-separated node public keys, where `none`
/// adds none, so `--allow none` allows no clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowArg(pub Vec<NodePublic>);

impl FromStr for AllowArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let keys = s.split(',').filter(|&k| k != "none");
        keys.map(|k| k.parse().map_err(|e| format!("invalid key {k:?}: {e}"))).collect::<Result<_, _>>().map(AllowArg)
    }
}

impl From<AllowArg> for KeySet {
    fn from(a: AllowArg) -> KeySet {
        let set = KeySet::default();
        for k in a.0 {
            set.add(k);
        }
        set
    }
}

/// A `--key` argument: empty for the default saved key (or a fresh
/// one if there's none saved), `new` for a fresh ephemeral key, a path
/// to a key file (anything with a slash), or a saved key's name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum KeyArg {
    #[default]
    Default,
    New,
    Path(PathBuf),
    Named(String),
}

impl FromStr for KeyArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "" => KeyArg::Default,
            "new" => KeyArg::New,
            s if crate::keys::is_path(s) => KeyArg::Path(s.into()),
            s => KeyArg::Named(s.into()),
        })
    }
}

impl fmt::Display for KeyArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyArg::Default => Ok(()),
            KeyArg::New => f.write_str("new"),
            KeyArg::Path(p) => write!(f, "{}", p.display()),
            KeyArg::Named(n) => f.write_str(n),
        }
    }
}

/// Where `ssh -p` or `cp -P` connects through the server: a port on the
/// server, or an IP:port its exit node reaches, where a bare IP means
/// its port 22.
#[cfg(feature = "ssh")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshTarget {
    Port(u16),
    Via(SocketAddr),
}

#[cfg(feature = "ssh")]
impl FromStr for SshTarget {
    type Err = String;

    fn from_str(v: &str) -> Result<Self, String> {
        if let Ok(p @ 1..) = v.parse::<u16>() {
            return Ok(SshTarget::Port(p));
        }
        if let Ok(ip) = v.parse::<IpAddr>() {
            return Ok(SshTarget::Via(SocketAddr::new(ip, 22)));
        }
        match v.parse::<SocketAddr>() {
            Ok(a) if a.port() != 0 => Ok(SshTarget::Via(a)),
            _ => Err(format!("invalid port or IP:port {v:?}")),
        }
    }
}

#[cfg(feature = "ssh")]
impl fmt::Display for SshTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshTarget::Port(p) => write!(f, "{p}"),
            SshTarget::Via(a) => write!(f, "{a}"),
        }
    }
}

/// An `--ssh-authorized-keys` list: comma-separated sources of SSH
/// public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedKeysArg(pub Vec<KeySource>);

/// Where `--ssh-authorized-keys` gets some of its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// `<user>@github`: the user's keys on GitHub.
    Github(String),
    /// An authorized_keys file or a literal public key line, which one
    /// found when the keys are loaded.
    Local(String),
}

impl fmt::Display for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySource::Github(user) => write!(f, "{user}@github"),
            KeySource::Local(s) => f.write_str(s),
        }
    }
}

impl FromStr for AuthorizedKeysArg {
    type Err = String;

    fn from_str(list: &str) -> Result<Self, String> {
        let source = |(i, s): (usize, &str)| {
            let (n, s) = (i + 1, s.trim());
            match s.strip_suffix("@github") {
                _ if s.is_empty() => Err(format!("source {n} is empty")),
                Some(user) if !valid_github_user(user) => Err(format!("source {n}: invalid GitHub username {user:?}")),
                Some(user) => Ok(KeySource::Github(user.into())),
                None => Ok(KeySource::Local(s.into())),
            }
        };
        list.split(',').enumerate().map(source).collect::<Result<_, _>>().map(AuthorizedKeysArg)
    }
}

/// Whether `u` can be a GitHub username.
fn valid_github_user(u: &str) -> bool {
    let b = u.as_bytes();
    (1..=39).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// A `--files` argument: a directory, the current one if empty, and
/// how it's served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesArg {
    pub dir: PathBuf,
    pub mode: FilesMode,
}

/// How `--files` serves its directory, by its suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesMode {
    /// `:ro`, or no suffix.
    ReadOnly,
    /// `:rw`.
    ReadWrite,
    /// `:wo`: a flat write-only drop box.
    WriteOnly,
    /// `:wo+`: a recursive write-only drop box.
    WriteOnlyTree,
}

impl FilesMode {
    const SUFFIXES: [(&str, FilesMode); 4] = [
        (":ro", FilesMode::ReadOnly),
        (":rw", FilesMode::ReadWrite),
        (":wo+", FilesMode::WriteOnlyTree),
        (":wo", FilesMode::WriteOnly),
    ];

    /// What it's called when the server says what it serves.
    pub fn name(self) -> &'static str {
        match self {
            FilesMode::ReadOnly => "read-only",
            FilesMode::ReadWrite => "read-write",
            FilesMode::WriteOnly => "flat write-only",
            FilesMode::WriteOnlyTree => "recursive write-only",
        }
    }
}

#[cfg(feature = "ssh")]
impl From<FilesMode> for tailcat::ssh::FileServeMode {
    fn from(m: FilesMode) -> Self {
        match m {
            FilesMode::ReadOnly => Self::ReadOnly,
            FilesMode::ReadWrite => Self::ReadWrite,
            FilesMode::WriteOnly => Self::WriteOnly,
            FilesMode::WriteOnlyTree => Self::WriteOnlyTree,
        }
    }
}

impl FromStr for FilesArg {
    type Err = String;

    fn from_str(v: &str) -> Result<Self, String> {
        let (dir, mode) = FilesMode::SUFFIXES
            .into_iter()
            .find_map(|(suffix, mode)| Some((v.strip_suffix(suffix)?, mode)))
            .unwrap_or((v, FilesMode::ReadOnly));
        Ok(FilesArg { dir: if dir.is_empty() { ".".into() } else { dir.into() }, mode })
    }
}

/// A perf `--bytes` count: more than zero, with an optional K, M, or G
/// suffix (powers of 1000).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteCount(pub i64);

impl FromStr for ByteCount {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        parse_si(s).filter(|n| *n > 0).map(ByteCount).ok_or_else(|| format!("invalid byte count {s:?}"))
    }
}

/// A perf `--bitrate` in bits per second: zero for as fast as possible,
/// or more, with an optional K, M, or G suffix (powers of 1000).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bitrate(pub i64);

impl FromStr for Bitrate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        parse_si(s).filter(|n| *n >= 0).map(Bitrate).ok_or_else(|| format!("invalid bitrate {s:?}"))
    }
}

/// Parses a number with an optional K, M, or G (powers of 1000) suffix.
fn parse_si(s: &str) -> Option<i64> {
    let (num, mult) = match s.char_indices().last() {
        Some((i, 'k' | 'K')) => (&s[..i], 1e3),
        Some((i, 'm' | 'M')) => (&s[..i], 1e6),
        Some((i, 'g' | 'G')) => (&s[..i], 1e9),
        _ => (s, 1.0),
    };
    let v = num.parse::<f64>().ok()? * mult;
    (v.is_finite() && v <= i64::MAX as f64 && v >= i64::MIN as f64).then_some(v as i64)
}

#[cfg(test)]
mod tests {
    use tailcat::NodePrivate;

    use super::*;

    #[test]
    fn key_args() {
        for (s, want) in [
            ("", KeyArg::Default),
            ("new", KeyArg::New),
            ("./k.json", KeyArg::Path("./k.json".into())),
            ("foo", KeyArg::Named("foo".into())),
        ] {
            let k: KeyArg = s.parse().unwrap();
            assert_eq!((&k, k.to_string()), (&want, s.to_string()));
        }
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn ssh_targets() {
        let target = |s: &str| s.parse::<SshTarget>().map(|t| t.to_string());
        assert_eq!(target("22"), Ok("22".into()));
        assert_eq!(target("10.0.0.1"), Ok("10.0.0.1:22".into()));
        assert_eq!(target("[fd7a::1]:2222"), Ok("[fd7a::1]:2222".into()));
        for bad in ["0", "10.0.0.1:0", "host:22"] {
            assert!(target(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn authorized_keys_args() {
        let arg = |s: &str| s.parse::<AuthorizedKeysArg>().map(|a| a.0);
        let local = |s: &str| KeySource::Local(s.into());
        assert_eq!(arg("alice@github, keys"), Ok(vec![KeySource::Github("alice".into()), local("keys")]));
        assert_eq!(arg("ssh-ed25519 AAAA"), Ok(vec![local("ssh-ed25519 AAAA")]));
        assert_eq!(arg("keys,"), Err("source 2 is empty".into()));
        assert!(arg("-x@github").unwrap_err().contains("invalid GitHub username"));

        assert!(valid_github_user("bradfitz"));
        assert!(valid_github_user("a-b"));
        for bad in ["-x", "x-", "", &"a".repeat(40)] {
            assert!(!valid_github_user(bad), "{bad:?} is valid");
        }
    }

    #[test]
    fn files_args() {
        let arg = |s: &str| s.parse::<FilesArg>().unwrap();
        let files = |dir: &str, mode| FilesArg { dir: dir.into(), mode };
        assert_eq!(arg("/srv"), files("/srv", FilesMode::ReadOnly));
        assert_eq!(arg("/srv:ro"), files("/srv", FilesMode::ReadOnly));
        assert_eq!(arg("/srv:rw"), files("/srv", FilesMode::ReadWrite));
        assert_eq!(arg("/srv:wo"), files("/srv", FilesMode::WriteOnly));
        assert_eq!(arg("/srv:wo+"), files("/srv", FilesMode::WriteOnlyTree));
        assert_eq!(arg(":rw"), files(".", FilesMode::ReadWrite));
    }

    #[test]
    fn si_numbers() {
        assert_eq!(parse_si("10M"), Some(10_000_000));
        assert_eq!(parse_si("1.5G"), Some(1_500_000_000));
        assert_eq!(parse_si("2k"), Some(2_000));
        assert_eq!(parse_si("7"), Some(7));
        for bad in ["x", "", "M", "1e30G"] {
            assert_eq!(parse_si(bad), None, "{bad:?}");
        }
        assert_eq!("1K".parse(), Ok(ByteCount(1000)));
        assert!("0".parse::<ByteCount>().is_err(), "no bytes to send");
        assert_eq!("0".parse(), Ok(Bitrate(0)));
        assert!("-1".parse::<Bitrate>().is_err());
    }

    #[test]
    fn allow_args() {
        let (a, b) = (NodePrivate::generate().public(), NodePrivate::generate().public());
        assert_eq!(format!("{a},{b}").parse(), Ok(AllowArg(vec![a, b])));
        assert_eq!("none".parse(), Ok(AllowArg(vec![])));
        assert_eq!(format!("none,{a}").parse(), Ok(AllowArg(vec![a])));
        assert!("bogus".parse::<AllowArg>().is_err());
        assert!("".parse::<AllowArg>().is_err());

        let set = KeySet::from(AllowArg(vec![a]));
        assert!(set.contains(&a) && !set.contains(&b));
    }
}
