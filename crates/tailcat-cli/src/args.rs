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
