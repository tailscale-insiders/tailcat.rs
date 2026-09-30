//! How the command's flags spell things, parsed into the library's
//! types. Grammars `tailcat-device` shares are in `tailcat-args`.

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

#[cfg(test)]
mod tests {
    use tailcat::NodePrivate;

    use super::*;

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
