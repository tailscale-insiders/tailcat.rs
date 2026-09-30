//! Command-line argument grammars shared by the `tailcat` and
//! `tailcat-device` commands. Each parses an argument's text into the
//! library type it chooses; the library's types know nothing of how a
//! command spells them.

use std::fmt;
use std::str::FromStr;

use tailcat::{Host, RegionChoice};

/// A `--region` argument: `list`, to list the regions instead of
/// choosing one, or a [`RegionChoice`]: `auto` for the nearest region,
/// a region ID, comma-separated hostnames of one's own DERP servers
/// (each with a dot), or a region code or part of a region's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionArg {
    List,
    Choice(RegionChoice),
}

impl FromStr for RegionArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty DERP region".into());
        }
        if s.eq_ignore_ascii_case("list") {
            return Ok(RegionArg::List);
        }
        let choice = if s.eq_ignore_ascii_case("auto") {
            RegionChoice::Nearest
        } else if let Ok(id) = s.parse() {
            RegionChoice::Id(id)
        } else if !s.contains('.') {
            RegionChoice::Named(s.into())
        } else {
            let hosts: Vec<&str> = s.split(',').map(str::trim).collect();
            if hosts.iter().any(|h| h.is_empty()) {
                return Err(format!("empty hostname in DERP region {s:?}"));
            }
            RegionChoice::Custom(hosts.into_iter().map(Host::from).collect())
        };
        Ok(RegionArg::Choice(choice))
    }
}

/// What `--region list` is instead of a [`RegionChoice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListsRegions;

impl fmt::Display for ListsRegions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("'list' lists the DERP regions rather than choosing one")
    }
}

impl std::error::Error for ListsRegions {}

impl TryFrom<RegionArg> for RegionChoice {
    type Error = ListsRegions;

    fn try_from(a: RegionArg) -> Result<RegionChoice, ListsRegions> {
        match a {
            RegionArg::Choice(c) => Ok(c),
            RegionArg::List => Err(ListsRegions),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_args() {
        let arg = |s: &str| s.parse::<RegionArg>();
        let choice = |c| Ok(RegionArg::Choice(c));
        assert_eq!(arg("auto"), choice(RegionChoice::Nearest));
        assert_eq!(arg(" AUTO "), choice(RegionChoice::Nearest));
        assert_eq!(arg("list"), Ok(RegionArg::List));
        assert_eq!(arg("302"), choice(RegionChoice::Id(302)));
        assert_eq!(arg("-1"), choice(RegionChoice::Id(-1)));
        assert_eq!(arg("sfo"), choice(RegionChoice::Named("sfo".into())));
        assert_eq!(arg("San Francisco"), choice(RegionChoice::Named("San Francisco".into())));
        let hosts = RegionChoice::Custom(vec!["a.example".into(), "b.example".into()]);
        assert_eq!(arg("a.example, b.example"), choice(hosts));
        assert!(arg("").is_err());
        assert!(arg("a.example,").is_err());
    }

    #[test]
    fn only_choices_convert() {
        assert_eq!(RegionChoice::try_from(RegionArg::Choice(RegionChoice::Nearest)), Ok(RegionChoice::Nearest));
        assert_eq!(RegionChoice::try_from(RegionArg::List), Err(ListsRegions));
    }
}
