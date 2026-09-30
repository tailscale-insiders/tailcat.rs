//! Command-line argument grammars shared by the `tailcat` and
//! `tailcat-device` commands. Each parses an argument's text into the
//! library type it chooses; the library's types know nothing of how a
//! command spells them.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

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

/// Parses a Go-style duration like "10s", "1m30s", "250ms" or "1.5h".
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    match s {
        "0" => return Ok(Duration::ZERO),
        "" => return Err("empty duration".into()),
        _ => {}
    }
    let is_num = |c: char| c.is_ascii_digit() || c == '.';
    let mut total = 0f64;
    let mut rest = s;
    while !rest.is_empty() {
        let (num, r) = rest.split_at(rest.find(|c| !is_num(c)).unwrap_or(rest.len()));
        let n: f64 = num.parse().map_err(|_| format!("invalid duration {s:?}"))?;
        let (unit, r) = r.split_at(r.find(is_num).unwrap_or(r.len()));
        rest = r;
        total += n * match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "" => return Err(format!("missing unit in duration {s:?}")),
            _ => return Err(format!("unknown unit {unit:?} in duration {s:?}")),
        };
    }
    Duration::try_from_secs_f64(total).map_err(|_| format!("duration {s:?} is out of range"))
}

#[cfg(test)]
mod tests {
    use hegel::TestCase;
    use hegel::generators as gs;

    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration(" 0 ").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("1h2m3.5s").unwrap(), Duration::from_millis(3_723_500));
        assert_eq!(parse_duration("5us").unwrap(), parse_duration("5µs").unwrap());
        assert_eq!(parse_duration("100ns").unwrap(), Duration::from_nanos(100));
        let huge = format!("{}h", "9".repeat(30));
        for bad in ["10", "x", "", "s", ".s", "1.2.3s", "5d", "-1s", "1s 2s", &huge] {
            assert!(parse_duration(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[hegel::test]
    fn parse_duration_never_panics(tc: TestCase) {
        // Mostly digits, to reach huge values, among the units.
        let s = tc.draw(gs::text().alphabet("0123456789.nuµmsh ").max_size(60));
        let _ = parse_duration(&s);
    }

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
