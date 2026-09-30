//! Destination arguments: a tailcat address, or a DNS name whose
//! `tailcat=` TXT record holds one.

use anyhow::{Result, anyhow, bail};
use tailcat::Addr;

/// How a destination argument should be interpreted.
#[derive(Debug, PartialEq, Eq)]
pub enum AddrArg {
    Addr(Addr),
    Dns(String),
}

/// Classifies `arg` without any lookup. It refuses DNS-looking input
/// that contains a valid tailcat address as a label, so that pasting an
/// address with a stray dot can't leak it in a DNS query.
pub fn classify(arg: &str) -> Result<AddrArg> {
    let a = Addr::new(arg);
    if a.parse().is_ok() {
        return Ok(AddrArg::Addr(a));
    }
    if !arg.contains('.') {
        bail!("argument {arg:?} is neither a valid tailcat address nor a DNS name");
    }
    let name = arg.trim_end_matches('.');
    if name.split('.').any(|l| Addr::new(l).parse().is_ok()) {
        bail!("argument contains a valid tailcat address as a DNS label; refusing DNS lookup");
    }
    validate_dns_name(name).map_err(|e| anyhow!("invalid DNS name {arg:?}: {e}"))?;
    Ok(AddrArg::Dns(arg.to_string()))
}

/// Validates the conservative ASCII hostname syntax accepted for lookups.
pub fn validate_dns_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() {
        return Err("name is empty".into());
    }
    if name.len() > 253 {
        return Err("name is longer than 253 bytes".into());
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("name contains an empty label".into());
        }
        if label.len() > 63 {
            return Err("name contains a label longer than 63 bytes".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("name contains a label beginning or ending with a hyphen".into());
        }
        if let Some(c) = label.chars().find(|c| !(c.is_ascii_alphanumeric() || *c == '-')) {
            return Err(format!("name contains invalid character {c:?}"));
        }
    }
    Ok(())
}

/// Looks up the `tailcat=` TXT record of `name`.
pub async fn lookup_txt(name: &str) -> Result<Addr> {
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .and_then(|b| b.build())
        .map_err(|e| anyhow!("DNS resolver: {e}"))?;
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), resolver.txt_lookup(name))
        .await
        .map_err(|_| anyhow!("looking up TXT record for {name:?}: timeout"))?
        .map_err(|e| anyhow!("looking up TXT record for {name:?}: {e}"))?;
    for rec in res.answers() {
        let hickory_resolver::proto::rr::RData::TXT(txt) = &rec.data else { continue };
        let s: String = txt.txt_data.iter().map(|d| String::from_utf8_lossy(d)).collect();
        if let Some(v) = s.strip_prefix("tailcat=") {
            return Ok(Addr::new(v.trim()));
        }
    }
    bail!("no \"tailcat=\" TXT record found for {name:?}")
}

/// Resolves a destination argument to an address, looking up TXT
/// records for DNS names.
pub async fn tailcat_addr_arg(arg: &str) -> Result<Addr> {
    match classify(arg)? {
        AddrArg::Addr(a) => Ok(a),
        AddrArg::Dns(n) => lookup_txt(&n).await,
    }
}

/// Like [`tailcat_addr_arg`], also reporting whether it came from DNS.
#[cfg(feature = "ssh")]
pub async fn validated_addr(arg: &str) -> Result<(Addr, bool)> {
    let via_dns = arg.contains('.');
    let a = if via_dns { tailcat_addr_arg(arg).await? } else { Addr::new(arg) };
    a.parse().map_err(|e| anyhow!("invalid tailcat address {arg:?}: {e}"))?;
    Ok((a, via_dns))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu";

    #[test]
    fn classifies() {
        assert!(matches!(classify(ADDR).unwrap(), AddrArg::Addr(_)));
        assert_eq!(classify("example.com").unwrap(), AddrArg::Dns("example.com".into()));
        // A fully qualified name keeps its dot for the lookup.
        assert_eq!(classify("example.com.").unwrap(), AddrArg::Dns("example.com.".into()));

        let addr_dot = format!("{ADDR}.");
        let addr_label = format!("{ADDR}.example.com");
        for bad in ["nonsense", &addr_dot, &addr_label, "bad_name.com", "-x.com", "a..b"] {
            assert!(classify(bad).is_err(), "{bad:?} classified");
        }
    }

    #[test]
    fn dns_names() {
        assert!(validate_dns_name("a-b.example.com").is_ok());
        assert!(validate_dns_name(&format!("{}.com", "a".repeat(63))).is_ok());
        let cases: [(&str, &str); 8] = [
            ("", "name is empty"),
            (&format!("{}.com", "a".repeat(64)), "longer than 63"),
            (&vec!["a".repeat(60); 5].join("."), "longer than 253"),
            ("x.-a", "hyphen"),
            ("a-.x", "hyphen"),
            ("a.b.", "empty label"),
            ("caf\u{e9}.fr", "invalid character '\u{e9}'"),
            ("a b.c", "invalid character ' '"),
        ];
        for (name, want) in cases {
            let e = validate_dns_name(name).unwrap_err();
            assert!(e.contains(want), "{name:?}: {e}");
        }
    }

    #[cfg(feature = "ssh")]
    #[tokio::test]
    async fn validated_addrs() {
        let (a, via_dns) = validated_addr(ADDR).await.unwrap();
        assert_eq!((a.as_str(), via_dns), (ADDR, false));

        let e = validated_addr("tcnope").await.unwrap_err();
        assert!(e.to_string().contains("invalid tailcat address"), "{e}");
    }
}
