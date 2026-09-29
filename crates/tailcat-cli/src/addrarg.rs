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
        if let Some(c) = label.bytes().find(|c| !(c.is_ascii_alphanumeric() || *c == b'-')) {
            return Err(format!("name contains invalid character {:?}", c as char));
        }
    }
    Ok(())
}

/// Looks up the `tailcat=` TXT record of `name`.
pub async fn lookup_txt(name: &str) -> Result<Addr> {
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|e| anyhow!("DNS resolver: {e}"))?
        .build()
        .map_err(|e| anyhow!("DNS resolver: {e}"))?;
    let fut = resolver.txt_lookup(name);
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), fut)
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
        assert!(classify("nonsense").is_err());
        assert!(classify(&format!("{ADDR}.")).is_err());
        assert!(classify(&format!("{ADDR}.example.com")).is_err());
        assert!(classify("bad_name.com").is_err());
        assert!(classify("-x.com").is_err());
    }
}
