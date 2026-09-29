//! An on-disk DERP map cache in `$CACHE/tailcat`, shared with the Go
//! implementation: each URL gets `derpmap-<query-escaped URL>.json`,
//! whose mtime is the stored-at time, and a parallel `.etag` file.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::SystemTime;

use tailcat::{DerpMapCache, FetchMode, FetchOptions};

use crate::Global;

pub struct DiskDerpMapCache;

/// Options for fetching the DERP map named by --derpmap-url through the
/// disk cache.
pub fn fetch_options(g: &Global, mode: FetchMode) -> FetchOptions<'_> {
    FetchOptions { url: Some(&g.derpmap_url), mode, cache: Some(&DiskDerpMapCache) }
}

/// Go's `url.QueryEscape`.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => _ = write!(out, "%{b:02X}"),
        }
    }
    out
}

impl DiskDerpMapCache {
    fn paths(url: &str) -> Option<(PathBuf, PathBuf)> {
        let dir = crate::util::user_cache_dir()?.join("tailcat");
        let base = format!("derpmap-{}", query_escape(url));
        Some((dir.join(format!("{base}.json")), dir.join(format!("{base}.etag"))))
    }
}

impl DerpMapCache for DiskDerpMapCache {
    fn get(&self, url: &str) -> Option<(Vec<u8>, String, SystemTime)> {
        let (data, etag) = Self::paths(url)?;
        let mtime = std::fs::metadata(&data).ok()?.modified().ok()?;
        let d = std::fs::read(&data).ok()?;
        let e = std::fs::read_to_string(&etag).map(|s| s.trim().to_string()).unwrap_or_default();
        Some((d, e, mtime))
    }

    fn put(&self, url: &str, data: &[u8], etag: &str) {
        let Some((dp, ep)) = Self::paths(url) else { return };
        if let Some(dir) = dp.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Rewriting bumps the mtime, restarting the freshness window.
        let _ = std::fs::write(&dp, data);
        if etag.is_empty() {
            let _ = std::fs::remove_file(&ep);
        } else {
            let _ = std::fs::write(&ep, etag);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes_like_go() {
        assert_eq!(super::query_escape("https://tailcat.dev/derpmap.json"), "https%3A%2F%2Ftailcat.dev%2Fderpmap.json");
        assert_eq!(super::query_escape("a b?c=d&e~"), "a+b%3Fc%3Dd%26e~");
        assert_eq!(super::query_escape("é"), "%C3%A9");
    }
}
