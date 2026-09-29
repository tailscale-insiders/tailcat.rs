//! An on-disk DERP map cache in `$CACHE/tailcat`, shared with the Go
//! implementation: each URL gets `derpmap-<query-escaped URL>.json`,
//! whose mtime is the stored-at time, and a parallel `.etag` file. A
//! `.lock` file keeps the two consistent between tailcat.rs processes.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
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

/// A URL's cache files in `dir`: the body, the ETag, and a lock file.
fn paths(dir: &Path, url: &str) -> [PathBuf; 3] {
    let base = format!("derpmap-{}", query_escape(url));
    ["json", "etag", "lock"].map(|ext| dir.join(format!("{base}.{ext}")))
}

/// An advisory lock on a URL's cache entry, held until dropped. The body
/// and ETag are separate files (the Go implementation's format), so
/// without it a reader could pair one fetch's body with another's ETag,
/// and then revalidate the stale body as current.
struct Lock {
    _file: std::fs::File,
}

impl Lock {
    /// Locks `path`, shared or exclusive; `None` if it can't, and then
    /// the cache goes unlocked.
    fn new(path: &Path, exclusive: bool) -> Option<Lock> {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path).ok()?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let op = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
            if unsafe { libc::flock(file.as_raw_fd(), op) } != 0 {
                return None;
            }
        }
        #[cfg(not(unix))]
        let _ = exclusive;
        Some(Lock { _file: file })
    }
}

fn get(dir: &Path, url: &str) -> Option<(Vec<u8>, String, SystemTime)> {
    let [data, etag, lock] = paths(dir, url);
    let _lock = Lock::new(&lock, false);
    let mut f = std::fs::File::open(&data).ok()?;
    let mtime = f.metadata().ok()?.modified().ok()?;
    let mut d = Vec::new();
    f.read_to_end(&mut d).ok()?;
    let e = std::fs::read_to_string(&etag).map(|s| s.trim().to_string()).unwrap_or_default();
    Some((d, e, mtime))
}

fn put(dir: &Path, url: &str, data: &[u8], etag: &str) {
    let [dp, ep, lock] = paths(dir, url);
    let _ = std::fs::create_dir_all(dir);
    let _lock = Lock::new(&lock, true);
    // Each file is replaced whole, for readers that don't lock (the Go
    // implementation). The old ETag goes first, so a failure leaves none
    // rather than a mismatched one. Rewriting the body bumps its mtime,
    // restarting the freshness window.
    let _ = std::fs::remove_file(&ep);
    if crate::util::replace_private(&dp, data).is_ok() && !etag.is_empty() {
        let _ = crate::util::replace_private(&ep, etag.as_bytes());
    }
}

impl DerpMapCache for DiskDerpMapCache {
    fn get(&self, url: &str) -> Option<(Vec<u8>, String, SystemTime)> {
        get(&crate::util::user_cache_dir()?.join("tailcat"), url)
    }

    fn put(&self, url: &str, data: &[u8], etag: &str) {
        if let Some(dir) = crate::util::user_cache_dir() {
            put(&dir.join("tailcat"), url, data, etag);
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

    #[test]
    fn stores_body_and_etag() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://example.com/derpmap.json";
        assert!(super::get(dir.path(), url).is_none());
        super::put(dir.path(), url, b"{}", "\"v1\"");
        let (d, e, _) = super::get(dir.path(), url).unwrap();
        assert_eq!((d.as_slice(), e.as_str()), (&b"{}"[..], "\"v1\""));
        super::put(dir.path(), url, b"{ }", "");
        let (d, e, _) = super::get(dir.path(), url).unwrap();
        assert_eq!((d.as_slice(), e.as_str()), (&b"{ }"[..], ""));
    }

    /// Racing processes each store their own fetch, and a reader always
    /// sees one fetch's body with that fetch's ETag (or none), never
    /// another's.
    #[cfg(unix)]
    #[test]
    fn body_and_etag_stay_paired() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://example.com/derpmap.json";
        let body = |i: usize| format!("{{\"fetch\": {i}, \"pad\": \"{}\"}}", "x".repeat(i * 1000));
        super::put(dir.path(), url, body(0).as_bytes(), "\"0\"");
        let stop = std::sync::atomic::AtomicBool::new(false);
        let check = || {
            let (d, e, _) = super::get(dir.path(), url).ok_or("no cache entry")?;
            let i = (0..=4).find(|&i| d == body(i).as_bytes()).ok_or("torn body")?;
            if !e.is_empty() && e != format!("\"{i}\"") {
                return Err(format!("body of fetch {i} with ETag {e}"));
            }
            Ok(())
        };
        let res = std::thread::scope(|s| {
            for w in 1..=2 {
                let (dir, stop) = (dir.path(), &stop);
                s.spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        for i in [w, w + 2] {
                            super::put(dir, url, body(i).as_bytes(), &format!("\"{i}\""));
                        }
                    }
                });
            }
            let res = (0..2000).try_for_each(|_| check());
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            res
        });
        res.unwrap();
    }
}
