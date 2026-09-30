//! Where peers' node records come from.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::{debug, warn};

use crate::github::{self, GithubEnv, Scope, Verifier};
use crate::record::NodeRecord;

/// A source of node records, polled repeatedly as nodes come up.
pub struct Source {
    kind: Kind,
    /// The last record read from each file, for polls that find it
    /// half-written.
    last: HashMap<PathBuf, NodeRecord>,
}

enum Kind {
    /// Every `*.json` file in a directory.
    Dir(PathBuf),
    /// Specific files.
    Files(Vec<PathBuf>),
    /// GitHub Actions run artifacts.
    Github(Box<GithubSource>),
}

/// Polls GitHub Actions artifacts for node records.
pub struct GithubSource {
    pub env: GithubEnv,
    pub scope: Scope,
    /// Artifact names must start with this (for example `node-<attempt>-`).
    pub name_prefix: String,
    pub audience_prefix: String,
    verifier: Option<Verifier>,
    /// Artifacts already fetched, by ID: their run, and their admitted
    /// record, if any.
    seen: HashMap<u64, (String, Option<NodeRecord>)>,
}

impl GithubSource {
    pub fn new(env: GithubEnv, scope: Scope, name_prefix: String, audience_prefix: String) -> Self {
        GithubSource { env, scope, name_prefix, audience_prefix, verifier: None, seen: HashMap::new() }
    }

    /// Uses `v` to check OIDC tokens instead of fetching GitHub's keys.
    pub fn with_verifier(mut self, v: Verifier) -> Self {
        self.verifier = Some(v);
        self
    }

    async fn poll(&mut self) -> Result<Vec<NodeRecord>> {
        let runs = match self.scope {
            Scope::Run => vec![self.env.run_id.clone()],
            s => github::sibling_runs(&self.env, s).await?,
        };
        for run in &runs {
            for a in github::list_artifacts(&self.env, run).await? {
                if !a.name.starts_with(&self.name_prefix) || self.seen.contains_key(&a.id) {
                    continue;
                }
                let body = match github::download(&self.env, &a).await {
                    Ok(b) => b,
                    Err(e) => {
                        debug!("artifact {}: {e:#}", a.name);
                        continue; // retried next poll
                    }
                };
                let rec = NodeRecord::from_json(&body);
                if let Ok(r) = &rec
                    && !r.jwt.is_empty()
                    && self.verifier.is_none()
                {
                    self.verifier = Some(Verifier::fetch().await?);
                }
                let admitted = rec.and_then(|r| {
                    github::admit(&r, run, &self.env, self.scope, self.verifier.as_ref(), &self.audience_prefix)?;
                    Ok(r)
                });
                // Not retried: artifacts don't change.
                let admitted = admitted.inspect_err(|e| warn!("not admitting artifact {}: {e:#}", a.name)).ok();
                self.seen.insert(a.id, (run.clone(), admitted));
            }
        }
        // Only runs still in progress: a finished run's nodes are gone.
        // Oldest artifact first, so the result doesn't depend on hashing.
        let mut live: Vec<(u64, &NodeRecord)> = self
            .seen
            .iter()
            .filter(|(_, (run, _))| runs.contains(run))
            .filter_map(|(id, (_, r))| Some((*id, r.as_ref()?)))
            .collect();
        live.sort_by_key(|(id, _)| *id);
        Ok(live.into_iter().map(|(_, r)| r.clone()).collect())
    }
}

impl Source {
    /// Every `*.json` file in a directory.
    pub fn dir(d: PathBuf) -> Source {
        Source { kind: Kind::Dir(d), last: HashMap::new() }
    }

    /// Specific files.
    pub fn files(fs: Vec<PathBuf>) -> Source {
        Source { kind: Kind::Files(fs), last: HashMap::new() }
    }

    /// GitHub Actions run artifacts.
    pub fn github(g: GithubSource) -> Source {
        Source { kind: Kind::Github(Box::new(g)), last: HashMap::new() }
    }

    /// Returns every admitted record of a node still there, one per node
    /// key. Each poll is the whole truth: a record it leaves out is gone,
    /// and so is its peer. A record file that can't be read for now (for
    /// example while it's being written) still counts as its last good
    /// record; one that no longer exists doesn't.
    pub async fn poll(&mut self) -> Result<Vec<NodeRecord>> {
        let paths = match &mut self.kind {
            Kind::Github(g) => return Ok(dedup(g.poll().await?)),
            Kind::Files(fs) => fs.clone(),
            Kind::Dir(d) => match std::fs::read_dir(&*d) {
                Ok(rd) => {
                    let mut ps: Vec<PathBuf> = rd
                        .filter_map(|e| Some(e.ok()?.path()))
                        .filter(|p| p.extension().is_some_and(|x| x == "json"))
                        .collect();
                    ps.sort();
                    ps
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e.into()),
            },
        };
        let mut found = Vec::new();
        for p in paths {
            let r = match read(&p) {
                Ok(r) => r,
                Err(e) => {
                    // Half-written, say: it'll be read again next poll.
                    debug!("{}: {e:#}", p.display());
                    self.last.get(&p).cloned()
                }
            };
            found.extend(r.map(|r| (p, r)));
        }
        self.last = found.iter().cloned().collect();
        Ok(dedup(found.into_iter().map(|(_, r)| r).collect()))
    }
}

/// Reads a record file, or `None` if there's no such file.
fn read(p: &Path) -> Result<Option<NodeRecord>> {
    match std::fs::read(p) {
        Ok(b) => NodeRecord::from_json(&b).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Keeps one record per node key.
fn dedup(v: Vec<NodeRecord>) -> Vec<NodeRecord> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|r| seen.insert(r.nodekey)).collect()
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::{Arc, Mutex};

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::github::tests::{P, Signer, genv, rec};

    type Routes = dyn Fn(&str, &str, usize) -> (u16, Vec<u8>) + Send + Sync;

    /// A fake GitHub API at the returned URL: `routes(base, path, n)`
    /// answers the `n`th request for `path`. Hits are counted by path.
    async fn fake_github(routes: Box<Routes>) -> (String, Arc<Mutex<HashMap<String, usize>>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let hits = Arc::new(Mutex::new(HashMap::new()));
        let (b, h, routes) = (base.clone(), hits.clone(), Arc::<Routes>::from(routes));
        tokio::spawn(async move {
            loop {
                let (mut c, _) = l.accept().await.unwrap();
                let (b, h, routes) = (b.clone(), h.clone(), routes.clone());
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    while !req.ends_with(b"\r\n\r\n") {
                        let mut buf = [0; 4096];
                        match c.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let path = String::from_utf8_lossy(&req).split(' ').nth(1).unwrap().to_string();
                    let n = *h.lock().unwrap().entry(path.clone()).and_modify(|n| *n += 1).or_insert(1);
                    let (status, body) = routes(&b, &path, n);
                    let head =
                        format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = c.write_all(&[head.as_bytes(), &body].concat()).await;
                });
            }
        });
        (base, hits)
    }

    fn artifacts(base: &str, list: &[(u64, &str, bool)]) -> Vec<u8> {
        let a: Vec<_> = list
            .iter()
            .map(|&(id, name, expired)| {
                json!({"id": id, "name": name, "expired": expired, "archive_download_url": format!("{base}/dl/{id}")})
            })
            .collect();
        serde_json::to_vec(&json!({ "artifacts": a })).unwrap()
    }

    fn zipped(name: &str, b: &[u8]) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        z.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(b).unwrap();
        z.finish().unwrap().into_inner()
    }

    fn github(base: String, scope: Scope, prefix: &str) -> GithubSource {
        GithubSource::new(GithubEnv { api_url: base, ..genv() }, scope, prefix.into(), P.into())
    }

    fn keys(v: &[NodeRecord]) -> HashSet<tailcat::NodePublic> {
        v.iter().map(|r| r.nodekey).collect()
    }

    fn bodies<const N: usize>(b: [(&str, Vec<u8>); N]) -> HashMap<String, Vec<u8>> {
        b.map(|(p, b)| (p.to_string(), b)).into()
    }

    fn body(r: &NodeRecord) -> Vec<u8> {
        serde_json::to_vec(r).unwrap()
    }

    #[tokio::test]
    async fn github_run_scope() {
        let (plain, zip, flaky, stale) = (rec("1"), rec("1"), rec("1"), rec("2"));
        let bodies = bodies([
            ("/dl/1", body(&plain)),
            ("/dl/2", zipped("node-1-1.json", &body(&zip))),
            ("/dl/4", b"{not json".to_vec()),
            ("/dl/6", body(&flaky)),
            ("/dl/7", body(&stale)),
        ]);
        let (base, hits) = fake_github(Box::new(move |base, path, n| match path {
            "/repos/o/r/actions/runs/100/artifacts?per_page=100&page=1" => (
                200,
                artifacts(
                    base,
                    &[
                        (1, "node-1-0", false),
                        (2, "node-1-1", false),
                        (3, "other", false),
                        (4, "node-1-2", false),
                        (5, "node-1-3", true),
                        (6, "node-1-4", false),
                        (7, "node-1-5", false),
                    ],
                ),
            ),
            "/dl/6" if n == 1 => (500, Vec::new()),
            p => bodies.get(p).map_or((404, Vec::new()), |b| (200, b.clone())),
        }))
        .await;
        let mut src = Source::github(github(base, Scope::Run, "node-1-"));

        // The flaky download is retried; everything else is fetched once.
        assert_eq!(keys(&src.poll().await.unwrap()), keys(&[plain.clone(), zip.clone()]));
        assert_eq!(keys(&src.poll().await.unwrap()), keys(&[plain, zip, flaky]));
        let hits = hits.lock().unwrap();
        for (p, n) in [("/dl/1", 1), ("/dl/2", 1), ("/dl/4", 1), ("/dl/6", 2), ("/dl/7", 1)] {
            assert_eq!(hits.get(p), Some(&n), "{p}");
        }
        assert!(!hits.contains_key("/dl/3") && !hits.contains_key("/dl/5"), "{hits:?}");
    }

    #[tokio::test]
    async fn github_branch_scope() {
        let s = Signer::new();
        let ours = s.rec(json!({}));
        let sibling = s.rec(json!({"run_id": "99"}));
        let untokened = rec("1");
        let misfiled = s.rec(json!({})); // a token for run 100 in run 99's artifacts
        let bodies = bodies([
            ("/dl/1", body(&ours)),
            ("/dl/2", body(&sibling)),
            ("/dl/3", body(&untokened)),
            ("/dl/4", body(&misfiled)),
        ]);
        let (base, _) = fake_github(Box::new(move |base, path, n| match path {
            // Run 99 finishes after the first poll.
            "/repos/o/r/actions/workflows/mesh.yml/runs?status=in_progress&per_page=50&branch=main" if n == 1 => {
                (200, br#"{"workflow_runs": [{"id": 99}]}"#.to_vec())
            }
            "/repos/o/r/actions/workflows/mesh.yml/runs?status=in_progress&per_page=50&branch=main" => {
                (200, br#"{"workflow_runs": []}"#.to_vec())
            }
            "/repos/o/r/actions/runs/100/artifacts?per_page=100&page=1" => {
                (200, artifacts(base, &[(1, "node-1-0", false)]))
            }
            "/repos/o/r/actions/runs/99/artifacts?per_page=100&page=1" => {
                (200, artifacts(base, &[(2, "node-1-0", false), (3, "node-1-1", false), (4, "node-2-0", false)]))
            }
            p => bodies.get(p).map_or((404, Vec::new()), |b| (200, b.clone())),
        }))
        .await;
        let mut src = Source::github(github(base, Scope::Branch, "node-").with_verifier(s.verifier()));
        assert_eq!(keys(&src.poll().await.unwrap()), keys(&[ours.clone(), sibling]));
        assert_eq!(keys(&src.poll().await.unwrap()), keys(&[ours]), "a finished run's records are dropped");
    }

    #[tokio::test]
    async fn github_api_errors_fail_the_poll() {
        let (base, _) = fake_github(Box::new(|_, _, _| (403, b"{}".to_vec()))).await;
        let err = Source::github(github(base, Scope::Run, "node-")).poll().await.unwrap_err();
        assert!(format!("{err:#}").contains("listing artifacts of run 100"), "{err:#}");
    }

    #[tokio::test]
    async fn dirs_and_files() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (rec("1"), rec("1"));
        let write = |name: &str, r: &NodeRecord| r.write(&d.path().join(name)).unwrap();
        write("a.json", &a);
        write("b.json", &b);
        write("c.txt", &rec("1")); // not *.json
        write("d.json", &NodeRecord { index: 9, ..a.clone() }); // a duplicate key
        std::fs::write(d.path().join("e.json"), b"{\"index\": ").unwrap(); // half-written

        let got = Source::dir(d.path().into()).poll().await.unwrap();
        assert_eq!(got, [a.clone(), b.clone()], "sorted by file name, first record per key wins");
        let got = Source::files(vec![d.path().join("missing.json"), d.path().join("b.json")]).poll().await.unwrap();
        assert_eq!(got, [b]);
        assert!(Source::dir(d.path().join("missing")).poll().await.unwrap().is_empty());
    }

    /// A record file caught half-written still gives its last record; one
    /// that's gone gives nothing, in a directory or named.
    #[tokio::test]
    async fn unreadable_files_keep_their_record() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (rec("1"), rec("1"));
        let (pa, pb) = (d.path().join("a.json"), d.path().join("b.json"));
        a.write(&pa).unwrap();
        b.write(&pb).unwrap();
        for mut src in [Source::dir(d.path().into()), Source::files(vec![pa.clone(), pb.clone()])] {
            a.write(&pa).unwrap();
            b.write(&pb).unwrap();
            assert_eq!(src.poll().await.unwrap(), [a.clone(), b.clone()]);
            std::fs::write(&pa, b"{\"index\": ").unwrap();
            assert_eq!(src.poll().await.unwrap(), [a.clone(), b.clone()], "a is half-written");
            std::fs::remove_file(&pb).unwrap();
            assert_eq!(src.poll().await.unwrap(), std::slice::from_ref(&a), "b is gone");
            let a2 = NodeRecord { index: 7, ..a.clone() };
            a2.write(&pa).unwrap();
            assert_eq!(src.poll().await.unwrap(), [a2], "a is rewritten");
        }
    }
}
