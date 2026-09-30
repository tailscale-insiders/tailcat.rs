//! Where peers' node records come from.

use std::collections::{BTreeMap, HashMap, HashSet};
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
    /// Artifacts already fetched, by ID, so oldest first: their run, and
    /// their admitted record, if any.
    seen: BTreeMap<u64, (String, Option<NodeRecord>)>,
}

impl GithubSource {
    pub fn new(env: GithubEnv, scope: Scope, name_prefix: String, audience_prefix: String) -> Self {
        GithubSource { env, scope, name_prefix, audience_prefix, verifier: None, seen: BTreeMap::new() }
    }

    /// Uses `v` to check OIDC tokens instead of fetching GitHub's keys.
    pub fn with_verifier(mut self, v: Verifier) -> Self {
        self.verifier = Some(v);
        self
    }

    async fn poll(&mut self) -> Result<impl Iterator<Item = &NodeRecord>> {
        let runs = match self.scope {
            Scope::Run => vec![(self.env.run_id.clone(), self.env.run_attempt.clone())],
            s => github::sibling_runs(&self.env, s).await?,
        };
        for (run, _) in &runs {
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
                    && r.jwt.is_some()
                    && self.verifier.is_none()
                {
                    self.verifier = Some(Verifier::fetch().await?);
                }
                // A token is checked as of the upload, which GitHub dates.
                let published = a.uploaded().unwrap_or_else(unix_now);
                let admitted = rec.and_then(|r| {
                    let (v, prefix) = (self.verifier.as_ref(), &self.audience_prefix);
                    github::admit(&r, run, &self.env, self.scope, v, prefix, published)?;
                    Ok(r)
                });
                // Not retried: artifacts don't change.
                let admitted = admitted.inspect_err(|e| warn!("not admitting artifact {}: {e:#}", a.name)).ok();
                self.seen.insert(a.id, (run.clone(), admitted));
            }
        }
        // Only the attempt each run in progress is on: a finished run's
        // nodes are gone, and so are an earlier attempt's. That's checked
        // here, not when an artifact is first seen, since a run can be
        // re-run between polls. Run scope admits records that name no
        // attempt, as `admit` does. Oldest artifact first, so the result
        // doesn't depend on the order artifacts were listed in.
        let scope = self.scope;
        let current = move |run: &str, r: &NodeRecord| {
            runs.iter().any(|(id, attempt)| {
                id == run && (r.run_attempt == *attempt || scope == Scope::Run && r.run_attempt.is_empty())
            })
        };
        Ok(self.seen.values().filter_map(move |(run, r)| r.as_ref().filter(|r| current(run, r))))
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
        let records = dedup(found.iter().map(|(_, r)| r));
        self.last = found.into_iter().collect();
        Ok(records)
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

/// The time now, in Unix seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Keeps one record per node key, the first.
fn dedup<'a>(rs: impl IntoIterator<Item = &'a NodeRecord>) -> Vec<NodeRecord> {
    let mut seen = HashSet::new();
    rs.into_iter().filter(|r| seen.insert(r.nodekey)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Cursor, Write as _};
    use std::slice;
    use std::sync::{Arc, Mutex};

    use serde_json::{Value, json};
    use tailcat::NodePublic;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;
    use crate::github::tests::{P, Signer, genv, rec};

    type Routes = dyn Fn(&str, &str, usize) -> (u16, Vec<u8>) + Send + Sync;

    /// How many requests there have been for each path.
    type Hits = Arc<Mutex<HashMap<String, usize>>>;

    const RUN_100_ARTIFACTS: &str = "/repos/o/r/actions/runs/100/artifacts?per_page=100&page=1";
    const RUN_99_ARTIFACTS: &str = "/repos/o/r/actions/runs/99/artifacts?per_page=100&page=1";
    const RUNS_IN_PROGRESS: &str =
        "/repos/o/r/actions/workflows/mesh.yml/runs?status=in_progress&per_page=50&branch=main";

    /// A record file caught while it's being written.
    const HALF_WRITTEN: &[u8] = b"{\"index\": ";

    /// A fake GitHub API at the returned URL: `routes(base, path, n)`
    /// answers the `n`th request for `path`. Hits are counted by path.
    async fn fake_github(routes: Box<Routes>) -> (String, Hits) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits = Hits::default();
        let routes = Arc::<Routes>::from(routes);
        let (b, h) = (base.clone(), hits.clone());
        tokio::spawn(async move {
            loop {
                let (conn, _) = listener.accept().await.unwrap();
                tokio::spawn(serve(conn, b.clone(), h.clone(), routes.clone()));
            }
        });
        (base, hits)
    }

    /// Answers one request on `conn` from `routes`.
    async fn serve(mut conn: TcpStream, base: String, hits: Hits, routes: Arc<Routes>) {
        let Some(path) = request_path(&mut conn).await else { return };
        let n = count(&hits, &path);
        let (status, body) = routes(&base, &path, n);
        let head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = conn.write_all(&[head.as_bytes(), &body].concat()).await;
    }

    /// Reads a request's head, and returns the path it asks for.
    async fn request_path(conn: &mut TcpStream) -> Option<String> {
        let mut req = Vec::new();
        let mut buf = [0; 4096];
        while !req.ends_with(b"\r\n\r\n") {
            let n = conn.read(&mut buf).await.ok().filter(|&n| n > 0)?;
            req.extend_from_slice(&buf[..n]);
        }
        let path = String::from_utf8_lossy(&req).split(' ').nth(1).expect("a request line").to_string();
        Some(path)
    }

    /// Counts a request for `path`, and returns how many there have been.
    fn count(hits: &Hits, path: &str) -> usize {
        let mut hits = hits.lock().unwrap();
        let n = hits.entry(path.into()).or_default();
        *n += 1;
        *n
    }

    /// Serves `path` from `bodies`, or 404s.
    fn download(bodies: &HashMap<String, Vec<u8>>, path: &str) -> (u16, Vec<u8>) {
        bodies.get(path).map_or((404, Vec::new()), |b| (200, b.clone()))
    }

    /// A run's artifacts, `(id, name, expired)`, each downloaded from
    /// /dl/`id`.
    fn artifacts(base: &str, list: &[(u64, &str, bool)]) -> Vec<u8> {
        let artifact = |&(id, name, expired): &(u64, &str, bool)| {
            let url = format!("{base}/dl/{id}");
            json!({"id": id, "name": name, "expired": expired, "archive_download_url": url})
        };
        let list: Vec<Value> = list.iter().map(artifact).collect();
        serde_json::to_vec(&json!({ "artifacts": list })).unwrap()
    }

    fn zipped(name: &str, b: &[u8]) -> Vec<u8> {
        let mut z = ZipWriter::new(Cursor::new(Vec::new()));
        z.start_file(name, SimpleFileOptions::default()).unwrap();
        z.write_all(b).unwrap();
        z.finish().unwrap().into_inner()
    }

    fn github(base: String, scope: Scope, prefix: &str) -> GithubSource {
        GithubSource::new(GithubEnv { api_url: base, ..genv() }, scope, prefix.into(), P.into())
    }

    fn keys<'a>(v: impl IntoIterator<Item = &'a NodeRecord>) -> HashSet<NodePublic> {
        v.into_iter().map(|r| r.nodekey).collect()
    }

    fn bodies<const N: usize>(b: [(&str, Vec<u8>); N]) -> HashMap<String, Vec<u8>> {
        b.map(|(p, b)| (p.to_string(), b)).into()
    }

    fn body(r: &NodeRecord) -> Vec<u8> {
        serde_json::to_vec(r).unwrap()
    }

    async fn poll(src: &mut Source) -> Vec<NodeRecord> {
        src.poll().await.unwrap()
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
        let listing = [
            (1, "node-1-0", false),
            (2, "node-1-1", false),
            (3, "other", false),
            (4, "node-1-2", false),
            (5, "node-1-3", true),
            (6, "node-1-4", false),
            (7, "node-1-5", false),
        ];
        let (base, hits) = fake_github(Box::new(move |base, path, n| match path {
            RUN_100_ARTIFACTS => (200, artifacts(base, &listing)),
            "/dl/6" if n == 1 => (500, Vec::new()),
            p => download(&bodies, p),
        }))
        .await;
        let mut src = Source::github(github(base, Scope::Run, "node-1-"));

        // The flaky download is retried; everything else is fetched once.
        let first = poll(&mut src).await;
        assert_eq!(keys(&first), keys([&plain, &zip]));
        let second = poll(&mut src).await;
        assert_eq!(keys(&second), keys([&plain, &zip, &flaky]));

        // 3 isn't a node's and 5 has expired, so neither is fetched.
        let hits = hits.lock().unwrap();
        let fetched = |p: &str| hits.get(p).copied().unwrap_or(0);
        for (p, n) in [("/dl/1", 1), ("/dl/2", 1), ("/dl/3", 0), ("/dl/4", 1), ("/dl/5", 0), ("/dl/6", 2), ("/dl/7", 1)]
        {
            assert_eq!(fetched(p), n, "{p}");
        }
    }

    #[tokio::test]
    async fn github_branch_scope() {
        let s = Signer::new();
        // We're run 100's second attempt, and its first left a record.
        let ours = s.rec(json!({"run_attempt": "2"}));
        let earlier = s.rec(json!({}));
        let sibling = s.rec(json!({"run_id": "99"}));
        let rerun = s.rec(json!({"run_id": "99", "run_attempt": "2"}));
        let untokened = rec("1");
        let misfiled = s.rec(json!({})); // a token for run 100 in run 99's artifacts
        let bodies = bodies([
            ("/dl/1", body(&ours)),
            ("/dl/2", body(&sibling)),
            ("/dl/3", body(&untokened)),
            ("/dl/4", body(&misfiled)),
            ("/dl/5", body(&earlier)),
            ("/dl/6", body(&rerun)),
        ]);
        let (base, _) = fake_github(Box::new(move |base, path, n| match path {
            // Run 99 is re-run after the first poll, and finishes after the
            // second. The list leaves our run out at first.
            RUNS_IN_PROGRESS => {
                let runs = match n {
                    1 => json!([{"id": 99, "run_attempt": 1}]),
                    2 => json!([{"id": 99, "run_attempt": 2}, {"id": 100, "run_attempt": 2}]),
                    _ => json!([]),
                };
                (200, serde_json::to_vec(&json!({ "workflow_runs": runs })).unwrap())
            }
            RUN_100_ARTIFACTS => (200, artifacts(base, &[(1, "node-2-0", false), (5, "node-1-0", false)])),
            RUN_99_ARTIFACTS => {
                let mut list = vec![(2, "node-1-0", false), (3, "node-1-1", false), (4, "node-2-0", false)];
                if n > 1 {
                    list.push((6, "node-2-1", false));
                }
                (200, artifacts(base, &list))
            }
            p => download(&bodies, p),
        }))
        .await;
        let env = GithubEnv { api_url: base, run_attempt: "2".into(), ..genv() };
        let g = GithubSource::new(env, Scope::Branch, "node-".into(), P.into()).with_verifier(s.verifier());
        let mut src = Source::github(g);

        let first = poll(&mut src).await;
        assert_eq!(keys(&first), keys([&ours, &sibling]), "our run's earlier attempt's records are dropped");
        let second = poll(&mut src).await;
        assert_eq!(keys(&second), keys([&ours, &rerun]), "a re-run run's earlier attempt's records are dropped");
        let third = poll(&mut src).await;
        assert_eq!(keys(&third), keys([&ours]), "a finished run's records are dropped");
    }

    /// A node that starts late still admits a record whose token was
    /// valid when it was uploaded, as GitHub dates the upload.
    #[tokio::test]
    async fn github_tokens_count_as_of_their_upload() {
        let s = Signer::new();
        // Both tokens lapsed at 2023-11-14T22:13:20Z.
        let (early, late) = (s.rec(json!({"exp": 1_700_000_000})), s.rec(json!({"exp": 1_700_000_000})));
        let bodies = bodies([("/dl/1", body(&early)), ("/dl/2", body(&late))]);
        let (base, _) = fake_github(Box::new(move |base, path, _| match path {
            RUN_100_ARTIFACTS => {
                let artifact = |id: u64, created: &str| {
                    let url = format!("{base}/dl/{id}");
                    json!({"id": id, "name": format!("node-{id}"), "archive_download_url": url, "created_at": created})
                };
                let list = [artifact(1, "2023-11-14T22:00:00Z"), artifact(2, "2023-11-14T22:30:00Z")];
                (200, serde_json::to_vec(&json!({ "artifacts": list })).unwrap())
            }
            p => download(&bodies, p),
        }))
        .await;
        let mut src = Source::github(github(base, Scope::Run, "node-").with_verifier(s.verifier()));

        assert_eq!(keys(&poll(&mut src).await), keys([&early]));
    }

    #[tokio::test]
    async fn github_api_errors_fail_the_poll() {
        let (base, _) = fake_github(Box::new(|_, _, _| (403, b"{}".to_vec()))).await;
        let mut src = Source::github(github(base, Scope::Run, "node-"));
        let err = src.poll().await.unwrap_err();
        assert!(format!("{err:#}").contains("listing artifacts of run 100"), "{err:#}");
    }

    #[tokio::test]
    async fn dirs_and_files() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();
        let (a, b) = (rec("1"), rec("1"));
        let write = |name: &str, r: &NodeRecord| r.write(&dir.join(name)).unwrap();
        write("a.json", &a);
        write("b.json", &b);
        write("c.txt", &rec("1")); // not *.json
        write("d.json", &NodeRecord { index: 9, ..a.clone() }); // a duplicate key
        fs::write(dir.join("e.json"), HALF_WRITTEN).unwrap();

        let listed = poll(&mut Source::dir(dir.into())).await;
        assert_eq!(listed, [a, b.clone()], "sorted by file name, first record per key wins");
        let named = poll(&mut Source::files(vec![dir.join("missing.json"), dir.join("b.json")])).await;
        assert_eq!(named, [b]);
        let missing = poll(&mut Source::dir(dir.join("missing"))).await;
        assert!(missing.is_empty());
    }

    /// A record file caught half-written still gives its last record; one
    /// that's gone gives nothing, in a directory or named.
    #[tokio::test]
    async fn unreadable_files_keep_their_record() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (rec("1"), rec("1"));
        let (pa, pb) = (d.path().join("a.json"), d.path().join("b.json"));
        for mut src in [Source::dir(d.path().into()), Source::files(vec![pa.clone(), pb.clone()])] {
            a.write(&pa).unwrap();
            b.write(&pb).unwrap();
            assert_eq!(poll(&mut src).await, [a.clone(), b.clone()]);

            fs::write(&pa, HALF_WRITTEN).unwrap();
            assert_eq!(poll(&mut src).await, [a.clone(), b.clone()], "a is half-written");

            fs::remove_file(&pb).unwrap();
            assert_eq!(poll(&mut src).await, slice::from_ref(&a), "b is gone");

            let a2 = NodeRecord { index: 7, ..a.clone() };
            a2.write(&pa).unwrap();
            assert_eq!(poll(&mut src).await, [a2], "a is rewritten");
        }
    }
}
