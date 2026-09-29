//! Where peers' node records come from.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::Result;
use tracing::{debug, warn};

use crate::github::{self, GithubEnv, Scope, Verifier};
use crate::record::NodeRecord;

/// A source of node records, polled repeatedly as nodes come up.
pub enum Source {
    /// Every `*.json` file in a directory.
    Dir(PathBuf),
    /// Specific files.
    Files(Vec<PathBuf>),
    /// GitHub Actions run artifacts.
    Github(GithubSource),
}

/// Polls GitHub Actions artifacts for node records.
pub struct GithubSource {
    pub env: GithubEnv,
    pub scope: Scope,
    /// Artifact names must start with this (for example `node-<attempt>-`).
    pub name_prefix: String,
    pub audience_prefix: String,
    verifier: Option<Verifier>,
    /// Artifacts already fetched, by ID: their admitted record, if any.
    seen: HashMap<u64, Option<NodeRecord>>,
}

impl GithubSource {
    pub fn new(env: GithubEnv, scope: Scope, name_prefix: String, audience_prefix: String) -> Self {
        GithubSource { env, scope, name_prefix, audience_prefix, verifier: None, seen: HashMap::new() }
    }

    async fn poll(&mut self) -> Result<Vec<NodeRecord>> {
        let runs = match self.scope {
            Scope::Run => vec![self.env.run_id.clone()],
            s => github::sibling_runs(&self.env, s).await?,
        };
        for run in runs {
            for a in github::list_artifacts(&self.env, &run).await? {
                if !a.name.starts_with(&self.name_prefix) || self.seen.contains_key(&a.id) {
                    continue;
                }
                let body = match github::download(&self.env, &a).await {
                    Ok(b) => b,
                    Err(e) => {
                        debug!("artifact {}: {e}", a.name);
                        continue; // retried next poll
                    }
                };
                let rec = match NodeRecord::from_json(&body) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("artifact {}: {e}", a.name);
                        self.seen.insert(a.id, None);
                        continue;
                    }
                };
                if !rec.jwt.is_empty() && self.verifier.is_none() {
                    self.verifier = Some(Verifier::fetch().await?);
                }
                match github::admit(&rec, &run, &self.env, self.scope, self.verifier.as_ref(), &self.audience_prefix) {
                    Ok(()) => {
                        self.seen.insert(a.id, Some(rec));
                    }
                    Err(e) => {
                        warn!("not admitting node {} from artifact {}: {e}", rec.index, a.name);
                        self.seen.insert(a.id, None);
                    }
                }
            }
        }
        Ok(self.seen.values().flatten().cloned().collect())
    }
}

impl Source {
    /// Returns every admitted record found so far.
    pub async fn poll(&mut self) -> Result<Vec<NodeRecord>> {
        match self {
            Source::Dir(d) => {
                let mut out = Vec::new();
                let rd = match std::fs::read_dir(&*d) {
                    Ok(rd) => rd,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
                    Err(e) => return Err(e.into()),
                };
                let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
                paths.sort();
                for p in paths {
                    if p.extension().is_some_and(|x| x == "json") {
                        read_into(&p, &mut out);
                    }
                }
                Ok(dedup(out))
            }
            Source::Files(fs) => {
                let mut out = Vec::new();
                for p in fs.iter() {
                    read_into(p, &mut out);
                }
                Ok(dedup(out))
            }
            Source::Github(g) => Ok(dedup(g.poll().await?)),
        }
    }
}

fn read_into(p: &std::path::Path, out: &mut Vec<NodeRecord>) {
    match std::fs::read(p) {
        // A record may be half-written; it'll be read again next poll.
        Ok(b) => match NodeRecord::from_json(&b) {
            Ok(r) => out.push(r),
            Err(e) => debug!("{}: {e}", p.display()),
        },
        Err(e) => debug!("{}: {e}", p.display()),
    }
}

/// Keeps one record per node key.
fn dedup(v: Vec<NodeRecord>) -> Vec<NodeRecord> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|r| seen.insert(r.nodekey)).collect()
}
