//! GitHub Actions integration: node records published as run artifacts,
//! and GitHub OIDC tokens that bind a node key to a repository, ref and
//! run.
//!
//! Run artifacts give integrity for free: only jobs in a run can upload
//! to it. So within one run ("run scope") a record is admitted just by
//! being there. Records from other runs ("branch" or "pr" scope) prove
//! nothing by existing, so they must carry an OIDC token whose audience
//! is the record's node key and whose claims match ours.

use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::record::{NodeRecord, audience_for};

/// GitHub's OIDC issuer.
pub const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Which records to admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Scope {
    /// Only this run and attempt's own artifacts (no tokens needed).
    Run,
    /// Any run of this workflow on the same repository and ref.
    Branch,
    /// Any run for the same pull request (ref refs/pull/N/merge).
    Pr,
}

/// The job's GitHub context, from the runner's environment.
#[derive(Debug, Clone)]
pub struct GithubEnv {
    pub api_url: String,
    pub repository: String,
    pub repository_id: String,
    pub run_id: String,
    pub run_attempt: String,
    pub git_ref: String,
    pub ref_name: String,
    pub head_ref: String,
    pub workflow_ref: String,
    pub token: String,
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

impl GithubEnv {
    /// Reads the environment GitHub Actions sets for every step.
    pub fn from_env() -> Result<GithubEnv> {
        let e = GithubEnv {
            api_url: std::env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".into()),
            repository: env("GITHUB_REPOSITORY"),
            repository_id: env("GITHUB_REPOSITORY_ID"),
            run_id: env("GITHUB_RUN_ID"),
            run_attempt: env("GITHUB_RUN_ATTEMPT"),
            git_ref: env("GITHUB_REF"),
            ref_name: env("GITHUB_REF_NAME"),
            head_ref: env("GITHUB_HEAD_REF"),
            workflow_ref: env("GITHUB_WORKFLOW_REF"),
            token: env("GITHUB_TOKEN"),
        };
        if e.repository.is_empty() || e.run_id.is_empty() {
            bail!("not running in GitHub Actions (GITHUB_REPOSITORY and GITHUB_RUN_ID are unset)");
        }
        if e.token.is_empty() {
            bail!("GITHUB_TOKEN is unset; pass it with `env: {{ GITHUB_TOKEN: ${{{{ github.token }}}} }}` and grant `actions: read`");
        }
        Ok(e)
    }

    fn get(&self, url: &str) -> reqwest::RequestBuilder {
        tailcat::shared_client()
            .get(url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .timeout(Duration::from_secs(30))
    }
}

/// A run artifact.
#[derive(Debug, Clone, Deserialize)]
pub struct Artifact {
    pub id: u64,
    pub name: String,
    pub archive_download_url: String,
    #[serde(default)]
    pub expired: bool,
    #[serde(default)]
    pub workflow_run: Option<ArtifactRun>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArtifactRun {
    pub id: u64,
}

#[derive(Deserialize)]
struct ArtifactList {
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
struct RunList {
    workflow_runs: Vec<Run>,
}

#[derive(Deserialize)]
struct Run {
    id: u64,
}

/// Lists a run's artifacts.
pub async fn list_artifacts(e: &GithubEnv, run_id: &str) -> Result<Vec<Artifact>> {
    let mut out = Vec::new();
    for page in 1..=10 {
        let url = format!("{}/repos/{}/actions/runs/{run_id}/artifacts?per_page=100&page={page}", e.api_url, e.repository);
        let res = e.get(&url).send().await.with_context(|| format!("listing artifacts of run {run_id}"))?;
        if !res.status().is_success() {
            bail!("listing artifacts of run {run_id}: {}", res.status());
        }
        let l: ArtifactList = res.json().await.context("decoding the artifact list")?;
        let n = l.artifacts.len();
        out.extend(l.artifacts.into_iter().filter(|a| !a.expired));
        if n < 100 {
            break;
        }
    }
    Ok(out)
}

/// Lists the in-progress runs of this workflow sharing our branch (or,
/// for a pull request, its head branch).
pub async fn sibling_runs(e: &GithubEnv, scope: Scope) -> Result<Vec<String>> {
    let workflow = e
        .workflow_ref
        .split('@')
        .next()
        .and_then(|p| p.rsplit('/').next())
        .filter(|w| !w.is_empty())
        .ok_or_else(|| anyhow!("GITHUB_WORKFLOW_REF is unset"))?;
    let branch = match scope {
        Scope::Pr => &e.head_ref,
        _ => &e.ref_name,
    };
    let url = format!(
        "{}/repos/{}/actions/workflows/{workflow}/runs?status=in_progress&per_page=50&branch={branch}",
        e.api_url, e.repository
    );
    let res = e.get(&url).send().await.context("listing workflow runs")?;
    if !res.status().is_success() {
        bail!("listing workflow runs: {}", res.status());
    }
    let l: RunList = res.json().await.context("decoding the run list")?;
    let mut ids: Vec<String> = l.workflow_runs.into_iter().map(|r| r.id.to_string()).collect();
    if !ids.contains(&e.run_id) {
        ids.push(e.run_id.clone());
    }
    Ok(ids)
}

/// Downloads an artifact's content: the single file inside its zip, or
/// the raw file for single-file (unarchived) uploads.
pub async fn download(e: &GithubEnv, a: &Artifact) -> Result<Vec<u8>> {
    let res = e.get(&a.archive_download_url).send().await.with_context(|| format!("downloading artifact {}", a.name))?;
    if !res.status().is_success() {
        bail!("downloading artifact {}: {}", a.name, res.status());
    }
    let body = res.bytes().await?.to_vec();
    if body.starts_with(b"PK\x03\x04") {
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(body)).context("opening the artifact zip")?;
        if z.is_empty() {
            bail!("artifact {} is an empty zip", a.name);
        }
        let mut f = z.by_index(0)?;
        let mut out = Vec::new();
        f.by_ref().take(1 << 20).read_to_end(&mut out)?;
        return Ok(out);
    }
    Ok(body)
}

/// Mints a GitHub OIDC token for `audience`. The job needs
/// `permissions: id-token: write`.
pub async fn mint_oidc(audience: &str) -> Result<String> {
    let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
        anyhow!("ACTIONS_ID_TOKEN_REQUEST_URL is unset; the job needs `permissions: id-token: write` (and fork PRs can't mint tokens)")
    })?;
    let tok = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").context("ACTIONS_ID_TOKEN_REQUEST_TOKEN is unset")?;
    #[derive(Deserialize)]
    struct Resp {
        value: String,
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    let full = format!("{url}{sep}audience={}", urlencode(audience));
    let res = tailcat::shared_client().get(full).bearer_auth(tok).timeout(Duration::from_secs(15)).send().await?;
    if !res.status().is_success() {
        bail!("minting an OIDC token: {}", res.status());
    }
    Ok(res.json::<Resp>().await?.value)
}

fn urlencode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// The claims of a GitHub Actions OIDC token that admission checks.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub exp: u64,
    #[serde(default)]
    pub repository_id: String,
    #[serde(default, rename = "ref")]
    pub git_ref: String,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub run_attempt: String,
    #[serde(default)]
    pub sha: String,
    #[serde(default)]
    pub job_workflow_ref: String,
    #[serde(default)]
    pub actor: String,
}

/// Verifies OIDC tokens against GitHub's published signing keys.
pub struct Verifier {
    jwks: jsonwebtoken::jwk::JwkSet,
}

impl Verifier {
    /// Fetches the issuer's signing keys.
    pub async fn fetch() -> Result<Verifier> {
        let url = format!("{OIDC_ISSUER}/.well-known/jwks");
        let jwks = tailcat::shared_client()
            .get(url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .context("fetching GitHub's OIDC keys")?
            .json()
            .await
            .context("decoding GitHub's OIDC keys")?;
        Ok(Verifier { jwks })
    }

    /// Builds a verifier from a JWKS document (for tests).
    pub fn from_jwks(jwks: jsonwebtoken::jwk::JwkSet) -> Verifier {
        Verifier { jwks }
    }

    /// Checks a token's signature, issuer, expiry and audience.
    pub fn verify(&self, token: &str, audience: &str) -> Result<Claims> {
        let header = jsonwebtoken::decode_header(token).context("decoding the token header")?;
        let kid = header.kid.ok_or_else(|| anyhow!("token has no key ID"))?;
        let jwk = self.jwks.find(&kid).ok_or_else(|| anyhow!("token signed by unknown key {kid:?}"))?;
        let key = jsonwebtoken::DecodingKey::from_jwk(jwk)?;
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        v.set_issuer(&[OIDC_ISSUER]);
        v.set_audience(&[audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        Ok(jsonwebtoken::decode::<Claims>(token, &key, &v).context("verifying the token")?.claims)
    }
}

/// Decides whether a record may join, per the scope. `from_run` is the
/// run whose artifacts held it.
pub fn admit(
    r: &NodeRecord,
    from_run: &str,
    e: &GithubEnv,
    scope: Scope,
    verifier: Option<&Verifier>,
    audience_prefix: &str,
) -> Result<()> {
    let own_run = from_run == e.run_id;
    if scope == Scope::Run {
        if !own_run {
            bail!("record from run {from_run}, not ours");
        }
        if !r.run_attempt.is_empty() && r.run_attempt != e.run_attempt {
            bail!("record from attempt {}, not ours ({})", r.run_attempt, e.run_attempt);
        }
    }
    if r.jwt.is_empty() {
        if scope != Scope::Run {
            bail!("record carries no OIDC token, required outside run scope");
        }
        return Ok(());
    }
    let v = verifier.ok_or_else(|| anyhow!("no OIDC verifier"))?;
    let c = v.verify(&r.jwt, &audience_for(audience_prefix, &r.nodekey))?;
    if !e.repository_id.is_empty() && c.repository_id != e.repository_id {
        bail!("token is for repository {}, not ours", c.repository_id);
    }
    match scope {
        Scope::Run => {
            if c.run_id != e.run_id || c.run_attempt != e.run_attempt {
                bail!("token is for run {} attempt {}, not ours", c.run_id, c.run_attempt);
            }
        }
        Scope::Branch => {
            if c.git_ref != e.git_ref {
                bail!("token is for ref {}, not {}", c.git_ref, e.git_ref);
            }
        }
        Scope::Pr => {
            if !(c.git_ref.starts_with("refs/pull/") && c.git_ref.ends_with("/merge")) || c.git_ref != e.git_ref {
                bail!("token is for ref {}, not this pull request's {}", c.git_ref, e.git_ref);
            }
        }
    }
    if c.run_id != from_run {
        bail!("token is for run {}, but the record came from run {from_run}", c.run_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tailcat::NodePrivate;

    fn genv() -> GithubEnv {
        GithubEnv {
            api_url: "https://api.github.com".into(),
            repository: "o/r".into(),
            repository_id: "42".into(),
            run_id: "100".into(),
            run_attempt: "1".into(),
            git_ref: "refs/heads/main".into(),
            ref_name: "main".into(),
            head_ref: String::new(),
            workflow_ref: "o/r/.github/workflows/mesh.yml@refs/heads/main".into(),
            token: "t".into(),
        }
    }

    fn rec(attempt: &str) -> NodeRecord {
        let k = NodePrivate::generate();
        NodeRecord {
            index: 0,
            nodekey: k.public(),
            discokey: k.disco_private().public(),
            overlay_ip: "100.64.1.0".parse().unwrap(),
            derp_region: 1,
            derp: None,
            routes: vec![],
            endpoints: vec![],
            os: String::new(),
            arch: String::new(),
            run_id: "100".into(),
            run_attempt: attempt.into(),
            jwt: String::new(),
        }
    }

    #[test]
    fn run_scope_admission() {
        let e = genv();
        assert!(admit(&rec("1"), "100", &e, Scope::Run, None, "p:").is_ok());
        assert!(admit(&rec("2"), "100", &e, Scope::Run, None, "p:").is_err(), "stale attempt");
        assert!(admit(&rec("1"), "99", &e, Scope::Run, None, "p:").is_err(), "another run");
        assert!(admit(&rec("1"), "100", &e, Scope::Branch, None, "p:").is_err(), "no token outside run scope");
    }

    #[test]
    fn url_encoding() {
        assert_eq!(urlencode("tailcat-device:ab"), "tailcat-device%3Aab");
    }
}
