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

use anyhow::{Context, Result, anyhow, bail, ensure};
use reqwest::{IntoUrl, RequestBuilder, Response, Url};
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

impl GithubEnv {
    /// Reads the environment GitHub Actions sets for every step.
    pub fn from_env() -> Result<GithubEnv> {
        let env = |k| std::env::var(k).unwrap_or_default();
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
        ensure!(
            !e.repository.is_empty() && !e.run_id.is_empty(),
            "not running in GitHub Actions (GITHUB_REPOSITORY and GITHUB_RUN_ID are unset)"
        );
        ensure!(
            !e.token.is_empty(),
            "GITHUB_TOKEN is unset; pass it with `env: {{ GITHUB_TOKEN: ${{{{ github.token }}}} }}` and grant `actions: read`"
        );
        Ok(e)
    }

    fn get(&self, url: impl IntoUrl) -> RequestBuilder {
        tailcat::shared_client()
            .get(url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .timeout(Duration::from_secs(30))
    }
}

/// Sends a request, failing unless the response is a success.
async fn send(req: RequestBuilder, what: impl FnOnce() -> String) -> Result<Response> {
    req.send().await.and_then(Response::error_for_status).with_context(what)
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

/// Lists a run's artifacts.
pub async fn list_artifacts(e: &GithubEnv, run_id: &str) -> Result<Vec<Artifact>> {
    #[derive(Deserialize)]
    struct List {
        artifacts: Vec<Artifact>,
    }
    let mut out = Vec::new();
    for page in 1..=10 {
        let url =
            format!("{}/repos/{}/actions/runs/{run_id}/artifacts?per_page=100&page={page}", e.api_url, e.repository);
        let l: List = send(e.get(url), || format!("listing artifacts of run {run_id}"))
            .await?
            .json()
            .await
            .context("decoding the artifact list")?;
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
    #[derive(Deserialize)]
    struct List {
        workflow_runs: Vec<Run>,
    }
    #[derive(Deserialize)]
    struct Run {
        id: u64,
    }
    let workflow = e
        .workflow_ref
        .split('@')
        .next()
        .and_then(|p| p.rsplit('/').next())
        .filter(|w| !w.is_empty())
        .ok_or_else(|| anyhow!("GITHUB_WORKFLOW_REF is unset"))?;
    let branch = if scope == Scope::Pr { &e.head_ref } else { &e.ref_name };
    let url = Url::parse_with_params(
        &format!("{}/repos/{}/actions/workflows/{workflow}/runs", e.api_url, e.repository),
        [("status", "in_progress"), ("per_page", "50"), ("branch", branch)],
    )?;
    let l: List =
        send(e.get(url), || "listing workflow runs".into()).await?.json().await.context("decoding the run list")?;
    let mut ids: Vec<String> = l.workflow_runs.into_iter().map(|r| r.id.to_string()).collect();
    if !ids.contains(&e.run_id) {
        ids.push(e.run_id.clone());
    }
    Ok(ids)
}

/// Downloads an artifact's content: the single file inside its zip, or
/// the raw file for single-file (unarchived) uploads.
pub async fn download(e: &GithubEnv, a: &Artifact) -> Result<Vec<u8>> {
    let body =
        send(e.get(&a.archive_download_url), || format!("downloading artifact {}", a.name)).await?.bytes().await?;
    if !body.starts_with(b"PK\x03\x04") {
        return Ok(body.into());
    }
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(body)).context("opening the artifact zip")?;
    ensure!(!z.is_empty(), "artifact {} is an empty zip", a.name);
    let mut out = Vec::new();
    z.by_index(0)?.take(1 << 20).read_to_end(&mut out)?;
    Ok(out)
}

/// Mints a GitHub OIDC token for `audience`. The job needs
/// `permissions: id-token: write`.
pub async fn mint_oidc(audience: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Resp {
        value: String,
    }
    let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
        anyhow!("ACTIONS_ID_TOKEN_REQUEST_URL is unset; the job needs `permissions: id-token: write` (and fork PRs can't mint tokens)")
    })?;
    let tok = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").context("ACTIONS_ID_TOKEN_REQUEST_TOKEN is unset")?;
    let mut url = Url::parse(&url).context("parsing ACTIONS_ID_TOKEN_REQUEST_URL")?;
    url.query_pairs_mut().append_pair("audience", audience);
    let req = tailcat::shared_client().get(url).bearer_auth(tok).timeout(Duration::from_secs(15));
    Ok(send(req, || "minting an OIDC token".into()).await?.json::<Resp>().await?.value)
}

/// The claims of a GitHub Actions OIDC token that admission checks.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Claims {
    pub iss: String,
    pub exp: u64,
    pub repository_id: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub run_id: String,
    pub run_attempt: String,
    pub sha: String,
    pub job_workflow_ref: String,
    pub actor: String,
}

/// Verifies OIDC tokens against GitHub's published signing keys.
pub struct Verifier {
    jwks: jsonwebtoken::jwk::JwkSet,
}

impl Verifier {
    /// Fetches the issuer's signing keys.
    pub async fn fetch() -> Result<Verifier> {
        let req =
            tailcat::shared_client().get(format!("{OIDC_ISSUER}/.well-known/jwks")).timeout(Duration::from_secs(15));
        let jwks = send(req, || "fetching GitHub's OIDC keys".into())
            .await?
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
/// run whose artifacts held it. A record must say it's from that run,
/// and if it carries a token, from the attempt the token was minted in:
/// peers are ranked by the run and attempt a record says it's from.
pub fn admit(
    r: &NodeRecord,
    from_run: &str,
    e: &GithubEnv,
    scope: Scope,
    verifier: Option<&Verifier>,
    audience_prefix: &str,
) -> Result<()> {
    ensure!(r.run_id == from_run, "record says it's from run {:?}, but came from run {from_run}", r.run_id);
    if scope == Scope::Run {
        ensure!(from_run == e.run_id, "record from run {from_run}, not ours");
        ensure!(
            r.run_attempt.is_empty() || r.run_attempt == e.run_attempt,
            "record from attempt {}, not ours ({})",
            r.run_attempt,
            e.run_attempt
        );
    }
    if r.jwt.is_empty() {
        ensure!(scope == Scope::Run, "record carries no OIDC token, required outside run scope");
        return Ok(());
    }
    let v = verifier.ok_or_else(|| anyhow!("no OIDC verifier"))?;
    let c = v.verify(&r.jwt, &audience_for(audience_prefix, &r.nodekey))?;
    ensure!(
        e.repository_id.is_empty() || c.repository_id == e.repository_id,
        "token is for repository {}, not ours",
        c.repository_id
    );
    match scope {
        Scope::Run if c.run_id != e.run_id || c.run_attempt != e.run_attempt => {
            bail!("token is for run {} attempt {}, not ours", c.run_id, c.run_attempt)
        }
        Scope::Branch if c.git_ref != e.git_ref => bail!("token is for ref {}, not {}", c.git_ref, e.git_ref),
        Scope::Pr
            if !(c.git_ref.starts_with("refs/pull/") && c.git_ref.ends_with("/merge")) || c.git_ref != e.git_ref =>
        {
            bail!("token is for ref {}, not this pull request's {}", c.git_ref, e.git_ref)
        }
        _ => {}
    }
    ensure!(c.run_id == from_run, "token is for run {}, but the record came from run {from_run}", c.run_id);
    ensure!(
        c.run_attempt == r.run_attempt,
        "token is for attempt {}, but the record says it's from attempt {:?}",
        c.run_attempt,
        r.run_attempt
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tailcat::NodePrivate;

    pub fn genv() -> GithubEnv {
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

    pub fn rec(attempt: &str) -> NodeRecord {
        NodeRecord {
            derp_region: 1,
            run_id: "100".into(),
            run_attempt: attempt.into(),
            ..NodeRecord::new(0, &NodePrivate::generate(), "100.64.1.0".parse().unwrap())
        }
    }

    #[test]
    fn run_scope_admission() {
        let e = genv();
        assert!(admit(&rec("1"), "100", &e, Scope::Run, None, "p:").is_ok());
        assert!(admit(&rec(""), "100", &e, Scope::Run, None, "p:").is_ok(), "no attempt recorded");
        assert!(admit(&rec("2"), "100", &e, Scope::Run, None, "p:").is_err(), "stale attempt");
        assert!(admit(&rec("1"), "99", &e, Scope::Run, None, "p:").is_err(), "another run");
        let claims_another = NodeRecord { run_id: "99".into(), ..rec("1") };
        assert!(admit(&claims_another, "100", &e, Scope::Run, None, "p:").is_err(), "says it's from another run");
        assert!(admit(&rec("1"), "100", &e, Scope::Branch, None, "p:").is_err(), "no token outside run scope");
        assert!(admit(&rec("1"), "100", &e, Scope::Pr, None, "p:").is_err(), "no token outside run scope");
        let mut r = rec("1");
        r.jwt = "x.y.z".into();
        assert!(admit(&r, "100", &e, Scope::Run, None, "p:").is_err(), "a token but no verifier");
    }

    /// Signs GitHub-shaped OIDC tokens with a local key.
    pub(crate) struct Signer {
        enc: jsonwebtoken::EncodingKey,
        jwks: jsonwebtoken::jwk::JwkSet,
        pub now: u64,
    }

    impl Signer {
        pub fn new() -> Signer {
            use base64::Engine as _;
            use rsa::pkcs1::EncodeRsaPrivateKey;
            use rsa::traits::PublicKeyParts;

            let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
            let b64 = |b: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
            let jwks = serde_json::from_value(serde_json::json!({
                "keys": [{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
                          "n": b64(key.n().to_bytes_be()), "e": b64(key.e().to_bytes_be())}]
            }))
            .unwrap();
            Signer {
                enc: jsonwebtoken::EncodingKey::from_rsa_der(key.to_pkcs1_der().unwrap().as_bytes()),
                jwks,
                now: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            }
        }

        /// A verifier that trusts this signer.
        pub fn verifier(&self) -> Verifier {
            Verifier::from_jwks(self.jwks.clone())
        }

        /// Signs `claims` over a valid default set for run 100 of repo 42.
        pub fn sign(&self, kid: Option<&str>, claims: serde_json::Value) -> String {
            let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            h.kid = kid.map(Into::into);
            let mut c = serde_json::json!({
                "iss": OIDC_ISSUER, "exp": self.now + 600, "iat": self.now,
                "repository_id": "42", "ref": "refs/heads/main", "run_id": "100", "run_attempt": "1",
            });
            c.as_object_mut().unwrap().extend(claims.as_object().unwrap().clone());
            jsonwebtoken::encode(&h, &c, &self.enc).unwrap()
        }

        /// A record for a fresh key with a token for it, plus `claims`.
        /// The record says it's from the token's run and attempt.
        pub fn rec(&self, claims: serde_json::Value) -> NodeRecord {
            let mut r = rec("1");
            let mut c = serde_json::json!({ "aud": audience_for(P, &r.nodekey) });
            c.as_object_mut().unwrap().extend(claims.as_object().unwrap().clone());
            for (field, claim) in [(&mut r.run_id, "run_id"), (&mut r.run_attempt, "run_attempt")] {
                if let Some(v) = c[claim].as_str() {
                    *field = v.into();
                }
            }
            r.jwt = self.sign(Some("k1"), c);
            r
        }
    }

    pub const P: &str = "tailcat-device:";

    #[test]
    fn oidc_admission() {
        use serde_json::json;

        let s = Signer::new();
        let v = s.verifier();
        let e = genv();
        let admit = |r: &NodeRecord, from_run: &str, scope| admit(r, from_run, &e, scope, Some(&v), P);

        let r = s.rec(json!({}));
        admit(&r, "100", Scope::Run).unwrap();

        // A token for another node's key doesn't transfer.
        let mut stolen = rec("1");
        stolen.jwt = r.jwt.clone();
        assert!(admit(&stolen, "100", Scope::Run).is_err());

        // Run scope wants this very run and attempt.
        assert!(admit(&s.rec(json!({"run_attempt": "2"})), "100", Scope::Run).is_err(), "other attempt");

        // Branch scope admits another run on the same ref, not another ref.
        let sib = s.rec(json!({"run_id": "99"}));
        admit(&sib, "99", Scope::Branch).unwrap();
        assert!(admit(&sib, "100", Scope::Branch).is_err(), "token run != artifact run");
        let posing = NodeRecord { run_id: "100".into(), ..sib.clone() };
        assert!(admit(&posing, "99", Scope::Branch).is_err(), "says it's from our run");
        let retried = NodeRecord { run_attempt: "2".into(), ..sib.clone() };
        assert!(admit(&retried, "99", Scope::Branch).is_err(), "says it's from another attempt");
        assert!(admit(&s.rec(json!({"run_id": "99", "ref": "refs/heads/evil"})), "99", Scope::Branch).is_err());

        // Another repository's token fails in every scope.
        let foreign = s.rec(json!({"repository_id": "7"}));
        for scope in [Scope::Run, Scope::Branch] {
            assert!(admit(&foreign, "100", scope).is_err(), "{scope:?}");
        }

        // Expired, forged, keyless and unknown-key tokens fail.
        assert!(admit(&s.rec(json!({"exp": s.now - 3600})), "100", Scope::Run).is_err(), "expired");
        assert!(admit(&s.rec(json!({"iss": "https://evil.example"})), "100", Scope::Run).is_err(), "issuer");
        let mut forged = r.clone();
        let mut b = forged.jwt.into_bytes();
        let i = b.len() - 10; // inside the signature
        b[i] = if b[i] == b'A' { b'B' } else { b'A' };
        forged.jwt = String::from_utf8(b).unwrap();
        assert!(admit(&forged, "100", Scope::Run).is_err(), "forged");
        let mut keyless = r.clone();
        keyless.jwt = s.sign(None, json!({"aud": audience_for(P, &r.nodekey)}));
        assert!(admit(&keyless, "100", Scope::Run).is_err(), "no key ID");
        let mut unknown = r.clone();
        unknown.jwt = s.sign(Some("k2"), json!({"aud": audience_for(P, &r.nodekey)}));
        assert!(admit(&unknown, "100", Scope::Run).is_err(), "unknown key ID");
    }

    /// Ranking trusts the run and attempt a record says it's from, so an
    /// admitted record's must be true: the run whose artifacts held it,
    /// and the run and attempt its token was minted in.
    #[hegel::test(test_cases = 300)]
    fn admitted_records_are_from_the_run_they_say(tc: hegel::TestCase) {
        use hegel::generators as gs;
        static SIGNER: std::sync::OnceLock<Signer> = std::sync::OnceLock::new();
        let s = SIGNER.get_or_init(Signer::new);
        let runs = || gs::sampled_from(vec!["100", "99", ""]);
        let attempts = || gs::sampled_from(vec!["1", "2", ""]);
        let scope = if tc.draw(gs::booleans()) { Scope::Run } else { Scope::Branch };
        let from_run = tc.draw(gs::sampled_from(vec!["100", "99"]));
        let token = tc.draw(gs::booleans()).then(|| (tc.draw(runs()), tc.draw(attempts())));
        let mut r = match token {
            Some((run, attempt)) => s.rec(serde_json::json!({"run_id": run, "run_attempt": attempt})),
            None => rec("1"),
        };
        r.run_id = tc.draw(runs()).into();
        r.run_attempt = tc.draw(attempts()).into();
        if admit(&r, from_run, &genv(), scope, Some(&s.verifier()), P).is_ok() {
            assert_eq!(r.run_id, from_run);
            if let Some((run, attempt)) = token {
                assert_eq!((r.run_id.as_str(), r.run_attempt.as_str()), (run, attempt));
            }
        }
    }

    #[test]
    fn pr_scope_admission() {
        use serde_json::json;

        let s = Signer::new();
        let pr = GithubEnv { git_ref: "refs/pull/5/merge".into(), head_ref: "feature".into(), ..genv() };
        let v = s.verifier();
        let admit = |r: &NodeRecord, e: &GithubEnv| admit(r, "99", e, Scope::Pr, Some(&v), P);

        admit(&s.rec(json!({"run_id": "99", "ref": "refs/pull/5/merge"})), &pr).unwrap();
        assert!(admit(&s.rec(json!({"run_id": "99", "ref": "refs/pull/6/merge"})), &pr).is_err(), "other PR");
        // Branch refs never pass PR scope, even when they match ours.
        assert!(admit(&s.rec(json!({"run_id": "99"})), &genv()).is_err(), "not a PR ref");
    }
}
