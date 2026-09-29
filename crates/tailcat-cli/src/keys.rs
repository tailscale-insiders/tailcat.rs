//! Saved keys, in `$CONFIG/tailcat/keys/<name>.private.json` (the same
//! location and format as the Go implementation, so keys are shared).

use std::path::PathBuf;

use anyhow::{Context, Result};
use tailcat::{NodePrivate, PrivateKey};

use crate::Global;

/// Reports whether a key name is a path rather than a name.
pub fn is_path(name: &str) -> bool {
    name.contains(['/', '\\'])
}

/// The keys directory.
pub fn keys_dir() -> Result<PathBuf> {
    Ok(crate::util::user_config_dir().context("no user config directory")?.join("tailcat").join("keys"))
}

/// The path of a key given by name or path.
pub fn key_path(name: &str) -> Result<PathBuf> {
    if is_path(name) {
        return Ok(PathBuf::from(name));
    }
    Ok(keys_dir()?.join(format!("{name}.private.json")))
}

/// Loads a key file.
pub fn load(name: &str) -> Result<PrivateKey> {
    let path = key_path(name)?;
    let j = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&j).with_context(|| format!("failed to parse {}", path.display()))
}

/// The key named by --key, where "new" means a fresh ephemeral key. No
/// --key means the saved key `default` if it exists, else "new".
pub fn key_name(g: &Global, default: &str) -> Result<String> {
    Ok(match g.key.as_deref() {
        None | Some("") if key_path(default)?.exists() => default.to_string(),
        None | Some("") => "new".to_string(),
        Some(k) => k.to_string(),
    })
}

/// The client identity per --key, defaulting to the saved
/// "client-default" key.
pub fn client_key(g: &Global) -> Result<NodePrivate> {
    match key_name(g, "client-default")?.as_str() {
        "new" => Ok(NodePrivate::generate()),
        name => Ok(load(name)?.private),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global(key: Option<&str>) -> Global {
        Global { key: key.map(String::from), verbose: false, json: false, derpmap_url: String::new() }
    }

    #[test]
    fn names_and_paths() {
        assert!(is_path("a/b.private.json") && is_path(r"a\b") && !is_path("default"));
        assert_eq!(key_path("./k.json").unwrap(), PathBuf::from("./k.json"));
        assert!(key_path("foo").unwrap().ends_with("tailcat/keys/foo.private.json"));
        assert_eq!(key_name(&global(Some("new")), "default").unwrap(), "new");
        assert_eq!(key_name(&global(Some("foo")), "default").unwrap(), "foo");
    }

    #[test]
    fn loads_client_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.private.json");
        let k = PrivateKey::generate();
        std::fs::write(&path, k.to_json_pretty()).unwrap();
        assert_eq!(client_key(&global(path.to_str())).unwrap(), k.private);
        assert_ne!(client_key(&global(Some("new"))).unwrap(), k.private);
        std::fs::write(&path, "{").unwrap();
        let e = client_key(&global(path.to_str())).unwrap_err();
        assert!(format!("{e:#}").contains("failed to parse"), "{e:#}");
        assert!(client_key(&global(dir.path().join("missing").to_str())).is_err());
    }
}
