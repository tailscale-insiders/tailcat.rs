//! Saved keys, in `$CONFIG/tailcat/keys/<name>.private.json` (the same
//! location and format as the Go implementation, so keys are shared).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tailcat::{NodePrivate, PrivateKey};

use crate::Global;
use crate::args::KeyArg;

/// Reports whether a key name is a path rather than a name.
pub fn is_path(name: &str) -> bool {
    name.contains(['/', '\\'])
}

/// The keys directory.
pub fn keys_dir() -> Result<PathBuf> {
    Ok(crate::util::user_config_dir().context("no user config directory")?.join("tailcat").join("keys"))
}

/// The file a key is saved in, if `k` names one.
pub fn key_file(k: &KeyArg) -> Result<Option<PathBuf>> {
    Ok(match k {
        KeyArg::Named(name) => Some(keys_dir()?.join(format!("{name}.private.json"))),
        KeyArg::Path(p) => Some(p.clone()),
        KeyArg::Default | KeyArg::New => None,
    })
}

/// Loads a key file.
pub fn load(path: &Path) -> Result<PrivateKey> {
    let j = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&j).with_context(|| format!("failed to parse {}", path.display()))
}

/// The key --key chooses: with none given, the saved key `default` if it
/// exists, else a fresh ephemeral key.
pub fn chosen(g: &Global, default: &str) -> Result<KeyArg> {
    Ok(match &g.key {
        KeyArg::Default => {
            let saved = KeyArg::Named(default.into());
            if key_file(&saved)?.is_some_and(|p| p.exists()) { saved } else { KeyArg::New }
        }
        k => k.clone(),
    })
}

/// The client identity per --key, defaulting to the saved
/// "client-default" key.
pub fn client_key(g: &Global) -> Result<NodePrivate> {
    match key_file(&chosen(g, "client-default")?)? {
        None => Ok(NodePrivate::generate()),
        Some(path) => Ok(load(&path)?.private),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global(key: Option<&str>) -> Global {
        let key = key.map_or(KeyArg::Default, |k| k.parse().unwrap());
        Global { key, verbose: false, json: false, derpmap_url: String::new() }
    }

    /// The client key per `--key <path>`.
    fn client_key_at(path: &Path) -> Result<NodePrivate> {
        client_key(&global(path.to_str()))
    }

    #[test]
    fn names_and_paths() {
        assert!(is_path("a/b.private.json"));
        assert!(is_path(r"a\b"));
        assert!(!is_path("default"));
        assert_eq!(key_file(&"./k.json".parse().unwrap()).unwrap(), Some(PathBuf::from("./k.json")));
        let named = key_file(&"foo".parse().unwrap()).unwrap().unwrap();
        assert!(named.ends_with("tailcat/keys/foo.private.json"));
        assert_eq!(chosen(&global(Some("new")), "default").unwrap(), KeyArg::New);
        assert_eq!(chosen(&global(Some("foo")), "default").unwrap(), KeyArg::Named("foo".into()));
    }

    #[test]
    fn loads_client_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.private.json");
        let k = PrivateKey::generate();
        fs::write(&path, k.to_json_pretty()).unwrap();
        assert_eq!(client_key_at(&path).unwrap(), k.private);

        let fresh = client_key(&global(Some("new"))).unwrap();
        assert_ne!(fresh, k.private);

        fs::write(&path, "{").unwrap();
        let e = client_key_at(&path).unwrap_err();
        assert!(format!("{e:#}").contains("failed to parse"), "{e:#}");
        assert!(client_key_at(&dir.path().join("missing")).is_err());
    }
}
