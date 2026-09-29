//! Saved keys, in `$CONFIG/tailcat/keys/<name>.private.json` (the same
//! location and format as the Go implementation, so keys are shared).

use std::path::PathBuf;

use anyhow::{Context, Result};
use tailcat::{NodePrivate, PrivateKey};

use crate::Global;

/// Reports whether a key name is a path rather than a name.
pub fn is_path(name: &str) -> bool {
    name.contains('/') || name.contains('\\')
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

/// The client identity per --key: "new" or no saved "client-default"
/// key means a fresh ephemeral key.
pub fn client_key(g: &Global) -> Result<NodePrivate> {
    let name = match g.key.as_deref() {
        None | Some("") => {
            if key_path("client-default")?.exists() {
                "client-default"
            } else {
                return Ok(NodePrivate::generate());
            }
        }
        Some("new") => return Ok(NodePrivate::generate()),
        Some(n) => n,
    };
    Ok(load(name)?.private)
}
