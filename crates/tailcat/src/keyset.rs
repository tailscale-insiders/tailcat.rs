use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::key::NodePublic;

/// A concurrency-safe set of node public keys, the usual source for a
/// server's client allowlist:
///
/// ```
/// let allow = tailcat::KeySet::default();
/// # let k = tailcat::NodePrivate::generate().public();
/// allow.add(k);
/// let builder = tailcat::Server::builder().allow_client(allow.checker());
/// ```
///
/// An empty set allows no clients (unlike having no allow hook at all,
/// which allows everyone). Removing a connected client's key doesn't
/// disconnect it; call [`crate::Server::disconnect_client`] as well.
#[derive(Clone, Default)]
pub struct KeySet(Arc<Mutex<HashSet<NodePublic>>>);

impl KeySet {
    /// Adds `k` to the set.
    pub fn add(&self, k: NodePublic) {
        self.0.lock().unwrap().insert(k);
    }

    /// Removes `k` from the set.
    pub fn remove(&self, k: &NodePublic) {
        self.0.lock().unwrap().remove(k);
    }

    /// Reports whether `k` is in the set.
    pub fn contains(&self, k: &NodePublic) -> bool {
        self.0.lock().unwrap().contains(k)
    }

    /// Returns a closure suitable for [`crate::ServerBuilder::allow_client`].
    pub fn checker(&self) -> impl Fn(NodePublic) -> bool + Send + Sync + 'static {
        let s = self.clone();
        move |k| s.contains(&k)
    }
}
