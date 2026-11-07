//! Replay protection: remember each verified signature until it expires.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Mutex;

pub trait ReplayGuard: Send + Sync {
    /// Records `key` as used until `expires_at` (Unix seconds).
    /// Returns `false` when the key was already used and has not expired.
    fn first_use(&self, key: &str, expires_at: i64, now: i64) -> bool;
}

/// In-process replay cache with a hard size cap.
///
/// When full after pruning expired entries, the entries closest to expiry are evicted.
/// Under a flood that weakens protection for those entries rather than rejecting
/// legitimate traffic. Multi-instance deployments need a shared store (Redis etc.).
pub struct MemoryReplayGuard {
    capacity: usize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    seen: HashMap<String, i64>,
    by_expiry: BinaryHeap<Reverse<(i64, String)>>,
}

impl MemoryReplayGuard {
    pub fn new(capacity: usize) -> Self {
        MemoryReplayGuard {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|i| i.seen.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MemoryReplayGuard {
    fn default() -> Self {
        MemoryReplayGuard::new(100_000)
    }
}

impl Inner {
    fn pop_earliest(&mut self) {
        if let Some(Reverse((exp, key))) = self.by_expiry.pop()
            && self.seen.get(&key) == Some(&exp)
        {
            self.seen.remove(&key);
        }
    }

    fn prune(&mut self, now: i64) {
        while let Some(Reverse((exp, _))) = self.by_expiry.peek() {
            if *exp >= now {
                break;
            }
            self.pop_earliest();
        }
    }
}

impl ReplayGuard for MemoryReplayGuard {
    fn first_use(&self, key: &str, expires_at: i64, now: i64) -> bool {
        let mut inner = self.inner.lock().expect("replay cache lock");
        inner.prune(now);
        if inner.seen.get(key).is_some_and(|exp| *exp >= now) {
            return false;
        }
        while inner.seen.len() >= self.capacity && !inner.by_expiry.is_empty() {
            inner.pop_earliest();
        }
        inner.seen.insert(key.to_string(), expires_at);
        inner.by_expiry.push(Reverse((expires_at, key.to_string())));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_reuse_until_expiry() {
        let g = MemoryReplayGuard::default();
        assert!(g.first_use("a", 100, 10));
        assert!(!g.first_use("a", 100, 50));
        assert!(g.first_use("a", 200, 101)); // expired entry is forgotten
    }

    #[test]
    fn stays_within_capacity() {
        let g = MemoryReplayGuard::new(2);
        assert!(g.first_use("a", 100, 0));
        assert!(g.first_use("b", 200, 0));
        assert!(g.first_use("c", 300, 0));
        assert_eq!(g.len(), 2);
        assert!(!g.first_use("c", 300, 1));
    }
}
