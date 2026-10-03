//! Deterministic, seed-keyed [`HashMap`]/[`HashSet`] aliases.
//!
//! [`std::collections::HashMap`] and [`std::collections::HashSet`] default to
//! [`RandomState`], whose per-process random keys are invisible to a bolero
//! seed. Any test whose logic depends on map or set iteration order is
//! therefore non-deterministic across runs and does not replay from a recorded
//! `BOLERO_RANDOM_SEED`.
//!
//! The [`HashMap`]/[`HashSet`] aliases in this module use [`BoleroBuildHasher`],
//! which derives its hasher key from the seed of the currently running bolero
//! test (read through [`crate::with_context`]). The same seed produces the same
//! iteration order on every run and every platform, so an order-dependent
//! failure becomes reproducible and shrinkable. When no bolero test context is
//! active -- in production, or in a plain `#[test]` not driven by bolero -- the
//! hasher falls back to [`RandomState`], matching std's behavior exactly.
//!
//! The key varies with the seed rather than being one fixed value, so fuzzing
//! still explores different iteration orders while keeping each one replayable.
//! A single fixed order would hide order-dependent bugs instead of surfacing
//! them.
//!
//! `cfg(test)` does not propagate to downstream crates, so to pick these up in
//! your own tests, alias them where you need them (for example behind your
//! crate's own `#[cfg(test)]`, or a `testing` feature):
//!
//! ```rust
//! # #[cfg(feature = "std")] {
//! use bolero::hash::HashMap;
//!
//! let mut map: HashMap<u32, u32> = HashMap::default();
//! map.insert(1, 1);
//! assert_eq!(map.get(&1), Some(&1));
//! # }
//! ```

use core::hash::{BuildHasher, Hasher};
use std::collections::hash_map::{DefaultHasher, RandomState};

/// A [`std::collections::HashMap`] that hashes with [`BoleroBuildHasher`].
pub type HashMap<K, V> = std::collections::HashMap<K, V, BoleroBuildHasher>;

/// A [`std::collections::HashSet`] that hashes with [`BoleroBuildHasher`].
pub type HashSet<T> = std::collections::HashSet<T, BoleroBuildHasher>;

/// A [`BuildHasher`] that keys itself from the running bolero test's seed when a
/// bolero context is active, and falls back to [`RandomState`] otherwise.
///
/// Construct it with [`BoleroBuildHasher::default`] (the aliases in this module
/// do this for you). The source is captured once, when the hasher is built, so
/// every hasher produced by a given map uses the same key.
#[derive(Clone)]
pub struct BoleroBuildHasher(Source);

#[derive(Clone)]
enum Source {
    /// Keyed from a bolero seed: deterministic and replayable.
    Seeded { k0: u64, k1: u64 },
    /// No active bolero context: behave like std's default hasher.
    Random(RandomState),
}

impl Default for BoleroBuildHasher {
    fn default() -> Self {
        match seed_keys() {
            Some((k0, k1)) => Self(Source::Seeded { k0, k1 }),
            None => Self(Source::Random(RandomState::new())),
        }
    }
}

impl core::fmt::Debug for BoleroBuildHasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoleroBuildHasher").finish_non_exhaustive()
    }
}

impl BuildHasher for BoleroBuildHasher {
    type Hasher = DefaultHasher;

    fn build_hasher(&self) -> DefaultHasher {
        match &self.0 {
            // `DefaultHasher::new` always starts from the same fixed internal
            // keys, so writing the seed-derived key bytes first makes every
            // subsequent hash depend deterministically on the seed.
            Source::Seeded { k0, k1 } => {
                let mut hasher = DefaultHasher::new();
                hasher.write_u64(*k0);
                hasher.write_u64(*k1);
                hasher
            }
            Source::Random(state) => state.build_hasher(),
        }
    }
}

/// Read the current bolero test seed, if any, and derive two hasher keys from it.
fn seed_keys() -> Option<(u64, u64)> {
    let seed = crate::with_context(|ctx| ctx.input.seed)??;
    let bytes = seed.to_le_bytes();
    let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    Some((mix(lo), mix(hi ^ 0x9E37_79B9_7F4A_7C15)))
}

/// splitmix64 finalizer -- spreads the raw seed bits across the key so that
/// seeds that differ in only a few bits still give well-separated keys.
fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolero_engine::{test_context, EngineKind, RunPhase, TestInput, TestRunContext};

    fn with_seed<R>(seed: u128, f: impl FnOnce() -> R) -> R {
        let ctx = TestRunContext::new(
            EngineKind::Test,
            TestInput::new(Some(seed), None),
            0,
            RunPhase::Normal,
        );
        let _guard = test_context::enter(ctx);
        f()
    }

    fn order(seed: u128) -> Vec<i32> {
        with_seed(seed, || {
            let mut map: HashMap<i32, i32> = HashMap::default();
            for i in 0..64 {
                map.insert(i, i);
            }
            map.keys().copied().collect()
        })
    }

    #[test]
    fn same_seed_same_order() {
        let seed = 0x1234_5678_9abc_def0_1122_3344_5566_7788;
        assert_eq!(order(seed), order(seed));
    }

    #[test]
    fn different_seed_usually_different_order() {
        // With 64 keys an identical order from two different seeds is
        // astronomically unlikely, so a match means the key is not being
        // applied.
        assert_ne!(order(1), order(2));
    }

    #[test]
    fn no_context_falls_back_and_works() {
        // Outside any bolero context the hasher behaves like a normal map.
        let mut map: HashMap<i32, i32> = HashMap::default();
        map.insert(1, 10);
        map.insert(2, 20);
        assert_eq!(map.get(&1), Some(&10));
        assert_eq!(map.get(&2), Some(&20));
    }

    #[test]
    fn set_alias_builds() {
        let seed = 0xdead_beef_cafe_f00d;
        let members: HashSet<i32> = with_seed(seed, || (0..16).collect());
        assert_eq!(members.len(), 16);
        assert!(members.contains(&7));
    }
}
