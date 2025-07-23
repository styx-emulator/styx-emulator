// SPDX-License-Identifier: BSD-2-Clause
//! Caching mechanism for pcodes.
//!
//! libsleigh was not built with emulation speeds in mind and makes up one of the slowest components
//! of Styx taking up ~50% of execution time. To mitigate this, I present a pcode cacher. The idea
//! is to save translated pcodes in memory for retrieval at a later point.
//!
//! ## State Invalidation
//!
//! The current "state" of the instruction/processor/etc. is checked after a preliminary cache hit.
//! I.e. the cache structure [PcodeCache::cache] contains an entry for the translation address
//! establishing a preliminary cache hit, then we must check if the current state has not changed
//! since the cached entry.
//!
//! The state is stored in [`CacheEntryState`] and stores/checks:
//!
//! 1. Translations bytes - 16 bytes starting from the translation address. This is equivalent to
//!    the 16 byte load that libsleigh requests when translating.
//!
//! It SHOULD check the ContextOption but this is not implemented yet.
//!
//! I also tried using the state has the cache key (tried FxHash and ahash) and saw a ~5%
//! performance degradation compared to using the address as the cache key and checking the state
//! after.
//!
//! ## Return Values
//!
//! Pcodes are large (184 bytes currently) so moving them from the translator to execution is
//! nontrivial. It would be best to return references to avoid clones but that has issues.
//!
//! The three ways I have experimented returning pcodes are listed below.
//!
//! ### 1: Mutable Vec which gets appended.
//!
//! This is avoids heap allocation and agrees with the [`Sleigh::translate()`] api. This apis fails
//! with caching implemented. With caching, the translator owns the Pcode Vec and so must now clone
//! all pcodes into the buffer. If we are optimizing for the cached case, this will not do.
//!
//! ### 2: Return Ref Pcode Slice
//!
//! This way we can simply reference the cached pcode Vec, no clones required! To support disabling
//! the cache, we keep an internal Vec to return references to. This Vec gets pushed to when
//! translating and stores the most recently translated pcodes.
//!
//! This is the variation that is used in the current version of the code.
//!
//! ### 3: Return `Arc<Vec<Pcode>>`
//!
//! To explain this one I should start with the problem with `2`. Returning a reference of
//! translated pcodes requires us hold the reference to the translator while we want to keep the
//! pcodes around. This is sound but in practice, the PcodeBackend groups a lot of its functions and
//! behaviors, meaning a function like fetch_pcode now holds hostage a reference to the entire
//! PcodeBackend, effectively halting further emulation.
//!
//! The outcome here is that the PcodeBackend user of the translator ends up cloning the Pcodes
//! anyway to release the lock on the PcodeBackend.
//!
//! Theoretically, Arcing cached pcodes and returning those instead (cloned, of course) would remove
//! the reference problems and be fast enough because you're only cloning the Arc, not the whole
//! pcode structure.
//!
//! In my implementation, this destroyed performance. It's possible there is a better way to
//! implement this.
//!
use polonius_the_crab::prelude::*;
use quick_cache::{
    unsync::{Cache, DefaultLifecycle},
    UnitWeighter,
};
use rustc_hash::FxBuildHasher;
use styx_pcode::pcode::Pcode;
use styx_pcode_sleigh_backend::{Loader, Sleigh, SleighTranslateError};
use tracing::trace;

use crate::TranslatedPcode;

impl<'a> From<&'a CacheEntry> for TranslatedPcode<'a> {
    fn from(value: &'a CacheEntry) -> Self {
        TranslatedPcode {
            pcodes: value.pcodes.as_slice(),
            bytes_consumed: value.bytes_consumed,
        }
    }
}

/// Configurable cache/no cache pcodes.
///
/// Construct with [`MaybePcodeCache::should_cache()`], translate with
/// [`MaybePcodeCache::translate()`].
///
/// See module documentation for more details.
pub(crate) enum MaybePcodeCache {
    /// We are caching pcodes.
    Cached(PcodeCache),
    /// We are NOT caching pcodes.
    ///
    /// We return a reference to the internal pcode Vec here.
    NotCached(Vec<Pcode>),
}

impl MaybePcodeCache {
    /// Construct and determine if we are caching pcodes or not.
    pub(crate) fn should_cache(should_cache: bool) -> Self {
        match should_cache {
            true => Self::Cached(Default::default()),
            false => Self::NotCached(Vec::with_capacity(20)),
        }
    }

    /// Translate pcodes.
    pub(crate) fn translate<'a, L: Loader + 'static>(
        &'a mut self,
        sleigh: &mut Sleigh<L>,
        address: u64,
        data: &mut L::LoadRequires<'_>,
    ) -> Result<TranslatedPcode<'a>, SleighTranslateError> {
        match self {
            MaybePcodeCache::Cached(cache) => {
                // translate via pcode cache
                cache.translate(sleigh, address, data).map(Into::into)
            }
            MaybePcodeCache::NotCached(pcode_buffer) => {
                // no caching here, we use the internal buffer and do normal translation.
                pcode_buffer.clear();
                let bytes = sleigh.translate(address, pcode_buffer, data)?;
                Ok(TranslatedPcode {
                    pcodes: pcode_buffer,
                    bytes_consumed: bytes as _,
                })
            }
        }
    }
}

pub(crate) struct PcodeCache {
    /// Actual cache implementation.
    ///
    /// Using FxHasher eliminates the 5% performance regression I was seeing when using
    /// [quick_cache]'s default ahash.
    cache: Cache<u64, CacheEntry, UnitWeighter, FxBuildHasher>,
    /// Should we treat loads of all zeros as "invalid" or "cache invalid".
    ///
    /// See module documentation for more information.
    ignore_zeros: bool,
    /// Total translates.
    ///
    /// I don't think this will overflow
    /// `pow(2, 64) /(4*pow(9,11) * (60 * 60 * 24 * 365)) = 4.65`
    ///
    /// Running a processor at 4GHz it would take 4.6 years of running to
    /// overflow.
    total_hits: u64,
    cache_hits: u64,
}

/// Rough maximum cache size in bytes.
const CACHE_SIZE_BYTES: usize = 100_000_000;
/// Estimated Pcodes per instruction translation.
const AVG_PCODE_PER_ENTRY: usize = 30;
/// Calculate total number of cache size.
///
/// With the current [Cache] library we could weight entries by their size but that would incur some
/// runtime overhead.
const CACHE_SIZE_ENTRIES: usize =
    CACHE_SIZE_BYTES / (std::mem::size_of::<Pcode>() * AVG_PCODE_PER_ENTRY);

impl Default for PcodeCache {
    fn default() -> Self {
        Self {
            cache: Cache::with(
                CACHE_SIZE_ENTRIES,
                // Same value for weight because we're using UnitWeighter.
                CACHE_SIZE_ENTRIES as u64,
                UnitWeighter,
                FxBuildHasher,
                DefaultLifecycle::default(),
            ),
            ignore_zeros: true,
            total_hits: 0,
            cache_hits: 0,
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
struct CacheEntryState {
    /// instruction bytes that where loaded by sleigh
    instructions: SleighLoadBytes,
    address: u64,
}

impl CacheEntryState {
    /// Construct entry state of current state.
    fn new<L: Loader + 'static>(
        sleigh: &mut Sleigh<L>,
        address: u64,
        data: &mut L::LoadRequires<'_>,
    ) -> Self {
        let instr_bytes = sleigh.load(address, data);

        Self {
            address,
            instructions: instr_bytes,
        }
    }
}

/// Stored in [PcodeCache]
#[derive(Debug)]
struct CacheEntry {
    /// Stores state to be checked to ensure cache freshness.
    state: CacheEntryState,
    /// Pcodes that are cached.
    pcodes: Vec<Pcode>,
    /// Bytes consumed from translating.
    bytes_consumed: u64,
}

impl PcodeCache {
    /// Return cached pcodes if possible, otherwise translate and return.
    fn translate<'a, L: Loader + 'static>(
        &'a mut self,
        sleigh: &mut Sleigh<L>,
        address: u64,
        data: &mut L::LoadRequires<'_>,
    ) -> Result<&'a CacheEntry, SleighTranslateError> {
        let mut cache = self;
        cache.total_hits += 1;
        // First we should check cache for pcodes
        //   this will check for byte eqiviliance in memory
        //   also context equality
        //   All determined by CacheEntryState
        // If no cache, add pcodes to cache then return from cache

        // polonius is a safe way to get around a shortcoming of the borrow checker
        //
        // this allows us to return early with a reference to `cache`, but continue the function
        // without holding the reference if `cache` doesn't have the entry we need.
        polonius!(|cache| -> Result<&'polonius CacheEntry, _> {
            if let Some(v) = cache.check_cache(sleigh, address, data) {
                polonius_return!(Ok(v));
            }
        });

        // cache was not hit, we translate and add to the cache now
        cache.translate_and_fill(sleigh, address, data)
    }

    /// Translate pcodes and fill the cache with the result.
    fn translate_and_fill<'a, L: Loader + 'static>(
        &'a mut self,
        sleigh: &mut Sleigh<L>,
        address: u64,
        data: &mut L::LoadRequires<'_>,
    ) -> Result<&'a CacheEntry, SleighTranslateError> {
        trace!("pcode at 0x{address:X?} not in cache, fetching");
        // new pcode buffer, in my testing a >0 initial capacity improves perf a noticeable amount
        // with negligible decrease as capacity grows.
        let mut pcodes = Vec::with_capacity(20);
        let bytes = sleigh.translate(address, &mut pcodes, data)?;

        let state = CacheEntryState::new(sleigh, address, data);

        let entry = CacheEntry {
            state,
            pcodes,
            bytes_consumed: bytes as u64,
        };

        self.cache.insert(address, entry);
        // have to do a get to get back the entry :/
        Ok(self
            .cache
            .get(&address)
            .expect("value added to cache not found, this doesn't make sense"))
    }

    /// check cache for pcodes this will check for byte eqiviliance in memory also context equality
    ///
    /// EDGE CASE FAILURE HERE
    ///
    /// If the cpu hits a block of all 0s and successfully decodes that into an instruction, then later,
    /// the cpu hits the same block but it is not unmapped or memory protection error then it would use
    /// the saved 0s cache. To stop this we don't save all 0s.
    fn check_cache<'a, L: Loader + 'static>(
        &'a mut self,
        sleigh: &mut Sleigh<L>,
        address: u64,
        data: &mut L::LoadRequires<'_>,
    ) -> Option<&'a CacheEntry> {
        let entry = self.cache.get(&address)?;

        let current_state = CacheEntryState::new(sleigh, address, data);

        if state_eq(&entry.state, &current_state, self.ignore_zeros) {
            self.cache_hits += 1;
            if self.cache_hits % 1000 == 0 {
                trace!(
                    "cache hit stats: {:.2E}/{:.2E} ({:.2}%)",
                    self.cache_hits,
                    self.total_hits,
                    (self.cache_hits as f64 / self.total_hits as f64) * 100f64
                );
            }

            Some(entry)
        } else {
            None
        }
    }
}

/// Slice of bytes loaded by sleigh, its always 16 bytes.
type SleighLoadBytes = [u8; 16];

fn check_zero(loaded_bytes: &SleighLoadBytes, ignore_zeros: bool) -> bool {
    !ignore_zeros || loaded_bytes != &[0u8; 16]
}

fn state_eq(
    cache_state: &CacheEntryState,
    current_state: &CacheEntryState,
    ignore_zeros: bool,
) -> bool {
    cache_state == current_state && check_zero(&current_state.instructions, ignore_zeros)
}
