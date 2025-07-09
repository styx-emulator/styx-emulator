// SPDX-License-Identifier: BSD-2-Clause

use crate::{Loader, LoaderHints, MemoryLoaderDesc};
use std::borrow::Cow;
use styx_errors::anyhow::Context;
use styx_memory::MemoryPermissions;
use styx_memory::MemoryRegion;

/// Loader for raw `.bin`'s or files
///
/// This loader takes the raw contents of the file provided to
/// [`Loader::load_bytes`] and produces a [`MemoryLoaderDesc`]
/// with a single region starting at address 0 with `RWX` permissions.
#[derive(Debug, Default)]
pub struct RawLoader;

impl Loader for RawLoader {
    /// Returns the name of the [`Loader`]
    ///
    /// ```rust
    /// use styx_loader::{Loader, RawLoader};
    ///
    /// assert_eq!("raw", RawLoader.name());
    /// ```
    fn name(&self) -> &'static str {
        "raw"
    }

    /// Given a sequence of bytes, return a [`MemoryLoaderDesc`] with
    /// a single region starting at address 0, and `RWX` permissions.
    ///
    /// ```rust
    /// use styx_loader::{RawLoader, Loader, MemoryLoaderDesc};
    /// use styx_memory::MemoryRegion;
    /// use std::collections::HashMap;
    ///
    /// let mut desc = RawLoader::default().load_bytes(vec![0x0, 0x8].into(), HashMap::default()).unwrap();
    ///
    /// # let regions = desc.take_memory_regions();
    /// # let region = regions.first().unwrap();
    /// # assert_eq!(2, region.size(), "Region size is not 2");
    /// # assert_eq!(0, region.base(), "Region base is not 0");
    /// ```
    fn load_bytes(
        &self,
        data: Cow<[u8]>,
        _hints: LoaderHints,
    ) -> Result<MemoryLoaderDesc, crate::StyxLoaderError> {
        load_raw(data.into_owned())
    }
}

/// Load the provided raw data. Breaking this out into a helper allows us to call it from other
/// loaders.
pub(crate) fn load_raw_with_base(
    data: Vec<u8>,
    base: u64,
    perms: MemoryPermissions,
) -> Result<MemoryLoaderDesc, crate::StyxLoaderError> {
    let region = MemoryRegion::new_with_data(
        base,
        // if this unsigned cast fails then something is very wrong
        // (eg. attempting to mmap larger than u64::MAX), so accept this panic
        // since we definitely dont want to attempt to be doing that
        data.len() as u64,
        perms,
        data,
    )?;

    let mut desc = MemoryLoaderDesc::default();

    // add the bare region
    desc.add_region(region)
        .with_context(|| "could not add raw region")?;

    Ok(desc)
}

/// Load the raw data at base address 0. This allows us to maintain the existing
/// [`RawLoader::load_bytes`] behavior.
fn load_raw(data: Vec<u8>) -> Result<MemoryLoaderDesc, crate::StyxLoaderError> {
    load_raw_with_base(data, 0, MemoryPermissions::all())
}
