// SPDX-License-Identifier: BSD-2-Clause

// Currently only used in tests which could be migrated to HashStore.
// BlobStore *could* be faster than HashStore.
#[allow(dead_code)]
pub mod blob_store;
mod const_memory;
pub mod hash_store;
pub mod mmu_store;
mod simple_store;
pub mod sized_value;
pub mod space;
pub mod space_manager;
