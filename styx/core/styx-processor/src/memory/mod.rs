// SPDX-License-Identifier: BSD-2-Clause
//! Part of the Processor Core used for managing memory.
//!
//! The [processor core](crate::core) contains the [`Mmu`]. The [`Mmu`] supports traditional mmu
//! behaviors using the [`TlbImpl`] however it also supports no-translation behavior with the
//! [`DummyTlb`].
//!
//! ## Memory Structures
//! `Mmu` is the per-core/per-vCPU Memory Management Unit.
//! It is transient in that no-one owns a CPU.
//! This is because we want to provide exclusive access to main memory when
//! emulation is paused.
//!
//! The `Mmu` holds an exclusive reference to a `Tlb`
//! and a shared reference to the `ProcessorMemory`.
//!
//! `ProcessorMemory` is owned by the `Processor` and shared to others.
//!
//! ## Atomic Operations
//! In Styx we must faithfully emulate target atomic operations.
//! While there are many atomic operations that may be implemented by ISAs, we can emulate all of them
//! using a simple compare and swap operation.
//! Compare exchange is used as the base operator because our host target architecture x86_64 supports
//! the operation (`CMPXCHG`) and Rust has stable APIs for compare exchange ([`AtomicU64::compare_exchange()`]).
//!
//! [`AtomicU64::compare_exchange()`]: std::sync::atomic::AtomicU64::compare_exchange()
//!
//! To perform an arbitrary atomic operation (e.g. Add, Sub, Increment, etc.) use the following steps.
//!
//! 1. Load from the address you will modify
//! 2. Do the operation on the loaded value
//! 3. Compare exchange using the original loaded value and post operation result
//! 4. if the compare exchange fails, start again from step 1
//!
//! ```
//! # use styx_processor::memory::Mmu;
//! # let mut mmu = Mmu::default();
//! let mut success = false;
//! while !success {
//!      // step 1: read initial data
//!      let mut read_buffer = [0u8; 2];
//!      mmu.read_data(0x1000, &mut read_buffer).unwrap();
//!      // step 2: perform operation (`inc` in this case)
//!      let op_result = (u16::from_le_bytes(read_buffer) + 1).to_le_bytes();
//!      // step 3: compare exchange with old value
//!      let compare_exchange_result = mmu.compare_exchange_code(0x1000, &read_buffer, &op_result).unwrap();
//!      // step 4: repeat if no successful
//!      success = compare_exchange_result.success();
//! }
//! ```
//!
//! ### Atomic Operation Restrictions
//! Styx's atomic operations operate on byte slices
//! that are sized less than the host word size (assume 8).
//! The size of the atomic operation must fit into a host word.
//! For example, a 4 byte atomic operation at address 0 fits within a host word,
//! but a 4 byte atomic operation at address 6 would not.
//!
//! See the Internal Representation section for a visual diagram.
//!
//! ### Compare Exchange
//! The compare exchange (or compare and swap) is an atomic operation used to build other sync primitives.
//! Briefly, supplied with an `address` as well as `current` and `new` values,
//! the `new` value will be written if and only if the value at `address` is `current`.
//! The success or failure of the operation will be reported.
//!
//! Styx's implementation of compare exchange follows a similar behavior with a few key differences.
//!
//! The first difference is that Styx's compare exchange operation can operate on byte slices
//! that are sized less than the host word size (assume 8).
//! Compare exchange operations must follow the restrictions of atomic operations, listed above.
//!
//! The second difference is that the compare exchange operation implemented in Styx is weak.
//! This means that the operation could **fail** despite ``*address == current``.
//! In practice, the chances of this happening are low.
//! See the documentation and source code for `AtomicWord` for more information.
//!
//! ### Load-Link/Store-Conditional
//! The Load-link/store-conditional (LL/SC) operation is the primary atomic primitive in RISC architectures.
//! As such, it is imperative we can emulate this primitive in Styx.
//!
//! The behavior of LL/SC is as follows.
//! An LL instruction loads the value of an `address` from memory and "tags" that `address`.
//! Later, a SC instruction on the same `address` is used to store a `new` value.
//! If the memory at `address` has been modified by an atomic instruction since the LL,
//! the SC will fail.
//! Otherwise, the operation *can* succeed.
//! The LL/SC operation is allowed to spuriously fail.
//!
//! Users can access a LL/SC api via [`Mmu::load_linked_data()`], [`Mmu::load_linked_code()`],
//! [`Mmu::store_conditional_data()`] and [`Mmu::store_conditional_code()`].
//! Is is the caller's responsibility to store a previous load (returned from `load_linked()`)
//! to be used with the `store_conditional()`.
//! Styx's implementation of LL/SC follows a similar behavior with a few key differences.
//!
//! The first difference is that Styx's LL/SC operation can operate on byte slices
//! that are sized less than the host word size (assume 8).
//! LL/SC operations must follow the restrictions of atomic operations, listed above.
//!
//! The second difference is that Styx's current implementation will succeed if the
//! `current` value is unchanged, but the `address` has been modified.
//! This behavior is subject to the ABA problem.
//! In firmware emulation, this should rarely be an issue.
//!
//! #### LL/SC Addressing Modes
//! Depending on the emulated ISA, LL/SC operations may reserve based
//! on the **physical** or **virtual** address.
//! Since proper reservation is left to the caller, the caller has the option
//! to track reservations based on virtual or physical addressing.
//!
//! However, the `load_linked` and `store_conditional` methods **do** check that the
//! loaded address matches the store address.
//! So to load a virtual address but reserve based on a physical address the caller
//! must use [`Mmu::translate_va()`] then use the physical addressing LL/SC methods.
//!
//! The table below shows the methods you should uses for LL/SC with respect to
//! what addressing mode you are using to Access the memory and to reserve the memory.
//! All the methods have `_code()` variants.
//!
//! | Access/Reservation | Methods to use |
//! | ------------------ | -------------- |
//! | Physical/Physical  | [`Mmu::load_linked_data()`]/[`Mmu::store_conditional_data()`] |
//! | Virtual/Physical   | [`Mmu::translate_va()`] + [`Mmu::load_linked_data()`]/[`Mmu::store_conditional_data()`] |
//! | Physical/Virtual   | N/A |
//! | Virtual/Virtual   | [`Mmu::virt_load_linked_data()`]/[`Mmu::virt_store_conditional_data()`] |
//!
//! ### Internal Representation
//!
//! ```text
//! === Representation of Memory ===
//!
//! AtomicWord based representation
//! |      AtomicWord       |      AtomicWord       |
//! |u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|
//! Byte addressable representation
//!
//!
//! === Acceptable Atomic Operations ===
//!
//! Aligned Read/Write
//!
//!  4 byte r/w
//! |-----------|
//! |           |
//! -------------------------------------------------
//! |      AtomicWord       |      AtomicWord       |
//! |u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|
//!
//! Unalgined but fits inside Atomc Word
//!
//!        4 byte r/w
//!       |-----------|
//!       |           |
//! -------------------------------------------------
//! |      AtomicWord       |      AtomicWord       |
//! |u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|
//!
//! === NonAtomic Operations ===
//!
//! Small enough, but straddles multiple atomic words
//!
//!                    4 byte r/w
//!                   |-----------|
//!                   |           |
//! -------------------------------------------------
//! |      AtomicWord       |      AtomicWord       |
//! |u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|u8|
//!
//! ```
//!
use bitflags::bitflags;
use derive_more::Display;

mod atomic_word;
pub mod helpers;
mod llsc;
mod mem_arch;
pub mod memory_region;
mod mmu;
mod mmu_sized_rw;
pub mod physical;
mod region;
mod tlb;

pub use atomic_word::CompareExchangeResult;
pub use llsc::{StoreConditionalError, StoreConditionalResult};
pub use mem_arch::MemoryArchitecture;
pub use memory_region::{
    HasRegions, MemoryRegion, MemoryRegionFormat, MemoryRegionPerms, MemoryRegionRawData,
    MemoryRegionSize, MemoryRegionsWithFormat,
};
pub use mmu::{
    CodeMemoryOp, DataMemoryOp, MemoryType, Mmu, MmuOpError, SudoCodeMemoryOp, SudoDataMemoryOp,
};
pub use physical::{
    AddRegionError, AtomicMemoryOperationError, CompareExchangeError, FromConfigError,
    MemoryBackend, MemoryOperationError, PhysicalMemoryVariant, UnmappedMemoryError,
};
pub use tlb::{
    DummyTlb, FnTlb, TlbImpl, TlbProcessor, TlbTranslateError, TlbTranslateResult,
};

/// Enum that is used to be explicit in error handling
/// of current memory operations
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
pub enum MemoryOperation {
    Read,
    Write,
}

bitflags! {
    #[repr(C)]
    #[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
    pub struct MemoryPermissions : u32 {
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
        const RW = Self::READ.bits() | Self::WRITE.bits();
        const RX = Self::READ.bits() | Self::EXEC.bits();
        const WX = Self::WRITE.bits() | Self::EXEC.bits();
    }
}

impl std::fmt::Display for MemoryPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.contains(Self::READ) { "R" } else { "-" },
            if self.contains(Self::WRITE) { "W" } else { "-" },
            if self.contains(Self::EXEC) { "X" } else { "-" }
        )
    }
}
