// SPDX-License-Identifier: BSD-2-Clause
//! Load-Linked/Store-Conditional methods for Mmu.
use tap::Conv;
use thiserror::Error;

use crate::cpu::CpuBackend;

use super::{
    atomic_word::AtomicWord, physical::AtomicMemoryOperationError, CompareExchangeError,
    MemoryOperation, MemoryType, Mmu, TlbTranslateError,
};

/// Returned from a Load Linked call to enable a Store Conditional.
///
/// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
/// for detailed information and gotchas.
pub struct Load {
    /// Address of access.
    ///
    /// Used to sanity check that the SC and LL match.
    address: u64,
    /// Value of `*address`, spans `size` bytes.
    value: [u8; AtomicWord::WORD_SIZE_BYTES],
    /// Indicates size of `value`.
    size: usize,
}

impl Load {
    /// Loaded data from the Load Linked operation.
    pub fn data(&self) -> &[u8] {
        &self.value[..self.size]
    }

    /// Address of the Load Linked operation.
    pub fn address(&self) -> u64 {
        self.address
    }
}

impl Mmu {
    /// Loads and reserves `*paddr` in data memory in memory for future [`Mmu::store_conditional_data()`].
    ///
    /// Use the `code`/`data` variant that is most appropriate.
    /// For Von Neumann architectures, `data` vs `code` has no effect.
    ///
    /// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
    /// for detailed information and gotchas.
    pub fn load_linked_data(
        &self,
        paddr: u64,
        size: usize,
    ) -> Result<Load, AtomicMemoryOperationError> {
        let mut load = check_load(paddr, size)?;
        self.read_data(paddr, &mut load.value[..size])?;
        Ok(load)
    }

    /// Loads and reserves `*paddr` in code memory in memory for future [`Mmu::store_conditional_code()`].
    ///
    /// Use the `code`/`data` variant that is most appropriate.
    /// For Von Neumann architectures, `data` vs `code` has no effect.
    ///
    /// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
    /// for detailed information and gotchas.
    pub fn load_linked_code(
        &self,
        paddr: u64,
        size: usize,
    ) -> Result<Load, AtomicMemoryOperationError> {
        let mut load = check_load(paddr, size)?;
        self.read_code(paddr, &mut load.value[..size])?;
        Ok(load)
    }

    /// Loads and reserves `*vaddr` in data memory in memory for future [`Mmu::virt_store_conditional_data()`].
    ///
    /// Use the `code`/`data` variant that is most appropriate.
    /// For Von Neumann architectures, `data` vs `code` has no effect.
    ///
    /// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
    /// for detailed information and gotchas.
    pub fn virt_load_linked_data(
        &mut self,
        vaddr: u64,
        size: usize,
        cpu: &mut dyn CpuBackend,
    ) -> Result<Load, AtomicMmuOpError> {
        let phys_addr = self.translate_va(vaddr, MemoryOperation::Read, MemoryType::Data, cpu)?;
        let mut load = check_load(phys_addr, size)?;
        self.read_data(vaddr, &mut load.value[..size])
            .map_err(|e| e.conv::<AtomicMemoryOperationError>())?;
        Ok(load)
    }

    /// Loads and reserves `*vaddr` in code memory in memory for future [`Mmu::virt_store_conditional_code()`].
    ///
    /// Use the `code`/`data` variant that is most appropriate.
    /// For Von Neumann architectures, `data` vs `code` has no effect.
    ///
    /// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
    /// for detailed information and gotchas.
    pub fn virt_load_linked_code(
        &mut self,
        vaddr: u64,
        size: usize,
        cpu: &mut dyn CpuBackend,
    ) -> Result<Load, AtomicMmuOpError> {
        let phys_addr = self.translate_va(vaddr, MemoryOperation::Read, MemoryType::Code, cpu)?;
        let mut load = check_load(phys_addr, size)?;
        self.read_code(vaddr, &mut load.value[..size])
            .map_err(|e| e.conv::<AtomicMemoryOperationError>())?;
        Ok(load)
    }

    /// Conditionally store `*paddr` that was reserved from a previous [`Mmu::load_linked_data()`].
    ///
    /// [`StoreConditionalResult`] is successful if the current value of `*paddr` is the same as
    /// captured at the time of the `load`.
    /// Note: this is different behavior from traditional LL/SC that would fail if the value is the same
    /// but the memory what written to.
    ///
    /// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
    /// for detailed information and gotchas.
    pub fn store_conditional_data(
        &self,
        paddr: u64,
        load: Load,
        store: &[u8],
    ) -> Result<StoreConditionalResult, StoreConditionalError> {
        if paddr != load.address {
            return Err(StoreConditionalError::MismatchAddress(paddr, load.address));
        }

        Ok(StoreConditionalResult::from_success(
            self.compare_exchange_data(paddr, load.data(), store)?
                .success(),
        ))
    }

    /// Conditionally store `*paddr` that was reserved from a previous [`Mmu::load_linked_code()`].
    ///
    /// [`StoreConditionalResult`] is successful if the current value of `*paddr` is the same as
    /// captured at the time of the `load`.
    /// Note: this is different behavior from traditional LL/SC that would fail if the value is the same
    /// but the memory what written to.
    ///
    /// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
    /// for detailed information and gotchas.
    pub fn store_conditional_code(
        &self,
        paddr: u64,
        load: Load,
        store: &[u8],
    ) -> Result<StoreConditionalResult, StoreConditionalError> {
        if paddr != load.address {
            return Err(StoreConditionalError::MismatchAddress(paddr, load.address));
        }

        Ok(StoreConditionalResult::from_success(
            self.compare_exchange_code(paddr, load.data(), store)?
                .success(),
        ))
    }

    /// Conditionally store `*vaddr` that was reserved from a previous [`Mmu::virt_load_linked_data()`].
    ///
    /// [`StoreConditionalResult`] is successful if the current value of `*vaddr` is the same as
    /// captured at the time of the `load`.
    /// Note: this is different behavior from traditional LL/SC that would fail if the value is the same
    /// but the memory what written to.
    ///
    /// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
    /// for detailed information and gotchas.
    pub fn virt_store_conditional_data(
        &mut self,
        vaddr: u64,
        load: Load,
        store: &[u8],
        cpu: &mut dyn CpuBackend,
    ) -> Result<StoreConditionalResult, VirtStoreConditionalError> {
        if vaddr != load.address {
            return Err(StoreConditionalError::MismatchAddress(vaddr, load.address).into());
        }
        let paddr = self.translate_va(vaddr, MemoryOperation::Read, MemoryType::Data, cpu)?;
        Ok(StoreConditionalResult::from_success(
            self.compare_exchange_data(paddr, load.data(), store)
                .map_err(|e| e.conv::<StoreConditionalError>())?
                .success(),
        ))
    }

    /// Conditionally store `*vaddr` that was reserved from a previous [`Mmu::virt_load_linked_code()`].
    ///
    /// [`StoreConditionalResult`] is successful if the current value of `*vaddr` is the same as
    /// captured at the time of the `load`.
    /// Note: this is different behavior from traditional LL/SC that would fail if the value is the same
    /// but the memory what written to.
    ///
    /// Refer to the [module documentation](crate::memory#load-linkstore-conditional)
    /// for detailed information and gotchas.
    pub fn virt_store_conditional_code(
        &mut self,
        vaddr: u64,
        load: Load,
        store: &[u8],
        cpu: &mut dyn CpuBackend,
    ) -> Result<StoreConditionalResult, VirtStoreConditionalError> {
        if vaddr != load.address {
            return Err(StoreConditionalError::MismatchAddress(vaddr, load.address).into());
        }
        let paddr = self.translate_va(vaddr, MemoryOperation::Read, MemoryType::Code, cpu)?;
        Ok(StoreConditionalResult::from_success(
            self.compare_exchange_code(paddr, load.data(), store)
                .map_err(|e| e.conv::<StoreConditionalError>())?
                .success(),
        ))
    }
}

#[derive(Error, Debug)]
pub enum StoreConditionalError {
    #[error("mismatched address")]
    MismatchAddress(u64, u64),
    #[error(transparent)]
    AtomicOperation(#[from] CompareExchangeError),
}

/// Success of [`Mmu::store_conditional_data()`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreConditionalResult {
    Success,
    Failure,
}
impl StoreConditionalResult {
    pub fn from_success(success: bool) -> Self {
        if success {
            Self::Success
        } else {
            Self::Failure
        }
    }

    pub fn success(self) -> bool {
        match self {
            StoreConditionalResult::Success => true,
            StoreConditionalResult::Failure => false,
        }
    }
}

#[derive(Error, Debug)]
pub enum AtomicMmuOpError {
    #[error("encountered physical memory error")]
    PhysicalMemoryError(#[from] AtomicMemoryOperationError),
    #[error(transparent)]
    TlbTranslateError(#[from] TlbTranslateError),
}

#[derive(Error, Debug)]
pub enum VirtStoreConditionalError {
    #[error(transparent)]
    TlbTranslateError(#[from] TlbTranslateError),
    #[error(transparent)]
    StoreConditionalError(#[from] StoreConditionalError),
}

/// Helper, verifies size of atomic load fits in [`AtomicWord`].
fn check_load(address: u64, size: usize) -> Result<Load, AtomicMemoryOperationError> {
    // this check is to avoid a panic when we index into `load.value`.
    if size > AtomicWord::WORD_SIZE_BYTES {
        return Err(AtomicMemoryOperationError::TooLarge {
            address,
            bytes: size,
            max_size: AtomicWord::WORD_SIZE_BYTES,
        });
    }

    Ok(Load {
        address,
        size,
        value: [0u8; AtomicWord::WORD_SIZE_BYTES],
    })
}

#[cfg(test)]
mod tests {
    use crate::memory::helpers::{ReadExt, WriteExt};

    use super::*;

    #[test]
    fn test_ll_sc() {
        const ADDRESS: u64 = 0x1000;
        let mut mmu = Mmu::default();
        mmu.data().write(ADDRESS).bytes(&[0x12, 0x34]).unwrap();

        let ll = mmu.load_linked_data(ADDRESS, 2).unwrap();
        assert_eq!(ll.data(), &[0x12, 0x34]);
        let result = mmu
            .store_conditional_data(ll.address(), ll, &[0x13, 0x37])
            .unwrap();
        assert_eq!(result, StoreConditionalResult::Success);
        // store successful, data should be written
        assert_eq!(
            mmu.data().read(ADDRESS).vec(2).unwrap().as_slice(),
            &[0x13, 0x37]
        );

        let ll = mmu.load_linked_data(ADDRESS, 2).unwrap();
        assert_eq!(ll.data(), &[0x13, 0x37]);
        mmu.data().write(ADDRESS).bytes(&[0xCA, 0xFE]).unwrap();
        let result = mmu
            .store_conditional_data(ll.address(), ll, &[0xBA, 0xBE])
            .unwrap();
        assert_eq!(result, StoreConditionalResult::Failure);
        // not successful, did not write 0xBABE
        assert_eq!(
            mmu.data().read(ADDRESS).vec(2).unwrap().as_slice(),
            &[0xCA, 0xFE]
        )
    }
}
