// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use enum_map::Enum;
use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

use super::mmr_offsets;
use super::sys;
use crate::core_event_controller::PeripheralId;

/// Identifier for each DMA channel. Implements helper methods for getting static info on DMA
/// channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(super) enum DmaId {
    Zero,
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
    Ten,
    Eleven,
}

impl From<DmaId> for PeripheralId {
    fn from(value: DmaId) -> Self {
        match value {
            DmaId::Zero => PeripheralId::DMA0,
            DmaId::One => PeripheralId::DMA1,
            DmaId::Two => PeripheralId::DMA2,
            DmaId::Three => PeripheralId::DMA3,
            DmaId::Four => PeripheralId::DMA4,
            DmaId::Five => PeripheralId::DMA5,
            DmaId::Six => PeripheralId::DMA6,
            DmaId::Seven => PeripheralId::DMA7,
            DmaId::Eight => PeripheralId::DMA8,
            DmaId::Nine => PeripheralId::DMA9,
            DmaId::Ten => PeripheralId::DMA10,
            DmaId::Eleven => PeripheralId::DMA11,
        }
    }
}

#[derive(Debug)]
pub(super) enum FromMmrAddressError {
    AddressOutOfBounds,
}
impl DmaId {
    /// Given a known memory mapped dma register, find what [DmaId] it refers to.
    ///
    /// E.g. `sys::DMA3_CURR_X_COUNT` -> [DmaId::Three].
    pub(super) fn from_mmr_address(address: u64) -> Result<Self, FromMmrAddressError> {
        let total_mmr_offset = (address as u32)
            .checked_sub(sys::DMA0_NEXT_DESC_PTR)
            .ok_or(FromMmrAddressError::AddressOutOfBounds)?;
        let dma_select = total_mmr_offset / mmr_offsets::DMA_MMR_LENGTH;
        let dma_select: u8 = dma_select
            .try_into()
            .or(Err(FromMmrAddressError::AddressOutOfBounds))?;
        DmaId::try_from(dma_select).or(Err(FromMmrAddressError::AddressOutOfBounds))
    }
    /// Numeric value of channel. [DmaId::Zero] -> 0, [DmaId::One] -> 1, etc.
    pub(super) fn index(self) -> u8 {
        self.into()
    }

    /// Base address of memory mapped registers for this DMA channel.
    pub(super) fn mmr_base_address(self) -> u32 {
        mmr_offsets::DMA_MMR_BASE + (self.index() as u32 * mmr_offsets::DMA_MMR_LENGTH)
    }

    /// `CURR_X_COUNT` register address.
    pub(super) fn x_current_register(self) -> u32 {
        self.mmr_base_address() + mmr_offsets::CURR_X_COUNT_OFFSET
    }
    /// `CURR_Y_COUNT` register address.
    pub(super) fn y_current_register(self) -> u32 {
        self.mmr_base_address() + mmr_offsets::CURR_Y_COUNT_OFFSET
    }
    /// `IRQ_STATUS` register address.
    pub(super) fn irq_status_register(self) -> u32 {
        self.mmr_base_address() + mmr_offsets::IRQ_STATUS_OFFSET
    }
}

#[cfg(test)]
mod tests {
    use super::sys;
    use crate::dma::id::DmaId;
    use test_case::test_case;

    #[test_case(DmaId::Three, sys::DMA3_CURR_Y_COUNT)]
    #[test_case(DmaId::Four, sys::DMA4_NEXT_DESC_PTR)]
    #[test_case(DmaId::Zero, sys::DMA0_IRQ_STATUS)]
    #[test_case(DmaId::Eleven, sys::DMA11_IRQ_STATUS)]
    fn test_from_mmr_address_simple(expected: DmaId, address: u32) {
        assert_eq!(expected, DmaId::from_mmr_address(address as u64).unwrap());
    }

    #[test_case(sys::SIC_IMASK)]
    #[test_case(sys::DMA0_NEXT_DESC_PTR - 4)]
    #[test_case(sys::DMA11_CURR_Y_COUNT + 8)] // +4 is technically reserved and valid
    fn test_from_mmr_address_invalid(address: u32) {
        assert!(DmaId::from_mmr_address(address as u64).is_err());
    }

    #[test_case(DmaId::Zero, sys::DMA0_IRQ_STATUS)]
    #[test_case(DmaId::Eleven, sys::DMA11_IRQ_STATUS)]
    fn test_irq_status_address(dma: DmaId, expended: u32) {
        assert_eq!(dma.irq_status_register(), expended);
    }
}
