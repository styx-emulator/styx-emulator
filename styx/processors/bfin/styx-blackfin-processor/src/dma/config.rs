// SPDX-License-Identifier: BSD-2-Clause
//! Bitfields for configuring DMA channels.
//!
//! Mostly these are bitfields from the `DMAx_CONFIG` register but also [IrqStatus] is defined which
//! is its own register.
use bilge::prelude::*;

/// `DMAx_CONFIG` register.
#[bitsize(15)]
#[derive(TryFromBits, DefaultBits, DebugBits)]
pub struct DmaConfig {
    pub enable: bool,
    pub direction: DmaDirection,
    pub word_size: WordSize,
    pub mode: Mode,
    pub sync: SyncWorkUnitTransitions,
    pub interrupt_timing: DataInterruptTimingSelect,
    pub interrupt_enabled: bool,
    pub flex_descriptor_size: u4,
    pub flow: NextOperationFlow,
}

#[bitsize(1)]
#[derive(FromBits, Default, Debug)]
pub enum DmaDirection {
    /// DMA is a memory read (source) operation
    #[default]
    MemoryRead,
    /// DMA is a memory write (destination) operation
    MemoryWrite,
}

#[bitsize(2)]
#[derive(TryFromBits, Default, Debug)]
pub enum WordSize {
    #[default]
    EightBit,
    SixteenBit,
    ThirtyTwoBit,
}

#[bitsize(1)]
#[derive(FromBits, Default, Debug, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Linear,
    TwoDimensional,
}

#[bitsize(1)]
#[derive(FromBits, Default, Debug)]
pub enum SyncWorkUnitTransitions {
    #[default]
    Continuous,
    Synchronized,
}

#[bitsize(1)]
#[derive(FromBits, Default, Debug)]
pub enum DataInterruptTimingSelect {
    #[default]
    InterruptAfterWholeBuffer,
    InterruptAfterRow,
}

#[bitsize(3)]
#[derive(TryFromBits, Default, Debug)]
pub enum NextOperationFlow {
    /// Stop after current work unit completes.
    #[default]
    Stop,
    /// Repeat using MMR configuration until disabled by `DMAEN` bit in `DMAx_CONFIG` register
    AutoBuffer,
    DescriptorArray = 0x4,
    DescriptorListSmallModel = 0x6,
    DescriptorListLargeModel = 0x7,
}

/// `IRQ_STATUS` register.
#[bitsize(4)]
#[derive(FromBits, DebugBits, DefaultBits, Clone, Copy)]
pub struct IrqStatus {
    pub done: bool,
    pub error: bool,
    pub descriptor_fetch: bool,
    pub run: bool,
}
