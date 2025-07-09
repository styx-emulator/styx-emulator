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
