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
//! Offsets into a DMA's memory mapped registers. Use
//! [DmaId::mmr_base_address()](super::id::DmaId::mmr_base_address()) to calculate register
//! addresses.
//!

// allow used offset constants
#![allow(dead_code)]

use super::sys;

pub const DMA_MMR_BASE: u32 = sys::DMA0_NEXT_DESC_PTR;
pub const DMA_MMR_LENGTH: u32 = sys::DMA1_NEXT_DESC_PTR - sys::DMA0_NEXT_DESC_PTR;

pub const NEXT_DESC_PTR_OFFSET: u32 = 0;
pub const START_ADDR_OFFSET: u32 = sys::DMA0_START_ADDR - sys::DMA0_NEXT_DESC_PTR;
pub const CONFIG_OFFSET: u32 = sys::DMA0_CONFIG - sys::DMA0_NEXT_DESC_PTR;
pub const X_COUNT_OFFSET: u32 = sys::DMA0_X_COUNT - sys::DMA0_NEXT_DESC_PTR;
pub const X_MODIFY_OFFSET: u32 = sys::DMA0_X_MODIFY - sys::DMA0_NEXT_DESC_PTR;
pub const Y_COUNT_OFFSET: u32 = sys::DMA0_Y_COUNT - sys::DMA0_NEXT_DESC_PTR;
pub const Y_MODIFY_OFFSET: u32 = sys::DMA0_Y_MODIFY - sys::DMA0_NEXT_DESC_PTR;
pub const CURR_DESC_PTR_OFFSET: u32 = sys::DMA0_CURR_DESC_PTR - sys::DMA0_NEXT_DESC_PTR;
pub const CURR_ADDR_OFFSET: u32 = sys::DMA0_CURR_ADDR - sys::DMA0_NEXT_DESC_PTR;
pub const IRQ_STATUS_OFFSET: u32 = sys::DMA0_IRQ_STATUS - sys::DMA0_NEXT_DESC_PTR;
pub const PERIPHERAL_MAP_OFFSET: u32 = sys::DMA0_PERIPHERAL_MAP - sys::DMA0_NEXT_DESC_PTR;
pub const CURR_X_COUNT_OFFSET: u32 = sys::DMA0_CURR_X_COUNT - sys::DMA0_NEXT_DESC_PTR;
pub const CURR_Y_COUNT_OFFSET: u32 = sys::DMA0_CURR_Y_COUNT - sys::DMA0_NEXT_DESC_PTR;
