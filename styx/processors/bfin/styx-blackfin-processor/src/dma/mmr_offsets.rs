// SPDX-License-Identifier: BSD-2-Clause
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
