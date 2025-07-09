// SPDX-License-Identifier: BSD-2-Clause
//! DMA support for blackfin processors.
//!
//! - manages peripheral DMA channels, including receiving data from mapped async sources and
//!   register based configuration
//! - interrupt on row/total completion as well as proper irq status
//! - 2d mode support and updated DMAx_X_CURR and DMAx_Y_CURR registers.
//!
//! # Interface
//!
//! The processor will only have to interact with the [DmaController] and the [DmaSources]. The
//! [DmaSources] is used to map async [Stream](futures::stream::Stream)s to DMA channels. Currently
//! this only supports the peripheral -> dma stream but in the future would contain a sender to
//! facilitate dma -> peripheral communication.
//!
//! # Missing features
//!
//! - memory DMA
//! - DMA transmit
//! - many configuration values
//! - memory descriptors
//! - DMA run bit while running
//!
//! # Layout
//!
//! - [controller] contains the [DmaController] (the
//!   [Peripheral](styx_core::prelude::Peripheral) for dma) including register hooks and the
//!   peripheral source async loop.
//! - [container] facilitates creation and delegation to the 12 DMA channels.
//! - [state] contains the low level logic for manipulating runtime state of the DMA channels.
//! - [id] has the static info of the DMA channels through [DmaId](id::DmaId) (register addresses,
//!   etc.)
//!

mod config;
mod container;
mod controller;
mod id;
mod mmr_offsets;
mod peripheral_mapping;
mod state;

use styx_blackfin_sys::bf512 as sys;

pub(crate) use controller::{DmaController, DmaSources, DmaStream};
pub(crate) use peripheral_mapping::DmaPeripheralMapping;
