// SPDX-License-Identifier: BSD-2-Clause
//! Low level details about the Altera Cyclone V HPS
#![allow(non_upper_case_globals)]

pub type IRQn = ::std::os::raw::c_int;

/// UART0 Receive/Transmit interrupt
/// Reference: todo() verify
pub const IRQn_UART0_RX_TX_IRQn: IRQn = 194;

/// UART1 Receive/Transmit interrupt
/// Reference: todo() verify
pub const IRQn_UART1_RX_TX_IRQn: IRQn = 195;
