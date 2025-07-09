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
/// Hooks assume reads/writes are aligned to 4 bytes
use styx_core::{
    hooks::{MemoryReadHook, MemoryWriteHook},
    prelude::*,
};
use styx_peripherals::uart::UartController;
use tracing::debug;

use super::UartPortInner;

const UART_RX_FIFO_OFFSET: u64 = 0x84000000;
const UART_TX_FIFO_OFFSET: u64 = 0x84000004;
const UART_STATUS_OFFSET: u64 = 0x84000008;
const UART_CTL_OFFSET: u64 = 0x8400000C;

const CTL_REG_ENABLE_INTR: u8 = 0x10;
const CTL_REG_RX_FIFO_RESET: u8 = 0x2;

const STAT_REG_INTR_ENABLED: u8 = 0x10;
const STAT_REG_TX_FIFO_EMPTY: u8 = 0x4;
const STAT_REG_RX_FIFO_VALID: u8 = 0x1;

pub struct UartHook {
    pub interface_id: String,
}

impl MemoryReadHook for UartHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "[0x{:X}] Read from UART registers @0x{:x} of size: {}, data: {:?}",
            proc.cpu.pc().unwrap(),
            address,
            size,
            data
        );

        let uart_controller = proc
            .event_controller
            .peripherals
            .get::<UartController>()
            .unwrap();
        let uart_port = &mut uart_controller
            .get::<UartPortInner>(&self.interface_id)
            .unwrap();

        // a pointer to the last byte in the read data, the 1 byte register
        let register_data = &mut data[3];

        match address {
            UART_RX_FIFO_OFFSET => {
                *register_data = uart_port.guest_receive_data();
                debug!("UART Receive Data: 0x{:x}", register_data);
            }
            UART_STATUS_OFFSET => {
                // return the actual status register value
                let mut stat_reg: u8 = STAT_REG_TX_FIFO_EMPTY;

                if uart_port.intr_enabled {
                    stat_reg |= STAT_REG_INTR_ENABLED;
                }

                if uart_port.rx_valid() {
                    stat_reg |= STAT_REG_RX_FIFO_VALID;
                }

                // update memory read to the proper value
                *register_data = stat_reg;
            }
            UART_TX_FIFO_OFFSET | UART_CTL_OFFSET => {
                // todo, ignore read i.e. return 0
                // for now assume that programs don't try to read these registers
            }
            _ => {
                // if we hit this branch then something weird happened (like an unaligned read)
                unreachable!()
            }
        }
        Ok(())
    }
}

impl MemoryWriteHook for UartHook {
    /// Size should always be 4 bytes, registers themselves are always 1 byte
    /// CPU is big endian so the 4th byte will be the one of interest.
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "[0x{:X}] Write to UART registers @{:x} or size: {}, data: {:?}",
            proc.cpu.pc().unwrap(),
            address,
            size,
            data
        );
        let uart_controller = proc
            .event_controller
            .peripherals
            .get::<UartController>()
            .unwrap();
        let uart_port = &mut uart_controller.try_get::<UartPortInner>("0")?;
        let register_data: u8 = data[3];

        match address {
            UART_TX_FIFO_OFFSET => {
                debug!("UART Transmit Data: 0x{:x}", register_data);
                uart_port.guest_transmit_data(register_data);
            }
            UART_CTL_OFFSET => {
                if register_data & CTL_REG_ENABLE_INTR > 0 {
                    debug!("UART Enable Interrupts");
                    uart_port.intr_enabled = true;
                } else {
                    debug!("UART Disable Interrupts");
                    uart_port.intr_enabled = false;
                }

                // there is another flag to clear the tx fifo but we don't ever need to do that
                if register_data & CTL_REG_RX_FIFO_RESET > 0 {
                    debug!("UART Reset RX FIFO");
                    uart_port.reset_rx_fifo();
                }
            }
            UART_RX_FIFO_OFFSET | UART_STATUS_OFFSET => {
                // todo, ignore write i.e. do nothing
                // for now assume that programs don't try to write to these registers
            }
            _ => {
                // if we hit this branch then something weird happened (like an unaligned write)
                unreachable!()
            }
        }
        Ok(())
    }
}
