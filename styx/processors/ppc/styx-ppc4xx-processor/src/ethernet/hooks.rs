// SPDX-License-Identifier: BSD-2-Clause
use styx_core::hooks::{MemoryReadHook, MemoryWriteHook};
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
use styx_core::prelude::*;
use tracing::debug;

use crate::core_event_controller::Event;
use crate::ethernet::EthernetController;

const ETHERNET_BASE_ADDR: u64 = 0x81000000;

const TX_BUFFER: u64 = ETHERNET_BASE_ADDR;
const TX_LEN: u64 = ETHERNET_BASE_ADDR + 0x07F4;
const GIE: u64 = ETHERNET_BASE_ADDR + 0x07F8;
const TX_CTL: u64 = ETHERNET_BASE_ADDR + 0x07FC;

const RX_BUFFER: u64 = ETHERNET_BASE_ADDR + 0x1000;
const RX_CTL: u64 = ETHERNET_BASE_ADDR + 0x17FC;

const TX_CTL_INT_ENABLE: u32 = 0x1 << 3;
const TX_CTL_PROGRAM: u32 = 0x1 << 1;
const TX_CTL_STATUS: u32 = 0x1 << 0;

const RX_CTL_STATUS: u32 = 0x1 << 0;
const RX_CTL_INT_ENABLE: u32 = 0x1 << 3;

/// Helper function to convert an array of big endian bytes to a u32
fn u32_from_be_word(data: &[u8], size: u32) -> u32 {
    debug_assert!(size <= 4, "writes >4 bytes not supported");

    let mut u32_data = [0u8; 4];
    let bytes_to_copy = size as usize;
    u32_data[0..bytes_to_copy].copy_from_slice(&data[0..bytes_to_copy]);
    u32::from_be_bytes(u32_data)
}

pub struct EthernetTxHook;

impl MemoryWriteHook for EthernetTxHook {
    /// hook callback for ethernet tx registers: TX_LEN, GIE, and TX_CTL
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "[0x{:X}] Write to ETHERNET TX registers @{:x} or size: {}, data: {:?}",
            proc.cpu.pc().unwrap(),
            address,
            size,
            data
        );

        let ethernet_controller = proc
            .event_controller
            .peripherals
            .get::<EthernetController>()
            .unwrap();

        let register_value: u32 = u32_from_be_word(data, size);

        match address {
            TX_LEN => {
                debug!("\tTX len set to: {}", register_value);
                ethernet_controller.set_tx_len(register_value as usize);
            }
            GIE => {
                if register_value == 0 {
                    // global interrupts disabled
                    ethernet_controller.global_interrupts_enabled = false;
                } else {
                    // global interrupts enabled
                    ethernet_controller.global_interrupts_enabled = true;
                }
            }
            TX_CTL => {
                if register_value & TX_CTL_INT_ENABLE == 0 {
                    // tx interrupts disabled
                    ethernet_controller.tx_interrupts_enabled = false;
                } else {
                    // tx interrupts enabled
                    ethernet_controller.tx_interrupts_enabled = true;
                }

                // program bit set
                if register_value & TX_CTL_PROGRAM > 0 {
                    if register_value & TX_CTL_STATUS > 0 {
                        // program and status bits both set, updating MAC
                        let mac_vec = proc.mmu.data().read(TX_BUFFER).vec(6)?;
                        let mac = mac_vec.as_slice();
                        ethernet_controller.mac_addr = mac.try_into().unwrap();

                        // mac change is ethernet interrupt?
                        if ethernet_controller.global_interrupts_enabled
                            && ethernet_controller.tx_interrupts_enabled
                        {
                            proc.event_controller.latch(Event::Ethernet.into()).unwrap();
                        }
                    }
                } else {
                    // send packet
                    if register_value & TX_CTL_STATUS > 0 {
                        let packet = proc
                            .mmu
                            .data()
                            .read(TX_BUFFER)
                            .vec(ethernet_controller.get_tx_len())?;
                        ethernet_controller.guest_send_packet(packet);
                    }
                }
            }
            _ => unreachable!("something wrong has happened"),
        }
        Ok(())
    }
}

/// Memory read hook callback for TX_CTL register
impl MemoryReadHook for EthernetTxHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "[0x{:X}] Read from ETHERNET TX CTL register @{:x} or size: {}, data: {:?}",
            proc.cpu.pc()?,
            address,
            size,
            data
        );

        // the program and status bits should always get unset immediately after being set, we don't care about the loopback flag, and the guest programs will never read the interrupt enabled flag so this register can always read 0
        data[3] = 0;
        Ok(())
    }
}

pub struct EthernetRxHook;

/// Memory write hook callback for the RX_CTL register
impl MemoryWriteHook for EthernetRxHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "[0x{:X}] Write to ETHERNET RX CTL register @{:x} or size: {}, data: {:?}",
            proc.cpu.pc()?,
            address,
            size,
            data
        );

        let ethernet_controller = proc
            .event_controller
            .peripherals
            .get::<EthernetController>()
            .unwrap();

        let register_value: u32 = u32_from_be_word(data, size);

        if register_value & RX_CTL_STATUS == 0 {
            // clear bit set, ready for more data
            if let Some(packet) = ethernet_controller.guest_receive_data() {
                // write frame + crc to rx buffer
                proc.mmu.data().write(RX_BUFFER).bytes(&packet.frame)?;
                proc.mmu
                    .data()
                    .write(RX_BUFFER + (packet.frame.len() as u64))
                    .le()
                    .u32(packet.crc)?;

                // set status bit to indicate data is ready to be read
                proc.mmu.data().write(RX_CTL).be().u32(1)?;
            }
        }

        if register_value & RX_CTL_INT_ENABLE == 0 {
            // disable rx interrupts
            ethernet_controller.rx_interrupts_enabled = false;
        } else {
            // enable rx interrupts
            ethernet_controller.rx_interrupts_enabled = true;
        }

        Ok(())
    }
}

/// Memory read hook callback for RX_CTL register
impl MemoryReadHook for EthernetRxHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "[0x{:X}] Read from ETHERNET RX CTL register @{:x} or size: {}, data: {:?}",
            proc.cpu.pc()?,
            address,
            size,
            data
        );

        let ethernet_controller = proc
            .event_controller
            .peripherals
            .get::<EthernetController>()
            .unwrap();

        if ethernet_controller.rx_data_available() {
            data[3] = 1;
        } else {
            data[3] = 0;
        }

        Ok(())
    }
}
