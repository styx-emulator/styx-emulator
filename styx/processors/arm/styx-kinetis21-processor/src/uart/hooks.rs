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
// # Allow
// allow unused variables because most of this file was just
// scripted creation, when the implementation finishes this
// will be removed.
use std::mem::offset_of;
use styx_core::hooks::MemoryReadHook;
use styx_core::hooks::MemoryWriteHook;
use styx_core::prelude::*;
use styx_peripherals::uart::UartController;
use tracing::{debug, error};

use styx_mk21f12_sys::UART_Type;

use super::inner::*;
use super::UartPortInner;

pub struct UartC2Hook(pub String);
pub struct UartS1Hook(pub String);
pub struct UartDHook(pub String);

impl MemoryWriteHook for UartC2Hook {
    fn call(
        &mut self,
        proc: CoreHandle,
        _address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        if size != 1 {
            error!("Write to C2 of improper size: {}", size);
        }

        let uart_controller = proc
            .event_controller
            .peripherals
            .get::<UartController>()
            .unwrap();
        let uart_port = uart_controller.get::<UartPortInner>(&self.0).unwrap();
        let uart_inner = &mut uart_port.inner_hal;

        uart_inner.c2 = C2::from(data[0]);

        debug!(
            "Guest wrote to UART{} C2: {:?}",
            uart_port.interface_id,
            *uart_inner.c2()
        );

        if uart_inner.c2.tie() {
            // enabled the interrupt....lets go for it

            // set transmit data register empty
            let s1_address = uart_port.base_address as u64 + offset_of!(UART_Type, S1) as u64;
            uart_inner.s1 = S1::from(proc.mmu.read_u8_le_phys_data(s1_address).unwrap());
            uart_inner.s1.set_tdre(true.into());
            proc.mmu
                .write_data(s1_address, &[uart_inner.s1.clone().into()])
                .unwrap();

            // latch the irq
            let irq = uart_port.tx_rx_irqn;
            proc.event_controller.latch(irq).unwrap();
        }
        Ok(())
    }
}

impl MemoryWriteHook for UartS1Hook {
    fn call(
        &mut self,
        proc: CoreHandle,
        _address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        if size != 1 {
            error!("Write to S1 of improper size: {}", size);
        }

        let uart_controller = proc
            .event_controller
            .peripherals
            .get::<UartController>()
            .unwrap();
        let uart_port = uart_controller.get::<UartPortInner>(&self.0).unwrap();
        let uart_inner = &mut uart_port.inner_hal;

        uart_inner.s1 = S1::from(data[0]);

        debug!(
            "Guest wrote to UART{} S1: {:?}",
            uart_port.interface_id,
            *uart_inner.s1()
        );
        Ok(())
    }
}

impl MemoryReadHook for UartS1Hook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        if size != 1 {
            error!("Read from S1 of improper size: {}", size);
        }

        let uart_controller = proc
            .event_controller
            .peripherals
            .get::<UartController>()
            .unwrap();
        let uart_port = uart_controller.get::<UartPortInner>(&self.0).unwrap();

        let has_data = uart_port.rx_valid();

        let uart_inner = &mut uart_port.inner_hal;

        let s1 = &mut uart_inner.s1;
        *s1 = S1::from(proc.mmu.read_u8_le_phys_data(address).unwrap());

        debug!(
            "Guest read from UART{} S1: {:?}",
            uart_port.interface_id, *s1
        );

        // set the RDRF flag accordingly
        if has_data {
            s1.set_rdrf(true.into());
        } else {
            s1.set_rdrf(false.into());
        }

        // now get the S1 as a u8 and write it
        let new_s1: S1 = uart_inner.s1().clone();
        data[0] = new_s1.into();
        Ok(())
    }
}

impl MemoryWriteHook for UartDHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        _address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        if size != 1 {
            error!("Write to D of improper size: {}", size);
        }

        let uart_controller = proc
            .event_controller
            .peripherals
            .get::<UartController>()
            .unwrap();
        let uart_port = uart_controller.get::<UartPortInner>(&self.0).unwrap();

        debug!(
            "Guest wrote to UART{} D: {:?} from: {:#08x}",
            uart_port.interface_id,
            data[0],
            proc.cpu.pc().unwrap()
        );
        uart_port.guest_transmit_data(data[0]);

        let uart_inner = &mut uart_port.inner_hal;

        uart_inner.d = D::from(data[0]);

        // completed 1 tx, set bit
        let mut s1 = uart_inner.s1().clone();
        s1.set_tc(true.into());
        // set s1 in the memory copy
        uart_inner.s1 = s1.clone();
        let data: u8 = s1.into();
        let s1_address = uart_port.base_address as u64 + offset_of!(UART_Type, S1) as u64;
        // set s1 in the emulator
        proc.mmu.write_data(s1_address, &[data]).unwrap();
        Ok(())
    }
}

impl MemoryReadHook for UartDHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        _address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        if size != 1 {
            error!("Read from D of improper size: {}", size);
        }

        let uart_controller = proc
            .event_controller
            .peripherals
            .get::<UartController>()
            .unwrap();
        let uart_port = uart_controller.get::<UartPortInner>(&self.0).unwrap();

        debug!("Guest read from UART{} D", uart_port.interface_id);

        let value = uart_port.guest_receive_data();
        data[0] = value;

        let uart_inner = &mut uart_port.inner_hal;
        uart_inner.s1.set_rdrf(false.into());

        // keeping this for now in case we need it, instead of writing to memory i just modified the mut data buffer
        //proc.mmu.write_data(address, &[value]).unwrap();
        Ok(())
    }
}
