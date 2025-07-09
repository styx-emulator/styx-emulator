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
//! Emulates Uart controller for the STM32F405.
use inner::{Port, UartPortInner};
use paste::paste;
use styx_core::{
    hooks::{MemoryReadHook, MemoryWriteHook},
    prelude::*,
};
use styx_peripherals::uart::{UartController, UartInterface};
use styx_stm32f405_sys::{
    uart4, uart5, usart1, usart2, usart3, usart6, Uart4, Uart5, Usart1, Usart2, Usart3, Usart6,
};

// all the memory hooks
mod hooks;
mod inner;

pub fn get_uarts() -> Vec<UartInterface> {
    vec![
        UartInterface::new("1".into(), inner::UartPortBuilder::new(Port::UsartOne)),
        UartInterface::new("2".into(), inner::UartPortBuilder::new(Port::UsartTwo)),
        UartInterface::new("3".into(), inner::UartPortBuilder::new(Port::UsartThree)),
        UartInterface::new("4".into(), inner::UartPortBuilder::new(Port::UartFour)),
        UartInterface::new("5".into(), inner::UartPortBuilder::new(Port::UartFive)),
        UartInterface::new("6".into(), inner::UartPortBuilder::new(Port::UsartSix)),
    ]
}

/// Generates the code required to tie the Read + Write callback to
/// to the backend, lots of code de-dupe
// Define constant register addresses for all ports.
macro_rules! compute_reg_address_usart {
    ($port_num:literal, $register:ident) => {
        paste! {
            [< usart $port_num >]::[< $register:camel >]::offset()
                + [< Usart $port_num >]::BASE as u64
        }
    };
}

macro_rules! compute_reg_address_uart {
    ($port_num:literal, $register:ident) => {
        paste! {
            [< uart $port_num >]::[< $register:camel >]::offset()
                + [< Uart $port_num >]::BASE as u64
        }
    };
}
macro_rules! const_reg_addr_usart {
    ($port_num:literal, $register:ident) => {
        paste! {
            const [< USART $port_num _ $register:upper _ADDR >]: u64 = compute_reg_address_usart!($port_num, $register);
        }
    };
}

macro_rules! const_reg_addr_uart {
    ($port_num:literal, $register:ident) => {
        paste! {
            const [< UART $port_num _ $register:upper _ADDR >]: u64 = compute_reg_address_uart!($port_num, $register);
        }
    };
}

macro_rules! def_const_reg_addrs_usart {
    ([ $( $register:ident ),* $(,)?]) => {
        $(
            const_reg_addr_usart!(1, $register);
            const_reg_addr_usart!(2, $register);
            const_reg_addr_usart!(3, $register);
            const_reg_addr_usart!(6, $register);
        )*
    }
}

macro_rules! def_const_reg_addrs_uart {
    ([ $( $register:ident ),* $(,)?]) => {
        $(
            const_reg_addr_uart!(4, $register);
            const_reg_addr_uart!(5, $register);
        )*
    }
}

macro_rules! def_const_reg_addresses_usart {
    () => {
        def_const_reg_addrs_usart!([cr1, sr, dr,]);
    };
}

macro_rules! def_const_reg_addresses_uart {
    () => {
        def_const_reg_addrs_uart!([cr1, sr, dr,]);
    };
}
def_const_reg_addresses_usart!();
def_const_reg_addresses_uart!();

macro_rules! call_reg_hook {
    (
        $rw:ident,
        $register:ident,
        $cpu:ident,
        $ev:ident,
        $addr:ident,
        $size:ident,
        $data:ident,
        $port:ident
     ) => {
        paste! {
            if $addr == [< USART 1 _ $register:upper _ADDR >]
                || $addr == [< USART 2 _ $register:upper _ADDR >]
                || $addr == [< USART 3 _ $register:upper _ADDR >]
                || $addr == [< UART 4 _ $register:upper _ADDR >]
                || $addr == [< UART 5 _ $register:upper _ADDR >]
                || $addr == [< USART 6 _ $register:upper _ADDR >] {
                return hooks::[<usart_port_ $register:lower _ $rw:lower _hook>]( // usart
                    $cpu, $ev, $addr, $size, $data, $port
                );
            }
        }
    };
}

macro_rules! call_hooks_inner {
    (
        $rw:ident,
        $cpu:ident,
        $ev:ident,
        $addr:ident,
        $size:ident,
        $data:ident,
        $port:ident,
        [ $( $register:ident ),* $(,)? ]
    ) => {
        $( call_reg_hook!($rw, $register, $cpu, $ev, $addr, $size, $data, $port); )*
    }
}

macro_rules! call_hooks {
    (
        $rw:ident,
        $cpu:ident,
        $ev:ident,
        $addr:ident,
        $size:ident,
        $data:ident,
        $port:ident
     ) => {
        call_hooks_inner!(
            $rw,
            $cpu,
            $ev,
            $addr,
            $size,
            $data,
            $port,
            // note: the only registers we care about are dr, sr, cr1, and possibly cr3
            [
                cr1, // cr3, not used in our simulation as of now
                sr, dr,
            ]
        )
    };
}

struct InnerHook(String);

impl MemoryReadHook for InnerHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let controller = proc
            .event_controller
            .peripherals
            .get_expect::<UartController>()?;
        let port = controller.try_get::<UartPortInner>(&self.0)?;
        let cpu = proc.cpu;
        let ev = proc.event_controller.inner.as_mut();
        call_hooks!(r, cpu, ev, address, size, data, port);

        Ok(())
    }
}
impl MemoryWriteHook for InnerHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let controller = proc
            .event_controller
            .peripherals
            .get_expect::<UartController>()?;
        let port = controller.try_get::<UartPortInner>(&self.0)?;
        let cpu = proc.cpu;
        let ev = proc.event_controller.inner.as_mut();
        call_hooks!(w, cpu, ev, address, size, data, port);

        Ok(())
    }
}

impl UartPortInner {
    /// Connects all the MMIO registers belonging to the [`UartPortInner`]
    /// to the actual backend.
    fn register_mmio_hooks(&self, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        let start = self.base_address() as u64;
        let end = self.base_address() as u64 + std::mem::size_of::<usart1::RegisterBlock>() as u64;
        let range = start..=end;
        cpu.add_hook(StyxHook::memory_write(
            range.clone(),
            InnerHook(self.interface_id.clone()),
        ))?;
        cpu.add_hook(StyxHook::memory_read(
            range,
            InnerHook(self.interface_id.clone()),
        ))?;

        Ok(())
    }
}
