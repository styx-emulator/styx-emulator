// SPDX-License-Identifier: BSD-2-Clause
//! Emulation of the DMA controller for STM32F405
#![allow(dead_code)] // todo: dma not fully implemented yet
use std::{
    collections::{HashMap, VecDeque},
    mem::size_of,
};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use styx_core::prelude::*;

use styx_stm32f405_sys::{dma1, dma2, generic::FromBytes, Dma1};

/// Apply a macro to the register structure, also passing additional arguments. This helps with
/// increasing code reuse and improving code readability.
#[allow(unused_macros)] // todo: not fully implemented yet
macro_rules! apply_macro_to_regs {
    ($hal:ident, $macro:ident, $($args:ident),*) => {
        match &mut $hal.registers {
            DmaRegisters::Dma1(regs) => {
                $macro!($hal, regs, $($args),*);
            },
            DmaRegisters::Dma2(regs) => {
                $macro!($hal, regs, $($args),*);
            },
        }
    }
}
#[allow(unused_imports)] // todo: not fully implemented yet
pub(crate) use apply_macro_to_regs;

/// STM32F405 DMA data streams each have 4-word transmit and receive buffers, so 16 total bytes.
/// See **[STM32F405xx: Memory Mapping: Figure 18 and Table 10](https://www.st.com/resource/en/datasheet/dm00037051.pdf#page=71)**
pub const DMA_STREAM_FIFO_SIZE: usize = 16;

// # Safety
// These two unsafe blocks are performing hardware initialization,
// so it should use the sys_reset/register_clear methods
//
// in other words "permissions have no bearing here"
macro_rules! reset_dma_regs {
    ($regs:ident, $mmu:ident, $base:ident) => {
        unsafe {
            // Reset all registers in the DMA block.
            $regs.lisr().sys_reset();
            $regs.hisr().sys_reset();
            $regs.lifcr().sys_reset();
            $regs.hifcr().sys_reset();
            $regs.s0cr().sys_reset();
            $regs.s0ndtr().sys_reset();
            $regs.s0par().sys_reset();
            $regs.s0m0ar().sys_reset();
            $regs.s0m1ar().sys_reset();
            $regs.s0fcr().sys_reset();
            $regs.s1cr().sys_reset();
            $regs.s1ndtr().sys_reset();
            $regs.s1par().sys_reset();
            $regs.s1m0ar().sys_reset();
            $regs.s1m1ar().sys_reset();
            $regs.s1fcr().sys_reset();
            $regs.s2cr().sys_reset();
            $regs.s2ndtr().sys_reset();
            $regs.s2par().sys_reset();
            $regs.s2m0ar().sys_reset();
            $regs.s2m1ar().sys_reset();
            $regs.s2fcr().sys_reset();
            $regs.s3cr().sys_reset();
            $regs.s3ndtr().sys_reset();
            $regs.s3par().sys_reset();
            $regs.s3m0ar().sys_reset();
            $regs.s3m1ar().sys_reset();
            $regs.s3fcr().sys_reset();
            $regs.s4cr().sys_reset();
            $regs.s4ndtr().sys_reset();
            $regs.s4par().sys_reset();
            $regs.s4m0ar().sys_reset();
            $regs.s4m1ar().sys_reset();
            $regs.s4fcr().sys_reset();
            $regs.s5cr().sys_reset();
            $regs.s5ndtr().sys_reset();
            $regs.s5par().sys_reset();
            $regs.s5m0ar().sys_reset();
            $regs.s5m1ar().sys_reset();
            $regs.s5fcr().sys_reset();
            $regs.s6cr().sys_reset();
            $regs.s6ndtr().sys_reset();
            $regs.s6par().sys_reset();
            $regs.s6m0ar().sys_reset();
            $regs.s6m1ar().sys_reset();
            $regs.s6fcr().sys_reset();
            $regs.s7cr().sys_reset();
            $regs.s7ndtr().sys_reset();
            $regs.s7par().sys_reset();
            $regs.s7m0ar().sys_reset();
            $regs.s7m1ar().sys_reset();
            $regs.s7fcr().sys_reset();
        }
        // Write the reset values back to memory.
        $mmu.data()
            .write($base)
            .bytes($regs.as_bytes_ref())
            .unwrap();
    };
}
pub enum DmaRegisters {
    Dma1(dma1::RegisterBlock),
    Dma2(dma2::RegisterBlock),
}

#[derive(Debug, EnumIter, Eq, Hash, PartialEq, Clone, Copy)]
pub enum DmaStreamId {
    Stream0,
    Stream1,
    Stream2,
    Stream3,
    Stream4,
    Stream5,
    Stream6,
    Stream7,
}

#[derive(Default)]
pub enum DmaDirection {
    MemoryToMemory,
    MemoryToPeripheral,
    #[default]
    PeripheralToMemory,
}

#[derive(Default)]
pub enum DmaFifoThreshold {
    Full,
    Half,
    #[default]
    OneFourth,
    ThreeFourths,
}

#[derive(Default)]
pub enum DmaDataWidth {
    #[default]
    Byte,
    HalfWord,
    Word,
}

#[derive(Default)]
pub enum DmaTransferMode {
    #[default]
    Direct,
    Fifo,
}

// TODO: because we atomically transfer data, is this needed?
#[derive(Default)]
pub enum DmaStreamPriority {
    High,
    #[default]
    Low,
    Medium,
    VeryHigh,
}

#[derive(Default)]
pub enum DmaChannelId {
    #[default]
    Channel0,
    Channel1,
    Channel2,
    Channel3,
    Channel4,
    Channel5,
    Channel6,
    Channel7,
}

pub struct DmaStreamConfig {
    direction: DmaDirection,
    priority: DmaStreamPriority,
    transfer_mode: DmaTransferMode,
    fifo_threshold: DmaFifoThreshold,
    channel_select: DmaChannelId,
    memory_auto_increment: bool,
    peripheral_auto_increment: bool,
    memory_data_width: DmaDataWidth,
    peripheral_data_width: DmaDataWidth,
}

impl Default for DmaStreamConfig {
    fn default() -> Self {
        Self {
            direction: DmaDirection::default(),
            priority: DmaStreamPriority::default(),
            transfer_mode: DmaTransferMode::default(),
            fifo_threshold: DmaFifoThreshold::default(),
            channel_select: DmaChannelId::default(),
            memory_auto_increment: true,
            peripheral_auto_increment: false,
            memory_data_width: Default::default(),
            peripheral_data_width: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct DmaStreamChannels {
    channel_0_request: bool,
    channel_1_request: bool,
    channel_2_request: bool,
    channel_3_request: bool,
    channel_4_request: bool,
    channel_5_request: bool,
    channel_6_request: bool,
    channel_7_request: bool,
}

/// The DMA stream implementation with a 16-byte FIFO buffer and configuration settings
pub struct DmaStream {
    fifo: VecDeque<u8>, // flat queue of bytes to avoid data packing complexity
    channels: DmaStreamChannels,
    config: DmaStreamConfig,
    memory_addr: u32,
    peripheral_addr: u32,
}

#[allow(dead_code)]
impl DmaStream {
    pub fn new() -> Self {
        DmaStream {
            memory_addr: 0u32,
            peripheral_addr: 0u32,
            fifo: VecDeque::with_capacity(DMA_STREAM_FIFO_SIZE),
            channels: DmaStreamChannels::default(),
            config: DmaStreamConfig::default(),
        }
    }

    pub fn set_transfer_mode(&mut self, mode: DmaTransferMode) {
        self.config.transfer_mode = mode;
    }

    pub fn set_memory_addr(&mut self, addr: u32) {
        self.memory_addr = addr;
    }

    pub fn set_peripheral_addr(&mut self, addr: u32) {
        self.peripheral_addr = addr;
    }

    pub fn set_fifo_threshold(&mut self, threshold: DmaFifoThreshold) {
        self.config.fifo_threshold = threshold;
    }

    pub fn set_direction(&mut self, dir: DmaDirection) {
        self.config.direction = dir;
    }

    pub fn set_priority(&mut self, priority: DmaStreamPriority) {
        self.config.priority = priority;
    }

    pub fn set_memory_data_width(&mut self, width: DmaDataWidth) {
        self.config.memory_data_width = width;
    }

    pub fn set_peripheral_data_width(&mut self, width: DmaDataWidth) {
        self.config.peripheral_data_width = width;
    }

    pub fn enable_memory_auto_increment(&mut self) {
        self.config.memory_auto_increment = true;
    }

    pub fn disable_memory_auto_increment(&mut self) {
        self.config.memory_auto_increment = false;
    }

    pub fn enable_peripheral_auto_increment(&mut self) {
        self.config.peripheral_auto_increment = true;
    }

    pub fn disable_peripheral_auto_increment(&mut self) {
        self.config.peripheral_auto_increment = false;
    }

    pub fn select_channel(&mut self, channel: DmaChannelId) {
        self.config.channel_select = channel;
    }

    pub fn put_word(&mut self, data: u32) {
        // add a word to the FIFO
        // note: check for exceeding size?
        // note: the flat queue of bytes we abstract the FIFO as eliminates the need for packing
        for byte in data.to_le_bytes() {
            self.fifo.push_back(byte);
        }
    }

    pub fn put_half_word(&mut self, data: u16) {
        // add a half-word to the back of the FIFO
        // note: check for exceeding size?
        for byte in data.to_le_bytes() {
            self.fifo.push_back(byte);
        }
    }

    pub fn put_byte(&mut self, data: u8) {
        // add a byte to the back of the FIFO
        // note: check for exceeding size?
        self.fifo.push_back(data);
    }

    pub fn get_word(&mut self) -> Option<u32> {
        // get a word from the fifo, or None if it is not full enough
        if self.fifo.len() <= 3 {
            return None;
        }

        Some(u32::from_le_bytes([
            self.fifo.pop_front()?,
            self.fifo.pop_front()?,
            self.fifo.pop_front()?,
            self.fifo.pop_front()?,
        ]))
    }

    pub fn get_half_word(&mut self) -> Option<u16> {
        // get a half-word from the fifo, or None if it is not full enough
        if self.fifo.len() <= 1 {
            return None;
        }

        Some(u16::from_le_bytes([
            self.fifo.pop_front()?,
            self.fifo.pop_front()?,
        ]))
    }

    pub fn get_byte(&mut self) -> Option<u8> {
        // get a byte from the fifo, or None if it is empty
        self.fifo.pop_front()
    }

    pub fn lodge_request(&mut self, channel: DmaChannelId) {
        match channel {
            DmaChannelId::Channel0 => self.channels.channel_0_request = true,
            DmaChannelId::Channel1 => self.channels.channel_1_request = true,
            DmaChannelId::Channel2 => self.channels.channel_2_request = true,
            DmaChannelId::Channel3 => self.channels.channel_3_request = true,
            DmaChannelId::Channel4 => self.channels.channel_4_request = true,
            DmaChannelId::Channel5 => self.channels.channel_5_request = true,
            DmaChannelId::Channel6 => self.channels.channel_6_request = true,
            DmaChannelId::Channel7 => self.channels.channel_7_request = true,
        }
    }

    pub fn clear_request(&mut self, channel: DmaChannelId) {
        match channel {
            DmaChannelId::Channel0 => self.channels.channel_0_request = false,
            DmaChannelId::Channel1 => self.channels.channel_1_request = false,
            DmaChannelId::Channel2 => self.channels.channel_2_request = false,
            DmaChannelId::Channel3 => self.channels.channel_3_request = false,
            DmaChannelId::Channel4 => self.channels.channel_4_request = false,
            DmaChannelId::Channel5 => self.channels.channel_5_request = false,
            DmaChannelId::Channel6 => self.channels.channel_6_request = false,
            DmaChannelId::Channel7 => self.channels.channel_7_request = false,
        }
    }

    pub fn fifo_len(&mut self) -> usize {
        self.fifo.len()
    }

    pub fn fifo_clear(&mut self) {
        self.fifo.clear();
    }

    pub fn fifo_is_empty(&mut self) -> bool {
        self.fifo.is_empty()
    }
}

#[derive(Default)]
pub struct DmaInterrupt {
    interrupt: bool,
    interrupt_enabled: bool,
    /// Captures whether or not the most recent state change should trigger an interrupt event to
    /// get queued.
    trigger_event: bool,
}

impl DmaInterrupt {
    pub fn active(&self) -> bool {
        self.interrupt && self.interrupt_enabled
    }

    pub fn triggered(&self) -> bool {
        self.trigger_event
    }

    pub fn set(&mut self) {
        let prev_setting = self.interrupt;
        self.interrupt = true;

        // If the interrupt goes from cleared to set and it is already enabled, we'll want to queue
        // an interrupt with the event manager. We don't worry about the situation where the
        // interrupt was already active, since an interrupt would already have been queued.
        self.trigger_event = !prev_setting && self.interrupt && self.interrupt_enabled;
    }

    pub fn clear(&mut self) {
        self.interrupt = false;
        self.trigger_event = false;
    }

    pub fn set_enabled(&mut self, status: bool) {
        let prev_setting = self.interrupt_enabled;
        self.interrupt_enabled = status;

        // If the interrupt goes from disabled to enabled, then we'll want to fire an interrupt if
        // it is set. We don't worry about situations where the interrupt is getting disabled, or
        // the interrupt was already enabled.
        self.trigger_event = !prev_setting && self.interrupt_enabled && self.interrupt;
    }
}
/// DMA Interrupt Types. See **[STM32F405xx: USART Interrupts](https://www.st.com/resource/en/reference_manual/dm00031020-stm32f405-415-stm32f407-417-stm32f427-437-and-stm32f429-439-advanced-arm-based-32-bit-mcus-stmicroelectronics.pdf#page=327)** for
/// details.
#[derive(Default)]
#[allow(dead_code)] // not fully implemented yet
pub struct DmaInterruptControl {
    /// Half-transfer
    pub int_htif: DmaInterrupt,

    /// Transfer Complete
    pub int_tcif: DmaInterrupt,

    /// Transfer error
    pub int_teif: DmaInterrupt,

    /// FIFO overrun/underrun
    pub int_feif: DmaInterrupt,

    // Direct mode error
    pub int_dmeif: DmaInterrupt,
}

/// A DMA controller, either DMA1 or DMA1. Note that
/// request arbitration logic is abstracted over as
/// all emulated data transfers are atomic.
pub struct DmaController {
    registers: DmaRegisters,
    stream_map: HashMap<DmaStreamId, DmaStream>,
}

impl DmaController {
    pub fn new_dma1() -> Self {
        let init_dma_bytes: [u8; DMA_REG_BLOCK_SIZE] = [0u8; DMA_REG_BLOCK_SIZE];
        let registers = unsafe {
            DmaRegisters::Dma1(dma1::RegisterBlock::from_bytes(&init_dma_bytes).unwrap())
        };

        let mut stream_map: HashMap<DmaStreamId, DmaStream> = HashMap::with_capacity(8);
        for id in DmaStreamId::iter() {
            stream_map.insert(id, DmaStream::new());
        }

        DmaController {
            registers,
            stream_map,
        }
    }

    pub fn new_dma2() -> Self {
        let init_dma_bytes: [u8; DMA_REG_BLOCK_SIZE] = [0u8; DMA_REG_BLOCK_SIZE];
        let registers = unsafe {
            DmaRegisters::Dma2(dma2::RegisterBlock::from_bytes(&init_dma_bytes).unwrap())
        };

        let mut stream_map: HashMap<DmaStreamId, DmaStream> = HashMap::with_capacity(8);
        for id in DmaStreamId::iter() {
            stream_map.insert(id, DmaStream::new());
        }

        DmaController {
            registers,
            stream_map,
        }
    }
}

/// Hardware Abstraction Layer for the STM32F405 DMA.
pub struct DmaHalLayer {
    pub dma1: DmaController,
    pub dma2: DmaController,
    pub interrupt_control: DmaInterruptControl,
    // XXX: We capture when a client subscribes, but not when they disconnect.
    client_connected: bool,
}

pub(crate) const DMA_REG_BLOCK_SIZE: usize = size_of::<dma1::RegisterBlock>();

impl DmaHalLayer {
    /// Construct a new abstraction for the DMA controllers
    pub fn new() -> Self {
        let dma1 = DmaController::new_dma1();
        let dma2 = DmaController::new_dma2();
        let interrupt_control = DmaInterruptControl::default();
        DmaHalLayer {
            dma1,
            dma2,
            interrupt_control,
            client_connected: false,
        }
    }

    pub fn reset(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.client_connected = false;
        self.interrupt_control = DmaInterruptControl::default();

        self.dma1.stream_map.values_mut().for_each(|stream| {
            stream.channels = DmaStreamChannels::default();
            stream.config = DmaStreamConfig::default();
            stream.fifo_clear();
            stream.memory_addr = 0u32;
            stream.peripheral_addr = 0u32;
        });

        let dma1_base = Dma1::BASE;
        let dma1_regs = match &mut self.dma1.registers {
            DmaRegisters::Dma1(regs) => regs,
            DmaRegisters::Dma2(_) => unreachable!(),
        };
        reset_dma_regs!(dma1_regs, mmu, dma1_base);

        self.dma2.stream_map.values_mut().for_each(|stream| {
            stream.channels = DmaStreamChannels::default();
            stream.config = DmaStreamConfig::default();
            stream.fifo_clear();
            stream.memory_addr = 0u32;
            stream.peripheral_addr = 0u32;
        });

        let dma2_base = Dma1::BASE;
        let dma2_regs = match &mut self.dma1.registers {
            DmaRegisters::Dma1(_) => unreachable!(),
            DmaRegisters::Dma2(regs) => regs,
        };
        reset_dma_regs!(dma2_regs, mmu, dma2_base);

        Ok(())
    }
}

#[cfg(test)]
mod sanity_tests {
    // sanity tests for proper data handling in each stream
    #[test]
    fn test_little_endian_ordering() {
        let mut stream = super::DmaStream::new();
        stream.put_word(0x12345678);

        assert_eq!(0x78, stream.get_byte().unwrap());
        assert_eq!(0x56, stream.get_byte().unwrap());
        assert_eq!(0x34, stream.get_byte().unwrap());
        assert_eq!(0x12, stream.get_byte().unwrap());
    }

    #[test]
    fn test_pull_more_data_than_stream_contains() {
        let mut stream = super::DmaStream::new();
        stream.put_half_word(0x1234);

        assert!(stream.get_word().is_none());

        // ensure stream is not corrupted after illegal data request
        assert_eq!(0x34, stream.get_byte().unwrap());
        assert_eq!(0x12, stream.get_byte().unwrap());
    }

    #[test]
    fn test_initialize_dma() {
        // just making sure nothing panics, which means the register block is setup properly
        // and nothing has gone wrong
        super::DmaHalLayer::new();
    }
}
