// SPDX-License-Identifier: BSD-2-Clause
use std::fmt::Debug;

use arbitrary_int::{u15, u4};
use styx_core::event_controller::RaisedIrqs;
use styx_core::prelude::*;
use tap::Conv;
use tracing::{trace, warn};

use crate::core_event_controller::SicHandle;

use super::{config, id::DmaId, DmaPeripheralMapping};

/// Runtime state of a single DMA channel.
///
/// DMA data and DMA register writes come to this struct which facilitates register
/// updates and the peripheral interrupt activation.
pub(super) struct DmaState {
    system: SicHandle,
    id: DmaId,

    status: config::IrqStatus,
    config: config::DmaConfig,
    x_modify: u16,
    x_count: u16,
    x_current: u16,
    start_address: u32,
    y_modify: u16,
    y_count: u16,
    y_current: u16,
    mapping: DmaPeripheralMapping,
    /// Buffers incoming DMA bytes until we have a full word to write to memory.
    ///
    /// At the moment this could be an [Option] but we will have to support 4 byte words in the
    /// future which will require a vec or similar data structure.
    internal_buffer: Vec<u8>,
}

impl DmaState {
    pub(super) fn new(id: DmaId, system: SicHandle) -> Self {
        Self {
            id,
            system,
            config: Default::default(),
            x_modify: Default::default(),
            x_count: Default::default(),
            y_modify: Default::default(),
            y_count: Default::default(),
            x_current: Default::default(),
            y_current: Default::default(),
            mapping: DmaPeripheralMapping::try_from(id.index()).unwrap(),
            start_address: Default::default(),
            internal_buffer: Vec::new(),
            status: Default::default(),
        }
    }

    /// Triggers interrupt if enabled. Checks interrupt enabled bit.
    ///
    /// Pushes the raised core interrupt onto `raised` for the caller to route.
    fn trigger_interrupt(&mut self, memory: &MemoryBackend, raised: &mut RaisedIrqs) {
        if self.config.interrupt_enabled() {
            self.set_status_done(memory, true);
            if let Some(irq) = self.system.latch_peripheral(memory, self.id) {
                raised.push(irq);
            }
        }
    }

    fn clear_interrupt(&mut self, memory: &MemoryBackend) {
        self.set_status_done(memory, false);
        self.system.unlatch_peripheral(self.id);
    }

    fn set_status_done(&mut self, memory: &MemoryBackend, done: bool) {
        self.status.set_done(done);
        self.update_status(memory);
    }

    /// Updates status memory mapped register
    fn update_status(&self, memory: &MemoryBackend) {
        self.debug_print_config("irq_status", &self.status);
        let data_bytes = self.status.conv::<u4>().value().to_le_bytes();
        memory
            .data()
            .write(self.id.irq_status_register())
            .bytes(&data_bytes)
            .unwrap();
    }

    fn set_x_current(&mut self, memory: &MemoryBackend, new_x_current: u16) {
        self.x_current = new_x_current;
        memory
            .data()
            .write(self.id.x_current_register())
            .le()
            .value(new_x_current)
            .unwrap();
    }

    fn set_y_current(&mut self, memory: &MemoryBackend, new_y_current: u16) {
        self.y_current = new_y_current;
        memory
            .data()
            .write(self.id.y_current_register())
            .le()
            .value(new_y_current)
            .unwrap();
    }

    /// Current pointer where data will be written to next. Resets to [Self::start_address].
    ///
    /// Dynamically calculated and should be correct as long as current and count values are
    /// correct.
    fn current_address(&self) -> u32 {
        if matches!(self.config.mode(), config::Mode::TwoDimensional) {
            self.start_address
                + (self.actual_x_current() * self.x_modify as u32)
                + (self.actual_y_current() * self.y_modify as u32)
        } else {
            unimplemented!("Linear mode not implemented")
        }
    }

    fn actual_x_current(&self) -> u32 {
        self.x_count as u32 - self.x_current as u32
    }
    fn actual_y_current(&self) -> u32 {
        self.y_count as u32 - self.y_current as u32
    }

    /// Adjust current x/y counts after reading a word in.
    ///
    /// This will decrement current counts by 1 and reset them to their reset count if they hit
    /// zero. Also triggers interrupt if a row/complete transfer is completed.
    fn decrement_counts(&mut self, memory: &MemoryBackend, raised: &mut RaisedIrqs) {
        assert_eq!(
            self.config.mode(),
            config::Mode::TwoDimensional,
            "Linear mode not implemented."
        );
        self.set_x_current(memory, self.x_current - 1);
        if self.x_current == 0 {
            self.x_current = self.x_count;
            self.set_y_current(memory, self.y_current - 1);
            self.completed_row(memory, raised);
            if self.y_current == 0 {
                self.y_current = self.y_count;
                self.completed_transfer(memory, raised)
            }
        }
    }

    /// Completed a full transfer.
    fn completed_transfer(&mut self, memory: &MemoryBackend, raised: &mut RaisedIrqs) {
        trace!("dma {:?} completed transfer", self.id);

        match self.config.mode() {
            config::Mode::Linear => self.trigger_interrupt(memory, raised),
            config::Mode::TwoDimensional => match self.config.interrupt_timing() {
                config::DataInterruptTimingSelect::InterruptAfterWholeBuffer => {
                    self.trigger_interrupt(memory, raised)
                }
                config::DataInterruptTimingSelect::InterruptAfterRow => (),
            },
        }
    }

    /// Completed a row, e.g. x_count hit zero.
    fn completed_row(&mut self, memory: &MemoryBackend, raised: &mut RaisedIrqs) {
        trace!("dma {:?} completed row", self.id);

        if let config::DataInterruptTimingSelect::InterruptAfterRow = self.config.interrupt_timing()
        {
            self.trigger_interrupt(memory, raised)
        }
    }

    /// Pass incoming data from the mapped peripheral to be handled by this dma channel.
    ///
    /// Note: Only supports 16-bit word length.
    pub(super) fn pipe_new_data(
        &mut self,
        memory: &MemoryBackend,
        raised: &mut RaisedIrqs,
        data: u8,
    ) {
        // ignore new data if we're not enabled
        if self.config.enable() {
            if self.internal_buffer.is_empty() {
                // no buffered data, save this byte for now
                self.internal_buffer.push(data);
            } else if self.internal_buffer.len() == 1 {
                // we already have a byte! write and decrement current count.
                self.internal_buffer.push(data);

                memory
                    .data()
                    .write(self.current_address() as u64)
                    .bytes(&self.internal_buffer)
                    .unwrap();

                self.internal_buffer.clear();
                self.decrement_counts(memory, raised);
            } else {
                panic!("err");
            }
        }
    }

    /// A write to the config register.
    pub(super) fn set_config(&mut self, config: u16) {
        let config = u15::new(config);
        let dma_config = config::DmaConfig::try_from(config).expect("config is invalid!");

        self.debug_print_config("config", &dma_config);

        self.config = dma_config;
    }

    pub(super) fn set_x_count(&mut self, memory: &MemoryBackend, x_count: u16) {
        self.debug_print_config("x_count", &x_count);
        self.x_count = x_count;
        self.set_x_current(memory, x_count);
    }

    pub(super) fn set_x_modify(&mut self, x_modify: u16) {
        self.debug_print_config("x_modify", &x_modify);

        self.x_modify = x_modify;
    }

    pub(super) fn set_start_address(&mut self, start_address: u32) {
        self.debug_print_config("start_address", &start_address);
        self.start_address = start_address;
    }

    pub(super) fn set_y_modify(&mut self, y_modify: u16) {
        self.debug_print_config("y_modify", &y_modify);
        self.y_modify = y_modify;
    }

    pub(super) fn set_y_count(&mut self, memory: &MemoryBackend, y_count: u16) {
        self.debug_print_config("y_count", &y_count);
        self.y_count = y_count;
        self.set_y_current(memory, y_count);
    }

    pub(super) fn mapping(&self) -> DmaPeripheralMapping {
        self.mapping
    }

    fn debug_print_config(&self, parameter_name: &str, value: &impl Debug) {
        trace!("dma {:?} {parameter_name} set to {value:?}", self.id);
    }

    /// A write to the status register. Write 1 clears the `done` and `error` bits.
    pub(super) fn write_status(&mut self, memory: &MemoryBackend, status: u4) {
        let written_status = config::IrqStatus::from(status);

        // `done` and `error` are W1C
        if written_status.done() {
            self.clear_interrupt(memory)
        }
        if written_status.error() {
            self.status.set_error(false);
        }

        // these are RO
        if written_status.descriptor_fetch() || written_status.run() {
            warn!("invalid write to descriptor fetch or run bit");
        }

        self.update_status(memory);
    }
}
