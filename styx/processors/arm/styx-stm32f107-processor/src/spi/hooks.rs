// SPDX-License-Identifier: BSD-2-Clause
use std::sync::{Arc, Mutex};
use styx_core::hooks::{MemoryReadHook, MemoryWriteHook};
use styx_core::prelude::{log::debug, *};

use crate::spi::SPIPortInner;

pub(crate) struct SpiDrWHook {
    pub(crate) inner: Arc<Mutex<SPIPortInner>>,
}

impl MemoryWriteHook for SpiDrWHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        _address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let mut inner = self.inner.lock().unwrap();

        debug!(
            "[SPI{}] write to DR: {:?} of size: {}",
            inner.port_num, data, size
        );

        // clear TXE flag
        inner.inner_hal.sr.set_txe(false.into());

        // check frame size flag
        if inner.byte_frame_size {
            // transmit single byte
            inner.transmit_data(proc.event_controller.inner.as_mut(), data[0]);
        } else {
            // transmit 2 bytes
            inner.transmit_data(proc.event_controller.inner.as_mut(), data[0]);
            inner.transmit_data(proc.event_controller.inner.as_mut(), data[1]);
        }
        Ok(())
    }
}

pub(crate) struct SpiDrRHook {
    pub(crate) inner: Arc<Mutex<SPIPortInner>>,
}

impl MemoryReadHook for SpiDrRHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        _data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let mut inner = self.inner.lock().unwrap();

        debug!("[SPI{}] read from DR of size: {}", inner.port_num, size);

        // get the data at the front of the queue and write it into the data register
        let value = inner.read_data();
        proc.mmu.data().write(address).bytes(&[value])?;

        Ok(())
    }
}

const SPI_CR1_SSI: u16 = 0b1_0000_0000;
const SPI_CR1_DFF: u16 = 0b1000_0000_0000;

pub(crate) struct SpiCr1WHook {
    pub(crate) inner: Arc<Mutex<SPIPortInner>>,
}

impl MemoryWriteHook for SpiCr1WHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let mut inner = self.inner.lock().unwrap();

        debug!(
            "[SPI{}] write to CR1: {:?} of size: {}",
            inner.port_num, data, size
        );

        let val = u16::from_le_bytes(data[..2].try_into().unwrap());

        inner.slave_select(val & SPI_CR1_SSI > 0);
        inner.byte_frame_size = val & SPI_CR1_DFF == 0;

        Ok(())
    }
}

const TXEIE: u16 = 0b1000_0000;
const RXNEIE: u16 = 0b0100_0000;
const ERRIE: u16 = 0b0010_0000;

pub(crate) struct SpiCr2WHook {
    pub(crate) inner: Arc<Mutex<SPIPortInner>>,
}

impl MemoryWriteHook for SpiCr2WHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let mut inner = self.inner.lock().unwrap();

        debug!(
            "[SPI{}] write to CR2: {:?} of size: {}",
            inner.port_num, data, size
        );

        let val = u16::from_le_bytes(data[..2].try_into().unwrap());

        inner.txeie = val & TXEIE > 0;
        inner.rxneie = val & RXNEIE > 0;
        inner.errie = val & ERRIE > 0;

        Ok(())
    }
}

pub(crate) struct SpiSrRHook {
    pub(crate) inner: Arc<Mutex<SPIPortInner>>,
}

impl MemoryReadHook for SpiSrRHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        _address: u64,
        _size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let inner = self.inner.lock().unwrap();

        let sr = inner.inner_hal.sr.value.to_le_bytes();

        data[0] = sr[0];
        data[1] = sr[1];

        Ok(())
    }
}
