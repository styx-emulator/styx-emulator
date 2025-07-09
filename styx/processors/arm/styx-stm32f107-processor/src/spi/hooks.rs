// SPDX-License-Identifier: BSD-2-Clause
use styx_core::prelude::*;
use tracing::debug;

use super::{addr_to_spi_port, SPIController};

pub(crate) fn spi_dr_w_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let controller = proc
        .event_controller
        .peripherals
        .get_expect::<SPIController>()?;
    let inner = &mut controller.spi_ports[addr_to_spi_port(address)];

    debug!(
        "[SPI{}] write to DR: {:?} of size: {}",
        inner.num, data, size
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

pub(crate) fn spi_dr_r_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    _data: &mut [u8],
) -> Result<(), UnknownError> {
    let controller = proc
        .event_controller
        .peripherals
        .get_expect::<SPIController>()?;
    let inner = &mut controller.spi_ports[addr_to_spi_port(address)];

    debug!("[SPI{}] read from DR of size: {}", inner.num, size);

    // get the data at the front of the queue and write it into the data register
    let value = inner.read_data();
    proc.mmu.data().write(address).bytes(&[value])?;

    Ok(())
}

const SPI_CR1_SSI: u16 = 0b1_0000_0000;
const SPI_CR1_DFF: u16 = 0b1000_0000_0000;

pub(crate) fn spi_cr1_w_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let controller = proc
        .event_controller
        .peripherals
        .get_expect::<SPIController>()?;
    let inner = &mut controller.spi_ports[addr_to_spi_port(address)];

    debug!(
        "[SPI{}] write to CR1: {:?} of size: {}",
        inner.num, data, size
    );

    let val = u16::from_le_bytes(data[..2].try_into().unwrap());

    inner.slave_select(val & SPI_CR1_SSI > 0);
    inner.byte_frame_size = val & SPI_CR1_DFF == 0;

    Ok(())
}

const TXEIE: u16 = 0b1000_0000;
const RXNEIE: u16 = 0b0100_0000;
const ERRIE: u16 = 0b0010_0000;

pub(crate) fn spi_cr2_w_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let controller = proc
        .event_controller
        .peripherals
        .get_expect::<SPIController>()?;
    let inner = &mut controller.spi_ports[addr_to_spi_port(address)];

    debug!(
        "[SPI{}] write to CR2: {:?} of size: {}",
        inner.num, data, size
    );

    let val = u16::from_le_bytes(data[..2].try_into().unwrap());

    inner.txeie = val & TXEIE > 0;
    inner.rxneie = val & RXNEIE > 0;
    inner.errie = val & ERRIE > 0;

    Ok(())
}

pub(crate) fn spi_sr_r_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let controller = proc
        .event_controller
        .peripherals
        .get_expect::<SPIController>()?;
    let inner = &controller.spi_ports[addr_to_spi_port(address)];

    let sr = inner.inner_hal.sr.value.to_le_bytes();

    data[0] = sr[0];
    data[1] = sr[1];

    Ok(())
}
