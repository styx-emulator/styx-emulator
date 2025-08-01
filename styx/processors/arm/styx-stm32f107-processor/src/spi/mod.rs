// SPDX-License-Identifier: BSD-2-Clause
//!
//! memory ranges for each SPI port:
//!
//! SPI2 : 0x4000 3800 - 0x4000 3BFF
//! SPI3 : 0x4000 3C00 - 0x4000 3FFF
//! SPI1 : 0x4001 3000 - 0x4001 33FF
//!
use bilge::prelude::*;
use derivative::Derivative;
use getset::Getters;
use std::collections::VecDeque;
use styx_core::grpc::io;
use styx_core::grpc::io::spi::{MasterChipSelectPacket, MasterPacket};
use styx_core::prelude::*;
use styx_spi::{IntoSpiImp, SpiImpl};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::TryRecvError;

mod hooks;

const SPI2_END: u64 = 0x4000_3BFF;
const SPI3_END: u64 = 0x4000_3FFF;

/// Converts an address into the SPI port that it belongs to, as zero-indexed number.
/// SPI1 has a higher address block compared to SPI2 and SPI3 which is why this function looks wrong.
fn addr_to_spi_port(addr: u64) -> u32 {
    if addr <= SPI2_END {
        1
    } else if addr <= SPI3_END {
        2
    } else {
        0
    }
}

pub struct StmSpiPrecursor {
    pub base_addr: u64,
    pub event_irqn: ExceptionNumber,
}

impl StmSpiPrecursor {
    pub fn new(base_addr: u64, event_irqn: ExceptionNumber) -> Self {
        Self {
            base_addr,
            event_irqn,
        }
    }
}

impl IntoSpiImp for StmSpiPrecursor {
    fn new_spi_impl(
        self,

        as_master_csel: broadcast::Sender<io::spi::MasterChipSelectPacket>,
        as_master_mosi: broadcast::Sender<io::spi::MasterPacket>,
        as_master_miso: broadcast::Receiver<io::spi::MasterPacket>,

        _as_slave_csel: broadcast::Receiver<io::spi::SlaveChipSelectPacket>,
        _as_slave_mosi: broadcast::Receiver<io::spi::SlavePacket>,
        _as_slave_miso: broadcast::Sender<io::spi::SlavePacket>,

        port_id: u32,
    ) -> Result<Box<dyn styx_spi::SpiImpl>, UnknownError> {
        Ok(Box::new(SPIPortInner {
            port_num: port_id,
            base_addr: self.base_addr,
            inner_hal: Default::default(),
            event_irqn: self.event_irqn,
            byte_frame_size: true,
            rx_fifo: VecDeque::with_capacity(RX_TX_FIFO_SIZE),
            inbound_data: as_master_miso,
            outbound_data: as_master_mosi,
            outbound_csel: as_master_csel,
            txeie: false,
            rxneie: false,
            errie: false,
            selected: false,
        }))
    }
}

#[derive(Derivative)]
pub struct SPIPortInner {
    /// port number identifier
    port_num: u32,
    /// the base address for this port's register block
    base_addr: u64,
    /// the stored SPI register state
    inner_hal: SPIHal,
    /// IRQn for SPI interrupts
    event_irqn: ExceptionNumber,
    /// supports 8 bit or 16 bit data frame size
    byte_frame_size: bool,
    /// a queue for received data
    rx_fifo: VecDeque<u8>,

    inbound_data: broadcast::Receiver<MasterPacket>,
    outbound_data: broadcast::Sender<MasterPacket>,
    outbound_csel: broadcast::Sender<MasterChipSelectPacket>,

    /// transmit buffer empty interrupt enable
    txeie: bool,
    /// receive buffer not empty interrupt enable
    rxneie: bool,
    /// error interrupt enable
    errie: bool,
    /// slave select line
    selected: bool,
}

const RX_TX_FIFO_SIZE: usize = 32;

// register offsets within each SPI port memory block
const SPI_CR1_OFFSET: u64 = 0x0;
const SPI_CR2_OFFSET: u64 = 0x4;
const SPI_SR_OFFSET: u64 = 0x8;
const SPI_DR_OFFSET: u64 = 0xC;

impl SpiImpl for SPIPortInner {
    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        // reset the inner register state
        self.inner_hal.reset();
        Ok(())
    }

    /// sets up the required memory hooks
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        let cpu = proc.core.cpu.as_mut();

        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + SPI_CR1_OFFSET,
            hooks::spi_cr1_w_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + SPI_CR2_OFFSET,
            hooks::spi_cr2_w_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + SPI_DR_OFFSET,
            hooks::spi_dr_w_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_read(
            self.base_addr + SPI_DR_OFFSET,
            hooks::spi_dr_r_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_read(
            self.base_addr + SPI_SR_OFFSET,
            hooks::spi_sr_r_hook,
        ))?;

        Ok(())
    }

    /// Retrieves the IRQs belonging to this [`SPIPortInner`]
    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![self.event_irqn]
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        self.receive_data(event_controller)?;
        Ok(())
    }

    fn pre_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        Ok(())
    }
}

impl SPIPortInner {
    pub fn slave_select(&mut self, state: bool) {
        log::trace!("[SPI{}] slave select: {state}", self.port_num);

        if self.selected != state {
            self.selected = state;
            // state changed, send signal and clear buffer
            self.rx_fifo.clear();
            self.outbound_csel
                .send(MasterChipSelectPacket {
                    port: self.port_num,
                    chip_select_id: 0,
                    chip_select: state,
                })
                .unwrap();
        }
    }

    pub fn transmit_data(&mut self, ev: &mut dyn EventControllerImpl, value: u8) {
        log::debug!("[SPI{}] sending data: {value:08b}", self.port_num);
        self.outbound_data
            .send(MasterPacket {
                port: self.port_num,
                chip_select_id: 0,
                data: Vec::from([value]),
            })
            .unwrap();

        // trigger a TX buffer empty interrupt event, if enabled
        if self.txeie {
            ev.latch(self.event_irqn).unwrap();
        }

        // set TXE flag
        self.inner_hal.sr.set_txe(true.into());
    }

    pub fn receive_data(
        &mut self,
        event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        let rx_fifo = &mut self.rx_fifo;
        while let Some(data) = try_recv(&mut self.inbound_data) {
            for data_byte in data {
                rx_fifo.push_back(data_byte);
            }
        }
        if rx_fifo.is_empty() {
            return Ok(());
        }
        if !self.selected {
            // ignore data from device if we haven't selected it
            self.inner_hal.sr.set_rxne(false.into());
            return Ok(());
        }
        log::debug!("processing!!!! ");

        // trigger a RX buffer full interrupt event, if enabled
        if self.rxneie {
            event_controller.latch(self.event_irqn).unwrap();
        }
        // set RXNE flag
        self.inner_hal.sr.set_rxne(true.into());
        Ok(())
    }

    pub fn read_data(&mut self) -> u8 {
        let q = &mut self.rx_fifo;
        // if no data is available, then return 0
        let d = q.pop_front().unwrap_or(0);

        if q.is_empty() {
            // clear RXNE flag if we just pulled the last value from the queue
            self.inner_hal.sr.set_rxne(false.into());
        }
        d
    }
}

fn try_recv(inbound_data: &mut broadcast::Receiver<MasterPacket>) -> Option<Vec<u8>> {
    loop {
        let res = inbound_data.try_recv();
        match res {
            Ok(value) => break Some(value.data),
            Err(e) => {
                if let TryRecvError::Lagged(n) = e {
                    log::warn!("spi receive lagged {n} values");
                    continue;
                } else {
                    break None;
                }
            }
        }
    }
}

#[derive(Default, Getters, Debug)]
#[getset(get = "pub")]
pub struct SPIHal {
    pub(crate) cr1: CR1,
    pub(crate) cr2: CR2,
    pub(crate) sr: SR,
    pub(crate) dr: DR,
    pub(crate) crcpr: CRCPR,
    pub(crate) rxcrcr: RXCRCR,
    pub(crate) txcrcr: TXCRCR,
}

impl SPIHal {
    pub fn reset(&mut self) {
        self.cr1 = CR1::from(0);
        self.cr2 = CR2::from(0);
        self.sr = SR::from(0x2);
        self.dr = DR::from(0);
        self.crcpr = CRCPR::from(0x7);
        self.rxcrcr = RXCRCR::from(0);
        self.txcrcr = TXCRCR::from(0);
    }
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x0
// reset: 0x0000
pub struct CR1 {
    pub cpha: u1,
    pub cpol: u1,
    pub mstr: u1,
    pub br: u3,
    pub spe: u1,
    pub lsb_first: u1,
    pub ssi: u1,
    pub ssm: u1,
    pub rx_only: u1,
    pub dff: u1,
    pub crc_next: u1,
    pub crc_en: u1,
    pub bidioe: u1,
    pub bidi_mode: u1,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x04
// reset: 0x0000
pub struct CR2 {
    pub rxdmaen: u1,
    pub txdmaen: u1,
    pub ssoe: u1,
    res1: u2,
    pub errie: u1,
    pub rxneie: u1,
    pub txeie: u1,
    res2: u8,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x08
// reset: 0x0002
pub struct SR {
    pub rxne: u1,
    pub txe: u1,
    pub chside: u1,
    pub udr: u1,
    pub crc_err: u1,
    pub modf: u1,
    pub ovr: u1,
    pub bsy: u1,
    res: u8,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x0C
// reset: 0x0000
pub struct DR {
    dr: u16,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x10
// reset: 0x0007
pub struct CRCPR {
    crcpoly: u16,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x14
// reset: 0x0000
pub struct RXCRCR {
    rxcrc: u16,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x18
// reset: 0x0000
pub struct TXCRCR {
    txcrc: u16,
}

#[cfg(test)]
mod tests {
    use super::SPIHal;

    #[test]
    fn test_reset() {
        let mut hal = SPIHal::default();
        hal.reset();

        assert_eq!(hal.crcpr.crcpoly(), 0x7);
        assert_eq!(hal.sr.txe(), true.into());
    }
}
