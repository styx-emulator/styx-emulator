// SPDX-License-Identifier: BSD-2-Clause
//! Notes from "LogiCORE IP AXI Ethernet Lite Media Access Controller (v1.01b) Data Sheet"
//! - <https://docs.amd.com/v/u/en-US/ds787_axi_ethernetlite>
//!
//! Memory Setup:
//! - 32 bit bus to a 4k chunk of shared memory (half for each send/receive)
//!   - capable of hold 1 max length packet in each send/receive area
//! - also includes optional 2k chunk of shared memory for PONG buffer (not implemented)
//!
//! Transmit Interface:
//! - starts at address 0x0
//! - memory interface requires 4 byte reads/writes, no single byte interactions
//! - includes dest addr (6 bytes), source addr (6 bytes), type/length (2 bytes), and data (0-1500 bytes)
//! - the ethernet controller (this) is responsible for adding preamble, start of frame, and CRC to the packet
//!
//! Received interface:
//! - if destination Mac matches our Mac or broadcast Mac
//! - entire frame from dest addr through crc is stored in rx buffer (offset 0x1000)
//! - controller verifies crc, and if it is good sets rx status bit
//! - includes dest addr (6 bytes), source addr (6 bytes), type/length (2 bytes), data (0-1500 bytes), and crc (4 bytes)
//! - ethernet controller drops packets where crc is incorrect, and when destination address doesn't match
//!
//! Unimplemented:
//! - loopback mode
//!
mod service;

use service::EthernetControllerService;
use styx_core::errors::UnknownError;
use styx_core::grpc::io::ethernet::ethernet_port_server::EthernetPortServer;
use styx_core::grpc::io::ethernet::EthernetPacket;
use styx_core::prelude::*;

use crate::core_event_controller::Event;
use derivative::Derivative;

use std::collections::VecDeque;
use tokio::sync::broadcast;

mod hooks;

const ETHER_BASE_ADDR: u64 = 0x81000000;
const ETHER_SIZE: usize = 0x2000;

const TX_LEN_OFFSET: u64 = 0x07F4;
const TX_CTL_OFFSET: u64 = 0x07FC;

const RX_CTL_OFFSET: u64 = 0x17FC;

const DEFAULT_MAC: &str = "00:00:5E:00:FA:CE";
const BROADCAST_MAC: Mac = Mac([0xFF; 6]);

#[derive(Debug, PartialEq, Eq)]
struct Mac([u8; 6]);

impl Mac {
    pub fn from_str(s: &str) -> Result<Self, UnknownError> {
        let mut bytes: [u8; 6] = [0; 6];

        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(UnknownError::msg("Invalid Mac address format"));
        }

        for (idx, part) in parts.iter().enumerate() {
            if let Ok(byte) = u8::from_str_radix(part, 16) {
                bytes[idx] = byte;
            } else {
                return Err(UnknownError::msg("Invalid hex digit in Mac address"));
            }
        }
        Ok(Self(bytes))
    }
}

impl From<[u8; 6]> for Mac {
    fn from(bytes: [u8; 6]) -> Self {
        Mac(bytes)
    }
}

impl TryFrom<&[u8]> for Mac {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Mac(value.try_into().map_err(|_| ())?))
    }
}

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        ))
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct EthernetController {
    tx: broadcast::Sender<EthernetPacket>,
    rx_send: broadcast::Sender<EthernetPacket>,
    rx: broadcast::Receiver<EthernetPacket>,
    /// structure to hold received packes
    rx_fifo: VecDeque<EthernetPacket>,

    /// holds the current Mac address of this interface
    mac_addr: Mac,
    /// controlled by guest writing to GIE register
    global_interrupts_enabled: bool,
    /// flag in TX_CTL register
    tx_interrupts_enabled: bool,
    /// flag in RX_CTL register
    rx_interrupts_enabled: bool,
    /// set by guest writing to TX_LEN register
    tx_len: usize,
}

impl EthernetController {
    /// true if data is available to be read
    pub fn rx_data_available(&self) -> bool {
        !self.rx_fifo.is_empty()
    }

    pub fn new() -> Self {
        let (tx_send, _) = broadcast::channel(2048);
        let (rx_send, rx_recv) = broadcast::channel(2048);

        let rx_fifo: VecDeque<EthernetPacket> = VecDeque::new();

        Self {
            tx: tx_send,
            rx: rx_recv,
            rx_send,
            mac_addr: Mac::from_str(DEFAULT_MAC).unwrap(),
            rx_fifo,
            global_interrupts_enabled: false,
            tx_interrupts_enabled: false,
            rx_interrupts_enabled: false,
            tx_len: 0,
        }
    }

    /// triggered when guest code clears RX_CTL status flag, indicating ready for more data
    pub fn guest_receive_data(&mut self) -> Option<EthernetPacket> {
        self.rx_fifo.pop_front()
    }

    fn grab_packets(&mut self) -> Result<(), UnknownError> {
        loop {
            let res = self.rx.try_recv();
            match res {
                Ok(packet) => self.add_packet_if_verify(packet)?,
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    log::warn!("ethernet rx stream closed??");
                    break;
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    log::warn!("ethernet rx stream lagged {n} items");
                    break;
                }
            }
        }
        Ok(())
    }

    fn add_packet_if_verify(&mut self, packet: EthernetPacket) -> Result<(), UnknownError> {
        if verify_packet(&self.mac_addr, &packet) {
            self.rx_fifo.push_back(packet);
        }
        Ok(())
    }

    /// called from memory hook callback, when guest code writes to TX_LEN register
    pub fn set_tx_len(&mut self, len: usize) {
        self.tx_len = len;
    }

    /// called from memory hook callback, when a packet is being sent so that we know how much memory to read from the TX buffer
    pub fn get_tx_len(&self) -> usize {
        self.tx_len
    }

    pub fn guest_send_packet(&self, frame: Vec<u8>) {
        let crc: u32 = crc32fast::hash(&frame);
        let data: EthernetPacket = EthernetPacket { frame, crc };

        let subscribers = self.tx.send(data).unwrap_or(0);

        // should this trigger interrupt??

        log::trace!("Send new value to {} subscriber", subscribers);
    }

    fn reset_state(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // clear the memory designated to the peripheral
        mmu.data()
            .write(ETHER_BASE_ADDR)
            .bytes(&[0_u8; ETHER_SIZE])
            .unwrap();

        // reset flags and clear rx'd data
        self.global_interrupts_enabled = false;
        self.tx_interrupts_enabled = false;
        self.rx_interrupts_enabled = false;
        self.rx_fifo.clear();

        // reset mac to default
        self.mac_addr = Mac::from_str(DEFAULT_MAC).unwrap();

        Ok(())
    }
}

impl Peripheral for EthernetController {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // add memory read and write hooks for the TX and RX control/status register memory regions
        proc.core.cpu.mem_write_hook(
            ETHER_BASE_ADDR + TX_LEN_OFFSET,
            ETHER_BASE_ADDR + TX_CTL_OFFSET,
            Box::new(hooks::EthernetTxHook),
        )?;
        proc.core.cpu.mem_write_hook(
            ETHER_BASE_ADDR + RX_CTL_OFFSET,
            ETHER_BASE_ADDR + RX_CTL_OFFSET,
            Box::new(hooks::EthernetRxHook),
        )?;
        proc.core.cpu.mem_read_hook(
            ETHER_BASE_ADDR + RX_CTL_OFFSET,
            ETHER_BASE_ADDR + RX_CTL_OFFSET,
            Box::new(hooks::EthernetRxHook),
        )?;
        proc.core.cpu.mem_read_hook(
            ETHER_BASE_ADDR + TX_CTL_OFFSET,
            ETHER_BASE_ADDR + TX_CTL_OFFSET,
            Box::new(hooks::EthernetTxHook),
        )?;

        // create inner wrapper struct that implements the service
        let service = EthernetPortServer::new(EthernetControllerService {
            tx: self.tx.clone(),
            rx: self.rx_send.clone(),
        });

        proc.routes.add_service(service);
        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![Event::Ethernet.into()]
    }

    fn name(&self) -> &str {
        "Ethernet Controller"
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        _delta: &styx_core::prelude::Delta,
    ) -> Result<(), UnknownError> {
        self.grab_packets()?;

        // both global interrupt and tx interrupt flags need to be set for an interrupt to be generated
        if self.rx_data_available() && self.global_interrupts_enabled && self.tx_interrupts_enabled
        {
            event_controller.latch(Event::Ethernet.into()).unwrap();
        }
        Ok(())
    }

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.reset_state(mmu)
    }
}

fn verify_packet(our_mac: &Mac, packet: &EthernetPacket) -> bool {
    let dst_addr = &packet.frame[0..6];

    let verify_crc: u32 = crc32fast::hash(&packet.frame);

    let their_mac_res = dst_addr.try_into();
    let Ok(their_mac) = their_mac_res else {
        log::warn!("couldn't parse incoming mac address");
        return false;
    };

    // only packets with destination of our Mac or broadcast are accepted
    // crc needs to be correct
    // runt packets are also dropped
    address_matches(our_mac, &their_mac) && packet.crc == verify_crc && packet.frame.len() >= 60
}

/// Compares a Mac address against our address.
/// We'll accept any address that matches ours or is the broadcast address
fn address_matches(our_mac: &Mac, their_mac: &Mac) -> bool {
    our_mac == their_mac || their_mac == &BROADCAST_MAC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_struct() {
        let a = Mac::from_str("AA:BB:CC:DD:EE:FF").unwrap();
        let b: Mac = [1, 2, 3, 4, 5, 6].into();
        let c: Mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff].into();

        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(a, c);
    }
}
