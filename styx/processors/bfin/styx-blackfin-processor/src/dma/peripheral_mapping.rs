// SPDX-License-Identifier: BSD-2-Clause
use enum_map::Enum;
use num_enum::{IntoPrimitive, TryFromPrimitive};

/// This is the peripheral mapping as defined in the DMAx_PERIPHERAL_MAP register.
///
/// Users of the [DmaController](super::DmaController) use this to source data streams to proper DMA
/// channel. Internally, the controller will map peripheral source mappings to their correct DMA
/// channel.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Enum, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum DmaPeripheralMapping {
    PpiReceiveTransmit,
    EthernetMacReceive,
    EthernetMacTransmit,
    Sport0Receive,
    Sport0TransmitOrRsi,
    Sport1ReceiveOrSpi1TransmitReceive,
    Sport1Transmit,
    Spi0TransmitReceive,
    Uart0Receive,
    Uart0Transmit,
    Uart1Receive,
    Uart1Transmit,
}
