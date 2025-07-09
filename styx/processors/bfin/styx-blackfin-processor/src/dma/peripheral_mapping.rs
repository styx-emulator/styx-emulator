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
