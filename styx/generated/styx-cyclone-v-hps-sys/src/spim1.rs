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
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    ctrlr0: Ctrlr0,
    ctrlr1: Ctrlr1,
    spienr: Spienr,
    mwcr: Mwcr,
    ser: Ser,
    baudr: Baudr,
    txftlr: Txftlr,
    rxftlr: Rxftlr,
    txflr: Txflr,
    rxflr: Rxflr,
    sr: Sr,
    imr: Imr,
    isr: Isr,
    risr: Risr,
    txoicr: Txoicr,
    rxoicr: Rxoicr,
    rxuicr: Rxuicr,
    _reserved17: [u8; 0x04],
    icr: Icr,
    dmacr: Dmacr,
    dmatdlr: Dmatdlr,
    dmardlr: Dmardlr,
    idr: Idr,
    spi_version_id: SpiVersionId,
    dr: Dr,
    _reserved24: [u8; 0x98],
    rx_sample_dly: RxSampleDly,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - This register controls the serial data transfer. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
    #[inline(always)]
    pub const fn ctrlr0(&self) -> &Ctrlr0 {
        &self.ctrlr0
    }
    #[doc = "0x04 - Control register 1 controls the end of serial transfers when in receive-only mode. It is impossible to write to this register when the SPI Master is enabled.The SPI Master is enabled and disabled by writing to the SPIENR register."]
    #[inline(always)]
    pub const fn ctrlr1(&self) -> &Ctrlr1 {
        &self.ctrlr1
    }
    #[doc = "0x08 - Enables and Disables all SPI operations."]
    #[inline(always)]
    pub const fn spienr(&self) -> &Spienr {
        &self.spienr
    }
    #[doc = "0x0c - This register controls the direction of the data word for the half-duplex Microwire serial protocol. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
    #[inline(always)]
    pub const fn mwcr(&self) -> &Mwcr {
        &self.mwcr
    }
    #[doc = "0x10 - The register enables the individual slave select output lines from the SPI Master. Up to 4 slave-select output pins are available on the SPI Master. You cannot write to this register when SPI Master is busy and when SPI_EN = 1."]
    #[inline(always)]
    pub const fn ser(&self) -> &Ser {
        &self.ser
    }
    #[doc = "0x14 - This register derives the frequency of the serial clock that regulates the data transfer. The 16-bit field in this register defines the spi_m_clk divider value. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
    #[inline(always)]
    pub const fn baudr(&self) -> &Baudr {
        &self.baudr
    }
    #[doc = "0x18 - This register controls the threshold value for the transmit FIFO memory. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
    #[inline(always)]
    pub const fn txftlr(&self) -> &Txftlr {
        &self.txftlr
    }
    #[doc = "0x1c - This register controls the threshold value for the receive FIFO memory. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
    #[inline(always)]
    pub const fn rxftlr(&self) -> &Rxftlr {
        &self.rxftlr
    }
    #[doc = "0x20 - This register contains the number of valid data entries in the transmit FIFO memory. Ranges from 0 to 256."]
    #[inline(always)]
    pub const fn txflr(&self) -> &Txflr {
        &self.txflr
    }
    #[doc = "0x24 - This register contains the number of valid data entries in the receive FIFO memory. This register can be read at any time. Ranges from 0 to 256."]
    #[inline(always)]
    pub const fn rxflr(&self) -> &Rxflr {
        &self.rxflr
    }
    #[doc = "0x28 - This register is used to indicate the current transfer status, FIFO status, and any transmission/reception errors that may have occurred. The status register may be read at any time. None of the bits in this register request an interrupt."]
    #[inline(always)]
    pub const fn sr(&self) -> &Sr {
        &self.sr
    }
    #[doc = "0x2c - This register masks or enables all interrupts generated by the SPI Master."]
    #[inline(always)]
    pub const fn imr(&self) -> &Imr {
        &self.imr
    }
    #[doc = "0x30 - This register reports the status of the SPI Master interrupts after they have been masked."]
    #[inline(always)]
    pub const fn isr(&self) -> &Isr {
        &self.isr
    }
    #[doc = "0x34 - This register reports the status of the SPI Master interrupts prior to masking."]
    #[inline(always)]
    pub const fn risr(&self) -> &Risr {
        &self.risr
    }
    #[doc = "0x38 - Transmit FIFO Overflow Interrupt Clear Register"]
    #[inline(always)]
    pub const fn txoicr(&self) -> &Txoicr {
        &self.txoicr
    }
    #[doc = "0x3c - Receive FIFO Overflow Interrupt Clear Register"]
    #[inline(always)]
    pub const fn rxoicr(&self) -> &Rxoicr {
        &self.rxoicr
    }
    #[doc = "0x40 - Receive FIFO Underflow Interrupt Clear Register"]
    #[inline(always)]
    pub const fn rxuicr(&self) -> &Rxuicr {
        &self.rxuicr
    }
    #[doc = "0x48 - Clear Interrupt"]
    #[inline(always)]
    pub const fn icr(&self) -> &Icr {
        &self.icr
    }
    #[doc = "0x4c - This register is used to enable the DMA Controller interface operation."]
    #[inline(always)]
    pub const fn dmacr(&self) -> &Dmacr {
        &self.dmacr
    }
    #[doc = "0x50 - Controls the FIFO Level for a DMA transmit request"]
    #[inline(always)]
    pub const fn dmatdlr(&self) -> &Dmatdlr {
        &self.dmatdlr
    }
    #[doc = "0x54 - Controls the FIFO Level for a DMA receeive request"]
    #[inline(always)]
    pub const fn dmardlr(&self) -> &Dmardlr {
        &self.dmardlr
    }
    #[doc = "0x58 - This register contains the peripherals identification code, which is 0x05510000."]
    #[inline(always)]
    pub const fn idr(&self) -> &Idr {
        &self.idr
    }
    #[doc = "0x5c - Version ID Register value"]
    #[inline(always)]
    pub const fn spi_version_id(&self) -> &SpiVersionId {
        &self.spi_version_id
    }
    #[doc = "0x60 - This register is a 16-bit read/write buffer for the transmit/receive FIFOs. When the register is read, data in the receive FIFO buffer is accessed. When it is written to, data are moved into the transmit FIFO buffer; a write can occur only when SPI_EN = 1. FIFOs are reset when SPI_EN = 0. The data register occupies 36 32-bit locations in the address map (0x60 to 0xec). These are all aliases for the same data register. This is done to support burst accesses."]
    #[inline(always)]
    pub const fn dr(&self) -> &Dr {
        &self.dr
    }
    #[doc = "0xfc - This register controls the number of spi_m_clk cycles that are delayed (from the default sample time) before the actual sample of the rxd input occurs. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
    #[inline(always)]
    pub const fn rx_sample_dly(&self) -> &RxSampleDly {
        &self.rx_sample_dly
    }
}
#[doc = "ctrlr0 (rw) register accessor: This register controls the serial data transfer. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlr0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlr0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlr0`]
module"]
#[doc(alias = "ctrlr0")]
pub type Ctrlr0 = crate::Reg<ctrlr0::Ctrlr0Spec>;
#[doc = "This register controls the serial data transfer. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
pub mod ctrlr0;
#[doc = "ctrlr1 (rw) register accessor: Control register 1 controls the end of serial transfers when in receive-only mode. It is impossible to write to this register when the SPI Master is enabled.The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlr1`]
module"]
#[doc(alias = "ctrlr1")]
pub type Ctrlr1 = crate::Reg<ctrlr1::Ctrlr1Spec>;
#[doc = "Control register 1 controls the end of serial transfers when in receive-only mode. It is impossible to write to this register when the SPI Master is enabled.The SPI Master is enabled and disabled by writing to the SPIENR register."]
pub mod ctrlr1;
#[doc = "spienr (rw) register accessor: Enables and Disables all SPI operations.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`spienr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`spienr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@spienr`]
module"]
#[doc(alias = "spienr")]
pub type Spienr = crate::Reg<spienr::SpienrSpec>;
#[doc = "Enables and Disables all SPI operations."]
pub mod spienr;
#[doc = "mwcr (rw) register accessor: This register controls the direction of the data word for the half-duplex Microwire serial protocol. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mwcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mwcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mwcr`]
module"]
#[doc(alias = "mwcr")]
pub type Mwcr = crate::Reg<mwcr::MwcrSpec>;
#[doc = "This register controls the direction of the data word for the half-duplex Microwire serial protocol. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
pub mod mwcr;
#[doc = "ser (rw) register accessor: The register enables the individual slave select output lines from the SPI Master. Up to 4 slave-select output pins are available on the SPI Master. You cannot write to this register when SPI Master is busy and when SPI_EN = 1.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ser::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ser::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ser`]
module"]
#[doc(alias = "ser")]
pub type Ser = crate::Reg<ser::SerSpec>;
#[doc = "The register enables the individual slave select output lines from the SPI Master. Up to 4 slave-select output pins are available on the SPI Master. You cannot write to this register when SPI Master is busy and when SPI_EN = 1."]
pub mod ser;
#[doc = "baudr (rw) register accessor: This register derives the frequency of the serial clock that regulates the data transfer. The 16-bit field in this register defines the spi_m_clk divider value. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`baudr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`baudr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@baudr`]
module"]
#[doc(alias = "baudr")]
pub type Baudr = crate::Reg<baudr::BaudrSpec>;
#[doc = "This register derives the frequency of the serial clock that regulates the data transfer. The 16-bit field in this register defines the spi_m_clk divider value. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
pub mod baudr;
#[doc = "txftlr (rw) register accessor: This register controls the threshold value for the transmit FIFO memory. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txftlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`txftlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@txftlr`]
module"]
#[doc(alias = "txftlr")]
pub type Txftlr = crate::Reg<txftlr::TxftlrSpec>;
#[doc = "This register controls the threshold value for the transmit FIFO memory. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
pub mod txftlr;
#[doc = "rxftlr (rw) register accessor: This register controls the threshold value for the receive FIFO memory. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxftlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rxftlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rxftlr`]
module"]
#[doc(alias = "rxftlr")]
pub type Rxftlr = crate::Reg<rxftlr::RxftlrSpec>;
#[doc = "This register controls the threshold value for the receive FIFO memory. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
pub mod rxftlr;
#[doc = "txflr (r) register accessor: This register contains the number of valid data entries in the transmit FIFO memory. Ranges from 0 to 256.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txflr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@txflr`]
module"]
#[doc(alias = "txflr")]
pub type Txflr = crate::Reg<txflr::TxflrSpec>;
#[doc = "This register contains the number of valid data entries in the transmit FIFO memory. Ranges from 0 to 256."]
pub mod txflr;
#[doc = "rxflr (r) register accessor: This register contains the number of valid data entries in the receive FIFO memory. This register can be read at any time. Ranges from 0 to 256.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxflr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rxflr`]
module"]
#[doc(alias = "rxflr")]
pub type Rxflr = crate::Reg<rxflr::RxflrSpec>;
#[doc = "This register contains the number of valid data entries in the receive FIFO memory. This register can be read at any time. Ranges from 0 to 256."]
pub mod rxflr;
#[doc = "sr (r) register accessor: This register is used to indicate the current transfer status, FIFO status, and any transmission/reception errors that may have occurred. The status register may be read at any time. None of the bits in this register request an interrupt.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr`]
module"]
#[doc(alias = "sr")]
pub type Sr = crate::Reg<sr::SrSpec>;
#[doc = "This register is used to indicate the current transfer status, FIFO status, and any transmission/reception errors that may have occurred. The status register may be read at any time. None of the bits in this register request an interrupt."]
pub mod sr;
#[doc = "imr (rw) register accessor: This register masks or enables all interrupts generated by the SPI Master.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`imr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`imr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@imr`]
module"]
#[doc(alias = "imr")]
pub type Imr = crate::Reg<imr::ImrSpec>;
#[doc = "This register masks or enables all interrupts generated by the SPI Master."]
pub mod imr;
#[doc = "isr (r) register accessor: This register reports the status of the SPI Master interrupts after they have been masked.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@isr`]
module"]
#[doc(alias = "isr")]
pub type Isr = crate::Reg<isr::IsrSpec>;
#[doc = "This register reports the status of the SPI Master interrupts after they have been masked."]
pub mod isr;
#[doc = "risr (r) register accessor: This register reports the status of the SPI Master interrupts prior to masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`risr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@risr`]
module"]
#[doc(alias = "risr")]
pub type Risr = crate::Reg<risr::RisrSpec>;
#[doc = "This register reports the status of the SPI Master interrupts prior to masking."]
pub mod risr;
#[doc = "txoicr (r) register accessor: Transmit FIFO Overflow Interrupt Clear Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txoicr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@txoicr`]
module"]
#[doc(alias = "txoicr")]
pub type Txoicr = crate::Reg<txoicr::TxoicrSpec>;
#[doc = "Transmit FIFO Overflow Interrupt Clear Register"]
pub mod txoicr;
#[doc = "rxoicr (r) register accessor: Receive FIFO Overflow Interrupt Clear Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxoicr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rxoicr`]
module"]
#[doc(alias = "rxoicr")]
pub type Rxoicr = crate::Reg<rxoicr::RxoicrSpec>;
#[doc = "Receive FIFO Overflow Interrupt Clear Register"]
pub mod rxoicr;
#[doc = "rxuicr (r) register accessor: Receive FIFO Underflow Interrupt Clear Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxuicr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rxuicr`]
module"]
#[doc(alias = "rxuicr")]
pub type Rxuicr = crate::Reg<rxuicr::RxuicrSpec>;
#[doc = "Receive FIFO Underflow Interrupt Clear Register"]
pub mod rxuicr;
#[doc = "icr (r) register accessor: Clear Interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icr`]
module"]
#[doc(alias = "icr")]
pub type Icr = crate::Reg<icr::IcrSpec>;
#[doc = "Clear Interrupt"]
pub mod icr;
#[doc = "dmacr (rw) register accessor: This register is used to enable the DMA Controller interface operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmacr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmacr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmacr`]
module"]
#[doc(alias = "dmacr")]
pub type Dmacr = crate::Reg<dmacr::DmacrSpec>;
#[doc = "This register is used to enable the DMA Controller interface operation."]
pub mod dmacr;
#[doc = "dmatdlr (rw) register accessor: Controls the FIFO Level for a DMA transmit request\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmatdlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmatdlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmatdlr`]
module"]
#[doc(alias = "dmatdlr")]
pub type Dmatdlr = crate::Reg<dmatdlr::DmatdlrSpec>;
#[doc = "Controls the FIFO Level for a DMA transmit request"]
pub mod dmatdlr;
#[doc = "dmardlr (rw) register accessor: Controls the FIFO Level for a DMA receeive request\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmardlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmardlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmardlr`]
module"]
#[doc(alias = "dmardlr")]
pub type Dmardlr = crate::Reg<dmardlr::DmardlrSpec>;
#[doc = "Controls the FIFO Level for a DMA receeive request"]
pub mod dmardlr;
#[doc = "idr (r) register accessor: This register contains the peripherals identification code, which is 0x05510000.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idr`]
module"]
#[doc(alias = "idr")]
pub type Idr = crate::Reg<idr::IdrSpec>;
#[doc = "This register contains the peripherals identification code, which is 0x05510000."]
pub mod idr;
#[doc = "spi_version_id (rw) register accessor: Version ID Register value\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`spi_version_id::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`spi_version_id::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@spi_version_id`]
module"]
#[doc(alias = "spi_version_id")]
pub type SpiVersionId = crate::Reg<spi_version_id::SpiVersionIdSpec>;
#[doc = "Version ID Register value"]
pub mod spi_version_id;
#[doc = "dr (rw) register accessor: This register is a 16-bit read/write buffer for the transmit/receive FIFOs. When the register is read, data in the receive FIFO buffer is accessed. When it is written to, data are moved into the transmit FIFO buffer; a write can occur only when SPI_EN = 1. FIFOs are reset when SPI_EN = 0. The data register occupies 36 32-bit locations in the address map (0x60 to 0xec). These are all aliases for the same data register. This is done to support burst accesses.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dr`]
module"]
#[doc(alias = "dr")]
pub type Dr = crate::Reg<dr::DrSpec>;
#[doc = "This register is a 16-bit read/write buffer for the transmit/receive FIFOs. When the register is read, data in the receive FIFO buffer is accessed. When it is written to, data are moved into the transmit FIFO buffer; a write can occur only when SPI_EN = 1. FIFOs are reset when SPI_EN = 0. The data register occupies 36 32-bit locations in the address map (0x60 to 0xec). These are all aliases for the same data register. This is done to support burst accesses."]
pub mod dr;
#[doc = "rx_sample_dly (rw) register accessor: This register controls the number of spi_m_clk cycles that are delayed (from the default sample time) before the actual sample of the rxd input occurs. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rx_sample_dly::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rx_sample_dly::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rx_sample_dly`]
module"]
#[doc(alias = "rx_sample_dly")]
pub type RxSampleDly = crate::Reg<rx_sample_dly::RxSampleDlySpec>;
#[doc = "This register controls the number of spi_m_clk cycles that are delayed (from the default sample time) before the actual sample of the rxd input occurs. It is impossible to write to this register when the SPI Master is enabled. The SPI Master is enabled and disabled by writing to the SPIENR register."]
pub mod rx_sample_dly;
