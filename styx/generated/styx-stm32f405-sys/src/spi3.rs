// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    cr1: Cr1,
    cr2: Cr2,
    sr: Sr,
    dr: Dr,
    crcpr: Crcpr,
    rxcrcr: Rxcrcr,
    txcrcr: Txcrcr,
    i2scfgr: I2scfgr,
    i2spr: I2spr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - control register 1"]
    #[inline(always)]
    pub const fn cr1(&self) -> &Cr1 {
        &self.cr1
    }
    #[doc = "0x04 - control register 2"]
    #[inline(always)]
    pub const fn cr2(&self) -> &Cr2 {
        &self.cr2
    }
    #[doc = "0x08 - status register"]
    #[inline(always)]
    pub const fn sr(&self) -> &Sr {
        &self.sr
    }
    #[doc = "0x0c - data register"]
    #[inline(always)]
    pub const fn dr(&self) -> &Dr {
        &self.dr
    }
    #[doc = "0x10 - CRC polynomial register"]
    #[inline(always)]
    pub const fn crcpr(&self) -> &Crcpr {
        &self.crcpr
    }
    #[doc = "0x14 - RX CRC register"]
    #[inline(always)]
    pub const fn rxcrcr(&self) -> &Rxcrcr {
        &self.rxcrcr
    }
    #[doc = "0x18 - TX CRC register"]
    #[inline(always)]
    pub const fn txcrcr(&self) -> &Txcrcr {
        &self.txcrcr
    }
    #[doc = "0x1c - I2S configuration register"]
    #[inline(always)]
    pub const fn i2scfgr(&self) -> &I2scfgr {
        &self.i2scfgr
    }
    #[doc = "0x20 - I2S prescaler register"]
    #[inline(always)]
    pub const fn i2spr(&self) -> &I2spr {
        &self.i2spr
    }
}
#[doc = "CR1 (rw) register accessor: control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr1`]
module"]
#[doc(alias = "CR1")]
pub type Cr1 = crate::Reg<cr1::Cr1Spec>;
#[doc = "control register 1"]
pub mod cr1;
#[doc = "CR2 (rw) register accessor: control register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr2`]
module"]
#[doc(alias = "CR2")]
pub type Cr2 = crate::Reg<cr2::Cr2Spec>;
#[doc = "control register 2"]
pub mod cr2;
#[doc = "SR (rw) register accessor: status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr`]
module"]
#[doc(alias = "SR")]
pub type Sr = crate::Reg<sr::SrSpec>;
#[doc = "status register"]
pub mod sr;
#[doc = "DR (rw) register accessor: data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dr`]
module"]
#[doc(alias = "DR")]
pub type Dr = crate::Reg<dr::DrSpec>;
#[doc = "data register"]
pub mod dr;
#[doc = "CRCPR (rw) register accessor: CRC polynomial register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`crcpr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`crcpr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@crcpr`]
module"]
#[doc(alias = "CRCPR")]
pub type Crcpr = crate::Reg<crcpr::CrcprSpec>;
#[doc = "CRC polynomial register"]
pub mod crcpr;
#[doc = "RXCRCR (r) register accessor: RX CRC register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxcrcr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rxcrcr`]
module"]
#[doc(alias = "RXCRCR")]
pub type Rxcrcr = crate::Reg<rxcrcr::RxcrcrSpec>;
#[doc = "RX CRC register"]
pub mod rxcrcr;
#[doc = "TXCRCR (r) register accessor: TX CRC register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txcrcr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@txcrcr`]
module"]
#[doc(alias = "TXCRCR")]
pub type Txcrcr = crate::Reg<txcrcr::TxcrcrSpec>;
#[doc = "TX CRC register"]
pub mod txcrcr;
#[doc = "I2SCFGR (rw) register accessor: I2S configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`i2scfgr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`i2scfgr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@i2scfgr`]
module"]
#[doc(alias = "I2SCFGR")]
pub type I2scfgr = crate::Reg<i2scfgr::I2scfgrSpec>;
#[doc = "I2S configuration register"]
pub mod i2scfgr;
#[doc = "I2SPR (rw) register accessor: I2S prescaler register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`i2spr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`i2spr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@i2spr`]
module"]
#[doc(alias = "I2SPR")]
pub type I2spr = crate::Reg<i2spr::I2sprSpec>;
#[doc = "I2S prescaler register"]
pub mod i2spr;
