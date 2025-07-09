// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    dmabmr: Dmabmr,
    dmatpdr: Dmatpdr,
    dmarpdr: Dmarpdr,
    dmardlar: Dmardlar,
    dmatdlar: Dmatdlar,
    dmasr: Dmasr,
    dmaomr: Dmaomr,
    dmaier: Dmaier,
    dmamfbocr: Dmamfbocr,
    dmarswtr: Dmarswtr,
    _reserved10: [u8; 0x20],
    dmachtdr: Dmachtdr,
    dmachrdr: Dmachrdr,
    dmachtbar: Dmachtbar,
    dmachrbar: Dmachrbar,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Ethernet DMA bus mode register"]
    #[inline(always)]
    pub const fn dmabmr(&self) -> &Dmabmr {
        &self.dmabmr
    }
    #[doc = "0x04 - Ethernet DMA transmit poll demand register"]
    #[inline(always)]
    pub const fn dmatpdr(&self) -> &Dmatpdr {
        &self.dmatpdr
    }
    #[doc = "0x08 - EHERNET DMA receive poll demand register"]
    #[inline(always)]
    pub const fn dmarpdr(&self) -> &Dmarpdr {
        &self.dmarpdr
    }
    #[doc = "0x0c - Ethernet DMA receive descriptor list address register"]
    #[inline(always)]
    pub const fn dmardlar(&self) -> &Dmardlar {
        &self.dmardlar
    }
    #[doc = "0x10 - Ethernet DMA transmit descriptor list address register"]
    #[inline(always)]
    pub const fn dmatdlar(&self) -> &Dmatdlar {
        &self.dmatdlar
    }
    #[doc = "0x14 - Ethernet DMA status register"]
    #[inline(always)]
    pub const fn dmasr(&self) -> &Dmasr {
        &self.dmasr
    }
    #[doc = "0x18 - Ethernet DMA operation mode register"]
    #[inline(always)]
    pub const fn dmaomr(&self) -> &Dmaomr {
        &self.dmaomr
    }
    #[doc = "0x1c - Ethernet DMA interrupt enable register"]
    #[inline(always)]
    pub const fn dmaier(&self) -> &Dmaier {
        &self.dmaier
    }
    #[doc = "0x20 - Ethernet DMA missed frame and buffer overflow counter register"]
    #[inline(always)]
    pub const fn dmamfbocr(&self) -> &Dmamfbocr {
        &self.dmamfbocr
    }
    #[doc = "0x24 - Ethernet DMA receive status watchdog timer register"]
    #[inline(always)]
    pub const fn dmarswtr(&self) -> &Dmarswtr {
        &self.dmarswtr
    }
    #[doc = "0x48 - Ethernet DMA current host transmit descriptor register"]
    #[inline(always)]
    pub const fn dmachtdr(&self) -> &Dmachtdr {
        &self.dmachtdr
    }
    #[doc = "0x4c - Ethernet DMA current host receive descriptor register"]
    #[inline(always)]
    pub const fn dmachrdr(&self) -> &Dmachrdr {
        &self.dmachrdr
    }
    #[doc = "0x50 - Ethernet DMA current host transmit buffer address register"]
    #[inline(always)]
    pub const fn dmachtbar(&self) -> &Dmachtbar {
        &self.dmachtbar
    }
    #[doc = "0x54 - Ethernet DMA current host receive buffer address register"]
    #[inline(always)]
    pub const fn dmachrbar(&self) -> &Dmachrbar {
        &self.dmachrbar
    }
}
#[doc = "DMABMR (rw) register accessor: Ethernet DMA bus mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmabmr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmabmr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmabmr`]
module"]
#[doc(alias = "DMABMR")]
pub type Dmabmr = crate::Reg<dmabmr::DmabmrSpec>;
#[doc = "Ethernet DMA bus mode register"]
pub mod dmabmr;
#[doc = "DMATPDR (rw) register accessor: Ethernet DMA transmit poll demand register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmatpdr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmatpdr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmatpdr`]
module"]
#[doc(alias = "DMATPDR")]
pub type Dmatpdr = crate::Reg<dmatpdr::DmatpdrSpec>;
#[doc = "Ethernet DMA transmit poll demand register"]
pub mod dmatpdr;
#[doc = "DMARPDR (rw) register accessor: EHERNET DMA receive poll demand register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmarpdr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmarpdr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmarpdr`]
module"]
#[doc(alias = "DMARPDR")]
pub type Dmarpdr = crate::Reg<dmarpdr::DmarpdrSpec>;
#[doc = "EHERNET DMA receive poll demand register"]
pub mod dmarpdr;
#[doc = "DMARDLAR (rw) register accessor: Ethernet DMA receive descriptor list address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmardlar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmardlar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmardlar`]
module"]
#[doc(alias = "DMARDLAR")]
pub type Dmardlar = crate::Reg<dmardlar::DmardlarSpec>;
#[doc = "Ethernet DMA receive descriptor list address register"]
pub mod dmardlar;
#[doc = "DMATDLAR (rw) register accessor: Ethernet DMA transmit descriptor list address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmatdlar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmatdlar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmatdlar`]
module"]
#[doc(alias = "DMATDLAR")]
pub type Dmatdlar = crate::Reg<dmatdlar::DmatdlarSpec>;
#[doc = "Ethernet DMA transmit descriptor list address register"]
pub mod dmatdlar;
#[doc = "DMASR (rw) register accessor: Ethernet DMA status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmasr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmasr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmasr`]
module"]
#[doc(alias = "DMASR")]
pub type Dmasr = crate::Reg<dmasr::DmasrSpec>;
#[doc = "Ethernet DMA status register"]
pub mod dmasr;
#[doc = "DMAOMR (rw) register accessor: Ethernet DMA operation mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmaomr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmaomr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmaomr`]
module"]
#[doc(alias = "DMAOMR")]
pub type Dmaomr = crate::Reg<dmaomr::DmaomrSpec>;
#[doc = "Ethernet DMA operation mode register"]
pub mod dmaomr;
#[doc = "DMAIER (rw) register accessor: Ethernet DMA interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmaier::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmaier::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmaier`]
module"]
#[doc(alias = "DMAIER")]
pub type Dmaier = crate::Reg<dmaier::DmaierSpec>;
#[doc = "Ethernet DMA interrupt enable register"]
pub mod dmaier;
#[doc = "DMAMFBOCR (rw) register accessor: Ethernet DMA missed frame and buffer overflow counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmamfbocr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmamfbocr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmamfbocr`]
module"]
#[doc(alias = "DMAMFBOCR")]
pub type Dmamfbocr = crate::Reg<dmamfbocr::DmamfbocrSpec>;
#[doc = "Ethernet DMA missed frame and buffer overflow counter register"]
pub mod dmamfbocr;
#[doc = "DMARSWTR (rw) register accessor: Ethernet DMA receive status watchdog timer register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmarswtr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmarswtr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmarswtr`]
module"]
#[doc(alias = "DMARSWTR")]
pub type Dmarswtr = crate::Reg<dmarswtr::DmarswtrSpec>;
#[doc = "Ethernet DMA receive status watchdog timer register"]
pub mod dmarswtr;
#[doc = "DMACHTDR (r) register accessor: Ethernet DMA current host transmit descriptor register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmachtdr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmachtdr`]
module"]
#[doc(alias = "DMACHTDR")]
pub type Dmachtdr = crate::Reg<dmachtdr::DmachtdrSpec>;
#[doc = "Ethernet DMA current host transmit descriptor register"]
pub mod dmachtdr;
#[doc = "DMACHRDR (r) register accessor: Ethernet DMA current host receive descriptor register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmachrdr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmachrdr`]
module"]
#[doc(alias = "DMACHRDR")]
pub type Dmachrdr = crate::Reg<dmachrdr::DmachrdrSpec>;
#[doc = "Ethernet DMA current host receive descriptor register"]
pub mod dmachrdr;
#[doc = "DMACHTBAR (r) register accessor: Ethernet DMA current host transmit buffer address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmachtbar::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmachtbar`]
module"]
#[doc(alias = "DMACHTBAR")]
pub type Dmachtbar = crate::Reg<dmachtbar::DmachtbarSpec>;
#[doc = "Ethernet DMA current host transmit buffer address register"]
pub mod dmachtbar;
#[doc = "DMACHRBAR (r) register accessor: Ethernet DMA current host receive buffer address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmachrbar::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmachrbar`]
module"]
#[doc(alias = "DMACHRBAR")]
pub type Dmachrbar = crate::Reg<dmachrbar::DmachrbarSpec>;
#[doc = "Ethernet DMA current host receive buffer address register"]
pub mod dmachrbar;
