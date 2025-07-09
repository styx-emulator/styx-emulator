// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    otg_hs_gotgctl: OtgHsGotgctl,
    otg_hs_gotgint: OtgHsGotgint,
    otg_hs_gahbcfg: OtgHsGahbcfg,
    otg_hs_gusbcfg: OtgHsGusbcfg,
    otg_hs_grstctl: OtgHsGrstctl,
    otg_hs_gintsts: OtgHsGintsts,
    otg_hs_gintmsk: OtgHsGintmsk,
    _reserved_7_otg_hs_grxstsr: [u8; 0x04],
    _reserved_8_otg_hs_grxstsp: [u8; 0x04],
    otg_hs_grxfsiz: OtgHsGrxfsiz,
    _reserved_10_otg_hs: [u8; 0x04],
    otg_hs_gnptxsts: OtgHsGnptxsts,
    _reserved12: [u8; 0x08],
    otg_hs_gccfg: OtgHsGccfg,
    otg_hs_cid: OtgHsCid,
    _reserved14: [u8; 0xc0],
    otg_hs_hptxfsiz: OtgHsHptxfsiz,
    otg_hs_dieptxf1: OtgHsDieptxf1,
    otg_hs_dieptxf2: OtgHsDieptxf2,
    _reserved17: [u8; 0x10],
    otg_hs_dieptxf3: OtgHsDieptxf3,
    otg_hs_dieptxf4: OtgHsDieptxf4,
    otg_hs_dieptxf5: OtgHsDieptxf5,
    otg_hs_dieptxf6: OtgHsDieptxf6,
    otg_hs_dieptxf7: OtgHsDieptxf7,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_HS control and status register"]
    #[inline(always)]
    pub const fn otg_hs_gotgctl(&self) -> &OtgHsGotgctl {
        &self.otg_hs_gotgctl
    }
    #[doc = "0x04 - OTG_HS interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_gotgint(&self) -> &OtgHsGotgint {
        &self.otg_hs_gotgint
    }
    #[doc = "0x08 - OTG_HS AHB configuration register"]
    #[inline(always)]
    pub const fn otg_hs_gahbcfg(&self) -> &OtgHsGahbcfg {
        &self.otg_hs_gahbcfg
    }
    #[doc = "0x0c - OTG_HS USB configuration register"]
    #[inline(always)]
    pub const fn otg_hs_gusbcfg(&self) -> &OtgHsGusbcfg {
        &self.otg_hs_gusbcfg
    }
    #[doc = "0x10 - OTG_HS reset register"]
    #[inline(always)]
    pub const fn otg_hs_grstctl(&self) -> &OtgHsGrstctl {
        &self.otg_hs_grstctl
    }
    #[doc = "0x14 - OTG_HS core interrupt register"]
    #[inline(always)]
    pub const fn otg_hs_gintsts(&self) -> &OtgHsGintsts {
        &self.otg_hs_gintsts
    }
    #[doc = "0x18 - OTG_HS interrupt mask register"]
    #[inline(always)]
    pub const fn otg_hs_gintmsk(&self) -> &OtgHsGintmsk {
        &self.otg_hs_gintmsk
    }
    #[doc = "0x1c - OTG_HS Receive status debug read register (peripheral mode mode)"]
    #[inline(always)]
    pub const fn otg_hs_grxstsr_peripheral(&self) -> &OtgHsGrxstsrPeripheral {
        unsafe { &*(self as *const Self).cast::<u8>().add(28).cast() }
    }
    #[doc = "0x1c - OTG_HS Receive status debug read register (host mode)"]
    #[inline(always)]
    pub const fn otg_hs_grxstsr_host(&self) -> &OtgHsGrxstsrHost {
        unsafe { &*(self as *const Self).cast::<u8>().add(28).cast() }
    }
    #[doc = "0x20 - OTG_HS status read and pop register (peripheral mode)"]
    #[inline(always)]
    pub const fn otg_hs_grxstsp_peripheral(&self) -> &OtgHsGrxstspPeripheral {
        unsafe { &*(self as *const Self).cast::<u8>().add(32).cast() }
    }
    #[doc = "0x20 - OTG_HS status read and pop register (host mode)"]
    #[inline(always)]
    pub const fn otg_hs_grxstsp_host(&self) -> &OtgHsGrxstspHost {
        unsafe { &*(self as *const Self).cast::<u8>().add(32).cast() }
    }
    #[doc = "0x24 - OTG_HS Receive FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_grxfsiz(&self) -> &OtgHsGrxfsiz {
        &self.otg_hs_grxfsiz
    }
    #[doc = "0x28 - Endpoint 0 transmit FIFO size (peripheral mode)"]
    #[inline(always)]
    pub const fn otg_hs_tx0fsiz_peripheral(&self) -> &OtgHsTx0fsizPeripheral {
        unsafe { &*(self as *const Self).cast::<u8>().add(40).cast() }
    }
    #[doc = "0x28 - OTG_HS nonperiodic transmit FIFO size register (host mode)"]
    #[inline(always)]
    pub const fn otg_hs_gnptxfsiz_host(&self) -> &OtgHsGnptxfsizHost {
        unsafe { &*(self as *const Self).cast::<u8>().add(40).cast() }
    }
    #[doc = "0x2c - OTG_HS nonperiodic transmit FIFO/queue status register"]
    #[inline(always)]
    pub const fn otg_hs_gnptxsts(&self) -> &OtgHsGnptxsts {
        &self.otg_hs_gnptxsts
    }
    #[doc = "0x38 - OTG_HS general core configuration register"]
    #[inline(always)]
    pub const fn otg_hs_gccfg(&self) -> &OtgHsGccfg {
        &self.otg_hs_gccfg
    }
    #[doc = "0x3c - OTG_HS core ID register"]
    #[inline(always)]
    pub const fn otg_hs_cid(&self) -> &OtgHsCid {
        &self.otg_hs_cid
    }
    #[doc = "0x100 - OTG_HS Host periodic transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_hptxfsiz(&self) -> &OtgHsHptxfsiz {
        &self.otg_hs_hptxfsiz
    }
    #[doc = "0x104 - OTG_HS device IN endpoint transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptxf1(&self) -> &OtgHsDieptxf1 {
        &self.otg_hs_dieptxf1
    }
    #[doc = "0x108 - OTG_HS device IN endpoint transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptxf2(&self) -> &OtgHsDieptxf2 {
        &self.otg_hs_dieptxf2
    }
    #[doc = "0x11c - OTG_HS device IN endpoint transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptxf3(&self) -> &OtgHsDieptxf3 {
        &self.otg_hs_dieptxf3
    }
    #[doc = "0x120 - OTG_HS device IN endpoint transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptxf4(&self) -> &OtgHsDieptxf4 {
        &self.otg_hs_dieptxf4
    }
    #[doc = "0x124 - OTG_HS device IN endpoint transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptxf5(&self) -> &OtgHsDieptxf5 {
        &self.otg_hs_dieptxf5
    }
    #[doc = "0x128 - OTG_HS device IN endpoint transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptxf6(&self) -> &OtgHsDieptxf6 {
        &self.otg_hs_dieptxf6
    }
    #[doc = "0x12c - OTG_HS device IN endpoint transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_hs_dieptxf7(&self) -> &OtgHsDieptxf7 {
        &self.otg_hs_dieptxf7
    }
}
#[doc = "OTG_HS_GOTGCTL (rw) register accessor: OTG_HS control and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gotgctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gotgctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gotgctl`]
module"]
#[doc(alias = "OTG_HS_GOTGCTL")]
pub type OtgHsGotgctl = crate::Reg<otg_hs_gotgctl::OtgHsGotgctlSpec>;
#[doc = "OTG_HS control and status register"]
pub mod otg_hs_gotgctl;
#[doc = "OTG_HS_GOTGINT (rw) register accessor: OTG_HS interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gotgint::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gotgint::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gotgint`]
module"]
#[doc(alias = "OTG_HS_GOTGINT")]
pub type OtgHsGotgint = crate::Reg<otg_hs_gotgint::OtgHsGotgintSpec>;
#[doc = "OTG_HS interrupt register"]
pub mod otg_hs_gotgint;
#[doc = "OTG_HS_GAHBCFG (rw) register accessor: OTG_HS AHB configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gahbcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gahbcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gahbcfg`]
module"]
#[doc(alias = "OTG_HS_GAHBCFG")]
pub type OtgHsGahbcfg = crate::Reg<otg_hs_gahbcfg::OtgHsGahbcfgSpec>;
#[doc = "OTG_HS AHB configuration register"]
pub mod otg_hs_gahbcfg;
#[doc = "OTG_HS_GUSBCFG (rw) register accessor: OTG_HS USB configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gusbcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gusbcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gusbcfg`]
module"]
#[doc(alias = "OTG_HS_GUSBCFG")]
pub type OtgHsGusbcfg = crate::Reg<otg_hs_gusbcfg::OtgHsGusbcfgSpec>;
#[doc = "OTG_HS USB configuration register"]
pub mod otg_hs_gusbcfg;
#[doc = "OTG_HS_GRSTCTL (rw) register accessor: OTG_HS reset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_grstctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_grstctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_grstctl`]
module"]
#[doc(alias = "OTG_HS_GRSTCTL")]
pub type OtgHsGrstctl = crate::Reg<otg_hs_grstctl::OtgHsGrstctlSpec>;
#[doc = "OTG_HS reset register"]
pub mod otg_hs_grstctl;
#[doc = "OTG_HS_GINTSTS (rw) register accessor: OTG_HS core interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gintsts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gintsts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gintsts`]
module"]
#[doc(alias = "OTG_HS_GINTSTS")]
pub type OtgHsGintsts = crate::Reg<otg_hs_gintsts::OtgHsGintstsSpec>;
#[doc = "OTG_HS core interrupt register"]
pub mod otg_hs_gintsts;
#[doc = "OTG_HS_GINTMSK (rw) register accessor: OTG_HS interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gintmsk`]
module"]
#[doc(alias = "OTG_HS_GINTMSK")]
pub type OtgHsGintmsk = crate::Reg<otg_hs_gintmsk::OtgHsGintmskSpec>;
#[doc = "OTG_HS interrupt mask register"]
pub mod otg_hs_gintmsk;
#[doc = "OTG_HS_GRXSTSR_Host (r) register accessor: OTG_HS Receive status debug read register (host mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_grxstsr_host::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_grxstsr_host`]
module"]
#[doc(alias = "OTG_HS_GRXSTSR_Host")]
pub type OtgHsGrxstsrHost = crate::Reg<otg_hs_grxstsr_host::OtgHsGrxstsrHostSpec>;
#[doc = "OTG_HS Receive status debug read register (host mode)"]
pub mod otg_hs_grxstsr_host;
#[doc = "OTG_HS_GRXSTSP_Host (r) register accessor: OTG_HS status read and pop register (host mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_grxstsp_host::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_grxstsp_host`]
module"]
#[doc(alias = "OTG_HS_GRXSTSP_Host")]
pub type OtgHsGrxstspHost = crate::Reg<otg_hs_grxstsp_host::OtgHsGrxstspHostSpec>;
#[doc = "OTG_HS status read and pop register (host mode)"]
pub mod otg_hs_grxstsp_host;
#[doc = "OTG_HS_GRXFSIZ (rw) register accessor: OTG_HS Receive FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_grxfsiz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_grxfsiz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_grxfsiz`]
module"]
#[doc(alias = "OTG_HS_GRXFSIZ")]
pub type OtgHsGrxfsiz = crate::Reg<otg_hs_grxfsiz::OtgHsGrxfsizSpec>;
#[doc = "OTG_HS Receive FIFO size register"]
pub mod otg_hs_grxfsiz;
#[doc = "OTG_HS_GNPTXFSIZ_Host (rw) register accessor: OTG_HS nonperiodic transmit FIFO size register (host mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gnptxfsiz_host::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gnptxfsiz_host::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gnptxfsiz_host`]
module"]
#[doc(alias = "OTG_HS_GNPTXFSIZ_Host")]
pub type OtgHsGnptxfsizHost = crate::Reg<otg_hs_gnptxfsiz_host::OtgHsGnptxfsizHostSpec>;
#[doc = "OTG_HS nonperiodic transmit FIFO size register (host mode)"]
pub mod otg_hs_gnptxfsiz_host;
#[doc = "OTG_HS_TX0FSIZ_Peripheral (rw) register accessor: Endpoint 0 transmit FIFO size (peripheral mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_tx0fsiz_peripheral::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_tx0fsiz_peripheral::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_tx0fsiz_peripheral`]
module"]
#[doc(alias = "OTG_HS_TX0FSIZ_Peripheral")]
pub type OtgHsTx0fsizPeripheral = crate::Reg<otg_hs_tx0fsiz_peripheral::OtgHsTx0fsizPeripheralSpec>;
#[doc = "Endpoint 0 transmit FIFO size (peripheral mode)"]
pub mod otg_hs_tx0fsiz_peripheral;
#[doc = "OTG_HS_GNPTXSTS (r) register accessor: OTG_HS nonperiodic transmit FIFO/queue status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gnptxsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gnptxsts`]
module"]
#[doc(alias = "OTG_HS_GNPTXSTS")]
pub type OtgHsGnptxsts = crate::Reg<otg_hs_gnptxsts::OtgHsGnptxstsSpec>;
#[doc = "OTG_HS nonperiodic transmit FIFO/queue status register"]
pub mod otg_hs_gnptxsts;
#[doc = "OTG_HS_GCCFG (rw) register accessor: OTG_HS general core configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gccfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gccfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_gccfg`]
module"]
#[doc(alias = "OTG_HS_GCCFG")]
pub type OtgHsGccfg = crate::Reg<otg_hs_gccfg::OtgHsGccfgSpec>;
#[doc = "OTG_HS general core configuration register"]
pub mod otg_hs_gccfg;
#[doc = "OTG_HS_CID (rw) register accessor: OTG_HS core ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_cid::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_cid::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_cid`]
module"]
#[doc(alias = "OTG_HS_CID")]
pub type OtgHsCid = crate::Reg<otg_hs_cid::OtgHsCidSpec>;
#[doc = "OTG_HS core ID register"]
pub mod otg_hs_cid;
#[doc = "OTG_HS_HPTXFSIZ (rw) register accessor: OTG_HS Host periodic transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hptxfsiz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hptxfsiz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_hptxfsiz`]
module"]
#[doc(alias = "OTG_HS_HPTXFSIZ")]
pub type OtgHsHptxfsiz = crate::Reg<otg_hs_hptxfsiz::OtgHsHptxfsizSpec>;
#[doc = "OTG_HS Host periodic transmit FIFO size register"]
pub mod otg_hs_hptxfsiz;
#[doc = "OTG_HS_DIEPTXF1 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptxf1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptxf1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptxf1`]
module"]
#[doc(alias = "OTG_HS_DIEPTXF1")]
pub type OtgHsDieptxf1 = crate::Reg<otg_hs_dieptxf1::OtgHsDieptxf1Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO size register"]
pub mod otg_hs_dieptxf1;
#[doc = "OTG_HS_DIEPTXF2 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptxf2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptxf2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptxf2`]
module"]
#[doc(alias = "OTG_HS_DIEPTXF2")]
pub type OtgHsDieptxf2 = crate::Reg<otg_hs_dieptxf2::OtgHsDieptxf2Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO size register"]
pub mod otg_hs_dieptxf2;
#[doc = "OTG_HS_DIEPTXF3 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptxf3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptxf3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptxf3`]
module"]
#[doc(alias = "OTG_HS_DIEPTXF3")]
pub type OtgHsDieptxf3 = crate::Reg<otg_hs_dieptxf3::OtgHsDieptxf3Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO size register"]
pub mod otg_hs_dieptxf3;
#[doc = "OTG_HS_DIEPTXF4 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptxf4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptxf4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptxf4`]
module"]
#[doc(alias = "OTG_HS_DIEPTXF4")]
pub type OtgHsDieptxf4 = crate::Reg<otg_hs_dieptxf4::OtgHsDieptxf4Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO size register"]
pub mod otg_hs_dieptxf4;
#[doc = "OTG_HS_DIEPTXF5 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptxf5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptxf5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptxf5`]
module"]
#[doc(alias = "OTG_HS_DIEPTXF5")]
pub type OtgHsDieptxf5 = crate::Reg<otg_hs_dieptxf5::OtgHsDieptxf5Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO size register"]
pub mod otg_hs_dieptxf5;
#[doc = "OTG_HS_DIEPTXF6 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptxf6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptxf6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptxf6`]
module"]
#[doc(alias = "OTG_HS_DIEPTXF6")]
pub type OtgHsDieptxf6 = crate::Reg<otg_hs_dieptxf6::OtgHsDieptxf6Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO size register"]
pub mod otg_hs_dieptxf6;
#[doc = "OTG_HS_DIEPTXF7 (rw) register accessor: OTG_HS device IN endpoint transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_dieptxf7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_dieptxf7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_dieptxf7`]
module"]
#[doc(alias = "OTG_HS_DIEPTXF7")]
pub type OtgHsDieptxf7 = crate::Reg<otg_hs_dieptxf7::OtgHsDieptxf7Spec>;
#[doc = "OTG_HS device IN endpoint transmit FIFO size register"]
pub mod otg_hs_dieptxf7;
#[doc = "OTG_HS_GRXSTSR_Peripheral (r) register accessor: OTG_HS Receive status debug read register (peripheral mode mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_grxstsr_peripheral::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_grxstsr_peripheral`]
module"]
#[doc(alias = "OTG_HS_GRXSTSR_Peripheral")]
pub type OtgHsGrxstsrPeripheral = crate::Reg<otg_hs_grxstsr_peripheral::OtgHsGrxstsrPeripheralSpec>;
#[doc = "OTG_HS Receive status debug read register (peripheral mode mode)"]
pub mod otg_hs_grxstsr_peripheral;
#[doc = "OTG_HS_GRXSTSP_Peripheral (r) register accessor: OTG_HS status read and pop register (peripheral mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_grxstsp_peripheral::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_hs_grxstsp_peripheral`]
module"]
#[doc(alias = "OTG_HS_GRXSTSP_Peripheral")]
pub type OtgHsGrxstspPeripheral = crate::Reg<otg_hs_grxstsp_peripheral::OtgHsGrxstspPeripheralSpec>;
#[doc = "OTG_HS status read and pop register (peripheral mode)"]
pub mod otg_hs_grxstsp_peripheral;
