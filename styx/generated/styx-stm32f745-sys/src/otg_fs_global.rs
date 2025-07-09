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
    otg_fs_gotgctl: OtgFsGotgctl,
    otg_fs_gotgint: OtgFsGotgint,
    otg_fs_gahbcfg: OtgFsGahbcfg,
    otg_fs_gusbcfg: OtgFsGusbcfg,
    otg_fs_grstctl: OtgFsGrstctl,
    otg_fs_gintsts: OtgFsGintsts,
    otg_fs_gintmsk: OtgFsGintmsk,
    _reserved_7_otg_fs_grxstsr: [u8; 0x04],
    _reserved_8_otg_fs_grxstsp: [u8; 0x04],
    otg_fs_grxfsiz: OtgFsGrxfsiz,
    _reserved_10_otg_fs: [u8; 0x04],
    otg_fs_hnptxsts: OtgFsHnptxsts,
    otg_fs_gi2cctl: OtgFsGi2cctl,
    _reserved13: [u8; 0x04],
    otg_fs_gccfg: OtgFsGccfg,
    otg_fs_cid: OtgFsCid,
    _reserved15: [u8; 0x14],
    otg_fs_glpmcfg: OtgFsGlpmcfg,
    otg_fs_gpwrdn: OtgFsGpwrdn,
    _reserved17: [u8; 0x04],
    otg_fs_gadpctl: OtgFsGadpctl,
    _reserved18: [u8; 0x9c],
    otg_fs_hptxfsiz: OtgFsHptxfsiz,
    otg_fs_dieptxf1: OtgFsDieptxf1,
    otg_fs_dieptxf2: OtgFsDieptxf2,
    otg_fs_dieptxf3: OtgFsDieptxf3,
    otg_fs_dieptxf4: OtgFsDieptxf4,
    otg_fs_dieptxf5: OtgFsDieptxf5,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - OTG_FS control and status register (OTG_FS_GOTGCTL)"]
    #[inline(always)]
    pub const fn otg_fs_gotgctl(&self) -> &OtgFsGotgctl {
        &self.otg_fs_gotgctl
    }
    #[doc = "0x04 - OTG_FS interrupt register (OTG_FS_GOTGINT)"]
    #[inline(always)]
    pub const fn otg_fs_gotgint(&self) -> &OtgFsGotgint {
        &self.otg_fs_gotgint
    }
    #[doc = "0x08 - OTG_FS AHB configuration register (OTG_FS_GAHBCFG)"]
    #[inline(always)]
    pub const fn otg_fs_gahbcfg(&self) -> &OtgFsGahbcfg {
        &self.otg_fs_gahbcfg
    }
    #[doc = "0x0c - OTG_FS USB configuration register (OTG_FS_GUSBCFG)"]
    #[inline(always)]
    pub const fn otg_fs_gusbcfg(&self) -> &OtgFsGusbcfg {
        &self.otg_fs_gusbcfg
    }
    #[doc = "0x10 - OTG_FS reset register (OTG_FS_GRSTCTL)"]
    #[inline(always)]
    pub const fn otg_fs_grstctl(&self) -> &OtgFsGrstctl {
        &self.otg_fs_grstctl
    }
    #[doc = "0x14 - OTG_FS core interrupt register (OTG_FS_GINTSTS)"]
    #[inline(always)]
    pub const fn otg_fs_gintsts(&self) -> &OtgFsGintsts {
        &self.otg_fs_gintsts
    }
    #[doc = "0x18 - OTG_FS interrupt mask register (OTG_FS_GINTMSK)"]
    #[inline(always)]
    pub const fn otg_fs_gintmsk(&self) -> &OtgFsGintmsk {
        &self.otg_fs_gintmsk
    }
    #[doc = "0x1c - OTG_FS Receive status debug read(Host mode)"]
    #[inline(always)]
    pub const fn otg_fs_grxstsr_host(&self) -> &OtgFsGrxstsrHost {
        unsafe { &*(self as *const Self).cast::<u8>().add(28).cast() }
    }
    #[doc = "0x1c - OTG_FS Receive status debug read(Device mode)"]
    #[inline(always)]
    pub const fn otg_fs_grxstsr_device(&self) -> &OtgFsGrxstsrDevice {
        unsafe { &*(self as *const Self).cast::<u8>().add(28).cast() }
    }
    #[doc = "0x20 - OTG status read and pop register (Host mode)"]
    #[inline(always)]
    pub const fn otg_fs_grxstsp_host(&self) -> &OtgFsGrxstspHost {
        unsafe { &*(self as *const Self).cast::<u8>().add(32).cast() }
    }
    #[doc = "0x20 - OTG status read and pop register (Device mode)"]
    #[inline(always)]
    pub const fn otg_fs_grxstsp_device(&self) -> &OtgFsGrxstspDevice {
        unsafe { &*(self as *const Self).cast::<u8>().add(32).cast() }
    }
    #[doc = "0x24 - OTG_FS Receive FIFO size register (OTG_FS_GRXFSIZ)"]
    #[inline(always)]
    pub const fn otg_fs_grxfsiz(&self) -> &OtgFsGrxfsiz {
        &self.otg_fs_grxfsiz
    }
    #[doc = "0x28 - OTG_FS Host non-periodic transmit FIFO size register"]
    #[inline(always)]
    pub const fn otg_fs_hnptxfsiz_host(&self) -> &OtgFsHnptxfsizHost {
        unsafe { &*(self as *const Self).cast::<u8>().add(40).cast() }
    }
    #[doc = "0x28 - OTG_FS Endpoint 0 Transmit FIFO size"]
    #[inline(always)]
    pub const fn otg_fs_dieptxf0_device(&self) -> &OtgFsDieptxf0Device {
        unsafe { &*(self as *const Self).cast::<u8>().add(40).cast() }
    }
    #[doc = "0x2c - OTG_FS non-periodic transmit FIFO/queue status register (OTG_FS_GNPTXSTS)"]
    #[inline(always)]
    pub const fn otg_fs_hnptxsts(&self) -> &OtgFsHnptxsts {
        &self.otg_fs_hnptxsts
    }
    #[doc = "0x30 - OTG I2C access register"]
    #[inline(always)]
    pub const fn otg_fs_gi2cctl(&self) -> &OtgFsGi2cctl {
        &self.otg_fs_gi2cctl
    }
    #[doc = "0x38 - OTG_FS general core configuration register (OTG_FS_GCCFG)"]
    #[inline(always)]
    pub const fn otg_fs_gccfg(&self) -> &OtgFsGccfg {
        &self.otg_fs_gccfg
    }
    #[doc = "0x3c - core ID register"]
    #[inline(always)]
    pub const fn otg_fs_cid(&self) -> &OtgFsCid {
        &self.otg_fs_cid
    }
    #[doc = "0x54 - OTG core LPM configuration register"]
    #[inline(always)]
    pub const fn otg_fs_glpmcfg(&self) -> &OtgFsGlpmcfg {
        &self.otg_fs_glpmcfg
    }
    #[doc = "0x58 - OTG power down register"]
    #[inline(always)]
    pub const fn otg_fs_gpwrdn(&self) -> &OtgFsGpwrdn {
        &self.otg_fs_gpwrdn
    }
    #[doc = "0x60 - OTG ADP timer, control and status register"]
    #[inline(always)]
    pub const fn otg_fs_gadpctl(&self) -> &OtgFsGadpctl {
        &self.otg_fs_gadpctl
    }
    #[doc = "0x100 - OTG_FS Host periodic transmit FIFO size register (OTG_FS_HPTXFSIZ)"]
    #[inline(always)]
    pub const fn otg_fs_hptxfsiz(&self) -> &OtgFsHptxfsiz {
        &self.otg_fs_hptxfsiz
    }
    #[doc = "0x104 - OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF1)"]
    #[inline(always)]
    pub const fn otg_fs_dieptxf1(&self) -> &OtgFsDieptxf1 {
        &self.otg_fs_dieptxf1
    }
    #[doc = "0x108 - OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF2)"]
    #[inline(always)]
    pub const fn otg_fs_dieptxf2(&self) -> &OtgFsDieptxf2 {
        &self.otg_fs_dieptxf2
    }
    #[doc = "0x10c - OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF3)"]
    #[inline(always)]
    pub const fn otg_fs_dieptxf3(&self) -> &OtgFsDieptxf3 {
        &self.otg_fs_dieptxf3
    }
    #[doc = "0x110 - OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF4)"]
    #[inline(always)]
    pub const fn otg_fs_dieptxf4(&self) -> &OtgFsDieptxf4 {
        &self.otg_fs_dieptxf4
    }
    #[doc = "0x114 - OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF5)"]
    #[inline(always)]
    pub const fn otg_fs_dieptxf5(&self) -> &OtgFsDieptxf5 {
        &self.otg_fs_dieptxf5
    }
}
#[doc = "OTG_FS_GOTGCTL (rw) register accessor: OTG_FS control and status register (OTG_FS_GOTGCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gotgctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gotgctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gotgctl`]
module"]
#[doc(alias = "OTG_FS_GOTGCTL")]
pub type OtgFsGotgctl = crate::Reg<otg_fs_gotgctl::OtgFsGotgctlSpec>;
#[doc = "OTG_FS control and status register (OTG_FS_GOTGCTL)"]
pub mod otg_fs_gotgctl;
#[doc = "OTG_FS_GOTGINT (rw) register accessor: OTG_FS interrupt register (OTG_FS_GOTGINT)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gotgint::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gotgint::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gotgint`]
module"]
#[doc(alias = "OTG_FS_GOTGINT")]
pub type OtgFsGotgint = crate::Reg<otg_fs_gotgint::OtgFsGotgintSpec>;
#[doc = "OTG_FS interrupt register (OTG_FS_GOTGINT)"]
pub mod otg_fs_gotgint;
#[doc = "OTG_FS_GAHBCFG (rw) register accessor: OTG_FS AHB configuration register (OTG_FS_GAHBCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gahbcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gahbcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gahbcfg`]
module"]
#[doc(alias = "OTG_FS_GAHBCFG")]
pub type OtgFsGahbcfg = crate::Reg<otg_fs_gahbcfg::OtgFsGahbcfgSpec>;
#[doc = "OTG_FS AHB configuration register (OTG_FS_GAHBCFG)"]
pub mod otg_fs_gahbcfg;
#[doc = "OTG_FS_GUSBCFG (rw) register accessor: OTG_FS USB configuration register (OTG_FS_GUSBCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gusbcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gusbcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gusbcfg`]
module"]
#[doc(alias = "OTG_FS_GUSBCFG")]
pub type OtgFsGusbcfg = crate::Reg<otg_fs_gusbcfg::OtgFsGusbcfgSpec>;
#[doc = "OTG_FS USB configuration register (OTG_FS_GUSBCFG)"]
pub mod otg_fs_gusbcfg;
#[doc = "OTG_FS_GRSTCTL (rw) register accessor: OTG_FS reset register (OTG_FS_GRSTCTL)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grstctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_grstctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_grstctl`]
module"]
#[doc(alias = "OTG_FS_GRSTCTL")]
pub type OtgFsGrstctl = crate::Reg<otg_fs_grstctl::OtgFsGrstctlSpec>;
#[doc = "OTG_FS reset register (OTG_FS_GRSTCTL)"]
pub mod otg_fs_grstctl;
#[doc = "OTG_FS_GINTSTS (rw) register accessor: OTG_FS core interrupt register (OTG_FS_GINTSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gintsts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gintsts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gintsts`]
module"]
#[doc(alias = "OTG_FS_GINTSTS")]
pub type OtgFsGintsts = crate::Reg<otg_fs_gintsts::OtgFsGintstsSpec>;
#[doc = "OTG_FS core interrupt register (OTG_FS_GINTSTS)"]
pub mod otg_fs_gintsts;
#[doc = "OTG_FS_GINTMSK (rw) register accessor: OTG_FS interrupt mask register (OTG_FS_GINTMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gintmsk`]
module"]
#[doc(alias = "OTG_FS_GINTMSK")]
pub type OtgFsGintmsk = crate::Reg<otg_fs_gintmsk::OtgFsGintmskSpec>;
#[doc = "OTG_FS interrupt mask register (OTG_FS_GINTMSK)"]
pub mod otg_fs_gintmsk;
#[doc = "OTG_FS_GRXSTSR_Device (r) register accessor: OTG_FS Receive status debug read(Device mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grxstsr_device::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_grxstsr_device`]
module"]
#[doc(alias = "OTG_FS_GRXSTSR_Device")]
pub type OtgFsGrxstsrDevice = crate::Reg<otg_fs_grxstsr_device::OtgFsGrxstsrDeviceSpec>;
#[doc = "OTG_FS Receive status debug read(Device mode)"]
pub mod otg_fs_grxstsr_device;
#[doc = "OTG_FS_GRXSTSR_Host (r) register accessor: OTG_FS Receive status debug read(Host mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grxstsr_host::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_grxstsr_host`]
module"]
#[doc(alias = "OTG_FS_GRXSTSR_Host")]
pub type OtgFsGrxstsrHost = crate::Reg<otg_fs_grxstsr_host::OtgFsGrxstsrHostSpec>;
#[doc = "OTG_FS Receive status debug read(Host mode)"]
pub mod otg_fs_grxstsr_host;
#[doc = "OTG_FS_GRXFSIZ (rw) register accessor: OTG_FS Receive FIFO size register (OTG_FS_GRXFSIZ)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grxfsiz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_grxfsiz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_grxfsiz`]
module"]
#[doc(alias = "OTG_FS_GRXFSIZ")]
pub type OtgFsGrxfsiz = crate::Reg<otg_fs_grxfsiz::OtgFsGrxfsizSpec>;
#[doc = "OTG_FS Receive FIFO size register (OTG_FS_GRXFSIZ)"]
pub mod otg_fs_grxfsiz;
#[doc = "OTG_FS_DIEPTXF0_Device (rw) register accessor: OTG_FS Endpoint 0 Transmit FIFO size\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptxf0_device::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptxf0_device::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptxf0_device`]
module"]
#[doc(alias = "OTG_FS_DIEPTXF0_Device")]
pub type OtgFsDieptxf0Device = crate::Reg<otg_fs_dieptxf0_device::OtgFsDieptxf0DeviceSpec>;
#[doc = "OTG_FS Endpoint 0 Transmit FIFO size"]
pub mod otg_fs_dieptxf0_device;
#[doc = "OTG_FS_HNPTXFSIZ_Host (rw) register accessor: OTG_FS Host non-periodic transmit FIFO size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hnptxfsiz_host::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hnptxfsiz_host::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hnptxfsiz_host`]
module"]
#[doc(alias = "OTG_FS_HNPTXFSIZ_Host")]
pub type OtgFsHnptxfsizHost = crate::Reg<otg_fs_hnptxfsiz_host::OtgFsHnptxfsizHostSpec>;
#[doc = "OTG_FS Host non-periodic transmit FIFO size register"]
pub mod otg_fs_hnptxfsiz_host;
#[doc = "OTG_FS_HNPTXSTS (r) register accessor: OTG_FS non-periodic transmit FIFO/queue status register (OTG_FS_GNPTXSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hnptxsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hnptxsts`]
module"]
#[doc(alias = "OTG_FS_HNPTXSTS")]
pub type OtgFsHnptxsts = crate::Reg<otg_fs_hnptxsts::OtgFsHnptxstsSpec>;
#[doc = "OTG_FS non-periodic transmit FIFO/queue status register (OTG_FS_GNPTXSTS)"]
pub mod otg_fs_hnptxsts;
#[doc = "OTG_FS_GCCFG (rw) register accessor: OTG_FS general core configuration register (OTG_FS_GCCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gccfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gccfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gccfg`]
module"]
#[doc(alias = "OTG_FS_GCCFG")]
pub type OtgFsGccfg = crate::Reg<otg_fs_gccfg::OtgFsGccfgSpec>;
#[doc = "OTG_FS general core configuration register (OTG_FS_GCCFG)"]
pub mod otg_fs_gccfg;
#[doc = "OTG_FS_CID (rw) register accessor: core ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_cid::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_cid::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_cid`]
module"]
#[doc(alias = "OTG_FS_CID")]
pub type OtgFsCid = crate::Reg<otg_fs_cid::OtgFsCidSpec>;
#[doc = "core ID register"]
pub mod otg_fs_cid;
#[doc = "OTG_FS_HPTXFSIZ (rw) register accessor: OTG_FS Host periodic transmit FIFO size register (OTG_FS_HPTXFSIZ)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hptxfsiz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hptxfsiz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_hptxfsiz`]
module"]
#[doc(alias = "OTG_FS_HPTXFSIZ")]
pub type OtgFsHptxfsiz = crate::Reg<otg_fs_hptxfsiz::OtgFsHptxfsizSpec>;
#[doc = "OTG_FS Host periodic transmit FIFO size register (OTG_FS_HPTXFSIZ)"]
pub mod otg_fs_hptxfsiz;
#[doc = "OTG_FS_DIEPTXF1 (rw) register accessor: OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF1)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptxf1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptxf1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptxf1`]
module"]
#[doc(alias = "OTG_FS_DIEPTXF1")]
pub type OtgFsDieptxf1 = crate::Reg<otg_fs_dieptxf1::OtgFsDieptxf1Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF1)"]
pub mod otg_fs_dieptxf1;
#[doc = "OTG_FS_DIEPTXF2 (rw) register accessor: OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF2)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptxf2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptxf2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptxf2`]
module"]
#[doc(alias = "OTG_FS_DIEPTXF2")]
pub type OtgFsDieptxf2 = crate::Reg<otg_fs_dieptxf2::OtgFsDieptxf2Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF2)"]
pub mod otg_fs_dieptxf2;
#[doc = "OTG_FS_DIEPTXF3 (rw) register accessor: OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF3)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptxf3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptxf3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptxf3`]
module"]
#[doc(alias = "OTG_FS_DIEPTXF3")]
pub type OtgFsDieptxf3 = crate::Reg<otg_fs_dieptxf3::OtgFsDieptxf3Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF3)"]
pub mod otg_fs_dieptxf3;
#[doc = "OTG_FS_GRXSTSP_Device (r) register accessor: OTG status read and pop register (Device mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grxstsp_device::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_grxstsp_device`]
module"]
#[doc(alias = "OTG_FS_GRXSTSP_Device")]
pub type OtgFsGrxstspDevice = crate::Reg<otg_fs_grxstsp_device::OtgFsGrxstspDeviceSpec>;
#[doc = "OTG status read and pop register (Device mode)"]
pub mod otg_fs_grxstsp_device;
#[doc = "OTG_FS_GRXSTSP_Host (r) register accessor: OTG status read and pop register (Host mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_grxstsp_host::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_grxstsp_host`]
module"]
#[doc(alias = "OTG_FS_GRXSTSP_Host")]
pub type OtgFsGrxstspHost = crate::Reg<otg_fs_grxstsp_host::OtgFsGrxstspHostSpec>;
#[doc = "OTG status read and pop register (Host mode)"]
pub mod otg_fs_grxstsp_host;
#[doc = "OTG_FS_GI2CCTL (rw) register accessor: OTG I2C access register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gi2cctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gi2cctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gi2cctl`]
module"]
#[doc(alias = "OTG_FS_GI2CCTL")]
pub type OtgFsGi2cctl = crate::Reg<otg_fs_gi2cctl::OtgFsGi2cctlSpec>;
#[doc = "OTG I2C access register"]
pub mod otg_fs_gi2cctl;
#[doc = "OTG_FS_GPWRDN (rw) register accessor: OTG power down register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gpwrdn::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gpwrdn::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gpwrdn`]
module"]
#[doc(alias = "OTG_FS_GPWRDN")]
pub type OtgFsGpwrdn = crate::Reg<otg_fs_gpwrdn::OtgFsGpwrdnSpec>;
#[doc = "OTG power down register"]
pub mod otg_fs_gpwrdn;
#[doc = "OTG_FS_GADPCTL (rw) register accessor: OTG ADP timer, control and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gadpctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gadpctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_gadpctl`]
module"]
#[doc(alias = "OTG_FS_GADPCTL")]
pub type OtgFsGadpctl = crate::Reg<otg_fs_gadpctl::OtgFsGadpctlSpec>;
#[doc = "OTG ADP timer, control and status register"]
pub mod otg_fs_gadpctl;
#[doc = "OTG_FS_DIEPTXF4 (rw) register accessor: OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF4)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptxf4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptxf4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptxf4`]
module"]
#[doc(alias = "OTG_FS_DIEPTXF4")]
pub type OtgFsDieptxf4 = crate::Reg<otg_fs_dieptxf4::OtgFsDieptxf4Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF4)"]
pub mod otg_fs_dieptxf4;
#[doc = "OTG_FS_DIEPTXF5 (rw) register accessor: OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF5)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dieptxf5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dieptxf5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_dieptxf5`]
module"]
#[doc(alias = "OTG_FS_DIEPTXF5")]
pub type OtgFsDieptxf5 = crate::Reg<otg_fs_dieptxf5::OtgFsDieptxf5Spec>;
#[doc = "OTG_FS device IN endpoint transmit FIFO size register (OTG_FS_DIEPTXF5)"]
pub mod otg_fs_dieptxf5;
#[doc = "OTG_FS_GLPMCFG (rw) register accessor: OTG core LPM configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_glpmcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_glpmcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@otg_fs_glpmcfg`]
module"]
#[doc(alias = "OTG_FS_GLPMCFG")]
pub type OtgFsGlpmcfg = crate::Reg<otg_fs_glpmcfg::OtgFsGlpmcfgSpec>;
#[doc = "OTG core LPM configuration register"]
pub mod otg_fs_glpmcfg;
