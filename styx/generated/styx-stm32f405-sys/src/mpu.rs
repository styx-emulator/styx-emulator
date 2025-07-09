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
    mpu_typer: MpuTyper,
    mpu_ctrl: MpuCtrl,
    mpu_rnr: MpuRnr,
    mpu_rbar: MpuRbar,
    mpu_rasr: MpuRasr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - MPU type register"]
    #[inline(always)]
    pub const fn mpu_typer(&self) -> &MpuTyper {
        &self.mpu_typer
    }
    #[doc = "0x04 - MPU control register"]
    #[inline(always)]
    pub const fn mpu_ctrl(&self) -> &MpuCtrl {
        &self.mpu_ctrl
    }
    #[doc = "0x08 - MPU region number register"]
    #[inline(always)]
    pub const fn mpu_rnr(&self) -> &MpuRnr {
        &self.mpu_rnr
    }
    #[doc = "0x0c - MPU region base address register"]
    #[inline(always)]
    pub const fn mpu_rbar(&self) -> &MpuRbar {
        &self.mpu_rbar
    }
    #[doc = "0x10 - MPU region attribute and size register"]
    #[inline(always)]
    pub const fn mpu_rasr(&self) -> &MpuRasr {
        &self.mpu_rasr
    }
}
#[doc = "MPU_TYPER (r) register accessor: MPU type register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_typer::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mpu_typer`]
module"]
#[doc(alias = "MPU_TYPER")]
pub type MpuTyper = crate::Reg<mpu_typer::MpuTyperSpec>;
#[doc = "MPU type register"]
pub mod mpu_typer;
#[doc = "MPU_CTRL (r) register accessor: MPU control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_ctrl::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mpu_ctrl`]
module"]
#[doc(alias = "MPU_CTRL")]
pub type MpuCtrl = crate::Reg<mpu_ctrl::MpuCtrlSpec>;
#[doc = "MPU control register"]
pub mod mpu_ctrl;
#[doc = "MPU_RNR (rw) register accessor: MPU region number register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_rnr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mpu_rnr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mpu_rnr`]
module"]
#[doc(alias = "MPU_RNR")]
pub type MpuRnr = crate::Reg<mpu_rnr::MpuRnrSpec>;
#[doc = "MPU region number register"]
pub mod mpu_rnr;
#[doc = "MPU_RBAR (rw) register accessor: MPU region base address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_rbar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mpu_rbar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mpu_rbar`]
module"]
#[doc(alias = "MPU_RBAR")]
pub type MpuRbar = crate::Reg<mpu_rbar::MpuRbarSpec>;
#[doc = "MPU region base address register"]
pub mod mpu_rbar;
#[doc = "MPU_RASR (rw) register accessor: MPU region attribute and size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mpu_rasr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mpu_rasr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mpu_rasr`]
module"]
#[doc(alias = "MPU_RASR")]
pub type MpuRasr = crate::Reg<mpu_rasr::MpuRasrSpec>;
#[doc = "MPU region attribute and size register"]
pub mod mpu_rasr;
