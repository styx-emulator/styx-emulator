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
    itcmcr: Itcmcr,
    dtcmcr: Dtcmcr,
    ahbpcr: Ahbpcr,
    cacr: Cacr,
    ahbscr: Ahbscr,
    _reserved5: [u8; 0x04],
    abfsr: Abfsr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Instruction and Data Tightly-Coupled Memory Control Registers"]
    #[inline(always)]
    pub const fn itcmcr(&self) -> &Itcmcr {
        &self.itcmcr
    }
    #[doc = "0x04 - Instruction and Data Tightly-Coupled Memory Control Registers"]
    #[inline(always)]
    pub const fn dtcmcr(&self) -> &Dtcmcr {
        &self.dtcmcr
    }
    #[doc = "0x08 - AHBP Control register"]
    #[inline(always)]
    pub const fn ahbpcr(&self) -> &Ahbpcr {
        &self.ahbpcr
    }
    #[doc = "0x0c - Auxiliary Cache Control register"]
    #[inline(always)]
    pub const fn cacr(&self) -> &Cacr {
        &self.cacr
    }
    #[doc = "0x10 - AHB Slave Control register"]
    #[inline(always)]
    pub const fn ahbscr(&self) -> &Ahbscr {
        &self.ahbscr
    }
    #[doc = "0x18 - Auxiliary Bus Fault Status register"]
    #[inline(always)]
    pub const fn abfsr(&self) -> &Abfsr {
        &self.abfsr
    }
}
#[doc = "ITCMCR (rw) register accessor: Instruction and Data Tightly-Coupled Memory Control Registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`itcmcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`itcmcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@itcmcr`]
module"]
#[doc(alias = "ITCMCR")]
pub type Itcmcr = crate::Reg<itcmcr::ItcmcrSpec>;
#[doc = "Instruction and Data Tightly-Coupled Memory Control Registers"]
pub mod itcmcr;
#[doc = "DTCMCR (rw) register accessor: Instruction and Data Tightly-Coupled Memory Control Registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtcmcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dtcmcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dtcmcr`]
module"]
#[doc(alias = "DTCMCR")]
pub type Dtcmcr = crate::Reg<dtcmcr::DtcmcrSpec>;
#[doc = "Instruction and Data Tightly-Coupled Memory Control Registers"]
pub mod dtcmcr;
#[doc = "AHBPCR (rw) register accessor: AHBP Control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahbpcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahbpcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ahbpcr`]
module"]
#[doc(alias = "AHBPCR")]
pub type Ahbpcr = crate::Reg<ahbpcr::AhbpcrSpec>;
#[doc = "AHBP Control register"]
pub mod ahbpcr;
#[doc = "CACR (rw) register accessor: Auxiliary Cache Control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cacr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cacr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cacr`]
module"]
#[doc(alias = "CACR")]
pub type Cacr = crate::Reg<cacr::CacrSpec>;
#[doc = "Auxiliary Cache Control register"]
pub mod cacr;
#[doc = "AHBSCR (rw) register accessor: AHB Slave Control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahbscr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahbscr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ahbscr`]
module"]
#[doc(alias = "AHBSCR")]
pub type Ahbscr = crate::Reg<ahbscr::AhbscrSpec>;
#[doc = "AHB Slave Control register"]
pub mod ahbscr;
#[doc = "ABFSR (rw) register accessor: Auxiliary Bus Fault Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`abfsr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`abfsr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@abfsr`]
module"]
#[doc(alias = "ABFSR")]
pub type Abfsr = crate::Reg<abfsr::AbfsrSpec>;
#[doc = "Auxiliary Bus Fault Status register"]
pub mod abfsr;
