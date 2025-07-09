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
    ptptscr: Ptptscr,
    ptpssir: Ptpssir,
    ptptshr: Ptptshr,
    ptptslr: Ptptslr,
    ptptshur: Ptptshur,
    ptptslur: Ptptslur,
    ptptsar: Ptptsar,
    ptptthr: Ptptthr,
    ptpttlr: Ptpttlr,
    _reserved9: [u8; 0x04],
    ptptssr: Ptptssr,
    ptpppscr: Ptpppscr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Ethernet PTP time stamp control register"]
    #[inline(always)]
    pub const fn ptptscr(&self) -> &Ptptscr {
        &self.ptptscr
    }
    #[doc = "0x04 - Ethernet PTP subsecond increment register"]
    #[inline(always)]
    pub const fn ptpssir(&self) -> &Ptpssir {
        &self.ptpssir
    }
    #[doc = "0x08 - Ethernet PTP time stamp high register"]
    #[inline(always)]
    pub const fn ptptshr(&self) -> &Ptptshr {
        &self.ptptshr
    }
    #[doc = "0x0c - Ethernet PTP time stamp low register"]
    #[inline(always)]
    pub const fn ptptslr(&self) -> &Ptptslr {
        &self.ptptslr
    }
    #[doc = "0x10 - Ethernet PTP time stamp high update register"]
    #[inline(always)]
    pub const fn ptptshur(&self) -> &Ptptshur {
        &self.ptptshur
    }
    #[doc = "0x14 - Ethernet PTP time stamp low update register"]
    #[inline(always)]
    pub const fn ptptslur(&self) -> &Ptptslur {
        &self.ptptslur
    }
    #[doc = "0x18 - Ethernet PTP time stamp addend register"]
    #[inline(always)]
    pub const fn ptptsar(&self) -> &Ptptsar {
        &self.ptptsar
    }
    #[doc = "0x1c - Ethernet PTP target time high register"]
    #[inline(always)]
    pub const fn ptptthr(&self) -> &Ptptthr {
        &self.ptptthr
    }
    #[doc = "0x20 - Ethernet PTP target time low register"]
    #[inline(always)]
    pub const fn ptpttlr(&self) -> &Ptpttlr {
        &self.ptpttlr
    }
    #[doc = "0x28 - Ethernet PTP time stamp status register"]
    #[inline(always)]
    pub const fn ptptssr(&self) -> &Ptptssr {
        &self.ptptssr
    }
    #[doc = "0x2c - Ethernet PTP PPS control register"]
    #[inline(always)]
    pub const fn ptpppscr(&self) -> &Ptpppscr {
        &self.ptpppscr
    }
}
#[doc = "PTPTSCR (rw) register accessor: Ethernet PTP time stamp control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptscr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptscr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptptscr`]
module"]
#[doc(alias = "PTPTSCR")]
pub type Ptptscr = crate::Reg<ptptscr::PtptscrSpec>;
#[doc = "Ethernet PTP time stamp control register"]
pub mod ptptscr;
#[doc = "PTPSSIR (rw) register accessor: Ethernet PTP subsecond increment register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptpssir::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptpssir::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptpssir`]
module"]
#[doc(alias = "PTPSSIR")]
pub type Ptpssir = crate::Reg<ptpssir::PtpssirSpec>;
#[doc = "Ethernet PTP subsecond increment register"]
pub mod ptpssir;
#[doc = "PTPTSHR (r) register accessor: Ethernet PTP time stamp high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptshr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptptshr`]
module"]
#[doc(alias = "PTPTSHR")]
pub type Ptptshr = crate::Reg<ptptshr::PtptshrSpec>;
#[doc = "Ethernet PTP time stamp high register"]
pub mod ptptshr;
#[doc = "PTPTSLR (r) register accessor: Ethernet PTP time stamp low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptslr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptptslr`]
module"]
#[doc(alias = "PTPTSLR")]
pub type Ptptslr = crate::Reg<ptptslr::PtptslrSpec>;
#[doc = "Ethernet PTP time stamp low register"]
pub mod ptptslr;
#[doc = "PTPTSHUR (rw) register accessor: Ethernet PTP time stamp high update register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptshur::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptshur::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptptshur`]
module"]
#[doc(alias = "PTPTSHUR")]
pub type Ptptshur = crate::Reg<ptptshur::PtptshurSpec>;
#[doc = "Ethernet PTP time stamp high update register"]
pub mod ptptshur;
#[doc = "PTPTSLUR (rw) register accessor: Ethernet PTP time stamp low update register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptslur::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptslur::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptptslur`]
module"]
#[doc(alias = "PTPTSLUR")]
pub type Ptptslur = crate::Reg<ptptslur::PtptslurSpec>;
#[doc = "Ethernet PTP time stamp low update register"]
pub mod ptptslur;
#[doc = "PTPTSAR (rw) register accessor: Ethernet PTP time stamp addend register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptsar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptsar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptptsar`]
module"]
#[doc(alias = "PTPTSAR")]
pub type Ptptsar = crate::Reg<ptptsar::PtptsarSpec>;
#[doc = "Ethernet PTP time stamp addend register"]
pub mod ptptsar;
#[doc = "PTPTTHR (rw) register accessor: Ethernet PTP target time high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptthr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptthr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptptthr`]
module"]
#[doc(alias = "PTPTTHR")]
pub type Ptptthr = crate::Reg<ptptthr::PtptthrSpec>;
#[doc = "Ethernet PTP target time high register"]
pub mod ptptthr;
#[doc = "PTPTTLR (rw) register accessor: Ethernet PTP target time low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptpttlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptpttlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptpttlr`]
module"]
#[doc(alias = "PTPTTLR")]
pub type Ptpttlr = crate::Reg<ptpttlr::PtpttlrSpec>;
#[doc = "Ethernet PTP target time low register"]
pub mod ptpttlr;
#[doc = "PTPTSSR (r) register accessor: Ethernet PTP time stamp status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptssr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptptssr`]
module"]
#[doc(alias = "PTPTSSR")]
pub type Ptptssr = crate::Reg<ptptssr::PtptssrSpec>;
#[doc = "Ethernet PTP time stamp status register"]
pub mod ptptssr;
#[doc = "PTPPPSCR (r) register accessor: Ethernet PTP PPS control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptpppscr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ptpppscr`]
module"]
#[doc(alias = "PTPPPSCR")]
pub type Ptpppscr = crate::Reg<ptpppscr::PtpppscrSpec>;
#[doc = "Ethernet PTP PPS control register"]
pub mod ptpppscr;
