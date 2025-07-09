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
    clidr: Clidr,
    ctr: Ctr,
    ccsidr: Ccsidr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Cache Level ID register"]
    #[inline(always)]
    pub const fn clidr(&self) -> &Clidr {
        &self.clidr
    }
    #[doc = "0x04 - Cache Type register"]
    #[inline(always)]
    pub const fn ctr(&self) -> &Ctr {
        &self.ctr
    }
    #[doc = "0x08 - Cache Size ID register"]
    #[inline(always)]
    pub const fn ccsidr(&self) -> &Ccsidr {
        &self.ccsidr
    }
}
#[doc = "CLIDR (r) register accessor: Cache Level ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clidr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@clidr`]
module"]
#[doc(alias = "CLIDR")]
pub type Clidr = crate::Reg<clidr::ClidrSpec>;
#[doc = "Cache Level ID register"]
pub mod clidr;
#[doc = "CTR (r) register accessor: Cache Type register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctr`]
module"]
#[doc(alias = "CTR")]
pub type Ctr = crate::Reg<ctr::CtrSpec>;
#[doc = "Cache Type register"]
pub mod ctr;
#[doc = "CCSIDR (r) register accessor: Cache Size ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccsidr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ccsidr`]
module"]
#[doc(alias = "CCSIDR")]
pub type Ccsidr = crate::Reg<ccsidr::CcsidrSpec>;
#[doc = "Cache Size ID register"]
pub mod ccsidr;
