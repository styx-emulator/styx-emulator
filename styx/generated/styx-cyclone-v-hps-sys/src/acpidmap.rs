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
    vid2rd: Vid2rd,
    vid2wr: Vid2wr,
    vid3rd: Vid3rd,
    vid3wr: Vid3wr,
    vid4rd: Vid4rd,
    vid4wr: Vid4wr,
    vid5rd: Vid5rd,
    vid5wr: Vid5wr,
    vid6rd: Vid6rd,
    vid6wr: Vid6wr,
    dynrd: Dynrd,
    dynwr: Dynwr,
    vid2rd_s: Vid2rdS,
    vid2wr_s: Vid2wrS,
    vid3rd_s: Vid3rdS,
    vid3wr_s: Vid3wrS,
    vid4rd_s: Vid4rdS,
    vid4wr_s: Vid4wrS,
    vid5rd_s: Vid5rdS,
    vid5wr_s: Vid5wrS,
    vid6rd_s: Vid6rdS,
    vid6wr_s: Vid6wrS,
    dynrd_s: DynrdS,
    dynwr_s: DynwrS,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid2rd(&self) -> &Vid2rd {
        &self.vid2rd
    }
    #[doc = "0x04 - The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid2wr(&self) -> &Vid2wr {
        &self.vid2wr
    }
    #[doc = "0x08 - The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid3rd(&self) -> &Vid3rd {
        &self.vid3rd
    }
    #[doc = "0x0c - The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid3wr(&self) -> &Vid3wr {
        &self.vid3wr
    }
    #[doc = "0x10 - The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid4rd(&self) -> &Vid4rd {
        &self.vid4rd
    }
    #[doc = "0x14 - The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid4wr(&self) -> &Vid4wr {
        &self.vid4wr
    }
    #[doc = "0x18 - The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid5rd(&self) -> &Vid5rd {
        &self.vid5rd
    }
    #[doc = "0x1c - The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid5wr(&self) -> &Vid5wr {
        &self.vid5wr
    }
    #[doc = "0x20 - The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid6rd(&self) -> &Vid6rd {
        &self.vid6rd
    }
    #[doc = "0x24 - The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid6wr(&self) -> &Vid6wr {
        &self.vid6wr
    }
    #[doc = "0x28 - The Read AXI Master Mapping Register contains the USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs."]
    #[inline(always)]
    pub const fn dynrd(&self) -> &Dynrd {
        &self.dynrd
    }
    #[doc = "0x2c - The Write AXI Master Mapping Register contains the USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs."]
    #[inline(always)]
    pub const fn dynwr(&self) -> &Dynwr {
        &self.dynwr
    }
    #[doc = "0x30 - The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid2rd_s(&self) -> &Vid2rdS {
        &self.vid2rd_s
    }
    #[doc = "0x34 - The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid2wr_s(&self) -> &Vid2wrS {
        &self.vid2wr_s
    }
    #[doc = "0x38 - The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid3rd_s(&self) -> &Vid3rdS {
        &self.vid3rd_s
    }
    #[doc = "0x3c - The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid3wr_s(&self) -> &Vid3wrS {
        &self.vid3wr_s
    }
    #[doc = "0x40 - The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid4rd_s(&self) -> &Vid4rdS {
        &self.vid4rd_s
    }
    #[doc = "0x44 - The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid4wr_s(&self) -> &Vid4wrS {
        &self.vid4wr_s
    }
    #[doc = "0x48 - The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid5rd_s(&self) -> &Vid5rdS {
        &self.vid5rd_s
    }
    #[doc = "0x4c - The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid5wr_s(&self) -> &Vid5wrS {
        &self.vid5wr_s
    }
    #[doc = "0x50 - The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid6rd_s(&self) -> &Vid6rdS {
        &self.vid6rd_s
    }
    #[doc = "0x54 - The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
    #[inline(always)]
    pub const fn vid6wr_s(&self) -> &Vid6wrS {
        &self.vid6wr_s
    }
    #[doc = "0x58 - The Read AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs."]
    #[inline(always)]
    pub const fn dynrd_s(&self) -> &DynrdS {
        &self.dynrd_s
    }
    #[doc = "0x5c - The Write AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs."]
    #[inline(always)]
    pub const fn dynwr_s(&self) -> &DynwrS {
        &self.dynwr_s
    }
}
#[doc = "vid2rd (rw) register accessor: The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid2rd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid2rd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid2rd`]
module"]
#[doc(alias = "vid2rd")]
pub type Vid2rd = crate::Reg<vid2rd::Vid2rdSpec>;
#[doc = "The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid2rd;
#[doc = "vid2wr (rw) register accessor: The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid2wr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid2wr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid2wr`]
module"]
#[doc(alias = "vid2wr")]
pub type Vid2wr = crate::Reg<vid2wr::Vid2wrSpec>;
#[doc = "The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid2wr;
#[doc = "vid3rd (rw) register accessor: The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid3rd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid3rd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid3rd`]
module"]
#[doc(alias = "vid3rd")]
pub type Vid3rd = crate::Reg<vid3rd::Vid3rdSpec>;
#[doc = "The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid3rd;
#[doc = "vid3wr (rw) register accessor: The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid3wr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid3wr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid3wr`]
module"]
#[doc(alias = "vid3wr")]
pub type Vid3wr = crate::Reg<vid3wr::Vid3wrSpec>;
#[doc = "The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid3wr;
#[doc = "vid4rd (rw) register accessor: The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid4rd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid4rd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid4rd`]
module"]
#[doc(alias = "vid4rd")]
pub type Vid4rd = crate::Reg<vid4rd::Vid4rdSpec>;
#[doc = "The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid4rd;
#[doc = "vid4wr (rw) register accessor: The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid4wr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid4wr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid4wr`]
module"]
#[doc(alias = "vid4wr")]
pub type Vid4wr = crate::Reg<vid4wr::Vid4wrSpec>;
#[doc = "The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid4wr;
#[doc = "vid5rd (rw) register accessor: The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid5rd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid5rd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid5rd`]
module"]
#[doc(alias = "vid5rd")]
pub type Vid5rd = crate::Reg<vid5rd::Vid5rdSpec>;
#[doc = "The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid5rd;
#[doc = "vid5wr (rw) register accessor: The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid5wr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid5wr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid5wr`]
module"]
#[doc(alias = "vid5wr")]
pub type Vid5wr = crate::Reg<vid5wr::Vid5wrSpec>;
#[doc = "The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid5wr;
#[doc = "vid6rd (rw) register accessor: The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid6rd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid6rd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid6rd`]
module"]
#[doc(alias = "vid6rd")]
pub type Vid6rd = crate::Reg<vid6rd::Vid6rdSpec>;
#[doc = "The Read AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid6rd;
#[doc = "vid6wr (rw) register accessor: The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid6wr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vid6wr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid6wr`]
module"]
#[doc(alias = "vid6wr")]
pub type Vid6wr = crate::Reg<vid6wr::Vid6wrSpec>;
#[doc = "The Write AXI Master Mapping Register contains the USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid6wr;
#[doc = "dynrd (rw) register accessor: The Read AXI Master Mapping Register contains the USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dynrd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dynrd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dynrd`]
module"]
#[doc(alias = "dynrd")]
pub type Dynrd = crate::Reg<dynrd::DynrdSpec>;
#[doc = "The Read AXI Master Mapping Register contains the USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs."]
pub mod dynrd;
#[doc = "dynwr (rw) register accessor: The Write AXI Master Mapping Register contains the USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dynwr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dynwr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dynwr`]
module"]
#[doc(alias = "dynwr")]
pub type Dynwr = crate::Reg<dynwr::DynwrSpec>;
#[doc = "The Write AXI Master Mapping Register contains the USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs."]
pub mod dynwr;
#[doc = "vid2rd_s (r) register accessor: The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid2rd_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid2rd_s`]
module"]
#[doc(alias = "vid2rd_s")]
pub type Vid2rdS = crate::Reg<vid2rd_s::Vid2rdSSpec>;
#[doc = "The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid2rd_s;
#[doc = "vid2wr_s (r) register accessor: The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid2wr_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid2wr_s`]
module"]
#[doc(alias = "vid2wr_s")]
pub type Vid2wrS = crate::Reg<vid2wr_s::Vid2wrSSpec>;
#[doc = "The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid2wr_s;
#[doc = "vid3rd_s (r) register accessor: The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid3rd_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid3rd_s`]
module"]
#[doc(alias = "vid3rd_s")]
pub type Vid3rdS = crate::Reg<vid3rd_s::Vid3rdSSpec>;
#[doc = "The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid3rd_s;
#[doc = "vid3wr_s (r) register accessor: The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid3wr_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid3wr_s`]
module"]
#[doc(alias = "vid3wr_s")]
pub type Vid3wrS = crate::Reg<vid3wr_s::Vid3wrSSpec>;
#[doc = "The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid3wr_s;
#[doc = "vid4rd_s (r) register accessor: The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid4rd_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid4rd_s`]
module"]
#[doc(alias = "vid4rd_s")]
pub type Vid4rdS = crate::Reg<vid4rd_s::Vid4rdSSpec>;
#[doc = "The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid4rd_s;
#[doc = "vid4wr_s (r) register accessor: The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid4wr_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid4wr_s`]
module"]
#[doc(alias = "vid4wr_s")]
pub type Vid4wrS = crate::Reg<vid4wr_s::Vid4wrSSpec>;
#[doc = "The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid4wr_s;
#[doc = "vid5rd_s (r) register accessor: The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid5rd_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid5rd_s`]
module"]
#[doc(alias = "vid5rd_s")]
pub type Vid5rdS = crate::Reg<vid5rd_s::Vid5rdSSpec>;
#[doc = "The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid5rd_s;
#[doc = "vid5wr_s (r) register accessor: The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid5wr_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid5wr_s`]
module"]
#[doc(alias = "vid5wr_s")]
pub type Vid5wrS = crate::Reg<vid5wr_s::Vid5wrSSpec>;
#[doc = "The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid5wr_s;
#[doc = "vid6rd_s (r) register accessor: The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid6rd_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid6rd_s`]
module"]
#[doc(alias = "vid6rd_s")]
pub type Vid6rdS = crate::Reg<vid6rd_s::Vid6rdSSpec>;
#[doc = "The Read AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid6rd_s;
#[doc = "vid6wr_s (r) register accessor: The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vid6wr_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vid6wr_s`]
module"]
#[doc(alias = "vid6wr_s")]
pub type Vid6wrS = crate::Reg<vid6wr_s::Vid6wrSSpec>;
#[doc = "The Write AXI Master Mapping Status Register contains the configured USER, ADDR page, and ID signals mapping values for particular transaction with 12-bit ID which locks the fixed 3-bit virtual ID."]
pub mod vid6wr_s;
#[doc = "dynrd_s (r) register accessor: The Read AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dynrd_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dynrd_s`]
module"]
#[doc(alias = "dynrd_s")]
pub type DynrdS = crate::Reg<dynrd_s::DynrdSSpec>;
#[doc = "The Read AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs."]
pub mod dynrd_s;
#[doc = "dynwr_s (r) register accessor: The Write AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dynwr_s::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dynwr_s`]
module"]
#[doc(alias = "dynwr_s")]
pub type DynwrS = crate::Reg<dynwr_s::DynwrSSpec>;
#[doc = "The Write AXI Master Mapping Status Register contains the configured USER, and ADDR page signals mapping values for transaction that dynamically remapped to one of the available 3-bit virtual IDs."]
pub mod dynwr_s;
