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
    iser0: Iser0,
    iser1: Iser1,
    iser2: Iser2,
    _reserved3: [u8; 0x74],
    icer0: Icer0,
    icer1: Icer1,
    icer2: Icer2,
    _reserved6: [u8; 0x74],
    ispr0: Ispr0,
    ispr1: Ispr1,
    ispr2: Ispr2,
    _reserved9: [u8; 0x74],
    icpr0: Icpr0,
    icpr1: Icpr1,
    icpr2: Icpr2,
    _reserved12: [u8; 0x74],
    iabr0: Iabr0,
    iabr1: Iabr1,
    iabr2: Iabr2,
    _reserved15: [u8; 0xf4],
    ipr0: Ipr0,
    ipr1: Ipr1,
    ipr2: Ipr2,
    ipr3: Ipr3,
    ipr4: Ipr4,
    ipr5: Ipr5,
    ipr6: Ipr6,
    ipr7: Ipr7,
    ipr8: Ipr8,
    ipr9: Ipr9,
    ipr10: Ipr10,
    ipr11: Ipr11,
    ipr12: Ipr12,
    ipr13: Ipr13,
    ipr14: Ipr14,
    ipr15: Ipr15,
    ipr16: Ipr16,
    ipr17: Ipr17,
    ipr18: Ipr18,
    ipr19: Ipr19,
    ipr20: Ipr20,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Interrupt Set-Enable Register"]
    #[inline(always)]
    pub const fn iser0(&self) -> &Iser0 {
        &self.iser0
    }
    #[doc = "0x04 - Interrupt Set-Enable Register"]
    #[inline(always)]
    pub const fn iser1(&self) -> &Iser1 {
        &self.iser1
    }
    #[doc = "0x08 - Interrupt Set-Enable Register"]
    #[inline(always)]
    pub const fn iser2(&self) -> &Iser2 {
        &self.iser2
    }
    #[doc = "0x80 - Interrupt Clear-Enable Register"]
    #[inline(always)]
    pub const fn icer0(&self) -> &Icer0 {
        &self.icer0
    }
    #[doc = "0x84 - Interrupt Clear-Enable Register"]
    #[inline(always)]
    pub const fn icer1(&self) -> &Icer1 {
        &self.icer1
    }
    #[doc = "0x88 - Interrupt Clear-Enable Register"]
    #[inline(always)]
    pub const fn icer2(&self) -> &Icer2 {
        &self.icer2
    }
    #[doc = "0x100 - Interrupt Set-Pending Register"]
    #[inline(always)]
    pub const fn ispr0(&self) -> &Ispr0 {
        &self.ispr0
    }
    #[doc = "0x104 - Interrupt Set-Pending Register"]
    #[inline(always)]
    pub const fn ispr1(&self) -> &Ispr1 {
        &self.ispr1
    }
    #[doc = "0x108 - Interrupt Set-Pending Register"]
    #[inline(always)]
    pub const fn ispr2(&self) -> &Ispr2 {
        &self.ispr2
    }
    #[doc = "0x180 - Interrupt Clear-Pending Register"]
    #[inline(always)]
    pub const fn icpr0(&self) -> &Icpr0 {
        &self.icpr0
    }
    #[doc = "0x184 - Interrupt Clear-Pending Register"]
    #[inline(always)]
    pub const fn icpr1(&self) -> &Icpr1 {
        &self.icpr1
    }
    #[doc = "0x188 - Interrupt Clear-Pending Register"]
    #[inline(always)]
    pub const fn icpr2(&self) -> &Icpr2 {
        &self.icpr2
    }
    #[doc = "0x200 - Interrupt Active Bit Register"]
    #[inline(always)]
    pub const fn iabr0(&self) -> &Iabr0 {
        &self.iabr0
    }
    #[doc = "0x204 - Interrupt Active Bit Register"]
    #[inline(always)]
    pub const fn iabr1(&self) -> &Iabr1 {
        &self.iabr1
    }
    #[doc = "0x208 - Interrupt Active Bit Register"]
    #[inline(always)]
    pub const fn iabr2(&self) -> &Iabr2 {
        &self.iabr2
    }
    #[doc = "0x300 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr0(&self) -> &Ipr0 {
        &self.ipr0
    }
    #[doc = "0x304 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr1(&self) -> &Ipr1 {
        &self.ipr1
    }
    #[doc = "0x308 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr2(&self) -> &Ipr2 {
        &self.ipr2
    }
    #[doc = "0x30c - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr3(&self) -> &Ipr3 {
        &self.ipr3
    }
    #[doc = "0x310 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr4(&self) -> &Ipr4 {
        &self.ipr4
    }
    #[doc = "0x314 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr5(&self) -> &Ipr5 {
        &self.ipr5
    }
    #[doc = "0x318 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr6(&self) -> &Ipr6 {
        &self.ipr6
    }
    #[doc = "0x31c - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr7(&self) -> &Ipr7 {
        &self.ipr7
    }
    #[doc = "0x320 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr8(&self) -> &Ipr8 {
        &self.ipr8
    }
    #[doc = "0x324 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr9(&self) -> &Ipr9 {
        &self.ipr9
    }
    #[doc = "0x328 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr10(&self) -> &Ipr10 {
        &self.ipr10
    }
    #[doc = "0x32c - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr11(&self) -> &Ipr11 {
        &self.ipr11
    }
    #[doc = "0x330 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr12(&self) -> &Ipr12 {
        &self.ipr12
    }
    #[doc = "0x334 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr13(&self) -> &Ipr13 {
        &self.ipr13
    }
    #[doc = "0x338 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr14(&self) -> &Ipr14 {
        &self.ipr14
    }
    #[doc = "0x33c - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr15(&self) -> &Ipr15 {
        &self.ipr15
    }
    #[doc = "0x340 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr16(&self) -> &Ipr16 {
        &self.ipr16
    }
    #[doc = "0x344 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr17(&self) -> &Ipr17 {
        &self.ipr17
    }
    #[doc = "0x348 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr18(&self) -> &Ipr18 {
        &self.ipr18
    }
    #[doc = "0x34c - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr19(&self) -> &Ipr19 {
        &self.ipr19
    }
    #[doc = "0x350 - Interrupt Priority Register"]
    #[inline(always)]
    pub const fn ipr20(&self) -> &Ipr20 {
        &self.ipr20
    }
}
#[doc = "ISER0 (rw) register accessor: Interrupt Set-Enable Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iser0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iser0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iser0`]
module"]
#[doc(alias = "ISER0")]
pub type Iser0 = crate::Reg<iser0::Iser0Spec>;
#[doc = "Interrupt Set-Enable Register"]
pub mod iser0;
#[doc = "ISER1 (rw) register accessor: Interrupt Set-Enable Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iser1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iser1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iser1`]
module"]
#[doc(alias = "ISER1")]
pub type Iser1 = crate::Reg<iser1::Iser1Spec>;
#[doc = "Interrupt Set-Enable Register"]
pub mod iser1;
#[doc = "ISER2 (rw) register accessor: Interrupt Set-Enable Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iser2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iser2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iser2`]
module"]
#[doc(alias = "ISER2")]
pub type Iser2 = crate::Reg<iser2::Iser2Spec>;
#[doc = "Interrupt Set-Enable Register"]
pub mod iser2;
#[doc = "ICER0 (rw) register accessor: Interrupt Clear-Enable Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icer0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icer0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icer0`]
module"]
#[doc(alias = "ICER0")]
pub type Icer0 = crate::Reg<icer0::Icer0Spec>;
#[doc = "Interrupt Clear-Enable Register"]
pub mod icer0;
#[doc = "ICER1 (rw) register accessor: Interrupt Clear-Enable Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icer1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icer1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icer1`]
module"]
#[doc(alias = "ICER1")]
pub type Icer1 = crate::Reg<icer1::Icer1Spec>;
#[doc = "Interrupt Clear-Enable Register"]
pub mod icer1;
#[doc = "ICER2 (rw) register accessor: Interrupt Clear-Enable Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icer2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icer2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icer2`]
module"]
#[doc(alias = "ICER2")]
pub type Icer2 = crate::Reg<icer2::Icer2Spec>;
#[doc = "Interrupt Clear-Enable Register"]
pub mod icer2;
#[doc = "ISPR0 (rw) register accessor: Interrupt Set-Pending Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ispr0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ispr0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ispr0`]
module"]
#[doc(alias = "ISPR0")]
pub type Ispr0 = crate::Reg<ispr0::Ispr0Spec>;
#[doc = "Interrupt Set-Pending Register"]
pub mod ispr0;
#[doc = "ISPR1 (rw) register accessor: Interrupt Set-Pending Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ispr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ispr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ispr1`]
module"]
#[doc(alias = "ISPR1")]
pub type Ispr1 = crate::Reg<ispr1::Ispr1Spec>;
#[doc = "Interrupt Set-Pending Register"]
pub mod ispr1;
#[doc = "ISPR2 (rw) register accessor: Interrupt Set-Pending Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ispr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ispr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ispr2`]
module"]
#[doc(alias = "ISPR2")]
pub type Ispr2 = crate::Reg<ispr2::Ispr2Spec>;
#[doc = "Interrupt Set-Pending Register"]
pub mod ispr2;
#[doc = "ICPR0 (rw) register accessor: Interrupt Clear-Pending Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icpr0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icpr0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icpr0`]
module"]
#[doc(alias = "ICPR0")]
pub type Icpr0 = crate::Reg<icpr0::Icpr0Spec>;
#[doc = "Interrupt Clear-Pending Register"]
pub mod icpr0;
#[doc = "ICPR1 (rw) register accessor: Interrupt Clear-Pending Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icpr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icpr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icpr1`]
module"]
#[doc(alias = "ICPR1")]
pub type Icpr1 = crate::Reg<icpr1::Icpr1Spec>;
#[doc = "Interrupt Clear-Pending Register"]
pub mod icpr1;
#[doc = "ICPR2 (rw) register accessor: Interrupt Clear-Pending Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icpr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icpr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icpr2`]
module"]
#[doc(alias = "ICPR2")]
pub type Icpr2 = crate::Reg<icpr2::Icpr2Spec>;
#[doc = "Interrupt Clear-Pending Register"]
pub mod icpr2;
#[doc = "IABR0 (r) register accessor: Interrupt Active Bit Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iabr0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iabr0`]
module"]
#[doc(alias = "IABR0")]
pub type Iabr0 = crate::Reg<iabr0::Iabr0Spec>;
#[doc = "Interrupt Active Bit Register"]
pub mod iabr0;
#[doc = "IABR1 (r) register accessor: Interrupt Active Bit Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iabr1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iabr1`]
module"]
#[doc(alias = "IABR1")]
pub type Iabr1 = crate::Reg<iabr1::Iabr1Spec>;
#[doc = "Interrupt Active Bit Register"]
pub mod iabr1;
#[doc = "IABR2 (r) register accessor: Interrupt Active Bit Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iabr2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iabr2`]
module"]
#[doc(alias = "IABR2")]
pub type Iabr2 = crate::Reg<iabr2::Iabr2Spec>;
#[doc = "Interrupt Active Bit Register"]
pub mod iabr2;
#[doc = "IPR0 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr0`]
module"]
#[doc(alias = "IPR0")]
pub type Ipr0 = crate::Reg<ipr0::Ipr0Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr0;
#[doc = "IPR1 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr1`]
module"]
#[doc(alias = "IPR1")]
pub type Ipr1 = crate::Reg<ipr1::Ipr1Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr1;
#[doc = "IPR2 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr2`]
module"]
#[doc(alias = "IPR2")]
pub type Ipr2 = crate::Reg<ipr2::Ipr2Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr2;
#[doc = "IPR3 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr3`]
module"]
#[doc(alias = "IPR3")]
pub type Ipr3 = crate::Reg<ipr3::Ipr3Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr3;
#[doc = "IPR4 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr4`]
module"]
#[doc(alias = "IPR4")]
pub type Ipr4 = crate::Reg<ipr4::Ipr4Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr4;
#[doc = "IPR5 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr5`]
module"]
#[doc(alias = "IPR5")]
pub type Ipr5 = crate::Reg<ipr5::Ipr5Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr5;
#[doc = "IPR6 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr6`]
module"]
#[doc(alias = "IPR6")]
pub type Ipr6 = crate::Reg<ipr6::Ipr6Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr6;
#[doc = "IPR7 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr7`]
module"]
#[doc(alias = "IPR7")]
pub type Ipr7 = crate::Reg<ipr7::Ipr7Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr7;
#[doc = "IPR8 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr8`]
module"]
#[doc(alias = "IPR8")]
pub type Ipr8 = crate::Reg<ipr8::Ipr8Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr8;
#[doc = "IPR9 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr9`]
module"]
#[doc(alias = "IPR9")]
pub type Ipr9 = crate::Reg<ipr9::Ipr9Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr9;
#[doc = "IPR10 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr10`]
module"]
#[doc(alias = "IPR10")]
pub type Ipr10 = crate::Reg<ipr10::Ipr10Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr10;
#[doc = "IPR11 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr11`]
module"]
#[doc(alias = "IPR11")]
pub type Ipr11 = crate::Reg<ipr11::Ipr11Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr11;
#[doc = "IPR12 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr12`]
module"]
#[doc(alias = "IPR12")]
pub type Ipr12 = crate::Reg<ipr12::Ipr12Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr12;
#[doc = "IPR13 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr13`]
module"]
#[doc(alias = "IPR13")]
pub type Ipr13 = crate::Reg<ipr13::Ipr13Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr13;
#[doc = "IPR14 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr14`]
module"]
#[doc(alias = "IPR14")]
pub type Ipr14 = crate::Reg<ipr14::Ipr14Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr14;
#[doc = "IPR15 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr15`]
module"]
#[doc(alias = "IPR15")]
pub type Ipr15 = crate::Reg<ipr15::Ipr15Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr15;
#[doc = "IPR16 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr16::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr16::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr16`]
module"]
#[doc(alias = "IPR16")]
pub type Ipr16 = crate::Reg<ipr16::Ipr16Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr16;
#[doc = "IPR17 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr17::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr17::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr17`]
module"]
#[doc(alias = "IPR17")]
pub type Ipr17 = crate::Reg<ipr17::Ipr17Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr17;
#[doc = "IPR18 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr18::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr18::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr18`]
module"]
#[doc(alias = "IPR18")]
pub type Ipr18 = crate::Reg<ipr18::Ipr18Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr18;
#[doc = "IPR19 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr19::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr19::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr19`]
module"]
#[doc(alias = "IPR19")]
pub type Ipr19 = crate::Reg<ipr19::Ipr19Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr19;
#[doc = "IPR20 (rw) register accessor: Interrupt Priority Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ipr20::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ipr20::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ipr20`]
module"]
#[doc(alias = "IPR20")]
pub type Ipr20 = crate::Reg<ipr20::Ipr20Spec>;
#[doc = "Interrupt Priority Register"]
pub mod ipr20;
