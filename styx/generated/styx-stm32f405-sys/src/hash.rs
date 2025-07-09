// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    cr: Cr,
    din: Din,
    str: Str,
    hr0: Hr0,
    hr1: Hr1,
    hr2: Hr2,
    hr3: Hr3,
    hr4: Hr4,
    imr: Imr,
    sr: Sr,
    _reserved10: [u8; 0xd0],
    csr0: Csr0,
    csr1: Csr1,
    csr2: Csr2,
    csr3: Csr3,
    csr4: Csr4,
    csr5: Csr5,
    csr6: Csr6,
    csr7: Csr7,
    csr8: Csr8,
    csr9: Csr9,
    csr10: Csr10,
    csr11: Csr11,
    csr12: Csr12,
    csr13: Csr13,
    csr14: Csr14,
    csr15: Csr15,
    csr16: Csr16,
    csr17: Csr17,
    csr18: Csr18,
    csr19: Csr19,
    csr20: Csr20,
    csr21: Csr21,
    csr22: Csr22,
    csr23: Csr23,
    csr24: Csr24,
    csr25: Csr25,
    csr26: Csr26,
    csr27: Csr27,
    csr28: Csr28,
    csr29: Csr29,
    csr30: Csr30,
    csr31: Csr31,
    csr32: Csr32,
    csr33: Csr33,
    csr34: Csr34,
    csr35: Csr35,
    csr36: Csr36,
    csr37: Csr37,
    csr38: Csr38,
    csr39: Csr39,
    csr40: Csr40,
    csr41: Csr41,
    csr42: Csr42,
    csr43: Csr43,
    csr44: Csr44,
    csr45: Csr45,
    csr46: Csr46,
    csr47: Csr47,
    csr48: Csr48,
    csr49: Csr49,
    csr50: Csr50,
    csr51: Csr51,
    csr52: Csr52,
    csr53: Csr53,
    _reserved64: [u8; 0x0140],
    hash_hr0: HashHr0,
    hash_hr1: HashHr1,
    hash_hr2: HashHr2,
    hash_hr3: HashHr3,
    hash_hr4: HashHr4,
    hash_hr5: HashHr5,
    hash_hr6: HashHr6,
    hash_hr7: HashHr7,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - control register"]
    #[inline(always)]
    pub const fn cr(&self) -> &Cr {
        &self.cr
    }
    #[doc = "0x04 - data input register"]
    #[inline(always)]
    pub const fn din(&self) -> &Din {
        &self.din
    }
    #[doc = "0x08 - start register"]
    #[inline(always)]
    pub const fn str(&self) -> &Str {
        &self.str
    }
    #[doc = "0x0c - digest registers"]
    #[inline(always)]
    pub const fn hr0(&self) -> &Hr0 {
        &self.hr0
    }
    #[doc = "0x10 - digest registers"]
    #[inline(always)]
    pub const fn hr1(&self) -> &Hr1 {
        &self.hr1
    }
    #[doc = "0x14 - digest registers"]
    #[inline(always)]
    pub const fn hr2(&self) -> &Hr2 {
        &self.hr2
    }
    #[doc = "0x18 - digest registers"]
    #[inline(always)]
    pub const fn hr3(&self) -> &Hr3 {
        &self.hr3
    }
    #[doc = "0x1c - digest registers"]
    #[inline(always)]
    pub const fn hr4(&self) -> &Hr4 {
        &self.hr4
    }
    #[doc = "0x20 - interrupt enable register"]
    #[inline(always)]
    pub const fn imr(&self) -> &Imr {
        &self.imr
    }
    #[doc = "0x24 - status register"]
    #[inline(always)]
    pub const fn sr(&self) -> &Sr {
        &self.sr
    }
    #[doc = "0xf8 - context swap registers"]
    #[inline(always)]
    pub const fn csr0(&self) -> &Csr0 {
        &self.csr0
    }
    #[doc = "0xfc - context swap registers"]
    #[inline(always)]
    pub const fn csr1(&self) -> &Csr1 {
        &self.csr1
    }
    #[doc = "0x100 - context swap registers"]
    #[inline(always)]
    pub const fn csr2(&self) -> &Csr2 {
        &self.csr2
    }
    #[doc = "0x104 - context swap registers"]
    #[inline(always)]
    pub const fn csr3(&self) -> &Csr3 {
        &self.csr3
    }
    #[doc = "0x108 - context swap registers"]
    #[inline(always)]
    pub const fn csr4(&self) -> &Csr4 {
        &self.csr4
    }
    #[doc = "0x10c - context swap registers"]
    #[inline(always)]
    pub const fn csr5(&self) -> &Csr5 {
        &self.csr5
    }
    #[doc = "0x110 - context swap registers"]
    #[inline(always)]
    pub const fn csr6(&self) -> &Csr6 {
        &self.csr6
    }
    #[doc = "0x114 - context swap registers"]
    #[inline(always)]
    pub const fn csr7(&self) -> &Csr7 {
        &self.csr7
    }
    #[doc = "0x118 - context swap registers"]
    #[inline(always)]
    pub const fn csr8(&self) -> &Csr8 {
        &self.csr8
    }
    #[doc = "0x11c - context swap registers"]
    #[inline(always)]
    pub const fn csr9(&self) -> &Csr9 {
        &self.csr9
    }
    #[doc = "0x120 - context swap registers"]
    #[inline(always)]
    pub const fn csr10(&self) -> &Csr10 {
        &self.csr10
    }
    #[doc = "0x124 - context swap registers"]
    #[inline(always)]
    pub const fn csr11(&self) -> &Csr11 {
        &self.csr11
    }
    #[doc = "0x128 - context swap registers"]
    #[inline(always)]
    pub const fn csr12(&self) -> &Csr12 {
        &self.csr12
    }
    #[doc = "0x12c - context swap registers"]
    #[inline(always)]
    pub const fn csr13(&self) -> &Csr13 {
        &self.csr13
    }
    #[doc = "0x130 - context swap registers"]
    #[inline(always)]
    pub const fn csr14(&self) -> &Csr14 {
        &self.csr14
    }
    #[doc = "0x134 - context swap registers"]
    #[inline(always)]
    pub const fn csr15(&self) -> &Csr15 {
        &self.csr15
    }
    #[doc = "0x138 - context swap registers"]
    #[inline(always)]
    pub const fn csr16(&self) -> &Csr16 {
        &self.csr16
    }
    #[doc = "0x13c - context swap registers"]
    #[inline(always)]
    pub const fn csr17(&self) -> &Csr17 {
        &self.csr17
    }
    #[doc = "0x140 - context swap registers"]
    #[inline(always)]
    pub const fn csr18(&self) -> &Csr18 {
        &self.csr18
    }
    #[doc = "0x144 - context swap registers"]
    #[inline(always)]
    pub const fn csr19(&self) -> &Csr19 {
        &self.csr19
    }
    #[doc = "0x148 - context swap registers"]
    #[inline(always)]
    pub const fn csr20(&self) -> &Csr20 {
        &self.csr20
    }
    #[doc = "0x14c - context swap registers"]
    #[inline(always)]
    pub const fn csr21(&self) -> &Csr21 {
        &self.csr21
    }
    #[doc = "0x150 - context swap registers"]
    #[inline(always)]
    pub const fn csr22(&self) -> &Csr22 {
        &self.csr22
    }
    #[doc = "0x154 - context swap registers"]
    #[inline(always)]
    pub const fn csr23(&self) -> &Csr23 {
        &self.csr23
    }
    #[doc = "0x158 - context swap registers"]
    #[inline(always)]
    pub const fn csr24(&self) -> &Csr24 {
        &self.csr24
    }
    #[doc = "0x15c - context swap registers"]
    #[inline(always)]
    pub const fn csr25(&self) -> &Csr25 {
        &self.csr25
    }
    #[doc = "0x160 - context swap registers"]
    #[inline(always)]
    pub const fn csr26(&self) -> &Csr26 {
        &self.csr26
    }
    #[doc = "0x164 - context swap registers"]
    #[inline(always)]
    pub const fn csr27(&self) -> &Csr27 {
        &self.csr27
    }
    #[doc = "0x168 - context swap registers"]
    #[inline(always)]
    pub const fn csr28(&self) -> &Csr28 {
        &self.csr28
    }
    #[doc = "0x16c - context swap registers"]
    #[inline(always)]
    pub const fn csr29(&self) -> &Csr29 {
        &self.csr29
    }
    #[doc = "0x170 - context swap registers"]
    #[inline(always)]
    pub const fn csr30(&self) -> &Csr30 {
        &self.csr30
    }
    #[doc = "0x174 - context swap registers"]
    #[inline(always)]
    pub const fn csr31(&self) -> &Csr31 {
        &self.csr31
    }
    #[doc = "0x178 - context swap registers"]
    #[inline(always)]
    pub const fn csr32(&self) -> &Csr32 {
        &self.csr32
    }
    #[doc = "0x17c - context swap registers"]
    #[inline(always)]
    pub const fn csr33(&self) -> &Csr33 {
        &self.csr33
    }
    #[doc = "0x180 - context swap registers"]
    #[inline(always)]
    pub const fn csr34(&self) -> &Csr34 {
        &self.csr34
    }
    #[doc = "0x184 - context swap registers"]
    #[inline(always)]
    pub const fn csr35(&self) -> &Csr35 {
        &self.csr35
    }
    #[doc = "0x188 - context swap registers"]
    #[inline(always)]
    pub const fn csr36(&self) -> &Csr36 {
        &self.csr36
    }
    #[doc = "0x18c - context swap registers"]
    #[inline(always)]
    pub const fn csr37(&self) -> &Csr37 {
        &self.csr37
    }
    #[doc = "0x190 - context swap registers"]
    #[inline(always)]
    pub const fn csr38(&self) -> &Csr38 {
        &self.csr38
    }
    #[doc = "0x194 - context swap registers"]
    #[inline(always)]
    pub const fn csr39(&self) -> &Csr39 {
        &self.csr39
    }
    #[doc = "0x198 - context swap registers"]
    #[inline(always)]
    pub const fn csr40(&self) -> &Csr40 {
        &self.csr40
    }
    #[doc = "0x19c - context swap registers"]
    #[inline(always)]
    pub const fn csr41(&self) -> &Csr41 {
        &self.csr41
    }
    #[doc = "0x1a0 - context swap registers"]
    #[inline(always)]
    pub const fn csr42(&self) -> &Csr42 {
        &self.csr42
    }
    #[doc = "0x1a4 - context swap registers"]
    #[inline(always)]
    pub const fn csr43(&self) -> &Csr43 {
        &self.csr43
    }
    #[doc = "0x1a8 - context swap registers"]
    #[inline(always)]
    pub const fn csr44(&self) -> &Csr44 {
        &self.csr44
    }
    #[doc = "0x1ac - context swap registers"]
    #[inline(always)]
    pub const fn csr45(&self) -> &Csr45 {
        &self.csr45
    }
    #[doc = "0x1b0 - context swap registers"]
    #[inline(always)]
    pub const fn csr46(&self) -> &Csr46 {
        &self.csr46
    }
    #[doc = "0x1b4 - context swap registers"]
    #[inline(always)]
    pub const fn csr47(&self) -> &Csr47 {
        &self.csr47
    }
    #[doc = "0x1b8 - context swap registers"]
    #[inline(always)]
    pub const fn csr48(&self) -> &Csr48 {
        &self.csr48
    }
    #[doc = "0x1bc - context swap registers"]
    #[inline(always)]
    pub const fn csr49(&self) -> &Csr49 {
        &self.csr49
    }
    #[doc = "0x1c0 - context swap registers"]
    #[inline(always)]
    pub const fn csr50(&self) -> &Csr50 {
        &self.csr50
    }
    #[doc = "0x1c4 - context swap registers"]
    #[inline(always)]
    pub const fn csr51(&self) -> &Csr51 {
        &self.csr51
    }
    #[doc = "0x1c8 - context swap registers"]
    #[inline(always)]
    pub const fn csr52(&self) -> &Csr52 {
        &self.csr52
    }
    #[doc = "0x1cc - context swap registers"]
    #[inline(always)]
    pub const fn csr53(&self) -> &Csr53 {
        &self.csr53
    }
    #[doc = "0x310 - HASH digest register"]
    #[inline(always)]
    pub const fn hash_hr0(&self) -> &HashHr0 {
        &self.hash_hr0
    }
    #[doc = "0x314 - read-only"]
    #[inline(always)]
    pub const fn hash_hr1(&self) -> &HashHr1 {
        &self.hash_hr1
    }
    #[doc = "0x318 - read-only"]
    #[inline(always)]
    pub const fn hash_hr2(&self) -> &HashHr2 {
        &self.hash_hr2
    }
    #[doc = "0x31c - read-only"]
    #[inline(always)]
    pub const fn hash_hr3(&self) -> &HashHr3 {
        &self.hash_hr3
    }
    #[doc = "0x320 - read-only"]
    #[inline(always)]
    pub const fn hash_hr4(&self) -> &HashHr4 {
        &self.hash_hr4
    }
    #[doc = "0x324 - read-only"]
    #[inline(always)]
    pub const fn hash_hr5(&self) -> &HashHr5 {
        &self.hash_hr5
    }
    #[doc = "0x328 - read-only"]
    #[inline(always)]
    pub const fn hash_hr6(&self) -> &HashHr6 {
        &self.hash_hr6
    }
    #[doc = "0x32c - read-only"]
    #[inline(always)]
    pub const fn hash_hr7(&self) -> &HashHr7 {
        &self.hash_hr7
    }
}
#[doc = "CR (rw) register accessor: control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr`]
module"]
#[doc(alias = "CR")]
pub type Cr = crate::Reg<cr::CrSpec>;
#[doc = "control register"]
pub mod cr;
#[doc = "DIN (rw) register accessor: data input register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`din::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`din::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@din`]
module"]
#[doc(alias = "DIN")]
pub type Din = crate::Reg<din::DinSpec>;
#[doc = "data input register"]
pub mod din;
#[doc = "STR (rw) register accessor: start register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`str::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`str::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@str`]
module"]
#[doc(alias = "STR")]
pub type Str = crate::Reg<str::StrSpec>;
#[doc = "start register"]
pub mod str;
#[doc = "HR0 (r) register accessor: digest registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hr0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hr0`]
module"]
#[doc(alias = "HR0")]
pub type Hr0 = crate::Reg<hr0::Hr0Spec>;
#[doc = "digest registers"]
pub mod hr0;
#[doc = "HR1 (r) register accessor: digest registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hr1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hr1`]
module"]
#[doc(alias = "HR1")]
pub type Hr1 = crate::Reg<hr1::Hr1Spec>;
#[doc = "digest registers"]
pub mod hr1;
#[doc = "HR2 (r) register accessor: digest registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hr2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hr2`]
module"]
#[doc(alias = "HR2")]
pub type Hr2 = crate::Reg<hr2::Hr2Spec>;
#[doc = "digest registers"]
pub mod hr2;
#[doc = "HR3 (r) register accessor: digest registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hr3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hr3`]
module"]
#[doc(alias = "HR3")]
pub type Hr3 = crate::Reg<hr3::Hr3Spec>;
#[doc = "digest registers"]
pub mod hr3;
#[doc = "HR4 (r) register accessor: digest registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hr4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hr4`]
module"]
#[doc(alias = "HR4")]
pub type Hr4 = crate::Reg<hr4::Hr4Spec>;
#[doc = "digest registers"]
pub mod hr4;
#[doc = "IMR (rw) register accessor: interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`imr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`imr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@imr`]
module"]
#[doc(alias = "IMR")]
pub type Imr = crate::Reg<imr::ImrSpec>;
#[doc = "interrupt enable register"]
pub mod imr;
#[doc = "SR (rw) register accessor: status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr`]
module"]
#[doc(alias = "SR")]
pub type Sr = crate::Reg<sr::SrSpec>;
#[doc = "status register"]
pub mod sr;
#[doc = "CSR0 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr0`]
module"]
#[doc(alias = "CSR0")]
pub type Csr0 = crate::Reg<csr0::Csr0Spec>;
#[doc = "context swap registers"]
pub mod csr0;
#[doc = "CSR1 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr1`]
module"]
#[doc(alias = "CSR1")]
pub type Csr1 = crate::Reg<csr1::Csr1Spec>;
#[doc = "context swap registers"]
pub mod csr1;
#[doc = "CSR2 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr2`]
module"]
#[doc(alias = "CSR2")]
pub type Csr2 = crate::Reg<csr2::Csr2Spec>;
#[doc = "context swap registers"]
pub mod csr2;
#[doc = "CSR3 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr3`]
module"]
#[doc(alias = "CSR3")]
pub type Csr3 = crate::Reg<csr3::Csr3Spec>;
#[doc = "context swap registers"]
pub mod csr3;
#[doc = "CSR4 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr4`]
module"]
#[doc(alias = "CSR4")]
pub type Csr4 = crate::Reg<csr4::Csr4Spec>;
#[doc = "context swap registers"]
pub mod csr4;
#[doc = "CSR5 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr5`]
module"]
#[doc(alias = "CSR5")]
pub type Csr5 = crate::Reg<csr5::Csr5Spec>;
#[doc = "context swap registers"]
pub mod csr5;
#[doc = "CSR6 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr6`]
module"]
#[doc(alias = "CSR6")]
pub type Csr6 = crate::Reg<csr6::Csr6Spec>;
#[doc = "context swap registers"]
pub mod csr6;
#[doc = "CSR7 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr7`]
module"]
#[doc(alias = "CSR7")]
pub type Csr7 = crate::Reg<csr7::Csr7Spec>;
#[doc = "context swap registers"]
pub mod csr7;
#[doc = "CSR8 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr8`]
module"]
#[doc(alias = "CSR8")]
pub type Csr8 = crate::Reg<csr8::Csr8Spec>;
#[doc = "context swap registers"]
pub mod csr8;
#[doc = "CSR9 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr9`]
module"]
#[doc(alias = "CSR9")]
pub type Csr9 = crate::Reg<csr9::Csr9Spec>;
#[doc = "context swap registers"]
pub mod csr9;
#[doc = "CSR10 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr10`]
module"]
#[doc(alias = "CSR10")]
pub type Csr10 = crate::Reg<csr10::Csr10Spec>;
#[doc = "context swap registers"]
pub mod csr10;
#[doc = "CSR11 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr11`]
module"]
#[doc(alias = "CSR11")]
pub type Csr11 = crate::Reg<csr11::Csr11Spec>;
#[doc = "context swap registers"]
pub mod csr11;
#[doc = "CSR12 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr12`]
module"]
#[doc(alias = "CSR12")]
pub type Csr12 = crate::Reg<csr12::Csr12Spec>;
#[doc = "context swap registers"]
pub mod csr12;
#[doc = "CSR13 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr13`]
module"]
#[doc(alias = "CSR13")]
pub type Csr13 = crate::Reg<csr13::Csr13Spec>;
#[doc = "context swap registers"]
pub mod csr13;
#[doc = "CSR14 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr14`]
module"]
#[doc(alias = "CSR14")]
pub type Csr14 = crate::Reg<csr14::Csr14Spec>;
#[doc = "context swap registers"]
pub mod csr14;
#[doc = "CSR15 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr15`]
module"]
#[doc(alias = "CSR15")]
pub type Csr15 = crate::Reg<csr15::Csr15Spec>;
#[doc = "context swap registers"]
pub mod csr15;
#[doc = "CSR16 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr16::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr16::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr16`]
module"]
#[doc(alias = "CSR16")]
pub type Csr16 = crate::Reg<csr16::Csr16Spec>;
#[doc = "context swap registers"]
pub mod csr16;
#[doc = "CSR17 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr17::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr17::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr17`]
module"]
#[doc(alias = "CSR17")]
pub type Csr17 = crate::Reg<csr17::Csr17Spec>;
#[doc = "context swap registers"]
pub mod csr17;
#[doc = "CSR18 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr18::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr18::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr18`]
module"]
#[doc(alias = "CSR18")]
pub type Csr18 = crate::Reg<csr18::Csr18Spec>;
#[doc = "context swap registers"]
pub mod csr18;
#[doc = "CSR19 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr19::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr19::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr19`]
module"]
#[doc(alias = "CSR19")]
pub type Csr19 = crate::Reg<csr19::Csr19Spec>;
#[doc = "context swap registers"]
pub mod csr19;
#[doc = "CSR20 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr20::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr20::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr20`]
module"]
#[doc(alias = "CSR20")]
pub type Csr20 = crate::Reg<csr20::Csr20Spec>;
#[doc = "context swap registers"]
pub mod csr20;
#[doc = "CSR21 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr21::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr21::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr21`]
module"]
#[doc(alias = "CSR21")]
pub type Csr21 = crate::Reg<csr21::Csr21Spec>;
#[doc = "context swap registers"]
pub mod csr21;
#[doc = "CSR22 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr22::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr22::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr22`]
module"]
#[doc(alias = "CSR22")]
pub type Csr22 = crate::Reg<csr22::Csr22Spec>;
#[doc = "context swap registers"]
pub mod csr22;
#[doc = "CSR23 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr23::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr23::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr23`]
module"]
#[doc(alias = "CSR23")]
pub type Csr23 = crate::Reg<csr23::Csr23Spec>;
#[doc = "context swap registers"]
pub mod csr23;
#[doc = "CSR24 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr24::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr24::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr24`]
module"]
#[doc(alias = "CSR24")]
pub type Csr24 = crate::Reg<csr24::Csr24Spec>;
#[doc = "context swap registers"]
pub mod csr24;
#[doc = "CSR25 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr25::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr25::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr25`]
module"]
#[doc(alias = "CSR25")]
pub type Csr25 = crate::Reg<csr25::Csr25Spec>;
#[doc = "context swap registers"]
pub mod csr25;
#[doc = "CSR26 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr26::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr26::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr26`]
module"]
#[doc(alias = "CSR26")]
pub type Csr26 = crate::Reg<csr26::Csr26Spec>;
#[doc = "context swap registers"]
pub mod csr26;
#[doc = "CSR27 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr27::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr27::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr27`]
module"]
#[doc(alias = "CSR27")]
pub type Csr27 = crate::Reg<csr27::Csr27Spec>;
#[doc = "context swap registers"]
pub mod csr27;
#[doc = "CSR28 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr28::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr28::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr28`]
module"]
#[doc(alias = "CSR28")]
pub type Csr28 = crate::Reg<csr28::Csr28Spec>;
#[doc = "context swap registers"]
pub mod csr28;
#[doc = "CSR29 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr29::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr29::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr29`]
module"]
#[doc(alias = "CSR29")]
pub type Csr29 = crate::Reg<csr29::Csr29Spec>;
#[doc = "context swap registers"]
pub mod csr29;
#[doc = "CSR30 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr30::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr30::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr30`]
module"]
#[doc(alias = "CSR30")]
pub type Csr30 = crate::Reg<csr30::Csr30Spec>;
#[doc = "context swap registers"]
pub mod csr30;
#[doc = "CSR31 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr31::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr31::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr31`]
module"]
#[doc(alias = "CSR31")]
pub type Csr31 = crate::Reg<csr31::Csr31Spec>;
#[doc = "context swap registers"]
pub mod csr31;
#[doc = "CSR32 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr32::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr32::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr32`]
module"]
#[doc(alias = "CSR32")]
pub type Csr32 = crate::Reg<csr32::Csr32Spec>;
#[doc = "context swap registers"]
pub mod csr32;
#[doc = "CSR33 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr33::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr33::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr33`]
module"]
#[doc(alias = "CSR33")]
pub type Csr33 = crate::Reg<csr33::Csr33Spec>;
#[doc = "context swap registers"]
pub mod csr33;
#[doc = "CSR34 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr34::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr34::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr34`]
module"]
#[doc(alias = "CSR34")]
pub type Csr34 = crate::Reg<csr34::Csr34Spec>;
#[doc = "context swap registers"]
pub mod csr34;
#[doc = "CSR35 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr35::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr35::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr35`]
module"]
#[doc(alias = "CSR35")]
pub type Csr35 = crate::Reg<csr35::Csr35Spec>;
#[doc = "context swap registers"]
pub mod csr35;
#[doc = "CSR36 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr36::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr36::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr36`]
module"]
#[doc(alias = "CSR36")]
pub type Csr36 = crate::Reg<csr36::Csr36Spec>;
#[doc = "context swap registers"]
pub mod csr36;
#[doc = "CSR37 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr37::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr37::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr37`]
module"]
#[doc(alias = "CSR37")]
pub type Csr37 = crate::Reg<csr37::Csr37Spec>;
#[doc = "context swap registers"]
pub mod csr37;
#[doc = "CSR38 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr38::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr38::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr38`]
module"]
#[doc(alias = "CSR38")]
pub type Csr38 = crate::Reg<csr38::Csr38Spec>;
#[doc = "context swap registers"]
pub mod csr38;
#[doc = "CSR39 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr39::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr39::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr39`]
module"]
#[doc(alias = "CSR39")]
pub type Csr39 = crate::Reg<csr39::Csr39Spec>;
#[doc = "context swap registers"]
pub mod csr39;
#[doc = "CSR40 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr40::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr40::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr40`]
module"]
#[doc(alias = "CSR40")]
pub type Csr40 = crate::Reg<csr40::Csr40Spec>;
#[doc = "context swap registers"]
pub mod csr40;
#[doc = "CSR41 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr41::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr41::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr41`]
module"]
#[doc(alias = "CSR41")]
pub type Csr41 = crate::Reg<csr41::Csr41Spec>;
#[doc = "context swap registers"]
pub mod csr41;
#[doc = "CSR42 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr42::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr42::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr42`]
module"]
#[doc(alias = "CSR42")]
pub type Csr42 = crate::Reg<csr42::Csr42Spec>;
#[doc = "context swap registers"]
pub mod csr42;
#[doc = "CSR43 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr43::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr43::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr43`]
module"]
#[doc(alias = "CSR43")]
pub type Csr43 = crate::Reg<csr43::Csr43Spec>;
#[doc = "context swap registers"]
pub mod csr43;
#[doc = "CSR44 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr44::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr44::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr44`]
module"]
#[doc(alias = "CSR44")]
pub type Csr44 = crate::Reg<csr44::Csr44Spec>;
#[doc = "context swap registers"]
pub mod csr44;
#[doc = "CSR45 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr45::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr45::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr45`]
module"]
#[doc(alias = "CSR45")]
pub type Csr45 = crate::Reg<csr45::Csr45Spec>;
#[doc = "context swap registers"]
pub mod csr45;
#[doc = "CSR46 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr46::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr46::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr46`]
module"]
#[doc(alias = "CSR46")]
pub type Csr46 = crate::Reg<csr46::Csr46Spec>;
#[doc = "context swap registers"]
pub mod csr46;
#[doc = "CSR47 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr47::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr47::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr47`]
module"]
#[doc(alias = "CSR47")]
pub type Csr47 = crate::Reg<csr47::Csr47Spec>;
#[doc = "context swap registers"]
pub mod csr47;
#[doc = "CSR48 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr48::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr48::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr48`]
module"]
#[doc(alias = "CSR48")]
pub type Csr48 = crate::Reg<csr48::Csr48Spec>;
#[doc = "context swap registers"]
pub mod csr48;
#[doc = "CSR49 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr49::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr49::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr49`]
module"]
#[doc(alias = "CSR49")]
pub type Csr49 = crate::Reg<csr49::Csr49Spec>;
#[doc = "context swap registers"]
pub mod csr49;
#[doc = "CSR50 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr50::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr50::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr50`]
module"]
#[doc(alias = "CSR50")]
pub type Csr50 = crate::Reg<csr50::Csr50Spec>;
#[doc = "context swap registers"]
pub mod csr50;
#[doc = "CSR51 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr51::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr51::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr51`]
module"]
#[doc(alias = "CSR51")]
pub type Csr51 = crate::Reg<csr51::Csr51Spec>;
#[doc = "context swap registers"]
pub mod csr51;
#[doc = "CSR52 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr52::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr52::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr52`]
module"]
#[doc(alias = "CSR52")]
pub type Csr52 = crate::Reg<csr52::Csr52Spec>;
#[doc = "context swap registers"]
pub mod csr52;
#[doc = "CSR53 (rw) register accessor: context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr53::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr53::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csr53`]
module"]
#[doc(alias = "CSR53")]
pub type Csr53 = crate::Reg<csr53::Csr53Spec>;
#[doc = "context swap registers"]
pub mod csr53;
#[doc = "HASH_HR0 (r) register accessor: HASH digest register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hash_hr0`]
module"]
#[doc(alias = "HASH_HR0")]
pub type HashHr0 = crate::Reg<hash_hr0::HashHr0Spec>;
#[doc = "HASH digest register"]
pub mod hash_hr0;
#[doc = "HASH_HR1 (r) register accessor: read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hash_hr1`]
module"]
#[doc(alias = "HASH_HR1")]
pub type HashHr1 = crate::Reg<hash_hr1::HashHr1Spec>;
#[doc = "read-only"]
pub mod hash_hr1;
#[doc = "HASH_HR2 (r) register accessor: read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hash_hr2`]
module"]
#[doc(alias = "HASH_HR2")]
pub type HashHr2 = crate::Reg<hash_hr2::HashHr2Spec>;
#[doc = "read-only"]
pub mod hash_hr2;
#[doc = "HASH_HR3 (r) register accessor: read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hash_hr3`]
module"]
#[doc(alias = "HASH_HR3")]
pub type HashHr3 = crate::Reg<hash_hr3::HashHr3Spec>;
#[doc = "read-only"]
pub mod hash_hr3;
#[doc = "HASH_HR4 (r) register accessor: read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hash_hr4`]
module"]
#[doc(alias = "HASH_HR4")]
pub type HashHr4 = crate::Reg<hash_hr4::HashHr4Spec>;
#[doc = "read-only"]
pub mod hash_hr4;
#[doc = "HASH_HR5 (r) register accessor: read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr5::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hash_hr5`]
module"]
#[doc(alias = "HASH_HR5")]
pub type HashHr5 = crate::Reg<hash_hr5::HashHr5Spec>;
#[doc = "read-only"]
pub mod hash_hr5;
#[doc = "HASH_HR6 (r) register accessor: read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr6::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hash_hr6`]
module"]
#[doc(alias = "HASH_HR6")]
pub type HashHr6 = crate::Reg<hash_hr6::HashHr6Spec>;
#[doc = "read-only"]
pub mod hash_hr6;
#[doc = "HASH_HR7 (r) register accessor: read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr7::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hash_hr7`]
module"]
#[doc(alias = "HASH_HR7")]
pub type HashHr7 = crate::Reg<hash_hr7::HashHr7Spec>;
#[doc = "read-only"]
pub mod hash_hr7;
