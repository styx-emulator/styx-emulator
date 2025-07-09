// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    bcr1: Bcr1,
    btr1: Btr1,
    bcr2: Bcr2,
    btr2: Btr2,
    bcr3: Bcr3,
    btr3: Btr3,
    bcr4: Bcr4,
    btr4: Btr4,
    _reserved8: [u8; 0x40],
    pcr2: Pcr2,
    sr2: Sr2,
    pmem2: Pmem2,
    patt2: Patt2,
    _reserved12: [u8; 0x04],
    eccr2: Eccr2,
    _reserved13: [u8; 0x08],
    pcr3: Pcr3,
    sr3: Sr3,
    pmem3: Pmem3,
    patt3: Patt3,
    _reserved17: [u8; 0x04],
    eccr3: Eccr3,
    _reserved18: [u8; 0x08],
    pcr4: Pcr4,
    sr4: Sr4,
    pmem4: Pmem4,
    patt4: Patt4,
    pio4: Pio4,
    _reserved23: [u8; 0x50],
    bwtr1: Bwtr1,
    _reserved24: [u8; 0x04],
    bwtr2: Bwtr2,
    _reserved25: [u8; 0x04],
    bwtr3: Bwtr3,
    _reserved26: [u8; 0x04],
    bwtr4: Bwtr4,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - SRAM/NOR-Flash chip-select control register 1"]
    #[inline(always)]
    pub const fn bcr1(&self) -> &Bcr1 {
        &self.bcr1
    }
    #[doc = "0x04 - SRAM/NOR-Flash chip-select timing register 1"]
    #[inline(always)]
    pub const fn btr1(&self) -> &Btr1 {
        &self.btr1
    }
    #[doc = "0x08 - SRAM/NOR-Flash chip-select control register 2"]
    #[inline(always)]
    pub const fn bcr2(&self) -> &Bcr2 {
        &self.bcr2
    }
    #[doc = "0x0c - SRAM/NOR-Flash chip-select timing register 2"]
    #[inline(always)]
    pub const fn btr2(&self) -> &Btr2 {
        &self.btr2
    }
    #[doc = "0x10 - SRAM/NOR-Flash chip-select control register 3"]
    #[inline(always)]
    pub const fn bcr3(&self) -> &Bcr3 {
        &self.bcr3
    }
    #[doc = "0x14 - SRAM/NOR-Flash chip-select timing register 3"]
    #[inline(always)]
    pub const fn btr3(&self) -> &Btr3 {
        &self.btr3
    }
    #[doc = "0x18 - SRAM/NOR-Flash chip-select control register 4"]
    #[inline(always)]
    pub const fn bcr4(&self) -> &Bcr4 {
        &self.bcr4
    }
    #[doc = "0x1c - SRAM/NOR-Flash chip-select timing register 4"]
    #[inline(always)]
    pub const fn btr4(&self) -> &Btr4 {
        &self.btr4
    }
    #[doc = "0x60 - PC Card/NAND Flash control register 2"]
    #[inline(always)]
    pub const fn pcr2(&self) -> &Pcr2 {
        &self.pcr2
    }
    #[doc = "0x64 - FIFO status and interrupt register 2"]
    #[inline(always)]
    pub const fn sr2(&self) -> &Sr2 {
        &self.sr2
    }
    #[doc = "0x68 - Common memory space timing register 2"]
    #[inline(always)]
    pub const fn pmem2(&self) -> &Pmem2 {
        &self.pmem2
    }
    #[doc = "0x6c - Attribute memory space timing register 2"]
    #[inline(always)]
    pub const fn patt2(&self) -> &Patt2 {
        &self.patt2
    }
    #[doc = "0x74 - ECC result register 2"]
    #[inline(always)]
    pub const fn eccr2(&self) -> &Eccr2 {
        &self.eccr2
    }
    #[doc = "0x80 - PC Card/NAND Flash control register 3"]
    #[inline(always)]
    pub const fn pcr3(&self) -> &Pcr3 {
        &self.pcr3
    }
    #[doc = "0x84 - FIFO status and interrupt register 3"]
    #[inline(always)]
    pub const fn sr3(&self) -> &Sr3 {
        &self.sr3
    }
    #[doc = "0x88 - Common memory space timing register 3"]
    #[inline(always)]
    pub const fn pmem3(&self) -> &Pmem3 {
        &self.pmem3
    }
    #[doc = "0x8c - Attribute memory space timing register 3"]
    #[inline(always)]
    pub const fn patt3(&self) -> &Patt3 {
        &self.patt3
    }
    #[doc = "0x94 - ECC result register 3"]
    #[inline(always)]
    pub const fn eccr3(&self) -> &Eccr3 {
        &self.eccr3
    }
    #[doc = "0xa0 - PC Card/NAND Flash control register 4"]
    #[inline(always)]
    pub const fn pcr4(&self) -> &Pcr4 {
        &self.pcr4
    }
    #[doc = "0xa4 - FIFO status and interrupt register 4"]
    #[inline(always)]
    pub const fn sr4(&self) -> &Sr4 {
        &self.sr4
    }
    #[doc = "0xa8 - Common memory space timing register 4"]
    #[inline(always)]
    pub const fn pmem4(&self) -> &Pmem4 {
        &self.pmem4
    }
    #[doc = "0xac - Attribute memory space timing register 4"]
    #[inline(always)]
    pub const fn patt4(&self) -> &Patt4 {
        &self.patt4
    }
    #[doc = "0xb0 - I/O space timing register 4"]
    #[inline(always)]
    pub const fn pio4(&self) -> &Pio4 {
        &self.pio4
    }
    #[doc = "0x104 - SRAM/NOR-Flash write timing registers 1"]
    #[inline(always)]
    pub const fn bwtr1(&self) -> &Bwtr1 {
        &self.bwtr1
    }
    #[doc = "0x10c - SRAM/NOR-Flash write timing registers 2"]
    #[inline(always)]
    pub const fn bwtr2(&self) -> &Bwtr2 {
        &self.bwtr2
    }
    #[doc = "0x114 - SRAM/NOR-Flash write timing registers 3"]
    #[inline(always)]
    pub const fn bwtr3(&self) -> &Bwtr3 {
        &self.bwtr3
    }
    #[doc = "0x11c - SRAM/NOR-Flash write timing registers 4"]
    #[inline(always)]
    pub const fn bwtr4(&self) -> &Bwtr4 {
        &self.bwtr4
    }
}
#[doc = "BCR1 (rw) register accessor: SRAM/NOR-Flash chip-select control register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bcr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bcr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bcr1`]
module"]
#[doc(alias = "BCR1")]
pub type Bcr1 = crate::Reg<bcr1::Bcr1Spec>;
#[doc = "SRAM/NOR-Flash chip-select control register 1"]
pub mod bcr1;
#[doc = "BTR1 (rw) register accessor: SRAM/NOR-Flash chip-select timing register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`btr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`btr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@btr1`]
module"]
#[doc(alias = "BTR1")]
pub type Btr1 = crate::Reg<btr1::Btr1Spec>;
#[doc = "SRAM/NOR-Flash chip-select timing register 1"]
pub mod btr1;
#[doc = "BCR2 (rw) register accessor: SRAM/NOR-Flash chip-select control register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bcr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bcr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bcr2`]
module"]
#[doc(alias = "BCR2")]
pub type Bcr2 = crate::Reg<bcr2::Bcr2Spec>;
#[doc = "SRAM/NOR-Flash chip-select control register 2"]
pub mod bcr2;
#[doc = "BTR2 (rw) register accessor: SRAM/NOR-Flash chip-select timing register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`btr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`btr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@btr2`]
module"]
#[doc(alias = "BTR2")]
pub type Btr2 = crate::Reg<btr2::Btr2Spec>;
#[doc = "SRAM/NOR-Flash chip-select timing register 2"]
pub mod btr2;
#[doc = "BCR3 (rw) register accessor: SRAM/NOR-Flash chip-select control register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bcr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bcr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bcr3`]
module"]
#[doc(alias = "BCR3")]
pub type Bcr3 = crate::Reg<bcr3::Bcr3Spec>;
#[doc = "SRAM/NOR-Flash chip-select control register 3"]
pub mod bcr3;
#[doc = "BTR3 (rw) register accessor: SRAM/NOR-Flash chip-select timing register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`btr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`btr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@btr3`]
module"]
#[doc(alias = "BTR3")]
pub type Btr3 = crate::Reg<btr3::Btr3Spec>;
#[doc = "SRAM/NOR-Flash chip-select timing register 3"]
pub mod btr3;
#[doc = "BCR4 (rw) register accessor: SRAM/NOR-Flash chip-select control register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bcr4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bcr4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bcr4`]
module"]
#[doc(alias = "BCR4")]
pub type Bcr4 = crate::Reg<bcr4::Bcr4Spec>;
#[doc = "SRAM/NOR-Flash chip-select control register 4"]
pub mod bcr4;
#[doc = "BTR4 (rw) register accessor: SRAM/NOR-Flash chip-select timing register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`btr4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`btr4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@btr4`]
module"]
#[doc(alias = "BTR4")]
pub type Btr4 = crate::Reg<btr4::Btr4Spec>;
#[doc = "SRAM/NOR-Flash chip-select timing register 4"]
pub mod btr4;
#[doc = "PCR2 (rw) register accessor: PC Card/NAND Flash control register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pcr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pcr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pcr2`]
module"]
#[doc(alias = "PCR2")]
pub type Pcr2 = crate::Reg<pcr2::Pcr2Spec>;
#[doc = "PC Card/NAND Flash control register 2"]
pub mod pcr2;
#[doc = "SR2 (rw) register accessor: FIFO status and interrupt register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr2`]
module"]
#[doc(alias = "SR2")]
pub type Sr2 = crate::Reg<sr2::Sr2Spec>;
#[doc = "FIFO status and interrupt register 2"]
pub mod sr2;
#[doc = "PMEM2 (rw) register accessor: Common memory space timing register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pmem2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pmem2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pmem2`]
module"]
#[doc(alias = "PMEM2")]
pub type Pmem2 = crate::Reg<pmem2::Pmem2Spec>;
#[doc = "Common memory space timing register 2"]
pub mod pmem2;
#[doc = "PATT2 (rw) register accessor: Attribute memory space timing register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`patt2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`patt2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@patt2`]
module"]
#[doc(alias = "PATT2")]
pub type Patt2 = crate::Reg<patt2::Patt2Spec>;
#[doc = "Attribute memory space timing register 2"]
pub mod patt2;
#[doc = "ECCR2 (r) register accessor: ECC result register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccr2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccr2`]
module"]
#[doc(alias = "ECCR2")]
pub type Eccr2 = crate::Reg<eccr2::Eccr2Spec>;
#[doc = "ECC result register 2"]
pub mod eccr2;
#[doc = "PCR3 (rw) register accessor: PC Card/NAND Flash control register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pcr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pcr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pcr3`]
module"]
#[doc(alias = "PCR3")]
pub type Pcr3 = crate::Reg<pcr3::Pcr3Spec>;
#[doc = "PC Card/NAND Flash control register 3"]
pub mod pcr3;
#[doc = "SR3 (rw) register accessor: FIFO status and interrupt register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr3`]
module"]
#[doc(alias = "SR3")]
pub type Sr3 = crate::Reg<sr3::Sr3Spec>;
#[doc = "FIFO status and interrupt register 3"]
pub mod sr3;
#[doc = "PMEM3 (rw) register accessor: Common memory space timing register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pmem3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pmem3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pmem3`]
module"]
#[doc(alias = "PMEM3")]
pub type Pmem3 = crate::Reg<pmem3::Pmem3Spec>;
#[doc = "Common memory space timing register 3"]
pub mod pmem3;
#[doc = "PATT3 (rw) register accessor: Attribute memory space timing register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`patt3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`patt3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@patt3`]
module"]
#[doc(alias = "PATT3")]
pub type Patt3 = crate::Reg<patt3::Patt3Spec>;
#[doc = "Attribute memory space timing register 3"]
pub mod patt3;
#[doc = "ECCR3 (r) register accessor: ECC result register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccr3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@eccr3`]
module"]
#[doc(alias = "ECCR3")]
pub type Eccr3 = crate::Reg<eccr3::Eccr3Spec>;
#[doc = "ECC result register 3"]
pub mod eccr3;
#[doc = "PCR4 (rw) register accessor: PC Card/NAND Flash control register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pcr4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pcr4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pcr4`]
module"]
#[doc(alias = "PCR4")]
pub type Pcr4 = crate::Reg<pcr4::Pcr4Spec>;
#[doc = "PC Card/NAND Flash control register 4"]
pub mod pcr4;
#[doc = "SR4 (rw) register accessor: FIFO status and interrupt register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sr4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr4`]
module"]
#[doc(alias = "SR4")]
pub type Sr4 = crate::Reg<sr4::Sr4Spec>;
#[doc = "FIFO status and interrupt register 4"]
pub mod sr4;
#[doc = "PMEM4 (rw) register accessor: Common memory space timing register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pmem4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pmem4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pmem4`]
module"]
#[doc(alias = "PMEM4")]
pub type Pmem4 = crate::Reg<pmem4::Pmem4Spec>;
#[doc = "Common memory space timing register 4"]
pub mod pmem4;
#[doc = "PATT4 (rw) register accessor: Attribute memory space timing register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`patt4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`patt4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@patt4`]
module"]
#[doc(alias = "PATT4")]
pub type Patt4 = crate::Reg<patt4::Patt4Spec>;
#[doc = "Attribute memory space timing register 4"]
pub mod patt4;
#[doc = "PIO4 (rw) register accessor: I/O space timing register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pio4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pio4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pio4`]
module"]
#[doc(alias = "PIO4")]
pub type Pio4 = crate::Reg<pio4::Pio4Spec>;
#[doc = "I/O space timing register 4"]
pub mod pio4;
#[doc = "BWTR1 (rw) register accessor: SRAM/NOR-Flash write timing registers 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bwtr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bwtr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bwtr1`]
module"]
#[doc(alias = "BWTR1")]
pub type Bwtr1 = crate::Reg<bwtr1::Bwtr1Spec>;
#[doc = "SRAM/NOR-Flash write timing registers 1"]
pub mod bwtr1;
#[doc = "BWTR2 (rw) register accessor: SRAM/NOR-Flash write timing registers 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bwtr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bwtr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bwtr2`]
module"]
#[doc(alias = "BWTR2")]
pub type Bwtr2 = crate::Reg<bwtr2::Bwtr2Spec>;
#[doc = "SRAM/NOR-Flash write timing registers 2"]
pub mod bwtr2;
#[doc = "BWTR3 (rw) register accessor: SRAM/NOR-Flash write timing registers 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bwtr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bwtr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bwtr3`]
module"]
#[doc(alias = "BWTR3")]
pub type Bwtr3 = crate::Reg<bwtr3::Bwtr3Spec>;
#[doc = "SRAM/NOR-Flash write timing registers 3"]
pub mod bwtr3;
#[doc = "BWTR4 (rw) register accessor: SRAM/NOR-Flash write timing registers 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bwtr4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bwtr4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bwtr4`]
module"]
#[doc(alias = "BWTR4")]
pub type Bwtr4 = crate::Reg<bwtr4::Bwtr4Spec>;
#[doc = "SRAM/NOR-Flash write timing registers 4"]
pub mod bwtr4;
