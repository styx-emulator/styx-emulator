// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    cr: Cr,
    sr: Sr,
    din: Din,
    dout: Dout,
    dmacr: Dmacr,
    imscr: Imscr,
    risr: Risr,
    misr: Misr,
    k0lr: K0lr,
    k0rr: K0rr,
    k1lr: K1lr,
    k1rr: K1rr,
    k2lr: K2lr,
    k2rr: K2rr,
    k3lr: K3lr,
    k3rr: K3rr,
    iv0lr: Iv0lr,
    iv0rr: Iv0rr,
    iv1lr: Iv1lr,
    iv1rr: Iv1rr,
    csgcmccm0r: Csgcmccm0r,
    csgcmccm1r: Csgcmccm1r,
    csgcmccm2r: Csgcmccm2r,
    csgcmccm3r: Csgcmccm3r,
    csgcmccm4r: Csgcmccm4r,
    csgcmccm5r: Csgcmccm5r,
    csgcmccm6r: Csgcmccm6r,
    csgcmccm7r: Csgcmccm7r,
    csgcm0r: Csgcm0r,
    csgcm1r: Csgcm1r,
    csgcm2r: Csgcm2r,
    csgcm3r: Csgcm3r,
    csgcm4r: Csgcm4r,
    csgcm5r: Csgcm5r,
    csgcm6r: Csgcm6r,
    csgcm7r: Csgcm7r,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - control register"]
    #[inline(always)]
    pub const fn cr(&self) -> &Cr {
        &self.cr
    }
    #[doc = "0x04 - status register"]
    #[inline(always)]
    pub const fn sr(&self) -> &Sr {
        &self.sr
    }
    #[doc = "0x08 - data input register"]
    #[inline(always)]
    pub const fn din(&self) -> &Din {
        &self.din
    }
    #[doc = "0x0c - data output register"]
    #[inline(always)]
    pub const fn dout(&self) -> &Dout {
        &self.dout
    }
    #[doc = "0x10 - DMA control register"]
    #[inline(always)]
    pub const fn dmacr(&self) -> &Dmacr {
        &self.dmacr
    }
    #[doc = "0x14 - interrupt mask set/clear register"]
    #[inline(always)]
    pub const fn imscr(&self) -> &Imscr {
        &self.imscr
    }
    #[doc = "0x18 - raw interrupt status register"]
    #[inline(always)]
    pub const fn risr(&self) -> &Risr {
        &self.risr
    }
    #[doc = "0x1c - masked interrupt status register"]
    #[inline(always)]
    pub const fn misr(&self) -> &Misr {
        &self.misr
    }
    #[doc = "0x20 - key registers"]
    #[inline(always)]
    pub const fn k0lr(&self) -> &K0lr {
        &self.k0lr
    }
    #[doc = "0x24 - key registers"]
    #[inline(always)]
    pub const fn k0rr(&self) -> &K0rr {
        &self.k0rr
    }
    #[doc = "0x28 - key registers"]
    #[inline(always)]
    pub const fn k1lr(&self) -> &K1lr {
        &self.k1lr
    }
    #[doc = "0x2c - key registers"]
    #[inline(always)]
    pub const fn k1rr(&self) -> &K1rr {
        &self.k1rr
    }
    #[doc = "0x30 - key registers"]
    #[inline(always)]
    pub const fn k2lr(&self) -> &K2lr {
        &self.k2lr
    }
    #[doc = "0x34 - key registers"]
    #[inline(always)]
    pub const fn k2rr(&self) -> &K2rr {
        &self.k2rr
    }
    #[doc = "0x38 - key registers"]
    #[inline(always)]
    pub const fn k3lr(&self) -> &K3lr {
        &self.k3lr
    }
    #[doc = "0x3c - key registers"]
    #[inline(always)]
    pub const fn k3rr(&self) -> &K3rr {
        &self.k3rr
    }
    #[doc = "0x40 - initialization vector registers"]
    #[inline(always)]
    pub const fn iv0lr(&self) -> &Iv0lr {
        &self.iv0lr
    }
    #[doc = "0x44 - initialization vector registers"]
    #[inline(always)]
    pub const fn iv0rr(&self) -> &Iv0rr {
        &self.iv0rr
    }
    #[doc = "0x48 - initialization vector registers"]
    #[inline(always)]
    pub const fn iv1lr(&self) -> &Iv1lr {
        &self.iv1lr
    }
    #[doc = "0x4c - initialization vector registers"]
    #[inline(always)]
    pub const fn iv1rr(&self) -> &Iv1rr {
        &self.iv1rr
    }
    #[doc = "0x50 - context swap register"]
    #[inline(always)]
    pub const fn csgcmccm0r(&self) -> &Csgcmccm0r {
        &self.csgcmccm0r
    }
    #[doc = "0x54 - context swap register"]
    #[inline(always)]
    pub const fn csgcmccm1r(&self) -> &Csgcmccm1r {
        &self.csgcmccm1r
    }
    #[doc = "0x58 - context swap register"]
    #[inline(always)]
    pub const fn csgcmccm2r(&self) -> &Csgcmccm2r {
        &self.csgcmccm2r
    }
    #[doc = "0x5c - context swap register"]
    #[inline(always)]
    pub const fn csgcmccm3r(&self) -> &Csgcmccm3r {
        &self.csgcmccm3r
    }
    #[doc = "0x60 - context swap register"]
    #[inline(always)]
    pub const fn csgcmccm4r(&self) -> &Csgcmccm4r {
        &self.csgcmccm4r
    }
    #[doc = "0x64 - context swap register"]
    #[inline(always)]
    pub const fn csgcmccm5r(&self) -> &Csgcmccm5r {
        &self.csgcmccm5r
    }
    #[doc = "0x68 - context swap register"]
    #[inline(always)]
    pub const fn csgcmccm6r(&self) -> &Csgcmccm6r {
        &self.csgcmccm6r
    }
    #[doc = "0x6c - context swap register"]
    #[inline(always)]
    pub const fn csgcmccm7r(&self) -> &Csgcmccm7r {
        &self.csgcmccm7r
    }
    #[doc = "0x70 - context swap register"]
    #[inline(always)]
    pub const fn csgcm0r(&self) -> &Csgcm0r {
        &self.csgcm0r
    }
    #[doc = "0x74 - context swap register"]
    #[inline(always)]
    pub const fn csgcm1r(&self) -> &Csgcm1r {
        &self.csgcm1r
    }
    #[doc = "0x78 - context swap register"]
    #[inline(always)]
    pub const fn csgcm2r(&self) -> &Csgcm2r {
        &self.csgcm2r
    }
    #[doc = "0x7c - context swap register"]
    #[inline(always)]
    pub const fn csgcm3r(&self) -> &Csgcm3r {
        &self.csgcm3r
    }
    #[doc = "0x80 - context swap register"]
    #[inline(always)]
    pub const fn csgcm4r(&self) -> &Csgcm4r {
        &self.csgcm4r
    }
    #[doc = "0x84 - context swap register"]
    #[inline(always)]
    pub const fn csgcm5r(&self) -> &Csgcm5r {
        &self.csgcm5r
    }
    #[doc = "0x88 - context swap register"]
    #[inline(always)]
    pub const fn csgcm6r(&self) -> &Csgcm6r {
        &self.csgcm6r
    }
    #[doc = "0x8c - context swap register"]
    #[inline(always)]
    pub const fn csgcm7r(&self) -> &Csgcm7r {
        &self.csgcm7r
    }
}
#[doc = "CR (rw) register accessor: control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr`]
module"]
#[doc(alias = "CR")]
pub type Cr = crate::Reg<cr::CrSpec>;
#[doc = "control register"]
pub mod cr;
#[doc = "SR (r) register accessor: status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sr`]
module"]
#[doc(alias = "SR")]
pub type Sr = crate::Reg<sr::SrSpec>;
#[doc = "status register"]
pub mod sr;
#[doc = "DIN (rw) register accessor: data input register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`din::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`din::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@din`]
module"]
#[doc(alias = "DIN")]
pub type Din = crate::Reg<din::DinSpec>;
#[doc = "data input register"]
pub mod din;
#[doc = "DOUT (r) register accessor: data output register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dout::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dout`]
module"]
#[doc(alias = "DOUT")]
pub type Dout = crate::Reg<dout::DoutSpec>;
#[doc = "data output register"]
pub mod dout;
#[doc = "DMACR (rw) register accessor: DMA control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmacr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmacr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmacr`]
module"]
#[doc(alias = "DMACR")]
pub type Dmacr = crate::Reg<dmacr::DmacrSpec>;
#[doc = "DMA control register"]
pub mod dmacr;
#[doc = "IMSCR (rw) register accessor: interrupt mask set/clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`imscr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`imscr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@imscr`]
module"]
#[doc(alias = "IMSCR")]
pub type Imscr = crate::Reg<imscr::ImscrSpec>;
#[doc = "interrupt mask set/clear register"]
pub mod imscr;
#[doc = "RISR (r) register accessor: raw interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`risr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@risr`]
module"]
#[doc(alias = "RISR")]
pub type Risr = crate::Reg<risr::RisrSpec>;
#[doc = "raw interrupt status register"]
pub mod risr;
#[doc = "MISR (r) register accessor: masked interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`misr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@misr`]
module"]
#[doc(alias = "MISR")]
pub type Misr = crate::Reg<misr::MisrSpec>;
#[doc = "masked interrupt status register"]
pub mod misr;
#[doc = "K0LR (w) register accessor: key registers\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`k0lr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@k0lr`]
module"]
#[doc(alias = "K0LR")]
pub type K0lr = crate::Reg<k0lr::K0lrSpec>;
#[doc = "key registers"]
pub mod k0lr;
#[doc = "K0RR (w) register accessor: key registers\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`k0rr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@k0rr`]
module"]
#[doc(alias = "K0RR")]
pub type K0rr = crate::Reg<k0rr::K0rrSpec>;
#[doc = "key registers"]
pub mod k0rr;
#[doc = "K1LR (w) register accessor: key registers\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`k1lr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@k1lr`]
module"]
#[doc(alias = "K1LR")]
pub type K1lr = crate::Reg<k1lr::K1lrSpec>;
#[doc = "key registers"]
pub mod k1lr;
#[doc = "K1RR (w) register accessor: key registers\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`k1rr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@k1rr`]
module"]
#[doc(alias = "K1RR")]
pub type K1rr = crate::Reg<k1rr::K1rrSpec>;
#[doc = "key registers"]
pub mod k1rr;
#[doc = "K2LR (w) register accessor: key registers\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`k2lr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@k2lr`]
module"]
#[doc(alias = "K2LR")]
pub type K2lr = crate::Reg<k2lr::K2lrSpec>;
#[doc = "key registers"]
pub mod k2lr;
#[doc = "K2RR (w) register accessor: key registers\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`k2rr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@k2rr`]
module"]
#[doc(alias = "K2RR")]
pub type K2rr = crate::Reg<k2rr::K2rrSpec>;
#[doc = "key registers"]
pub mod k2rr;
#[doc = "K3LR (w) register accessor: key registers\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`k3lr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@k3lr`]
module"]
#[doc(alias = "K3LR")]
pub type K3lr = crate::Reg<k3lr::K3lrSpec>;
#[doc = "key registers"]
pub mod k3lr;
#[doc = "K3RR (w) register accessor: key registers\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`k3rr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@k3rr`]
module"]
#[doc(alias = "K3RR")]
pub type K3rr = crate::Reg<k3rr::K3rrSpec>;
#[doc = "key registers"]
pub mod k3rr;
#[doc = "IV0LR (rw) register accessor: initialization vector registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iv0lr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iv0lr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iv0lr`]
module"]
#[doc(alias = "IV0LR")]
pub type Iv0lr = crate::Reg<iv0lr::Iv0lrSpec>;
#[doc = "initialization vector registers"]
pub mod iv0lr;
#[doc = "IV0RR (rw) register accessor: initialization vector registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iv0rr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iv0rr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iv0rr`]
module"]
#[doc(alias = "IV0RR")]
pub type Iv0rr = crate::Reg<iv0rr::Iv0rrSpec>;
#[doc = "initialization vector registers"]
pub mod iv0rr;
#[doc = "IV1LR (rw) register accessor: initialization vector registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iv1lr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iv1lr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iv1lr`]
module"]
#[doc(alias = "IV1LR")]
pub type Iv1lr = crate::Reg<iv1lr::Iv1lrSpec>;
#[doc = "initialization vector registers"]
pub mod iv1lr;
#[doc = "IV1RR (rw) register accessor: initialization vector registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iv1rr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iv1rr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iv1rr`]
module"]
#[doc(alias = "IV1RR")]
pub type Iv1rr = crate::Reg<iv1rr::Iv1rrSpec>;
#[doc = "initialization vector registers"]
pub mod iv1rr;
#[doc = "CSGCMCCM0R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm0r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm0r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcmccm0r`]
module"]
#[doc(alias = "CSGCMCCM0R")]
pub type Csgcmccm0r = crate::Reg<csgcmccm0r::Csgcmccm0rSpec>;
#[doc = "context swap register"]
pub mod csgcmccm0r;
#[doc = "CSGCMCCM1R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcmccm1r`]
module"]
#[doc(alias = "CSGCMCCM1R")]
pub type Csgcmccm1r = crate::Reg<csgcmccm1r::Csgcmccm1rSpec>;
#[doc = "context swap register"]
pub mod csgcmccm1r;
#[doc = "CSGCMCCM2R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm2r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm2r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcmccm2r`]
module"]
#[doc(alias = "CSGCMCCM2R")]
pub type Csgcmccm2r = crate::Reg<csgcmccm2r::Csgcmccm2rSpec>;
#[doc = "context swap register"]
pub mod csgcmccm2r;
#[doc = "CSGCMCCM3R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm3r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm3r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcmccm3r`]
module"]
#[doc(alias = "CSGCMCCM3R")]
pub type Csgcmccm3r = crate::Reg<csgcmccm3r::Csgcmccm3rSpec>;
#[doc = "context swap register"]
pub mod csgcmccm3r;
#[doc = "CSGCMCCM4R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm4r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm4r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcmccm4r`]
module"]
#[doc(alias = "CSGCMCCM4R")]
pub type Csgcmccm4r = crate::Reg<csgcmccm4r::Csgcmccm4rSpec>;
#[doc = "context swap register"]
pub mod csgcmccm4r;
#[doc = "CSGCMCCM5R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm5r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm5r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcmccm5r`]
module"]
#[doc(alias = "CSGCMCCM5R")]
pub type Csgcmccm5r = crate::Reg<csgcmccm5r::Csgcmccm5rSpec>;
#[doc = "context swap register"]
pub mod csgcmccm5r;
#[doc = "CSGCMCCM6R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm6r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm6r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcmccm6r`]
module"]
#[doc(alias = "CSGCMCCM6R")]
pub type Csgcmccm6r = crate::Reg<csgcmccm6r::Csgcmccm6rSpec>;
#[doc = "context swap register"]
pub mod csgcmccm6r;
#[doc = "CSGCMCCM7R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcmccm7r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcmccm7r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcmccm7r`]
module"]
#[doc(alias = "CSGCMCCM7R")]
pub type Csgcmccm7r = crate::Reg<csgcmccm7r::Csgcmccm7rSpec>;
#[doc = "context swap register"]
pub mod csgcmccm7r;
#[doc = "CSGCM0R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm0r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm0r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcm0r`]
module"]
#[doc(alias = "CSGCM0R")]
pub type Csgcm0r = crate::Reg<csgcm0r::Csgcm0rSpec>;
#[doc = "context swap register"]
pub mod csgcm0r;
#[doc = "CSGCM1R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm1r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm1r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcm1r`]
module"]
#[doc(alias = "CSGCM1R")]
pub type Csgcm1r = crate::Reg<csgcm1r::Csgcm1rSpec>;
#[doc = "context swap register"]
pub mod csgcm1r;
#[doc = "CSGCM2R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm2r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm2r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcm2r`]
module"]
#[doc(alias = "CSGCM2R")]
pub type Csgcm2r = crate::Reg<csgcm2r::Csgcm2rSpec>;
#[doc = "context swap register"]
pub mod csgcm2r;
#[doc = "CSGCM3R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm3r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm3r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcm3r`]
module"]
#[doc(alias = "CSGCM3R")]
pub type Csgcm3r = crate::Reg<csgcm3r::Csgcm3rSpec>;
#[doc = "context swap register"]
pub mod csgcm3r;
#[doc = "CSGCM4R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm4r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm4r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcm4r`]
module"]
#[doc(alias = "CSGCM4R")]
pub type Csgcm4r = crate::Reg<csgcm4r::Csgcm4rSpec>;
#[doc = "context swap register"]
pub mod csgcm4r;
#[doc = "CSGCM5R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm5r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm5r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcm5r`]
module"]
#[doc(alias = "CSGCM5R")]
pub type Csgcm5r = crate::Reg<csgcm5r::Csgcm5rSpec>;
#[doc = "context swap register"]
pub mod csgcm5r;
#[doc = "CSGCM6R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm6r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm6r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcm6r`]
module"]
#[doc(alias = "CSGCM6R")]
pub type Csgcm6r = crate::Reg<csgcm6r::Csgcm6rSpec>;
#[doc = "context swap register"]
pub mod csgcm6r;
#[doc = "CSGCM7R (rw) register accessor: context swap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csgcm7r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csgcm7r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@csgcm7r`]
module"]
#[doc(alias = "CSGCM7R")]
pub type Csgcm7r = crate::Reg<csgcm7r::Csgcm7rSpec>;
#[doc = "context swap register"]
pub mod csgcm7r;
