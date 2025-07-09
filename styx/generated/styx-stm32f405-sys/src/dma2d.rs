// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    cr: Cr,
    isr: Isr,
    ifcr: Ifcr,
    fgmar: Fgmar,
    fgor: Fgor,
    bgmar: Bgmar,
    bgor: Bgor,
    fgpfccr: Fgpfccr,
    fgcolr: Fgcolr,
    bgpfccr: Bgpfccr,
    bgcolr: Bgcolr,
    fgcmar: Fgcmar,
    bgcmar: Bgcmar,
    opfccr: Opfccr,
    ocolr: Ocolr,
    omar: Omar,
    oor: Oor,
    nlr: Nlr,
    lwr: Lwr,
    amtcr: Amtcr,
    _reserved20: [u8; 0x03b0],
    fgclut: Fgclut,
    _reserved21: [u8; 0x03fc],
    bgclut: Bgclut,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - control register"]
    #[inline(always)]
    pub const fn cr(&self) -> &Cr {
        &self.cr
    }
    #[doc = "0x04 - Interrupt Status Register"]
    #[inline(always)]
    pub const fn isr(&self) -> &Isr {
        &self.isr
    }
    #[doc = "0x08 - interrupt flag clear register"]
    #[inline(always)]
    pub const fn ifcr(&self) -> &Ifcr {
        &self.ifcr
    }
    #[doc = "0x0c - foreground memory address register"]
    #[inline(always)]
    pub const fn fgmar(&self) -> &Fgmar {
        &self.fgmar
    }
    #[doc = "0x10 - foreground offset register"]
    #[inline(always)]
    pub const fn fgor(&self) -> &Fgor {
        &self.fgor
    }
    #[doc = "0x14 - background memory address register"]
    #[inline(always)]
    pub const fn bgmar(&self) -> &Bgmar {
        &self.bgmar
    }
    #[doc = "0x18 - background offset register"]
    #[inline(always)]
    pub const fn bgor(&self) -> &Bgor {
        &self.bgor
    }
    #[doc = "0x1c - foreground PFC control register"]
    #[inline(always)]
    pub const fn fgpfccr(&self) -> &Fgpfccr {
        &self.fgpfccr
    }
    #[doc = "0x20 - foreground color register"]
    #[inline(always)]
    pub const fn fgcolr(&self) -> &Fgcolr {
        &self.fgcolr
    }
    #[doc = "0x24 - background PFC control register"]
    #[inline(always)]
    pub const fn bgpfccr(&self) -> &Bgpfccr {
        &self.bgpfccr
    }
    #[doc = "0x28 - background color register"]
    #[inline(always)]
    pub const fn bgcolr(&self) -> &Bgcolr {
        &self.bgcolr
    }
    #[doc = "0x2c - foreground CLUT memory address register"]
    #[inline(always)]
    pub const fn fgcmar(&self) -> &Fgcmar {
        &self.fgcmar
    }
    #[doc = "0x30 - background CLUT memory address register"]
    #[inline(always)]
    pub const fn bgcmar(&self) -> &Bgcmar {
        &self.bgcmar
    }
    #[doc = "0x34 - output PFC control register"]
    #[inline(always)]
    pub const fn opfccr(&self) -> &Opfccr {
        &self.opfccr
    }
    #[doc = "0x38 - output color register"]
    #[inline(always)]
    pub const fn ocolr(&self) -> &Ocolr {
        &self.ocolr
    }
    #[doc = "0x3c - output memory address register"]
    #[inline(always)]
    pub const fn omar(&self) -> &Omar {
        &self.omar
    }
    #[doc = "0x40 - output offset register"]
    #[inline(always)]
    pub const fn oor(&self) -> &Oor {
        &self.oor
    }
    #[doc = "0x44 - number of line register"]
    #[inline(always)]
    pub const fn nlr(&self) -> &Nlr {
        &self.nlr
    }
    #[doc = "0x48 - line watermark register"]
    #[inline(always)]
    pub const fn lwr(&self) -> &Lwr {
        &self.lwr
    }
    #[doc = "0x4c - AHB master timer configuration register"]
    #[inline(always)]
    pub const fn amtcr(&self) -> &Amtcr {
        &self.amtcr
    }
    #[doc = "0x400 - FGCLUT"]
    #[inline(always)]
    pub const fn fgclut(&self) -> &Fgclut {
        &self.fgclut
    }
    #[doc = "0x800 - BGCLUT"]
    #[inline(always)]
    pub const fn bgclut(&self) -> &Bgclut {
        &self.bgclut
    }
}
#[doc = "CR (rw) register accessor: control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cr`]
module"]
#[doc(alias = "CR")]
pub type Cr = crate::Reg<cr::CrSpec>;
#[doc = "control register"]
pub mod cr;
#[doc = "ISR (r) register accessor: Interrupt Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@isr`]
module"]
#[doc(alias = "ISR")]
pub type Isr = crate::Reg<isr::IsrSpec>;
#[doc = "Interrupt Status Register"]
pub mod isr;
#[doc = "IFCR (rw) register accessor: interrupt flag clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ifcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ifcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ifcr`]
module"]
#[doc(alias = "IFCR")]
pub type Ifcr = crate::Reg<ifcr::IfcrSpec>;
#[doc = "interrupt flag clear register"]
pub mod ifcr;
#[doc = "FGMAR (rw) register accessor: foreground memory address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgmar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgmar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fgmar`]
module"]
#[doc(alias = "FGMAR")]
pub type Fgmar = crate::Reg<fgmar::FgmarSpec>;
#[doc = "foreground memory address register"]
pub mod fgmar;
#[doc = "FGOR (rw) register accessor: foreground offset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgor::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgor::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fgor`]
module"]
#[doc(alias = "FGOR")]
pub type Fgor = crate::Reg<fgor::FgorSpec>;
#[doc = "foreground offset register"]
pub mod fgor;
#[doc = "BGMAR (rw) register accessor: background memory address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgmar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgmar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bgmar`]
module"]
#[doc(alias = "BGMAR")]
pub type Bgmar = crate::Reg<bgmar::BgmarSpec>;
#[doc = "background memory address register"]
pub mod bgmar;
#[doc = "BGOR (rw) register accessor: background offset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgor::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgor::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bgor`]
module"]
#[doc(alias = "BGOR")]
pub type Bgor = crate::Reg<bgor::BgorSpec>;
#[doc = "background offset register"]
pub mod bgor;
#[doc = "FGPFCCR (rw) register accessor: foreground PFC control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgpfccr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgpfccr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fgpfccr`]
module"]
#[doc(alias = "FGPFCCR")]
pub type Fgpfccr = crate::Reg<fgpfccr::FgpfccrSpec>;
#[doc = "foreground PFC control register"]
pub mod fgpfccr;
#[doc = "FGCOLR (rw) register accessor: foreground color register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgcolr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgcolr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fgcolr`]
module"]
#[doc(alias = "FGCOLR")]
pub type Fgcolr = crate::Reg<fgcolr::FgcolrSpec>;
#[doc = "foreground color register"]
pub mod fgcolr;
#[doc = "BGPFCCR (rw) register accessor: background PFC control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgpfccr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgpfccr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bgpfccr`]
module"]
#[doc(alias = "BGPFCCR")]
pub type Bgpfccr = crate::Reg<bgpfccr::BgpfccrSpec>;
#[doc = "background PFC control register"]
pub mod bgpfccr;
#[doc = "BGCOLR (rw) register accessor: background color register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgcolr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgcolr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bgcolr`]
module"]
#[doc(alias = "BGCOLR")]
pub type Bgcolr = crate::Reg<bgcolr::BgcolrSpec>;
#[doc = "background color register"]
pub mod bgcolr;
#[doc = "FGCMAR (rw) register accessor: foreground CLUT memory address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgcmar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgcmar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fgcmar`]
module"]
#[doc(alias = "FGCMAR")]
pub type Fgcmar = crate::Reg<fgcmar::FgcmarSpec>;
#[doc = "foreground CLUT memory address register"]
pub mod fgcmar;
#[doc = "BGCMAR (rw) register accessor: background CLUT memory address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgcmar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgcmar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bgcmar`]
module"]
#[doc(alias = "BGCMAR")]
pub type Bgcmar = crate::Reg<bgcmar::BgcmarSpec>;
#[doc = "background CLUT memory address register"]
pub mod bgcmar;
#[doc = "OPFCCR (rw) register accessor: output PFC control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`opfccr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`opfccr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@opfccr`]
module"]
#[doc(alias = "OPFCCR")]
pub type Opfccr = crate::Reg<opfccr::OpfccrSpec>;
#[doc = "output PFC control register"]
pub mod opfccr;
#[doc = "OCOLR (rw) register accessor: output color register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ocolr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ocolr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ocolr`]
module"]
#[doc(alias = "OCOLR")]
pub type Ocolr = crate::Reg<ocolr::OcolrSpec>;
#[doc = "output color register"]
pub mod ocolr;
#[doc = "OMAR (rw) register accessor: output memory address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`omar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`omar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@omar`]
module"]
#[doc(alias = "OMAR")]
pub type Omar = crate::Reg<omar::OmarSpec>;
#[doc = "output memory address register"]
pub mod omar;
#[doc = "OOR (rw) register accessor: output offset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`oor::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`oor::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@oor`]
module"]
#[doc(alias = "OOR")]
pub type Oor = crate::Reg<oor::OorSpec>;
#[doc = "output offset register"]
pub mod oor;
#[doc = "NLR (rw) register accessor: number of line register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`nlr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`nlr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@nlr`]
module"]
#[doc(alias = "NLR")]
pub type Nlr = crate::Reg<nlr::NlrSpec>;
#[doc = "number of line register"]
pub mod nlr;
#[doc = "LWR (rw) register accessor: line watermark register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lwr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lwr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@lwr`]
module"]
#[doc(alias = "LWR")]
pub type Lwr = crate::Reg<lwr::LwrSpec>;
#[doc = "line watermark register"]
pub mod lwr;
#[doc = "AMTCR (rw) register accessor: AHB master timer configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`amtcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`amtcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@amtcr`]
module"]
#[doc(alias = "AMTCR")]
pub type Amtcr = crate::Reg<amtcr::AmtcrSpec>;
#[doc = "AHB master timer configuration register"]
pub mod amtcr;
#[doc = "FGCLUT (rw) register accessor: FGCLUT\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgclut::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgclut::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fgclut`]
module"]
#[doc(alias = "FGCLUT")]
pub type Fgclut = crate::Reg<fgclut::FgclutSpec>;
#[doc = "FGCLUT"]
pub mod fgclut;
#[doc = "BGCLUT (rw) register accessor: BGCLUT\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgclut::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgclut::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bgclut`]
module"]
#[doc(alias = "BGCLUT")]
pub type Bgclut = crate::Reg<bgclut::BgclutSpec>;
#[doc = "BGCLUT"]
pub mod bgclut;
