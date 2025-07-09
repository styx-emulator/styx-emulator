// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    cpuid: Cpuid,
    icsr: Icsr,
    vtor: Vtor,
    aircr: Aircr,
    scr: Scr,
    ccr: Ccr,
    shpr1: Shpr1,
    shpr2: Shpr2,
    shpr3: Shpr3,
    shcrs: Shcrs,
    cfsr_ufsr_bfsr_mmfsr: CfsrUfsrBfsrMmfsr,
    hfsr: Hfsr,
    _reserved12: [u8; 0x04],
    mmfar: Mmfar,
    bfar: Bfar,
    afsr: Afsr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - CPUID base register"]
    #[inline(always)]
    pub const fn cpuid(&self) -> &Cpuid {
        &self.cpuid
    }
    #[doc = "0x04 - Interrupt control and state register"]
    #[inline(always)]
    pub const fn icsr(&self) -> &Icsr {
        &self.icsr
    }
    #[doc = "0x08 - Vector table offset register"]
    #[inline(always)]
    pub const fn vtor(&self) -> &Vtor {
        &self.vtor
    }
    #[doc = "0x0c - Application interrupt and reset control register"]
    #[inline(always)]
    pub const fn aircr(&self) -> &Aircr {
        &self.aircr
    }
    #[doc = "0x10 - System control register"]
    #[inline(always)]
    pub const fn scr(&self) -> &Scr {
        &self.scr
    }
    #[doc = "0x14 - Configuration and control register"]
    #[inline(always)]
    pub const fn ccr(&self) -> &Ccr {
        &self.ccr
    }
    #[doc = "0x18 - System handler priority registers"]
    #[inline(always)]
    pub const fn shpr1(&self) -> &Shpr1 {
        &self.shpr1
    }
    #[doc = "0x1c - System handler priority registers"]
    #[inline(always)]
    pub const fn shpr2(&self) -> &Shpr2 {
        &self.shpr2
    }
    #[doc = "0x20 - System handler priority registers"]
    #[inline(always)]
    pub const fn shpr3(&self) -> &Shpr3 {
        &self.shpr3
    }
    #[doc = "0x24 - System handler control and state register"]
    #[inline(always)]
    pub const fn shcrs(&self) -> &Shcrs {
        &self.shcrs
    }
    #[doc = "0x28 - Configurable fault status register"]
    #[inline(always)]
    pub const fn cfsr_ufsr_bfsr_mmfsr(&self) -> &CfsrUfsrBfsrMmfsr {
        &self.cfsr_ufsr_bfsr_mmfsr
    }
    #[doc = "0x2c - Hard fault status register"]
    #[inline(always)]
    pub const fn hfsr(&self) -> &Hfsr {
        &self.hfsr
    }
    #[doc = "0x34 - Memory management fault address register"]
    #[inline(always)]
    pub const fn mmfar(&self) -> &Mmfar {
        &self.mmfar
    }
    #[doc = "0x38 - Bus fault address register"]
    #[inline(always)]
    pub const fn bfar(&self) -> &Bfar {
        &self.bfar
    }
    #[doc = "0x3c - Auxiliary fault status register"]
    #[inline(always)]
    pub const fn afsr(&self) -> &Afsr {
        &self.afsr
    }
}
#[doc = "CPUID (r) register accessor: CPUID base register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cpuid::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cpuid`]
module"]
#[doc(alias = "CPUID")]
pub type Cpuid = crate::Reg<cpuid::CpuidSpec>;
#[doc = "CPUID base register"]
pub mod cpuid;
#[doc = "ICSR (rw) register accessor: Interrupt control and state register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icsr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icsr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@icsr`]
module"]
#[doc(alias = "ICSR")]
pub type Icsr = crate::Reg<icsr::IcsrSpec>;
#[doc = "Interrupt control and state register"]
pub mod icsr;
#[doc = "VTOR (rw) register accessor: Vector table offset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`vtor::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`vtor::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@vtor`]
module"]
#[doc(alias = "VTOR")]
pub type Vtor = crate::Reg<vtor::VtorSpec>;
#[doc = "Vector table offset register"]
pub mod vtor;
#[doc = "AIRCR (rw) register accessor: Application interrupt and reset control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`aircr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`aircr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@aircr`]
module"]
#[doc(alias = "AIRCR")]
pub type Aircr = crate::Reg<aircr::AircrSpec>;
#[doc = "Application interrupt and reset control register"]
pub mod aircr;
#[doc = "SCR (rw) register accessor: System control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`scr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`scr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@scr`]
module"]
#[doc(alias = "SCR")]
pub type Scr = crate::Reg<scr::ScrSpec>;
#[doc = "System control register"]
pub mod scr;
#[doc = "CCR (rw) register accessor: Configuration and control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ccr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ccr`]
module"]
#[doc(alias = "CCR")]
pub type Ccr = crate::Reg<ccr::CcrSpec>;
#[doc = "Configuration and control register"]
pub mod ccr;
#[doc = "SHPR1 (rw) register accessor: System handler priority registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`shpr1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`shpr1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@shpr1`]
module"]
#[doc(alias = "SHPR1")]
pub type Shpr1 = crate::Reg<shpr1::Shpr1Spec>;
#[doc = "System handler priority registers"]
pub mod shpr1;
#[doc = "SHPR2 (rw) register accessor: System handler priority registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`shpr2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`shpr2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@shpr2`]
module"]
#[doc(alias = "SHPR2")]
pub type Shpr2 = crate::Reg<shpr2::Shpr2Spec>;
#[doc = "System handler priority registers"]
pub mod shpr2;
#[doc = "SHPR3 (rw) register accessor: System handler priority registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`shpr3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`shpr3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@shpr3`]
module"]
#[doc(alias = "SHPR3")]
pub type Shpr3 = crate::Reg<shpr3::Shpr3Spec>;
#[doc = "System handler priority registers"]
pub mod shpr3;
#[doc = "SHCRS (rw) register accessor: System handler control and state register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`shcrs::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`shcrs::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@shcrs`]
module"]
#[doc(alias = "SHCRS")]
pub type Shcrs = crate::Reg<shcrs::ShcrsSpec>;
#[doc = "System handler control and state register"]
pub mod shcrs;
#[doc = "CFSR_UFSR_BFSR_MMFSR (rw) register accessor: Configurable fault status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cfsr_ufsr_bfsr_mmfsr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cfsr_ufsr_bfsr_mmfsr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cfsr_ufsr_bfsr_mmfsr`]
module"]
#[doc(alias = "CFSR_UFSR_BFSR_MMFSR")]
pub type CfsrUfsrBfsrMmfsr = crate::Reg<cfsr_ufsr_bfsr_mmfsr::CfsrUfsrBfsrMmfsrSpec>;
#[doc = "Configurable fault status register"]
pub mod cfsr_ufsr_bfsr_mmfsr;
#[doc = "HFSR (rw) register accessor: Hard fault status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hfsr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hfsr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hfsr`]
module"]
#[doc(alias = "HFSR")]
pub type Hfsr = crate::Reg<hfsr::HfsrSpec>;
#[doc = "Hard fault status register"]
pub mod hfsr;
#[doc = "MMFAR (rw) register accessor: Memory management fault address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmfar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mmfar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mmfar`]
module"]
#[doc(alias = "MMFAR")]
pub type Mmfar = crate::Reg<mmfar::MmfarSpec>;
#[doc = "Memory management fault address register"]
pub mod mmfar;
#[doc = "BFAR (rw) register accessor: Bus fault address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bfar::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bfar::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bfar`]
module"]
#[doc(alias = "BFAR")]
pub type Bfar = crate::Reg<bfar::BfarSpec>;
#[doc = "Bus fault address register"]
pub mod bfar;
#[doc = "AFSR (rw) register accessor: Auxiliary fault status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`afsr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`afsr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@afsr`]
module"]
#[doc(alias = "AFSR")]
pub type Afsr = crate::Reg<afsr::AfsrSpec>;
#[doc = "Auxiliary fault status register"]
pub mod afsr;
