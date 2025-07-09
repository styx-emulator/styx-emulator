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
    cfg: Cfg,
    devrd: Devrd,
    devwr: Devwr,
    delay: Delay,
    rddatacap: Rddatacap,
    devsz: Devsz,
    srampart: Srampart,
    indaddrtrig: Indaddrtrig,
    dmaper: Dmaper,
    remapaddr: Remapaddr,
    modebit: Modebit,
    sramfill: Sramfill,
    txthresh: Txthresh,
    rxthresh: Rxthresh,
    _reserved14: [u8; 0x08],
    irqstat: Irqstat,
    irqmask: Irqmask,
    _reserved16: [u8; 0x08],
    lowwrprot: Lowwrprot,
    uppwrprot: Uppwrprot,
    wrprot: Wrprot,
    _reserved19: [u8; 0x04],
    indrd: Indrd,
    indrdwater: Indrdwater,
    indrdstaddr: Indrdstaddr,
    indrdcnt: Indrdcnt,
    indwr: Indwr,
    indwrwater: Indwrwater,
    indwrstaddr: Indwrstaddr,
    indwrcnt: Indwrcnt,
    _reserved27: [u8; 0x10],
    flashcmd: Flashcmd,
    flashcmdaddr: Flashcmdaddr,
    _reserved29: [u8; 0x08],
    flashcmdrddatalo: Flashcmdrddatalo,
    flashcmdrddataup: Flashcmdrddataup,
    flashcmdwrdatalo: Flashcmdwrdatalo,
    flashcmdwrdataup: Flashcmdwrdataup,
    _reserved33: [u8; 0x4c],
    moduleid: Moduleid,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - "]
    #[inline(always)]
    pub const fn cfg(&self) -> &Cfg {
        &self.cfg
    }
    #[doc = "0x04 - "]
    #[inline(always)]
    pub const fn devrd(&self) -> &Devrd {
        &self.devrd
    }
    #[doc = "0x08 - "]
    #[inline(always)]
    pub const fn devwr(&self) -> &Devwr {
        &self.devwr
    }
    #[doc = "0x0c - This register is used to introduce relative delays into the generation of the master output signals. All timings are defined in cycles of the qspi_clk."]
    #[inline(always)]
    pub const fn delay(&self) -> &Delay {
        &self.delay
    }
    #[doc = "0x10 - "]
    #[inline(always)]
    pub const fn rddatacap(&self) -> &Rddatacap {
        &self.rddatacap
    }
    #[doc = "0x14 - "]
    #[inline(always)]
    pub const fn devsz(&self) -> &Devsz {
        &self.devsz
    }
    #[doc = "0x18 - "]
    #[inline(always)]
    pub const fn srampart(&self) -> &Srampart {
        &self.srampart
    }
    #[doc = "0x1c - "]
    #[inline(always)]
    pub const fn indaddrtrig(&self) -> &Indaddrtrig {
        &self.indaddrtrig
    }
    #[doc = "0x20 - "]
    #[inline(always)]
    pub const fn dmaper(&self) -> &Dmaper {
        &self.dmaper
    }
    #[doc = "0x24 - This register is used to remap an incoming AHB address to a different address used by the FLASH device."]
    #[inline(always)]
    pub const fn remapaddr(&self) -> &Remapaddr {
        &self.remapaddr
    }
    #[doc = "0x28 - "]
    #[inline(always)]
    pub const fn modebit(&self) -> &Modebit {
        &self.modebit
    }
    #[doc = "0x2c - "]
    #[inline(always)]
    pub const fn sramfill(&self) -> &Sramfill {
        &self.sramfill
    }
    #[doc = "0x30 - "]
    #[inline(always)]
    pub const fn txthresh(&self) -> &Txthresh {
        &self.txthresh
    }
    #[doc = "0x34 - Device Instruction Register"]
    #[inline(always)]
    pub const fn rxthresh(&self) -> &Rxthresh {
        &self.rxthresh
    }
    #[doc = "0x40 - The status fields in this register are set when the described event occurs and the interrupt is enabled in the mask register. When any of these bit fields are set, the interrupt output is asserted high. The fields are each cleared by writing a 1 to the field. Note that bit fields 7 thru 11 are only valid when legacy SPI mode is active."]
    #[inline(always)]
    pub const fn irqstat(&self) -> &Irqstat {
        &self.irqstat
    }
    #[doc = "0x44 - If disabled, the interrupt for the corresponding interrupt status register bit is disabled. If enabled, the interrupt for the corresponding interrupt status register bit is enabled."]
    #[inline(always)]
    pub const fn irqmask(&self) -> &Irqmask {
        &self.irqmask
    }
    #[doc = "0x50 - "]
    #[inline(always)]
    pub const fn lowwrprot(&self) -> &Lowwrprot {
        &self.lowwrprot
    }
    #[doc = "0x54 - "]
    #[inline(always)]
    pub const fn uppwrprot(&self) -> &Uppwrprot {
        &self.uppwrprot
    }
    #[doc = "0x58 - "]
    #[inline(always)]
    pub const fn wrprot(&self) -> &Wrprot {
        &self.wrprot
    }
    #[doc = "0x60 - "]
    #[inline(always)]
    pub const fn indrd(&self) -> &Indrd {
        &self.indrd
    }
    #[doc = "0x64 - "]
    #[inline(always)]
    pub const fn indrdwater(&self) -> &Indrdwater {
        &self.indrdwater
    }
    #[doc = "0x68 - "]
    #[inline(always)]
    pub const fn indrdstaddr(&self) -> &Indrdstaddr {
        &self.indrdstaddr
    }
    #[doc = "0x6c - "]
    #[inline(always)]
    pub const fn indrdcnt(&self) -> &Indrdcnt {
        &self.indrdcnt
    }
    #[doc = "0x70 - "]
    #[inline(always)]
    pub const fn indwr(&self) -> &Indwr {
        &self.indwr
    }
    #[doc = "0x74 - "]
    #[inline(always)]
    pub const fn indwrwater(&self) -> &Indwrwater {
        &self.indwrwater
    }
    #[doc = "0x78 - "]
    #[inline(always)]
    pub const fn indwrstaddr(&self) -> &Indwrstaddr {
        &self.indwrstaddr
    }
    #[doc = "0x7c - "]
    #[inline(always)]
    pub const fn indwrcnt(&self) -> &Indwrcnt {
        &self.indwrcnt
    }
    #[doc = "0x90 - "]
    #[inline(always)]
    pub const fn flashcmd(&self) -> &Flashcmd {
        &self.flashcmd
    }
    #[doc = "0x94 - "]
    #[inline(always)]
    pub const fn flashcmdaddr(&self) -> &Flashcmdaddr {
        &self.flashcmdaddr
    }
    #[doc = "0xa0 - "]
    #[inline(always)]
    pub const fn flashcmdrddatalo(&self) -> &Flashcmdrddatalo {
        &self.flashcmdrddatalo
    }
    #[doc = "0xa4 - Device Instruction Register"]
    #[inline(always)]
    pub const fn flashcmdrddataup(&self) -> &Flashcmdrddataup {
        &self.flashcmdrddataup
    }
    #[doc = "0xa8 - "]
    #[inline(always)]
    pub const fn flashcmdwrdatalo(&self) -> &Flashcmdwrdatalo {
        &self.flashcmdwrdatalo
    }
    #[doc = "0xac - "]
    #[inline(always)]
    pub const fn flashcmdwrdataup(&self) -> &Flashcmdwrdataup {
        &self.flashcmdwrdataup
    }
    #[doc = "0xfc - "]
    #[inline(always)]
    pub const fn moduleid(&self) -> &Moduleid {
        &self.moduleid
    }
}
#[doc = "cfg (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
#[doc(alias = "cfg")]
pub type Cfg = crate::Reg<cfg::CfgSpec>;
#[doc = ""]
pub mod cfg;
#[doc = "devrd (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devrd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devrd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devrd`]
module"]
#[doc(alias = "devrd")]
pub type Devrd = crate::Reg<devrd::DevrdSpec>;
#[doc = ""]
pub mod devrd;
#[doc = "devwr (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devwr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devwr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devwr`]
module"]
#[doc(alias = "devwr")]
pub type Devwr = crate::Reg<devwr::DevwrSpec>;
#[doc = ""]
pub mod devwr;
#[doc = "delay (rw) register accessor: This register is used to introduce relative delays into the generation of the master output signals. All timings are defined in cycles of the qspi_clk.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`delay::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`delay::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@delay`]
module"]
#[doc(alias = "delay")]
pub type Delay = crate::Reg<delay::DelaySpec>;
#[doc = "This register is used to introduce relative delays into the generation of the master output signals. All timings are defined in cycles of the qspi_clk."]
pub mod delay;
#[doc = "rddatacap (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rddatacap::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rddatacap::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rddatacap`]
module"]
#[doc(alias = "rddatacap")]
pub type Rddatacap = crate::Reg<rddatacap::RddatacapSpec>;
#[doc = ""]
pub mod rddatacap;
#[doc = "devsz (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devsz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devsz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devsz`]
module"]
#[doc(alias = "devsz")]
pub type Devsz = crate::Reg<devsz::DevszSpec>;
#[doc = ""]
pub mod devsz;
#[doc = "srampart (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`srampart::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srampart::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@srampart`]
module"]
#[doc(alias = "srampart")]
pub type Srampart = crate::Reg<srampart::SrampartSpec>;
#[doc = ""]
pub mod srampart;
#[doc = "indaddrtrig (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indaddrtrig::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indaddrtrig::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indaddrtrig`]
module"]
#[doc(alias = "indaddrtrig")]
pub type Indaddrtrig = crate::Reg<indaddrtrig::IndaddrtrigSpec>;
#[doc = ""]
pub mod indaddrtrig;
#[doc = "dmaper (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmaper::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmaper::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmaper`]
module"]
#[doc(alias = "dmaper")]
pub type Dmaper = crate::Reg<dmaper::DmaperSpec>;
#[doc = ""]
pub mod dmaper;
#[doc = "remapaddr (rw) register accessor: This register is used to remap an incoming AHB address to a different address used by the FLASH device.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`remapaddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`remapaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@remapaddr`]
module"]
#[doc(alias = "remapaddr")]
pub type Remapaddr = crate::Reg<remapaddr::RemapaddrSpec>;
#[doc = "This register is used to remap an incoming AHB address to a different address used by the FLASH device."]
pub mod remapaddr;
#[doc = "modebit (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`modebit::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`modebit::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@modebit`]
module"]
#[doc(alias = "modebit")]
pub type Modebit = crate::Reg<modebit::ModebitSpec>;
#[doc = ""]
pub mod modebit;
#[doc = "sramfill (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sramfill::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sramfill`]
module"]
#[doc(alias = "sramfill")]
pub type Sramfill = crate::Reg<sramfill::SramfillSpec>;
#[doc = ""]
pub mod sramfill;
#[doc = "txthresh (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txthresh::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`txthresh::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@txthresh`]
module"]
#[doc(alias = "txthresh")]
pub type Txthresh = crate::Reg<txthresh::TxthreshSpec>;
#[doc = ""]
pub mod txthresh;
#[doc = "rxthresh (rw) register accessor: Device Instruction Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxthresh::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rxthresh::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rxthresh`]
module"]
#[doc(alias = "rxthresh")]
pub type Rxthresh = crate::Reg<rxthresh::RxthreshSpec>;
#[doc = "Device Instruction Register"]
pub mod rxthresh;
#[doc = "irqstat (rw) register accessor: The status fields in this register are set when the described event occurs and the interrupt is enabled in the mask register. When any of these bit fields are set, the interrupt output is asserted high. The fields are each cleared by writing a 1 to the field. Note that bit fields 7 thru 11 are only valid when legacy SPI mode is active.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`irqstat::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`irqstat::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@irqstat`]
module"]
#[doc(alias = "irqstat")]
pub type Irqstat = crate::Reg<irqstat::IrqstatSpec>;
#[doc = "The status fields in this register are set when the described event occurs and the interrupt is enabled in the mask register. When any of these bit fields are set, the interrupt output is asserted high. The fields are each cleared by writing a 1 to the field. Note that bit fields 7 thru 11 are only valid when legacy SPI mode is active."]
pub mod irqstat;
#[doc = "irqmask (rw) register accessor: If disabled, the interrupt for the corresponding interrupt status register bit is disabled. If enabled, the interrupt for the corresponding interrupt status register bit is enabled.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`irqmask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`irqmask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@irqmask`]
module"]
#[doc(alias = "irqmask")]
pub type Irqmask = crate::Reg<irqmask::IrqmaskSpec>;
#[doc = "If disabled, the interrupt for the corresponding interrupt status register bit is disabled. If enabled, the interrupt for the corresponding interrupt status register bit is enabled."]
pub mod irqmask;
#[doc = "lowwrprot (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lowwrprot::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lowwrprot::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@lowwrprot`]
module"]
#[doc(alias = "lowwrprot")]
pub type Lowwrprot = crate::Reg<lowwrprot::LowwrprotSpec>;
#[doc = ""]
pub mod lowwrprot;
#[doc = "uppwrprot (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`uppwrprot::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`uppwrprot::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@uppwrprot`]
module"]
#[doc(alias = "uppwrprot")]
pub type Uppwrprot = crate::Reg<uppwrprot::UppwrprotSpec>;
#[doc = ""]
pub mod uppwrprot;
#[doc = "wrprot (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wrprot::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wrprot::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wrprot`]
module"]
#[doc(alias = "wrprot")]
pub type Wrprot = crate::Reg<wrprot::WrprotSpec>;
#[doc = ""]
pub mod wrprot;
#[doc = "indrd (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indrd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indrd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indrd`]
module"]
#[doc(alias = "indrd")]
pub type Indrd = crate::Reg<indrd::IndrdSpec>;
#[doc = ""]
pub mod indrd;
#[doc = "indrdwater (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indrdwater::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indrdwater::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indrdwater`]
module"]
#[doc(alias = "indrdwater")]
pub type Indrdwater = crate::Reg<indrdwater::IndrdwaterSpec>;
#[doc = ""]
pub mod indrdwater;
#[doc = "indrdstaddr (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indrdstaddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indrdstaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indrdstaddr`]
module"]
#[doc(alias = "indrdstaddr")]
pub type Indrdstaddr = crate::Reg<indrdstaddr::IndrdstaddrSpec>;
#[doc = ""]
pub mod indrdstaddr;
#[doc = "indrdcnt (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indrdcnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indrdcnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indrdcnt`]
module"]
#[doc(alias = "indrdcnt")]
pub type Indrdcnt = crate::Reg<indrdcnt::IndrdcntSpec>;
#[doc = ""]
pub mod indrdcnt;
#[doc = "indwr (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indwr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indwr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indwr`]
module"]
#[doc(alias = "indwr")]
pub type Indwr = crate::Reg<indwr::IndwrSpec>;
#[doc = ""]
pub mod indwr;
#[doc = "indwrwater (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indwrwater::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indwrwater::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indwrwater`]
module"]
#[doc(alias = "indwrwater")]
pub type Indwrwater = crate::Reg<indwrwater::IndwrwaterSpec>;
#[doc = ""]
pub mod indwrwater;
#[doc = "indwrstaddr (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indwrstaddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indwrstaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indwrstaddr`]
module"]
#[doc(alias = "indwrstaddr")]
pub type Indwrstaddr = crate::Reg<indwrstaddr::IndwrstaddrSpec>;
#[doc = ""]
pub mod indwrstaddr;
#[doc = "indwrcnt (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indwrcnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indwrcnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@indwrcnt`]
module"]
#[doc(alias = "indwrcnt")]
pub type Indwrcnt = crate::Reg<indwrcnt::IndwrcntSpec>;
#[doc = ""]
pub mod indwrcnt;
#[doc = "flashcmd (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@flashcmd`]
module"]
#[doc(alias = "flashcmd")]
pub type Flashcmd = crate::Reg<flashcmd::FlashcmdSpec>;
#[doc = ""]
pub mod flashcmd;
#[doc = "flashcmdaddr (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmdaddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmdaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@flashcmdaddr`]
module"]
#[doc(alias = "flashcmdaddr")]
pub type Flashcmdaddr = crate::Reg<flashcmdaddr::FlashcmdaddrSpec>;
#[doc = ""]
pub mod flashcmdaddr;
#[doc = "flashcmdrddatalo (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmdrddatalo::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmdrddatalo::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@flashcmdrddatalo`]
module"]
#[doc(alias = "flashcmdrddatalo")]
pub type Flashcmdrddatalo = crate::Reg<flashcmdrddatalo::FlashcmdrddataloSpec>;
#[doc = ""]
pub mod flashcmdrddatalo;
#[doc = "flashcmdrddataup (rw) register accessor: Device Instruction Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmdrddataup::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmdrddataup::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@flashcmdrddataup`]
module"]
#[doc(alias = "flashcmdrddataup")]
pub type Flashcmdrddataup = crate::Reg<flashcmdrddataup::FlashcmdrddataupSpec>;
#[doc = "Device Instruction Register"]
pub mod flashcmdrddataup;
#[doc = "flashcmdwrdatalo (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmdwrdatalo::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmdwrdatalo::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@flashcmdwrdatalo`]
module"]
#[doc(alias = "flashcmdwrdatalo")]
pub type Flashcmdwrdatalo = crate::Reg<flashcmdwrdatalo::FlashcmdwrdataloSpec>;
#[doc = ""]
pub mod flashcmdwrdatalo;
#[doc = "flashcmdwrdataup (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`flashcmdwrdataup::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`flashcmdwrdataup::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@flashcmdwrdataup`]
module"]
#[doc(alias = "flashcmdwrdataup")]
pub type Flashcmdwrdataup = crate::Reg<flashcmdwrdataup::FlashcmdwrdataupSpec>;
#[doc = ""]
pub mod flashcmdwrdataup;
#[doc = "moduleid (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`moduleid::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@moduleid`]
module"]
#[doc(alias = "moduleid")]
pub type Moduleid = crate::Reg<moduleid::ModuleidSpec>;
#[doc = ""]
pub mod moduleid;
