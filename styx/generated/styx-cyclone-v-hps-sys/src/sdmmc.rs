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
    ctrl: Ctrl,
    pwren: Pwren,
    clkdiv: Clkdiv,
    clksrc: Clksrc,
    clkena: Clkena,
    tmout: Tmout,
    ctype: Ctype,
    blksiz: Blksiz,
    bytcnt: Bytcnt,
    intmask: Intmask,
    cmdarg: Cmdarg,
    cmd: Cmd,
    resp0: Resp0,
    resp1: Resp1,
    resp2: Resp2,
    resp3: Resp3,
    mintsts: Mintsts,
    rintsts: Rintsts,
    status: Status,
    fifoth: Fifoth,
    cdetect: Cdetect,
    wrtprt: Wrtprt,
    _reserved22: [u8; 0x04],
    tcbcnt: Tcbcnt,
    tbbcnt: Tbbcnt,
    debnce: Debnce,
    usrid: Usrid,
    verid: Verid,
    hcon: Hcon,
    uhs_reg: UhsReg,
    rst_n: RstN,
    _reserved30: [u8; 0x04],
    bmod: Bmod,
    pldmnd: Pldmnd,
    dbaddr: Dbaddr,
    idsts: Idsts,
    idinten: Idinten,
    dscaddr: Dscaddr,
    bufaddr: Bufaddr,
    _reserved37: [u8; 0x64],
    cardthrctl: Cardthrctl,
    back_end_power_r: BackEndPowerR,
    _reserved39: [u8; 0xf8],
    data: Data,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Sets various operating condiitions."]
    #[inline(always)]
    pub const fn ctrl(&self) -> &Ctrl {
        &self.ctrl
    }
    #[doc = "0x04 - Power on/off switch for card; once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card."]
    #[inline(always)]
    pub const fn pwren(&self) -> &Pwren {
        &self.pwren
    }
    #[doc = "0x08 - Divides Clock sdmmc_clk."]
    #[inline(always)]
    pub const fn clkdiv(&self) -> &Clkdiv {
        &self.clkdiv
    }
    #[doc = "0x0c - Selects among available clock dividers. The sdmmc_cclk_out is always from clock divider 0."]
    #[inline(always)]
    pub const fn clksrc(&self) -> &Clksrc {
        &self.clksrc
    }
    #[doc = "0x10 - Controls external SD/MMC Clock Enable."]
    #[inline(always)]
    pub const fn clkena(&self) -> &Clkena {
        &self.clkena
    }
    #[doc = "0x14 - Sets timeout values"]
    #[inline(always)]
    pub const fn tmout(&self) -> &Tmout {
        &self.tmout
    }
    #[doc = "0x18 - Describes card formats."]
    #[inline(always)]
    pub const fn ctype(&self) -> &Ctype {
        &self.ctype
    }
    #[doc = "0x1c - The Block Size."]
    #[inline(always)]
    pub const fn blksiz(&self) -> &Blksiz {
        &self.blksiz
    }
    #[doc = "0x20 - The number of bytes to be transferred."]
    #[inline(always)]
    pub const fn bytcnt(&self) -> &Bytcnt {
        &self.bytcnt
    }
    #[doc = "0x24 - Allows Masking of Various Interrupts"]
    #[inline(always)]
    pub const fn intmask(&self) -> &Intmask {
        &self.intmask
    }
    #[doc = "0x28 - See Field Description."]
    #[inline(always)]
    pub const fn cmdarg(&self) -> &Cmdarg {
        &self.cmdarg
    }
    #[doc = "0x2c - This register issues various commands."]
    #[inline(always)]
    pub const fn cmd(&self) -> &Cmd {
        &self.cmd
    }
    #[doc = "0x30 - Preserves previous command."]
    #[inline(always)]
    pub const fn resp0(&self) -> &Resp0 {
        &self.resp0
    }
    #[doc = "0x34 - "]
    #[inline(always)]
    pub const fn resp1(&self) -> &Resp1 {
        &self.resp1
    }
    #[doc = "0x38 - "]
    #[inline(always)]
    pub const fn resp2(&self) -> &Resp2 {
        &self.resp2
    }
    #[doc = "0x3c - "]
    #[inline(always)]
    pub const fn resp3(&self) -> &Resp3 {
        &self.resp3
    }
    #[doc = "0x40 - Describes state of Masked Interrupt Register."]
    #[inline(always)]
    pub const fn mintsts(&self) -> &Mintsts {
        &self.mintsts
    }
    #[doc = "0x44 - Interrupt Status Before Masking."]
    #[inline(always)]
    pub const fn rintsts(&self) -> &Rintsts {
        &self.rintsts
    }
    #[doc = "0x48 - Reports various operting status conditions."]
    #[inline(always)]
    pub const fn status(&self) -> &Status {
        &self.status
    }
    #[doc = "0x4c - DMA and FIFO Control Fields."]
    #[inline(always)]
    pub const fn fifoth(&self) -> &Fifoth {
        &self.fifoth
    }
    #[doc = "0x50 - Determines if card is present."]
    #[inline(always)]
    pub const fn cdetect(&self) -> &Cdetect {
        &self.cdetect
    }
    #[doc = "0x54 - See Field Description."]
    #[inline(always)]
    pub const fn wrtprt(&self) -> &Wrtprt {
        &self.wrtprt
    }
    #[doc = "0x5c - "]
    #[inline(always)]
    pub const fn tcbcnt(&self) -> &Tcbcnt {
        &self.tcbcnt
    }
    #[doc = "0x60 - Tracks number of bytes transferred between Host and FIFO."]
    #[inline(always)]
    pub const fn tbbcnt(&self) -> &Tbbcnt {
        &self.tbbcnt
    }
    #[doc = "0x64 - "]
    #[inline(always)]
    pub const fn debnce(&self) -> &Debnce {
        &self.debnce
    }
    #[doc = "0x68 - "]
    #[inline(always)]
    pub const fn usrid(&self) -> &Usrid {
        &self.usrid
    }
    #[doc = "0x6c - "]
    #[inline(always)]
    pub const fn verid(&self) -> &Verid {
        &self.verid
    }
    #[doc = "0x70 - Hardware configurations registers. Register can be used to develop configuration-independent software drivers."]
    #[inline(always)]
    pub const fn hcon(&self) -> &Hcon {
        &self.hcon
    }
    #[doc = "0x74 - UHS-1 Register"]
    #[inline(always)]
    pub const fn uhs_reg(&self) -> &UhsReg {
        &self.uhs_reg
    }
    #[doc = "0x78 - "]
    #[inline(always)]
    pub const fn rst_n(&self) -> &RstN {
        &self.rst_n
    }
    #[doc = "0x80 - Details different bus operating modes."]
    #[inline(always)]
    pub const fn bmod(&self) -> &Bmod {
        &self.bmod
    }
    #[doc = "0x84 - See Field Description."]
    #[inline(always)]
    pub const fn pldmnd(&self) -> &Pldmnd {
        &self.pldmnd
    }
    #[doc = "0x88 - See Field Descriptor"]
    #[inline(always)]
    pub const fn dbaddr(&self) -> &Dbaddr {
        &self.dbaddr
    }
    #[doc = "0x8c - Sets Internal DMAC Status Fields"]
    #[inline(always)]
    pub const fn idsts(&self) -> &Idsts {
        &self.idsts
    }
    #[doc = "0x90 - Various DMA Interrupt Enable Status"]
    #[inline(always)]
    pub const fn idinten(&self) -> &Idinten {
        &self.idinten
    }
    #[doc = "0x94 - See Field Description."]
    #[inline(always)]
    pub const fn dscaddr(&self) -> &Dscaddr {
        &self.dscaddr
    }
    #[doc = "0x98 - See Field Description."]
    #[inline(always)]
    pub const fn bufaddr(&self) -> &Bufaddr {
        &self.bufaddr
    }
    #[doc = "0x100 - See Field descriptions"]
    #[inline(always)]
    pub const fn cardthrctl(&self) -> &Cardthrctl {
        &self.cardthrctl
    }
    #[doc = "0x104 - See Field Description"]
    #[inline(always)]
    pub const fn back_end_power_r(&self) -> &BackEndPowerR {
        &self.back_end_power_r
    }
    #[doc = "0x200 - Provides read/write access to data FIFO. Addresses 0x200 and above are mapped to the data FIFO. More than one address is mapped to data FIFO so that FIFO can be accessed using bursts."]
    #[inline(always)]
    pub const fn data(&self) -> &Data {
        &self.data
    }
}
#[doc = "ctrl (rw) register accessor: Sets various operating condiitions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrl`]
module"]
#[doc(alias = "ctrl")]
pub type Ctrl = crate::Reg<ctrl::CtrlSpec>;
#[doc = "Sets various operating condiitions."]
pub mod ctrl;
#[doc = "pwren (rw) register accessor: Power on/off switch for card; once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pwren::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pwren::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pwren`]
module"]
#[doc(alias = "pwren")]
pub type Pwren = crate::Reg<pwren::PwrenSpec>;
#[doc = "Power on/off switch for card; once power is turned on, firmware should wait for regulator/switch ramp-up time before trying to initialize card."]
pub mod pwren;
#[doc = "clkdiv (rw) register accessor: Divides Clock sdmmc_clk.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clkdiv::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`clkdiv::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@clkdiv`]
module"]
#[doc(alias = "clkdiv")]
pub type Clkdiv = crate::Reg<clkdiv::ClkdivSpec>;
#[doc = "Divides Clock sdmmc_clk."]
pub mod clkdiv;
#[doc = "clksrc (rw) register accessor: Selects among available clock dividers. The sdmmc_cclk_out is always from clock divider 0.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clksrc::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`clksrc::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@clksrc`]
module"]
#[doc(alias = "clksrc")]
pub type Clksrc = crate::Reg<clksrc::ClksrcSpec>;
#[doc = "Selects among available clock dividers. The sdmmc_cclk_out is always from clock divider 0."]
pub mod clksrc;
#[doc = "clkena (rw) register accessor: Controls external SD/MMC Clock Enable.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clkena::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`clkena::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@clkena`]
module"]
#[doc(alias = "clkena")]
pub type Clkena = crate::Reg<clkena::ClkenaSpec>;
#[doc = "Controls external SD/MMC Clock Enable."]
pub mod clkena;
#[doc = "tmout (rw) register accessor: Sets timeout values\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tmout::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tmout::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tmout`]
module"]
#[doc(alias = "tmout")]
pub type Tmout = crate::Reg<tmout::TmoutSpec>;
#[doc = "Sets timeout values"]
pub mod tmout;
#[doc = "ctype (rw) register accessor: Describes card formats.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctype::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctype::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctype`]
module"]
#[doc(alias = "ctype")]
pub type Ctype = crate::Reg<ctype::CtypeSpec>;
#[doc = "Describes card formats."]
pub mod ctype;
#[doc = "blksiz (rw) register accessor: The Block Size.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`blksiz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`blksiz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@blksiz`]
module"]
#[doc(alias = "blksiz")]
pub type Blksiz = crate::Reg<blksiz::BlksizSpec>;
#[doc = "The Block Size."]
pub mod blksiz;
#[doc = "bytcnt (rw) register accessor: The number of bytes to be transferred.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bytcnt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bytcnt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bytcnt`]
module"]
#[doc(alias = "bytcnt")]
pub type Bytcnt = crate::Reg<bytcnt::BytcntSpec>;
#[doc = "The number of bytes to be transferred."]
pub mod bytcnt;
#[doc = "intmask (rw) register accessor: Allows Masking of Various Interrupts\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`intmask::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`intmask::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@intmask`]
module"]
#[doc(alias = "intmask")]
pub type Intmask = crate::Reg<intmask::IntmaskSpec>;
#[doc = "Allows Masking of Various Interrupts"]
pub mod intmask;
#[doc = "cmdarg (rw) register accessor: See Field Description.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cmdarg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cmdarg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cmdarg`]
module"]
#[doc(alias = "cmdarg")]
pub type Cmdarg = crate::Reg<cmdarg::CmdargSpec>;
#[doc = "See Field Description."]
pub mod cmdarg;
#[doc = "cmd (rw) register accessor: This register issues various commands.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cmd::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cmd::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cmd`]
module"]
#[doc(alias = "cmd")]
pub type Cmd = crate::Reg<cmd::CmdSpec>;
#[doc = "This register issues various commands."]
pub mod cmd;
#[doc = "resp0 (r) register accessor: Preserves previous command.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@resp0`]
module"]
#[doc(alias = "resp0")]
pub type Resp0 = crate::Reg<resp0::Resp0Spec>;
#[doc = "Preserves previous command."]
pub mod resp0;
#[doc = "resp1 (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@resp1`]
module"]
#[doc(alias = "resp1")]
pub type Resp1 = crate::Reg<resp1::Resp1Spec>;
#[doc = ""]
pub mod resp1;
#[doc = "resp2 (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@resp2`]
module"]
#[doc(alias = "resp2")]
pub type Resp2 = crate::Reg<resp2::Resp2Spec>;
#[doc = ""]
pub mod resp2;
#[doc = "resp3 (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@resp3`]
module"]
#[doc(alias = "resp3")]
pub type Resp3 = crate::Reg<resp3::Resp3Spec>;
#[doc = ""]
pub mod resp3;
#[doc = "mintsts (r) register accessor: Describes state of Masked Interrupt Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mintsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mintsts`]
module"]
#[doc(alias = "mintsts")]
pub type Mintsts = crate::Reg<mintsts::MintstsSpec>;
#[doc = "Describes state of Masked Interrupt Register."]
pub mod mintsts;
#[doc = "rintsts (rw) register accessor: Interrupt Status Before Masking.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rintsts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rintsts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rintsts`]
module"]
#[doc(alias = "rintsts")]
pub type Rintsts = crate::Reg<rintsts::RintstsSpec>;
#[doc = "Interrupt Status Before Masking."]
pub mod rintsts;
#[doc = "status (r) register accessor: Reports various operting status conditions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@status`]
module"]
#[doc(alias = "status")]
pub type Status = crate::Reg<status::StatusSpec>;
#[doc = "Reports various operting status conditions."]
pub mod status;
#[doc = "fifoth (rw) register accessor: DMA and FIFO Control Fields.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifoth::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifoth::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fifoth`]
module"]
#[doc(alias = "fifoth")]
pub type Fifoth = crate::Reg<fifoth::FifothSpec>;
#[doc = "DMA and FIFO Control Fields."]
pub mod fifoth;
#[doc = "cdetect (r) register accessor: Determines if card is present.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cdetect::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cdetect`]
module"]
#[doc(alias = "cdetect")]
pub type Cdetect = crate::Reg<cdetect::CdetectSpec>;
#[doc = "Determines if card is present."]
pub mod cdetect;
#[doc = "wrtprt (r) register accessor: See Field Description.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wrtprt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@wrtprt`]
module"]
#[doc(alias = "wrtprt")]
pub type Wrtprt = crate::Reg<wrtprt::WrtprtSpec>;
#[doc = "See Field Description."]
pub mod wrtprt;
#[doc = "tcbcnt (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tcbcnt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tcbcnt`]
module"]
#[doc(alias = "tcbcnt")]
pub type Tcbcnt = crate::Reg<tcbcnt::TcbcntSpec>;
#[doc = ""]
pub mod tcbcnt;
#[doc = "tbbcnt (r) register accessor: Tracks number of bytes transferred between Host and FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tbbcnt::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tbbcnt`]
module"]
#[doc(alias = "tbbcnt")]
pub type Tbbcnt = crate::Reg<tbbcnt::TbbcntSpec>;
#[doc = "Tracks number of bytes transferred between Host and FIFO."]
pub mod tbbcnt;
#[doc = "debnce (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`debnce::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`debnce::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@debnce`]
module"]
#[doc(alias = "debnce")]
pub type Debnce = crate::Reg<debnce::DebnceSpec>;
#[doc = ""]
pub mod debnce;
#[doc = "usrid (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`usrid::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`usrid::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@usrid`]
module"]
#[doc(alias = "usrid")]
pub type Usrid = crate::Reg<usrid::UsridSpec>;
#[doc = ""]
pub mod usrid;
#[doc = "verid (r) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`verid::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@verid`]
module"]
#[doc(alias = "verid")]
pub type Verid = crate::Reg<verid::VeridSpec>;
#[doc = ""]
pub mod verid;
#[doc = "hcon (r) register accessor: Hardware configurations registers. Register can be used to develop configuration-independent software drivers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hcon::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hcon`]
module"]
#[doc(alias = "hcon")]
pub type Hcon = crate::Reg<hcon::HconSpec>;
#[doc = "Hardware configurations registers. Register can be used to develop configuration-independent software drivers."]
pub mod hcon;
#[doc = "uhs_reg (rw) register accessor: UHS-1 Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`uhs_reg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`uhs_reg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@uhs_reg`]
module"]
#[doc(alias = "uhs_reg")]
pub type UhsReg = crate::Reg<uhs_reg::UhsRegSpec>;
#[doc = "UHS-1 Register"]
pub mod uhs_reg;
#[doc = "rst_n (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rst_n::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rst_n::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rst_n`]
module"]
#[doc(alias = "rst_n")]
pub type RstN = crate::Reg<rst_n::RstNSpec>;
#[doc = ""]
pub mod rst_n;
#[doc = "bmod (rw) register accessor: Details different bus operating modes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bmod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bmod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bmod`]
module"]
#[doc(alias = "bmod")]
pub type Bmod = crate::Reg<bmod::BmodSpec>;
#[doc = "Details different bus operating modes."]
pub mod bmod;
#[doc = "pldmnd (w) register accessor: See Field Description.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pldmnd::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pldmnd`]
module"]
#[doc(alias = "pldmnd")]
pub type Pldmnd = crate::Reg<pldmnd::PldmndSpec>;
#[doc = "See Field Description."]
pub mod pldmnd;
#[doc = "dbaddr (rw) register accessor: See Field Descriptor\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbaddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dbaddr`]
module"]
#[doc(alias = "dbaddr")]
pub type Dbaddr = crate::Reg<dbaddr::DbaddrSpec>;
#[doc = "See Field Descriptor"]
pub mod dbaddr;
#[doc = "idsts (rw) register accessor: Sets Internal DMAC Status Fields\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idsts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`idsts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idsts`]
module"]
#[doc(alias = "idsts")]
pub type Idsts = crate::Reg<idsts::IdstsSpec>;
#[doc = "Sets Internal DMAC Status Fields"]
pub mod idsts;
#[doc = "idinten (rw) register accessor: Various DMA Interrupt Enable Status\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idinten::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`idinten::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idinten`]
module"]
#[doc(alias = "idinten")]
pub type Idinten = crate::Reg<idinten::IdintenSpec>;
#[doc = "Various DMA Interrupt Enable Status"]
pub mod idinten;
#[doc = "dscaddr (r) register accessor: See Field Description.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dscaddr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dscaddr`]
module"]
#[doc(alias = "dscaddr")]
pub type Dscaddr = crate::Reg<dscaddr::DscaddrSpec>;
#[doc = "See Field Description."]
pub mod dscaddr;
#[doc = "bufaddr (r) register accessor: See Field Description.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bufaddr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@bufaddr`]
module"]
#[doc(alias = "bufaddr")]
pub type Bufaddr = crate::Reg<bufaddr::BufaddrSpec>;
#[doc = "See Field Description."]
pub mod bufaddr;
#[doc = "cardthrctl (rw) register accessor: See Field descriptions\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cardthrctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cardthrctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cardthrctl`]
module"]
#[doc(alias = "cardthrctl")]
pub type Cardthrctl = crate::Reg<cardthrctl::CardthrctlSpec>;
#[doc = "See Field descriptions"]
pub mod cardthrctl;
#[doc = "back_end_power_r (rw) register accessor: See Field Description\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`back_end_power_r::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`back_end_power_r::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@back_end_power_r`]
module"]
#[doc(alias = "back_end_power_r")]
pub type BackEndPowerR = crate::Reg<back_end_power_r::BackEndPowerRSpec>;
#[doc = "See Field Description"]
pub mod back_end_power_r;
#[doc = "data (rw) register accessor: Provides read/write access to data FIFO. Addresses 0x200 and above are mapped to the data FIFO. More than one address is mapped to data FIFO so that FIFO can be accessed using bursts.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`data::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`data::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@data`]
module"]
#[doc(alias = "data")]
pub type Data = crate::Reg<data::DataSpec>;
#[doc = "Provides read/write access to data FIFO. Addresses 0x200 and above are mapped to the data FIFO. More than one address is mapped to data FIFO so that FIFO can be accessed using bursts."]
pub mod data;
