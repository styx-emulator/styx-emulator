// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    rbr_thr_dll: RbrThrDll,
    ier_dlh: IerDlh,
    _reserved_2_fcr: [u8; 0x04],
    lcr: Lcr,
    mcr: Mcr,
    lsr: Lsr,
    msr: Msr,
    scr: Scr,
    _reserved8: [u8; 0x10],
    srbr: Srbr,
    sthr: Sthr,
    _reserved10: [u8; 0x38],
    far: Far,
    tfr: Tfr,
    rfw: Rfw,
    usr: Usr,
    tfl: Tfl,
    rfl: Rfl,
    srr: Srr,
    srts: Srts,
    sbcr: Sbcr,
    sdmam: Sdmam,
    sfe: Sfe,
    srt: Srt,
    stet: Stet,
    htx: Htx,
    dmasa: Dmasa,
    _reserved25: [u8; 0x48],
    cpr: Cpr,
    ucv: Ucv,
    ctr: Ctr,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - This is a multi-function register. This register holds receives and transmit data and controls the least-signficant 8 bits of the baud rate divisor."]
    #[inline(always)]
    pub const fn rbr_thr_dll(&self) -> &RbrThrDll {
        &self.rbr_thr_dll
    }
    #[doc = "0x04 - This is a multi-function register. This register enables/disables receive and transmit interrupts and also controls the most-significant 8-bits of the baud rate divisor. Divisor Latch High Register: This register is accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 1.Bits\\[7:0\\]
contain the high order 8-bits of the baud rate divisor.The output baud rate is equal to the serial clock l4_sp_clk frequency divided by sixteen times the value of the baud rate divisor, as follows: baud rate = (serial clock freq) / (16 * divisor): Note that with the Divisor Latch Registers (DLLand DLH) set to zero, the baud clock is disabled and no serial communications will occur. Also, once the DLL is set, at least 8 l4_sp_clk clock cycles should be allowed to pass before transmitting or receiving data. Interrupt Enable Register: This register may only be accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 0.Allows control of the Interrupt Enables for transmit and receive functions."]
    #[inline(always)]
    pub const fn ier_dlh(&self) -> &IerDlh {
        &self.ier_dlh
    }
    #[doc = "0x08 - Controls FIFO Operations when written."]
    #[inline(always)]
    pub const fn fcr(&self) -> &Fcr {
        unsafe { &*(self as *const Self).cast::<u8>().add(8).cast() }
    }
    #[doc = "0x08 - Returns interrupt identification and FIFO enable/disable when read."]
    #[inline(always)]
    pub const fn iir(&self) -> &Iir {
        unsafe { &*(self as *const Self).cast::<u8>().add(8).cast() }
    }
    #[doc = "0x0c - Formats serial data."]
    #[inline(always)]
    pub const fn lcr(&self) -> &Lcr {
        &self.lcr
    }
    #[doc = "0x10 - Reports various operations of the modem signals"]
    #[inline(always)]
    pub const fn mcr(&self) -> &Mcr {
        &self.mcr
    }
    #[doc = "0x14 - Reports status of transmit and receive."]
    #[inline(always)]
    pub const fn lsr(&self) -> &Lsr {
        &self.lsr
    }
    #[doc = "0x18 - It should be noted that whenever bits 0, 1, 2 or 3 are set to logic one, to indicate a change on the modem control inputs, a modem status interrupt will be generated if enabled via the IER regardless of when the change occurred. Since the delta bits (bits 0, 1, 3) can get set after a reset if their respective modem signals are active (see individual bits for details), a read of the MSR after reset can be performed to prevent unwanted interrupts."]
    #[inline(always)]
    pub const fn msr(&self) -> &Msr {
        &self.msr
    }
    #[doc = "0x1c - Scratchpad Register"]
    #[inline(always)]
    pub const fn scr(&self) -> &Scr {
        &self.scr
    }
    #[doc = "0x30 - Used to accomadate burst accesses from the master."]
    #[inline(always)]
    pub const fn srbr(&self) -> &Srbr {
        &self.srbr
    }
    #[doc = "0x34 - Used to accomadate burst accesses from the master."]
    #[inline(always)]
    pub const fn sthr(&self) -> &Sthr {
        &self.sthr
    }
    #[doc = "0x70 - This register is used in FIFO access testing."]
    #[inline(always)]
    pub const fn far(&self) -> &Far {
        &self.far
    }
    #[doc = "0x74 - Used in FIFO Access test mode."]
    #[inline(always)]
    pub const fn tfr(&self) -> &Tfr {
        &self.tfr
    }
    #[doc = "0x78 - Used only with FIFO access test mode."]
    #[inline(always)]
    pub const fn rfw(&self) -> &Rfw {
        &self.rfw
    }
    #[doc = "0x7c - Status of FIFO Operations."]
    #[inline(always)]
    pub const fn usr(&self) -> &Usr {
        &self.usr
    }
    #[doc = "0x80 - This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state."]
    #[inline(always)]
    pub const fn tfl(&self) -> &Tfl {
        &self.tfl
    }
    #[doc = "0x84 - This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state."]
    #[inline(always)]
    pub const fn rfl(&self) -> &Rfl {
        &self.rfl
    }
    #[doc = "0x88 - Provides Software Resets for Tx/Rx FIFO's and the uart."]
    #[inline(always)]
    pub const fn srr(&self) -> &Srr {
        &self.srr
    }
    #[doc = "0x8c - This is a shadow register for the RTS status (MCR\\[1\\]), this can be used to remove the burden of having to performing a read modify write on the MCR."]
    #[inline(always)]
    pub const fn srts(&self) -> &Srts {
        &self.srts
    }
    #[doc = "0x90 - This is a shadow register for the Break bit \\[6\\]
of the register LCR. This can be used to remove the burden of having to performing a read modify write on the LCR."]
    #[inline(always)]
    pub const fn sbcr(&self) -> &Sbcr {
        &self.sbcr
    }
    #[doc = "0x94 - This is a shadow register for the DMA mode bit (FCR\\[3\\])."]
    #[inline(always)]
    pub const fn sdmam(&self) -> &Sdmam {
        &self.sdmam
    }
    #[doc = "0x98 - This is a shadow register for the FIFO enable bit \\[0\\]
of register FCR."]
    #[inline(always)]
    pub const fn sfe(&self) -> &Sfe {
        &self.sfe
    }
    #[doc = "0x9c - This is a shadow register for the Rx trigger bits (FCR\\[7:6\\])."]
    #[inline(always)]
    pub const fn srt(&self) -> &Srt {
        &self.srt
    }
    #[doc = "0xa0 - This is a shadow register for the Tx empty trigger bits (FCR\\[5:4\\])."]
    #[inline(always)]
    pub const fn stet(&self) -> &Stet {
        &self.stet
    }
    #[doc = "0xa4 - Used to halt transmission for testing."]
    #[inline(always)]
    pub const fn htx(&self) -> &Htx {
        &self.htx
    }
    #[doc = "0xa8 - DMA Operation Control"]
    #[inline(always)]
    pub const fn dmasa(&self) -> &Dmasa {
        &self.dmasa
    }
    #[doc = "0xf4 - Describes various fixed hardware setups states."]
    #[inline(always)]
    pub const fn cpr(&self) -> &Cpr {
        &self.cpr
    }
    #[doc = "0xf8 - Used only with Additional Features"]
    #[inline(always)]
    pub const fn ucv(&self) -> &Ucv {
        &self.ucv
    }
    #[doc = "0xfc - Describes a hex value associated with the component."]
    #[inline(always)]
    pub const fn ctr(&self) -> &Ctr {
        &self.ctr
    }
}
#[doc = "rbr_thr_dll (rw) register accessor: This is a multi-function register. This register holds receives and transmit data and controls the least-signficant 8 bits of the baud rate divisor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rbr_thr_dll::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rbr_thr_dll::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rbr_thr_dll`]
module"]
#[doc(alias = "rbr_thr_dll")]
pub type RbrThrDll = crate::Reg<rbr_thr_dll::RbrThrDllSpec>;
#[doc = "This is a multi-function register. This register holds receives and transmit data and controls the least-signficant 8 bits of the baud rate divisor."]
pub mod rbr_thr_dll;
#[doc = "ier_dlh (rw) register accessor: This is a multi-function register. This register enables/disables receive and transmit interrupts and also controls the most-significant 8-bits of the baud rate divisor. Divisor Latch High Register: This register is accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 1.Bits\\[7:0\\]
contain the high order 8-bits of the baud rate divisor.The output baud rate is equal to the serial clock l4_sp_clk frequency divided by sixteen times the value of the baud rate divisor, as follows: baud rate = (serial clock freq) / (16 * divisor): Note that with the Divisor Latch Registers (DLLand DLH) set to zero, the baud clock is disabled and no serial communications will occur. Also, once the DLL is set, at least 8 l4_sp_clk clock cycles should be allowed to pass before transmitting or receiving data. Interrupt Enable Register: This register may only be accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 0.Allows control of the Interrupt Enables for transmit and receive functions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ier_dlh::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ier_dlh::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ier_dlh`]
module"]
#[doc(alias = "ier_dlh")]
pub type IerDlh = crate::Reg<ier_dlh::IerDlhSpec>;
#[doc = "This is a multi-function register. This register enables/disables receive and transmit interrupts and also controls the most-significant 8-bits of the baud rate divisor. Divisor Latch High Register: This register is accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 1.Bits\\[7:0\\]
contain the high order 8-bits of the baud rate divisor.The output baud rate is equal to the serial clock l4_sp_clk frequency divided by sixteen times the value of the baud rate divisor, as follows: baud rate = (serial clock freq) / (16 * divisor): Note that with the Divisor Latch Registers (DLLand DLH) set to zero, the baud clock is disabled and no serial communications will occur. Also, once the DLL is set, at least 8 l4_sp_clk clock cycles should be allowed to pass before transmitting or receiving data. Interrupt Enable Register: This register may only be accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 0.Allows control of the Interrupt Enables for transmit and receive functions."]
pub mod ier_dlh;
#[doc = "iir (r) register accessor: Returns interrupt identification and FIFO enable/disable when read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iir::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@iir`]
module"]
#[doc(alias = "iir")]
pub type Iir = crate::Reg<iir::IirSpec>;
#[doc = "Returns interrupt identification and FIFO enable/disable when read."]
pub mod iir;
#[doc = "fcr (w) register accessor: Controls FIFO Operations when written.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fcr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@fcr`]
module"]
#[doc(alias = "fcr")]
pub type Fcr = crate::Reg<fcr::FcrSpec>;
#[doc = "Controls FIFO Operations when written."]
pub mod fcr;
#[doc = "lcr (rw) register accessor: Formats serial data.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@lcr`]
module"]
#[doc(alias = "lcr")]
pub type Lcr = crate::Reg<lcr::LcrSpec>;
#[doc = "Formats serial data."]
pub mod lcr;
#[doc = "mcr (rw) register accessor: Reports various operations of the modem signals\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mcr`]
module"]
#[doc(alias = "mcr")]
pub type Mcr = crate::Reg<mcr::McrSpec>;
#[doc = "Reports various operations of the modem signals"]
pub mod mcr;
#[doc = "lsr (r) register accessor: Reports status of transmit and receive.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lsr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@lsr`]
module"]
#[doc(alias = "lsr")]
pub type Lsr = crate::Reg<lsr::LsrSpec>;
#[doc = "Reports status of transmit and receive."]
pub mod lsr;
#[doc = "msr (r) register accessor: It should be noted that whenever bits 0, 1, 2 or 3 are set to logic one, to indicate a change on the modem control inputs, a modem status interrupt will be generated if enabled via the IER regardless of when the change occurred. Since the delta bits (bits 0, 1, 3) can get set after a reset if their respective modem signals are active (see individual bits for details), a read of the MSR after reset can be performed to prevent unwanted interrupts.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msr`]
module"]
#[doc(alias = "msr")]
pub type Msr = crate::Reg<msr::MsrSpec>;
#[doc = "It should be noted that whenever bits 0, 1, 2 or 3 are set to logic one, to indicate a change on the modem control inputs, a modem status interrupt will be generated if enabled via the IER regardless of when the change occurred. Since the delta bits (bits 0, 1, 3) can get set after a reset if their respective modem signals are active (see individual bits for details), a read of the MSR after reset can be performed to prevent unwanted interrupts."]
pub mod msr;
#[doc = "scr (rw) register accessor: Scratchpad Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`scr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`scr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@scr`]
module"]
#[doc(alias = "scr")]
pub type Scr = crate::Reg<scr::ScrSpec>;
#[doc = "Scratchpad Register"]
pub mod scr;
#[doc = "srbr (rw) register accessor: Used to accomadate burst accesses from the master.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`srbr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srbr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@srbr`]
module"]
#[doc(alias = "srbr")]
pub type Srbr = crate::Reg<srbr::SrbrSpec>;
#[doc = "Used to accomadate burst accesses from the master."]
pub mod srbr;
#[doc = "sthr (rw) register accessor: Used to accomadate burst accesses from the master.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sthr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sthr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sthr`]
module"]
#[doc(alias = "sthr")]
pub type Sthr = crate::Reg<sthr::SthrSpec>;
#[doc = "Used to accomadate burst accesses from the master."]
pub mod sthr;
#[doc = "far (rw) register accessor: This register is used in FIFO access testing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`far::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`far::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@far`]
module"]
#[doc(alias = "far")]
pub type Far = crate::Reg<far::FarSpec>;
#[doc = "This register is used in FIFO access testing."]
pub mod far;
#[doc = "tfr (r) register accessor: Used in FIFO Access test mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tfr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tfr`]
module"]
#[doc(alias = "tfr")]
pub type Tfr = crate::Reg<tfr::TfrSpec>;
#[doc = "Used in FIFO Access test mode."]
pub mod tfr;
#[doc = "RFW (w) register accessor: Used only with FIFO access test mode.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rfw::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rfw`]
module"]
#[doc(alias = "RFW")]
pub type Rfw = crate::Reg<rfw::RfwSpec>;
#[doc = "Used only with FIFO access test mode."]
pub mod rfw;
#[doc = "usr (r) register accessor: Status of FIFO Operations.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`usr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@usr`]
module"]
#[doc(alias = "usr")]
pub type Usr = crate::Reg<usr::UsrSpec>;
#[doc = "Status of FIFO Operations."]
pub mod usr;
#[doc = "tfl (r) register accessor: This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tfl::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@tfl`]
module"]
#[doc(alias = "tfl")]
pub type Tfl = crate::Reg<tfl::TflSpec>;
#[doc = "This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state."]
pub mod tfl;
#[doc = "rfl (r) register accessor: This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rfl::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@rfl`]
module"]
#[doc(alias = "rfl")]
pub type Rfl = crate::Reg<rfl::RflSpec>;
#[doc = "This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state."]
pub mod rfl;
#[doc = "srr (w) register accessor: Provides Software Resets for Tx/Rx FIFO's and the uart.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srr::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@srr`]
module"]
#[doc(alias = "srr")]
pub type Srr = crate::Reg<srr::SrrSpec>;
#[doc = "Provides Software Resets for Tx/Rx FIFO's and the uart."]
pub mod srr;
#[doc = "srts (rw) register accessor: This is a shadow register for the RTS status (MCR\\[1\\]), this can be used to remove the burden of having to performing a read modify write on the MCR.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`srts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@srts`]
module"]
#[doc(alias = "srts")]
pub type Srts = crate::Reg<srts::SrtsSpec>;
#[doc = "This is a shadow register for the RTS status (MCR\\[1\\]), this can be used to remove the burden of having to performing a read modify write on the MCR."]
pub mod srts;
#[doc = "sbcr (rw) register accessor: This is a shadow register for the Break bit \\[6\\]
of the register LCR. This can be used to remove the burden of having to performing a read modify write on the LCR.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sbcr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sbcr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sbcr`]
module"]
#[doc(alias = "sbcr")]
pub type Sbcr = crate::Reg<sbcr::SbcrSpec>;
#[doc = "This is a shadow register for the Break bit \\[6\\]
of the register LCR. This can be used to remove the burden of having to performing a read modify write on the LCR."]
pub mod sbcr;
#[doc = "sdmam (rw) register accessor: This is a shadow register for the DMA mode bit (FCR\\[3\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdmam::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdmam::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sdmam`]
module"]
#[doc(alias = "sdmam")]
pub type Sdmam = crate::Reg<sdmam::SdmamSpec>;
#[doc = "This is a shadow register for the DMA mode bit (FCR\\[3\\])."]
pub mod sdmam;
#[doc = "sfe (rw) register accessor: This is a shadow register for the FIFO enable bit \\[0\\]
of register FCR.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sfe::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sfe::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@sfe`]
module"]
#[doc(alias = "sfe")]
pub type Sfe = crate::Reg<sfe::SfeSpec>;
#[doc = "This is a shadow register for the FIFO enable bit \\[0\\]
of register FCR."]
pub mod sfe;
#[doc = "srt (rw) register accessor: This is a shadow register for the Rx trigger bits (FCR\\[7:6\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`srt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@srt`]
module"]
#[doc(alias = "srt")]
pub type Srt = crate::Reg<srt::SrtSpec>;
#[doc = "This is a shadow register for the Rx trigger bits (FCR\\[7:6\\])."]
pub mod srt;
#[doc = "stet (rw) register accessor: This is a shadow register for the Tx empty trigger bits (FCR\\[5:4\\]).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stet::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stet::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@stet`]
module"]
#[doc(alias = "stet")]
pub type Stet = crate::Reg<stet::StetSpec>;
#[doc = "This is a shadow register for the Tx empty trigger bits (FCR\\[5:4\\])."]
pub mod stet;
#[doc = "htx (rw) register accessor: Used to halt transmission for testing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`htx::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`htx::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@htx`]
module"]
#[doc(alias = "htx")]
pub type Htx = crate::Reg<htx::HtxSpec>;
#[doc = "Used to halt transmission for testing."]
pub mod htx;
#[doc = "dmasa (w) register accessor: DMA Operation Control\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmasa::W`]. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@dmasa`]
module"]
#[doc(alias = "dmasa")]
pub type Dmasa = crate::Reg<dmasa::DmasaSpec>;
#[doc = "DMA Operation Control"]
pub mod dmasa;
#[doc = "cpr (r) register accessor: Describes various fixed hardware setups states.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cpr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@cpr`]
module"]
#[doc(alias = "cpr")]
pub type Cpr = crate::Reg<cpr::CprSpec>;
#[doc = "Describes various fixed hardware setups states."]
pub mod cpr;
#[doc = "ucv (r) register accessor: Used only with Additional Features\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ucv::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ucv`]
module"]
#[doc(alias = "ucv")]
pub type Ucv = crate::Reg<ucv::UcvSpec>;
#[doc = "Used only with Additional Features"]
pub mod ucv;
#[doc = "ctr (r) register accessor: Describes a hex value associated with the component.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctr`]
module"]
#[doc(alias = "ctr")]
pub type Ctr = crate::Reg<ctr::CtrSpec>;
#[doc = "Describes a hex value associated with the component."]
pub mod ctr;
