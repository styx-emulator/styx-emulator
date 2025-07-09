// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    _reserved0: [u8; 0x5000],
    ctrlgrp_ctrlcfg: CtrlgrpCtrlcfg,
    ctrlgrp_dramtiming1: CtrlgrpDramtiming1,
    ctrlgrp_dramtiming2: CtrlgrpDramtiming2,
    ctrlgrp_dramtiming3: CtrlgrpDramtiming3,
    ctrlgrp_dramtiming4: CtrlgrpDramtiming4,
    ctrlgrp_lowpwrtiming: CtrlgrpLowpwrtiming,
    ctrlgrp_dramodt: CtrlgrpDramodt,
    _reserved7: [u8; 0x10],
    ctrlgrp_dramaddrw: CtrlgrpDramaddrw,
    ctrlgrp_dramifwidth: CtrlgrpDramifwidth,
    ctrlgrp_dramdevwidth: CtrlgrpDramdevwidth,
    ctrlgrp_dramsts: CtrlgrpDramsts,
    ctrlgrp_dramintr: CtrlgrpDramintr,
    ctrlgrp_sbecount: CtrlgrpSbecount,
    ctrlgrp_dbecount: CtrlgrpDbecount,
    ctrlgrp_erraddr: CtrlgrpErraddr,
    ctrlgrp_dropcount: CtrlgrpDropcount,
    ctrlgrp_dropaddr: CtrlgrpDropaddr,
    ctrlgrp_lowpwreq: CtrlgrpLowpwreq,
    ctrlgrp_lowpwrack: CtrlgrpLowpwrack,
    ctrlgrp_staticcfg: CtrlgrpStaticcfg,
    ctrlgrp_ctrlwidth: CtrlgrpCtrlwidth,
    _reserved21: [u8; 0x18],
    ctrlgrp_portcfg: CtrlgrpPortcfg,
    ctrlgrp_fpgaportrst: CtrlgrpFpgaportrst,
    _reserved23: [u8; 0x08],
    ctrlgrp_protportdefault: CtrlgrpProtportdefault,
    ctrlgrp_protruleaddr: CtrlgrpProtruleaddr,
    ctrlgrp_protruleid: CtrlgrpProtruleid,
    ctrlgrp_protruledata: CtrlgrpProtruledata,
    ctrlgrp_protrulerdwr: CtrlgrpProtrulerdwr,
    ctrlgrp_qoslowpri: CtrlgrpQoslowpri,
    ctrlgrp_qoshighpri: CtrlgrpQoshighpri,
    ctrlgrp_qospriorityen: CtrlgrpQospriorityen,
    ctrlgrp_mppriority: CtrlgrpMppriority,
    ctrlgrp_mpweight_mpweight_0_4: CtrlgrpMpweightMpweight0_4,
    ctrlgrp_mpweight_mpweight_1_4: CtrlgrpMpweightMpweight1_4,
    ctrlgrp_mpweight_mpweight_2_4: CtrlgrpMpweightMpweight2_4,
    ctrlgrp_mpweight_mpweight_3_4: CtrlgrpMpweightMpweight3_4,
    _reserved36: [u8; 0x20],
    ctrlgrp_remappriority: CtrlgrpRemappriority,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x5000 - The Controller Configuration Register determines the behavior of the controller."]
    #[inline(always)]
    pub const fn ctrlgrp_ctrlcfg(&self) -> &CtrlgrpCtrlcfg {
        &self.ctrlgrp_ctrlcfg
    }
    #[doc = "0x5004 - This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor."]
    #[inline(always)]
    pub const fn ctrlgrp_dramtiming1(&self) -> &CtrlgrpDramtiming1 {
        &self.ctrlgrp_dramtiming1
    }
    #[doc = "0x5008 - This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor."]
    #[inline(always)]
    pub const fn ctrlgrp_dramtiming2(&self) -> &CtrlgrpDramtiming2 {
        &self.ctrlgrp_dramtiming2
    }
    #[doc = "0x500c - This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor."]
    #[inline(always)]
    pub const fn ctrlgrp_dramtiming3(&self) -> &CtrlgrpDramtiming3 {
        &self.ctrlgrp_dramtiming3
    }
    #[doc = "0x5010 - This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor."]
    #[inline(always)]
    pub const fn ctrlgrp_dramtiming4(&self) -> &CtrlgrpDramtiming4 {
        &self.ctrlgrp_dramtiming4
    }
    #[doc = "0x5014 - This register controls the behavior of the low power logic in the controller."]
    #[inline(always)]
    pub const fn ctrlgrp_lowpwrtiming(&self) -> &CtrlgrpLowpwrtiming {
        &self.ctrlgrp_lowpwrtiming
    }
    #[doc = "0x5018 - This register controls which ODT pin is asserted during reads or writes. Bits \\[1:0\\]
control which ODT pin is asserted during to accesses to chip select 0, bits \\[3:2\\]
which ODT pin is asserted during accesses to chip select 1. For example, a value of &amp;quot;1001&amp;quot; will cause ODT\\[0\\]
to be asserted for accesses to CS\\[0\\], and ODT\\[1\\]
to be asserted for access to CS\\[1\\]
pin. Set this to &amp;quot;0001&amp;quot; if there is only one chip select available."]
    #[inline(always)]
    pub const fn ctrlgrp_dramodt(&self) -> &CtrlgrpDramodt {
        &self.ctrlgrp_dramodt
    }
    #[doc = "0x502c - This register configures the width of the various address fields of the DRAM. The values specified in this register must match the memory devices being used."]
    #[inline(always)]
    pub const fn ctrlgrp_dramaddrw(&self) -> &CtrlgrpDramaddrw {
        &self.ctrlgrp_dramaddrw
    }
    #[doc = "0x5030 - "]
    #[inline(always)]
    pub const fn ctrlgrp_dramifwidth(&self) -> &CtrlgrpDramifwidth {
        &self.ctrlgrp_dramifwidth
    }
    #[doc = "0x5034 - "]
    #[inline(always)]
    pub const fn ctrlgrp_dramdevwidth(&self) -> &CtrlgrpDramdevwidth {
        &self.ctrlgrp_dramdevwidth
    }
    #[doc = "0x5038 - This register provides the status of the calibration and ECC logic."]
    #[inline(always)]
    pub const fn ctrlgrp_dramsts(&self) -> &CtrlgrpDramsts {
        &self.ctrlgrp_dramsts
    }
    #[doc = "0x503c - "]
    #[inline(always)]
    pub const fn ctrlgrp_dramintr(&self) -> &CtrlgrpDramintr {
        &self.ctrlgrp_dramintr
    }
    #[doc = "0x5040 - "]
    #[inline(always)]
    pub const fn ctrlgrp_sbecount(&self) -> &CtrlgrpSbecount {
        &self.ctrlgrp_sbecount
    }
    #[doc = "0x5044 - "]
    #[inline(always)]
    pub const fn ctrlgrp_dbecount(&self) -> &CtrlgrpDbecount {
        &self.ctrlgrp_dbecount
    }
    #[doc = "0x5048 - "]
    #[inline(always)]
    pub const fn ctrlgrp_erraddr(&self) -> &CtrlgrpErraddr {
        &self.ctrlgrp_erraddr
    }
    #[doc = "0x504c - "]
    #[inline(always)]
    pub const fn ctrlgrp_dropcount(&self) -> &CtrlgrpDropcount {
        &self.ctrlgrp_dropcount
    }
    #[doc = "0x5050 - "]
    #[inline(always)]
    pub const fn ctrlgrp_dropaddr(&self) -> &CtrlgrpDropaddr {
        &self.ctrlgrp_dropaddr
    }
    #[doc = "0x5054 - This register instructs the controller to put the DRAM into a power down state. Note that some commands are only valid for certain memory types."]
    #[inline(always)]
    pub const fn ctrlgrp_lowpwreq(&self) -> &CtrlgrpLowpwreq {
        &self.ctrlgrp_lowpwreq
    }
    #[doc = "0x5058 - This register gives the status of the power down commands requested by the Low Power Control register."]
    #[inline(always)]
    pub const fn ctrlgrp_lowpwrack(&self) -> &CtrlgrpLowpwrack {
        &self.ctrlgrp_lowpwrack
    }
    #[doc = "0x505c - This register controls configuration values which cannot be updated while transactions are flowing. You should write once to this register with the membl and eccen fields set to your desired configuration, and then write to the register again with membl and eccen and the applycfg bit set. The applycfg bit is write only."]
    #[inline(always)]
    pub const fn ctrlgrp_staticcfg(&self) -> &CtrlgrpStaticcfg {
        &self.ctrlgrp_staticcfg
    }
    #[doc = "0x5060 - This register controls the width of the physical DRAM interface."]
    #[inline(always)]
    pub const fn ctrlgrp_ctrlwidth(&self) -> &CtrlgrpCtrlwidth {
        &self.ctrlgrp_ctrlwidth
    }
    #[doc = "0x507c - This register should be set to a zero in any bit which corresponds to a port which does mostly sequential memory accesses. For ports with highly random accesses, the bit should be set to a one."]
    #[inline(always)]
    pub const fn ctrlgrp_portcfg(&self) -> &CtrlgrpPortcfg {
        &self.ctrlgrp_portcfg
    }
    #[doc = "0x5080 - This register implements functionality to allow the CPU to control when the MPFE will enable the ports to the FPGA fabric."]
    #[inline(always)]
    pub const fn ctrlgrp_fpgaportrst(&self) -> &CtrlgrpFpgaportrst {
        &self.ctrlgrp_fpgaportrst
    }
    #[doc = "0x508c - This register controls the default protection assignment for a port. Ports which have explicit rules which define regions which are illegal to access should set the bits to pass by default. Ports which have explicit rules which define legal areas should set the bit to force all transactions to fail. Leaving this register to all zeros should be used for systems which do not desire any protection from the memory controller."]
    #[inline(always)]
    pub const fn ctrlgrp_protportdefault(&self) -> &CtrlgrpProtportdefault {
        &self.ctrlgrp_protportdefault
    }
    #[doc = "0x5090 - This register is used to control the memory protection for port 0 transactions. Address ranges can either be used to allow access to memory regions or disallow access to memory regions. If trustzone is being used, access can be enabled for protected transactions or disabled for unprotected transactions. The default state of this register is to allow all access. Address values used for protection are only physical addresses."]
    #[inline(always)]
    pub const fn ctrlgrp_protruleaddr(&self) -> &CtrlgrpProtruleaddr {
        &self.ctrlgrp_protruleaddr
    }
    #[doc = "0x5094 - "]
    #[inline(always)]
    pub const fn ctrlgrp_protruleid(&self) -> &CtrlgrpProtruleid {
        &self.ctrlgrp_protruleid
    }
    #[doc = "0x5098 - "]
    #[inline(always)]
    pub const fn ctrlgrp_protruledata(&self) -> &CtrlgrpProtruledata {
        &self.ctrlgrp_protruledata
    }
    #[doc = "0x509c - This register is used to perform read and write operations to the internal protection table."]
    #[inline(always)]
    pub const fn ctrlgrp_protrulerdwr(&self) -> &CtrlgrpProtrulerdwr {
        &self.ctrlgrp_protrulerdwr
    }
    #[doc = "0x50a0 - This register controls the mapping of AXI4 QOS received from the FPGA fabric to the internal priority used for traffic prioritization."]
    #[inline(always)]
    pub const fn ctrlgrp_qoslowpri(&self) -> &CtrlgrpQoslowpri {
        &self.ctrlgrp_qoslowpri
    }
    #[doc = "0x50a4 - "]
    #[inline(always)]
    pub const fn ctrlgrp_qoshighpri(&self) -> &CtrlgrpQoshighpri {
        &self.ctrlgrp_qoshighpri
    }
    #[doc = "0x50a8 - "]
    #[inline(always)]
    pub const fn ctrlgrp_qospriorityen(&self) -> &CtrlgrpQospriorityen {
        &self.ctrlgrp_qospriorityen
    }
    #[doc = "0x50ac - This register is used to configure the DRAM burst operation scheduling."]
    #[inline(always)]
    pub const fn ctrlgrp_mppriority(&self) -> &CtrlgrpMppriority {
        &self.ctrlgrp_mppriority
    }
    #[doc = "0x50b0 - This register is used to configure the DRAM burst operation scheduling."]
    #[inline(always)]
    pub const fn ctrlgrp_mpweight_mpweight_0_4(&self) -> &CtrlgrpMpweightMpweight0_4 {
        &self.ctrlgrp_mpweight_mpweight_0_4
    }
    #[doc = "0x50b4 - This register is used to configure the DRAM burst operation scheduling."]
    #[inline(always)]
    pub const fn ctrlgrp_mpweight_mpweight_1_4(&self) -> &CtrlgrpMpweightMpweight1_4 {
        &self.ctrlgrp_mpweight_mpweight_1_4
    }
    #[doc = "0x50b8 - This register is used to configure the DRAM burst operation scheduling."]
    #[inline(always)]
    pub const fn ctrlgrp_mpweight_mpweight_2_4(&self) -> &CtrlgrpMpweightMpweight2_4 {
        &self.ctrlgrp_mpweight_mpweight_2_4
    }
    #[doc = "0x50bc - This register is used to configure the DRAM burst operation scheduling."]
    #[inline(always)]
    pub const fn ctrlgrp_mpweight_mpweight_3_4(&self) -> &CtrlgrpMpweightMpweight3_4 {
        &self.ctrlgrp_mpweight_mpweight_3_4
    }
    #[doc = "0x50e0 - This register controls the priority for transactions in the controller command pool."]
    #[inline(always)]
    pub const fn ctrlgrp_remappriority(&self) -> &CtrlgrpRemappriority {
        &self.ctrlgrp_remappriority
    }
}
#[doc = "ctrlgrp_ctrlcfg (rw) register accessor: The Controller Configuration Register determines the behavior of the controller.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_ctrlcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_ctrlcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_ctrlcfg`]
module"]
#[doc(alias = "ctrlgrp_ctrlcfg")]
pub type CtrlgrpCtrlcfg = crate::Reg<ctrlgrp_ctrlcfg::CtrlgrpCtrlcfgSpec>;
#[doc = "The Controller Configuration Register determines the behavior of the controller."]
pub mod ctrlgrp_ctrlcfg;
#[doc = "ctrlgrp_dramtiming1 (rw) register accessor: This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramtiming1::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramtiming1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramtiming1`]
module"]
#[doc(alias = "ctrlgrp_dramtiming1")]
pub type CtrlgrpDramtiming1 = crate::Reg<ctrlgrp_dramtiming1::CtrlgrpDramtiming1Spec>;
#[doc = "This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor."]
pub mod ctrlgrp_dramtiming1;
#[doc = "ctrlgrp_dramtiming2 (rw) register accessor: This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramtiming2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramtiming2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramtiming2`]
module"]
#[doc(alias = "ctrlgrp_dramtiming2")]
pub type CtrlgrpDramtiming2 = crate::Reg<ctrlgrp_dramtiming2::CtrlgrpDramtiming2Spec>;
#[doc = "This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor."]
pub mod ctrlgrp_dramtiming2;
#[doc = "ctrlgrp_dramtiming3 (rw) register accessor: This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramtiming3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramtiming3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramtiming3`]
module"]
#[doc(alias = "ctrlgrp_dramtiming3")]
pub type CtrlgrpDramtiming3 = crate::Reg<ctrlgrp_dramtiming3::CtrlgrpDramtiming3Spec>;
#[doc = "This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor."]
pub mod ctrlgrp_dramtiming3;
#[doc = "ctrlgrp_dramtiming4 (rw) register accessor: This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramtiming4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramtiming4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramtiming4`]
module"]
#[doc(alias = "ctrlgrp_dramtiming4")]
pub type CtrlgrpDramtiming4 = crate::Reg<ctrlgrp_dramtiming4::CtrlgrpDramtiming4Spec>;
#[doc = "This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor."]
pub mod ctrlgrp_dramtiming4;
#[doc = "ctrlgrp_lowpwrtiming (rw) register accessor: This register controls the behavior of the low power logic in the controller.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_lowpwrtiming::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_lowpwrtiming::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_lowpwrtiming`]
module"]
#[doc(alias = "ctrlgrp_lowpwrtiming")]
pub type CtrlgrpLowpwrtiming = crate::Reg<ctrlgrp_lowpwrtiming::CtrlgrpLowpwrtimingSpec>;
#[doc = "This register controls the behavior of the low power logic in the controller."]
pub mod ctrlgrp_lowpwrtiming;
#[doc = "ctrlgrp_dramodt (rw) register accessor: This register controls which ODT pin is asserted during reads or writes. Bits \\[1:0\\]
control which ODT pin is asserted during to accesses to chip select 0, bits \\[3:2\\]
which ODT pin is asserted during accesses to chip select 1. For example, a value of &amp;quot;1001&amp;quot; will cause ODT\\[0\\]
to be asserted for accesses to CS\\[0\\], and ODT\\[1\\]
to be asserted for access to CS\\[1\\]
pin. Set this to &amp;quot;0001&amp;quot; if there is only one chip select available.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramodt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramodt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramodt`]
module"]
#[doc(alias = "ctrlgrp_dramodt")]
pub type CtrlgrpDramodt = crate::Reg<ctrlgrp_dramodt::CtrlgrpDramodtSpec>;
#[doc = "This register controls which ODT pin is asserted during reads or writes. Bits \\[1:0\\]
control which ODT pin is asserted during to accesses to chip select 0, bits \\[3:2\\]
which ODT pin is asserted during accesses to chip select 1. For example, a value of &amp;quot;1001&amp;quot; will cause ODT\\[0\\]
to be asserted for accesses to CS\\[0\\], and ODT\\[1\\]
to be asserted for access to CS\\[1\\]
pin. Set this to &amp;quot;0001&amp;quot; if there is only one chip select available."]
pub mod ctrlgrp_dramodt;
#[doc = "ctrlgrp_dramaddrw (rw) register accessor: This register configures the width of the various address fields of the DRAM. The values specified in this register must match the memory devices being used.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramaddrw::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramaddrw::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramaddrw`]
module"]
#[doc(alias = "ctrlgrp_dramaddrw")]
pub type CtrlgrpDramaddrw = crate::Reg<ctrlgrp_dramaddrw::CtrlgrpDramaddrwSpec>;
#[doc = "This register configures the width of the various address fields of the DRAM. The values specified in this register must match the memory devices being used."]
pub mod ctrlgrp_dramaddrw;
#[doc = "ctrlgrp_dramifwidth (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramifwidth::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramifwidth::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramifwidth`]
module"]
#[doc(alias = "ctrlgrp_dramifwidth")]
pub type CtrlgrpDramifwidth = crate::Reg<ctrlgrp_dramifwidth::CtrlgrpDramifwidthSpec>;
#[doc = ""]
pub mod ctrlgrp_dramifwidth;
#[doc = "ctrlgrp_dramdevwidth (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramdevwidth::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramdevwidth::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramdevwidth`]
module"]
#[doc(alias = "ctrlgrp_dramdevwidth")]
pub type CtrlgrpDramdevwidth = crate::Reg<ctrlgrp_dramdevwidth::CtrlgrpDramdevwidthSpec>;
#[doc = ""]
pub mod ctrlgrp_dramdevwidth;
#[doc = "ctrlgrp_dramsts (rw) register accessor: This register provides the status of the calibration and ECC logic.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramsts::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramsts::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramsts`]
module"]
#[doc(alias = "ctrlgrp_dramsts")]
pub type CtrlgrpDramsts = crate::Reg<ctrlgrp_dramsts::CtrlgrpDramstsSpec>;
#[doc = "This register provides the status of the calibration and ECC logic."]
pub mod ctrlgrp_dramsts;
#[doc = "ctrlgrp_dramintr (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramintr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramintr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dramintr`]
module"]
#[doc(alias = "ctrlgrp_dramintr")]
pub type CtrlgrpDramintr = crate::Reg<ctrlgrp_dramintr::CtrlgrpDramintrSpec>;
#[doc = ""]
pub mod ctrlgrp_dramintr;
#[doc = "ctrlgrp_sbecount (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_sbecount::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_sbecount::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_sbecount`]
module"]
#[doc(alias = "ctrlgrp_sbecount")]
pub type CtrlgrpSbecount = crate::Reg<ctrlgrp_sbecount::CtrlgrpSbecountSpec>;
#[doc = ""]
pub mod ctrlgrp_sbecount;
#[doc = "ctrlgrp_dbecount (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dbecount::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dbecount::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dbecount`]
module"]
#[doc(alias = "ctrlgrp_dbecount")]
pub type CtrlgrpDbecount = crate::Reg<ctrlgrp_dbecount::CtrlgrpDbecountSpec>;
#[doc = ""]
pub mod ctrlgrp_dbecount;
#[doc = "ctrlgrp_erraddr (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_erraddr::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_erraddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_erraddr`]
module"]
#[doc(alias = "ctrlgrp_erraddr")]
pub type CtrlgrpErraddr = crate::Reg<ctrlgrp_erraddr::CtrlgrpErraddrSpec>;
#[doc = ""]
pub mod ctrlgrp_erraddr;
#[doc = "ctrlgrp_dropcount (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dropcount::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dropcount::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dropcount`]
module"]
#[doc(alias = "ctrlgrp_dropcount")]
pub type CtrlgrpDropcount = crate::Reg<ctrlgrp_dropcount::CtrlgrpDropcountSpec>;
#[doc = ""]
pub mod ctrlgrp_dropcount;
#[doc = "ctrlgrp_dropaddr (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dropaddr::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dropaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_dropaddr`]
module"]
#[doc(alias = "ctrlgrp_dropaddr")]
pub type CtrlgrpDropaddr = crate::Reg<ctrlgrp_dropaddr::CtrlgrpDropaddrSpec>;
#[doc = ""]
pub mod ctrlgrp_dropaddr;
#[doc = "ctrlgrp_lowpwreq (rw) register accessor: This register instructs the controller to put the DRAM into a power down state. Note that some commands are only valid for certain memory types.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_lowpwreq::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_lowpwreq::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_lowpwreq`]
module"]
#[doc(alias = "ctrlgrp_lowpwreq")]
pub type CtrlgrpLowpwreq = crate::Reg<ctrlgrp_lowpwreq::CtrlgrpLowpwreqSpec>;
#[doc = "This register instructs the controller to put the DRAM into a power down state. Note that some commands are only valid for certain memory types."]
pub mod ctrlgrp_lowpwreq;
#[doc = "ctrlgrp_lowpwrack (rw) register accessor: This register gives the status of the power down commands requested by the Low Power Control register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_lowpwrack::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_lowpwrack::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_lowpwrack`]
module"]
#[doc(alias = "ctrlgrp_lowpwrack")]
pub type CtrlgrpLowpwrack = crate::Reg<ctrlgrp_lowpwrack::CtrlgrpLowpwrackSpec>;
#[doc = "This register gives the status of the power down commands requested by the Low Power Control register."]
pub mod ctrlgrp_lowpwrack;
#[doc = "ctrlgrp_staticcfg (rw) register accessor: This register controls configuration values which cannot be updated while transactions are flowing. You should write once to this register with the membl and eccen fields set to your desired configuration, and then write to the register again with membl and eccen and the applycfg bit set. The applycfg bit is write only.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_staticcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_staticcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_staticcfg`]
module"]
#[doc(alias = "ctrlgrp_staticcfg")]
pub type CtrlgrpStaticcfg = crate::Reg<ctrlgrp_staticcfg::CtrlgrpStaticcfgSpec>;
#[doc = "This register controls configuration values which cannot be updated while transactions are flowing. You should write once to this register with the membl and eccen fields set to your desired configuration, and then write to the register again with membl and eccen and the applycfg bit set. The applycfg bit is write only."]
pub mod ctrlgrp_staticcfg;
#[doc = "ctrlgrp_ctrlwidth (rw) register accessor: This register controls the width of the physical DRAM interface.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_ctrlwidth::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_ctrlwidth::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_ctrlwidth`]
module"]
#[doc(alias = "ctrlgrp_ctrlwidth")]
pub type CtrlgrpCtrlwidth = crate::Reg<ctrlgrp_ctrlwidth::CtrlgrpCtrlwidthSpec>;
#[doc = "This register controls the width of the physical DRAM interface."]
pub mod ctrlgrp_ctrlwidth;
#[doc = "ctrlgrp_portcfg (rw) register accessor: This register should be set to a zero in any bit which corresponds to a port which does mostly sequential memory accesses. For ports with highly random accesses, the bit should be set to a one.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_portcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_portcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_portcfg`]
module"]
#[doc(alias = "ctrlgrp_portcfg")]
pub type CtrlgrpPortcfg = crate::Reg<ctrlgrp_portcfg::CtrlgrpPortcfgSpec>;
#[doc = "This register should be set to a zero in any bit which corresponds to a port which does mostly sequential memory accesses. For ports with highly random accesses, the bit should be set to a one."]
pub mod ctrlgrp_portcfg;
#[doc = "ctrlgrp_fpgaportrst (rw) register accessor: This register implements functionality to allow the CPU to control when the MPFE will enable the ports to the FPGA fabric.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_fpgaportrst::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_fpgaportrst::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_fpgaportrst`]
module"]
#[doc(alias = "ctrlgrp_fpgaportrst")]
pub type CtrlgrpFpgaportrst = crate::Reg<ctrlgrp_fpgaportrst::CtrlgrpFpgaportrstSpec>;
#[doc = "This register implements functionality to allow the CPU to control when the MPFE will enable the ports to the FPGA fabric."]
pub mod ctrlgrp_fpgaportrst;
#[doc = "ctrlgrp_protportdefault (rw) register accessor: This register controls the default protection assignment for a port. Ports which have explicit rules which define regions which are illegal to access should set the bits to pass by default. Ports which have explicit rules which define legal areas should set the bit to force all transactions to fail. Leaving this register to all zeros should be used for systems which do not desire any protection from the memory controller.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protportdefault::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protportdefault::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_protportdefault`]
module"]
#[doc(alias = "ctrlgrp_protportdefault")]
pub type CtrlgrpProtportdefault = crate::Reg<ctrlgrp_protportdefault::CtrlgrpProtportdefaultSpec>;
#[doc = "This register controls the default protection assignment for a port. Ports which have explicit rules which define regions which are illegal to access should set the bits to pass by default. Ports which have explicit rules which define legal areas should set the bit to force all transactions to fail. Leaving this register to all zeros should be used for systems which do not desire any protection from the memory controller."]
pub mod ctrlgrp_protportdefault;
#[doc = "ctrlgrp_protruleaddr (rw) register accessor: This register is used to control the memory protection for port 0 transactions. Address ranges can either be used to allow access to memory regions or disallow access to memory regions. If trustzone is being used, access can be enabled for protected transactions or disabled for unprotected transactions. The default state of this register is to allow all access. Address values used for protection are only physical addresses.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protruleaddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protruleaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_protruleaddr`]
module"]
#[doc(alias = "ctrlgrp_protruleaddr")]
pub type CtrlgrpProtruleaddr = crate::Reg<ctrlgrp_protruleaddr::CtrlgrpProtruleaddrSpec>;
#[doc = "This register is used to control the memory protection for port 0 transactions. Address ranges can either be used to allow access to memory regions or disallow access to memory regions. If trustzone is being used, access can be enabled for protected transactions or disabled for unprotected transactions. The default state of this register is to allow all access. Address values used for protection are only physical addresses."]
pub mod ctrlgrp_protruleaddr;
#[doc = "ctrlgrp_protruleid (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protruleid::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protruleid::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_protruleid`]
module"]
#[doc(alias = "ctrlgrp_protruleid")]
pub type CtrlgrpProtruleid = crate::Reg<ctrlgrp_protruleid::CtrlgrpProtruleidSpec>;
#[doc = ""]
pub mod ctrlgrp_protruleid;
#[doc = "ctrlgrp_protruledata (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protruledata::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protruledata::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_protruledata`]
module"]
#[doc(alias = "ctrlgrp_protruledata")]
pub type CtrlgrpProtruledata = crate::Reg<ctrlgrp_protruledata::CtrlgrpProtruledataSpec>;
#[doc = ""]
pub mod ctrlgrp_protruledata;
#[doc = "ctrlgrp_protrulerdwr (rw) register accessor: This register is used to perform read and write operations to the internal protection table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protrulerdwr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protrulerdwr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_protrulerdwr`]
module"]
#[doc(alias = "ctrlgrp_protrulerdwr")]
pub type CtrlgrpProtrulerdwr = crate::Reg<ctrlgrp_protrulerdwr::CtrlgrpProtrulerdwrSpec>;
#[doc = "This register is used to perform read and write operations to the internal protection table."]
pub mod ctrlgrp_protrulerdwr;
#[doc = "ctrlgrp_qoslowpri (rw) register accessor: This register controls the mapping of AXI4 QOS received from the FPGA fabric to the internal priority used for traffic prioritization.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_qoslowpri::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_qoslowpri::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_qoslowpri`]
module"]
#[doc(alias = "ctrlgrp_qoslowpri")]
pub type CtrlgrpQoslowpri = crate::Reg<ctrlgrp_qoslowpri::CtrlgrpQoslowpriSpec>;
#[doc = "This register controls the mapping of AXI4 QOS received from the FPGA fabric to the internal priority used for traffic prioritization."]
pub mod ctrlgrp_qoslowpri;
#[doc = "ctrlgrp_qoshighpri (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_qoshighpri::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_qoshighpri::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_qoshighpri`]
module"]
#[doc(alias = "ctrlgrp_qoshighpri")]
pub type CtrlgrpQoshighpri = crate::Reg<ctrlgrp_qoshighpri::CtrlgrpQoshighpriSpec>;
#[doc = ""]
pub mod ctrlgrp_qoshighpri;
#[doc = "ctrlgrp_qospriorityen (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_qospriorityen::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_qospriorityen::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_qospriorityen`]
module"]
#[doc(alias = "ctrlgrp_qospriorityen")]
pub type CtrlgrpQospriorityen = crate::Reg<ctrlgrp_qospriorityen::CtrlgrpQospriorityenSpec>;
#[doc = ""]
pub mod ctrlgrp_qospriorityen;
#[doc = "ctrlgrp_mppriority (rw) register accessor: This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mppriority::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mppriority::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_mppriority`]
module"]
#[doc(alias = "ctrlgrp_mppriority")]
pub type CtrlgrpMppriority = crate::Reg<ctrlgrp_mppriority::CtrlgrpMpprioritySpec>;
#[doc = "This register is used to configure the DRAM burst operation scheduling."]
pub mod ctrlgrp_mppriority;
#[doc = "ctrlgrp_mpweight_mpweight_0_4 (rw) register accessor: This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mpweight_mpweight_0_4::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mpweight_mpweight_0_4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_mpweight_mpweight_0_4`]
module"]
#[doc(alias = "ctrlgrp_mpweight_mpweight_0_4")]
pub type CtrlgrpMpweightMpweight0_4 =
    crate::Reg<ctrlgrp_mpweight_mpweight_0_4::CtrlgrpMpweightMpweight0_4Spec>;
#[doc = "This register is used to configure the DRAM burst operation scheduling."]
pub mod ctrlgrp_mpweight_mpweight_0_4;
#[doc = "ctrlgrp_mpweight_mpweight_1_4 (rw) register accessor: This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mpweight_mpweight_1_4::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mpweight_mpweight_1_4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_mpweight_mpweight_1_4`]
module"]
#[doc(alias = "ctrlgrp_mpweight_mpweight_1_4")]
pub type CtrlgrpMpweightMpweight1_4 =
    crate::Reg<ctrlgrp_mpweight_mpweight_1_4::CtrlgrpMpweightMpweight1_4Spec>;
#[doc = "This register is used to configure the DRAM burst operation scheduling."]
pub mod ctrlgrp_mpweight_mpweight_1_4;
#[doc = "ctrlgrp_mpweight_mpweight_2_4 (rw) register accessor: This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mpweight_mpweight_2_4::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mpweight_mpweight_2_4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_mpweight_mpweight_2_4`]
module"]
#[doc(alias = "ctrlgrp_mpweight_mpweight_2_4")]
pub type CtrlgrpMpweightMpweight2_4 =
    crate::Reg<ctrlgrp_mpweight_mpweight_2_4::CtrlgrpMpweightMpweight2_4Spec>;
#[doc = "This register is used to configure the DRAM burst operation scheduling."]
pub mod ctrlgrp_mpweight_mpweight_2_4;
#[doc = "ctrlgrp_mpweight_mpweight_3_4 (rw) register accessor: This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mpweight_mpweight_3_4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mpweight_mpweight_3_4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_mpweight_mpweight_3_4`]
module"]
#[doc(alias = "ctrlgrp_mpweight_mpweight_3_4")]
pub type CtrlgrpMpweightMpweight3_4 =
    crate::Reg<ctrlgrp_mpweight_mpweight_3_4::CtrlgrpMpweightMpweight3_4Spec>;
#[doc = "This register is used to configure the DRAM burst operation scheduling."]
pub mod ctrlgrp_mpweight_mpweight_3_4;
#[doc = "ctrlgrp_remappriority (rw) register accessor: This register controls the priority for transactions in the controller command pool.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_remappriority::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_remappriority::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@ctrlgrp_remappriority`]
module"]
#[doc(alias = "ctrlgrp_remappriority")]
pub type CtrlgrpRemappriority = crate::Reg<ctrlgrp_remappriority::CtrlgrpRemapprioritySpec>;
#[doc = "This register controls the priority for transactions in the controller command pool."]
pub mod ctrlgrp_remappriority;
