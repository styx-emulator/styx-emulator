// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    _reserved0: [u8; 0x1fd0],
    idgrp_periph_id_4: IdgrpPeriphId4,
    _reserved1: [u8; 0x0c],
    idgrp_periph_id_0: IdgrpPeriphId0,
    idgrp_periph_id_1: IdgrpPeriphId1,
    idgrp_periph_id_2: IdgrpPeriphId2,
    idgrp_periph_id_3: IdgrpPeriphId3,
    idgrp_comp_id_0: IdgrpCompId0,
    idgrp_comp_id_1: IdgrpCompId1,
    idgrp_comp_id_2: IdgrpCompId2,
    idgrp_comp_id_3: IdgrpCompId3,
    _reserved9: [u8; 0x08],
    mastergrp_fpga2hpsregs_fn_mod_bm_iss: MastergrpFpga2hpsregsFnModBmIss,
    _reserved10: [u8; 0x38],
    mastergrp_fpga2hpsregs_ahb_cntl: MastergrpFpga2hpsregsAhbCntl,
    _reserved11: [u8; 0x0fc0],
    mastergrp_hps2fpgaregs_fn_mod_bm_iss: MastergrpHps2fpgaregsFnModBmIss,
    _reserved12: [u8; 0x38],
    mastergrp_hps2fpgaregs_ahb_cntl: MastergrpHps2fpgaregsAhbCntl,
    _reserved13: [u8; 0x1fc0],
    mastergrp_b32_fn_mod_bm_iss: MastergrpB32FnModBmIss,
    _reserved14: [u8; 0x34],
    mastergrp_b32_wr_tidemark: MastergrpB32WrTidemark,
    _reserved15: [u8; 0xc4],
    mastergrp_b32_fn_mod: MastergrpB32FnMod,
    _reserved16: [u8; 0x0003_fffc],
    slavegrp_b32_fn_mod: SlavegrpB32FnMod,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x1fd0 - JEP106 continuation code"]
    #[inline(always)]
    pub const fn idgrp_periph_id_4(&self) -> &IdgrpPeriphId4 {
        &self.idgrp_periph_id_4
    }
    #[doc = "0x1fe0 - Peripheral ID0"]
    #[inline(always)]
    pub const fn idgrp_periph_id_0(&self) -> &IdgrpPeriphId0 {
        &self.idgrp_periph_id_0
    }
    #[doc = "0x1fe4 - Peripheral ID1"]
    #[inline(always)]
    pub const fn idgrp_periph_id_1(&self) -> &IdgrpPeriphId1 {
        &self.idgrp_periph_id_1
    }
    #[doc = "0x1fe8 - Peripheral ID2"]
    #[inline(always)]
    pub const fn idgrp_periph_id_2(&self) -> &IdgrpPeriphId2 {
        &self.idgrp_periph_id_2
    }
    #[doc = "0x1fec - Peripheral ID3"]
    #[inline(always)]
    pub const fn idgrp_periph_id_3(&self) -> &IdgrpPeriphId3 {
        &self.idgrp_periph_id_3
    }
    #[doc = "0x1ff0 - Component ID0"]
    #[inline(always)]
    pub const fn idgrp_comp_id_0(&self) -> &IdgrpCompId0 {
        &self.idgrp_comp_id_0
    }
    #[doc = "0x1ff4 - Component ID1"]
    #[inline(always)]
    pub const fn idgrp_comp_id_1(&self) -> &IdgrpCompId1 {
        &self.idgrp_comp_id_1
    }
    #[doc = "0x1ff8 - Component ID2"]
    #[inline(always)]
    pub const fn idgrp_comp_id_2(&self) -> &IdgrpCompId2 {
        &self.idgrp_comp_id_2
    }
    #[doc = "0x1ffc - Component ID3"]
    #[inline(always)]
    pub const fn idgrp_comp_id_3(&self) -> &IdgrpCompId3 {
        &self.idgrp_comp_id_3
    }
    #[doc = "0x2008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_fpga2hpsregs_fn_mod_bm_iss(&self) -> &MastergrpFpga2hpsregsFnModBmIss {
        &self.mastergrp_fpga2hpsregs_fn_mod_bm_iss
    }
    #[doc = "0x2044 - Sets the block issuing capability to one outstanding transaction."]
    #[inline(always)]
    pub const fn mastergrp_fpga2hpsregs_ahb_cntl(&self) -> &MastergrpFpga2hpsregsAhbCntl {
        &self.mastergrp_fpga2hpsregs_ahb_cntl
    }
    #[doc = "0x3008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_hps2fpgaregs_fn_mod_bm_iss(&self) -> &MastergrpHps2fpgaregsFnModBmIss {
        &self.mastergrp_hps2fpgaregs_fn_mod_bm_iss
    }
    #[doc = "0x3044 - Sets the block issuing capability to one outstanding transaction."]
    #[inline(always)]
    pub const fn mastergrp_hps2fpgaregs_ahb_cntl(&self) -> &MastergrpHps2fpgaregsAhbCntl {
        &self.mastergrp_hps2fpgaregs_ahb_cntl
    }
    #[doc = "0x5008 - Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_b32_fn_mod_bm_iss(&self) -> &MastergrpB32FnModBmIss {
        &self.mastergrp_b32_fn_mod_bm_iss
    }
    #[doc = "0x5040 - Controls the release of the transaction in the write data FIFO."]
    #[inline(always)]
    pub const fn mastergrp_b32_wr_tidemark(&self) -> &MastergrpB32WrTidemark {
        &self.mastergrp_b32_wr_tidemark
    }
    #[doc = "0x5108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn mastergrp_b32_fn_mod(&self) -> &MastergrpB32FnMod {
        &self.mastergrp_b32_fn_mod
    }
    #[doc = "0x45108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_b32_fn_mod(&self) -> &SlavegrpB32FnMod {
        &self.slavegrp_b32_fn_mod
    }
}
#[doc = "idgrp_periph_id_4 (r) register accessor: JEP106 continuation code\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_4`]
module"]
#[doc(alias = "idgrp_periph_id_4")]
pub type IdgrpPeriphId4 = crate::Reg<idgrp_periph_id_4::IdgrpPeriphId4Spec>;
#[doc = "JEP106 continuation code"]
pub mod idgrp_periph_id_4;
#[doc = "idgrp_periph_id_0 (r) register accessor: Peripheral ID0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_0`]
module"]
#[doc(alias = "idgrp_periph_id_0")]
pub type IdgrpPeriphId0 = crate::Reg<idgrp_periph_id_0::IdgrpPeriphId0Spec>;
#[doc = "Peripheral ID0"]
pub mod idgrp_periph_id_0;
#[doc = "idgrp_periph_id_1 (r) register accessor: Peripheral ID1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_1`]
module"]
#[doc(alias = "idgrp_periph_id_1")]
pub type IdgrpPeriphId1 = crate::Reg<idgrp_periph_id_1::IdgrpPeriphId1Spec>;
#[doc = "Peripheral ID1"]
pub mod idgrp_periph_id_1;
#[doc = "idgrp_periph_id_2 (r) register accessor: Peripheral ID2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_2`]
module"]
#[doc(alias = "idgrp_periph_id_2")]
pub type IdgrpPeriphId2 = crate::Reg<idgrp_periph_id_2::IdgrpPeriphId2Spec>;
#[doc = "Peripheral ID2"]
pub mod idgrp_periph_id_2;
#[doc = "idgrp_periph_id_3 (r) register accessor: Peripheral ID3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_periph_id_3`]
module"]
#[doc(alias = "idgrp_periph_id_3")]
pub type IdgrpPeriphId3 = crate::Reg<idgrp_periph_id_3::IdgrpPeriphId3Spec>;
#[doc = "Peripheral ID3"]
pub mod idgrp_periph_id_3;
#[doc = "idgrp_comp_id_0 (r) register accessor: Component ID0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_comp_id_0`]
module"]
#[doc(alias = "idgrp_comp_id_0")]
pub type IdgrpCompId0 = crate::Reg<idgrp_comp_id_0::IdgrpCompId0Spec>;
#[doc = "Component ID0"]
pub mod idgrp_comp_id_0;
#[doc = "idgrp_comp_id_1 (r) register accessor: Component ID1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_comp_id_1`]
module"]
#[doc(alias = "idgrp_comp_id_1")]
pub type IdgrpCompId1 = crate::Reg<idgrp_comp_id_1::IdgrpCompId1Spec>;
#[doc = "Component ID1"]
pub mod idgrp_comp_id_1;
#[doc = "idgrp_comp_id_2 (r) register accessor: Component ID2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_comp_id_2`]
module"]
#[doc(alias = "idgrp_comp_id_2")]
pub type IdgrpCompId2 = crate::Reg<idgrp_comp_id_2::IdgrpCompId2Spec>;
#[doc = "Component ID2"]
pub mod idgrp_comp_id_2;
#[doc = "idgrp_comp_id_3 (r) register accessor: Component ID3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@idgrp_comp_id_3`]
module"]
#[doc(alias = "idgrp_comp_id_3")]
pub type IdgrpCompId3 = crate::Reg<idgrp_comp_id_3::IdgrpCompId3Spec>;
#[doc = "Component ID3"]
pub mod idgrp_comp_id_3;
#[doc = "mastergrp_fpga2hpsregs_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_fpga2hpsregs_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_fpga2hpsregs_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_fpga2hpsregs_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_fpga2hpsregs_fn_mod_bm_iss")]
pub type MastergrpFpga2hpsregsFnModBmIss =
    crate::Reg<mastergrp_fpga2hpsregs_fn_mod_bm_iss::MastergrpFpga2hpsregsFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_fpga2hpsregs_fn_mod_bm_iss;
#[doc = "mastergrp_fpga2hpsregs_ahb_cntl (rw) register accessor: Sets the block issuing capability to one outstanding transaction.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_fpga2hpsregs_ahb_cntl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_fpga2hpsregs_ahb_cntl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_fpga2hpsregs_ahb_cntl`]
module"]
#[doc(alias = "mastergrp_fpga2hpsregs_ahb_cntl")]
pub type MastergrpFpga2hpsregsAhbCntl =
    crate::Reg<mastergrp_fpga2hpsregs_ahb_cntl::MastergrpFpga2hpsregsAhbCntlSpec>;
#[doc = "Sets the block issuing capability to one outstanding transaction."]
pub mod mastergrp_fpga2hpsregs_ahb_cntl;
#[doc = "mastergrp_hps2fpgaregs_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_hps2fpgaregs_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_hps2fpgaregs_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_hps2fpgaregs_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_hps2fpgaregs_fn_mod_bm_iss")]
pub type MastergrpHps2fpgaregsFnModBmIss =
    crate::Reg<mastergrp_hps2fpgaregs_fn_mod_bm_iss::MastergrpHps2fpgaregsFnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_hps2fpgaregs_fn_mod_bm_iss;
#[doc = "mastergrp_hps2fpgaregs_ahb_cntl (rw) register accessor: Sets the block issuing capability to one outstanding transaction.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_hps2fpgaregs_ahb_cntl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_hps2fpgaregs_ahb_cntl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_hps2fpgaregs_ahb_cntl`]
module"]
#[doc(alias = "mastergrp_hps2fpgaregs_ahb_cntl")]
pub type MastergrpHps2fpgaregsAhbCntl =
    crate::Reg<mastergrp_hps2fpgaregs_ahb_cntl::MastergrpHps2fpgaregsAhbCntlSpec>;
#[doc = "Sets the block issuing capability to one outstanding transaction."]
pub mod mastergrp_hps2fpgaregs_ahb_cntl;
#[doc = "mastergrp_b32_fn_mod_bm_iss (rw) register accessor: Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_b32_fn_mod_bm_iss::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_b32_fn_mod_bm_iss::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_b32_fn_mod_bm_iss`]
module"]
#[doc(alias = "mastergrp_b32_fn_mod_bm_iss")]
pub type MastergrpB32FnModBmIss =
    crate::Reg<mastergrp_b32_fn_mod_bm_iss::MastergrpB32FnModBmIssSpec>;
#[doc = "Sets the issuing capability of the preceding switch arbitration scheme to multiple or single outstanding transactions."]
pub mod mastergrp_b32_fn_mod_bm_iss;
#[doc = "mastergrp_b32_wr_tidemark (rw) register accessor: Controls the release of the transaction in the write data FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_b32_wr_tidemark::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_b32_wr_tidemark::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_b32_wr_tidemark`]
module"]
#[doc(alias = "mastergrp_b32_wr_tidemark")]
pub type MastergrpB32WrTidemark = crate::Reg<mastergrp_b32_wr_tidemark::MastergrpB32WrTidemarkSpec>;
#[doc = "Controls the release of the transaction in the write data FIFO."]
pub mod mastergrp_b32_wr_tidemark;
#[doc = "mastergrp_b32_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mastergrp_b32_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mastergrp_b32_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@mastergrp_b32_fn_mod`]
module"]
#[doc(alias = "mastergrp_b32_fn_mod")]
pub type MastergrpB32FnMod = crate::Reg<mastergrp_b32_fn_mod::MastergrpB32FnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod mastergrp_b32_fn_mod;
#[doc = "slavegrp_b32_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_b32_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_b32_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_b32_fn_mod`]
module"]
#[doc(alias = "slavegrp_b32_fn_mod")]
pub type SlavegrpB32FnMod = crate::Reg<slavegrp_b32_fn_mod::SlavegrpB32FnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_b32_fn_mod;
