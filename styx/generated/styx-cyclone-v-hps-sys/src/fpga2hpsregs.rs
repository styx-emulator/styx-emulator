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
    _reserved9: [u8; 0x0004_0024],
    slavegrp_b32_fn_mod2: SlavegrpB32FnMod2,
    _reserved10: [u8; 0xe0],
    slavegrp_b32_fn_mod: SlavegrpB32FnMod,
    _reserved11: [u8; 0x1f18],
    slavegrp_b128_fn_mod2: SlavegrpB128FnMod2,
    _reserved12: [u8; 0xe0],
    slavegrp_b128_fn_mod: SlavegrpB128FnMod,
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
    #[doc = "0x42024 - Controls bypass merge of upsizing/downsizing."]
    #[inline(always)]
    pub const fn slavegrp_b32_fn_mod2(&self) -> &SlavegrpB32FnMod2 {
        &self.slavegrp_b32_fn_mod2
    }
    #[doc = "0x42108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_b32_fn_mod(&self) -> &SlavegrpB32FnMod {
        &self.slavegrp_b32_fn_mod
    }
    #[doc = "0x44024 - Controls bypass merge of upsizing/downsizing."]
    #[inline(always)]
    pub const fn slavegrp_b128_fn_mod2(&self) -> &SlavegrpB128FnMod2 {
        &self.slavegrp_b128_fn_mod2
    }
    #[doc = "0x44108 - Sets the block issuing capability to multiple or single outstanding transactions."]
    #[inline(always)]
    pub const fn slavegrp_b128_fn_mod(&self) -> &SlavegrpB128FnMod {
        &self.slavegrp_b128_fn_mod
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
#[doc = "slavegrp_b32_fn_mod2 (rw) register accessor: Controls bypass merge of upsizing/downsizing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_b32_fn_mod2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_b32_fn_mod2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_b32_fn_mod2`]
module"]
#[doc(alias = "slavegrp_b32_fn_mod2")]
pub type SlavegrpB32FnMod2 = crate::Reg<slavegrp_b32_fn_mod2::SlavegrpB32FnMod2Spec>;
#[doc = "Controls bypass merge of upsizing/downsizing."]
pub mod slavegrp_b32_fn_mod2;
#[doc = "slavegrp_b32_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_b32_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_b32_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_b32_fn_mod`]
module"]
#[doc(alias = "slavegrp_b32_fn_mod")]
pub type SlavegrpB32FnMod = crate::Reg<slavegrp_b32_fn_mod::SlavegrpB32FnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_b32_fn_mod;
#[doc = "slavegrp_b128_fn_mod2 (rw) register accessor: Controls bypass merge of upsizing/downsizing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_b128_fn_mod2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_b128_fn_mod2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_b128_fn_mod2`]
module"]
#[doc(alias = "slavegrp_b128_fn_mod2")]
pub type SlavegrpB128FnMod2 = crate::Reg<slavegrp_b128_fn_mod2::SlavegrpB128FnMod2Spec>;
#[doc = "Controls bypass merge of upsizing/downsizing."]
pub mod slavegrp_b128_fn_mod2;
#[doc = "slavegrp_b128_fn_mod (rw) register accessor: Sets the block issuing capability to multiple or single outstanding transactions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`slavegrp_b128_fn_mod::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`slavegrp_b128_fn_mod::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@slavegrp_b128_fn_mod`]
module"]
#[doc(alias = "slavegrp_b128_fn_mod")]
pub type SlavegrpB128FnMod = crate::Reg<slavegrp_b128_fn_mod::SlavegrpB128FnModSpec>;
#[doc = "Sets the block issuing capability to multiple or single outstanding transactions."]
pub mod slavegrp_b128_fn_mod;
