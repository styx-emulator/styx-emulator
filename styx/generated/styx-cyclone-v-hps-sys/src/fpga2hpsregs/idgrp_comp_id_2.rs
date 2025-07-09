// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `idgrp_comp_id_2` reader"]
pub type R = crate::R<IdgrpCompId2Spec>;
#[doc = "Register `idgrp_comp_id_2` writer"]
pub type W = crate::W<IdgrpCompId2Spec>;
#[doc = "Field `preamble` reader - Preamble"]
pub type PreambleR = crate::FieldReader;
#[doc = "Field `preamble` writer - Preamble"]
pub type PreambleW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Preamble"]
    #[inline(always)]
    pub fn preamble(&self) -> PreambleR {
        PreambleR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Preamble"]
    #[inline(always)]
    #[must_use]
    pub fn preamble(&mut self) -> PreambleW<IdgrpCompId2Spec> {
        PreambleW::new(self, 0)
    }
}
#[doc = "Component ID2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpCompId2Spec;
impl crate::RegisterSpec for IdgrpCompId2Spec {
    type Ux = u32;
    const OFFSET: u64 = 8184u64;
}
#[doc = "`read()` method returns [`idgrp_comp_id_2::R`](R) reader structure"]
impl crate::Readable for IdgrpCompId2Spec {}
#[doc = "`reset()` method sets idgrp_comp_id_2 to value 0x05"]
impl crate::Resettable for IdgrpCompId2Spec {
    const RESET_VALUE: u32 = 0x05;
}
