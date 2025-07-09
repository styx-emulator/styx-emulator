// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `idgrp_comp_id_0` reader"]
pub type R = crate::R<IdgrpCompId0Spec>;
#[doc = "Register `idgrp_comp_id_0` writer"]
pub type W = crate::W<IdgrpCompId0Spec>;
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
    pub fn preamble(&mut self) -> PreambleW<IdgrpCompId0Spec> {
        PreambleW::new(self, 0)
    }
}
#[doc = "Component ID0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpCompId0Spec;
impl crate::RegisterSpec for IdgrpCompId0Spec {
    type Ux = u32;
    const OFFSET: u64 = 8176u64;
}
#[doc = "`read()` method returns [`idgrp_comp_id_0::R`](R) reader structure"]
impl crate::Readable for IdgrpCompId0Spec {}
#[doc = "`reset()` method sets idgrp_comp_id_0 to value 0x0d"]
impl crate::Resettable for IdgrpCompId0Spec {
    const RESET_VALUE: u32 = 0x0d;
}
