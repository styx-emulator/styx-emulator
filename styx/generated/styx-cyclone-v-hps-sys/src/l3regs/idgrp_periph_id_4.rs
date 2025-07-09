// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `idgrp_periph_id_4` reader"]
pub type R = crate::R<IdgrpPeriphId4Spec>;
#[doc = "Register `idgrp_periph_id_4` writer"]
pub type W = crate::W<IdgrpPeriphId4Spec>;
#[doc = "Field `periph_id_4` reader - JEP106 continuation code"]
pub type PeriphId4R = crate::FieldReader;
#[doc = "Field `periph_id_4` writer - JEP106 continuation code"]
pub type PeriphId4W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - JEP106 continuation code"]
    #[inline(always)]
    pub fn periph_id_4(&self) -> PeriphId4R {
        PeriphId4R::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - JEP106 continuation code"]
    #[inline(always)]
    #[must_use]
    pub fn periph_id_4(&mut self) -> PeriphId4W<IdgrpPeriphId4Spec> {
        PeriphId4W::new(self, 0)
    }
}
#[doc = "JEP106 continuation code\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_4::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpPeriphId4Spec;
impl crate::RegisterSpec for IdgrpPeriphId4Spec {
    type Ux = u32;
    const OFFSET: u64 = 8144u64;
}
#[doc = "`read()` method returns [`idgrp_periph_id_4::R`](R) reader structure"]
impl crate::Readable for IdgrpPeriphId4Spec {}
#[doc = "`reset()` method sets idgrp_periph_id_4 to value 0x04"]
impl crate::Resettable for IdgrpPeriphId4Spec {
    const RESET_VALUE: u32 = 0x04;
}
