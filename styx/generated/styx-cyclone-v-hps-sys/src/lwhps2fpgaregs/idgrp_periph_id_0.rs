// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `idgrp_periph_id_0` reader"]
pub type R = crate::R<IdgrpPeriphId0Spec>;
#[doc = "Register `idgrp_periph_id_0` writer"]
pub type W = crate::W<IdgrpPeriphId0Spec>;
#[doc = "Field `pn7to0` reader - Part Number \\[7:0\\]"]
pub type Pn7to0R = crate::FieldReader;
#[doc = "Field `pn7to0` writer - Part Number \\[7:0\\]"]
pub type Pn7to0W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Part Number \\[7:0\\]"]
    #[inline(always)]
    pub fn pn7to0(&self) -> Pn7to0R {
        Pn7to0R::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Part Number \\[7:0\\]"]
    #[inline(always)]
    #[must_use]
    pub fn pn7to0(&mut self) -> Pn7to0W<IdgrpPeriphId0Spec> {
        Pn7to0W::new(self, 0)
    }
}
#[doc = "Peripheral ID0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpPeriphId0Spec;
impl crate::RegisterSpec for IdgrpPeriphId0Spec {
    type Ux = u32;
    const OFFSET: u64 = 8160u64;
}
#[doc = "`read()` method returns [`idgrp_periph_id_0::R`](R) reader structure"]
impl crate::Readable for IdgrpPeriphId0Spec {}
#[doc = "`reset()` method sets idgrp_periph_id_0 to value 0x01"]
impl crate::Resettable for IdgrpPeriphId0Spec {
    const RESET_VALUE: u32 = 0x01;
}
