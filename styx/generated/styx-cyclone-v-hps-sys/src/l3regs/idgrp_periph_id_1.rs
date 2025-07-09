// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `idgrp_periph_id_1` reader"]
pub type R = crate::R<IdgrpPeriphId1Spec>;
#[doc = "Register `idgrp_periph_id_1` writer"]
pub type W = crate::W<IdgrpPeriphId1Spec>;
#[doc = "Field `jep3to0_pn11to8` reader - JEP106\\[3:0\\], Part Number \\[11:8\\]"]
pub type Jep3to0Pn11to8R = crate::FieldReader;
#[doc = "Field `jep3to0_pn11to8` writer - JEP106\\[3:0\\], Part Number \\[11:8\\]"]
pub type Jep3to0Pn11to8W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - JEP106\\[3:0\\], Part Number \\[11:8\\]"]
    #[inline(always)]
    pub fn jep3to0_pn11to8(&self) -> Jep3to0Pn11to8R {
        Jep3to0Pn11to8R::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - JEP106\\[3:0\\], Part Number \\[11:8\\]"]
    #[inline(always)]
    #[must_use]
    pub fn jep3to0_pn11to8(&mut self) -> Jep3to0Pn11to8W<IdgrpPeriphId1Spec> {
        Jep3to0Pn11to8W::new(self, 0)
    }
}
#[doc = "Peripheral ID1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpPeriphId1Spec;
impl crate::RegisterSpec for IdgrpPeriphId1Spec {
    type Ux = u32;
    const OFFSET: u64 = 8164u64;
}
#[doc = "`read()` method returns [`idgrp_periph_id_1::R`](R) reader structure"]
impl crate::Readable for IdgrpPeriphId1Spec {}
#[doc = "`reset()` method sets idgrp_periph_id_1 to value 0xb3"]
impl crate::Resettable for IdgrpPeriphId1Spec {
    const RESET_VALUE: u32 = 0xb3;
}
