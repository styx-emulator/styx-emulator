// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `iswgrp_handoff_%s` reader"]
pub type R = crate::R<IswgrpHandoff_Spec>;
#[doc = "Register `iswgrp_handoff_%s` writer"]
pub type W = crate::W<IswgrpHandoff_Spec>;
#[doc = "Field `value` reader - Preloader Handoff Information."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - Preloader Handoff Information."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Preloader Handoff Information."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Preloader Handoff Information."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<IswgrpHandoff_Spec> {
        ValueW::new(self, 0)
    }
}
#[doc = "These registers are used to store handoff infomation between the preloader and the OS. These 8 registers can be used to store any information. The contents of these registers have no impact on the state of the HPS hardware.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`iswgrp_handoff_::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`iswgrp_handoff_::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IswgrpHandoff_Spec;
impl crate::RegisterSpec for IswgrpHandoff_Spec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`iswgrp_handoff_::R`](R) reader structure"]
impl crate::Readable for IswgrpHandoff_Spec {}
#[doc = "`write(|w| ..)` method takes [`iswgrp_handoff_::W`](W) writer structure"]
impl crate::Writable for IswgrpHandoff_Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets iswgrp_handoff_%s to value 0"]
impl crate::Resettable for IswgrpHandoff_Spec {
    const RESET_VALUE: u32 = 0;
}
