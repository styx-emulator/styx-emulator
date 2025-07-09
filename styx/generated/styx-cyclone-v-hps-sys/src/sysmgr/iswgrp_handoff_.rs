// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
