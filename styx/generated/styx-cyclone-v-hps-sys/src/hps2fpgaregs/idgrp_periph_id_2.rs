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
#[doc = "Register `idgrp_periph_id_2` reader"]
pub type R = crate::R<IdgrpPeriphId2Spec>;
#[doc = "Register `idgrp_periph_id_2` writer"]
pub type W = crate::W<IdgrpPeriphId2Spec>;
#[doc = "Field `rev_jepcode_jep6to4` reader - Revision, JEP106 code flag, JEP106\\[6:4\\]"]
pub type RevJepcodeJep6to4R = crate::FieldReader;
#[doc = "Field `rev_jepcode_jep6to4` writer - Revision, JEP106 code flag, JEP106\\[6:4\\]"]
pub type RevJepcodeJep6to4W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Revision, JEP106 code flag, JEP106\\[6:4\\]"]
    #[inline(always)]
    pub fn rev_jepcode_jep6to4(&self) -> RevJepcodeJep6to4R {
        RevJepcodeJep6to4R::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Revision, JEP106 code flag, JEP106\\[6:4\\]"]
    #[inline(always)]
    #[must_use]
    pub fn rev_jepcode_jep6to4(&mut self) -> RevJepcodeJep6to4W<IdgrpPeriphId2Spec> {
        RevJepcodeJep6to4W::new(self, 0)
    }
}
#[doc = "Peripheral ID2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpPeriphId2Spec;
impl crate::RegisterSpec for IdgrpPeriphId2Spec {
    type Ux = u32;
    const OFFSET: u64 = 8168u64;
}
#[doc = "`read()` method returns [`idgrp_periph_id_2::R`](R) reader structure"]
impl crate::Readable for IdgrpPeriphId2Spec {}
#[doc = "`reset()` method sets idgrp_periph_id_2 to value 0x6b"]
impl crate::Resettable for IdgrpPeriphId2Spec {
    const RESET_VALUE: u32 = 0x6b;
}
