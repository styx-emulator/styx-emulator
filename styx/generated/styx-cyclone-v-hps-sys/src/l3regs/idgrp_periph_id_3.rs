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
#[doc = "Register `idgrp_periph_id_3` reader"]
pub type R = crate::R<IdgrpPeriphId3Spec>;
#[doc = "Register `idgrp_periph_id_3` writer"]
pub type W = crate::W<IdgrpPeriphId3Spec>;
#[doc = "Field `cust_mod_num` reader - Customer Model Number"]
pub type CustModNumR = crate::FieldReader;
#[doc = "Field `cust_mod_num` writer - Customer Model Number"]
pub type CustModNumW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `rev_and` reader - Revision"]
pub type RevAndR = crate::FieldReader;
#[doc = "Field `rev_and` writer - Revision"]
pub type RevAndW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Customer Model Number"]
    #[inline(always)]
    pub fn cust_mod_num(&self) -> CustModNumR {
        CustModNumR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - Revision"]
    #[inline(always)]
    pub fn rev_and(&self) -> RevAndR {
        RevAndR::new(((self.bits >> 4) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Customer Model Number"]
    #[inline(always)]
    #[must_use]
    pub fn cust_mod_num(&mut self) -> CustModNumW<IdgrpPeriphId3Spec> {
        CustModNumW::new(self, 0)
    }
    #[doc = "Bits 4:7 - Revision"]
    #[inline(always)]
    #[must_use]
    pub fn rev_and(&mut self) -> RevAndW<IdgrpPeriphId3Spec> {
        RevAndW::new(self, 4)
    }
}
#[doc = "Peripheral ID3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_periph_id_3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpPeriphId3Spec;
impl crate::RegisterSpec for IdgrpPeriphId3Spec {
    type Ux = u32;
    const OFFSET: u64 = 8172u64;
}
#[doc = "`read()` method returns [`idgrp_periph_id_3::R`](R) reader structure"]
impl crate::Readable for IdgrpPeriphId3Spec {}
#[doc = "`reset()` method sets idgrp_periph_id_3 to value 0"]
impl crate::Resettable for IdgrpPeriphId3Spec {
    const RESET_VALUE: u32 = 0;
}
