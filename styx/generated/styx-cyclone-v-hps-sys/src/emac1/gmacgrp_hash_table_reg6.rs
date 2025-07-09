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
#[doc = "Register `gmacgrp_Hash_Table_Reg6` reader"]
pub type R = crate::R<GmacgrpHashTableReg6Spec>;
#[doc = "Register `gmacgrp_Hash_Table_Reg6` writer"]
pub type W = crate::W<GmacgrpHashTableReg6Spec>;
#[doc = "Field `ht223t196` reader - This field contains the seventh 32 Bits (223:196) of the Hash table."]
pub type Ht223t196R = crate::FieldReader<u32>;
#[doc = "Field `ht223t196` writer - This field contains the seventh 32 Bits (223:196) of the Hash table."]
pub type Ht223t196W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field contains the seventh 32 Bits (223:196) of the Hash table."]
    #[inline(always)]
    pub fn ht223t196(&self) -> Ht223t196R {
        Ht223t196R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field contains the seventh 32 Bits (223:196) of the Hash table."]
    #[inline(always)]
    #[must_use]
    pub fn ht223t196(&mut self) -> Ht223t196W<GmacgrpHashTableReg6Spec> {
        Ht223t196W::new(self, 0)
    }
}
#[doc = "This register contains the seventh 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg6::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg6::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpHashTableReg6Spec;
impl crate::RegisterSpec for GmacgrpHashTableReg6Spec {
    type Ux = u32;
    const OFFSET: u64 = 1304u64;
}
#[doc = "`read()` method returns [`gmacgrp_hash_table_reg6::R`](R) reader structure"]
impl crate::Readable for GmacgrpHashTableReg6Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_hash_table_reg6::W`](W) writer structure"]
impl crate::Writable for GmacgrpHashTableReg6Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Hash_Table_Reg6 to value 0"]
impl crate::Resettable for GmacgrpHashTableReg6Spec {
    const RESET_VALUE: u32 = 0;
}
