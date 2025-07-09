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
#[doc = "Register `gmacgrp_Hash_Table_Reg1` reader"]
pub type R = crate::R<GmacgrpHashTableReg1Spec>;
#[doc = "Register `gmacgrp_Hash_Table_Reg1` writer"]
pub type W = crate::W<GmacgrpHashTableReg1Spec>;
#[doc = "Field `ht63t32` reader - This field contains the second 32 Bits (63:32) of the Hash table."]
pub type Ht63t32R = crate::FieldReader<u32>;
#[doc = "Field `ht63t32` writer - This field contains the second 32 Bits (63:32) of the Hash table."]
pub type Ht63t32W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This field contains the second 32 Bits (63:32) of the Hash table."]
    #[inline(always)]
    pub fn ht63t32(&self) -> Ht63t32R {
        Ht63t32R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This field contains the second 32 Bits (63:32) of the Hash table."]
    #[inline(always)]
    #[must_use]
    pub fn ht63t32(&mut self) -> Ht63t32W<GmacgrpHashTableReg1Spec> {
        Ht63t32W::new(self, 0)
    }
}
#[doc = "This register contains the second 32 bits of the hash table.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_hash_table_reg1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_hash_table_reg1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpHashTableReg1Spec;
impl crate::RegisterSpec for GmacgrpHashTableReg1Spec {
    type Ux = u32;
    const OFFSET: u64 = 1284u64;
}
#[doc = "`read()` method returns [`gmacgrp_hash_table_reg1::R`](R) reader structure"]
impl crate::Readable for GmacgrpHashTableReg1Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_hash_table_reg1::W`](W) writer structure"]
impl crate::Writable for GmacgrpHashTableReg1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_Hash_Table_Reg1 to value 0"]
impl crate::Resettable for GmacgrpHashTableReg1Spec {
    const RESET_VALUE: u32 = 0;
}
