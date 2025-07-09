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
#[doc = "Register `HASH_HR6` reader"]
pub type R = crate::R<HashHr6Spec>;
#[doc = "Register `HASH_HR6` writer"]
pub type W = crate::W<HashHr6Spec>;
#[doc = "Field `H6` reader - H6"]
pub type H6R = crate::FieldReader<u32>;
#[doc = "Field `H6` writer - H6"]
pub type H6W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - H6"]
    #[inline(always)]
    pub fn h6(&self) -> H6R {
        H6R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - H6"]
    #[inline(always)]
    #[must_use]
    pub fn h6(&mut self) -> H6W<HashHr6Spec> {
        H6W::new(self, 0)
    }
}
#[doc = "read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr6::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HashHr6Spec;
impl crate::RegisterSpec for HashHr6Spec {
    type Ux = u32;
    const OFFSET: u64 = 808u64;
}
#[doc = "`read()` method returns [`hash_hr6::R`](R) reader structure"]
impl crate::Readable for HashHr6Spec {}
#[doc = "`reset()` method sets HASH_HR6 to value 0"]
impl crate::Resettable for HashHr6Spec {
    const RESET_VALUE: u32 = 0;
}
