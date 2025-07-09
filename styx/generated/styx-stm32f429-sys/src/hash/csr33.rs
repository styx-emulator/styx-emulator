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
#[doc = "Register `CSR33` reader"]
pub type R = crate::R<Csr33Spec>;
#[doc = "Register `CSR33` writer"]
pub type W = crate::W<Csr33Spec>;
#[doc = "Field `CSR33` reader - CSR33"]
pub type Csr33R = crate::FieldReader<u32>;
#[doc = "Field `CSR33` writer - CSR33"]
pub type Csr33W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR33"]
    #[inline(always)]
    pub fn csr33(&self) -> Csr33R {
        Csr33R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR33"]
    #[inline(always)]
    #[must_use]
    pub fn csr33(&mut self) -> Csr33W<Csr33Spec> {
        Csr33W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr33::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr33::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr33Spec;
impl crate::RegisterSpec for Csr33Spec {
    type Ux = u32;
    const OFFSET: u64 = 380u64;
}
#[doc = "`read()` method returns [`csr33::R`](R) reader structure"]
impl crate::Readable for Csr33Spec {}
#[doc = "`write(|w| ..)` method takes [`csr33::W`](W) writer structure"]
impl crate::Writable for Csr33Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR33 to value 0"]
impl crate::Resettable for Csr33Spec {
    const RESET_VALUE: u32 = 0;
}
