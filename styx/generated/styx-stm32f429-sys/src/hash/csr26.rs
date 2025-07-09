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
#[doc = "Register `CSR26` reader"]
pub type R = crate::R<Csr26Spec>;
#[doc = "Register `CSR26` writer"]
pub type W = crate::W<Csr26Spec>;
#[doc = "Field `CSR26` reader - CSR26"]
pub type Csr26R = crate::FieldReader<u32>;
#[doc = "Field `CSR26` writer - CSR26"]
pub type Csr26W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR26"]
    #[inline(always)]
    pub fn csr26(&self) -> Csr26R {
        Csr26R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR26"]
    #[inline(always)]
    #[must_use]
    pub fn csr26(&mut self) -> Csr26W<Csr26Spec> {
        Csr26W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr26::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr26::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr26Spec;
impl crate::RegisterSpec for Csr26Spec {
    type Ux = u32;
    const OFFSET: u64 = 352u64;
}
#[doc = "`read()` method returns [`csr26::R`](R) reader structure"]
impl crate::Readable for Csr26Spec {}
#[doc = "`write(|w| ..)` method takes [`csr26::W`](W) writer structure"]
impl crate::Writable for Csr26Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR26 to value 0"]
impl crate::Resettable for Csr26Spec {
    const RESET_VALUE: u32 = 0;
}
