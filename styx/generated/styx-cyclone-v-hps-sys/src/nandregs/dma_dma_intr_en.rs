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
#[doc = "Register `dma_dma_intr_en` reader"]
pub type R = crate::R<DmaDmaIntrEnSpec>;
#[doc = "Register `dma_dma_intr_en` writer"]
pub type W = crate::W<DmaDmaIntrEnSpec>;
#[doc = "Field `target_error` reader - Controller initiator interface received an ERROR target response for a transaction."]
pub type TargetErrorR = crate::BitReader;
#[doc = "Field `target_error` writer - Controller initiator interface received an ERROR target response for a transaction."]
pub type TargetErrorW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Controller initiator interface received an ERROR target response for a transaction."]
    #[inline(always)]
    pub fn target_error(&self) -> TargetErrorR {
        TargetErrorR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controller initiator interface received an ERROR target response for a transaction."]
    #[inline(always)]
    #[must_use]
    pub fn target_error(&mut self) -> TargetErrorW<DmaDmaIntrEnSpec> {
        TargetErrorW::new(self, 0)
    }
}
#[doc = "Enables corresponding interrupt bit in dma interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_dma_intr_en::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_dma_intr_en::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaDmaIntrEnSpec;
impl crate::RegisterSpec for DmaDmaIntrEnSpec {
    type Ux = u32;
    const OFFSET: u64 = 1840u64;
}
#[doc = "`read()` method returns [`dma_dma_intr_en::R`](R) reader structure"]
impl crate::Readable for DmaDmaIntrEnSpec {}
#[doc = "`write(|w| ..)` method takes [`dma_dma_intr_en::W`](W) writer structure"]
impl crate::Writable for DmaDmaIntrEnSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dma_dma_intr_en to value 0"]
impl crate::Resettable for DmaDmaIntrEnSpec {
    const RESET_VALUE: u32 = 0;
}
