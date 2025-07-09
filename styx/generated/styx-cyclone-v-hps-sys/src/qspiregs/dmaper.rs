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
#[doc = "Register `dmaper` reader"]
pub type R = crate::R<DmaperSpec>;
#[doc = "Register `dmaper` writer"]
pub type W = crate::W<DmaperSpec>;
#[doc = "Field `numsglreqbytes` reader - Number of bytes in a single type request on the DMA peripheral request. A programmed value of 0 represents a single byte. This should be setup before starting the indirect read or write operation. The actual number of bytes used is 2**(value in this register) which will simplify implementation."]
pub type NumsglreqbytesR = crate::FieldReader;
#[doc = "Field `numsglreqbytes` writer - Number of bytes in a single type request on the DMA peripheral request. A programmed value of 0 represents a single byte. This should be setup before starting the indirect read or write operation. The actual number of bytes used is 2**(value in this register) which will simplify implementation."]
pub type NumsglreqbytesW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `numburstreqbytes` reader - Number of bytes in a burst type request on the DMA peripheral request. A programmed value of 0 represents a single byte. This should be setup before starting the indirect read or write operation. The actual number of bytes used is 2**(value in this register) which will simplify implementation."]
pub type NumburstreqbytesR = crate::FieldReader;
#[doc = "Field `numburstreqbytes` writer - Number of bytes in a burst type request on the DMA peripheral request. A programmed value of 0 represents a single byte. This should be setup before starting the indirect read or write operation. The actual number of bytes used is 2**(value in this register) which will simplify implementation."]
pub type NumburstreqbytesW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Number of bytes in a single type request on the DMA peripheral request. A programmed value of 0 represents a single byte. This should be setup before starting the indirect read or write operation. The actual number of bytes used is 2**(value in this register) which will simplify implementation."]
    #[inline(always)]
    pub fn numsglreqbytes(&self) -> NumsglreqbytesR {
        NumsglreqbytesR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 8:11 - Number of bytes in a burst type request on the DMA peripheral request. A programmed value of 0 represents a single byte. This should be setup before starting the indirect read or write operation. The actual number of bytes used is 2**(value in this register) which will simplify implementation."]
    #[inline(always)]
    pub fn numburstreqbytes(&self) -> NumburstreqbytesR {
        NumburstreqbytesR::new(((self.bits >> 8) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Number of bytes in a single type request on the DMA peripheral request. A programmed value of 0 represents a single byte. This should be setup before starting the indirect read or write operation. The actual number of bytes used is 2**(value in this register) which will simplify implementation."]
    #[inline(always)]
    #[must_use]
    pub fn numsglreqbytes(&mut self) -> NumsglreqbytesW<DmaperSpec> {
        NumsglreqbytesW::new(self, 0)
    }
    #[doc = "Bits 8:11 - Number of bytes in a burst type request on the DMA peripheral request. A programmed value of 0 represents a single byte. This should be setup before starting the indirect read or write operation. The actual number of bytes used is 2**(value in this register) which will simplify implementation."]
    #[inline(always)]
    #[must_use]
    pub fn numburstreqbytes(&mut self) -> NumburstreqbytesW<DmaperSpec> {
        NumburstreqbytesW::new(self, 8)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmaper::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmaper::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaperSpec;
impl crate::RegisterSpec for DmaperSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`dmaper::R`](R) reader structure"]
impl crate::Readable for DmaperSpec {}
#[doc = "`write(|w| ..)` method takes [`dmaper::W`](W) writer structure"]
impl crate::Writable for DmaperSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmaper to value 0"]
impl crate::Resettable for DmaperSpec {
    const RESET_VALUE: u32 = 0;
}
