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
#[doc = "Register `STR` reader"]
pub type R = crate::R<StrSpec>;
#[doc = "Register `STR` writer"]
pub type W = crate::W<StrSpec>;
#[doc = "Field `NBLW` reader - Number of valid bits in the last word of the message"]
pub type NblwR = crate::FieldReader;
#[doc = "Field `NBLW` writer - Number of valid bits in the last word of the message"]
pub type NblwW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `DCAL` reader - Digest calculation"]
pub type DcalR = crate::BitReader;
#[doc = "Field `DCAL` writer - Digest calculation"]
pub type DcalW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:4 - Number of valid bits in the last word of the message"]
    #[inline(always)]
    pub fn nblw(&self) -> NblwR {
        NblwR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bit 8 - Digest calculation"]
    #[inline(always)]
    pub fn dcal(&self) -> DcalR {
        DcalR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:4 - Number of valid bits in the last word of the message"]
    #[inline(always)]
    #[must_use]
    pub fn nblw(&mut self) -> NblwW<StrSpec> {
        NblwW::new(self, 0)
    }
    #[doc = "Bit 8 - Digest calculation"]
    #[inline(always)]
    #[must_use]
    pub fn dcal(&mut self) -> DcalW<StrSpec> {
        DcalW::new(self, 8)
    }
}
#[doc = "start register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`str::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`str::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StrSpec;
impl crate::RegisterSpec for StrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`str::R`](R) reader structure"]
impl crate::Readable for StrSpec {}
#[doc = "`write(|w| ..)` method takes [`str::W`](W) writer structure"]
impl crate::Writable for StrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets STR to value 0"]
impl crate::Resettable for StrSpec {
    const RESET_VALUE: u32 = 0;
}
