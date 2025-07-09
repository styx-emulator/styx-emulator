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
#[doc = "Register `devsz` reader"]
pub type R = crate::R<DevszSpec>;
#[doc = "Register `devsz` writer"]
pub type W = crate::W<DevszSpec>;
#[doc = "Field `numaddrbytes` reader - Number of address bytes. A value of 0 indicates 1 byte."]
pub type NumaddrbytesR = crate::FieldReader;
#[doc = "Field `numaddrbytes` writer - Number of address bytes. A value of 0 indicates 1 byte."]
pub type NumaddrbytesW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `bytesperdevicepage` reader - Number of bytes per device page. This is required by the controller for performing FLASH writes up to and across page boundaries."]
pub type BytesperdevicepageR = crate::FieldReader<u16>;
#[doc = "Field `bytesperdevicepage` writer - Number of bytes per device page. This is required by the controller for performing FLASH writes up to and across page boundaries."]
pub type BytesperdevicepageW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `bytespersubsector` reader - Number of bytes per Block. This is required by the controller for performing the write protection logic. The number of bytes per block must be a power of 2 number."]
pub type BytespersubsectorR = crate::FieldReader;
#[doc = "Field `bytespersubsector` writer - Number of bytes per Block. This is required by the controller for performing the write protection logic. The number of bytes per block must be a power of 2 number."]
pub type BytespersubsectorW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:3 - Number of address bytes. A value of 0 indicates 1 byte."]
    #[inline(always)]
    pub fn numaddrbytes(&self) -> NumaddrbytesR {
        NumaddrbytesR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:15 - Number of bytes per device page. This is required by the controller for performing FLASH writes up to and across page boundaries."]
    #[inline(always)]
    pub fn bytesperdevicepage(&self) -> BytesperdevicepageR {
        BytesperdevicepageR::new(((self.bits >> 4) & 0x0fff) as u16)
    }
    #[doc = "Bits 16:20 - Number of bytes per Block. This is required by the controller for performing the write protection logic. The number of bytes per block must be a power of 2 number."]
    #[inline(always)]
    pub fn bytespersubsector(&self) -> BytespersubsectorR {
        BytespersubsectorR::new(((self.bits >> 16) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Number of address bytes. A value of 0 indicates 1 byte."]
    #[inline(always)]
    #[must_use]
    pub fn numaddrbytes(&mut self) -> NumaddrbytesW<DevszSpec> {
        NumaddrbytesW::new(self, 0)
    }
    #[doc = "Bits 4:15 - Number of bytes per device page. This is required by the controller for performing FLASH writes up to and across page boundaries."]
    #[inline(always)]
    #[must_use]
    pub fn bytesperdevicepage(&mut self) -> BytesperdevicepageW<DevszSpec> {
        BytesperdevicepageW::new(self, 4)
    }
    #[doc = "Bits 16:20 - Number of bytes per Block. This is required by the controller for performing the write protection logic. The number of bytes per block must be a power of 2 number."]
    #[inline(always)]
    #[must_use]
    pub fn bytespersubsector(&mut self) -> BytespersubsectorW<DevszSpec> {
        BytespersubsectorW::new(self, 16)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devsz::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devsz::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevszSpec;
impl crate::RegisterSpec for DevszSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`devsz::R`](R) reader structure"]
impl crate::Readable for DevszSpec {}
#[doc = "`write(|w| ..)` method takes [`devsz::W`](W) writer structure"]
impl crate::Writable for DevszSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devsz to value 0x0010_1002"]
impl crate::Resettable for DevszSpec {
    const RESET_VALUE: u32 = 0x0010_1002;
}
