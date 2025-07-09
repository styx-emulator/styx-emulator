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
#[doc = "Register `PIO4` reader"]
pub type R = crate::R<Pio4Spec>;
#[doc = "Register `PIO4` writer"]
pub type W = crate::W<Pio4Spec>;
#[doc = "Field `IOSETx` reader - IOSETx"]
pub type IosetxR = crate::FieldReader;
#[doc = "Field `IOSETx` writer - IOSETx"]
pub type IosetxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IOWAITx` reader - IOWAITx"]
pub type IowaitxR = crate::FieldReader;
#[doc = "Field `IOWAITx` writer - IOWAITx"]
pub type IowaitxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IOHOLDx` reader - IOHOLDx"]
pub type IoholdxR = crate::FieldReader;
#[doc = "Field `IOHOLDx` writer - IOHOLDx"]
pub type IoholdxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `IOHIZx` reader - IOHIZx"]
pub type IohizxR = crate::FieldReader;
#[doc = "Field `IOHIZx` writer - IOHIZx"]
pub type IohizxW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - IOSETx"]
    #[inline(always)]
    pub fn iosetx(&self) -> IosetxR {
        IosetxR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - IOWAITx"]
    #[inline(always)]
    pub fn iowaitx(&self) -> IowaitxR {
        IowaitxR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - IOHOLDx"]
    #[inline(always)]
    pub fn ioholdx(&self) -> IoholdxR {
        IoholdxR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - IOHIZx"]
    #[inline(always)]
    pub fn iohizx(&self) -> IohizxR {
        IohizxR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - IOSETx"]
    #[inline(always)]
    #[must_use]
    pub fn iosetx(&mut self) -> IosetxW<Pio4Spec> {
        IosetxW::new(self, 0)
    }
    #[doc = "Bits 8:15 - IOWAITx"]
    #[inline(always)]
    #[must_use]
    pub fn iowaitx(&mut self) -> IowaitxW<Pio4Spec> {
        IowaitxW::new(self, 8)
    }
    #[doc = "Bits 16:23 - IOHOLDx"]
    #[inline(always)]
    #[must_use]
    pub fn ioholdx(&mut self) -> IoholdxW<Pio4Spec> {
        IoholdxW::new(self, 16)
    }
    #[doc = "Bits 24:31 - IOHIZx"]
    #[inline(always)]
    #[must_use]
    pub fn iohizx(&mut self) -> IohizxW<Pio4Spec> {
        IohizxW::new(self, 24)
    }
}
#[doc = "I/O space timing register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pio4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pio4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Pio4Spec;
impl crate::RegisterSpec for Pio4Spec {
    type Ux = u32;
    const OFFSET: u64 = 176u64;
}
#[doc = "`read()` method returns [`pio4::R`](R) reader structure"]
impl crate::Readable for Pio4Spec {}
#[doc = "`write(|w| ..)` method takes [`pio4::W`](W) writer structure"]
impl crate::Writable for Pio4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PIO4 to value 0xfcfc_fcfc"]
impl crate::Resettable for Pio4Spec {
    const RESET_VALUE: u32 = 0xfcfc_fcfc;
}
