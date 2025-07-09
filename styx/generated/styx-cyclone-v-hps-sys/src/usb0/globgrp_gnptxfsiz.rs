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
#[doc = "Register `globgrp_gnptxfsiz` reader"]
pub type R = crate::R<GlobgrpGnptxfsizSpec>;
#[doc = "Register `globgrp_gnptxfsiz` writer"]
pub type W = crate::W<GlobgrpGnptxfsizSpec>;
#[doc = "Field `nptxfstaddr` reader - Mode: Host only. for host mode, this field is always valid.This field contains the memory start address for Non-periodic Transmit FIFO RAM. This field is set from 16-8192 32 bit words. The application can write a new value in this field. Programmed values must not exceed 8192."]
pub type NptxfstaddrR = crate::FieldReader<u16>;
#[doc = "Field `nptxfstaddr` writer - Mode: Host only. for host mode, this field is always valid.This field contains the memory start address for Non-periodic Transmit FIFO RAM. This field is set from 16-8192 32 bit words. The application can write a new value in this field. Programmed values must not exceed 8192."]
pub type NptxfstaddrW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
#[doc = "Field `nptxfdep` reader - Mode: Host only. for host mode, this field is always valid. The application can write a new value in this field. Programmed values must not exceed 8192"]
pub type NptxfdepR = crate::FieldReader<u16>;
#[doc = "Field `nptxfdep` writer - Mode: Host only. for host mode, this field is always valid. The application can write a new value in this field. Programmed values must not exceed 8192"]
pub type NptxfdepW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:13 - Mode: Host only. for host mode, this field is always valid.This field contains the memory start address for Non-periodic Transmit FIFO RAM. This field is set from 16-8192 32 bit words. The application can write a new value in this field. Programmed values must not exceed 8192."]
    #[inline(always)]
    pub fn nptxfstaddr(&self) -> NptxfstaddrR {
        NptxfstaddrR::new((self.bits & 0x3fff) as u16)
    }
    #[doc = "Bits 16:29 - Mode: Host only. for host mode, this field is always valid. The application can write a new value in this field. Programmed values must not exceed 8192"]
    #[inline(always)]
    pub fn nptxfdep(&self) -> NptxfdepR {
        NptxfdepR::new(((self.bits >> 16) & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:13 - Mode: Host only. for host mode, this field is always valid.This field contains the memory start address for Non-periodic Transmit FIFO RAM. This field is set from 16-8192 32 bit words. The application can write a new value in this field. Programmed values must not exceed 8192."]
    #[inline(always)]
    #[must_use]
    pub fn nptxfstaddr(&mut self) -> NptxfstaddrW<GlobgrpGnptxfsizSpec> {
        NptxfstaddrW::new(self, 0)
    }
    #[doc = "Bits 16:29 - Mode: Host only. for host mode, this field is always valid. The application can write a new value in this field. Programmed values must not exceed 8192"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfdep(&mut self) -> NptxfdepW<GlobgrpGnptxfsizSpec> {
        NptxfdepW::new(self, 16)
    }
}
#[doc = "The application can program the RAM size and the memory start address for the Non-periodic TxFIFO. The fields of this register change, depending on host or device mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gnptxfsiz::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gnptxfsiz::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGnptxfsizSpec;
impl crate::RegisterSpec for GlobgrpGnptxfsizSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`globgrp_gnptxfsiz::R`](R) reader structure"]
impl crate::Readable for GlobgrpGnptxfsizSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_gnptxfsiz::W`](W) writer structure"]
impl crate::Writable for GlobgrpGnptxfsizSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_gnptxfsiz to value 0x2000_2000"]
impl crate::Resettable for GlobgrpGnptxfsizSpec {
    const RESET_VALUE: u32 = 0x2000_2000;
}
