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
#[doc = "Register `MACVLANTR` reader"]
pub type R = crate::R<MacvlantrSpec>;
#[doc = "Register `MACVLANTR` writer"]
pub type W = crate::W<MacvlantrSpec>;
#[doc = "Field `VLANTI` reader - VLANTI"]
pub type VlantiR = crate::FieldReader<u16>;
#[doc = "Field `VLANTI` writer - VLANTI"]
pub type VlantiW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `VLANTC` reader - VLANTC"]
pub type VlantcR = crate::BitReader;
#[doc = "Field `VLANTC` writer - VLANTC"]
pub type VlantcW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - VLANTI"]
    #[inline(always)]
    pub fn vlanti(&self) -> VlantiR {
        VlantiR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bit 16 - VLANTC"]
    #[inline(always)]
    pub fn vlantc(&self) -> VlantcR {
        VlantcR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - VLANTI"]
    #[inline(always)]
    #[must_use]
    pub fn vlanti(&mut self) -> VlantiW<MacvlantrSpec> {
        VlantiW::new(self, 0)
    }
    #[doc = "Bit 16 - VLANTC"]
    #[inline(always)]
    #[must_use]
    pub fn vlantc(&mut self) -> VlantcW<MacvlantrSpec> {
        VlantcW::new(self, 16)
    }
}
#[doc = "Ethernet MAC VLAN tag register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macvlantr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macvlantr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacvlantrSpec;
impl crate::RegisterSpec for MacvlantrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`macvlantr::R`](R) reader structure"]
impl crate::Readable for MacvlantrSpec {}
#[doc = "`write(|w| ..)` method takes [`macvlantr::W`](W) writer structure"]
impl crate::Writable for MacvlantrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACVLANTR to value 0"]
impl crate::Resettable for MacvlantrSpec {
    const RESET_VALUE: u32 = 0;
}
