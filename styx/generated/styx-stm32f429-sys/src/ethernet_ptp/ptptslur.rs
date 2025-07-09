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
#[doc = "Register `PTPTSLUR` reader"]
pub type R = crate::R<PtptslurSpec>;
#[doc = "Register `PTPTSLUR` writer"]
pub type W = crate::W<PtptslurSpec>;
#[doc = "Field `TSUSS` reader - TSUSS"]
pub type TsussR = crate::FieldReader<u32>;
#[doc = "Field `TSUSS` writer - TSUSS"]
pub type TsussW<'a, REG> = crate::FieldWriter<'a, REG, 31, u32>;
#[doc = "Field `TSUPNS` reader - TSUSS"]
pub type TsupnsR = crate::BitReader;
#[doc = "Field `TSUPNS` writer - TSUSS"]
pub type TsupnsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:30 - TSUSS"]
    #[inline(always)]
    pub fn tsuss(&self) -> TsussR {
        TsussR::new(self.bits & 0x7fff_ffff)
    }
    #[doc = "Bit 31 - TSUSS"]
    #[inline(always)]
    pub fn tsupns(&self) -> TsupnsR {
        TsupnsR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:30 - TSUSS"]
    #[inline(always)]
    #[must_use]
    pub fn tsuss(&mut self) -> TsussW<PtptslurSpec> {
        TsussW::new(self, 0)
    }
    #[doc = "Bit 31 - TSUSS"]
    #[inline(always)]
    #[must_use]
    pub fn tsupns(&mut self) -> TsupnsW<PtptslurSpec> {
        TsupnsW::new(self, 31)
    }
}
#[doc = "Ethernet PTP time stamp low update register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptslur::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ptptslur::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptslurSpec;
impl crate::RegisterSpec for PtptslurSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`ptptslur::R`](R) reader structure"]
impl crate::Readable for PtptslurSpec {}
#[doc = "`write(|w| ..)` method takes [`ptptslur::W`](W) writer structure"]
impl crate::Writable for PtptslurSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PTPTSLUR to value 0"]
impl crate::Resettable for PtptslurSpec {
    const RESET_VALUE: u32 = 0;
}
