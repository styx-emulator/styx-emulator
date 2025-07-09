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
#[doc = "Register `MACSR` reader"]
pub type R = crate::R<MacsrSpec>;
#[doc = "Register `MACSR` writer"]
pub type W = crate::W<MacsrSpec>;
#[doc = "Field `PMTS` reader - PMTS"]
pub type PmtsR = crate::BitReader;
#[doc = "Field `PMTS` writer - PMTS"]
pub type PmtsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MMCS` reader - MMCS"]
pub type MmcsR = crate::BitReader;
#[doc = "Field `MMCS` writer - MMCS"]
pub type MmcsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MMCRS` reader - MMCRS"]
pub type MmcrsR = crate::BitReader;
#[doc = "Field `MMCRS` writer - MMCRS"]
pub type MmcrsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MMCTS` reader - MMCTS"]
pub type MmctsR = crate::BitReader;
#[doc = "Field `MMCTS` writer - MMCTS"]
pub type MmctsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSTS` reader - TSTS"]
pub type TstsR = crate::BitReader;
#[doc = "Field `TSTS` writer - TSTS"]
pub type TstsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 3 - PMTS"]
    #[inline(always)]
    pub fn pmts(&self) -> PmtsR {
        PmtsR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - MMCS"]
    #[inline(always)]
    pub fn mmcs(&self) -> MmcsR {
        MmcsR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - MMCRS"]
    #[inline(always)]
    pub fn mmcrs(&self) -> MmcrsR {
        MmcrsR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - MMCTS"]
    #[inline(always)]
    pub fn mmcts(&self) -> MmctsR {
        MmctsR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 9 - TSTS"]
    #[inline(always)]
    pub fn tsts(&self) -> TstsR {
        TstsR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 3 - PMTS"]
    #[inline(always)]
    #[must_use]
    pub fn pmts(&mut self) -> PmtsW<MacsrSpec> {
        PmtsW::new(self, 3)
    }
    #[doc = "Bit 4 - MMCS"]
    #[inline(always)]
    #[must_use]
    pub fn mmcs(&mut self) -> MmcsW<MacsrSpec> {
        MmcsW::new(self, 4)
    }
    #[doc = "Bit 5 - MMCRS"]
    #[inline(always)]
    #[must_use]
    pub fn mmcrs(&mut self) -> MmcrsW<MacsrSpec> {
        MmcrsW::new(self, 5)
    }
    #[doc = "Bit 6 - MMCTS"]
    #[inline(always)]
    #[must_use]
    pub fn mmcts(&mut self) -> MmctsW<MacsrSpec> {
        MmctsW::new(self, 6)
    }
    #[doc = "Bit 9 - TSTS"]
    #[inline(always)]
    #[must_use]
    pub fn tsts(&mut self) -> TstsW<MacsrSpec> {
        TstsW::new(self, 9)
    }
}
#[doc = "Ethernet MAC interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macsr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macsr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacsrSpec;
impl crate::RegisterSpec for MacsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`macsr::R`](R) reader structure"]
impl crate::Readable for MacsrSpec {}
#[doc = "`write(|w| ..)` method takes [`macsr::W`](W) writer structure"]
impl crate::Writable for MacsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACSR to value 0"]
impl crate::Resettable for MacsrSpec {
    const RESET_VALUE: u32 = 0;
}
