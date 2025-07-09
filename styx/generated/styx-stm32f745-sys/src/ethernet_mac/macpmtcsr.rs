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
#[doc = "Register `MACPMTCSR` reader"]
pub type R = crate::R<MacpmtcsrSpec>;
#[doc = "Register `MACPMTCSR` writer"]
pub type W = crate::W<MacpmtcsrSpec>;
#[doc = "Field `PD` reader - PD"]
pub type PdR = crate::BitReader;
#[doc = "Field `PD` writer - PD"]
pub type PdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MPE` reader - MPE"]
pub type MpeR = crate::BitReader;
#[doc = "Field `MPE` writer - MPE"]
pub type MpeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WFE` reader - WFE"]
pub type WfeR = crate::BitReader;
#[doc = "Field `WFE` writer - WFE"]
pub type WfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MPR` reader - MPR"]
pub type MprR = crate::BitReader;
#[doc = "Field `MPR` writer - MPR"]
pub type MprW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WFR` reader - WFR"]
pub type WfrR = crate::BitReader;
#[doc = "Field `WFR` writer - WFR"]
pub type WfrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `GU` reader - GU"]
pub type GuR = crate::BitReader;
#[doc = "Field `GU` writer - GU"]
pub type GuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WFFRPR` reader - WFFRPR"]
pub type WffrprR = crate::BitReader;
#[doc = "Field `WFFRPR` writer - WFFRPR"]
pub type WffrprW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - PD"]
    #[inline(always)]
    pub fn pd(&self) -> PdR {
        PdR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - MPE"]
    #[inline(always)]
    pub fn mpe(&self) -> MpeR {
        MpeR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - WFE"]
    #[inline(always)]
    pub fn wfe(&self) -> WfeR {
        WfeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 5 - MPR"]
    #[inline(always)]
    pub fn mpr(&self) -> MprR {
        MprR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - WFR"]
    #[inline(always)]
    pub fn wfr(&self) -> WfrR {
        WfrR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 9 - GU"]
    #[inline(always)]
    pub fn gu(&self) -> GuR {
        GuR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 31 - WFFRPR"]
    #[inline(always)]
    pub fn wffrpr(&self) -> WffrprR {
        WffrprR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - PD"]
    #[inline(always)]
    #[must_use]
    pub fn pd(&mut self) -> PdW<MacpmtcsrSpec> {
        PdW::new(self, 0)
    }
    #[doc = "Bit 1 - MPE"]
    #[inline(always)]
    #[must_use]
    pub fn mpe(&mut self) -> MpeW<MacpmtcsrSpec> {
        MpeW::new(self, 1)
    }
    #[doc = "Bit 2 - WFE"]
    #[inline(always)]
    #[must_use]
    pub fn wfe(&mut self) -> WfeW<MacpmtcsrSpec> {
        WfeW::new(self, 2)
    }
    #[doc = "Bit 5 - MPR"]
    #[inline(always)]
    #[must_use]
    pub fn mpr(&mut self) -> MprW<MacpmtcsrSpec> {
        MprW::new(self, 5)
    }
    #[doc = "Bit 6 - WFR"]
    #[inline(always)]
    #[must_use]
    pub fn wfr(&mut self) -> WfrW<MacpmtcsrSpec> {
        WfrW::new(self, 6)
    }
    #[doc = "Bit 9 - GU"]
    #[inline(always)]
    #[must_use]
    pub fn gu(&mut self) -> GuW<MacpmtcsrSpec> {
        GuW::new(self, 9)
    }
    #[doc = "Bit 31 - WFFRPR"]
    #[inline(always)]
    #[must_use]
    pub fn wffrpr(&mut self) -> WffrprW<MacpmtcsrSpec> {
        WffrprW::new(self, 31)
    }
}
#[doc = "Ethernet MAC PMT control and status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macpmtcsr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macpmtcsr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacpmtcsrSpec;
impl crate::RegisterSpec for MacpmtcsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`macpmtcsr::R`](R) reader structure"]
impl crate::Readable for MacpmtcsrSpec {}
#[doc = "`write(|w| ..)` method takes [`macpmtcsr::W`](W) writer structure"]
impl crate::Writable for MacpmtcsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACPMTCSR to value 0"]
impl crate::Resettable for MacpmtcsrSpec {
    const RESET_VALUE: u32 = 0;
}
