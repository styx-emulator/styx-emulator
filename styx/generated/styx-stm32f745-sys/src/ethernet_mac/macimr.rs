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
#[doc = "Register `MACIMR` reader"]
pub type R = crate::R<MacimrSpec>;
#[doc = "Register `MACIMR` writer"]
pub type W = crate::W<MacimrSpec>;
#[doc = "Field `PMTIM` reader - PMTIM"]
pub type PmtimR = crate::BitReader;
#[doc = "Field `PMTIM` writer - PMTIM"]
pub type PmtimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSTIM` reader - TSTIM"]
pub type TstimR = crate::BitReader;
#[doc = "Field `TSTIM` writer - TSTIM"]
pub type TstimW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 3 - PMTIM"]
    #[inline(always)]
    pub fn pmtim(&self) -> PmtimR {
        PmtimR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 9 - TSTIM"]
    #[inline(always)]
    pub fn tstim(&self) -> TstimR {
        TstimR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 3 - PMTIM"]
    #[inline(always)]
    #[must_use]
    pub fn pmtim(&mut self) -> PmtimW<MacimrSpec> {
        PmtimW::new(self, 3)
    }
    #[doc = "Bit 9 - TSTIM"]
    #[inline(always)]
    #[must_use]
    pub fn tstim(&mut self) -> TstimW<MacimrSpec> {
        TstimW::new(self, 9)
    }
}
#[doc = "Ethernet MAC interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macimr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macimr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacimrSpec;
impl crate::RegisterSpec for MacimrSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`macimr::R`](R) reader structure"]
impl crate::Readable for MacimrSpec {}
#[doc = "`write(|w| ..)` method takes [`macimr::W`](W) writer structure"]
impl crate::Writable for MacimrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACIMR to value 0"]
impl crate::Resettable for MacimrSpec {
    const RESET_VALUE: u32 = 0;
}
