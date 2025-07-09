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
#[doc = "Register `CMD` reader"]
pub type R = crate::R<CmdSpec>;
#[doc = "Register `CMD` writer"]
pub type W = crate::W<CmdSpec>;
#[doc = "Field `CMDINDEX` reader - Command index"]
pub type CmdindexR = crate::FieldReader;
#[doc = "Field `CMDINDEX` writer - Command index"]
pub type CmdindexW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `WAITRESP` reader - Wait for response bits"]
pub type WaitrespR = crate::FieldReader;
#[doc = "Field `WAITRESP` writer - Wait for response bits"]
pub type WaitrespW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `WAITINT` reader - CPSM waits for interrupt request"]
pub type WaitintR = crate::BitReader;
#[doc = "Field `WAITINT` writer - CPSM waits for interrupt request"]
pub type WaitintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WAITPEND` reader - CPSM Waits for ends of data transfer (CmdPend internal signal)."]
pub type WaitpendR = crate::BitReader;
#[doc = "Field `WAITPEND` writer - CPSM Waits for ends of data transfer (CmdPend internal signal)."]
pub type WaitpendW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CPSMEN` reader - Command path state machine (CPSM) Enable bit"]
pub type CpsmenR = crate::BitReader;
#[doc = "Field `CPSMEN` writer - Command path state machine (CPSM) Enable bit"]
pub type CpsmenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDIOSuspend` reader - SD I/O suspend command"]
pub type SdiosuspendR = crate::BitReader;
#[doc = "Field `SDIOSuspend` writer - SD I/O suspend command"]
pub type SdiosuspendW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ENCMDcompl` reader - Enable CMD completion"]
pub type EncmdcomplR = crate::BitReader;
#[doc = "Field `ENCMDcompl` writer - Enable CMD completion"]
pub type EncmdcomplW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nIEN` reader - not Interrupt Enable"]
pub type NIenR = crate::BitReader;
#[doc = "Field `nIEN` writer - not Interrupt Enable"]
pub type NIenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CE_ATACMD` reader - CE-ATA command"]
pub type CeAtacmdR = crate::BitReader;
#[doc = "Field `CE_ATACMD` writer - CE-ATA command"]
pub type CeAtacmdW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:5 - Command index"]
    #[inline(always)]
    pub fn cmdindex(&self) -> CmdindexR {
        CmdindexR::new((self.bits & 0x3f) as u8)
    }
    #[doc = "Bits 6:7 - Wait for response bits"]
    #[inline(always)]
    pub fn waitresp(&self) -> WaitrespR {
        WaitrespR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bit 8 - CPSM waits for interrupt request"]
    #[inline(always)]
    pub fn waitint(&self) -> WaitintR {
        WaitintR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - CPSM Waits for ends of data transfer (CmdPend internal signal)."]
    #[inline(always)]
    pub fn waitpend(&self) -> WaitpendR {
        WaitpendR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Command path state machine (CPSM) Enable bit"]
    #[inline(always)]
    pub fn cpsmen(&self) -> CpsmenR {
        CpsmenR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - SD I/O suspend command"]
    #[inline(always)]
    pub fn sdiosuspend(&self) -> SdiosuspendR {
        SdiosuspendR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Enable CMD completion"]
    #[inline(always)]
    pub fn encmdcompl(&self) -> EncmdcomplR {
        EncmdcomplR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - not Interrupt Enable"]
    #[inline(always)]
    pub fn n_ien(&self) -> NIenR {
        NIenR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - CE-ATA command"]
    #[inline(always)]
    pub fn ce_atacmd(&self) -> CeAtacmdR {
        CeAtacmdR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:5 - Command index"]
    #[inline(always)]
    #[must_use]
    pub fn cmdindex(&mut self) -> CmdindexW<CmdSpec> {
        CmdindexW::new(self, 0)
    }
    #[doc = "Bits 6:7 - Wait for response bits"]
    #[inline(always)]
    #[must_use]
    pub fn waitresp(&mut self) -> WaitrespW<CmdSpec> {
        WaitrespW::new(self, 6)
    }
    #[doc = "Bit 8 - CPSM waits for interrupt request"]
    #[inline(always)]
    #[must_use]
    pub fn waitint(&mut self) -> WaitintW<CmdSpec> {
        WaitintW::new(self, 8)
    }
    #[doc = "Bit 9 - CPSM Waits for ends of data transfer (CmdPend internal signal)."]
    #[inline(always)]
    #[must_use]
    pub fn waitpend(&mut self) -> WaitpendW<CmdSpec> {
        WaitpendW::new(self, 9)
    }
    #[doc = "Bit 10 - Command path state machine (CPSM) Enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn cpsmen(&mut self) -> CpsmenW<CmdSpec> {
        CpsmenW::new(self, 10)
    }
    #[doc = "Bit 11 - SD I/O suspend command"]
    #[inline(always)]
    #[must_use]
    pub fn sdiosuspend(&mut self) -> SdiosuspendW<CmdSpec> {
        SdiosuspendW::new(self, 11)
    }
    #[doc = "Bit 12 - Enable CMD completion"]
    #[inline(always)]
    #[must_use]
    pub fn encmdcompl(&mut self) -> EncmdcomplW<CmdSpec> {
        EncmdcomplW::new(self, 12)
    }
    #[doc = "Bit 13 - not Interrupt Enable"]
    #[inline(always)]
    #[must_use]
    pub fn n_ien(&mut self) -> NIenW<CmdSpec> {
        NIenW::new(self, 13)
    }
    #[doc = "Bit 14 - CE-ATA command"]
    #[inline(always)]
    #[must_use]
    pub fn ce_atacmd(&mut self) -> CeAtacmdW<CmdSpec> {
        CeAtacmdW::new(self, 14)
    }
}
#[doc = "command register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cmd::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cmd::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CmdSpec;
impl crate::RegisterSpec for CmdSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`cmd::R`](R) reader structure"]
impl crate::Readable for CmdSpec {}
#[doc = "`write(|w| ..)` method takes [`cmd::W`](W) writer structure"]
impl crate::Writable for CmdSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CMD to value 0"]
impl crate::Resettable for CmdSpec {
    const RESET_VALUE: u32 = 0;
}
