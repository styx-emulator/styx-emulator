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
#[doc = "Register `SAI_BCR1` reader"]
pub type R = crate::R<SaiBcr1Spec>;
#[doc = "Register `SAI_BCR1` writer"]
pub type W = crate::W<SaiBcr1Spec>;
#[doc = "Field `MODE` reader - Audio block mode"]
pub type ModeR = crate::FieldReader;
#[doc = "Field `MODE` writer - Audio block mode"]
pub type ModeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `PRTCFG` reader - Protocol configuration"]
pub type PrtcfgR = crate::FieldReader;
#[doc = "Field `PRTCFG` writer - Protocol configuration"]
pub type PrtcfgW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `DS` reader - Data size"]
pub type DsR = crate::FieldReader;
#[doc = "Field `DS` writer - Data size"]
pub type DsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `LSBFIRST` reader - Least significant bit first"]
pub type LsbfirstR = crate::BitReader;
#[doc = "Field `LSBFIRST` writer - Least significant bit first"]
pub type LsbfirstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CKSTR` reader - Clock strobing edge"]
pub type CkstrR = crate::BitReader;
#[doc = "Field `CKSTR` writer - Clock strobing edge"]
pub type CkstrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SYNCEN` reader - Synchronization enable"]
pub type SyncenR = crate::FieldReader;
#[doc = "Field `SYNCEN` writer - Synchronization enable"]
pub type SyncenW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MONO` reader - Mono mode"]
pub type MonoR = crate::BitReader;
#[doc = "Field `MONO` writer - Mono mode"]
pub type MonoW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OUTDRIV` reader - Output drive"]
pub type OutdrivR = crate::BitReader;
#[doc = "Field `OUTDRIV` writer - Output drive"]
pub type OutdrivW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SAIBEN` reader - Audio block enable"]
pub type SaibenR = crate::BitReader;
#[doc = "Field `SAIBEN` writer - Audio block enable"]
pub type SaibenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DMAEN` reader - DMA enable"]
pub type DmaenR = crate::BitReader;
#[doc = "Field `DMAEN` writer - DMA enable"]
pub type DmaenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NODIV` reader - No divider"]
pub type NodivR = crate::BitReader;
#[doc = "Field `NODIV` writer - No divider"]
pub type NodivW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MCKDIV` reader - Master clock divider"]
pub type MckdivR = crate::FieldReader;
#[doc = "Field `MCKDIV` writer - Master clock divider"]
pub type MckdivW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:1 - Audio block mode"]
    #[inline(always)]
    pub fn mode(&self) -> ModeR {
        ModeR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - Protocol configuration"]
    #[inline(always)]
    pub fn prtcfg(&self) -> PrtcfgR {
        PrtcfgR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 5:7 - Data size"]
    #[inline(always)]
    pub fn ds(&self) -> DsR {
        DsR::new(((self.bits >> 5) & 7) as u8)
    }
    #[doc = "Bit 8 - Least significant bit first"]
    #[inline(always)]
    pub fn lsbfirst(&self) -> LsbfirstR {
        LsbfirstR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Clock strobing edge"]
    #[inline(always)]
    pub fn ckstr(&self) -> CkstrR {
        CkstrR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bits 10:11 - Synchronization enable"]
    #[inline(always)]
    pub fn syncen(&self) -> SyncenR {
        SyncenR::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bit 12 - Mono mode"]
    #[inline(always)]
    pub fn mono(&self) -> MonoR {
        MonoR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Output drive"]
    #[inline(always)]
    pub fn outdriv(&self) -> OutdrivR {
        OutdrivR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 16 - Audio block enable"]
    #[inline(always)]
    pub fn saiben(&self) -> SaibenR {
        SaibenR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - DMA enable"]
    #[inline(always)]
    pub fn dmaen(&self) -> DmaenR {
        DmaenR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 19 - No divider"]
    #[inline(always)]
    pub fn nodiv(&self) -> NodivR {
        NodivR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bits 20:23 - Master clock divider"]
    #[inline(always)]
    pub fn mckdiv(&self) -> MckdivR {
        MckdivR::new(((self.bits >> 20) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Audio block mode"]
    #[inline(always)]
    #[must_use]
    pub fn mode(&mut self) -> ModeW<SaiBcr1Spec> {
        ModeW::new(self, 0)
    }
    #[doc = "Bits 2:3 - Protocol configuration"]
    #[inline(always)]
    #[must_use]
    pub fn prtcfg(&mut self) -> PrtcfgW<SaiBcr1Spec> {
        PrtcfgW::new(self, 2)
    }
    #[doc = "Bits 5:7 - Data size"]
    #[inline(always)]
    #[must_use]
    pub fn ds(&mut self) -> DsW<SaiBcr1Spec> {
        DsW::new(self, 5)
    }
    #[doc = "Bit 8 - Least significant bit first"]
    #[inline(always)]
    #[must_use]
    pub fn lsbfirst(&mut self) -> LsbfirstW<SaiBcr1Spec> {
        LsbfirstW::new(self, 8)
    }
    #[doc = "Bit 9 - Clock strobing edge"]
    #[inline(always)]
    #[must_use]
    pub fn ckstr(&mut self) -> CkstrW<SaiBcr1Spec> {
        CkstrW::new(self, 9)
    }
    #[doc = "Bits 10:11 - Synchronization enable"]
    #[inline(always)]
    #[must_use]
    pub fn syncen(&mut self) -> SyncenW<SaiBcr1Spec> {
        SyncenW::new(self, 10)
    }
    #[doc = "Bit 12 - Mono mode"]
    #[inline(always)]
    #[must_use]
    pub fn mono(&mut self) -> MonoW<SaiBcr1Spec> {
        MonoW::new(self, 12)
    }
    #[doc = "Bit 13 - Output drive"]
    #[inline(always)]
    #[must_use]
    pub fn outdriv(&mut self) -> OutdrivW<SaiBcr1Spec> {
        OutdrivW::new(self, 13)
    }
    #[doc = "Bit 16 - Audio block enable"]
    #[inline(always)]
    #[must_use]
    pub fn saiben(&mut self) -> SaibenW<SaiBcr1Spec> {
        SaibenW::new(self, 16)
    }
    #[doc = "Bit 17 - DMA enable"]
    #[inline(always)]
    #[must_use]
    pub fn dmaen(&mut self) -> DmaenW<SaiBcr1Spec> {
        DmaenW::new(self, 17)
    }
    #[doc = "Bit 19 - No divider"]
    #[inline(always)]
    #[must_use]
    pub fn nodiv(&mut self) -> NodivW<SaiBcr1Spec> {
        NodivW::new(self, 19)
    }
    #[doc = "Bits 20:23 - Master clock divider"]
    #[inline(always)]
    #[must_use]
    pub fn mckdiv(&mut self) -> MckdivW<SaiBcr1Spec> {
        MckdivW::new(self, 20)
    }
}
#[doc = "SAI BConfiguration register 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_bcr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_bcr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SaiBcr1Spec;
impl crate::RegisterSpec for SaiBcr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`sai_bcr1::R`](R) reader structure"]
impl crate::Readable for SaiBcr1Spec {}
#[doc = "`write(|w| ..)` method takes [`sai_bcr1::W`](W) writer structure"]
impl crate::Writable for SaiBcr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SAI_BCR1 to value 0x40"]
impl crate::Resettable for SaiBcr1Spec {
    const RESET_VALUE: u32 = 0x40;
}
