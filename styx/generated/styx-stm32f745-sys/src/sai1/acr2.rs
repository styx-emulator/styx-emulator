// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ACR2` reader"]
pub type R = crate::R<Acr2Spec>;
#[doc = "Register `ACR2` writer"]
pub type W = crate::W<Acr2Spec>;
#[doc = "Field `FTH` reader - FIFO threshold"]
pub type FthR = crate::FieldReader;
#[doc = "Field `FTH` writer - FIFO threshold"]
pub type FthW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `FFLUS` reader - FIFO flush"]
pub type FflusR = crate::BitReader;
#[doc = "Field `FFLUS` writer - FIFO flush"]
pub type FflusW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TRIS` reader - Tristate management on data line"]
pub type TrisR = crate::BitReader;
#[doc = "Field `TRIS` writer - Tristate management on data line"]
pub type TrisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTE` reader - Mute"]
pub type MuteR = crate::BitReader;
#[doc = "Field `MUTE` writer - Mute"]
pub type MuteW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTEVAL` reader - Mute value"]
pub type MutevalR = crate::BitReader;
#[doc = "Field `MUTEVAL` writer - Mute value"]
pub type MutevalW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTECN` reader - Mute counter"]
pub type MutecnR = crate::FieldReader;
#[doc = "Field `MUTECN` writer - Mute counter"]
pub type MutecnW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `CPL` reader - Complement bit"]
pub type CplR = crate::BitReader;
#[doc = "Field `CPL` writer - Complement bit"]
pub type CplW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `COMP` reader - Companding mode"]
pub type CompR = crate::FieldReader;
#[doc = "Field `COMP` writer - Companding mode"]
pub type CompW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:2 - FIFO threshold"]
    #[inline(always)]
    pub fn fth(&self) -> FthR {
        FthR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 3 - FIFO flush"]
    #[inline(always)]
    pub fn fflus(&self) -> FflusR {
        FflusR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Tristate management on data line"]
    #[inline(always)]
    pub fn tris(&self) -> TrisR {
        TrisR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Mute"]
    #[inline(always)]
    pub fn mute(&self) -> MuteR {
        MuteR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Mute value"]
    #[inline(always)]
    pub fn muteval(&self) -> MutevalR {
        MutevalR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bits 7:12 - Mute counter"]
    #[inline(always)]
    pub fn mutecn(&self) -> MutecnR {
        MutecnR::new(((self.bits >> 7) & 0x3f) as u8)
    }
    #[doc = "Bit 13 - Complement bit"]
    #[inline(always)]
    pub fn cpl(&self) -> CplR {
        CplR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 14:15 - Companding mode"]
    #[inline(always)]
    pub fn comp(&self) -> CompR {
        CompR::new(((self.bits >> 14) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - FIFO threshold"]
    #[inline(always)]
    #[must_use]
    pub fn fth(&mut self) -> FthW<Acr2Spec> {
        FthW::new(self, 0)
    }
    #[doc = "Bit 3 - FIFO flush"]
    #[inline(always)]
    #[must_use]
    pub fn fflus(&mut self) -> FflusW<Acr2Spec> {
        FflusW::new(self, 3)
    }
    #[doc = "Bit 4 - Tristate management on data line"]
    #[inline(always)]
    #[must_use]
    pub fn tris(&mut self) -> TrisW<Acr2Spec> {
        TrisW::new(self, 4)
    }
    #[doc = "Bit 5 - Mute"]
    #[inline(always)]
    #[must_use]
    pub fn mute(&mut self) -> MuteW<Acr2Spec> {
        MuteW::new(self, 5)
    }
    #[doc = "Bit 6 - Mute value"]
    #[inline(always)]
    #[must_use]
    pub fn muteval(&mut self) -> MutevalW<Acr2Spec> {
        MutevalW::new(self, 6)
    }
    #[doc = "Bits 7:12 - Mute counter"]
    #[inline(always)]
    #[must_use]
    pub fn mutecn(&mut self) -> MutecnW<Acr2Spec> {
        MutecnW::new(self, 7)
    }
    #[doc = "Bit 13 - Complement bit"]
    #[inline(always)]
    #[must_use]
    pub fn cpl(&mut self) -> CplW<Acr2Spec> {
        CplW::new(self, 13)
    }
    #[doc = "Bits 14:15 - Companding mode"]
    #[inline(always)]
    #[must_use]
    pub fn comp(&mut self) -> CompW<Acr2Spec> {
        CompW::new(self, 14)
    }
}
#[doc = "AConfiguration register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`acr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`acr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Acr2Spec;
impl crate::RegisterSpec for Acr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`acr2::R`](R) reader structure"]
impl crate::Readable for Acr2Spec {}
#[doc = "`write(|w| ..)` method takes [`acr2::W`](W) writer structure"]
impl crate::Writable for Acr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ACR2 to value 0"]
impl crate::Resettable for Acr2Spec {
    const RESET_VALUE: u32 = 0;
}
