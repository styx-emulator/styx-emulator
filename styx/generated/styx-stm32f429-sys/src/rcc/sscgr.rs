// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SSCGR` reader"]
pub type R = crate::R<SscgrSpec>;
#[doc = "Register `SSCGR` writer"]
pub type W = crate::W<SscgrSpec>;
#[doc = "Field `MODPER` reader - Modulation period"]
pub type ModperR = crate::FieldReader<u16>;
#[doc = "Field `MODPER` writer - Modulation period"]
pub type ModperW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
#[doc = "Field `INCSTEP` reader - Incrementation step"]
pub type IncstepR = crate::FieldReader<u16>;
#[doc = "Field `INCSTEP` writer - Incrementation step"]
pub type IncstepW<'a, REG> = crate::FieldWriter<'a, REG, 15, u16>;
#[doc = "Field `SPREADSEL` reader - Spread Select"]
pub type SpreadselR = crate::BitReader;
#[doc = "Field `SPREADSEL` writer - Spread Select"]
pub type SpreadselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SSCGEN` reader - Spread spectrum modulation enable"]
pub type SscgenR = crate::BitReader;
#[doc = "Field `SSCGEN` writer - Spread spectrum modulation enable"]
pub type SscgenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:12 - Modulation period"]
    #[inline(always)]
    pub fn modper(&self) -> ModperR {
        ModperR::new((self.bits & 0x1fff) as u16)
    }
    #[doc = "Bits 13:27 - Incrementation step"]
    #[inline(always)]
    pub fn incstep(&self) -> IncstepR {
        IncstepR::new(((self.bits >> 13) & 0x7fff) as u16)
    }
    #[doc = "Bit 30 - Spread Select"]
    #[inline(always)]
    pub fn spreadsel(&self) -> SpreadselR {
        SpreadselR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Spread spectrum modulation enable"]
    #[inline(always)]
    pub fn sscgen(&self) -> SscgenR {
        SscgenR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:12 - Modulation period"]
    #[inline(always)]
    #[must_use]
    pub fn modper(&mut self) -> ModperW<SscgrSpec> {
        ModperW::new(self, 0)
    }
    #[doc = "Bits 13:27 - Incrementation step"]
    #[inline(always)]
    #[must_use]
    pub fn incstep(&mut self) -> IncstepW<SscgrSpec> {
        IncstepW::new(self, 13)
    }
    #[doc = "Bit 30 - Spread Select"]
    #[inline(always)]
    #[must_use]
    pub fn spreadsel(&mut self) -> SpreadselW<SscgrSpec> {
        SpreadselW::new(self, 30)
    }
    #[doc = "Bit 31 - Spread spectrum modulation enable"]
    #[inline(always)]
    #[must_use]
    pub fn sscgen(&mut self) -> SscgenW<SscgrSpec> {
        SscgenW::new(self, 31)
    }
}
#[doc = "spread spectrum clock generation register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sscgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sscgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SscgrSpec;
impl crate::RegisterSpec for SscgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`sscgr::R`](R) reader structure"]
impl crate::Readable for SscgrSpec {}
#[doc = "`write(|w| ..)` method takes [`sscgr::W`](W) writer structure"]
impl crate::Writable for SscgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SSCGR to value 0"]
impl crate::Resettable for SscgrSpec {
    const RESET_VALUE: u32 = 0;
}
