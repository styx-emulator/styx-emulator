// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR` reader"]
pub type R = crate::R<CrSpec>;
#[doc = "Register `CR` writer"]
pub type W = crate::W<CrSpec>;
#[doc = "Field `ENABLE` reader - LPTIM Enable"]
pub type EnableR = crate::BitReader;
#[doc = "Field `ENABLE` writer - LPTIM Enable"]
pub type EnableW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SNGSTRT` reader - LPTIM start in single mode"]
pub type SngstrtR = crate::BitReader;
#[doc = "Field `SNGSTRT` writer - LPTIM start in single mode"]
pub type SngstrtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CNTSTRT` reader - Timer start in continuous mode"]
pub type CntstrtR = crate::BitReader;
#[doc = "Field `CNTSTRT` writer - Timer start in continuous mode"]
pub type CntstrtW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - LPTIM Enable"]
    #[inline(always)]
    pub fn enable(&self) -> EnableR {
        EnableR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - LPTIM start in single mode"]
    #[inline(always)]
    pub fn sngstrt(&self) -> SngstrtR {
        SngstrtR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Timer start in continuous mode"]
    #[inline(always)]
    pub fn cntstrt(&self) -> CntstrtR {
        CntstrtR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - LPTIM Enable"]
    #[inline(always)]
    #[must_use]
    pub fn enable(&mut self) -> EnableW<CrSpec> {
        EnableW::new(self, 0)
    }
    #[doc = "Bit 1 - LPTIM start in single mode"]
    #[inline(always)]
    #[must_use]
    pub fn sngstrt(&mut self) -> SngstrtW<CrSpec> {
        SngstrtW::new(self, 1)
    }
    #[doc = "Bit 2 - Timer start in continuous mode"]
    #[inline(always)]
    #[must_use]
    pub fn cntstrt(&mut self) -> CntstrtW<CrSpec> {
        CntstrtW::new(self, 2)
    }
}
#[doc = "Control Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CrSpec;
impl crate::RegisterSpec for CrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`cr::R`](R) reader structure"]
impl crate::Readable for CrSpec {}
#[doc = "`write(|w| ..)` method takes [`cr::W`](W) writer structure"]
impl crate::Writable for CrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR to value 0"]
impl crate::Resettable for CrSpec {
    const RESET_VALUE: u32 = 0;
}
