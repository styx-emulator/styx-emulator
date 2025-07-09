// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ACTRL` reader"]
pub type R = crate::R<ActrlSpec>;
#[doc = "Register `ACTRL` writer"]
pub type W = crate::W<ActrlSpec>;
#[doc = "Field `DISFOLD` reader - DISFOLD"]
pub type DisfoldR = crate::BitReader;
#[doc = "Field `DISFOLD` writer - DISFOLD"]
pub type DisfoldW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FPEXCODIS` reader - FPEXCODIS"]
pub type FpexcodisR = crate::BitReader;
#[doc = "Field `FPEXCODIS` writer - FPEXCODIS"]
pub type FpexcodisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISRAMODE` reader - DISRAMODE"]
pub type DisramodeR = crate::BitReader;
#[doc = "Field `DISRAMODE` writer - DISRAMODE"]
pub type DisramodeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DISITMATBFLUSH` reader - DISITMATBFLUSH"]
pub type DisitmatbflushR = crate::BitReader;
#[doc = "Field `DISITMATBFLUSH` writer - DISITMATBFLUSH"]
pub type DisitmatbflushW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 2 - DISFOLD"]
    #[inline(always)]
    pub fn disfold(&self) -> DisfoldR {
        DisfoldR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 10 - FPEXCODIS"]
    #[inline(always)]
    pub fn fpexcodis(&self) -> FpexcodisR {
        FpexcodisR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - DISRAMODE"]
    #[inline(always)]
    pub fn disramode(&self) -> DisramodeR {
        DisramodeR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - DISITMATBFLUSH"]
    #[inline(always)]
    pub fn disitmatbflush(&self) -> DisitmatbflushR {
        DisitmatbflushR::new(((self.bits >> 12) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 2 - DISFOLD"]
    #[inline(always)]
    #[must_use]
    pub fn disfold(&mut self) -> DisfoldW<ActrlSpec> {
        DisfoldW::new(self, 2)
    }
    #[doc = "Bit 10 - FPEXCODIS"]
    #[inline(always)]
    #[must_use]
    pub fn fpexcodis(&mut self) -> FpexcodisW<ActrlSpec> {
        FpexcodisW::new(self, 10)
    }
    #[doc = "Bit 11 - DISRAMODE"]
    #[inline(always)]
    #[must_use]
    pub fn disramode(&mut self) -> DisramodeW<ActrlSpec> {
        DisramodeW::new(self, 11)
    }
    #[doc = "Bit 12 - DISITMATBFLUSH"]
    #[inline(always)]
    #[must_use]
    pub fn disitmatbflush(&mut self) -> DisitmatbflushW<ActrlSpec> {
        DisitmatbflushW::new(self, 12)
    }
}
#[doc = "Auxiliary control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`actrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`actrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ActrlSpec;
impl crate::RegisterSpec for ActrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`actrl::R`](R) reader structure"]
impl crate::Readable for ActrlSpec {}
#[doc = "`write(|w| ..)` method takes [`actrl::W`](W) writer structure"]
impl crate::Writable for ActrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ACTRL to value 0"]
impl crate::Resettable for ActrlSpec {
    const RESET_VALUE: u32 = 0;
}
