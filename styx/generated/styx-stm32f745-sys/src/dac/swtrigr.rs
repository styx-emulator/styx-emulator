// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SWTRIGR` reader"]
pub type R = crate::R<SwtrigrSpec>;
#[doc = "Register `SWTRIGR` writer"]
pub type W = crate::W<SwtrigrSpec>;
#[doc = "Field `SWTRIG1` reader - DAC channel1 software trigger"]
pub type Swtrig1R = crate::BitReader;
#[doc = "Field `SWTRIG1` writer - DAC channel1 software trigger"]
pub type Swtrig1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SWTRIG2` reader - DAC channel2 software trigger"]
pub type Swtrig2R = crate::BitReader;
#[doc = "Field `SWTRIG2` writer - DAC channel2 software trigger"]
pub type Swtrig2W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - DAC channel1 software trigger"]
    #[inline(always)]
    pub fn swtrig1(&self) -> Swtrig1R {
        Swtrig1R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - DAC channel2 software trigger"]
    #[inline(always)]
    pub fn swtrig2(&self) -> Swtrig2R {
        Swtrig2R::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - DAC channel1 software trigger"]
    #[inline(always)]
    #[must_use]
    pub fn swtrig1(&mut self) -> Swtrig1W<SwtrigrSpec> {
        Swtrig1W::new(self, 0)
    }
    #[doc = "Bit 1 - DAC channel2 software trigger"]
    #[inline(always)]
    #[must_use]
    pub fn swtrig2(&mut self) -> Swtrig2W<SwtrigrSpec> {
        Swtrig2W::new(self, 1)
    }
}
#[doc = "software trigger register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`swtrigr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SwtrigrSpec;
impl crate::RegisterSpec for SwtrigrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`write(|w| ..)` method takes [`swtrigr::W`](W) writer structure"]
impl crate::Writable for SwtrigrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SWTRIGR to value 0"]
impl crate::Resettable for SwtrigrSpec {
    const RESET_VALUE: u32 = 0;
}
