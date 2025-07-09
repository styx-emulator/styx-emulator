// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CCMR1_Output` reader"]
pub type R = crate::R<Ccmr1OutputSpec>;
#[doc = "Register `CCMR1_Output` writer"]
pub type W = crate::W<Ccmr1OutputSpec>;
#[doc = "Field `CC1S` reader - Capture/Compare 1 selection"]
pub type Cc1sR = crate::FieldReader;
#[doc = "Field `CC1S` writer - Capture/Compare 1 selection"]
pub type Cc1sW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OC1FE` reader - Output Compare 1 fast enable"]
pub type Oc1feR = crate::BitReader;
#[doc = "Field `OC1FE` writer - Output Compare 1 fast enable"]
pub type Oc1feW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OC1PE` reader - Output Compare 1 preload enable"]
pub type Oc1peR = crate::BitReader;
#[doc = "Field `OC1PE` writer - Output Compare 1 preload enable"]
pub type Oc1peW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OC1M` reader - Output Compare 1 mode"]
pub type Oc1mR = crate::FieldReader;
#[doc = "Field `OC1M` writer - Output Compare 1 mode"]
pub type Oc1mW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CC2S` reader - Capture/Compare 2 selection"]
pub type Cc2sR = crate::FieldReader;
#[doc = "Field `CC2S` writer - Capture/Compare 2 selection"]
pub type Cc2sW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `OC2FE` reader - Output Compare 2 fast enable"]
pub type Oc2feR = crate::BitReader;
#[doc = "Field `OC2FE` writer - Output Compare 2 fast enable"]
pub type Oc2feW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OC2PE` reader - Output Compare 2 preload enable"]
pub type Oc2peR = crate::BitReader;
#[doc = "Field `OC2PE` writer - Output Compare 2 preload enable"]
pub type Oc2peW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OC2M` reader - Output Compare 2 mode"]
pub type Oc2mR = crate::FieldReader;
#[doc = "Field `OC2M` writer - Output Compare 2 mode"]
pub type Oc2mW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:1 - Capture/Compare 1 selection"]
    #[inline(always)]
    pub fn cc1s(&self) -> Cc1sR {
        Cc1sR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - Output Compare 1 fast enable"]
    #[inline(always)]
    pub fn oc1fe(&self) -> Oc1feR {
        Oc1feR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Output Compare 1 preload enable"]
    #[inline(always)]
    pub fn oc1pe(&self) -> Oc1peR {
        Oc1peR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:6 - Output Compare 1 mode"]
    #[inline(always)]
    pub fn oc1m(&self) -> Oc1mR {
        Oc1mR::new(((self.bits >> 4) & 7) as u8)
    }
    #[doc = "Bits 8:9 - Capture/Compare 2 selection"]
    #[inline(always)]
    pub fn cc2s(&self) -> Cc2sR {
        Cc2sR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bit 10 - Output Compare 2 fast enable"]
    #[inline(always)]
    pub fn oc2fe(&self) -> Oc2feR {
        Oc2feR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Output Compare 2 preload enable"]
    #[inline(always)]
    pub fn oc2pe(&self) -> Oc2peR {
        Oc2peR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bits 12:14 - Output Compare 2 mode"]
    #[inline(always)]
    pub fn oc2m(&self) -> Oc2mR {
        Oc2mR::new(((self.bits >> 12) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Capture/Compare 1 selection"]
    #[inline(always)]
    #[must_use]
    pub fn cc1s(&mut self) -> Cc1sW<Ccmr1OutputSpec> {
        Cc1sW::new(self, 0)
    }
    #[doc = "Bit 2 - Output Compare 1 fast enable"]
    #[inline(always)]
    #[must_use]
    pub fn oc1fe(&mut self) -> Oc1feW<Ccmr1OutputSpec> {
        Oc1feW::new(self, 2)
    }
    #[doc = "Bit 3 - Output Compare 1 preload enable"]
    #[inline(always)]
    #[must_use]
    pub fn oc1pe(&mut self) -> Oc1peW<Ccmr1OutputSpec> {
        Oc1peW::new(self, 3)
    }
    #[doc = "Bits 4:6 - Output Compare 1 mode"]
    #[inline(always)]
    #[must_use]
    pub fn oc1m(&mut self) -> Oc1mW<Ccmr1OutputSpec> {
        Oc1mW::new(self, 4)
    }
    #[doc = "Bits 8:9 - Capture/Compare 2 selection"]
    #[inline(always)]
    #[must_use]
    pub fn cc2s(&mut self) -> Cc2sW<Ccmr1OutputSpec> {
        Cc2sW::new(self, 8)
    }
    #[doc = "Bit 10 - Output Compare 2 fast enable"]
    #[inline(always)]
    #[must_use]
    pub fn oc2fe(&mut self) -> Oc2feW<Ccmr1OutputSpec> {
        Oc2feW::new(self, 10)
    }
    #[doc = "Bit 11 - Output Compare 2 preload enable"]
    #[inline(always)]
    #[must_use]
    pub fn oc2pe(&mut self) -> Oc2peW<Ccmr1OutputSpec> {
        Oc2peW::new(self, 11)
    }
    #[doc = "Bits 12:14 - Output Compare 2 mode"]
    #[inline(always)]
    #[must_use]
    pub fn oc2m(&mut self) -> Oc2mW<Ccmr1OutputSpec> {
        Oc2mW::new(self, 12)
    }
}
#[doc = "capture/compare mode register 1 (output mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccmr1_output::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ccmr1_output::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ccmr1OutputSpec;
impl crate::RegisterSpec for Ccmr1OutputSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`ccmr1_output::R`](R) reader structure"]
impl crate::Readable for Ccmr1OutputSpec {}
#[doc = "`write(|w| ..)` method takes [`ccmr1_output::W`](W) writer structure"]
impl crate::Writable for Ccmr1OutputSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CCMR1_Output to value 0"]
impl crate::Resettable for Ccmr1OutputSpec {
    const RESET_VALUE: u32 = 0;
}
