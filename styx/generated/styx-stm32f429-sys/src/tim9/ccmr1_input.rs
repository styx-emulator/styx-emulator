// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CCMR1_Input` reader"]
pub type R = crate::R<Ccmr1InputSpec>;
#[doc = "Register `CCMR1_Input` writer"]
pub type W = crate::W<Ccmr1InputSpec>;
#[doc = "Field `CC1S` reader - Capture/Compare 1 selection"]
pub type Cc1sR = crate::FieldReader;
#[doc = "Field `CC1S` writer - Capture/Compare 1 selection"]
pub type Cc1sW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ICPCS` reader - Input capture 1 prescaler"]
pub type IcpcsR = crate::FieldReader;
#[doc = "Field `ICPCS` writer - Input capture 1 prescaler"]
pub type IcpcsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `IC1F` reader - Input capture 1 filter"]
pub type Ic1fR = crate::FieldReader;
#[doc = "Field `IC1F` writer - Input capture 1 filter"]
pub type Ic1fW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CC2S` reader - Capture/Compare 2 selection"]
pub type Cc2sR = crate::FieldReader;
#[doc = "Field `CC2S` writer - Capture/Compare 2 selection"]
pub type Cc2sW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `IC2PCS` reader - Input capture 2 prescaler"]
pub type Ic2pcsR = crate::FieldReader;
#[doc = "Field `IC2PCS` writer - Input capture 2 prescaler"]
pub type Ic2pcsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `IC2F` reader - Input capture 2 filter"]
pub type Ic2fR = crate::FieldReader;
#[doc = "Field `IC2F` writer - Input capture 2 filter"]
pub type Ic2fW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:1 - Capture/Compare 1 selection"]
    #[inline(always)]
    pub fn cc1s(&self) -> Cc1sR {
        Cc1sR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - Input capture 1 prescaler"]
    #[inline(always)]
    pub fn icpcs(&self) -> IcpcsR {
        IcpcsR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:6 - Input capture 1 filter"]
    #[inline(always)]
    pub fn ic1f(&self) -> Ic1fR {
        Ic1fR::new(((self.bits >> 4) & 7) as u8)
    }
    #[doc = "Bits 8:9 - Capture/Compare 2 selection"]
    #[inline(always)]
    pub fn cc2s(&self) -> Cc2sR {
        Cc2sR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bits 10:11 - Input capture 2 prescaler"]
    #[inline(always)]
    pub fn ic2pcs(&self) -> Ic2pcsR {
        Ic2pcsR::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bits 12:14 - Input capture 2 filter"]
    #[inline(always)]
    pub fn ic2f(&self) -> Ic2fR {
        Ic2fR::new(((self.bits >> 12) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Capture/Compare 1 selection"]
    #[inline(always)]
    #[must_use]
    pub fn cc1s(&mut self) -> Cc1sW<Ccmr1InputSpec> {
        Cc1sW::new(self, 0)
    }
    #[doc = "Bits 2:3 - Input capture 1 prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn icpcs(&mut self) -> IcpcsW<Ccmr1InputSpec> {
        IcpcsW::new(self, 2)
    }
    #[doc = "Bits 4:6 - Input capture 1 filter"]
    #[inline(always)]
    #[must_use]
    pub fn ic1f(&mut self) -> Ic1fW<Ccmr1InputSpec> {
        Ic1fW::new(self, 4)
    }
    #[doc = "Bits 8:9 - Capture/Compare 2 selection"]
    #[inline(always)]
    #[must_use]
    pub fn cc2s(&mut self) -> Cc2sW<Ccmr1InputSpec> {
        Cc2sW::new(self, 8)
    }
    #[doc = "Bits 10:11 - Input capture 2 prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn ic2pcs(&mut self) -> Ic2pcsW<Ccmr1InputSpec> {
        Ic2pcsW::new(self, 10)
    }
    #[doc = "Bits 12:14 - Input capture 2 filter"]
    #[inline(always)]
    #[must_use]
    pub fn ic2f(&mut self) -> Ic2fW<Ccmr1InputSpec> {
        Ic2fW::new(self, 12)
    }
}
#[doc = "capture/compare mode register 1 (input mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccmr1_input::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ccmr1_input::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ccmr1InputSpec;
impl crate::RegisterSpec for Ccmr1InputSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`ccmr1_input::R`](R) reader structure"]
impl crate::Readable for Ccmr1InputSpec {}
#[doc = "`write(|w| ..)` method takes [`ccmr1_input::W`](W) writer structure"]
impl crate::Writable for Ccmr1InputSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CCMR1_Input to value 0"]
impl crate::Resettable for Ccmr1InputSpec {
    const RESET_VALUE: u32 = 0;
}
