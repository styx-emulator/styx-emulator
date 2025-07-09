// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `intren` reader"]
pub type R = crate::R<IntrenSpec>;
#[doc = "Register `intren` writer"]
pub type W = crate::W<IntrenSpec>;
#[doc = "Field `mainpllachieved` reader - When set to 1, the Main PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Main PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
pub type MainpllachievedR = crate::BitReader;
#[doc = "Field `mainpllachieved` writer - When set to 1, the Main PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Main PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
pub type MainpllachievedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `perpllachieved` reader - When set to 1, the Peripheral PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Peripheral PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
pub type PerpllachievedR = crate::BitReader;
#[doc = "Field `perpllachieved` writer - When set to 1, the Peripheral PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Peripheral PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
pub type PerpllachievedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdrpllachieved` reader - When set to 1, the SDRAM PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the SDRAM PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
pub type SdrpllachievedR = crate::BitReader;
#[doc = "Field `sdrpllachieved` writer - When set to 1, the SDRAM PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the SDRAM PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
pub type SdrpllachievedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `mainplllost` reader - When set to 1, the Main PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Main PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
pub type MainplllostR = crate::BitReader;
#[doc = "Field `mainplllost` writer - When set to 1, the Main PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Main PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
pub type MainplllostW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `perplllost` reader - When set to 1, the Peripheral PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Peripheral PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
pub type PerplllostR = crate::BitReader;
#[doc = "Field `perplllost` writer - When set to 1, the Peripheral PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Peripheral PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
pub type PerplllostW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdrplllost` reader - When set to 1, the SDRAM PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the SDRAM PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
pub type SdrplllostR = crate::BitReader;
#[doc = "Field `sdrplllost` writer - When set to 1, the SDRAM PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the SDRAM PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
pub type SdrplllostW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When set to 1, the Main PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Main PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    pub fn mainpllachieved(&self) -> MainpllachievedR {
        MainpllachievedR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When set to 1, the Peripheral PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Peripheral PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    pub fn perpllachieved(&self) -> PerpllachievedR {
        PerpllachievedR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - When set to 1, the SDRAM PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the SDRAM PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    pub fn sdrpllachieved(&self) -> SdrpllachievedR {
        SdrpllachievedR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When set to 1, the Main PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Main PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    pub fn mainplllost(&self) -> MainplllostR {
        MainplllostR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - When set to 1, the Peripheral PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Peripheral PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    pub fn perplllost(&self) -> PerplllostR {
        PerplllostR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When set to 1, the SDRAM PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the SDRAM PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    pub fn sdrplllost(&self) -> SdrplllostR {
        SdrplllostR::new(((self.bits >> 5) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When set to 1, the Main PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Main PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    #[must_use]
    pub fn mainpllachieved(&mut self) -> MainpllachievedW<IntrenSpec> {
        MainpllachievedW::new(self, 0)
    }
    #[doc = "Bit 1 - When set to 1, the Peripheral PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Peripheral PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    #[must_use]
    pub fn perpllachieved(&mut self) -> PerpllachievedW<IntrenSpec> {
        PerpllachievedW::new(self, 1)
    }
    #[doc = "Bit 2 - When set to 1, the SDRAM PLL achieved lock bit is ORed into the Clock Manager interrupt output. When set to 0 the SDRAM PLL achieved lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    #[must_use]
    pub fn sdrpllachieved(&mut self) -> SdrpllachievedW<IntrenSpec> {
        SdrpllachievedW::new(self, 2)
    }
    #[doc = "Bit 3 - When set to 1, the Main PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Main PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    #[must_use]
    pub fn mainplllost(&mut self) -> MainplllostW<IntrenSpec> {
        MainplllostW::new(self, 3)
    }
    #[doc = "Bit 4 - When set to 1, the Peripheral PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the Peripheral PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    #[must_use]
    pub fn perplllost(&mut self) -> PerplllostW<IntrenSpec> {
        PerplllostW::new(self, 4)
    }
    #[doc = "Bit 5 - When set to 1, the SDRAM PLL lost lock bit is ORed into the Clock Manager interrupt output. When set to 0 the SDRAM PLL lost lock bit is not ORed into the Clock Manager interrupt output."]
    #[inline(always)]
    #[must_use]
    pub fn sdrplllost(&mut self) -> SdrplllostW<IntrenSpec> {
        SdrplllostW::new(self, 5)
    }
}
#[doc = "Contain fields that enable the interrupt. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`intren::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`intren::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IntrenSpec;
impl crate::RegisterSpec for IntrenSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`intren::R`](R) reader structure"]
impl crate::Readable for IntrenSpec {}
#[doc = "`write(|w| ..)` method takes [`intren::W`](W) writer structure"]
impl crate::Writable for IntrenSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets intren to value 0"]
impl crate::Resettable for IntrenSpec {
    const RESET_VALUE: u32 = 0;
}
