// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHB2LPENR` reader"]
pub type R = crate::R<Ahb2lpenrSpec>;
#[doc = "Register `AHB2LPENR` writer"]
pub type W = crate::W<Ahb2lpenrSpec>;
#[doc = "Field `DCMILPEN` reader - Camera interface enable during Sleep mode"]
pub type DcmilpenR = crate::BitReader;
#[doc = "Field `DCMILPEN` writer - Camera interface enable during Sleep mode"]
pub type DcmilpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CRYPLPEN` reader - Cryptography modules clock enable during Sleep mode"]
pub type CryplpenR = crate::BitReader;
#[doc = "Field `CRYPLPEN` writer - Cryptography modules clock enable during Sleep mode"]
pub type CryplpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HASHLPEN` reader - Hash modules clock enable during Sleep mode"]
pub type HashlpenR = crate::BitReader;
#[doc = "Field `HASHLPEN` writer - Hash modules clock enable during Sleep mode"]
pub type HashlpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RNGLPEN` reader - Random number generator clock enable during Sleep mode"]
pub type RnglpenR = crate::BitReader;
#[doc = "Field `RNGLPEN` writer - Random number generator clock enable during Sleep mode"]
pub type RnglpenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTGFSLPEN` reader - USB OTG FS clock enable during Sleep mode"]
pub type OtgfslpenR = crate::BitReader;
#[doc = "Field `OTGFSLPEN` writer - USB OTG FS clock enable during Sleep mode"]
pub type OtgfslpenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Camera interface enable during Sleep mode"]
    #[inline(always)]
    pub fn dcmilpen(&self) -> DcmilpenR {
        DcmilpenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 4 - Cryptography modules clock enable during Sleep mode"]
    #[inline(always)]
    pub fn cryplpen(&self) -> CryplpenR {
        CryplpenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Hash modules clock enable during Sleep mode"]
    #[inline(always)]
    pub fn hashlpen(&self) -> HashlpenR {
        HashlpenR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Random number generator clock enable during Sleep mode"]
    #[inline(always)]
    pub fn rnglpen(&self) -> RnglpenR {
        RnglpenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - USB OTG FS clock enable during Sleep mode"]
    #[inline(always)]
    pub fn otgfslpen(&self) -> OtgfslpenR {
        OtgfslpenR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Camera interface enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn dcmilpen(&mut self) -> DcmilpenW<Ahb2lpenrSpec> {
        DcmilpenW::new(self, 0)
    }
    #[doc = "Bit 4 - Cryptography modules clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn cryplpen(&mut self) -> CryplpenW<Ahb2lpenrSpec> {
        CryplpenW::new(self, 4)
    }
    #[doc = "Bit 5 - Hash modules clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn hashlpen(&mut self) -> HashlpenW<Ahb2lpenrSpec> {
        HashlpenW::new(self, 5)
    }
    #[doc = "Bit 6 - Random number generator clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn rnglpen(&mut self) -> RnglpenW<Ahb2lpenrSpec> {
        RnglpenW::new(self, 6)
    }
    #[doc = "Bit 7 - USB OTG FS clock enable during Sleep mode"]
    #[inline(always)]
    #[must_use]
    pub fn otgfslpen(&mut self) -> OtgfslpenW<Ahb2lpenrSpec> {
        OtgfslpenW::new(self, 7)
    }
}
#[doc = "AHB2 peripheral clock enable in low power mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahb2lpenr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahb2lpenr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ahb2lpenrSpec;
impl crate::RegisterSpec for Ahb2lpenrSpec {
    type Ux = u32;
    const OFFSET: u64 = 84u64;
}
#[doc = "`read()` method returns [`ahb2lpenr::R`](R) reader structure"]
impl crate::Readable for Ahb2lpenrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahb2lpenr::W`](W) writer structure"]
impl crate::Writable for Ahb2lpenrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHB2LPENR to value 0xf1"]
impl crate::Resettable for Ahb2lpenrSpec {
    const RESET_VALUE: u32 = 0xf1;
}
