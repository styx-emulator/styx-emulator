// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHB2RSTR` reader"]
pub type R = crate::R<Ahb2rstrSpec>;
#[doc = "Register `AHB2RSTR` writer"]
pub type W = crate::W<Ahb2rstrSpec>;
#[doc = "Field `DCMIRST` reader - Camera interface reset"]
pub type DcmirstR = crate::BitReader;
#[doc = "Field `DCMIRST` writer - Camera interface reset"]
pub type DcmirstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CRYPRST` reader - Cryptographic module reset"]
pub type CryprstR = crate::BitReader;
#[doc = "Field `CRYPRST` writer - Cryptographic module reset"]
pub type CryprstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSAHRST` reader - Hash module reset"]
pub type HsahrstR = crate::BitReader;
#[doc = "Field `HSAHRST` writer - Hash module reset"]
pub type HsahrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RNGRST` reader - Random number generator module reset"]
pub type RngrstR = crate::BitReader;
#[doc = "Field `RNGRST` writer - Random number generator module reset"]
pub type RngrstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTGFSRST` reader - USB OTG FS module reset"]
pub type OtgfsrstR = crate::BitReader;
#[doc = "Field `OTGFSRST` writer - USB OTG FS module reset"]
pub type OtgfsrstW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Camera interface reset"]
    #[inline(always)]
    pub fn dcmirst(&self) -> DcmirstR {
        DcmirstR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 4 - Cryptographic module reset"]
    #[inline(always)]
    pub fn cryprst(&self) -> CryprstR {
        CryprstR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Hash module reset"]
    #[inline(always)]
    pub fn hsahrst(&self) -> HsahrstR {
        HsahrstR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Random number generator module reset"]
    #[inline(always)]
    pub fn rngrst(&self) -> RngrstR {
        RngrstR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - USB OTG FS module reset"]
    #[inline(always)]
    pub fn otgfsrst(&self) -> OtgfsrstR {
        OtgfsrstR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Camera interface reset"]
    #[inline(always)]
    #[must_use]
    pub fn dcmirst(&mut self) -> DcmirstW<Ahb2rstrSpec> {
        DcmirstW::new(self, 0)
    }
    #[doc = "Bit 4 - Cryptographic module reset"]
    #[inline(always)]
    #[must_use]
    pub fn cryprst(&mut self) -> CryprstW<Ahb2rstrSpec> {
        CryprstW::new(self, 4)
    }
    #[doc = "Bit 5 - Hash module reset"]
    #[inline(always)]
    #[must_use]
    pub fn hsahrst(&mut self) -> HsahrstW<Ahb2rstrSpec> {
        HsahrstW::new(self, 5)
    }
    #[doc = "Bit 6 - Random number generator module reset"]
    #[inline(always)]
    #[must_use]
    pub fn rngrst(&mut self) -> RngrstW<Ahb2rstrSpec> {
        RngrstW::new(self, 6)
    }
    #[doc = "Bit 7 - USB OTG FS module reset"]
    #[inline(always)]
    #[must_use]
    pub fn otgfsrst(&mut self) -> OtgfsrstW<Ahb2rstrSpec> {
        OtgfsrstW::new(self, 7)
    }
}
#[doc = "AHB2 peripheral reset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahb2rstr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahb2rstr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ahb2rstrSpec;
impl crate::RegisterSpec for Ahb2rstrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`ahb2rstr::R`](R) reader structure"]
impl crate::Readable for Ahb2rstrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahb2rstr::W`](W) writer structure"]
impl crate::Writable for Ahb2rstrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHB2RSTR to value 0"]
impl crate::Resettable for Ahb2rstrSpec {
    const RESET_VALUE: u32 = 0;
}
