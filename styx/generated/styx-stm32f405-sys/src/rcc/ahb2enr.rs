// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHB2ENR` reader"]
pub type R = crate::R<Ahb2enrSpec>;
#[doc = "Register `AHB2ENR` writer"]
pub type W = crate::W<Ahb2enrSpec>;
#[doc = "Field `DCMIEN` reader - Camera interface enable"]
pub type DcmienR = crate::BitReader;
#[doc = "Field `DCMIEN` writer - Camera interface enable"]
pub type DcmienW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RNGEN` reader - Random number generator clock enable"]
pub type RngenR = crate::BitReader;
#[doc = "Field `RNGEN` writer - Random number generator clock enable"]
pub type RngenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTGFSEN` reader - USB OTG FS clock enable"]
pub type OtgfsenR = crate::BitReader;
#[doc = "Field `OTGFSEN` writer - USB OTG FS clock enable"]
pub type OtgfsenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Camera interface enable"]
    #[inline(always)]
    pub fn dcmien(&self) -> DcmienR {
        DcmienR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 6 - Random number generator clock enable"]
    #[inline(always)]
    pub fn rngen(&self) -> RngenR {
        RngenR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - USB OTG FS clock enable"]
    #[inline(always)]
    pub fn otgfsen(&self) -> OtgfsenR {
        OtgfsenR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Camera interface enable"]
    #[inline(always)]
    #[must_use]
    pub fn dcmien(&mut self) -> DcmienW<Ahb2enrSpec> {
        DcmienW::new(self, 0)
    }
    #[doc = "Bit 6 - Random number generator clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn rngen(&mut self) -> RngenW<Ahb2enrSpec> {
        RngenW::new(self, 6)
    }
    #[doc = "Bit 7 - USB OTG FS clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn otgfsen(&mut self) -> OtgfsenW<Ahb2enrSpec> {
        OtgfsenW::new(self, 7)
    }
}
#[doc = "AHB2 peripheral clock enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahb2enr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahb2enr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ahb2enrSpec;
impl crate::RegisterSpec for Ahb2enrSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`ahb2enr::R`](R) reader structure"]
impl crate::Readable for Ahb2enrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahb2enr::W`](W) writer structure"]
impl crate::Writable for Ahb2enrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHB2ENR to value 0"]
impl crate::Resettable for Ahb2enrSpec {
    const RESET_VALUE: u32 = 0;
}
