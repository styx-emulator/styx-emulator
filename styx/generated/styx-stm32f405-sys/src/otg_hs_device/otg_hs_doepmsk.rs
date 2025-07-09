// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DOEPMSK` reader"]
pub type R = crate::R<OtgHsDoepmskSpec>;
#[doc = "Register `OTG_HS_DOEPMSK` writer"]
pub type W = crate::W<OtgHsDoepmskSpec>;
#[doc = "Field `XFRCM` reader - Transfer completed interrupt mask"]
pub type XfrcmR = crate::BitReader;
#[doc = "Field `XFRCM` writer - Transfer completed interrupt mask"]
pub type XfrcmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPDM` reader - Endpoint disabled interrupt mask"]
pub type EpdmR = crate::BitReader;
#[doc = "Field `EPDM` writer - Endpoint disabled interrupt mask"]
pub type EpdmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STUPM` reader - SETUP phase done mask"]
pub type StupmR = crate::BitReader;
#[doc = "Field `STUPM` writer - SETUP phase done mask"]
pub type StupmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTEPDM` reader - OUT token received when endpoint disabled mask"]
pub type OtepdmR = crate::BitReader;
#[doc = "Field `OTEPDM` writer - OUT token received when endpoint disabled mask"]
pub type OtepdmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `B2BSTUP` reader - Back-to-back SETUP packets received mask"]
pub type B2bstupR = crate::BitReader;
#[doc = "Field `B2BSTUP` writer - Back-to-back SETUP packets received mask"]
pub type B2bstupW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OPEM` reader - OUT packet error mask"]
pub type OpemR = crate::BitReader;
#[doc = "Field `OPEM` writer - OUT packet error mask"]
pub type OpemW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BOIM` reader - BNA interrupt mask"]
pub type BoimR = crate::BitReader;
#[doc = "Field `BOIM` writer - BNA interrupt mask"]
pub type BoimW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Transfer completed interrupt mask"]
    #[inline(always)]
    pub fn xfrcm(&self) -> XfrcmR {
        XfrcmR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Endpoint disabled interrupt mask"]
    #[inline(always)]
    pub fn epdm(&self) -> EpdmR {
        EpdmR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - SETUP phase done mask"]
    #[inline(always)]
    pub fn stupm(&self) -> StupmR {
        StupmR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - OUT token received when endpoint disabled mask"]
    #[inline(always)]
    pub fn otepdm(&self) -> OtepdmR {
        OtepdmR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - Back-to-back SETUP packets received mask"]
    #[inline(always)]
    pub fn b2bstup(&self) -> B2bstupR {
        B2bstupR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - OUT packet error mask"]
    #[inline(always)]
    pub fn opem(&self) -> OpemR {
        OpemR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - BNA interrupt mask"]
    #[inline(always)]
    pub fn boim(&self) -> BoimR {
        BoimR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Transfer completed interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn xfrcm(&mut self) -> XfrcmW<OtgHsDoepmskSpec> {
        XfrcmW::new(self, 0)
    }
    #[doc = "Bit 1 - Endpoint disabled interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn epdm(&mut self) -> EpdmW<OtgHsDoepmskSpec> {
        EpdmW::new(self, 1)
    }
    #[doc = "Bit 3 - SETUP phase done mask"]
    #[inline(always)]
    #[must_use]
    pub fn stupm(&mut self) -> StupmW<OtgHsDoepmskSpec> {
        StupmW::new(self, 3)
    }
    #[doc = "Bit 4 - OUT token received when endpoint disabled mask"]
    #[inline(always)]
    #[must_use]
    pub fn otepdm(&mut self) -> OtepdmW<OtgHsDoepmskSpec> {
        OtepdmW::new(self, 4)
    }
    #[doc = "Bit 6 - Back-to-back SETUP packets received mask"]
    #[inline(always)]
    #[must_use]
    pub fn b2bstup(&mut self) -> B2bstupW<OtgHsDoepmskSpec> {
        B2bstupW::new(self, 6)
    }
    #[doc = "Bit 8 - OUT packet error mask"]
    #[inline(always)]
    #[must_use]
    pub fn opem(&mut self) -> OpemW<OtgHsDoepmskSpec> {
        OpemW::new(self, 8)
    }
    #[doc = "Bit 9 - BNA interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn boim(&mut self) -> BoimW<OtgHsDoepmskSpec> {
        BoimW::new(self, 9)
    }
}
#[doc = "OTG_HS device OUT endpoint common interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_doepmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_doepmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDoepmskSpec;
impl crate::RegisterSpec for OtgHsDoepmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`otg_hs_doepmsk::R`](R) reader structure"]
impl crate::Readable for OtgHsDoepmskSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_doepmsk::W`](W) writer structure"]
impl crate::Writable for OtgHsDoepmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DOEPMSK to value 0"]
impl crate::Resettable for OtgHsDoepmskSpec {
    const RESET_VALUE: u32 = 0;
}
