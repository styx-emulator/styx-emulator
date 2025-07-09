// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DOEPINT0` reader"]
pub type R = crate::R<OtgFsDoepint0Spec>;
#[doc = "Register `OTG_FS_DOEPINT0` writer"]
pub type W = crate::W<OtgFsDoepint0Spec>;
#[doc = "Field `XFRC` reader - XFRC"]
pub type XfrcR = crate::BitReader;
#[doc = "Field `XFRC` writer - XFRC"]
pub type XfrcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPDISD` reader - EPDISD"]
pub type EpdisdR = crate::BitReader;
#[doc = "Field `EPDISD` writer - EPDISD"]
pub type EpdisdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STUP` reader - STUP"]
pub type StupR = crate::BitReader;
#[doc = "Field `STUP` writer - STUP"]
pub type StupW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OTEPDIS` reader - OTEPDIS"]
pub type OtepdisR = crate::BitReader;
#[doc = "Field `OTEPDIS` writer - OTEPDIS"]
pub type OtepdisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `B2BSTUP` reader - B2BSTUP"]
pub type B2bstupR = crate::BitReader;
#[doc = "Field `B2BSTUP` writer - B2BSTUP"]
pub type B2bstupW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - XFRC"]
    #[inline(always)]
    pub fn xfrc(&self) -> XfrcR {
        XfrcR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - EPDISD"]
    #[inline(always)]
    pub fn epdisd(&self) -> EpdisdR {
        EpdisdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - STUP"]
    #[inline(always)]
    pub fn stup(&self) -> StupR {
        StupR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - OTEPDIS"]
    #[inline(always)]
    pub fn otepdis(&self) -> OtepdisR {
        OtepdisR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 6 - B2BSTUP"]
    #[inline(always)]
    pub fn b2bstup(&self) -> B2bstupR {
        B2bstupR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - XFRC"]
    #[inline(always)]
    #[must_use]
    pub fn xfrc(&mut self) -> XfrcW<OtgFsDoepint0Spec> {
        XfrcW::new(self, 0)
    }
    #[doc = "Bit 1 - EPDISD"]
    #[inline(always)]
    #[must_use]
    pub fn epdisd(&mut self) -> EpdisdW<OtgFsDoepint0Spec> {
        EpdisdW::new(self, 1)
    }
    #[doc = "Bit 3 - STUP"]
    #[inline(always)]
    #[must_use]
    pub fn stup(&mut self) -> StupW<OtgFsDoepint0Spec> {
        StupW::new(self, 3)
    }
    #[doc = "Bit 4 - OTEPDIS"]
    #[inline(always)]
    #[must_use]
    pub fn otepdis(&mut self) -> OtepdisW<OtgFsDoepint0Spec> {
        OtepdisW::new(self, 4)
    }
    #[doc = "Bit 6 - B2BSTUP"]
    #[inline(always)]
    #[must_use]
    pub fn b2bstup(&mut self) -> B2bstupW<OtgFsDoepint0Spec> {
        B2bstupW::new(self, 6)
    }
}
#[doc = "device endpoint-0 interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doepint0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doepint0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDoepint0Spec;
impl crate::RegisterSpec for OtgFsDoepint0Spec {
    type Ux = u32;
    const OFFSET: u64 = 776u64;
}
#[doc = "`read()` method returns [`otg_fs_doepint0::R`](R) reader structure"]
impl crate::Readable for OtgFsDoepint0Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_doepint0::W`](W) writer structure"]
impl crate::Writable for OtgFsDoepint0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_DOEPINT0 to value 0x80"]
impl crate::Resettable for OtgFsDoepint0Spec {
    const RESET_VALUE: u32 = 0x80;
}
