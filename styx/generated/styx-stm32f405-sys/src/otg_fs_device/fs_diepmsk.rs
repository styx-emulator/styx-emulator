// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_DIEPMSK` reader"]
pub type R = crate::R<FsDiepmskSpec>;
#[doc = "Register `FS_DIEPMSK` writer"]
pub type W = crate::W<FsDiepmskSpec>;
#[doc = "Field `XFRCM` reader - Transfer completed interrupt mask"]
pub type XfrcmR = crate::BitReader;
#[doc = "Field `XFRCM` writer - Transfer completed interrupt mask"]
pub type XfrcmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EPDM` reader - Endpoint disabled interrupt mask"]
pub type EpdmR = crate::BitReader;
#[doc = "Field `EPDM` writer - Endpoint disabled interrupt mask"]
pub type EpdmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TOM` reader - Timeout condition mask (Non-isochronous endpoints)"]
pub type TomR = crate::BitReader;
#[doc = "Field `TOM` writer - Timeout condition mask (Non-isochronous endpoints)"]
pub type TomW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ITTXFEMSK` reader - IN token received when TxFIFO empty mask"]
pub type IttxfemskR = crate::BitReader;
#[doc = "Field `ITTXFEMSK` writer - IN token received when TxFIFO empty mask"]
pub type IttxfemskW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `INEPNMM` reader - IN token received with EP mismatch mask"]
pub type InepnmmR = crate::BitReader;
#[doc = "Field `INEPNMM` writer - IN token received with EP mismatch mask"]
pub type InepnmmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `INEPNEM` reader - IN endpoint NAK effective mask"]
pub type InepnemR = crate::BitReader;
#[doc = "Field `INEPNEM` writer - IN endpoint NAK effective mask"]
pub type InepnemW<'a, REG> = crate::BitWriter<'a, REG>;
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
    #[doc = "Bit 3 - Timeout condition mask (Non-isochronous endpoints)"]
    #[inline(always)]
    pub fn tom(&self) -> TomR {
        TomR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - IN token received when TxFIFO empty mask"]
    #[inline(always)]
    pub fn ittxfemsk(&self) -> IttxfemskR {
        IttxfemskR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - IN token received with EP mismatch mask"]
    #[inline(always)]
    pub fn inepnmm(&self) -> InepnmmR {
        InepnmmR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - IN endpoint NAK effective mask"]
    #[inline(always)]
    pub fn inepnem(&self) -> InepnemR {
        InepnemR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Transfer completed interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn xfrcm(&mut self) -> XfrcmW<FsDiepmskSpec> {
        XfrcmW::new(self, 0)
    }
    #[doc = "Bit 1 - Endpoint disabled interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn epdm(&mut self) -> EpdmW<FsDiepmskSpec> {
        EpdmW::new(self, 1)
    }
    #[doc = "Bit 3 - Timeout condition mask (Non-isochronous endpoints)"]
    #[inline(always)]
    #[must_use]
    pub fn tom(&mut self) -> TomW<FsDiepmskSpec> {
        TomW::new(self, 3)
    }
    #[doc = "Bit 4 - IN token received when TxFIFO empty mask"]
    #[inline(always)]
    #[must_use]
    pub fn ittxfemsk(&mut self) -> IttxfemskW<FsDiepmskSpec> {
        IttxfemskW::new(self, 4)
    }
    #[doc = "Bit 5 - IN token received with EP mismatch mask"]
    #[inline(always)]
    #[must_use]
    pub fn inepnmm(&mut self) -> InepnmmW<FsDiepmskSpec> {
        InepnmmW::new(self, 5)
    }
    #[doc = "Bit 6 - IN endpoint NAK effective mask"]
    #[inline(always)]
    #[must_use]
    pub fn inepnem(&mut self) -> InepnemW<FsDiepmskSpec> {
        InepnemW::new(self, 6)
    }
}
#[doc = "OTG_FS device IN endpoint common interrupt mask register (OTG_FS_DIEPMSK)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_diepmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_diepmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsDiepmskSpec;
impl crate::RegisterSpec for FsDiepmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`fs_diepmsk::R`](R) reader structure"]
impl crate::Readable for FsDiepmskSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_diepmsk::W`](W) writer structure"]
impl crate::Writable for FsDiepmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_DIEPMSK to value 0"]
impl crate::Resettable for FsDiepmskSpec {
    const RESET_VALUE: u32 = 0;
}
