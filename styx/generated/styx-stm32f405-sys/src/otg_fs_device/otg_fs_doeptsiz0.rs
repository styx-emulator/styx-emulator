// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DOEPTSIZ0` reader"]
pub type R = crate::R<OtgFsDoeptsiz0Spec>;
#[doc = "Register `OTG_FS_DOEPTSIZ0` writer"]
pub type W = crate::W<OtgFsDoeptsiz0Spec>;
#[doc = "Field `XFRSIZ` reader - Transfer size"]
pub type XfrsizR = crate::FieldReader;
#[doc = "Field `XFRSIZ` writer - Transfer size"]
pub type XfrsizW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `PKTCNT` reader - Packet count"]
pub type PktcntR = crate::BitReader;
#[doc = "Field `PKTCNT` writer - Packet count"]
pub type PktcntW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STUPCNT` reader - SETUP packet count"]
pub type StupcntR = crate::FieldReader;
#[doc = "Field `STUPCNT` writer - SETUP packet count"]
pub type StupcntW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:6 - Transfer size"]
    #[inline(always)]
    pub fn xfrsiz(&self) -> XfrsizR {
        XfrsizR::new((self.bits & 0x7f) as u8)
    }
    #[doc = "Bit 19 - Packet count"]
    #[inline(always)]
    pub fn pktcnt(&self) -> PktcntR {
        PktcntR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bits 29:30 - SETUP packet count"]
    #[inline(always)]
    pub fn stupcnt(&self) -> StupcntR {
        StupcntR::new(((self.bits >> 29) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:6 - Transfer size"]
    #[inline(always)]
    #[must_use]
    pub fn xfrsiz(&mut self) -> XfrsizW<OtgFsDoeptsiz0Spec> {
        XfrsizW::new(self, 0)
    }
    #[doc = "Bit 19 - Packet count"]
    #[inline(always)]
    #[must_use]
    pub fn pktcnt(&mut self) -> PktcntW<OtgFsDoeptsiz0Spec> {
        PktcntW::new(self, 19)
    }
    #[doc = "Bits 29:30 - SETUP packet count"]
    #[inline(always)]
    #[must_use]
    pub fn stupcnt(&mut self) -> StupcntW<OtgFsDoeptsiz0Spec> {
        StupcntW::new(self, 29)
    }
}
#[doc = "device OUT endpoint-0 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doeptsiz0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doeptsiz0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDoeptsiz0Spec;
impl crate::RegisterSpec for OtgFsDoeptsiz0Spec {
    type Ux = u32;
    const OFFSET: u64 = 784u64;
}
#[doc = "`read()` method returns [`otg_fs_doeptsiz0::R`](R) reader structure"]
impl crate::Readable for OtgFsDoeptsiz0Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_doeptsiz0::W`](W) writer structure"]
impl crate::Writable for OtgFsDoeptsiz0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_DOEPTSIZ0 to value 0"]
impl crate::Resettable for OtgFsDoeptsiz0Spec {
    const RESET_VALUE: u32 = 0;
}
