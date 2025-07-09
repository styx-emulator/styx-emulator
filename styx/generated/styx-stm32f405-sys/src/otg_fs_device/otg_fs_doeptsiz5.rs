// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DOEPTSIZ5` reader"]
pub type R = crate::R<OtgFsDoeptsiz5Spec>;
#[doc = "Register `OTG_FS_DOEPTSIZ5` writer"]
pub type W = crate::W<OtgFsDoeptsiz5Spec>;
#[doc = "Field `XFRSIZ` reader - Transfer size"]
pub type XfrsizR = crate::FieldReader<u32>;
#[doc = "Field `XFRSIZ` writer - Transfer size"]
pub type XfrsizW<'a, REG> = crate::FieldWriter<'a, REG, 19, u32>;
#[doc = "Field `PKTCNT` reader - Packet count"]
pub type PktcntR = crate::FieldReader<u16>;
#[doc = "Field `PKTCNT` writer - Packet count"]
pub type PktcntW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Field `RXDPID_STUPCNT` reader - Received data PID/SETUP packet count"]
pub type RxdpidStupcntR = crate::FieldReader;
#[doc = "Field `RXDPID_STUPCNT` writer - Received data PID/SETUP packet count"]
pub type RxdpidStupcntW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:18 - Transfer size"]
    #[inline(always)]
    pub fn xfrsiz(&self) -> XfrsizR {
        XfrsizR::new(self.bits & 0x0007_ffff)
    }
    #[doc = "Bits 19:28 - Packet count"]
    #[inline(always)]
    pub fn pktcnt(&self) -> PktcntR {
        PktcntR::new(((self.bits >> 19) & 0x03ff) as u16)
    }
    #[doc = "Bits 29:30 - Received data PID/SETUP packet count"]
    #[inline(always)]
    pub fn rxdpid_stupcnt(&self) -> RxdpidStupcntR {
        RxdpidStupcntR::new(((self.bits >> 29) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:18 - Transfer size"]
    #[inline(always)]
    #[must_use]
    pub fn xfrsiz(&mut self) -> XfrsizW<OtgFsDoeptsiz5Spec> {
        XfrsizW::new(self, 0)
    }
    #[doc = "Bits 19:28 - Packet count"]
    #[inline(always)]
    #[must_use]
    pub fn pktcnt(&mut self) -> PktcntW<OtgFsDoeptsiz5Spec> {
        PktcntW::new(self, 19)
    }
    #[doc = "Bits 29:30 - Received data PID/SETUP packet count"]
    #[inline(always)]
    #[must_use]
    pub fn rxdpid_stupcnt(&mut self) -> RxdpidStupcntW<OtgFsDoeptsiz5Spec> {
        RxdpidStupcntW::new(self, 29)
    }
}
#[doc = "device OUT endpoint-5 transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_doeptsiz5::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_doeptsiz5::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDoeptsiz5Spec;
impl crate::RegisterSpec for OtgFsDoeptsiz5Spec {
    type Ux = u32;
    const OFFSET: u64 = 928u64;
}
#[doc = "`read()` method returns [`otg_fs_doeptsiz5::R`](R) reader structure"]
impl crate::Readable for OtgFsDoeptsiz5Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_doeptsiz5::W`](W) writer structure"]
impl crate::Writable for OtgFsDoeptsiz5Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_DOEPTSIZ5 to value 0"]
impl crate::Resettable for OtgFsDoeptsiz5Spec {
    const RESET_VALUE: u32 = 0;
}
