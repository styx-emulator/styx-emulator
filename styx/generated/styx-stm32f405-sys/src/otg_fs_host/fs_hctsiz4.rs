// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_HCTSIZ4` reader"]
pub type R = crate::R<FsHctsiz4Spec>;
#[doc = "Register `FS_HCTSIZ4` writer"]
pub type W = crate::W<FsHctsiz4Spec>;
#[doc = "Field `XFRSIZ` reader - Transfer size"]
pub type XfrsizR = crate::FieldReader<u32>;
#[doc = "Field `XFRSIZ` writer - Transfer size"]
pub type XfrsizW<'a, REG> = crate::FieldWriter<'a, REG, 19, u32>;
#[doc = "Field `PKTCNT` reader - Packet count"]
pub type PktcntR = crate::FieldReader<u16>;
#[doc = "Field `PKTCNT` writer - Packet count"]
pub type PktcntW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Field `DPID` reader - Data PID"]
pub type DpidR = crate::FieldReader;
#[doc = "Field `DPID` writer - Data PID"]
pub type DpidW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
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
    #[doc = "Bits 29:30 - Data PID"]
    #[inline(always)]
    pub fn dpid(&self) -> DpidR {
        DpidR::new(((self.bits >> 29) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:18 - Transfer size"]
    #[inline(always)]
    #[must_use]
    pub fn xfrsiz(&mut self) -> XfrsizW<FsHctsiz4Spec> {
        XfrsizW::new(self, 0)
    }
    #[doc = "Bits 19:28 - Packet count"]
    #[inline(always)]
    #[must_use]
    pub fn pktcnt(&mut self) -> PktcntW<FsHctsiz4Spec> {
        PktcntW::new(self, 19)
    }
    #[doc = "Bits 29:30 - Data PID"]
    #[inline(always)]
    #[must_use]
    pub fn dpid(&mut self) -> DpidW<FsHctsiz4Spec> {
        DpidW::new(self, 29)
    }
}
#[doc = "OTG_FS host channel-x transfer size register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_hctsiz4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_hctsiz4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsHctsiz4Spec;
impl crate::RegisterSpec for FsHctsiz4Spec {
    type Ux = u32;
    const OFFSET: u64 = 400u64;
}
#[doc = "`read()` method returns [`fs_hctsiz4::R`](R) reader structure"]
impl crate::Readable for FsHctsiz4Spec {}
#[doc = "`write(|w| ..)` method takes [`fs_hctsiz4::W`](W) writer structure"]
impl crate::Writable for FsHctsiz4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_HCTSIZ4 to value 0"]
impl crate::Resettable for FsHctsiz4Spec {
    const RESET_VALUE: u32 = 0;
}
