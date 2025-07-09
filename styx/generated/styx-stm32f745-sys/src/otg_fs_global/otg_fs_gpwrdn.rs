// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_GPWRDN` reader"]
pub type R = crate::R<OtgFsGpwrdnSpec>;
#[doc = "Register `OTG_FS_GPWRDN` writer"]
pub type W = crate::W<OtgFsGpwrdnSpec>;
#[doc = "Field `ADPMEN` reader - ADP module enable"]
pub type AdpmenR = crate::BitReader;
#[doc = "Field `ADPMEN` writer - ADP module enable"]
pub type AdpmenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADPIF` reader - ADP interrupt flag"]
pub type AdpifR = crate::BitReader;
#[doc = "Field `ADPIF` writer - ADP interrupt flag"]
pub type AdpifW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - ADP module enable"]
    #[inline(always)]
    pub fn adpmen(&self) -> AdpmenR {
        AdpmenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 23 - ADP interrupt flag"]
    #[inline(always)]
    pub fn adpif(&self) -> AdpifR {
        AdpifR::new(((self.bits >> 23) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - ADP module enable"]
    #[inline(always)]
    #[must_use]
    pub fn adpmen(&mut self) -> AdpmenW<OtgFsGpwrdnSpec> {
        AdpmenW::new(self, 0)
    }
    #[doc = "Bit 23 - ADP interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn adpif(&mut self) -> AdpifW<OtgFsGpwrdnSpec> {
        AdpifW::new(self, 23)
    }
}
#[doc = "OTG power down register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gpwrdn::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gpwrdn::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGpwrdnSpec;
impl crate::RegisterSpec for OtgFsGpwrdnSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`otg_fs_gpwrdn::R`](R) reader structure"]
impl crate::Readable for OtgFsGpwrdnSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_gpwrdn::W`](W) writer structure"]
impl crate::Writable for OtgFsGpwrdnSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GPWRDN to value 0x0200_0400"]
impl crate::Resettable for OtgFsGpwrdnSpec {
    const RESET_VALUE: u32 = 0x0200_0400;
}
