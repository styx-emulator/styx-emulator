// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_DVBUSDIS` reader"]
pub type R = crate::R<OtgFsDvbusdisSpec>;
#[doc = "Register `OTG_FS_DVBUSDIS` writer"]
pub type W = crate::W<OtgFsDvbusdisSpec>;
#[doc = "Field `VBUSDT` reader - Device VBUS discharge time"]
pub type VbusdtR = crate::FieldReader<u16>;
#[doc = "Field `VBUSDT` writer - Device VBUS discharge time"]
pub type VbusdtW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Device VBUS discharge time"]
    #[inline(always)]
    pub fn vbusdt(&self) -> VbusdtR {
        VbusdtR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Device VBUS discharge time"]
    #[inline(always)]
    #[must_use]
    pub fn vbusdt(&mut self) -> VbusdtW<OtgFsDvbusdisSpec> {
        VbusdtW::new(self, 0)
    }
}
#[doc = "OTG_FS device VBUS discharge time register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_dvbusdis::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_dvbusdis::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsDvbusdisSpec;
impl crate::RegisterSpec for OtgFsDvbusdisSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`otg_fs_dvbusdis::R`](R) reader structure"]
impl crate::Readable for OtgFsDvbusdisSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_dvbusdis::W`](W) writer structure"]
impl crate::Writable for OtgFsDvbusdisSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_DVBUSDIS to value 0x17d7"]
impl crate::Resettable for OtgFsDvbusdisSpec {
    const RESET_VALUE: u32 = 0x17d7;
}
