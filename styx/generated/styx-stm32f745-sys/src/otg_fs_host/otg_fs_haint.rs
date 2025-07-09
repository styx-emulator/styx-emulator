// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_HAINT` reader"]
pub type R = crate::R<OtgFsHaintSpec>;
#[doc = "Register `OTG_FS_HAINT` writer"]
pub type W = crate::W<OtgFsHaintSpec>;
#[doc = "Field `HAINT` reader - Channel interrupts"]
pub type HaintR = crate::FieldReader<u16>;
#[doc = "Field `HAINT` writer - Channel interrupts"]
pub type HaintW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Channel interrupts"]
    #[inline(always)]
    pub fn haint(&self) -> HaintR {
        HaintR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Channel interrupts"]
    #[inline(always)]
    #[must_use]
    pub fn haint(&mut self) -> HaintW<OtgFsHaintSpec> {
        HaintW::new(self, 0)
    }
}
#[doc = "OTG_FS Host all channels interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_haint::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsHaintSpec;
impl crate::RegisterSpec for OtgFsHaintSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`otg_fs_haint::R`](R) reader structure"]
impl crate::Readable for OtgFsHaintSpec {}
#[doc = "`reset()` method sets OTG_FS_HAINT to value 0"]
impl crate::Resettable for OtgFsHaintSpec {
    const RESET_VALUE: u32 = 0;
}
