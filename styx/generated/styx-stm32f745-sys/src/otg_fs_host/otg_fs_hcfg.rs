// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_HCFG` reader"]
pub type R = crate::R<OtgFsHcfgSpec>;
#[doc = "Register `OTG_FS_HCFG` writer"]
pub type W = crate::W<OtgFsHcfgSpec>;
#[doc = "Field `FSLSPCS` reader - FS/LS PHY clock select"]
pub type FslspcsR = crate::FieldReader;
#[doc = "Field `FSLSPCS` writer - FS/LS PHY clock select"]
pub type FslspcsW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `FSLSS` reader - FS- and LS-only support"]
pub type FslssR = crate::BitReader;
#[doc = "Field `FSLSS` writer - FS- and LS-only support"]
pub type FslssW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - FS/LS PHY clock select"]
    #[inline(always)]
    pub fn fslspcs(&self) -> FslspcsR {
        FslspcsR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - FS- and LS-only support"]
    #[inline(always)]
    pub fn fslss(&self) -> FslssR {
        FslssR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - FS/LS PHY clock select"]
    #[inline(always)]
    #[must_use]
    pub fn fslspcs(&mut self) -> FslspcsW<OtgFsHcfgSpec> {
        FslspcsW::new(self, 0)
    }
    #[doc = "Bit 2 - FS- and LS-only support"]
    #[inline(always)]
    #[must_use]
    pub fn fslss(&mut self) -> FslssW<OtgFsHcfgSpec> {
        FslssW::new(self, 2)
    }
}
#[doc = "OTG_FS host configuration register (OTG_FS_HCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_hcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsHcfgSpec;
impl crate::RegisterSpec for OtgFsHcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`otg_fs_hcfg::R`](R) reader structure"]
impl crate::Readable for OtgFsHcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_hcfg::W`](W) writer structure"]
impl crate::Writable for OtgFsHcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_HCFG to value 0"]
impl crate::Resettable for OtgFsHcfgSpec {
    const RESET_VALUE: u32 = 0;
}
