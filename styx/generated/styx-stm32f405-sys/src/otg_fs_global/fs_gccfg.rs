// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_GCCFG` reader"]
pub type R = crate::R<FsGccfgSpec>;
#[doc = "Register `FS_GCCFG` writer"]
pub type W = crate::W<FsGccfgSpec>;
#[doc = "Field `PWRDWN` reader - Power down"]
pub type PwrdwnR = crate::BitReader;
#[doc = "Field `PWRDWN` writer - Power down"]
pub type PwrdwnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VBUSASEN` reader - Enable the VBUS sensing device"]
pub type VbusasenR = crate::BitReader;
#[doc = "Field `VBUSASEN` writer - Enable the VBUS sensing device"]
pub type VbusasenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VBUSBSEN` reader - Enable the VBUS sensing device"]
pub type VbusbsenR = crate::BitReader;
#[doc = "Field `VBUSBSEN` writer - Enable the VBUS sensing device"]
pub type VbusbsenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SOFOUTEN` reader - SOF output enable"]
pub type SofoutenR = crate::BitReader;
#[doc = "Field `SOFOUTEN` writer - SOF output enable"]
pub type SofoutenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 16 - Power down"]
    #[inline(always)]
    pub fn pwrdwn(&self) -> PwrdwnR {
        PwrdwnR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 18 - Enable the VBUS sensing device"]
    #[inline(always)]
    pub fn vbusasen(&self) -> VbusasenR {
        VbusasenR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Enable the VBUS sensing device"]
    #[inline(always)]
    pub fn vbusbsen(&self) -> VbusbsenR {
        VbusbsenR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - SOF output enable"]
    #[inline(always)]
    pub fn sofouten(&self) -> SofoutenR {
        SofoutenR::new(((self.bits >> 20) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 16 - Power down"]
    #[inline(always)]
    #[must_use]
    pub fn pwrdwn(&mut self) -> PwrdwnW<FsGccfgSpec> {
        PwrdwnW::new(self, 16)
    }
    #[doc = "Bit 18 - Enable the VBUS sensing device"]
    #[inline(always)]
    #[must_use]
    pub fn vbusasen(&mut self) -> VbusasenW<FsGccfgSpec> {
        VbusasenW::new(self, 18)
    }
    #[doc = "Bit 19 - Enable the VBUS sensing device"]
    #[inline(always)]
    #[must_use]
    pub fn vbusbsen(&mut self) -> VbusbsenW<FsGccfgSpec> {
        VbusbsenW::new(self, 19)
    }
    #[doc = "Bit 20 - SOF output enable"]
    #[inline(always)]
    #[must_use]
    pub fn sofouten(&mut self) -> SofoutenW<FsGccfgSpec> {
        SofoutenW::new(self, 20)
    }
}
#[doc = "OTG_FS general core configuration register (OTG_FS_GCCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_gccfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_gccfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsGccfgSpec;
impl crate::RegisterSpec for FsGccfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`fs_gccfg::R`](R) reader structure"]
impl crate::Readable for FsGccfgSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_gccfg::W`](W) writer structure"]
impl crate::Writable for FsGccfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_GCCFG to value 0"]
impl crate::Resettable for FsGccfgSpec {
    const RESET_VALUE: u32 = 0;
}
