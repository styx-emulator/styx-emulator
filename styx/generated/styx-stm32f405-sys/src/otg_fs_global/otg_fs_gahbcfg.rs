// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_FS_GAHBCFG` reader"]
pub type R = crate::R<OtgFsGahbcfgSpec>;
#[doc = "Register `OTG_FS_GAHBCFG` writer"]
pub type W = crate::W<OtgFsGahbcfgSpec>;
#[doc = "Field `GINT` reader - Global interrupt mask"]
pub type GintR = crate::BitReader;
#[doc = "Field `GINT` writer - Global interrupt mask"]
pub type GintW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXFELVL` reader - TxFIFO empty level"]
pub type TxfelvlR = crate::BitReader;
#[doc = "Field `TXFELVL` writer - TxFIFO empty level"]
pub type TxfelvlW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PTXFELVL` reader - Periodic TxFIFO empty level"]
pub type PtxfelvlR = crate::BitReader;
#[doc = "Field `PTXFELVL` writer - Periodic TxFIFO empty level"]
pub type PtxfelvlW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Global interrupt mask"]
    #[inline(always)]
    pub fn gint(&self) -> GintR {
        GintR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 7 - TxFIFO empty level"]
    #[inline(always)]
    pub fn txfelvl(&self) -> TxfelvlR {
        TxfelvlR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Periodic TxFIFO empty level"]
    #[inline(always)]
    pub fn ptxfelvl(&self) -> PtxfelvlR {
        PtxfelvlR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Global interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn gint(&mut self) -> GintW<OtgFsGahbcfgSpec> {
        GintW::new(self, 0)
    }
    #[doc = "Bit 7 - TxFIFO empty level"]
    #[inline(always)]
    #[must_use]
    pub fn txfelvl(&mut self) -> TxfelvlW<OtgFsGahbcfgSpec> {
        TxfelvlW::new(self, 7)
    }
    #[doc = "Bit 8 - Periodic TxFIFO empty level"]
    #[inline(always)]
    #[must_use]
    pub fn ptxfelvl(&mut self) -> PtxfelvlW<OtgFsGahbcfgSpec> {
        PtxfelvlW::new(self, 8)
    }
}
#[doc = "OTG_FS AHB configuration register (OTG_FS_GAHBCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gahbcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gahbcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGahbcfgSpec;
impl crate::RegisterSpec for OtgFsGahbcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`otg_fs_gahbcfg::R`](R) reader structure"]
impl crate::Readable for OtgFsGahbcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_gahbcfg::W`](W) writer structure"]
impl crate::Writable for OtgFsGahbcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GAHBCFG to value 0"]
impl crate::Resettable for OtgFsGahbcfgSpec {
    const RESET_VALUE: u32 = 0;
}
