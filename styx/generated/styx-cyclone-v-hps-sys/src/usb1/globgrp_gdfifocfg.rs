// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_gdfifocfg` reader"]
pub type R = crate::R<GlobgrpGdfifocfgSpec>;
#[doc = "Register `globgrp_gdfifocfg` writer"]
pub type W = crate::W<GlobgrpGdfifocfgSpec>;
#[doc = "Field `gdfifocfg` reader - This field is for dynamic programming of the DFIFO Size. This value takes effect only when the application programs a non zero value to this register. The otg core does not have any corrective logic if the FIFO sizes are programmed incorrectly."]
pub type GdfifocfgR = crate::FieldReader<u16>;
#[doc = "Field `gdfifocfg` writer - This field is for dynamic programming of the DFIFO Size. This value takes effect only when the application programs a non zero value to this register. The otg core does not have any corrective logic if the FIFO sizes are programmed incorrectly."]
pub type GdfifocfgW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `epinfobaseaddr` reader - This field provides the start address of the EP info controller."]
pub type EpinfobaseaddrR = crate::FieldReader<u16>;
#[doc = "Field `epinfobaseaddr` writer - This field provides the start address of the EP info controller."]
pub type EpinfobaseaddrW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This field is for dynamic programming of the DFIFO Size. This value takes effect only when the application programs a non zero value to this register. The otg core does not have any corrective logic if the FIFO sizes are programmed incorrectly."]
    #[inline(always)]
    pub fn gdfifocfg(&self) -> GdfifocfgR {
        GdfifocfgR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - This field provides the start address of the EP info controller."]
    #[inline(always)]
    pub fn epinfobaseaddr(&self) -> EpinfobaseaddrR {
        EpinfobaseaddrR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field is for dynamic programming of the DFIFO Size. This value takes effect only when the application programs a non zero value to this register. The otg core does not have any corrective logic if the FIFO sizes are programmed incorrectly."]
    #[inline(always)]
    #[must_use]
    pub fn gdfifocfg(&mut self) -> GdfifocfgW<GlobgrpGdfifocfgSpec> {
        GdfifocfgW::new(self, 0)
    }
    #[doc = "Bits 16:31 - This field provides the start address of the EP info controller."]
    #[inline(always)]
    #[must_use]
    pub fn epinfobaseaddr(&mut self) -> EpinfobaseaddrW<GlobgrpGdfifocfgSpec> {
        EpinfobaseaddrW::new(self, 16)
    }
}
#[doc = "Specifies whether Dedicated Transmit FIFOs should be enabled in device mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gdfifocfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gdfifocfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGdfifocfgSpec;
impl crate::RegisterSpec for GlobgrpGdfifocfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 92u64;
}
#[doc = "`read()` method returns [`globgrp_gdfifocfg::R`](R) reader structure"]
impl crate::Readable for GlobgrpGdfifocfgSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_gdfifocfg::W`](W) writer structure"]
impl crate::Writable for GlobgrpGdfifocfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_gdfifocfg to value 0x1f80_2000"]
impl crate::Resettable for GlobgrpGdfifocfgSpec {
    const RESET_VALUE: u32 = 0x1f80_2000;
}
