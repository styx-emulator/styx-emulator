// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_GMII_Data` reader"]
pub type R = crate::R<GmacgrpGmiiDataSpec>;
#[doc = "Register `gmacgrp_GMII_Data` writer"]
pub type W = crate::W<GmacgrpGmiiDataSpec>;
#[doc = "Field `gd` reader - This field contains the 16-bit data value read from the PHY or RevMII after a Management Read operation or the 16-bit data value to be written to the PHY or RevMII before a Management Write operation."]
pub type GdR = crate::FieldReader<u16>;
#[doc = "Field `gd` writer - This field contains the 16-bit data value read from the PHY or RevMII after a Management Read operation or the 16-bit data value to be written to the PHY or RevMII before a Management Write operation."]
pub type GdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This field contains the 16-bit data value read from the PHY or RevMII after a Management Read operation or the 16-bit data value to be written to the PHY or RevMII before a Management Write operation."]
    #[inline(always)]
    pub fn gd(&self) -> GdR {
        GdR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field contains the 16-bit data value read from the PHY or RevMII after a Management Read operation or the 16-bit data value to be written to the PHY or RevMII before a Management Write operation."]
    #[inline(always)]
    #[must_use]
    pub fn gd(&mut self) -> GdW<GmacgrpGmiiDataSpec> {
        GdW::new(self, 0)
    }
}
#[doc = "The GMII Data register stores Write data to be written to the PHY register located at the address specified in Register 4 (GMII Address Register). This register also stores the Read data from the PHY register located at the address specified by Register 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_gmii_data::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_gmii_data::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpGmiiDataSpec;
impl crate::RegisterSpec for GmacgrpGmiiDataSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`gmacgrp_gmii_data::R`](R) reader structure"]
impl crate::Readable for GmacgrpGmiiDataSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_gmii_data::W`](W) writer structure"]
impl crate::Writable for GmacgrpGmiiDataSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_GMII_Data to value 0"]
impl crate::Resettable for GmacgrpGmiiDataSpec {
    const RESET_VALUE: u32 = 0;
}
