// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_gsnpsid` reader"]
pub type R = crate::R<GlobgrpGsnpsidSpec>;
#[doc = "Register `globgrp_gsnpsid` writer"]
pub type W = crate::W<GlobgrpGsnpsidSpec>;
#[doc = "Field `gsnpsid` reader - Release number of the otg core being used is currently OTG 2.93a"]
pub type GsnpsidR = crate::FieldReader<u32>;
#[doc = "Field `gsnpsid` writer - Release number of the otg core being used is currently OTG 2.93a"]
pub type GsnpsidW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Release number of the otg core being used is currently OTG 2.93a"]
    #[inline(always)]
    pub fn gsnpsid(&self) -> GsnpsidR {
        GsnpsidR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Release number of the otg core being used is currently OTG 2.93a"]
    #[inline(always)]
    #[must_use]
    pub fn gsnpsid(&mut self) -> GsnpsidW<GlobgrpGsnpsidSpec> {
        GsnpsidW::new(self, 0)
    }
}
#[doc = "This read-only register contains the release number of the core being used.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gsnpsid::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGsnpsidSpec;
impl crate::RegisterSpec for GlobgrpGsnpsidSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`globgrp_gsnpsid::R`](R) reader structure"]
impl crate::Readable for GlobgrpGsnpsidSpec {}
#[doc = "`reset()` method sets globgrp_gsnpsid to value 0x4f54_293a"]
impl crate::Resettable for GlobgrpGsnpsidSpec {
    const RESET_VALUE: u32 = 0x4f54_293a;
}
