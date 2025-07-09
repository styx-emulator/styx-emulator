// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PMC` reader"]
pub type R = crate::R<PmcSpec>;
#[doc = "Register `PMC` writer"]
pub type W = crate::W<PmcSpec>;
#[doc = "Field `MII_RMII_SEL` reader - Ethernet PHY interface selection"]
pub type MiiRmiiSelR = crate::BitReader;
#[doc = "Field `MII_RMII_SEL` writer - Ethernet PHY interface selection"]
pub type MiiRmiiSelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 23 - Ethernet PHY interface selection"]
    #[inline(always)]
    pub fn mii_rmii_sel(&self) -> MiiRmiiSelR {
        MiiRmiiSelR::new(((self.bits >> 23) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 23 - Ethernet PHY interface selection"]
    #[inline(always)]
    #[must_use]
    pub fn mii_rmii_sel(&mut self) -> MiiRmiiSelW<PmcSpec> {
        MiiRmiiSelW::new(self, 23)
    }
}
#[doc = "peripheral mode configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pmc::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pmc::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PmcSpec;
impl crate::RegisterSpec for PmcSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`pmc::R`](R) reader structure"]
impl crate::Readable for PmcSpec {}
#[doc = "`write(|w| ..)` method takes [`pmc::W`](W) writer structure"]
impl crate::Writable for PmcSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PMC to value 0"]
impl crate::Resettable for PmcSpec {
    const RESET_VALUE: u32 = 0;
}
