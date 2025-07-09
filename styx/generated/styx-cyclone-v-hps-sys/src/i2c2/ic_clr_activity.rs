// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_activity` reader"]
pub type R = crate::R<IcClrActivitySpec>;
#[doc = "Register `ic_clr_activity` writer"]
pub type W = crate::W<IcClrActivitySpec>;
#[doc = "Field `clr_activity` reader - Reading this register clears the ACTIVITY interrupt if the I2C is not active anymore. If the I2C module is still active on the bus, the ACTIVITY interrupt bit continues to be set. It is automatically cleared by hardware if the module is disabled and if there is no further activity on the bus. The value read from this register to get status of the ACTIVITY interrupt (bit 8) of the ic_raw_intr_stat register."]
pub type ClrActivityR = crate::BitReader;
#[doc = "Field `clr_activity` writer - Reading this register clears the ACTIVITY interrupt if the I2C is not active anymore. If the I2C module is still active on the bus, the ACTIVITY interrupt bit continues to be set. It is automatically cleared by hardware if the module is disabled and if there is no further activity on the bus. The value read from this register to get status of the ACTIVITY interrupt (bit 8) of the ic_raw_intr_stat register."]
pub type ClrActivityW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Reading this register clears the ACTIVITY interrupt if the I2C is not active anymore. If the I2C module is still active on the bus, the ACTIVITY interrupt bit continues to be set. It is automatically cleared by hardware if the module is disabled and if there is no further activity on the bus. The value read from this register to get status of the ACTIVITY interrupt (bit 8) of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_activity(&self) -> ClrActivityR {
        ClrActivityR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Reading this register clears the ACTIVITY interrupt if the I2C is not active anymore. If the I2C module is still active on the bus, the ACTIVITY interrupt bit continues to be set. It is automatically cleared by hardware if the module is disabled and if there is no further activity on the bus. The value read from this register to get status of the ACTIVITY interrupt (bit 8) of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_activity(&mut self) -> ClrActivityW<IcClrActivitySpec> {
        ClrActivityW::new(self, 0)
    }
}
#[doc = "Clears ACTIVITY Interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_activity::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrActivitySpec;
impl crate::RegisterSpec for IcClrActivitySpec {
    type Ux = u32;
    const OFFSET: u64 = 92u64;
}
#[doc = "`read()` method returns [`ic_clr_activity::R`](R) reader structure"]
impl crate::Readable for IcClrActivitySpec {}
#[doc = "`reset()` method sets ic_clr_activity to value 0"]
impl crate::Resettable for IcClrActivitySpec {
    const RESET_VALUE: u32 = 0;
}
