// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_sda_hold` reader"]
pub type R = crate::R<IcSdaHoldSpec>;
#[doc = "Register `ic_sda_hold` writer"]
pub type W = crate::W<IcSdaHoldSpec>;
#[doc = "Field `ic_sda_hold` reader - Program to a minimum 0f 300ns."]
pub type IcSdaHoldR = crate::FieldReader<u16>;
#[doc = "Field `ic_sda_hold` writer - Program to a minimum 0f 300ns."]
pub type IcSdaHoldW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Program to a minimum 0f 300ns."]
    #[inline(always)]
    pub fn ic_sda_hold(&self) -> IcSdaHoldR {
        IcSdaHoldR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Program to a minimum 0f 300ns."]
    #[inline(always)]
    #[must_use]
    pub fn ic_sda_hold(&mut self) -> IcSdaHoldW<IcSdaHoldSpec> {
        IcSdaHoldW::new(self, 0)
    }
}
#[doc = "This register controls the amount of time delay (in terms of number of l4_sp_clk clock periods) introduced in the falling edge of SCL, relative to SDA changing, when I2C services a read request in a slave-transmitter operation. The relevant I2C requirement is thd:DAT as detailed in the I2C Bus Specification.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_sda_hold::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_sda_hold::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcSdaHoldSpec;
impl crate::RegisterSpec for IcSdaHoldSpec {
    type Ux = u32;
    const OFFSET: u64 = 124u64;
}
#[doc = "`read()` method returns [`ic_sda_hold::R`](R) reader structure"]
impl crate::Readable for IcSdaHoldSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_sda_hold::W`](W) writer structure"]
impl crate::Writable for IcSdaHoldSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_sda_hold to value 0x01"]
impl crate::Resettable for IcSdaHoldSpec {
    const RESET_VALUE: u32 = 0x01;
}
