// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_sda_setup` reader"]
pub type R = crate::R<IcSdaSetupSpec>;
#[doc = "Register `ic_sda_setup` writer"]
pub type W = crate::W<IcSdaSetupSpec>;
#[doc = "Field `sda_setup` reader - It is recommended that if the required delay is 1000ns, then for an l4_sp_clk frequency of 10 MHz, ic_sda_setup should be programmed to a value of 11."]
pub type SdaSetupR = crate::FieldReader;
#[doc = "Field `sda_setup` writer - It is recommended that if the required delay is 1000ns, then for an l4_sp_clk frequency of 10 MHz, ic_sda_setup should be programmed to a value of 11."]
pub type SdaSetupW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - It is recommended that if the required delay is 1000ns, then for an l4_sp_clk frequency of 10 MHz, ic_sda_setup should be programmed to a value of 11."]
    #[inline(always)]
    pub fn sda_setup(&self) -> SdaSetupR {
        SdaSetupR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - It is recommended that if the required delay is 1000ns, then for an l4_sp_clk frequency of 10 MHz, ic_sda_setup should be programmed to a value of 11."]
    #[inline(always)]
    #[must_use]
    pub fn sda_setup(&mut self) -> SdaSetupW<IcSdaSetupSpec> {
        SdaSetupW::new(self, 0)
    }
}
#[doc = "This register controls the amount of time delay (in terms of number of l4_sp_clk clock periods) introduced in the rising edge of SCL relative to SDA changing by holding SCL low when I2C services a read request while operating as a slave-transmitter. The relevant I2C requirement is tSU:DAT (note 4) as detailed in the I2C Bus Specification. This register must be programmed with a value equal to or greater than 2. Note: The length of setup time is calculated using \\[(IC_SDA_SETUP - 1) * (l4_sp_clk)\\], so if the user requires 10 l4_sp_clk periods of setup time, they should program a value of 11. The IC_SDA_SETUP register is only used by the I2C when operating as a slave transmitter.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_sda_setup::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_sda_setup::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcSdaSetupSpec;
impl crate::RegisterSpec for IcSdaSetupSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`ic_sda_setup::R`](R) reader structure"]
impl crate::Readable for IcSdaSetupSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_sda_setup::W`](W) writer structure"]
impl crate::Writable for IcSdaSetupSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_sda_setup to value 0x64"]
impl crate::Resettable for IcSdaSetupSpec {
    const RESET_VALUE: u32 = 0x64;
}
