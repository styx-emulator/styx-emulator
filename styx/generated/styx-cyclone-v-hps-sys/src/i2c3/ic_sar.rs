// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_sar` reader"]
pub type R = crate::R<IcSarSpec>;
#[doc = "Register `ic_sar` writer"]
pub type W = crate::W<IcSarSpec>;
#[doc = "Field `ic_sar` reader - The Slave Address register holds the slave address when the I2C is operating as a slave. For 7-bit addressing, only Field Bits \\[6:0\\]
of the Slave Address Register are used. This register can be written only when the I2C interface is disabled, which corresponds to field bit 0 of the Enable Register being set to 0. Writes at other times have no effect. Note, the default values cannot be any of the reserved address locations: that is, 0x00 to 0x07, or 0x78 to 0x7f. The correct operation of the device is not guaranteed if you program the Slave Address Register or Target Address Register to a reserved value."]
pub type IcSarR = crate::FieldReader<u16>;
#[doc = "Field `ic_sar` writer - The Slave Address register holds the slave address when the I2C is operating as a slave. For 7-bit addressing, only Field Bits \\[6:0\\]
of the Slave Address Register are used. This register can be written only when the I2C interface is disabled, which corresponds to field bit 0 of the Enable Register being set to 0. Writes at other times have no effect. Note, the default values cannot be any of the reserved address locations: that is, 0x00 to 0x07, or 0x78 to 0x7f. The correct operation of the device is not guaranteed if you program the Slave Address Register or Target Address Register to a reserved value."]
pub type IcSarW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
impl R {
    #[doc = "Bits 0:9 - The Slave Address register holds the slave address when the I2C is operating as a slave. For 7-bit addressing, only Field Bits \\[6:0\\]
of the Slave Address Register are used. This register can be written only when the I2C interface is disabled, which corresponds to field bit 0 of the Enable Register being set to 0. Writes at other times have no effect. Note, the default values cannot be any of the reserved address locations: that is, 0x00 to 0x07, or 0x78 to 0x7f. The correct operation of the device is not guaranteed if you program the Slave Address Register or Target Address Register to a reserved value."]
    #[inline(always)]
    pub fn ic_sar(&self) -> IcSarR {
        IcSarR::new((self.bits & 0x03ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:9 - The Slave Address register holds the slave address when the I2C is operating as a slave. For 7-bit addressing, only Field Bits \\[6:0\\]
of the Slave Address Register are used. This register can be written only when the I2C interface is disabled, which corresponds to field bit 0 of the Enable Register being set to 0. Writes at other times have no effect. Note, the default values cannot be any of the reserved address locations: that is, 0x00 to 0x07, or 0x78 to 0x7f. The correct operation of the device is not guaranteed if you program the Slave Address Register or Target Address Register to a reserved value."]
    #[inline(always)]
    #[must_use]
    pub fn ic_sar(&mut self) -> IcSarW<IcSarSpec> {
        IcSarW::new(self, 0)
    }
}
#[doc = "Holds Address of Slave\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_sar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_sar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcSarSpec;
impl crate::RegisterSpec for IcSarSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`ic_sar::R`](R) reader structure"]
impl crate::Readable for IcSarSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_sar::W`](W) writer structure"]
impl crate::Writable for IcSarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_sar to value 0x55"]
impl crate::Resettable for IcSarSpec {
    const RESET_VALUE: u32 = 0x55;
}
