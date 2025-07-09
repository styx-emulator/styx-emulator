// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_ss_scl_hcnt` reader"]
pub type R = crate::R<IcSsSclHcntSpec>;
#[doc = "Register `ic_ss_scl_hcnt` writer"]
pub type W = crate::W<IcSsSclHcntSpec>;
#[doc = "Field `ic_ss_scl_hcnt` reader - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock high-period count for standard speed. This register can be written only when the I2C interface is disabled which corresponds to the Enable Register being set to 0. Writes at other times have no effect. The minimum valid value is 6; hardware prevents values less than this being written, and if attempted results in 6 being set. It is readable and writeable. NOTE: This register must not be programmed to a value higher than 65525, because I2C uses a 16-bit counter to flag an I2C bus idle condition when this counter reaches a value of IC_SS_SCL_HCNT + 10."]
pub type IcSsSclHcntR = crate::FieldReader<u16>;
#[doc = "Field `ic_ss_scl_hcnt` writer - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock high-period count for standard speed. This register can be written only when the I2C interface is disabled which corresponds to the Enable Register being set to 0. Writes at other times have no effect. The minimum valid value is 6; hardware prevents values less than this being written, and if attempted results in 6 being set. It is readable and writeable. NOTE: This register must not be programmed to a value higher than 65525, because I2C uses a 16-bit counter to flag an I2C bus idle condition when this counter reaches a value of IC_SS_SCL_HCNT + 10."]
pub type IcSsSclHcntW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock high-period count for standard speed. This register can be written only when the I2C interface is disabled which corresponds to the Enable Register being set to 0. Writes at other times have no effect. The minimum valid value is 6; hardware prevents values less than this being written, and if attempted results in 6 being set. It is readable and writeable. NOTE: This register must not be programmed to a value higher than 65525, because I2C uses a 16-bit counter to flag an I2C bus idle condition when this counter reaches a value of IC_SS_SCL_HCNT + 10."]
    #[inline(always)]
    pub fn ic_ss_scl_hcnt(&self) -> IcSsSclHcntR {
        IcSsSclHcntR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock high-period count for standard speed. This register can be written only when the I2C interface is disabled which corresponds to the Enable Register being set to 0. Writes at other times have no effect. The minimum valid value is 6; hardware prevents values less than this being written, and if attempted results in 6 being set. It is readable and writeable. NOTE: This register must not be programmed to a value higher than 65525, because I2C uses a 16-bit counter to flag an I2C bus idle condition when this counter reaches a value of IC_SS_SCL_HCNT + 10."]
    #[inline(always)]
    #[must_use]
    pub fn ic_ss_scl_hcnt(&mut self) -> IcSsSclHcntW<IcSsSclHcntSpec> {
        IcSsSclHcntW::new(self, 0)
    }
}
#[doc = "This register sets the SCL clock high-period count for standard speed.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_ss_scl_hcnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_ss_scl_hcnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcSsSclHcntSpec;
impl crate::RegisterSpec for IcSsSclHcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`ic_ss_scl_hcnt::R`](R) reader structure"]
impl crate::Readable for IcSsSclHcntSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_ss_scl_hcnt::W`](W) writer structure"]
impl crate::Writable for IcSsSclHcntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_ss_scl_hcnt to value 0x0190"]
impl crate::Resettable for IcSsSclHcntSpec {
    const RESET_VALUE: u32 = 0x0190;
}
