// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_fs_scl_lcnt` reader"]
pub type R = crate::R<IcFsSclLcntSpec>;
#[doc = "Register `ic_fs_scl_lcnt` writer"]
pub type W = crate::W<IcFsSclLcntSpec>;
#[doc = "Field `ic_fs_scl_lcnt` reader - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock low period count for fast speed. It is used in high-speed mode to send the Master Code and START BYTE or General CALL. This register can be written only when the I2C interface is disabled, which corresponds to the Enable Register being set to 0. Writes at other times have no effect.The minimum valid value is 8; hardware prevents values less than this being written, and if attempted results in 8 being set."]
pub type IcFsSclLcntR = crate::FieldReader<u16>;
#[doc = "Field `ic_fs_scl_lcnt` writer - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock low period count for fast speed. It is used in high-speed mode to send the Master Code and START BYTE or General CALL. This register can be written only when the I2C interface is disabled, which corresponds to the Enable Register being set to 0. Writes at other times have no effect.The minimum valid value is 8; hardware prevents values less than this being written, and if attempted results in 8 being set."]
pub type IcFsSclLcntW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock low period count for fast speed. It is used in high-speed mode to send the Master Code and START BYTE or General CALL. This register can be written only when the I2C interface is disabled, which corresponds to the Enable Register being set to 0. Writes at other times have no effect.The minimum valid value is 8; hardware prevents values less than this being written, and if attempted results in 8 being set."]
    #[inline(always)]
    pub fn ic_fs_scl_lcnt(&self) -> IcFsSclLcntR {
        IcFsSclLcntR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock low period count for fast speed. It is used in high-speed mode to send the Master Code and START BYTE or General CALL. This register can be written only when the I2C interface is disabled, which corresponds to the Enable Register being set to 0. Writes at other times have no effect.The minimum valid value is 8; hardware prevents values less than this being written, and if attempted results in 8 being set."]
    #[inline(always)]
    #[must_use]
    pub fn ic_fs_scl_lcnt(&mut self) -> IcFsSclLcntW<IcFsSclLcntSpec> {
        IcFsSclLcntW::new(self, 0)
    }
}
#[doc = "This register sets the SCL clock low period count\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_fs_scl_lcnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_fs_scl_lcnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcFsSclLcntSpec;
impl crate::RegisterSpec for IcFsSclLcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`ic_fs_scl_lcnt::R`](R) reader structure"]
impl crate::Readable for IcFsSclLcntSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_fs_scl_lcnt::W`](W) writer structure"]
impl crate::Writable for IcFsSclLcntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_fs_scl_lcnt to value 0x82"]
impl crate::Resettable for IcFsSclLcntSpec {
    const RESET_VALUE: u32 = 0x82;
}
