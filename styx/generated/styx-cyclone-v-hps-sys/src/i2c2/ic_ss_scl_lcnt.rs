// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `ic_ss_scl_lcnt` reader"]
pub type R = crate::R<IcSsSclLcntSpec>;
#[doc = "Register `ic_ss_scl_lcnt` writer"]
pub type W = crate::W<IcSsSclLcntSpec>;
#[doc = "Field `ic_ss_scl_lcnt` reader - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock low period count for standard speed. This register can be written only when the I2C interface is disabled which corresponds to the Enable Register register being set to 0. Writes at other times have no effect. The minimum valid value is 8; hardware prevents values less than this from being written, and if attempted, results in 8 being set."]
pub type IcSsSclLcntR = crate::FieldReader<u16>;
#[doc = "Field `ic_ss_scl_lcnt` writer - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock low period count for standard speed. This register can be written only when the I2C interface is disabled which corresponds to the Enable Register register being set to 0. Writes at other times have no effect. The minimum valid value is 8; hardware prevents values less than this from being written, and if attempted, results in 8 being set."]
pub type IcSsSclLcntW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock low period count for standard speed. This register can be written only when the I2C interface is disabled which corresponds to the Enable Register register being set to 0. Writes at other times have no effect. The minimum valid value is 8; hardware prevents values less than this from being written, and if attempted, results in 8 being set."]
    #[inline(always)]
    pub fn ic_ss_scl_lcnt(&self) -> IcSsSclLcntR {
        IcSsSclLcntR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This register must be set before any I2C bus transaction can take place to ensure proper I/O timing. This field sets the SCL clock low period count for standard speed. This register can be written only when the I2C interface is disabled which corresponds to the Enable Register register being set to 0. Writes at other times have no effect. The minimum valid value is 8; hardware prevents values less than this from being written, and if attempted, results in 8 being set."]
    #[inline(always)]
    #[must_use]
    pub fn ic_ss_scl_lcnt(&mut self) -> IcSsSclLcntW<IcSsSclLcntSpec> {
        IcSsSclLcntW::new(self, 0)
    }
}
#[doc = "This register sets the SCL clock low-period count for standard speed\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_ss_scl_lcnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_ss_scl_lcnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcSsSclLcntSpec;
impl crate::RegisterSpec for IcSsSclLcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`ic_ss_scl_lcnt::R`](R) reader structure"]
impl crate::Readable for IcSsSclLcntSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_ss_scl_lcnt::W`](W) writer structure"]
impl crate::Writable for IcSsSclLcntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_ss_scl_lcnt to value 0x01d6"]
impl crate::Resettable for IcSsSclLcntSpec {
    const RESET_VALUE: u32 = 0x01d6;
}
