// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_ggpio` reader"]
pub type R = crate::R<GlobgrpGgpioSpec>;
#[doc = "Register `globgrp_ggpio` writer"]
pub type W = crate::W<GlobgrpGgpioSpec>;
#[doc = "Field `gpi` reader - This field's read value reflects the gp_i\\[15:0\\]
core input value."]
pub type GpiR = crate::FieldReader<u16>;
#[doc = "Field `gpi` writer - This field's read value reflects the gp_i\\[15:0\\]
core input value."]
pub type GpiW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `gpo` reader - This field is driven as an output from the core, gp_o\\[15:0\\]. The application can program this field to determine the corresponding value on the gp_o\\[15:0\\]
output."]
pub type GpoR = crate::FieldReader<u16>;
#[doc = "Field `gpo` writer - This field is driven as an output from the core, gp_o\\[15:0\\]. The application can program this field to determine the corresponding value on the gp_o\\[15:0\\]
output."]
pub type GpoW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - This field's read value reflects the gp_i\\[15:0\\]
core input value."]
    #[inline(always)]
    pub fn gpi(&self) -> GpiR {
        GpiR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - This field is driven as an output from the core, gp_o\\[15:0\\]. The application can program this field to determine the corresponding value on the gp_o\\[15:0\\]
output."]
    #[inline(always)]
    pub fn gpo(&self) -> GpoR {
        GpoR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field's read value reflects the gp_i\\[15:0\\]
core input value."]
    #[inline(always)]
    #[must_use]
    pub fn gpi(&mut self) -> GpiW<GlobgrpGgpioSpec> {
        GpiW::new(self, 0)
    }
    #[doc = "Bits 16:31 - This field is driven as an output from the core, gp_o\\[15:0\\]. The application can program this field to determine the corresponding value on the gp_o\\[15:0\\]
output."]
    #[inline(always)]
    #[must_use]
    pub fn gpo(&mut self) -> GpoW<GlobgrpGgpioSpec> {
        GpoW::new(self, 16)
    }
}
#[doc = "The application can use this register for general purpose input/output ports or for debugging.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ggpio::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_ggpio::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGgpioSpec;
impl crate::RegisterSpec for GlobgrpGgpioSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`globgrp_ggpio::R`](R) reader structure"]
impl crate::Readable for GlobgrpGgpioSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_ggpio::W`](W) writer structure"]
impl crate::Writable for GlobgrpGgpioSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_ggpio to value 0"]
impl crate::Resettable for GlobgrpGgpioSpec {
    const RESET_VALUE: u32 = 0;
}
