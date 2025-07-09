// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BRR` reader"]
pub type R = crate::R<BrrSpec>;
#[doc = "Register `BRR` writer"]
pub type W = crate::W<BrrSpec>;
#[doc = "Field `DIV_Fraction` reader - fraction of USARTDIV"]
pub type DivFractionR = crate::FieldReader;
#[doc = "Field `DIV_Fraction` writer - fraction of USARTDIV"]
pub type DivFractionW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `DIV_Mantissa` reader - mantissa of USARTDIV"]
pub type DivMantissaR = crate::FieldReader<u16>;
#[doc = "Field `DIV_Mantissa` writer - mantissa of USARTDIV"]
pub type DivMantissaW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:3 - fraction of USARTDIV"]
    #[inline(always)]
    pub fn div_fraction(&self) -> DivFractionR {
        DivFractionR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:15 - mantissa of USARTDIV"]
    #[inline(always)]
    pub fn div_mantissa(&self) -> DivMantissaR {
        DivMantissaR::new(((self.bits >> 4) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:3 - fraction of USARTDIV"]
    #[inline(always)]
    #[must_use]
    pub fn div_fraction(&mut self) -> DivFractionW<BrrSpec> {
        DivFractionW::new(self, 0)
    }
    #[doc = "Bits 4:15 - mantissa of USARTDIV"]
    #[inline(always)]
    #[must_use]
    pub fn div_mantissa(&mut self) -> DivMantissaW<BrrSpec> {
        DivMantissaW::new(self, 4)
    }
}
#[doc = "Baud rate register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`brr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`brr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BrrSpec;
impl crate::RegisterSpec for BrrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`brr::R`](R) reader structure"]
impl crate::Readable for BrrSpec {}
#[doc = "`write(|w| ..)` method takes [`brr::W`](W) writer structure"]
impl crate::Writable for BrrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BRR to value 0"]
impl crate::Resettable for BrrSpec {
    const RESET_VALUE: u32 = 0;
}
