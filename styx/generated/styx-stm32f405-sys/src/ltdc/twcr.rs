// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TWCR` reader"]
pub type R = crate::R<TwcrSpec>;
#[doc = "Register `TWCR` writer"]
pub type W = crate::W<TwcrSpec>;
#[doc = "Field `TOTALH` reader - Total Height (in units of horizontal scan line)"]
pub type TotalhR = crate::FieldReader<u16>;
#[doc = "Field `TOTALH` writer - Total Height (in units of horizontal scan line)"]
pub type TotalhW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
#[doc = "Field `TOTALW` reader - Total Width (in units of pixel clock period)"]
pub type TotalwR = crate::FieldReader<u16>;
#[doc = "Field `TOTALW` writer - Total Width (in units of pixel clock period)"]
pub type TotalwW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
impl R {
    #[doc = "Bits 0:10 - Total Height (in units of horizontal scan line)"]
    #[inline(always)]
    pub fn totalh(&self) -> TotalhR {
        TotalhR::new((self.bits & 0x07ff) as u16)
    }
    #[doc = "Bits 16:25 - Total Width (in units of pixel clock period)"]
    #[inline(always)]
    pub fn totalw(&self) -> TotalwR {
        TotalwR::new(((self.bits >> 16) & 0x03ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:10 - Total Height (in units of horizontal scan line)"]
    #[inline(always)]
    #[must_use]
    pub fn totalh(&mut self) -> TotalhW<TwcrSpec> {
        TotalhW::new(self, 0)
    }
    #[doc = "Bits 16:25 - Total Width (in units of pixel clock period)"]
    #[inline(always)]
    #[must_use]
    pub fn totalw(&mut self) -> TotalwW<TwcrSpec> {
        TotalwW::new(self, 16)
    }
}
#[doc = "Total Width Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`twcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`twcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TwcrSpec;
impl crate::RegisterSpec for TwcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`twcr::R`](R) reader structure"]
impl crate::Readable for TwcrSpec {}
#[doc = "`write(|w| ..)` method takes [`twcr::W`](W) writer structure"]
impl crate::Writable for TwcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets TWCR to value 0"]
impl crate::Resettable for TwcrSpec {
    const RESET_VALUE: u32 = 0;
}
