// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlr1` reader"]
pub type R = crate::R<Ctrlr1Spec>;
#[doc = "Register `ctrlr1` writer"]
pub type W = crate::W<Ctrlr1Spec>;
#[doc = "Field `ndf` reader - When TMOD = 10 or TMOD =11, this register field sets the number of data frames to be continuously received by the SPI Master. The SPI Master continues to receive serial data until the number of data frames received is equal to this register value plus 1, which enables you to receive up to 64 KB of data in a continuous transfer."]
pub type NdfR = crate::FieldReader<u16>;
#[doc = "Field `ndf` writer - When TMOD = 10 or TMOD =11, this register field sets the number of data frames to be continuously received by the SPI Master. The SPI Master continues to receive serial data until the number of data frames received is equal to this register value plus 1, which enables you to receive up to 64 KB of data in a continuous transfer."]
pub type NdfW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - When TMOD = 10 or TMOD =11, this register field sets the number of data frames to be continuously received by the SPI Master. The SPI Master continues to receive serial data until the number of data frames received is equal to this register value plus 1, which enables you to receive up to 64 KB of data in a continuous transfer."]
    #[inline(always)]
    pub fn ndf(&self) -> NdfR {
        NdfR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - When TMOD = 10 or TMOD =11, this register field sets the number of data frames to be continuously received by the SPI Master. The SPI Master continues to receive serial data until the number of data frames received is equal to this register value plus 1, which enables you to receive up to 64 KB of data in a continuous transfer."]
    #[inline(always)]
    #[must_use]
    pub fn ndf(&mut self) -> NdfW<Ctrlr1Spec> {
        NdfW::new(self, 0)
    }
}
#[doc = "Control register 1 controls the end of serial transfers when in receive-only mode. It is impossible to write to this register when the SPI Master is enabled.The SPI Master is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ctrlr1Spec;
impl crate::RegisterSpec for Ctrlr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`ctrlr1::R`](R) reader structure"]
impl crate::Readable for Ctrlr1Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlr1::W`](W) writer structure"]
impl crate::Writable for Ctrlr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlr1 to value 0"]
impl crate::Resettable for Ctrlr1Spec {
    const RESET_VALUE: u32 = 0;
}
