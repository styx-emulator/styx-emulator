// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DLEN` reader"]
pub type R = crate::R<DlenSpec>;
#[doc = "Register `DLEN` writer"]
pub type W = crate::W<DlenSpec>;
#[doc = "Field `DATALENGTH` reader - Data length value"]
pub type DatalengthR = crate::FieldReader<u32>;
#[doc = "Field `DATALENGTH` writer - Data length value"]
pub type DatalengthW<'a, REG> = crate::FieldWriter<'a, REG, 25, u32>;
impl R {
    #[doc = "Bits 0:24 - Data length value"]
    #[inline(always)]
    pub fn datalength(&self) -> DatalengthR {
        DatalengthR::new(self.bits & 0x01ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:24 - Data length value"]
    #[inline(always)]
    #[must_use]
    pub fn datalength(&mut self) -> DatalengthW<DlenSpec> {
        DatalengthW::new(self, 0)
    }
}
#[doc = "data length register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dlen::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dlen::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DlenSpec;
impl crate::RegisterSpec for DlenSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`dlen::R`](R) reader structure"]
impl crate::Readable for DlenSpec {}
#[doc = "`write(|w| ..)` method takes [`dlen::W`](W) writer structure"]
impl crate::Writable for DlenSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DLEN to value 0"]
impl crate::Resettable for DlenSpec {
    const RESET_VALUE: u32 = 0;
}
