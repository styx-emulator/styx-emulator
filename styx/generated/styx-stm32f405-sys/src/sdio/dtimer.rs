// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DTIMER` reader"]
pub type R = crate::R<DtimerSpec>;
#[doc = "Register `DTIMER` writer"]
pub type W = crate::W<DtimerSpec>;
#[doc = "Field `DATATIME` reader - Data timeout period"]
pub type DatatimeR = crate::FieldReader<u32>;
#[doc = "Field `DATATIME` writer - Data timeout period"]
pub type DatatimeW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Data timeout period"]
    #[inline(always)]
    pub fn datatime(&self) -> DatatimeR {
        DatatimeR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Data timeout period"]
    #[inline(always)]
    #[must_use]
    pub fn datatime(&mut self) -> DatatimeW<DtimerSpec> {
        DatatimeW::new(self, 0)
    }
}
#[doc = "data timer register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dtimer::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dtimer::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DtimerSpec;
impl crate::RegisterSpec for DtimerSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`dtimer::R`](R) reader structure"]
impl crate::Readable for DtimerSpec {}
#[doc = "`write(|w| ..)` method takes [`dtimer::W`](W) writer structure"]
impl crate::Writable for DtimerSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DTIMER to value 0"]
impl crate::Resettable for DtimerSpec {
    const RESET_VALUE: u32 = 0;
}
