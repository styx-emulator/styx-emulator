// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `L1CFBLNR` reader"]
pub type R = crate::R<L1cfblnrSpec>;
#[doc = "Register `L1CFBLNR` writer"]
pub type W = crate::W<L1cfblnrSpec>;
#[doc = "Field `CFBLNBR` reader - Frame Buffer Line Number"]
pub type CfblnbrR = crate::FieldReader<u16>;
#[doc = "Field `CFBLNBR` writer - Frame Buffer Line Number"]
pub type CfblnbrW<'a, REG> = crate::FieldWriter<'a, REG, 11, u16>;
impl R {
    #[doc = "Bits 0:10 - Frame Buffer Line Number"]
    #[inline(always)]
    pub fn cfblnbr(&self) -> CfblnbrR {
        CfblnbrR::new((self.bits & 0x07ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:10 - Frame Buffer Line Number"]
    #[inline(always)]
    #[must_use]
    pub fn cfblnbr(&mut self) -> CfblnbrW<L1cfblnrSpec> {
        CfblnbrW::new(self, 0)
    }
}
#[doc = "Layerx ColorFrame Buffer Line Number Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1cfblnr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1cfblnr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L1cfblnrSpec;
impl crate::RegisterSpec for L1cfblnrSpec {
    type Ux = u32;
    const OFFSET: u64 = 180u64;
}
#[doc = "`read()` method returns [`l1cfblnr::R`](R) reader structure"]
impl crate::Readable for L1cfblnrSpec {}
#[doc = "`write(|w| ..)` method takes [`l1cfblnr::W`](W) writer structure"]
impl crate::Writable for L1cfblnrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L1CFBLNR to value 0"]
impl crate::Resettable for L1cfblnrSpec {
    const RESET_VALUE: u32 = 0;
}
