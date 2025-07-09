// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMATPDR` reader"]
pub type R = crate::R<DmatpdrSpec>;
#[doc = "Register `DMATPDR` writer"]
pub type W = crate::W<DmatpdrSpec>;
#[doc = "Field `TPD` reader - TPD"]
pub type TpdR = crate::FieldReader<u32>;
#[doc = "Field `TPD` writer - TPD"]
pub type TpdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - TPD"]
    #[inline(always)]
    pub fn tpd(&self) -> TpdR {
        TpdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - TPD"]
    #[inline(always)]
    #[must_use]
    pub fn tpd(&mut self) -> TpdW<DmatpdrSpec> {
        TpdW::new(self, 0)
    }
}
#[doc = "Ethernet DMA transmit poll demand register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmatpdr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmatpdr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmatpdrSpec;
impl crate::RegisterSpec for DmatpdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`dmatpdr::R`](R) reader structure"]
impl crate::Readable for DmatpdrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmatpdr::W`](W) writer structure"]
impl crate::Writable for DmatpdrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMATPDR to value 0"]
impl crate::Resettable for DmatpdrSpec {
    const RESET_VALUE: u32 = 0;
}
