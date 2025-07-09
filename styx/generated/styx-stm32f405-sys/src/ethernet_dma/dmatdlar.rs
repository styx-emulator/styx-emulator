// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DMATDLAR` reader"]
pub type R = crate::R<DmatdlarSpec>;
#[doc = "Register `DMATDLAR` writer"]
pub type W = crate::W<DmatdlarSpec>;
#[doc = "Field `STL` reader - STL"]
pub type StlR = crate::FieldReader<u32>;
#[doc = "Field `STL` writer - STL"]
pub type StlW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - STL"]
    #[inline(always)]
    pub fn stl(&self) -> StlR {
        StlR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - STL"]
    #[inline(always)]
    #[must_use]
    pub fn stl(&mut self) -> StlW<DmatdlarSpec> {
        StlW::new(self, 0)
    }
}
#[doc = "Ethernet DMA transmit descriptor list address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmatdlar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmatdlar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmatdlarSpec;
impl crate::RegisterSpec for DmatdlarSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`dmatdlar::R`](R) reader structure"]
impl crate::Readable for DmatdlarSpec {}
#[doc = "`write(|w| ..)` method takes [`dmatdlar::W`](W) writer structure"]
impl crate::Writable for DmatdlarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMATDLAR to value 0"]
impl crate::Resettable for DmatdlarSpec {
    const RESET_VALUE: u32 = 0;
}
