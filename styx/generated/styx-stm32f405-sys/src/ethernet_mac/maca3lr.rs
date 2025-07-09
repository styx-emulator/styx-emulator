// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACA3LR` reader"]
pub type R = crate::R<Maca3lrSpec>;
#[doc = "Register `MACA3LR` writer"]
pub type W = crate::W<Maca3lrSpec>;
#[doc = "Field `MBCA3L` reader - MBCA3L"]
pub type Mbca3lR = crate::FieldReader<u32>;
#[doc = "Field `MBCA3L` writer - MBCA3L"]
pub type Mbca3lW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - MBCA3L"]
    #[inline(always)]
    pub fn mbca3l(&self) -> Mbca3lR {
        Mbca3lR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - MBCA3L"]
    #[inline(always)]
    #[must_use]
    pub fn mbca3l(&mut self) -> Mbca3lW<Maca3lrSpec> {
        Mbca3lW::new(self, 0)
    }
}
#[doc = "Ethernet MAC address 3 low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`maca3lr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`maca3lr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Maca3lrSpec;
impl crate::RegisterSpec for Maca3lrSpec {
    type Ux = u32;
    const OFFSET: u64 = 92u64;
}
#[doc = "`read()` method returns [`maca3lr::R`](R) reader structure"]
impl crate::Readable for Maca3lrSpec {}
#[doc = "`write(|w| ..)` method takes [`maca3lr::W`](W) writer structure"]
impl crate::Writable for Maca3lrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACA3LR to value 0xffff_ffff"]
impl crate::Resettable for Maca3lrSpec {
    const RESET_VALUE: u32 = 0xffff_ffff;
}
