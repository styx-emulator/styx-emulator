// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHB3ENR` reader"]
pub type R = crate::R<Ahb3enrSpec>;
#[doc = "Register `AHB3ENR` writer"]
pub type W = crate::W<Ahb3enrSpec>;
#[doc = "Field `FSMCEN` reader - Flexible static memory controller module clock enable"]
pub type FsmcenR = crate::BitReader;
#[doc = "Field `FSMCEN` writer - Flexible static memory controller module clock enable"]
pub type FsmcenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Flexible static memory controller module clock enable"]
    #[inline(always)]
    pub fn fsmcen(&self) -> FsmcenR {
        FsmcenR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Flexible static memory controller module clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn fsmcen(&mut self) -> FsmcenW<Ahb3enrSpec> {
        FsmcenW::new(self, 0)
    }
}
#[doc = "AHB3 peripheral clock enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahb3enr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahb3enr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ahb3enrSpec;
impl crate::RegisterSpec for Ahb3enrSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`ahb3enr::R`](R) reader structure"]
impl crate::Readable for Ahb3enrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahb3enr::W`](W) writer structure"]
impl crate::Writable for Ahb3enrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHB3ENR to value 0"]
impl crate::Resettable for Ahb3enrSpec {
    const RESET_VALUE: u32 = 0;
}
