// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `LOAD` reader"]
pub type R = crate::R<LoadSpec>;
#[doc = "Register `LOAD` writer"]
pub type W = crate::W<LoadSpec>;
#[doc = "Field `RELOAD` reader - RELOAD value"]
pub type ReloadR = crate::FieldReader<u32>;
#[doc = "Field `RELOAD` writer - RELOAD value"]
pub type ReloadW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:23 - RELOAD value"]
    #[inline(always)]
    pub fn reload(&self) -> ReloadR {
        ReloadR::new(self.bits & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:23 - RELOAD value"]
    #[inline(always)]
    #[must_use]
    pub fn reload(&mut self) -> ReloadW<LoadSpec> {
        ReloadW::new(self, 0)
    }
}
#[doc = "SysTick reload value register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`load::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`load::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LoadSpec;
impl crate::RegisterSpec for LoadSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`load::R`](R) reader structure"]
impl crate::Readable for LoadSpec {}
#[doc = "`write(|w| ..)` method takes [`load::W`](W) writer structure"]
impl crate::Writable for LoadSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets LOAD to value 0"]
impl crate::Resettable for LoadSpec {
    const RESET_VALUE: u32 = 0;
}
