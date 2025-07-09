// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHB3RSTR` reader"]
pub type R = crate::R<Ahb3rstrSpec>;
#[doc = "Register `AHB3RSTR` writer"]
pub type W = crate::W<Ahb3rstrSpec>;
#[doc = "Field `FMCRST` reader - Flexible memory controller module reset"]
pub type FmcrstR = crate::BitReader;
#[doc = "Field `FMCRST` writer - Flexible memory controller module reset"]
pub type FmcrstW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Flexible memory controller module reset"]
    #[inline(always)]
    pub fn fmcrst(&self) -> FmcrstR {
        FmcrstR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Flexible memory controller module reset"]
    #[inline(always)]
    #[must_use]
    pub fn fmcrst(&mut self) -> FmcrstW<Ahb3rstrSpec> {
        FmcrstW::new(self, 0)
    }
}
#[doc = "AHB3 peripheral reset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahb3rstr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahb3rstr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ahb3rstrSpec;
impl crate::RegisterSpec for Ahb3rstrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`ahb3rstr::R`](R) reader structure"]
impl crate::Readable for Ahb3rstrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahb3rstr::W`](W) writer structure"]
impl crate::Writable for Ahb3rstrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHB3RSTR to value 0"]
impl crate::Resettable for Ahb3rstrSpec {
    const RESET_VALUE: u32 = 0;
}
