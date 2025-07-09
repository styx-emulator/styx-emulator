// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FGMAR` reader"]
pub type R = crate::R<FgmarSpec>;
#[doc = "Register `FGMAR` writer"]
pub type W = crate::W<FgmarSpec>;
#[doc = "Field `MA` reader - Memory address"]
pub type MaR = crate::FieldReader<u32>;
#[doc = "Field `MA` writer - Memory address"]
pub type MaW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Memory address"]
    #[inline(always)]
    pub fn ma(&self) -> MaR {
        MaR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Memory address"]
    #[inline(always)]
    #[must_use]
    pub fn ma(&mut self) -> MaW<FgmarSpec> {
        MaW::new(self, 0)
    }
}
#[doc = "foreground memory address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgmar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgmar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FgmarSpec;
impl crate::RegisterSpec for FgmarSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`fgmar::R`](R) reader structure"]
impl crate::Readable for FgmarSpec {}
#[doc = "`write(|w| ..)` method takes [`fgmar::W`](W) writer structure"]
impl crate::Writable for FgmarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FGMAR to value 0"]
impl crate::Resettable for FgmarSpec {
    const RESET_VALUE: u32 = 0;
}
