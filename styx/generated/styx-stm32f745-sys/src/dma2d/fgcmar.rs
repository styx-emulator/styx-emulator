// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FGCMAR` reader"]
pub type R = crate::R<FgcmarSpec>;
#[doc = "Register `FGCMAR` writer"]
pub type W = crate::W<FgcmarSpec>;
#[doc = "Field `MA` reader - Memory Address"]
pub type MaR = crate::FieldReader<u32>;
#[doc = "Field `MA` writer - Memory Address"]
pub type MaW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Memory Address"]
    #[inline(always)]
    pub fn ma(&self) -> MaR {
        MaR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Memory Address"]
    #[inline(always)]
    #[must_use]
    pub fn ma(&mut self) -> MaW<FgcmarSpec> {
        MaW::new(self, 0)
    }
}
#[doc = "foreground CLUT memory address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgcmar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgcmar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FgcmarSpec;
impl crate::RegisterSpec for FgcmarSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`fgcmar::R`](R) reader structure"]
impl crate::Readable for FgcmarSpec {}
#[doc = "`write(|w| ..)` method takes [`fgcmar::W`](W) writer structure"]
impl crate::Writable for FgcmarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FGCMAR to value 0"]
impl crate::Resettable for FgcmarSpec {
    const RESET_VALUE: u32 = 0;
}
