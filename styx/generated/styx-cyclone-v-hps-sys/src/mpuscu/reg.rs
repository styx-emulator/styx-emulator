// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `reg` reader"]
pub type R = crate::R<RegSpec>;
#[doc = "Register `reg` writer"]
pub type W = crate::W<RegSpec>;
#[doc = "Field `fld` reader - Placeholder"]
pub type FldR = crate::FieldReader<u32>;
#[doc = "Field `fld` writer - Placeholder"]
pub type FldW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Placeholder"]
    #[inline(always)]
    pub fn fld(&self) -> FldR {
        FldR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Placeholder"]
    #[inline(always)]
    #[must_use]
    pub fn fld(&mut self) -> FldW<RegSpec> {
        FldW::new(self, 0)
    }
}
#[doc = "Placeholder\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`reg::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`reg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RegSpec;
impl crate::RegisterSpec for RegSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`reg::R`](R) reader structure"]
impl crate::Readable for RegSpec {}
#[doc = "`write(|w| ..)` method takes [`reg::W`](W) writer structure"]
impl crate::Writable for RegSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
