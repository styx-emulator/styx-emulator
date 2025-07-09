// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `lowwrprot` reader"]
pub type R = crate::R<LowwrprotSpec>;
#[doc = "Register `lowwrprot` writer"]
pub type W = crate::W<LowwrprotSpec>;
#[doc = "Field `subsector` reader - The block number that defines the lower block in the range of blocks that is to be locked from writing. The definition of a block in terms of number of bytes is programmable via the Device Size Configuration register."]
pub type SubsectorR = crate::FieldReader<u32>;
#[doc = "Field `subsector` writer - The block number that defines the lower block in the range of blocks that is to be locked from writing. The definition of a block in terms of number of bytes is programmable via the Device Size Configuration register."]
pub type SubsectorW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - The block number that defines the lower block in the range of blocks that is to be locked from writing. The definition of a block in terms of number of bytes is programmable via the Device Size Configuration register."]
    #[inline(always)]
    pub fn subsector(&self) -> SubsectorR {
        SubsectorR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - The block number that defines the lower block in the range of blocks that is to be locked from writing. The definition of a block in terms of number of bytes is programmable via the Device Size Configuration register."]
    #[inline(always)]
    #[must_use]
    pub fn subsector(&mut self) -> SubsectorW<LowwrprotSpec> {
        SubsectorW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`lowwrprot::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`lowwrprot::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct LowwrprotSpec;
impl crate::RegisterSpec for LowwrprotSpec {
    type Ux = u32;
    const OFFSET: u64 = 80u64;
}
#[doc = "`read()` method returns [`lowwrprot::R`](R) reader structure"]
impl crate::Readable for LowwrprotSpec {}
#[doc = "`write(|w| ..)` method takes [`lowwrprot::W`](W) writer structure"]
impl crate::Writable for LowwrprotSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets lowwrprot to value 0"]
impl crate::Resettable for LowwrprotSpec {
    const RESET_VALUE: u32 = 0;
}
