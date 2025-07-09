// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `uppwrprot` reader"]
pub type R = crate::R<UppwrprotSpec>;
#[doc = "Register `uppwrprot` writer"]
pub type W = crate::W<UppwrprotSpec>;
#[doc = "Field `subsector` reader - The block number that defines the upper block in the range of blocks that is to be locked from writing. The definition of a block in terms of number of bytes is programmable via the Device Size Configuration register."]
pub type SubsectorR = crate::FieldReader<u32>;
#[doc = "Field `subsector` writer - The block number that defines the upper block in the range of blocks that is to be locked from writing. The definition of a block in terms of number of bytes is programmable via the Device Size Configuration register."]
pub type SubsectorW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - The block number that defines the upper block in the range of blocks that is to be locked from writing. The definition of a block in terms of number of bytes is programmable via the Device Size Configuration register."]
    #[inline(always)]
    pub fn subsector(&self) -> SubsectorR {
        SubsectorR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - The block number that defines the upper block in the range of blocks that is to be locked from writing. The definition of a block in terms of number of bytes is programmable via the Device Size Configuration register."]
    #[inline(always)]
    #[must_use]
    pub fn subsector(&mut self) -> SubsectorW<UppwrprotSpec> {
        SubsectorW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`uppwrprot::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`uppwrprot::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct UppwrprotSpec;
impl crate::RegisterSpec for UppwrprotSpec {
    type Ux = u32;
    const OFFSET: u64 = 84u64;
}
#[doc = "`read()` method returns [`uppwrprot::R`](R) reader structure"]
impl crate::Readable for UppwrprotSpec {}
#[doc = "`write(|w| ..)` method takes [`uppwrprot::W`](W) writer structure"]
impl crate::Writable for UppwrprotSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets uppwrprot to value 0"]
impl crate::Resettable for UppwrprotSpec {
    const RESET_VALUE: u32 = 0;
}
