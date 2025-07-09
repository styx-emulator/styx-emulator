// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `srampart` reader"]
pub type R = crate::R<SrampartSpec>;
#[doc = "Register `srampart` writer"]
pub type W = crate::W<SrampartSpec>;
#[doc = "Field `addr` reader - Defines the size of the indirect read partition in the SRAM, in units of SRAM locations. By default, half of the SRAM is reserved for indirect read operations and half for indirect write operations."]
pub type AddrR = crate::FieldReader;
#[doc = "Field `addr` writer - Defines the size of the indirect read partition in the SRAM, in units of SRAM locations. By default, half of the SRAM is reserved for indirect read operations and half for indirect write operations."]
pub type AddrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bits 0:6 - Defines the size of the indirect read partition in the SRAM, in units of SRAM locations. By default, half of the SRAM is reserved for indirect read operations and half for indirect write operations."]
    #[inline(always)]
    pub fn addr(&self) -> AddrR {
        AddrR::new((self.bits & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:6 - Defines the size of the indirect read partition in the SRAM, in units of SRAM locations. By default, half of the SRAM is reserved for indirect read operations and half for indirect write operations."]
    #[inline(always)]
    #[must_use]
    pub fn addr(&mut self) -> AddrW<SrampartSpec> {
        AddrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`srampart::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`srampart::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrampartSpec;
impl crate::RegisterSpec for SrampartSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`srampart::R`](R) reader structure"]
impl crate::Readable for SrampartSpec {}
#[doc = "`write(|w| ..)` method takes [`srampart::W`](W) writer structure"]
impl crate::Writable for SrampartSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets srampart to value 0x40"]
impl crate::Resettable for SrampartSpec {
    const RESET_VALUE: u32 = 0x40;
}
