// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FPCAR` reader"]
pub type R = crate::R<FpcarSpec>;
#[doc = "Register `FPCAR` writer"]
pub type W = crate::W<FpcarSpec>;
#[doc = "Field `ADDRESS` reader - Location of unpopulated floating-point"]
pub type AddressR = crate::FieldReader<u32>;
#[doc = "Field `ADDRESS` writer - Location of unpopulated floating-point"]
pub type AddressW<'a, REG> = crate::FieldWriter<'a, REG, 29, u32>;
impl R {
    #[doc = "Bits 3:31 - Location of unpopulated floating-point"]
    #[inline(always)]
    pub fn address(&self) -> AddressR {
        AddressR::new((self.bits >> 3) & 0x1fff_ffff)
    }
}
impl W {
    #[doc = "Bits 3:31 - Location of unpopulated floating-point"]
    #[inline(always)]
    #[must_use]
    pub fn address(&mut self) -> AddressW<FpcarSpec> {
        AddressW::new(self, 3)
    }
}
#[doc = "Floating-point context address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpcar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpcar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FpcarSpec;
impl crate::RegisterSpec for FpcarSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`fpcar::R`](R) reader structure"]
impl crate::Readable for FpcarSpec {}
#[doc = "`write(|w| ..)` method takes [`fpcar::W`](W) writer structure"]
impl crate::Writable for FpcarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FPCAR to value 0"]
impl crate::Resettable for FpcarSpec {
    const RESET_VALUE: u32 = 0;
}
