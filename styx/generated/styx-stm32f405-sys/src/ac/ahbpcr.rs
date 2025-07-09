// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AHBPCR` reader"]
pub type R = crate::R<AhbpcrSpec>;
#[doc = "Register `AHBPCR` writer"]
pub type W = crate::W<AhbpcrSpec>;
#[doc = "Field `EN` reader - EN"]
pub type EnR = crate::BitReader;
#[doc = "Field `EN` writer - EN"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SZ` reader - SZ"]
pub type SzR = crate::FieldReader;
#[doc = "Field `SZ` writer - SZ"]
pub type SzW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bit 0 - EN"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:3 - SZ"]
    #[inline(always)]
    pub fn sz(&self) -> SzR {
        SzR::new(((self.bits >> 1) & 7) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - EN"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<AhbpcrSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bits 1:3 - SZ"]
    #[inline(always)]
    #[must_use]
    pub fn sz(&mut self) -> SzW<AhbpcrSpec> {
        SzW::new(self, 1)
    }
}
#[doc = "AHBP Control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ahbpcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ahbpcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AhbpcrSpec;
impl crate::RegisterSpec for AhbpcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`ahbpcr::R`](R) reader structure"]
impl crate::Readable for AhbpcrSpec {}
#[doc = "`write(|w| ..)` method takes [`ahbpcr::W`](W) writer structure"]
impl crate::Writable for AhbpcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AHBPCR to value 0"]
impl crate::Resettable for AhbpcrSpec {
    const RESET_VALUE: u32 = 0;
}
