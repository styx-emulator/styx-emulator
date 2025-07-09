// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PLLI2SCFGR` reader"]
pub type R = crate::R<Plli2scfgrSpec>;
#[doc = "Register `PLLI2SCFGR` writer"]
pub type W = crate::W<Plli2scfgrSpec>;
#[doc = "Field `PLLI2SNx` reader - PLLI2S multiplication factor for VCO"]
pub type Plli2snxR = crate::FieldReader<u16>;
#[doc = "Field `PLLI2SNx` writer - PLLI2S multiplication factor for VCO"]
pub type Plli2snxW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "Field `PLLI2SRx` reader - PLLI2S division factor for I2S clocks"]
pub type Plli2srxR = crate::FieldReader;
#[doc = "Field `PLLI2SRx` writer - PLLI2S division factor for I2S clocks"]
pub type Plli2srxW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 6:14 - PLLI2S multiplication factor for VCO"]
    #[inline(always)]
    pub fn plli2snx(&self) -> Plli2snxR {
        Plli2snxR::new(((self.bits >> 6) & 0x01ff) as u16)
    }
    #[doc = "Bits 28:30 - PLLI2S division factor for I2S clocks"]
    #[inline(always)]
    pub fn plli2srx(&self) -> Plli2srxR {
        Plli2srxR::new(((self.bits >> 28) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 6:14 - PLLI2S multiplication factor for VCO"]
    #[inline(always)]
    #[must_use]
    pub fn plli2snx(&mut self) -> Plli2snxW<Plli2scfgrSpec> {
        Plli2snxW::new(self, 6)
    }
    #[doc = "Bits 28:30 - PLLI2S division factor for I2S clocks"]
    #[inline(always)]
    #[must_use]
    pub fn plli2srx(&mut self) -> Plli2srxW<Plli2scfgrSpec> {
        Plli2srxW::new(self, 28)
    }
}
#[doc = "PLLI2S configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`plli2scfgr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`plli2scfgr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Plli2scfgrSpec;
impl crate::RegisterSpec for Plli2scfgrSpec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`read()` method returns [`plli2scfgr::R`](R) reader structure"]
impl crate::Readable for Plli2scfgrSpec {}
#[doc = "`write(|w| ..)` method takes [`plli2scfgr::W`](W) writer structure"]
impl crate::Writable for Plli2scfgrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PLLI2SCFGR to value 0x2000_3000"]
impl crate::Resettable for Plli2scfgrSpec {
    const RESET_VALUE: u32 = 0x2000_3000;
}
