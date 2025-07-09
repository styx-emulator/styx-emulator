// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SDCR2` reader"]
pub type R = crate::R<Sdcr2Spec>;
#[doc = "Register `SDCR2` writer"]
pub type W = crate::W<Sdcr2Spec>;
#[doc = "Field `NC` reader - Number of column address bits"]
pub type NcR = crate::FieldReader;
#[doc = "Field `NC` writer - Number of column address bits"]
pub type NcW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `NR` reader - Number of row address bits"]
pub type NrR = crate::FieldReader;
#[doc = "Field `NR` writer - Number of row address bits"]
pub type NrW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MWID` reader - Memory data bus width"]
pub type MwidR = crate::FieldReader;
#[doc = "Field `MWID` writer - Memory data bus width"]
pub type MwidW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `NB` reader - Number of internal banks"]
pub type NbR = crate::BitReader;
#[doc = "Field `NB` writer - Number of internal banks"]
pub type NbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAS` reader - CAS latency"]
pub type CasR = crate::FieldReader;
#[doc = "Field `CAS` writer - CAS latency"]
pub type CasW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `WP` reader - Write protection"]
pub type WpR = crate::BitReader;
#[doc = "Field `WP` writer - Write protection"]
pub type WpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SDCLK` reader - SDRAM clock configuration"]
pub type SdclkR = crate::FieldReader;
#[doc = "Field `SDCLK` writer - SDRAM clock configuration"]
pub type SdclkW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `RBURST` reader - Burst read"]
pub type RburstR = crate::BitReader;
#[doc = "Field `RBURST` writer - Burst read"]
pub type RburstW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RPIPE` reader - Read pipe"]
pub type RpipeR = crate::FieldReader;
#[doc = "Field `RPIPE` writer - Read pipe"]
pub type RpipeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Number of column address bits"]
    #[inline(always)]
    pub fn nc(&self) -> NcR {
        NcR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - Number of row address bits"]
    #[inline(always)]
    pub fn nr(&self) -> NrR {
        NrR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:5 - Memory data bus width"]
    #[inline(always)]
    pub fn mwid(&self) -> MwidR {
        MwidR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bit 6 - Number of internal banks"]
    #[inline(always)]
    pub fn nb(&self) -> NbR {
        NbR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bits 7:8 - CAS latency"]
    #[inline(always)]
    pub fn cas(&self) -> CasR {
        CasR::new(((self.bits >> 7) & 3) as u8)
    }
    #[doc = "Bit 9 - Write protection"]
    #[inline(always)]
    pub fn wp(&self) -> WpR {
        WpR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bits 10:11 - SDRAM clock configuration"]
    #[inline(always)]
    pub fn sdclk(&self) -> SdclkR {
        SdclkR::new(((self.bits >> 10) & 3) as u8)
    }
    #[doc = "Bit 12 - Burst read"]
    #[inline(always)]
    pub fn rburst(&self) -> RburstR {
        RburstR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bits 13:14 - Read pipe"]
    #[inline(always)]
    pub fn rpipe(&self) -> RpipeR {
        RpipeR::new(((self.bits >> 13) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Number of column address bits"]
    #[inline(always)]
    #[must_use]
    pub fn nc(&mut self) -> NcW<Sdcr2Spec> {
        NcW::new(self, 0)
    }
    #[doc = "Bits 2:3 - Number of row address bits"]
    #[inline(always)]
    #[must_use]
    pub fn nr(&mut self) -> NrW<Sdcr2Spec> {
        NrW::new(self, 2)
    }
    #[doc = "Bits 4:5 - Memory data bus width"]
    #[inline(always)]
    #[must_use]
    pub fn mwid(&mut self) -> MwidW<Sdcr2Spec> {
        MwidW::new(self, 4)
    }
    #[doc = "Bit 6 - Number of internal banks"]
    #[inline(always)]
    #[must_use]
    pub fn nb(&mut self) -> NbW<Sdcr2Spec> {
        NbW::new(self, 6)
    }
    #[doc = "Bits 7:8 - CAS latency"]
    #[inline(always)]
    #[must_use]
    pub fn cas(&mut self) -> CasW<Sdcr2Spec> {
        CasW::new(self, 7)
    }
    #[doc = "Bit 9 - Write protection"]
    #[inline(always)]
    #[must_use]
    pub fn wp(&mut self) -> WpW<Sdcr2Spec> {
        WpW::new(self, 9)
    }
    #[doc = "Bits 10:11 - SDRAM clock configuration"]
    #[inline(always)]
    #[must_use]
    pub fn sdclk(&mut self) -> SdclkW<Sdcr2Spec> {
        SdclkW::new(self, 10)
    }
    #[doc = "Bit 12 - Burst read"]
    #[inline(always)]
    #[must_use]
    pub fn rburst(&mut self) -> RburstW<Sdcr2Spec> {
        RburstW::new(self, 12)
    }
    #[doc = "Bits 13:14 - Read pipe"]
    #[inline(always)]
    #[must_use]
    pub fn rpipe(&mut self) -> RpipeW<Sdcr2Spec> {
        RpipeW::new(self, 13)
    }
}
#[doc = "SDRAM Control Register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdcr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdcr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Sdcr2Spec;
impl crate::RegisterSpec for Sdcr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 324u64;
}
#[doc = "`read()` method returns [`sdcr2::R`](R) reader structure"]
impl crate::Readable for Sdcr2Spec {}
#[doc = "`write(|w| ..)` method takes [`sdcr2::W`](W) writer structure"]
impl crate::Writable for Sdcr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SDCR2 to value 0x02d0"]
impl crate::Resettable for Sdcr2Spec {
    const RESET_VALUE: u32 = 0x02d0;
}
