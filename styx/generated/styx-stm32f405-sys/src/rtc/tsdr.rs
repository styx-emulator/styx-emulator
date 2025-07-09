// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `TSDR` reader"]
pub type R = crate::R<TsdrSpec>;
#[doc = "Register `TSDR` writer"]
pub type W = crate::W<TsdrSpec>;
#[doc = "Field `DU` reader - Date units in BCD format"]
pub type DuR = crate::FieldReader;
#[doc = "Field `DU` writer - Date units in BCD format"]
pub type DuW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `DT` reader - Date tens in BCD format"]
pub type DtR = crate::FieldReader;
#[doc = "Field `DT` writer - Date tens in BCD format"]
pub type DtW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `MU` reader - Month units in BCD format"]
pub type MuR = crate::FieldReader;
#[doc = "Field `MU` writer - Month units in BCD format"]
pub type MuW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `MT` reader - Month tens in BCD format"]
pub type MtR = crate::BitReader;
#[doc = "Field `MT` writer - Month tens in BCD format"]
pub type MtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WDU` reader - Week day units"]
pub type WduR = crate::FieldReader;
#[doc = "Field `WDU` writer - Week day units"]
pub type WduW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:3 - Date units in BCD format"]
    #[inline(always)]
    pub fn du(&self) -> DuR {
        DuR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:5 - Date tens in BCD format"]
    #[inline(always)]
    pub fn dt(&self) -> DtR {
        DtR::new(((self.bits >> 4) & 3) as u8)
    }
    #[doc = "Bits 8:11 - Month units in BCD format"]
    #[inline(always)]
    pub fn mu(&self) -> MuR {
        MuR::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bit 12 - Month tens in BCD format"]
    #[inline(always)]
    pub fn mt(&self) -> MtR {
        MtR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bits 13:15 - Week day units"]
    #[inline(always)]
    pub fn wdu(&self) -> WduR {
        WduR::new(((self.bits >> 13) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Date units in BCD format"]
    #[inline(always)]
    #[must_use]
    pub fn du(&mut self) -> DuW<TsdrSpec> {
        DuW::new(self, 0)
    }
    #[doc = "Bits 4:5 - Date tens in BCD format"]
    #[inline(always)]
    #[must_use]
    pub fn dt(&mut self) -> DtW<TsdrSpec> {
        DtW::new(self, 4)
    }
    #[doc = "Bits 8:11 - Month units in BCD format"]
    #[inline(always)]
    #[must_use]
    pub fn mu(&mut self) -> MuW<TsdrSpec> {
        MuW::new(self, 8)
    }
    #[doc = "Bit 12 - Month tens in BCD format"]
    #[inline(always)]
    #[must_use]
    pub fn mt(&mut self) -> MtW<TsdrSpec> {
        MtW::new(self, 12)
    }
    #[doc = "Bits 13:15 - Week day units"]
    #[inline(always)]
    #[must_use]
    pub fn wdu(&mut self) -> WduW<TsdrSpec> {
        WduW::new(self, 13)
    }
}
#[doc = "time stamp date register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tsdr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TsdrSpec;
impl crate::RegisterSpec for TsdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`tsdr::R`](R) reader structure"]
impl crate::Readable for TsdrSpec {}
#[doc = "`reset()` method sets TSDR to value 0"]
impl crate::Resettable for TsdrSpec {
    const RESET_VALUE: u32 = 0;
}
