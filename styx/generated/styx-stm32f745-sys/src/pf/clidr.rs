// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CLIDR` reader"]
pub type R = crate::R<ClidrSpec>;
#[doc = "Register `CLIDR` writer"]
pub type W = crate::W<ClidrSpec>;
#[doc = "Field `CL1` reader - CL1"]
pub type Cl1R = crate::FieldReader;
#[doc = "Field `CL1` writer - CL1"]
pub type Cl1W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CL2` reader - CL2"]
pub type Cl2R = crate::FieldReader;
#[doc = "Field `CL2` writer - CL2"]
pub type Cl2W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CL3` reader - CL3"]
pub type Cl3R = crate::FieldReader;
#[doc = "Field `CL3` writer - CL3"]
pub type Cl3W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CL4` reader - CL4"]
pub type Cl4R = crate::FieldReader;
#[doc = "Field `CL4` writer - CL4"]
pub type Cl4W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CL5` reader - CL5"]
pub type Cl5R = crate::FieldReader;
#[doc = "Field `CL5` writer - CL5"]
pub type Cl5W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CL6` reader - CL6"]
pub type Cl6R = crate::FieldReader;
#[doc = "Field `CL6` writer - CL6"]
pub type Cl6W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CL7` reader - CL7"]
pub type Cl7R = crate::FieldReader;
#[doc = "Field `CL7` writer - CL7"]
pub type Cl7W<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `LoUIS` reader - LoUIS"]
pub type LoUisR = crate::FieldReader;
#[doc = "Field `LoUIS` writer - LoUIS"]
pub type LoUisW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `LoC` reader - LoC"]
pub type LoCR = crate::FieldReader;
#[doc = "Field `LoC` writer - LoC"]
pub type LoCW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `LoU` reader - LoU"]
pub type LoUR = crate::FieldReader;
#[doc = "Field `LoU` writer - LoU"]
pub type LoUW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:2 - CL1"]
    #[inline(always)]
    pub fn cl1(&self) -> Cl1R {
        Cl1R::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 3:5 - CL2"]
    #[inline(always)]
    pub fn cl2(&self) -> Cl2R {
        Cl2R::new(((self.bits >> 3) & 7) as u8)
    }
    #[doc = "Bits 6:8 - CL3"]
    #[inline(always)]
    pub fn cl3(&self) -> Cl3R {
        Cl3R::new(((self.bits >> 6) & 7) as u8)
    }
    #[doc = "Bits 9:11 - CL4"]
    #[inline(always)]
    pub fn cl4(&self) -> Cl4R {
        Cl4R::new(((self.bits >> 9) & 7) as u8)
    }
    #[doc = "Bits 12:14 - CL5"]
    #[inline(always)]
    pub fn cl5(&self) -> Cl5R {
        Cl5R::new(((self.bits >> 12) & 7) as u8)
    }
    #[doc = "Bits 15:17 - CL6"]
    #[inline(always)]
    pub fn cl6(&self) -> Cl6R {
        Cl6R::new(((self.bits >> 15) & 7) as u8)
    }
    #[doc = "Bits 18:20 - CL7"]
    #[inline(always)]
    pub fn cl7(&self) -> Cl7R {
        Cl7R::new(((self.bits >> 18) & 7) as u8)
    }
    #[doc = "Bits 21:23 - LoUIS"]
    #[inline(always)]
    pub fn lo_uis(&self) -> LoUisR {
        LoUisR::new(((self.bits >> 21) & 7) as u8)
    }
    #[doc = "Bits 24:26 - LoC"]
    #[inline(always)]
    pub fn lo_c(&self) -> LoCR {
        LoCR::new(((self.bits >> 24) & 7) as u8)
    }
    #[doc = "Bits 27:29 - LoU"]
    #[inline(always)]
    pub fn lo_u(&self) -> LoUR {
        LoUR::new(((self.bits >> 27) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - CL1"]
    #[inline(always)]
    #[must_use]
    pub fn cl1(&mut self) -> Cl1W<ClidrSpec> {
        Cl1W::new(self, 0)
    }
    #[doc = "Bits 3:5 - CL2"]
    #[inline(always)]
    #[must_use]
    pub fn cl2(&mut self) -> Cl2W<ClidrSpec> {
        Cl2W::new(self, 3)
    }
    #[doc = "Bits 6:8 - CL3"]
    #[inline(always)]
    #[must_use]
    pub fn cl3(&mut self) -> Cl3W<ClidrSpec> {
        Cl3W::new(self, 6)
    }
    #[doc = "Bits 9:11 - CL4"]
    #[inline(always)]
    #[must_use]
    pub fn cl4(&mut self) -> Cl4W<ClidrSpec> {
        Cl4W::new(self, 9)
    }
    #[doc = "Bits 12:14 - CL5"]
    #[inline(always)]
    #[must_use]
    pub fn cl5(&mut self) -> Cl5W<ClidrSpec> {
        Cl5W::new(self, 12)
    }
    #[doc = "Bits 15:17 - CL6"]
    #[inline(always)]
    #[must_use]
    pub fn cl6(&mut self) -> Cl6W<ClidrSpec> {
        Cl6W::new(self, 15)
    }
    #[doc = "Bits 18:20 - CL7"]
    #[inline(always)]
    #[must_use]
    pub fn cl7(&mut self) -> Cl7W<ClidrSpec> {
        Cl7W::new(self, 18)
    }
    #[doc = "Bits 21:23 - LoUIS"]
    #[inline(always)]
    #[must_use]
    pub fn lo_uis(&mut self) -> LoUisW<ClidrSpec> {
        LoUisW::new(self, 21)
    }
    #[doc = "Bits 24:26 - LoC"]
    #[inline(always)]
    #[must_use]
    pub fn lo_c(&mut self) -> LoCW<ClidrSpec> {
        LoCW::new(self, 24)
    }
    #[doc = "Bits 27:29 - LoU"]
    #[inline(always)]
    #[must_use]
    pub fn lo_u(&mut self) -> LoUW<ClidrSpec> {
        LoUW::new(self, 27)
    }
}
#[doc = "Cache Level ID register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clidr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ClidrSpec;
impl crate::RegisterSpec for ClidrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`clidr::R`](R) reader structure"]
impl crate::Readable for ClidrSpec {}
#[doc = "`reset()` method sets CLIDR to value 0x0900_0003"]
impl crate::Resettable for ClidrSpec {
    const RESET_VALUE: u32 = 0x0900_0003;
}
