// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `protogrp_CRR` reader"]
pub type R = crate::R<ProtogrpCrrSpec>;
#[doc = "Register `protogrp_CRR` writer"]
pub type W = crate::W<ProtogrpCrrSpec>;
#[doc = "Field `DAY` reader - "]
pub type DayR = crate::FieldReader;
#[doc = "Field `DAY` writer - "]
pub type DayW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `MON` reader - "]
pub type MonR = crate::FieldReader;
#[doc = "Field `MON` writer - "]
pub type MonW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `YEAR` reader - "]
pub type YearR = crate::FieldReader;
#[doc = "Field `YEAR` writer - "]
pub type YearW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `STEP` reader - "]
pub type StepR = crate::FieldReader;
#[doc = "Field `STEP` writer - "]
pub type StepW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `REL` reader - "]
pub type RelR = crate::FieldReader;
#[doc = "Field `REL` writer - "]
pub type RelW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:7"]
    #[inline(always)]
    pub fn day(&self) -> DayR {
        DayR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15"]
    #[inline(always)]
    pub fn mon(&self) -> MonR {
        MonR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:19"]
    #[inline(always)]
    pub fn year(&self) -> YearR {
        YearR::new(((self.bits >> 16) & 0x0f) as u8)
    }
    #[doc = "Bits 20:27"]
    #[inline(always)]
    pub fn step(&self) -> StepR {
        StepR::new(((self.bits >> 20) & 0xff) as u8)
    }
    #[doc = "Bits 28:31"]
    #[inline(always)]
    pub fn rel(&self) -> RelR {
        RelR::new(((self.bits >> 28) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7"]
    #[inline(always)]
    #[must_use]
    pub fn day(&mut self) -> DayW<ProtogrpCrrSpec> {
        DayW::new(self, 0)
    }
    #[doc = "Bits 8:15"]
    #[inline(always)]
    #[must_use]
    pub fn mon(&mut self) -> MonW<ProtogrpCrrSpec> {
        MonW::new(self, 8)
    }
    #[doc = "Bits 16:19"]
    #[inline(always)]
    #[must_use]
    pub fn year(&mut self) -> YearW<ProtogrpCrrSpec> {
        YearW::new(self, 16)
    }
    #[doc = "Bits 20:27"]
    #[inline(always)]
    #[must_use]
    pub fn step(&mut self) -> StepW<ProtogrpCrrSpec> {
        StepW::new(self, 20)
    }
    #[doc = "Bits 28:31"]
    #[inline(always)]
    #[must_use]
    pub fn rel(&mut self) -> RelW<ProtogrpCrrSpec> {
        RelW::new(self, 28)
    }
}
#[doc = "Core Release Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_crr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpCrrSpec;
impl crate::RegisterSpec for ProtogrpCrrSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`protogrp_crr::R`](R) reader structure"]
impl crate::Readable for ProtogrpCrrSpec {}
#[doc = "`reset()` method sets protogrp_CRR to value 0x1116_1128"]
impl crate::Resettable for ProtogrpCrrSpec {
    const RESET_VALUE: u32 = 0x1116_1128;
}
