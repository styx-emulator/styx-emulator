// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `protogrp_CERC` reader"]
pub type R = crate::R<ProtogrpCercSpec>;
#[doc = "Register `protogrp_CERC` writer"]
pub type W = crate::W<ProtogrpCercSpec>;
#[doc = "Field `TEC` reader - Actual state of the Transmit Error Counter. Values between 0 and 255."]
pub type TecR = crate::FieldReader;
#[doc = "Field `TEC` writer - Actual state of the Transmit Error Counter. Values between 0 and 255."]
pub type TecW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `REC` reader - Actual state of the Receive Error Counter. Values between 0 and 127."]
pub type RecR = crate::FieldReader;
#[doc = "Field `REC` writer - Actual state of the Receive Error Counter. Values between 0 and 127."]
pub type RecW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rp {
    #[doc = "0: `0`"]
    Below = 0,
    #[doc = "1: `1`"]
    Reached = 1,
}
impl From<Rp> for bool {
    #[inline(always)]
    fn from(variant: Rp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `RP` reader - "]
pub type RpR = crate::BitReader<Rp>;
impl RpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rp {
        match self.bits {
            false => Rp::Below,
            true => Rp::Reached,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_below(&self) -> bool {
        *self == Rp::Below
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_reached(&self) -> bool {
        *self == Rp::Reached
    }
}
#[doc = "Field `RP` writer - "]
pub type RpW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - Actual state of the Transmit Error Counter. Values between 0 and 255."]
    #[inline(always)]
    pub fn tec(&self) -> TecR {
        TecR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:14 - Actual state of the Receive Error Counter. Values between 0 and 127."]
    #[inline(always)]
    pub fn rec(&self) -> RecR {
        RecR::new(((self.bits >> 8) & 0x7f) as u8)
    }
    #[doc = "Bit 15"]
    #[inline(always)]
    pub fn rp(&self) -> RpR {
        RpR::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - Actual state of the Transmit Error Counter. Values between 0 and 255."]
    #[inline(always)]
    #[must_use]
    pub fn tec(&mut self) -> TecW<ProtogrpCercSpec> {
        TecW::new(self, 0)
    }
    #[doc = "Bits 8:14 - Actual state of the Receive Error Counter. Values between 0 and 127."]
    #[inline(always)]
    #[must_use]
    pub fn rec(&mut self) -> RecW<ProtogrpCercSpec> {
        RecW::new(self, 8)
    }
    #[doc = "Bit 15"]
    #[inline(always)]
    #[must_use]
    pub fn rp(&mut self) -> RpW<ProtogrpCercSpec> {
        RpW::new(self, 15)
    }
}
#[doc = "Error Counter Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cerc::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpCercSpec;
impl crate::RegisterSpec for ProtogrpCercSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`protogrp_cerc::R`](R) reader structure"]
impl crate::Readable for ProtogrpCercSpec {}
#[doc = "`reset()` method sets protogrp_CERC to value 0"]
impl crate::Resettable for ProtogrpCercSpec {
    const RESET_VALUE: u32 = 0;
}
