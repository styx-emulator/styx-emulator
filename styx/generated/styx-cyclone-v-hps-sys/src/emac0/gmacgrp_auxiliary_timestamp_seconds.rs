// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Auxiliary_Timestamp_Seconds` reader"]
pub type R = crate::R<GmacgrpAuxiliaryTimestampSecondsSpec>;
#[doc = "Register `gmacgrp_Auxiliary_Timestamp_Seconds` writer"]
pub type W = crate::W<GmacgrpAuxiliaryTimestampSecondsSpec>;
#[doc = "Field `auxtshi` reader - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
pub type AuxtshiR = crate::FieldReader<u32>;
#[doc = "Field `auxtshi` writer - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
pub type AuxtshiW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
    #[inline(always)]
    pub fn auxtshi(&self) -> AuxtshiR {
        AuxtshiR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
    #[inline(always)]
    #[must_use]
    pub fn auxtshi(&mut self) -> AuxtshiW<GmacgrpAuxiliaryTimestampSecondsSpec> {
        AuxtshiW::new(self, 0)
    }
}
#[doc = "Contains the higher 32 bits (Seconds field) of the auxiliary timestamp.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_auxiliary_timestamp_seconds::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpAuxiliaryTimestampSecondsSpec;
impl crate::RegisterSpec for GmacgrpAuxiliaryTimestampSecondsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1844u64;
}
#[doc = "`read()` method returns [`gmacgrp_auxiliary_timestamp_seconds::R`](R) reader structure"]
impl crate::Readable for GmacgrpAuxiliaryTimestampSecondsSpec {}
#[doc = "`reset()` method sets gmacgrp_Auxiliary_Timestamp_Seconds to value 0"]
impl crate::Resettable for GmacgrpAuxiliaryTimestampSecondsSpec {
    const RESET_VALUE: u32 = 0;
}
