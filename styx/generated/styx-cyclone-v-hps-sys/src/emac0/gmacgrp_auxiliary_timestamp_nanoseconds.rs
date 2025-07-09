// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_Auxiliary_Timestamp_Nanoseconds` reader"]
pub type R = crate::R<GmacgrpAuxiliaryTimestampNanosecondsSpec>;
#[doc = "Register `gmacgrp_Auxiliary_Timestamp_Nanoseconds` writer"]
pub type W = crate::W<GmacgrpAuxiliaryTimestampNanosecondsSpec>;
#[doc = "Field `auxtslo` reader - Contains the lower 32 bits (nano-seconds field) of the auxiliary timestamp."]
pub type AuxtsloR = crate::FieldReader<u32>;
#[doc = "Field `auxtslo` writer - Contains the lower 32 bits (nano-seconds field) of the auxiliary timestamp."]
pub type AuxtsloW<'a, REG> = crate::FieldWriter<'a, REG, 31, u32>;
impl R {
    #[doc = "Bits 0:30 - Contains the lower 32 bits (nano-seconds field) of the auxiliary timestamp."]
    #[inline(always)]
    pub fn auxtslo(&self) -> AuxtsloR {
        AuxtsloR::new(self.bits & 0x7fff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:30 - Contains the lower 32 bits (nano-seconds field) of the auxiliary timestamp."]
    #[inline(always)]
    #[must_use]
    pub fn auxtslo(&mut self) -> AuxtsloW<GmacgrpAuxiliaryTimestampNanosecondsSpec> {
        AuxtsloW::new(self, 0)
    }
}
#[doc = "This register, along with Register 461 (Auxiliary Timestamp Seconds Register), gives the 64-bit timestamp stored as auxiliary snapshot. The two registers together form the read port of a 64-bit wide FIFO with a depth of 16. Multiple snapshots can be stored in this FIFO. The ATSNS bits in the Timestamp Status register indicate the fill-level of this FIFO. The top of the FIFO is removed only when the last byte of Register 461 (Auxiliary Timestamp - Seconds Register) is read. In the little-endian mode, this means when Bits\\[31:24\\]
are read. In big-endian mode, it corresponds to the reading of Bits\\[7:0\\]
of Register 461 (Auxiliary Timestamp - Seconds Register).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_auxiliary_timestamp_nanoseconds::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpAuxiliaryTimestampNanosecondsSpec;
impl crate::RegisterSpec for GmacgrpAuxiliaryTimestampNanosecondsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1840u64;
}
#[doc = "`read()` method returns [`gmacgrp_auxiliary_timestamp_nanoseconds::R`](R) reader structure"]
impl crate::Readable for GmacgrpAuxiliaryTimestampNanosecondsSpec {}
#[doc = "`reset()` method sets gmacgrp_Auxiliary_Timestamp_Nanoseconds to value 0"]
impl crate::Resettable for GmacgrpAuxiliaryTimestampNanosecondsSpec {
    const RESET_VALUE: u32 = 0;
}
