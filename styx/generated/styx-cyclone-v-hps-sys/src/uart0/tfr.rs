// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `tfr` reader"]
pub type R = crate::R<TfrSpec>;
#[doc = "Register `tfr` writer"]
pub type W = crate::W<TfrSpec>;
#[doc = "Field `tfr` reader - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, reading this register gives the data at the top of the transmit FIFO. Each consecutive read pops the transmit FIFO and gives the next data value that is currently at the top of the FIFO. When FIFO's are not enabled, reading this register gives the data in the THR."]
pub type TfrR = crate::FieldReader;
#[doc = "Field `tfr` writer - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, reading this register gives the data at the top of the transmit FIFO. Each consecutive read pops the transmit FIFO and gives the next data value that is currently at the top of the FIFO. When FIFO's are not enabled, reading this register gives the data in the THR."]
pub type TfrW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, reading this register gives the data at the top of the transmit FIFO. Each consecutive read pops the transmit FIFO and gives the next data value that is currently at the top of the FIFO. When FIFO's are not enabled, reading this register gives the data in the THR."]
    #[inline(always)]
    pub fn tfr(&self) -> TfrR {
        TfrR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, reading this register gives the data at the top of the transmit FIFO. Each consecutive read pops the transmit FIFO and gives the next data value that is currently at the top of the FIFO. When FIFO's are not enabled, reading this register gives the data in the THR."]
    #[inline(always)]
    #[must_use]
    pub fn tfr(&mut self) -> TfrW<TfrSpec> {
        TfrW::new(self, 0)
    }
}
#[doc = "Used in FIFO Access test mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tfr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TfrSpec;
impl crate::RegisterSpec for TfrSpec {
    type Ux = u32;
    const OFFSET: u64 = 116u64;
}
#[doc = "`read()` method returns [`tfr::R`](R) reader structure"]
impl crate::Readable for TfrSpec {}
#[doc = "`reset()` method sets tfr to value 0"]
impl crate::Resettable for TfrSpec {
    const RESET_VALUE: u32 = 0;
}
