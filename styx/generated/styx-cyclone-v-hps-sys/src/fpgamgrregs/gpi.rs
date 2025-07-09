// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpi` reader"]
pub type R = crate::R<GpiSpec>;
#[doc = "Register `gpi` writer"]
pub type W = crate::W<GpiSpec>;
#[doc = "Field `value` reader - The value being driven from the FPGA fabric on f2h_gp\\[31:0\\]. If the FPGA is not in User Mode, the value of this field is undefined."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - The value being driven from the FPGA fabric on f2h_gp\\[31:0\\]. If the FPGA is not in User Mode, the value of this field is undefined."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - The value being driven from the FPGA fabric on f2h_gp\\[31:0\\]. If the FPGA is not in User Mode, the value of this field is undefined."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - The value being driven from the FPGA fabric on f2h_gp\\[31:0\\]. If the FPGA is not in User Mode, the value of this field is undefined."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<GpiSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Provides a low-latency, low-performance, and simple way to read general-purpose signals driven from the FPGA fabric.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpi::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpiSpec;
impl crate::RegisterSpec for GpiSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`gpi::R`](R) reader structure"]
impl crate::Readable for GpiSpec {}
