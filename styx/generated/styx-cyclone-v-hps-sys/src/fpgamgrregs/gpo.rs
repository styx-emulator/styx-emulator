// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpo` reader"]
pub type R = crate::R<GpoSpec>;
#[doc = "Register `gpo` writer"]
pub type W = crate::W<GpoSpec>;
#[doc = "Field `value` reader - Drives h2f_gp\\[31:0\\]
with specified value. When read, returns the current value being driven to the FPGA fabric."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - Drives h2f_gp\\[31:0\\]
with specified value. When read, returns the current value being driven to the FPGA fabric."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Drives h2f_gp\\[31:0\\]
with specified value. When read, returns the current value being driven to the FPGA fabric."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Drives h2f_gp\\[31:0\\]
with specified value. When read, returns the current value being driven to the FPGA fabric."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<GpoSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Provides a low-latency, low-performance, and simple way to drive general-purpose signals to the FPGA fabric.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpo::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpo::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpoSpec;
impl crate::RegisterSpec for GpoSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`gpo::R`](R) reader structure"]
impl crate::Readable for GpoSpec {}
#[doc = "`write(|w| ..)` method takes [`gpo::W`](W) writer structure"]
impl crate::Writable for GpoSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpo to value 0"]
impl crate::Resettable for GpoSpec {
    const RESET_VALUE: u32 = 0;
}
