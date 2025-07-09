// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `fifodoublebyte` reader"]
pub type R = crate::R<FifodoublebyteSpec>;
#[doc = "Register `fifodoublebyte` writer"]
pub type W = crate::W<FifodoublebyteSpec>;
#[doc = "Field `value` reader - Transfers double byte value to/from command FIFO"]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Transfers double byte value to/from command FIFO"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Transfers double byte value to/from command FIFO"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Transfers double byte value to/from command FIFO"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<FifodoublebyteSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Writes to the FIFO Double Byte Register write a double byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Double Byte FIFO Register read a double byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO2 for writes and BRFIFO2 for reads.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifodoublebyte::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifodoublebyte::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FifodoublebyteSpec;
impl crate::RegisterSpec for FifodoublebyteSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`fifodoublebyte::R`](R) reader structure"]
impl crate::Readable for FifodoublebyteSpec {}
#[doc = "`write(|w| ..)` method takes [`fifodoublebyte::W`](W) writer structure"]
impl crate::Writable for FifodoublebyteSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets fifodoublebyte to value 0"]
impl crate::Resettable for FifodoublebyteSpec {
    const RESET_VALUE: u32 = 0;
}
