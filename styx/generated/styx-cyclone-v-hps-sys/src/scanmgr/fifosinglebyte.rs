// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `fifosinglebyte` reader"]
pub type R = crate::R<FifosinglebyteSpec>;
#[doc = "Register `fifosinglebyte` writer"]
pub type W = crate::W<FifosinglebyteSpec>;
#[doc = "Field `value` reader - Transfers single byte value to/from command FIFO"]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Transfers single byte value to/from command FIFO"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Transfers single byte value to/from command FIFO"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Transfers single byte value to/from command FIFO"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<FifosinglebyteSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Writes to the FIFO Single Byte Register write a single byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Single Byte FIFO Register read a single byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO1 for writes and BRFIFO1 for reads.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifosinglebyte::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifosinglebyte::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FifosinglebyteSpec;
impl crate::RegisterSpec for FifosinglebyteSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`fifosinglebyte::R`](R) reader structure"]
impl crate::Readable for FifosinglebyteSpec {}
#[doc = "`write(|w| ..)` method takes [`fifosinglebyte::W`](W) writer structure"]
impl crate::Writable for FifosinglebyteSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets fifosinglebyte to value 0"]
impl crate::Resettable for FifosinglebyteSpec {
    const RESET_VALUE: u32 = 0;
}
