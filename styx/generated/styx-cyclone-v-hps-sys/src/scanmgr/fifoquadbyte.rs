// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `fifoquadbyte` reader"]
pub type R = crate::R<FifoquadbyteSpec>;
#[doc = "Register `fifoquadbyte` writer"]
pub type W = crate::W<FifoquadbyteSpec>;
#[doc = "Field `value` reader - Transfers quad byte value to/from command FIFO"]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - Transfers quad byte value to/from command FIFO"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Transfers quad byte value to/from command FIFO"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Transfers quad byte value to/from command FIFO"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<FifoquadbyteSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Writes to the FIFO Quad Byte Register write a quad byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Quad Byte FIFO Register read a quad byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO4 for writes and BRFIFO4 for reads.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifoquadbyte::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifoquadbyte::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FifoquadbyteSpec;
impl crate::RegisterSpec for FifoquadbyteSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`fifoquadbyte::R`](R) reader structure"]
impl crate::Readable for FifoquadbyteSpec {}
#[doc = "`write(|w| ..)` method takes [`fifoquadbyte::W`](W) writer structure"]
impl crate::Writable for FifoquadbyteSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
