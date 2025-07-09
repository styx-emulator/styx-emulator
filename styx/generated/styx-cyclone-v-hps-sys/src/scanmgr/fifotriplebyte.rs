// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `fifotriplebyte` reader"]
pub type R = crate::R<FifotriplebyteSpec>;
#[doc = "Register `fifotriplebyte` writer"]
pub type W = crate::W<FifotriplebyteSpec>;
#[doc = "Field `value` reader - Transfers triple byte value to/from command FIFO"]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - Transfers triple byte value to/from command FIFO"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:23 - Transfers triple byte value to/from command FIFO"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:23 - Transfers triple byte value to/from command FIFO"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<FifotriplebyteSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Writes to the FIFO Triple Byte Register write a triple byte value to the command FIFO. If the command FIFO is full, the APB write operation is stalled until the command FIFO is not full. Reads from the Triple Byte FIFO Register read a triple byte value from the command FIFO. If the command FIFO is empty, the APB read operation is stalled until the command FIFO is not empty. See the ARM documentation for a description of the read and write values. The name of this register in ARM documentation is BWFIFO3 for writes and BRFIFO3 for reads.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifotriplebyte::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fifotriplebyte::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FifotriplebyteSpec;
impl crate::RegisterSpec for FifotriplebyteSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`fifotriplebyte::R`](R) reader structure"]
impl crate::Readable for FifotriplebyteSpec {}
#[doc = "`write(|w| ..)` method takes [`fifotriplebyte::W`](W) writer structure"]
impl crate::Writable for FifotriplebyteSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets fifotriplebyte to value 0"]
impl crate::Resettable for FifotriplebyteSpec {
    const RESET_VALUE: u32 = 0;
}
