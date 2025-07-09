// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `data` reader"]
pub type R = crate::R<DataSpec>;
#[doc = "Register `data` writer"]
pub type W = crate::W<DataSpec>;
#[doc = "Field `value` reader - Provides read/write access to data FIFO."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - Provides read/write access to data FIFO."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Provides read/write access to data FIFO."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Provides read/write access to data FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<DataSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Provides read/write access to data FIFO. Addresses 0x200 and above are mapped to the data FIFO. More than one address is mapped to data FIFO so that FIFO can be accessed using bursts.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`data::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`data::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DataSpec;
impl crate::RegisterSpec for DataSpec {
    type Ux = u32;
    const OFFSET: u64 = 512u64;
}
#[doc = "`read()` method returns [`data::R`](R) reader structure"]
impl crate::Readable for DataSpec {}
#[doc = "`write(|w| ..)` method takes [`data::W`](W) writer structure"]
impl crate::Writable for DataSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
