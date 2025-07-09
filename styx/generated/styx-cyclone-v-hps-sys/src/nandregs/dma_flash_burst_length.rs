// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dma_flash_burst_length` reader"]
pub type R = crate::R<DmaFlashBurstLengthSpec>;
#[doc = "Register `dma_flash_burst_length` writer"]
pub type W = crate::W<DmaFlashBurstLengthSpec>;
#[doc = "Field `value` reader - Sets the burst used by data dma for transferring data to/from flash device. This burst length is different and is larger than the burst length on the host bus so that larger amount of data can be transferred to/from device, descreasing controller data transfer overhead in the process. 00 - 64 bytes, 01 - 128 bytes, 10 - 256 bytes, 11 - 512 bytes. The host burst size multiplied by the number of outstanding requests on the host side should be greater than equal to this value. If not, the device side burst length will be equal to host side burst length."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Sets the burst used by data dma for transferring data to/from flash device. This burst length is different and is larger than the burst length on the host bus so that larger amount of data can be transferred to/from device, descreasing controller data transfer overhead in the process. 00 - 64 bytes, 01 - 128 bytes, 10 - 256 bytes, 11 - 512 bytes. The host burst size multiplied by the number of outstanding requests on the host side should be greater than equal to this value. If not, the device side burst length will be equal to host side burst length."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `continous_burst` reader - When this bit is set, the Data DMA will burst the entire page from/to the flash device. Please make sure that the host system can provide/sink data at a fast pace to avoid unnecessary pausing of data on the device interface."]
pub type ContinousBurstR = crate::BitReader;
#[doc = "Field `continous_burst` writer - When this bit is set, the Data DMA will burst the entire page from/to the flash device. Please make sure that the host system can provide/sink data at a fast pace to avoid unnecessary pausing of data on the device interface."]
pub type ContinousBurstW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:1 - Sets the burst used by data dma for transferring data to/from flash device. This burst length is different and is larger than the burst length on the host bus so that larger amount of data can be transferred to/from device, descreasing controller data transfer overhead in the process. 00 - 64 bytes, 01 - 128 bytes, 10 - 256 bytes, 11 - 512 bytes. The host burst size multiplied by the number of outstanding requests on the host side should be greater than equal to this value. If not, the device side burst length will be equal to host side burst length."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 4 - When this bit is set, the Data DMA will burst the entire page from/to the flash device. Please make sure that the host system can provide/sink data at a fast pace to avoid unnecessary pausing of data on the device interface."]
    #[inline(always)]
    pub fn continous_burst(&self) -> ContinousBurstR {
        ContinousBurstR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - Sets the burst used by data dma for transferring data to/from flash device. This burst length is different and is larger than the burst length on the host bus so that larger amount of data can be transferred to/from device, descreasing controller data transfer overhead in the process. 00 - 64 bytes, 01 - 128 bytes, 10 - 256 bytes, 11 - 512 bytes. The host burst size multiplied by the number of outstanding requests on the host side should be greater than equal to this value. If not, the device side burst length will be equal to host side burst length."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<DmaFlashBurstLengthSpec> {
        ValueW::new(self, 0)
    }
    #[doc = "Bit 4 - When this bit is set, the Data DMA will burst the entire page from/to the flash device. Please make sure that the host system can provide/sink data at a fast pace to avoid unnecessary pausing of data on the device interface."]
    #[inline(always)]
    #[must_use]
    pub fn continous_burst(&mut self) -> ContinousBurstW<DmaFlashBurstLengthSpec> {
        ContinousBurstW::new(self, 4)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_flash_burst_length::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_flash_burst_length::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaFlashBurstLengthSpec;
impl crate::RegisterSpec for DmaFlashBurstLengthSpec {
    type Ux = u32;
    const OFFSET: u64 = 1904u64;
}
#[doc = "`read()` method returns [`dma_flash_burst_length::R`](R) reader structure"]
impl crate::Readable for DmaFlashBurstLengthSpec {}
#[doc = "`write(|w| ..)` method takes [`dma_flash_burst_length::W`](W) writer structure"]
impl crate::Writable for DmaFlashBurstLengthSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dma_flash_burst_length to value 0x01"]
impl crate::Resettable for DmaFlashBurstLengthSpec {
    const RESET_VALUE: u32 = 0x01;
}
