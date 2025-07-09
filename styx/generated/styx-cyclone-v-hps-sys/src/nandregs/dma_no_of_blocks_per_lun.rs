// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dma_no_of_blocks_per_lun` reader"]
pub type R = crate::R<DmaNoOfBlocksPerLunSpec>;
#[doc = "Register `dma_no_of_blocks_per_lun` writer"]
pub type W = crate::W<DmaNoOfBlocksPerLunSpec>;
#[doc = "Field `value` reader - Indicates the first block of next LUN. This information is used for extracting the target LUN during LUN interleaving. After Initialization, if the controller detects an ONFi device, this field is automatically updated by the controller. For other devices, software will need to write to this register for proper interleaving. The value in this register is interpreted as follows- \\[list\\]\\[*\\]0 - Next LUN starts from 1024. \\[*\\]1 - Next LUN starts from 2048. \\[*\\]2 - Next LUN starts from 4096 and so on... \\[/list\\]"]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Indicates the first block of next LUN. This information is used for extracting the target LUN during LUN interleaving. After Initialization, if the controller detects an ONFi device, this field is automatically updated by the controller. For other devices, software will need to write to this register for proper interleaving. The value in this register is interpreted as follows- \\[list\\]\\[*\\]0 - Next LUN starts from 1024. \\[*\\]1 - Next LUN starts from 2048. \\[*\\]2 - Next LUN starts from 4096 and so on... \\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Indicates the first block of next LUN. This information is used for extracting the target LUN during LUN interleaving. After Initialization, if the controller detects an ONFi device, this field is automatically updated by the controller. For other devices, software will need to write to this register for proper interleaving. The value in this register is interpreted as follows- \\[list\\]\\[*\\]0 - Next LUN starts from 1024. \\[*\\]1 - Next LUN starts from 2048. \\[*\\]2 - Next LUN starts from 4096 and so on... \\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Indicates the first block of next LUN. This information is used for extracting the target LUN during LUN interleaving. After Initialization, if the controller detects an ONFi device, this field is automatically updated by the controller. For other devices, software will need to write to this register for proper interleaving. The value in this register is interpreted as follows- \\[list\\]\\[*\\]0 - Next LUN starts from 1024. \\[*\\]1 - Next LUN starts from 2048. \\[*\\]2 - Next LUN starts from 4096 and so on... \\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<DmaNoOfBlocksPerLunSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_no_of_blocks_per_lun::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_no_of_blocks_per_lun::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaNoOfBlocksPerLunSpec;
impl crate::RegisterSpec for DmaNoOfBlocksPerLunSpec {
    type Ux = u32;
    const OFFSET: u64 = 1936u64;
}
#[doc = "`read()` method returns [`dma_no_of_blocks_per_lun::R`](R) reader structure"]
impl crate::Readable for DmaNoOfBlocksPerLunSpec {}
#[doc = "`write(|w| ..)` method takes [`dma_no_of_blocks_per_lun::W`](W) writer structure"]
impl crate::Writable for DmaNoOfBlocksPerLunSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dma_no_of_blocks_per_lun to value 0x0f"]
impl crate::Resettable for DmaNoOfBlocksPerLunSpec {
    const RESET_VALUE: u32 = 0x0f;
}
