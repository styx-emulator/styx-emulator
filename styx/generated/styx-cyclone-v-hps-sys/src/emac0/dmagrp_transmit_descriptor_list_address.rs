// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_Transmit_Descriptor_List_Address` reader"]
pub type R = crate::R<DmagrpTransmitDescriptorListAddressSpec>;
#[doc = "Register `dmagrp_Transmit_Descriptor_List_Address` writer"]
pub type W = crate::W<DmagrpTransmitDescriptorListAddressSpec>;
#[doc = "Field `tdesla_32bit` reader - This field contains the base address of the first descriptor in the Transmit Descriptor list. The LSB bits (1:0) are ignored (32-bit wide bus) and are internally taken as all-zero by the DMA. Therefore, these LSB bits are read-only (RO)."]
pub type Tdesla32bitR = crate::FieldReader<u32>;
#[doc = "Field `tdesla_32bit` writer - This field contains the base address of the first descriptor in the Transmit Descriptor list. The LSB bits (1:0) are ignored (32-bit wide bus) and are internally taken as all-zero by the DMA. Therefore, these LSB bits are read-only (RO)."]
pub type Tdesla32bitW<'a, REG> = crate::FieldWriter<'a, REG, 30, u32>;
impl R {
    #[doc = "Bits 2:31 - This field contains the base address of the first descriptor in the Transmit Descriptor list. The LSB bits (1:0) are ignored (32-bit wide bus) and are internally taken as all-zero by the DMA. Therefore, these LSB bits are read-only (RO)."]
    #[inline(always)]
    pub fn tdesla_32bit(&self) -> Tdesla32bitR {
        Tdesla32bitR::new((self.bits >> 2) & 0x3fff_ffff)
    }
}
impl W {
    #[doc = "Bits 2:31 - This field contains the base address of the first descriptor in the Transmit Descriptor list. The LSB bits (1:0) are ignored (32-bit wide bus) and are internally taken as all-zero by the DMA. Therefore, these LSB bits are read-only (RO)."]
    #[inline(always)]
    #[must_use]
    pub fn tdesla_32bit(&mut self) -> Tdesla32bitW<DmagrpTransmitDescriptorListAddressSpec> {
        Tdesla32bitW::new(self, 2)
    }
}
#[doc = "The Transmit Descriptor List Address register points to the start of the Transmit Descriptor List. The descriptor lists reside in the host's physical memory space and must be Word, Dword, or Lword-aligned (for 32-bit, 64-bit, or 128-bit data bus). The DMA internally converts it to bus width aligned address by making the corresponding LSB to low. You can write to this register only when the Tx DMA has stopped, that is, Bit 13 (ST) is set to zero in Register 6 (Operation Mode Register). When stopped, this register can be written with a new descriptor list address. When you set the ST bit to 1, the DMA takes the newly programmed descriptor base address. If this register is not changed when the ST bit is set to 0, then the DMA takes the descriptor address where it was stopped earlier.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_transmit_descriptor_list_address::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_transmit_descriptor_list_address::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpTransmitDescriptorListAddressSpec;
impl crate::RegisterSpec for DmagrpTransmitDescriptorListAddressSpec {
    type Ux = u32;
    const OFFSET: u64 = 4112u64;
}
#[doc = "`read()` method returns [`dmagrp_transmit_descriptor_list_address::R`](R) reader structure"]
impl crate::Readable for DmagrpTransmitDescriptorListAddressSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_transmit_descriptor_list_address::W`](W) writer structure"]
impl crate::Writable for DmagrpTransmitDescriptorListAddressSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Transmit_Descriptor_List_Address to value 0"]
impl crate::Resettable for DmagrpTransmitDescriptorListAddressSpec {
    const RESET_VALUE: u32 = 0;
}
