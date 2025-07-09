// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `dmagrp_Receive_Descriptor_List_Address` reader"]
pub type R = crate::R<DmagrpReceiveDescriptorListAddressSpec>;
#[doc = "Register `dmagrp_Receive_Descriptor_List_Address` writer"]
pub type W = crate::W<DmagrpReceiveDescriptorListAddressSpec>;
#[doc = "Field `rdesla_32bit` reader - This field contains the base address of the first descriptor in the Receive Descriptor list. The LSB bits (1:0) are ignored (32-bit wide bus) and internally taken as all-zero by the DMA. Therefore, these LSB bits are read-only (RO)."]
pub type Rdesla32bitR = crate::FieldReader<u32>;
#[doc = "Field `rdesla_32bit` writer - This field contains the base address of the first descriptor in the Receive Descriptor list. The LSB bits (1:0) are ignored (32-bit wide bus) and internally taken as all-zero by the DMA. Therefore, these LSB bits are read-only (RO)."]
pub type Rdesla32bitW<'a, REG> = crate::FieldWriter<'a, REG, 30, u32>;
impl R {
    #[doc = "Bits 2:31 - This field contains the base address of the first descriptor in the Receive Descriptor list. The LSB bits (1:0) are ignored (32-bit wide bus) and internally taken as all-zero by the DMA. Therefore, these LSB bits are read-only (RO)."]
    #[inline(always)]
    pub fn rdesla_32bit(&self) -> Rdesla32bitR {
        Rdesla32bitR::new((self.bits >> 2) & 0x3fff_ffff)
    }
}
impl W {
    #[doc = "Bits 2:31 - This field contains the base address of the first descriptor in the Receive Descriptor list. The LSB bits (1:0) are ignored (32-bit wide bus) and internally taken as all-zero by the DMA. Therefore, these LSB bits are read-only (RO)."]
    #[inline(always)]
    #[must_use]
    pub fn rdesla_32bit(&mut self) -> Rdesla32bitW<DmagrpReceiveDescriptorListAddressSpec> {
        Rdesla32bitW::new(self, 2)
    }
}
#[doc = "The Receive Descriptor List Address register points to the start of the Receive Descriptor List. The descriptor lists reside in the host's physical memory space and must be Word, Dword, or Lword-aligned (for 32-bit, 64-bit, or 128-bit data bus). The DMA internally converts it to bus width aligned address by making the corresponding LS bits low. Writing to this register is permitted only when reception is stopped. When stopped, this register must be written to before the receive Start command is given. You can write to this register only when Rx DMA has stopped, that is, Bit 1 (SR) is set to zero in Register 6 (Operation Mode Register). When stopped, this register can be written with a new descriptor list address. When you set the SR bit to 1, the DMA takes the newly programmed descriptor base address. If this register is not changed when the SR bit is set to 0, then the DMA takes the descriptor address where it was stopped earlier.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_receive_descriptor_list_address::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_receive_descriptor_list_address::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpReceiveDescriptorListAddressSpec;
impl crate::RegisterSpec for DmagrpReceiveDescriptorListAddressSpec {
    type Ux = u32;
    const OFFSET: u64 = 4108u64;
}
#[doc = "`read()` method returns [`dmagrp_receive_descriptor_list_address::R`](R) reader structure"]
impl crate::Readable for DmagrpReceiveDescriptorListAddressSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_receive_descriptor_list_address::W`](W) writer structure"]
impl crate::Writable for DmagrpReceiveDescriptorListAddressSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Receive_Descriptor_List_Address to value 0"]
impl crate::Resettable for DmagrpReceiveDescriptorListAddressSpec {
    const RESET_VALUE: u32 = 0;
}
