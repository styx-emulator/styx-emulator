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
#[doc = "Register `dma_chip_interleave_enable_and_allow_int_reads` reader"]
pub type R = crate::R<DmaChipInterleaveEnableAndAllowIntReadsSpec>;
#[doc = "Register `dma_chip_interleave_enable_and_allow_int_reads` writer"]
pub type W = crate::W<DmaChipInterleaveEnableAndAllowIntReadsSpec>;
#[doc = "Field `chip_interleave_enable` reader - This bit informs the controller to enable or disable interleaving among banks/LUNS to increase the net performance of the controller. \\[list\\]\\[*\\]1 - Enable interleaving \\[*\\]0 - Disable Interleaving\\[/list\\]"]
pub type ChipInterleaveEnableR = crate::BitReader;
#[doc = "Field `chip_interleave_enable` writer - This bit informs the controller to enable or disable interleaving among banks/LUNS to increase the net performance of the controller. \\[list\\]\\[*\\]1 - Enable interleaving \\[*\\]0 - Disable Interleaving\\[/list\\]"]
pub type ChipInterleaveEnableW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `allow_int_reads_within_luns` reader - This bit informs the controller to enable or disable simultaneous read accesses to different LUNS in the same bank. This bit is of importance only if the controller supports interleaved operations among LUNs and if the device has multiple LUNS. If the bit is disabled, the controller will send read commands to different LUNS of of the same bank only sequentially and if enabled, the controller will issue simultaneous read accesses to LUNS of same bank if required. \\[list\\]\\[*\\]1 - Enable \\[*\\]0 - Disable\\[/list\\]"]
pub type AllowIntReadsWithinLunsR = crate::BitReader;
#[doc = "Field `allow_int_reads_within_luns` writer - This bit informs the controller to enable or disable simultaneous read accesses to different LUNS in the same bank. This bit is of importance only if the controller supports interleaved operations among LUNs and if the device has multiple LUNS. If the bit is disabled, the controller will send read commands to different LUNS of of the same bank only sequentially and if enabled, the controller will issue simultaneous read accesses to LUNS of same bank if required. \\[list\\]\\[*\\]1 - Enable \\[*\\]0 - Disable\\[/list\\]"]
pub type AllowIntReadsWithinLunsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit informs the controller to enable or disable interleaving among banks/LUNS to increase the net performance of the controller. \\[list\\]\\[*\\]1 - Enable interleaving \\[*\\]0 - Disable Interleaving\\[/list\\]"]
    #[inline(always)]
    pub fn chip_interleave_enable(&self) -> ChipInterleaveEnableR {
        ChipInterleaveEnableR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 4 - This bit informs the controller to enable or disable simultaneous read accesses to different LUNS in the same bank. This bit is of importance only if the controller supports interleaved operations among LUNs and if the device has multiple LUNS. If the bit is disabled, the controller will send read commands to different LUNS of of the same bank only sequentially and if enabled, the controller will issue simultaneous read accesses to LUNS of same bank if required. \\[list\\]\\[*\\]1 - Enable \\[*\\]0 - Disable\\[/list\\]"]
    #[inline(always)]
    pub fn allow_int_reads_within_luns(&self) -> AllowIntReadsWithinLunsR {
        AllowIntReadsWithinLunsR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit informs the controller to enable or disable interleaving among banks/LUNS to increase the net performance of the controller. \\[list\\]\\[*\\]1 - Enable interleaving \\[*\\]0 - Disable Interleaving\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn chip_interleave_enable(
        &mut self,
    ) -> ChipInterleaveEnableW<DmaChipInterleaveEnableAndAllowIntReadsSpec> {
        ChipInterleaveEnableW::new(self, 0)
    }
    #[doc = "Bit 4 - This bit informs the controller to enable or disable simultaneous read accesses to different LUNS in the same bank. This bit is of importance only if the controller supports interleaved operations among LUNs and if the device has multiple LUNS. If the bit is disabled, the controller will send read commands to different LUNS of of the same bank only sequentially and if enabled, the controller will issue simultaneous read accesses to LUNS of same bank if required. \\[list\\]\\[*\\]1 - Enable \\[*\\]0 - Disable\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn allow_int_reads_within_luns(
        &mut self,
    ) -> AllowIntReadsWithinLunsW<DmaChipInterleaveEnableAndAllowIntReadsSpec> {
        AllowIntReadsWithinLunsW::new(self, 4)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dma_chip_interleave_enable_and_allow_int_reads::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dma_chip_interleave_enable_and_allow_int_reads::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmaChipInterleaveEnableAndAllowIntReadsSpec;
impl crate::RegisterSpec for DmaChipInterleaveEnableAndAllowIntReadsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1920u64;
}
#[doc = "`read()` method returns [`dma_chip_interleave_enable_and_allow_int_reads::R`](R) reader structure"]
impl crate::Readable for DmaChipInterleaveEnableAndAllowIntReadsSpec {}
#[doc = "`write(|w| ..)` method takes [`dma_chip_interleave_enable_and_allow_int_reads::W`](W) writer structure"]
impl crate::Writable for DmaChipInterleaveEnableAndAllowIntReadsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dma_chip_interleave_enable_and_allow_int_reads to value 0x10"]
impl crate::Resettable for DmaChipInterleaveEnableAndAllowIntReadsSpec {
    const RESET_VALUE: u32 = 0x10;
}
