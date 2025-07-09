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
#[doc = "Register `romcodegrp_warmramgrp_length` reader"]
pub type R = crate::R<RomcodegrpWarmramgrpLengthSpec>;
#[doc = "Register `romcodegrp_warmramgrp_length` writer"]
pub type W = crate::W<RomcodegrpWarmramgrpLengthSpec>;
#[doc = "Field `size` reader - Contains the length (in bytes) of the region in the On-chip RAM for the warm boot CRC validation. If the length is 0, the Boot ROM won't perform CRC calculation and CRC check to avoid overhead caused by CRC validation. If the START + LENGTH exceeds the maximum offset into the On-chip RAM, the Boot ROM won't boot from the On-chip RAM. The length must be an integer multiple of 4. The Boot ROM code will clear the top 16 bits and the bottom 2 bits."]
pub type SizeR = crate::FieldReader<u16>;
#[doc = "Field `size` writer - Contains the length (in bytes) of the region in the On-chip RAM for the warm boot CRC validation. If the length is 0, the Boot ROM won't perform CRC calculation and CRC check to avoid overhead caused by CRC validation. If the START + LENGTH exceeds the maximum offset into the On-chip RAM, the Boot ROM won't boot from the On-chip RAM. The length must be an integer multiple of 4. The Boot ROM code will clear the top 16 bits and the bottom 2 bits."]
pub type SizeW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Contains the length (in bytes) of the region in the On-chip RAM for the warm boot CRC validation. If the length is 0, the Boot ROM won't perform CRC calculation and CRC check to avoid overhead caused by CRC validation. If the START + LENGTH exceeds the maximum offset into the On-chip RAM, the Boot ROM won't boot from the On-chip RAM. The length must be an integer multiple of 4. The Boot ROM code will clear the top 16 bits and the bottom 2 bits."]
    #[inline(always)]
    pub fn size(&self) -> SizeR {
        SizeR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Contains the length (in bytes) of the region in the On-chip RAM for the warm boot CRC validation. If the length is 0, the Boot ROM won't perform CRC calculation and CRC check to avoid overhead caused by CRC validation. If the START + LENGTH exceeds the maximum offset into the On-chip RAM, the Boot ROM won't boot from the On-chip RAM. The length must be an integer multiple of 4. The Boot ROM code will clear the top 16 bits and the bottom 2 bits."]
    #[inline(always)]
    #[must_use]
    pub fn size(&mut self) -> SizeW<RomcodegrpWarmramgrpLengthSpec> {
        SizeW::new(self, 0)
    }
}
#[doc = "Length of region in On-chip RAM for CRC validation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_length::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_length::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpWarmramgrpLengthSpec;
impl crate::RegisterSpec for RomcodegrpWarmramgrpLengthSpec {
    type Ux = u32;
    const OFFSET: u64 = 232u64;
}
#[doc = "`read()` method returns [`romcodegrp_warmramgrp_length::R`](R) reader structure"]
impl crate::Readable for RomcodegrpWarmramgrpLengthSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_warmramgrp_length::W`](W) writer structure"]
impl crate::Writable for RomcodegrpWarmramgrpLengthSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_warmramgrp_length to value 0"]
impl crate::Resettable for RomcodegrpWarmramgrpLengthSpec {
    const RESET_VALUE: u32 = 0;
}
