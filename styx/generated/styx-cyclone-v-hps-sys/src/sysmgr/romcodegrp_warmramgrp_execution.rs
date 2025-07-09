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
#[doc = "Register `romcodegrp_warmramgrp_execution` reader"]
pub type R = crate::R<RomcodegrpWarmramgrpExecutionSpec>;
#[doc = "Register `romcodegrp_warmramgrp_execution` writer"]
pub type W = crate::W<RomcodegrpWarmramgrpExecutionSpec>;
#[doc = "Field `offset` reader - Contains the byte offset into the On-chip RAM that the Boot ROM will jump to if the CRC validation succeeds. The Boot ROM code will set the top 16 bits to 0xFFFF."]
pub type OffsetR = crate::FieldReader<u16>;
#[doc = "Field `offset` writer - Contains the byte offset into the On-chip RAM that the Boot ROM will jump to if the CRC validation succeeds. The Boot ROM code will set the top 16 bits to 0xFFFF."]
pub type OffsetW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Contains the byte offset into the On-chip RAM that the Boot ROM will jump to if the CRC validation succeeds. The Boot ROM code will set the top 16 bits to 0xFFFF."]
    #[inline(always)]
    pub fn offset(&self) -> OffsetR {
        OffsetR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Contains the byte offset into the On-chip RAM that the Boot ROM will jump to if the CRC validation succeeds. The Boot ROM code will set the top 16 bits to 0xFFFF."]
    #[inline(always)]
    #[must_use]
    pub fn offset(&mut self) -> OffsetW<RomcodegrpWarmramgrpExecutionSpec> {
        OffsetW::new(self, 0)
    }
}
#[doc = "Offset into On-chip RAM to enter to on a warm boot.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_warmramgrp_execution::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_warmramgrp_execution::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpWarmramgrpExecutionSpec;
impl crate::RegisterSpec for RomcodegrpWarmramgrpExecutionSpec {
    type Ux = u32;
    const OFFSET: u64 = 236u64;
}
#[doc = "`read()` method returns [`romcodegrp_warmramgrp_execution::R`](R) reader structure"]
impl crate::Readable for RomcodegrpWarmramgrpExecutionSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_warmramgrp_execution::W`](W) writer structure"]
impl crate::Writable for RomcodegrpWarmramgrpExecutionSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_warmramgrp_execution to value 0"]
impl crate::Resettable for RomcodegrpWarmramgrpExecutionSpec {
    const RESET_VALUE: u32 = 0;
}
