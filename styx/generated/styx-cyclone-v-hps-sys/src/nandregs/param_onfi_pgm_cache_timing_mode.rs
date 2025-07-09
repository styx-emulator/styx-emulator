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
#[doc = "Register `param_onfi_pgm_cache_timing_mode` reader"]
pub type R = crate::R<ParamOnfiPgmCacheTimingModeSpec>;
#[doc = "Register `param_onfi_pgm_cache_timing_mode` writer"]
pub type W = crate::W<ParamOnfiPgmCacheTimingModeSpec>;
#[doc = "Field `value` reader - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports Timing mode 0. \\[*\\]Bit 1 - Supports Timing mode 1. \\[*\\]Bit 2 - Supports Timing mode 2. \\[*\\]Bit 3 - Supports Timing mode 3. \\[*\\]Bit 4 - Supports Timing mode 4. \\[*\\]Bit 5 - Supports Timing mode 5.\\[/list\\]"]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports Timing mode 0. \\[*\\]Bit 1 - Supports Timing mode 1. \\[*\\]Bit 2 - Supports Timing mode 2. \\[*\\]Bit 3 - Supports Timing mode 3. \\[*\\]Bit 4 - Supports Timing mode 4. \\[*\\]Bit 5 - Supports Timing mode 5.\\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:5 - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports Timing mode 0. \\[*\\]Bit 1 - Supports Timing mode 1. \\[*\\]Bit 2 - Supports Timing mode 2. \\[*\\]Bit 3 - Supports Timing mode 3. \\[*\\]Bit 4 - Supports Timing mode 4. \\[*\\]Bit 5 - Supports Timing mode 5.\\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:5 - The values in the field should be interpreted as follows\\[list\\]
\\[*\\]Bit 0 - Supports Timing mode 0. \\[*\\]Bit 1 - Supports Timing mode 1. \\[*\\]Bit 2 - Supports Timing mode 2. \\[*\\]Bit 3 - Supports Timing mode 3. \\[*\\]Bit 4 - Supports Timing mode 4. \\[*\\]Bit 5 - Supports Timing mode 5.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ParamOnfiPgmCacheTimingModeSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Asynchronous Program Cache Timing modes supported by the connected ONFI device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`param_onfi_pgm_cache_timing_mode::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ParamOnfiPgmCacheTimingModeSpec;
impl crate::RegisterSpec for ParamOnfiPgmCacheTimingModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 944u64;
}
#[doc = "`read()` method returns [`param_onfi_pgm_cache_timing_mode::R`](R) reader structure"]
impl crate::Readable for ParamOnfiPgmCacheTimingModeSpec {}
#[doc = "`reset()` method sets param_onfi_pgm_cache_timing_mode to value 0"]
impl crate::Resettable for ParamOnfiPgmCacheTimingModeSpec {
    const RESET_VALUE: u32 = 0;
}
