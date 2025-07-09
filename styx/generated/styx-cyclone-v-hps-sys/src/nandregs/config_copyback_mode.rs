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
#[doc = "Register `config_copyback_mode` reader"]
pub type R = crate::R<ConfigCopybackModeSpec>;
#[doc = "Register `config_copyback_mode` writer"]
pub type W = crate::W<ConfigCopybackModeSpec>;
#[doc = "Field `value` reader - The values in the field should be as follows\\[list\\]
\\[*\\]4'h0 - This value informs the controller that the copyback sequence to follow is, C00, Address, C35, C85, Address, C10 \\[*\\]4'h1 - This value informs the controller that the copyback sequence to follow is, C00, Address, C30, C8C, Address, C10 \\[*\\]4'h2 - This value informs the controller that the copyback sequence to follow is, C00, Address, C8A, Address, C10 \\[*\\]4'h3 - This value informs the controller that the copyback sequence to follow is of a four plane copyback sequence, C00, Address, C03, Address, C03, Address, C03, Address, C8A, Address, C11, C8A, Address, C11, C8A, Address, C11, C8A, Address, C10. \\[*\\]4'h4 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C00, Address, C35, C00, Address, C35, C85, Address, C11, C81, Address, C10. \\[*\\]4'h5 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C60, Address, C60, Address, C35, C85, Address, C11, C81, Address, C10. \\[*\\]4'h6 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C00, Address, C00, Address, C35, C85, Address, C11, C80, Address, C10. \\[*\\]4'h7 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C60, Address, C60, Address, C30, C8C, Address, C11, C8C, Address, C10. \\[*\\]4'h8 - 4'h15 - Reserved.\\[/list\\]"]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - The values in the field should be as follows\\[list\\]
\\[*\\]4'h0 - This value informs the controller that the copyback sequence to follow is, C00, Address, C35, C85, Address, C10 \\[*\\]4'h1 - This value informs the controller that the copyback sequence to follow is, C00, Address, C30, C8C, Address, C10 \\[*\\]4'h2 - This value informs the controller that the copyback sequence to follow is, C00, Address, C8A, Address, C10 \\[*\\]4'h3 - This value informs the controller that the copyback sequence to follow is of a four plane copyback sequence, C00, Address, C03, Address, C03, Address, C03, Address, C8A, Address, C11, C8A, Address, C11, C8A, Address, C11, C8A, Address, C10. \\[*\\]4'h4 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C00, Address, C35, C00, Address, C35, C85, Address, C11, C81, Address, C10. \\[*\\]4'h5 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C60, Address, C60, Address, C35, C85, Address, C11, C81, Address, C10. \\[*\\]4'h6 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C00, Address, C00, Address, C35, C85, Address, C11, C80, Address, C10. \\[*\\]4'h7 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C60, Address, C60, Address, C30, C8C, Address, C11, C8C, Address, C10. \\[*\\]4'h8 - 4'h15 - Reserved.\\[/list\\]"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - The values in the field should be as follows\\[list\\]
\\[*\\]4'h0 - This value informs the controller that the copyback sequence to follow is, C00, Address, C35, C85, Address, C10 \\[*\\]4'h1 - This value informs the controller that the copyback sequence to follow is, C00, Address, C30, C8C, Address, C10 \\[*\\]4'h2 - This value informs the controller that the copyback sequence to follow is, C00, Address, C8A, Address, C10 \\[*\\]4'h3 - This value informs the controller that the copyback sequence to follow is of a four plane copyback sequence, C00, Address, C03, Address, C03, Address, C03, Address, C8A, Address, C11, C8A, Address, C11, C8A, Address, C11, C8A, Address, C10. \\[*\\]4'h4 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C00, Address, C35, C00, Address, C35, C85, Address, C11, C81, Address, C10. \\[*\\]4'h5 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C60, Address, C60, Address, C35, C85, Address, C11, C81, Address, C10. \\[*\\]4'h6 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C00, Address, C00, Address, C35, C85, Address, C11, C80, Address, C10. \\[*\\]4'h7 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C60, Address, C60, Address, C30, C8C, Address, C11, C8C, Address, C10. \\[*\\]4'h8 - 4'h15 - Reserved.\\[/list\\]"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - The values in the field should be as follows\\[list\\]
\\[*\\]4'h0 - This value informs the controller that the copyback sequence to follow is, C00, Address, C35, C85, Address, C10 \\[*\\]4'h1 - This value informs the controller that the copyback sequence to follow is, C00, Address, C30, C8C, Address, C10 \\[*\\]4'h2 - This value informs the controller that the copyback sequence to follow is, C00, Address, C8A, Address, C10 \\[*\\]4'h3 - This value informs the controller that the copyback sequence to follow is of a four plane copyback sequence, C00, Address, C03, Address, C03, Address, C03, Address, C8A, Address, C11, C8A, Address, C11, C8A, Address, C11, C8A, Address, C10. \\[*\\]4'h4 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C00, Address, C35, C00, Address, C35, C85, Address, C11, C81, Address, C10. \\[*\\]4'h5 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C60, Address, C60, Address, C35, C85, Address, C11, C81, Address, C10. \\[*\\]4'h6 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C00, Address, C00, Address, C35, C85, Address, C11, C80, Address, C10. \\[*\\]4'h7 - This value informs the controller that the copyback sequence to follow is of a two plane copyback sequence, C60, Address, C60, Address, C30, C8C, Address, C11, C8C, Address, C10. \\[*\\]4'h8 - 4'h15 - Reserved.\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigCopybackModeSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "The type of copyback sequence that the controller will follow.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_copyback_mode::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_copyback_mode::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigCopybackModeSpec;
impl crate::RegisterSpec for ConfigCopybackModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 480u64;
}
#[doc = "`read()` method returns [`config_copyback_mode::R`](R) reader structure"]
impl crate::Readable for ConfigCopybackModeSpec {}
#[doc = "`write(|w| ..)` method takes [`config_copyback_mode::W`](W) writer structure"]
impl crate::Writable for ConfigCopybackModeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_copyback_mode to value 0"]
impl crate::Resettable for ConfigCopybackModeSpec {
    const RESET_VALUE: u32 = 0;
}
