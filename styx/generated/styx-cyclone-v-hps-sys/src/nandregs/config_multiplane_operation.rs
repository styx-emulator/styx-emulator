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
#[doc = "Register `config_multiplane_operation` reader"]
pub type R = crate::R<ConfigMultiplaneOperationSpec>;
#[doc = "Register `config_multiplane_operation` writer"]
pub type W = crate::W<ConfigMultiplaneOperationSpec>;
#[doc = "Field `flag` reader - list\\]\\[*\\]1 - Multiplane operation enabled \\[*\\]0 - Multiplane operation disabled\\[/list\\]"]
pub type FlagR = crate::BitReader;
#[doc = "Field `flag` writer - list\\]\\[*\\]1 - Multiplane operation enabled \\[*\\]0 - Multiplane operation disabled\\[/list\\]"]
pub type FlagW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - list\\]\\[*\\]1 - Multiplane operation enabled \\[*\\]0 - Multiplane operation disabled\\[/list\\]"]
    #[inline(always)]
    pub fn flag(&self) -> FlagR {
        FlagR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - list\\]\\[*\\]1 - Multiplane operation enabled \\[*\\]0 - Multiplane operation disabled\\[/list\\]"]
    #[inline(always)]
    #[must_use]
    pub fn flag(&mut self) -> FlagW<ConfigMultiplaneOperationSpec> {
        FlagW::new(self, 0)
    }
}
#[doc = "Multiplane transfer mode. Pipelined read, copyback, erase and program commands are transfered in multiplane mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_multiplane_operation::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_multiplane_operation::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigMultiplaneOperationSpec;
impl crate::RegisterSpec for ConfigMultiplaneOperationSpec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`config_multiplane_operation::R`](R) reader structure"]
impl crate::Readable for ConfigMultiplaneOperationSpec {}
#[doc = "`write(|w| ..)` method takes [`config_multiplane_operation::W`](W) writer structure"]
impl crate::Writable for ConfigMultiplaneOperationSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_multiplane_operation to value 0"]
impl crate::Resettable for ConfigMultiplaneOperationSpec {
    const RESET_VALUE: u32 = 0;
}
