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
#[doc = "Register `hostgrp_hflbaddr` reader"]
pub type R = crate::R<HostgrpHflbaddrSpec>;
#[doc = "Register `hostgrp_hflbaddr` writer"]
pub type W = crate::W<HostgrpHflbaddrSpec>;
#[doc = "Field `hflbaddr` reader - This Register is valid only for Host mode Scatter-Gather DMA mode. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
pub type HflbaddrR = crate::FieldReader<u32>;
#[doc = "Field `hflbaddr` writer - This Register is valid only for Host mode Scatter-Gather DMA mode. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
pub type HflbaddrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This Register is valid only for Host mode Scatter-Gather DMA mode. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
    #[inline(always)]
    pub fn hflbaddr(&self) -> HflbaddrR {
        HflbaddrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This Register is valid only for Host mode Scatter-Gather DMA mode. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
    #[inline(always)]
    #[must_use]
    pub fn hflbaddr(&mut self) -> HflbaddrW<HostgrpHflbaddrSpec> {
        HflbaddrW::new(self, 0)
    }
}
#[doc = "This Register is valid only for Host mode Scatter-Gather DMA. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hflbaddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hflbaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHflbaddrSpec;
impl crate::RegisterSpec for HostgrpHflbaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 1052u64;
}
#[doc = "`read()` method returns [`hostgrp_hflbaddr::R`](R) reader structure"]
impl crate::Readable for HostgrpHflbaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hflbaddr::W`](W) writer structure"]
impl crate::Writable for HostgrpHflbaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hflbaddr to value 0"]
impl crate::Resettable for HostgrpHflbaddrSpec {
    const RESET_VALUE: u32 = 0;
}
