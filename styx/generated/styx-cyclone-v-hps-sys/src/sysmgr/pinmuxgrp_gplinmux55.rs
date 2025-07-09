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
#[doc = "Register `pinmuxgrp_GPLINMUX55` reader"]
pub type R = crate::R<PinmuxgrpGplinmux55Spec>;
#[doc = "Register `pinmuxgrp_GPLINMUX55` writer"]
pub type W = crate::W<PinmuxgrpGplinmux55Spec>;
#[doc = "Field `sel` reader - Select source for GPIO/LoanIO 55. 0 : Source for GPIO/LoanIO 55 is GENERALIO7. 1 : Source for GPIO/LoanIO 55 is MIXED2IO1."]
pub type SelR = crate::BitReader;
#[doc = "Field `sel` writer - Select source for GPIO/LoanIO 55. 0 : Source for GPIO/LoanIO 55 is GENERALIO7. 1 : Source for GPIO/LoanIO 55 is MIXED2IO1."]
pub type SelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 55. 0 : Source for GPIO/LoanIO 55 is GENERALIO7. 1 : Source for GPIO/LoanIO 55 is MIXED2IO1."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 55. 0 : Source for GPIO/LoanIO 55 is GENERALIO7. 1 : Source for GPIO/LoanIO 55 is MIXED2IO1."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpGplinmux55Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 55. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux55::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux55::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpGplinmux55Spec;
impl crate::RegisterSpec for PinmuxgrpGplinmux55Spec {
    type Ux = u32;
    const OFFSET: u64 = 1428u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_gplinmux55::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpGplinmux55Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_gplinmux55::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpGplinmux55Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_GPLINMUX55 to value 0"]
impl crate::Resettable for PinmuxgrpGplinmux55Spec {
    const RESET_VALUE: u32 = 0;
}
