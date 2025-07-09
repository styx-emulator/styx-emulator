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
#[doc = "Register `pinmuxgrp_MIXED1IO11` reader"]
pub type R = crate::R<PinmuxgrpMixed1io11Spec>;
#[doc = "Register `pinmuxgrp_MIXED1IO11` writer"]
pub type W = crate::W<PinmuxgrpMixed1io11Spec>;
#[doc = "Field `sel` reader - Select peripheral signals connected nand_dq6. 0 : Pin is connected to GPIO/LoanIO number 25. 1 : Pin is connected to Peripheral signal USB1.D7. 2 : Pin is connected to Peripheral signal RGMII1.RXD1. 3 : Pin is connected to Peripheral signal NAND.dq6."]
pub type SelR = crate::FieldReader;
#[doc = "Field `sel` writer - Select peripheral signals connected nand_dq6. 0 : Pin is connected to GPIO/LoanIO number 25. 1 : Pin is connected to Peripheral signal USB1.D7. 2 : Pin is connected to Peripheral signal RGMII1.RXD1. 3 : Pin is connected to Peripheral signal NAND.dq6."]
pub type SelW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Select peripheral signals connected nand_dq6. 0 : Pin is connected to GPIO/LoanIO number 25. 1 : Pin is connected to Peripheral signal USB1.D7. 2 : Pin is connected to Peripheral signal RGMII1.RXD1. 3 : Pin is connected to Peripheral signal NAND.dq6."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Select peripheral signals connected nand_dq6. 0 : Pin is connected to GPIO/LoanIO number 25. 1 : Pin is connected to Peripheral signal USB1.D7. 2 : Pin is connected to Peripheral signal RGMII1.RXD1. 3 : Pin is connected to Peripheral signal NAND.dq6."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpMixed1io11Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "This register is used to control the peripherals connected to nand_dq6 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io11::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io11::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpMixed1io11Spec;
impl crate::RegisterSpec for PinmuxgrpMixed1io11Spec {
    type Ux = u32;
    const OFFSET: u64 = 1324u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_mixed1io11::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpMixed1io11Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_mixed1io11::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpMixed1io11Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_MIXED1IO11 to value 0"]
impl crate::Resettable for PinmuxgrpMixed1io11Spec {
    const RESET_VALUE: u32 = 0;
}
