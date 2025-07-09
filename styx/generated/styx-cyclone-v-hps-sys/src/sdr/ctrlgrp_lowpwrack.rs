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
#[doc = "Register `ctrlgrp_lowpwrack` reader"]
pub type R = crate::R<CtrlgrpLowpwrackSpec>;
#[doc = "Register `ctrlgrp_lowpwrack` writer"]
pub type W = crate::W<CtrlgrpLowpwrackSpec>;
#[doc = "Field `deeppwrdnack` reader - This bit is set to a one after a deep power down has been executed"]
pub type DeeppwrdnackR = crate::BitReader;
#[doc = "Field `deeppwrdnack` writer - This bit is set to a one after a deep power down has been executed"]
pub type DeeppwrdnackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `selfrfshack` reader - This bit is a one to indicate that the controller is in a self-refresh state."]
pub type SelfrfshackR = crate::BitReader;
#[doc = "Field `selfrfshack` writer - This bit is a one to indicate that the controller is in a self-refresh state."]
pub type SelfrfshackW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit is set to a one after a deep power down has been executed"]
    #[inline(always)]
    pub fn deeppwrdnack(&self) -> DeeppwrdnackR {
        DeeppwrdnackR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit is a one to indicate that the controller is in a self-refresh state."]
    #[inline(always)]
    pub fn selfrfshack(&self) -> SelfrfshackR {
        SelfrfshackR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is set to a one after a deep power down has been executed"]
    #[inline(always)]
    #[must_use]
    pub fn deeppwrdnack(&mut self) -> DeeppwrdnackW<CtrlgrpLowpwrackSpec> {
        DeeppwrdnackW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit is a one to indicate that the controller is in a self-refresh state."]
    #[inline(always)]
    #[must_use]
    pub fn selfrfshack(&mut self) -> SelfrfshackW<CtrlgrpLowpwrackSpec> {
        SelfrfshackW::new(self, 1)
    }
}
#[doc = "This register gives the status of the power down commands requested by the Low Power Control register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_lowpwrack::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_lowpwrack::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpLowpwrackSpec;
impl crate::RegisterSpec for CtrlgrpLowpwrackSpec {
    type Ux = u32;
    const OFFSET: u64 = 20568u64;
}
#[doc = "`read()` method returns [`ctrlgrp_lowpwrack::R`](R) reader structure"]
impl crate::Readable for CtrlgrpLowpwrackSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_lowpwrack::W`](W) writer structure"]
impl crate::Writable for CtrlgrpLowpwrackSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_lowpwrack to value 0"]
impl crate::Resettable for CtrlgrpLowpwrackSpec {
    const RESET_VALUE: u32 = 0;
}
