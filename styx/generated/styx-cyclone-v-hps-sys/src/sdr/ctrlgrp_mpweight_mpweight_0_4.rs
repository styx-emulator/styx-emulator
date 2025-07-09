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
#[doc = "Register `ctrlgrp_mpweight_mpweight_0_4` reader"]
pub type R = crate::R<CtrlgrpMpweightMpweight0_4Spec>;
#[doc = "Register `ctrlgrp_mpweight_mpweight_0_4` writer"]
pub type W = crate::W<CtrlgrpMpweightMpweight0_4Spec>;
#[doc = "Field `staticweight_31_0` reader - Set static weight of the port. Each port is programmed with a 5 bit value. Port 0 is bits 4:0, port 1 is bits 9:5, up to port 9 being bits 49:45"]
pub type Staticweight31_0R = crate::FieldReader<u32>;
#[doc = "Field `staticweight_31_0` writer - Set static weight of the port. Each port is programmed with a 5 bit value. Port 0 is bits 4:0, port 1 is bits 9:5, up to port 9 being bits 49:45"]
pub type Staticweight31_0W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Set static weight of the port. Each port is programmed with a 5 bit value. Port 0 is bits 4:0, port 1 is bits 9:5, up to port 9 being bits 49:45"]
    #[inline(always)]
    pub fn staticweight_31_0(&self) -> Staticweight31_0R {
        Staticweight31_0R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Set static weight of the port. Each port is programmed with a 5 bit value. Port 0 is bits 4:0, port 1 is bits 9:5, up to port 9 being bits 49:45"]
    #[inline(always)]
    #[must_use]
    pub fn staticweight_31_0(&mut self) -> Staticweight31_0W<CtrlgrpMpweightMpweight0_4Spec> {
        Staticweight31_0W::new(self, 0)
    }
}
#[doc = "This register is used to configure the DRAM burst operation scheduling.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_mpweight_mpweight_0_4::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_mpweight_mpweight_0_4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpMpweightMpweight0_4Spec;
impl crate::RegisterSpec for CtrlgrpMpweightMpweight0_4Spec {
    type Ux = u32;
    const OFFSET: u64 = 20656u64;
}
#[doc = "`read()` method returns [`ctrlgrp_mpweight_mpweight_0_4::R`](R) reader structure"]
impl crate::Readable for CtrlgrpMpweightMpweight0_4Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_mpweight_mpweight_0_4::W`](W) writer structure"]
impl crate::Writable for CtrlgrpMpweightMpweight0_4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
