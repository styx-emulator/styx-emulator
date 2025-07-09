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
#[doc = "Register `RESP4` reader"]
pub type R = crate::R<Resp4Spec>;
#[doc = "Register `RESP4` writer"]
pub type W = crate::W<Resp4Spec>;
#[doc = "Field `CARDSTATUS4` reader - see Table 132."]
pub type Cardstatus4R = crate::FieldReader<u32>;
#[doc = "Field `CARDSTATUS4` writer - see Table 132."]
pub type Cardstatus4W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - see Table 132."]
    #[inline(always)]
    pub fn cardstatus4(&self) -> Cardstatus4R {
        Cardstatus4R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - see Table 132."]
    #[inline(always)]
    #[must_use]
    pub fn cardstatus4(&mut self) -> Cardstatus4W<Resp4Spec> {
        Cardstatus4W::new(self, 0)
    }
}
#[doc = "response 1..4 register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`resp4::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Resp4Spec;
impl crate::RegisterSpec for Resp4Spec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`resp4::R`](R) reader structure"]
impl crate::Readable for Resp4Spec {}
#[doc = "`reset()` method sets RESP4 to value 0"]
impl crate::Resettable for Resp4Spec {
    const RESET_VALUE: u32 = 0;
}
