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
#[doc = "Register `IMSCR` reader"]
pub type R = crate::R<ImscrSpec>;
#[doc = "Register `IMSCR` writer"]
pub type W = crate::W<ImscrSpec>;
#[doc = "Field `INIM` reader - Input FIFO service interrupt mask"]
pub type InimR = crate::BitReader;
#[doc = "Field `INIM` writer - Input FIFO service interrupt mask"]
pub type InimW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OUTIM` reader - Output FIFO service interrupt mask"]
pub type OutimR = crate::BitReader;
#[doc = "Field `OUTIM` writer - Output FIFO service interrupt mask"]
pub type OutimW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Input FIFO service interrupt mask"]
    #[inline(always)]
    pub fn inim(&self) -> InimR {
        InimR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Output FIFO service interrupt mask"]
    #[inline(always)]
    pub fn outim(&self) -> OutimR {
        OutimR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Input FIFO service interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn inim(&mut self) -> InimW<ImscrSpec> {
        InimW::new(self, 0)
    }
    #[doc = "Bit 1 - Output FIFO service interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn outim(&mut self) -> OutimW<ImscrSpec> {
        OutimW::new(self, 1)
    }
}
#[doc = "interrupt mask set/clear register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`imscr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`imscr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ImscrSpec;
impl crate::RegisterSpec for ImscrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`imscr::R`](R) reader structure"]
impl crate::Readable for ImscrSpec {}
#[doc = "`write(|w| ..)` method takes [`imscr::W`](W) writer structure"]
impl crate::Writable for ImscrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets IMSCR to value 0"]
impl crate::Resettable for ImscrSpec {
    const RESET_VALUE: u32 = 0;
}
