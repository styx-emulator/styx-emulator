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
#[doc = "Register `msgifgrp_IF2DA` reader"]
pub type R = crate::R<MsgifgrpIf2daSpec>;
#[doc = "Register `msgifgrp_IF2DA` writer"]
pub type W = crate::W<MsgifgrpIf2daSpec>;
#[doc = "Field `Data0` reader - 1st data byte of a CAN Data Frame"]
pub type Data0R = crate::FieldReader;
#[doc = "Field `Data0` writer - 1st data byte of a CAN Data Frame"]
pub type Data0W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Data1` reader - 2nd data byte of a CAN Data Frame"]
pub type Data1R = crate::FieldReader;
#[doc = "Field `Data1` writer - 2nd data byte of a CAN Data Frame"]
pub type Data1W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Data2` reader - 3rd data byte of a CAN Data Frame"]
pub type Data2R = crate::FieldReader;
#[doc = "Field `Data2` writer - 3rd data byte of a CAN Data Frame"]
pub type Data2W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `Data3` reader - 4th data byte of a CAN Data Frame"]
pub type Data3R = crate::FieldReader;
#[doc = "Field `Data3` writer - 4th data byte of a CAN Data Frame"]
pub type Data3W<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - 1st data byte of a CAN Data Frame"]
    #[inline(always)]
    pub fn data0(&self) -> Data0R {
        Data0R::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - 2nd data byte of a CAN Data Frame"]
    #[inline(always)]
    pub fn data1(&self) -> Data1R {
        Data1R::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - 3rd data byte of a CAN Data Frame"]
    #[inline(always)]
    pub fn data2(&self) -> Data2R {
        Data2R::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - 4th data byte of a CAN Data Frame"]
    #[inline(always)]
    pub fn data3(&self) -> Data3R {
        Data3R::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - 1st data byte of a CAN Data Frame"]
    #[inline(always)]
    #[must_use]
    pub fn data0(&mut self) -> Data0W<MsgifgrpIf2daSpec> {
        Data0W::new(self, 0)
    }
    #[doc = "Bits 8:15 - 2nd data byte of a CAN Data Frame"]
    #[inline(always)]
    #[must_use]
    pub fn data1(&mut self) -> Data1W<MsgifgrpIf2daSpec> {
        Data1W::new(self, 8)
    }
    #[doc = "Bits 16:23 - 3rd data byte of a CAN Data Frame"]
    #[inline(always)]
    #[must_use]
    pub fn data2(&mut self) -> Data2W<MsgifgrpIf2daSpec> {
        Data2W::new(self, 16)
    }
    #[doc = "Bits 24:31 - 4th data byte of a CAN Data Frame"]
    #[inline(always)]
    #[must_use]
    pub fn data3(&mut self) -> Data3W<MsgifgrpIf2daSpec> {
        Data3W::new(self, 24)
    }
}
#[doc = "The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2da::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2da::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsgifgrpIf2daSpec;
impl crate::RegisterSpec for MsgifgrpIf2daSpec {
    type Ux = u32;
    const OFFSET: u64 = 304u64;
}
#[doc = "`read()` method returns [`msgifgrp_if2da::R`](R) reader structure"]
impl crate::Readable for MsgifgrpIf2daSpec {}
#[doc = "`write(|w| ..)` method takes [`msgifgrp_if2da::W`](W) writer structure"]
impl crate::Writable for MsgifgrpIf2daSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets msgifgrp_IF2DA to value 0"]
impl crate::Resettable for MsgifgrpIf2daSpec {
    const RESET_VALUE: u32 = 0;
}
