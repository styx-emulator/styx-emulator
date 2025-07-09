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
#[doc = "Register `frzctrl_src` reader"]
pub type R = crate::R<FrzctrlSrcSpec>;
#[doc = "Register `frzctrl_src` writer"]
pub type W = crate::W<FrzctrlSrcSpec>;
#[doc = "The freeze signal source for VIO channel 1 (VIO bank 2 and bank 3).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vio1 {
    #[doc = "0: `0`"]
    Sw = 0,
    #[doc = "1: `1`"]
    Hw = 1,
}
impl From<Vio1> for bool {
    #[inline(always)]
    fn from(variant: Vio1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vio1` reader - The freeze signal source for VIO channel 1 (VIO bank 2 and bank 3)."]
pub type Vio1R = crate::BitReader<Vio1>;
impl Vio1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Vio1 {
        match self.bits {
            false => Vio1::Sw,
            true => Vio1::Hw,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_sw(&self) -> bool {
        *self == Vio1::Sw
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_hw(&self) -> bool {
        *self == Vio1::Hw
    }
}
#[doc = "Field `vio1` writer - The freeze signal source for VIO channel 1 (VIO bank 2 and bank 3)."]
pub type Vio1W<'a, REG> = crate::BitWriter<'a, REG, Vio1>;
impl<'a, REG> Vio1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn sw(self) -> &'a mut crate::W<REG> {
        self.variant(Vio1::Sw)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn hw(self) -> &'a mut crate::W<REG> {
        self.variant(Vio1::Hw)
    }
}
impl R {
    #[doc = "Bit 0 - The freeze signal source for VIO channel 1 (VIO bank 2 and bank 3)."]
    #[inline(always)]
    pub fn vio1(&self) -> Vio1R {
        Vio1R::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - The freeze signal source for VIO channel 1 (VIO bank 2 and bank 3)."]
    #[inline(always)]
    #[must_use]
    pub fn vio1(&mut self) -> Vio1W<FrzctrlSrcSpec> {
        Vio1W::new(self, 0)
    }
}
#[doc = "Contains register field to choose between software state machine (vioctrl array index \\[1\\]
register) or hardware state machine in the Freeze Controller as the freeze signal source for VIO channel 1. All fields are only reset by a cold reset (ignore warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`frzctrl_src::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`frzctrl_src::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FrzctrlSrcSpec;
impl crate::RegisterSpec for FrzctrlSrcSpec {
    type Ux = u32;
    const OFFSET: u64 = 84u64;
}
#[doc = "`read()` method returns [`frzctrl_src::R`](R) reader structure"]
impl crate::Readable for FrzctrlSrcSpec {}
#[doc = "`write(|w| ..)` method takes [`frzctrl_src::W`](W) writer structure"]
impl crate::Writable for FrzctrlSrcSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets frzctrl_src to value 0"]
impl crate::Resettable for FrzctrlSrcSpec {
    const RESET_VALUE: u32 = 0;
}
