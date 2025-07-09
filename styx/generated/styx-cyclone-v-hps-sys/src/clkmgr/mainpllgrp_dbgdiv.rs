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
#[doc = "Register `mainpllgrp_dbgdiv` reader"]
pub type R = crate::R<MainpllgrpDbgdivSpec>;
#[doc = "Register `mainpllgrp_dbgdiv` writer"]
pub type W = crate::W<MainpllgrpDbgdivSpec>;
#[doc = "The dbg_at_clk is divided down from the C2 output of the Main PLL by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dbgatclk {
    #[doc = "0: `0`"]
    Div1 = 0,
    #[doc = "1: `1`"]
    Div2 = 1,
    #[doc = "2: `10`"]
    Div4 = 2,
}
impl From<Dbgatclk> for u8 {
    #[inline(always)]
    fn from(variant: Dbgatclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Dbgatclk {
    type Ux = u8;
}
#[doc = "Field `dbgatclk` reader - The dbg_at_clk is divided down from the C2 output of the Main PLL by the value specified in this field."]
pub type DbgatclkR = crate::FieldReader<Dbgatclk>;
impl DbgatclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Dbgatclk> {
        match self.bits {
            0 => Some(Dbgatclk::Div1),
            1 => Some(Dbgatclk::Div2),
            2 => Some(Dbgatclk::Div4),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == Dbgatclk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == Dbgatclk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == Dbgatclk::Div4
    }
}
#[doc = "Field `dbgatclk` writer - The dbg_at_clk is divided down from the C2 output of the Main PLL by the value specified in this field."]
pub type DbgatclkW<'a, REG> = crate::FieldWriter<'a, REG, 2, Dbgatclk>;
impl<'a, REG> DbgatclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(Dbgatclk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(Dbgatclk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(Dbgatclk::Div4)
    }
}
#[doc = "The dbg_clk is divided down from the dbg_at_clk by the value specified in this field.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dbgclk {
    #[doc = "1: `1`"]
    Div2 = 1,
    #[doc = "2: `10`"]
    Div4 = 2,
}
impl From<Dbgclk> for u8 {
    #[inline(always)]
    fn from(variant: Dbgclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Dbgclk {
    type Ux = u8;
}
#[doc = "Field `dbgclk` reader - The dbg_clk is divided down from the dbg_at_clk by the value specified in this field."]
pub type DbgclkR = crate::FieldReader<Dbgclk>;
impl DbgclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Dbgclk> {
        match self.bits {
            1 => Some(Dbgclk::Div2),
            2 => Some(Dbgclk::Div4),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == Dbgclk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == Dbgclk::Div4
    }
}
#[doc = "Field `dbgclk` writer - The dbg_clk is divided down from the dbg_at_clk by the value specified in this field."]
pub type DbgclkW<'a, REG> = crate::FieldWriter<'a, REG, 2, Dbgclk>;
impl<'a, REG> DbgclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(Dbgclk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(Dbgclk::Div4)
    }
}
impl R {
    #[doc = "Bits 0:1 - The dbg_at_clk is divided down from the C2 output of the Main PLL by the value specified in this field."]
    #[inline(always)]
    pub fn dbgatclk(&self) -> DbgatclkR {
        DbgatclkR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - The dbg_clk is divided down from the dbg_at_clk by the value specified in this field."]
    #[inline(always)]
    pub fn dbgclk(&self) -> DbgclkR {
        DbgclkR::new(((self.bits >> 2) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - The dbg_at_clk is divided down from the C2 output of the Main PLL by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn dbgatclk(&mut self) -> DbgatclkW<MainpllgrpDbgdivSpec> {
        DbgatclkW::new(self, 0)
    }
    #[doc = "Bits 2:3 - The dbg_clk is divided down from the dbg_at_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn dbgclk(&mut self) -> DbgclkW<MainpllgrpDbgdivSpec> {
        DbgclkW::new(self, 2)
    }
}
#[doc = "Contains fields that control clock dividers for debug clocks derived from the Main PLL Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_dbgdiv::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_dbgdiv::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MainpllgrpDbgdivSpec;
impl crate::RegisterSpec for MainpllgrpDbgdivSpec {
    type Ux = u32;
    const OFFSET: u64 = 104u64;
}
#[doc = "`read()` method returns [`mainpllgrp_dbgdiv::R`](R) reader structure"]
impl crate::Readable for MainpllgrpDbgdivSpec {}
#[doc = "`write(|w| ..)` method takes [`mainpllgrp_dbgdiv::W`](W) writer structure"]
impl crate::Writable for MainpllgrpDbgdivSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mainpllgrp_dbgdiv to value 0x04"]
impl crate::Resettable for MainpllgrpDbgdivSpec {
    const RESET_VALUE: u32 = 0x04;
}
