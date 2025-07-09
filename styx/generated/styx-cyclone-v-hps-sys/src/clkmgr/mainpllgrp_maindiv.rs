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
#[doc = "Register `mainpllgrp_maindiv` reader"]
pub type R = crate::R<MainpllgrpMaindivSpec>;
#[doc = "Register `mainpllgrp_maindiv` writer"]
pub type W = crate::W<MainpllgrpMaindivSpec>;
#[doc = "The l3_mp_clk is divided down from the l3_main_clk by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum L3mpclk {
    #[doc = "0: `0`"]
    Div1 = 0,
    #[doc = "1: `1`"]
    Div2 = 1,
}
impl From<L3mpclk> for u8 {
    #[inline(always)]
    fn from(variant: L3mpclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for L3mpclk {
    type Ux = u8;
}
#[doc = "Field `l3mpclk` reader - The l3_mp_clk is divided down from the l3_main_clk by the value specified in this field."]
pub type L3mpclkR = crate::FieldReader<L3mpclk>;
impl L3mpclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<L3mpclk> {
        match self.bits {
            0 => Some(L3mpclk::Div1),
            1 => Some(L3mpclk::Div2),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == L3mpclk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == L3mpclk::Div2
    }
}
#[doc = "Field `l3mpclk` writer - The l3_mp_clk is divided down from the l3_main_clk by the value specified in this field."]
pub type L3mpclkW<'a, REG> = crate::FieldWriter<'a, REG, 2, L3mpclk>;
impl<'a, REG> L3mpclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(L3mpclk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(L3mpclk::Div2)
    }
}
#[doc = "The l3_sp_clk is divided down from the l3_mp_clk by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum L3spclk {
    #[doc = "0: `0`"]
    Div1 = 0,
    #[doc = "1: `1`"]
    Div2 = 1,
}
impl From<L3spclk> for u8 {
    #[inline(always)]
    fn from(variant: L3spclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for L3spclk {
    type Ux = u8;
}
#[doc = "Field `l3spclk` reader - The l3_sp_clk is divided down from the l3_mp_clk by the value specified in this field."]
pub type L3spclkR = crate::FieldReader<L3spclk>;
impl L3spclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<L3spclk> {
        match self.bits {
            0 => Some(L3spclk::Div1),
            1 => Some(L3spclk::Div2),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == L3spclk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == L3spclk::Div2
    }
}
#[doc = "Field `l3spclk` writer - The l3_sp_clk is divided down from the l3_mp_clk by the value specified in this field."]
pub type L3spclkW<'a, REG> = crate::FieldWriter<'a, REG, 2, L3spclk>;
impl<'a, REG> L3spclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(L3spclk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(L3spclk::Div2)
    }
}
#[doc = "The l4_mp_clk is divided down from the periph_base_clk by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum L4mpclk {
    #[doc = "0: `0`"]
    Div1 = 0,
    #[doc = "1: `1`"]
    Div2 = 1,
    #[doc = "2: `10`"]
    Div4 = 2,
    #[doc = "3: `11`"]
    Div8 = 3,
    #[doc = "4: `100`"]
    Div16 = 4,
    #[doc = "5: `101`"]
    Reserved1 = 5,
    #[doc = "6: `110`"]
    Reserved2 = 6,
    #[doc = "7: `111`"]
    Reserved3 = 7,
}
impl From<L4mpclk> for u8 {
    #[inline(always)]
    fn from(variant: L4mpclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for L4mpclk {
    type Ux = u8;
}
#[doc = "Field `l4mpclk` reader - The l4_mp_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type L4mpclkR = crate::FieldReader<L4mpclk>;
impl L4mpclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> L4mpclk {
        match self.bits {
            0 => L4mpclk::Div1,
            1 => L4mpclk::Div2,
            2 => L4mpclk::Div4,
            3 => L4mpclk::Div8,
            4 => L4mpclk::Div16,
            5 => L4mpclk::Reserved1,
            6 => L4mpclk::Reserved2,
            7 => L4mpclk::Reserved3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == L4mpclk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == L4mpclk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == L4mpclk::Div4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_div8(&self) -> bool {
        *self == L4mpclk::Div8
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_div16(&self) -> bool {
        *self == L4mpclk::Div16
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved_1(&self) -> bool {
        *self == L4mpclk::Reserved1
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_reserved_2(&self) -> bool {
        *self == L4mpclk::Reserved2
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_reserved_3(&self) -> bool {
        *self == L4mpclk::Reserved3
    }
}
#[doc = "Field `l4mpclk` writer - The l4_mp_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type L4mpclkW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, L4mpclk>;
impl<'a, REG> L4mpclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(L4mpclk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(L4mpclk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(L4mpclk::Div4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn div8(self) -> &'a mut crate::W<REG> {
        self.variant(L4mpclk::Div8)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn div16(self) -> &'a mut crate::W<REG> {
        self.variant(L4mpclk::Div16)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved_1(self) -> &'a mut crate::W<REG> {
        self.variant(L4mpclk::Reserved1)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn reserved_2(self) -> &'a mut crate::W<REG> {
        self.variant(L4mpclk::Reserved2)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn reserved_3(self) -> &'a mut crate::W<REG> {
        self.variant(L4mpclk::Reserved3)
    }
}
#[doc = "The l4_sp_clk is divided down from the periph_base_clk by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum L4spclk {
    #[doc = "0: `0`"]
    Div1 = 0,
    #[doc = "1: `1`"]
    Div2 = 1,
    #[doc = "2: `10`"]
    Div4 = 2,
    #[doc = "3: `11`"]
    Div8 = 3,
    #[doc = "4: `100`"]
    Div16 = 4,
    #[doc = "5: `101`"]
    Reserved1 = 5,
    #[doc = "6: `110`"]
    Reserved2 = 6,
    #[doc = "7: `111`"]
    Reserved3 = 7,
}
impl From<L4spclk> for u8 {
    #[inline(always)]
    fn from(variant: L4spclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for L4spclk {
    type Ux = u8;
}
#[doc = "Field `l4spclk` reader - The l4_sp_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type L4spclkR = crate::FieldReader<L4spclk>;
impl L4spclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> L4spclk {
        match self.bits {
            0 => L4spclk::Div1,
            1 => L4spclk::Div2,
            2 => L4spclk::Div4,
            3 => L4spclk::Div8,
            4 => L4spclk::Div16,
            5 => L4spclk::Reserved1,
            6 => L4spclk::Reserved2,
            7 => L4spclk::Reserved3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == L4spclk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == L4spclk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == L4spclk::Div4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_div8(&self) -> bool {
        *self == L4spclk::Div8
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_div16(&self) -> bool {
        *self == L4spclk::Div16
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved_1(&self) -> bool {
        *self == L4spclk::Reserved1
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_reserved_2(&self) -> bool {
        *self == L4spclk::Reserved2
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_reserved_3(&self) -> bool {
        *self == L4spclk::Reserved3
    }
}
#[doc = "Field `l4spclk` writer - The l4_sp_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type L4spclkW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, L4spclk>;
impl<'a, REG> L4spclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(L4spclk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(L4spclk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(L4spclk::Div4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn div8(self) -> &'a mut crate::W<REG> {
        self.variant(L4spclk::Div8)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn div16(self) -> &'a mut crate::W<REG> {
        self.variant(L4spclk::Div16)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved_1(self) -> &'a mut crate::W<REG> {
        self.variant(L4spclk::Reserved1)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn reserved_2(self) -> &'a mut crate::W<REG> {
        self.variant(L4spclk::Reserved2)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn reserved_3(self) -> &'a mut crate::W<REG> {
        self.variant(L4spclk::Reserved3)
    }
}
impl R {
    #[doc = "Bits 0:1 - The l3_mp_clk is divided down from the l3_main_clk by the value specified in this field."]
    #[inline(always)]
    pub fn l3mpclk(&self) -> L3mpclkR {
        L3mpclkR::new((self.bits & 3) as u8)
    }
    #[doc = "Bits 2:3 - The l3_sp_clk is divided down from the l3_mp_clk by the value specified in this field."]
    #[inline(always)]
    pub fn l3spclk(&self) -> L3spclkR {
        L3spclkR::new(((self.bits >> 2) & 3) as u8)
    }
    #[doc = "Bits 4:6 - The l4_mp_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    pub fn l4mpclk(&self) -> L4mpclkR {
        L4mpclkR::new(((self.bits >> 4) & 7) as u8)
    }
    #[doc = "Bits 7:9 - The l4_sp_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    pub fn l4spclk(&self) -> L4spclkR {
        L4spclkR::new(((self.bits >> 7) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - The l3_mp_clk is divided down from the l3_main_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn l3mpclk(&mut self) -> L3mpclkW<MainpllgrpMaindivSpec> {
        L3mpclkW::new(self, 0)
    }
    #[doc = "Bits 2:3 - The l3_sp_clk is divided down from the l3_mp_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn l3spclk(&mut self) -> L3spclkW<MainpllgrpMaindivSpec> {
        L3spclkW::new(self, 2)
    }
    #[doc = "Bits 4:6 - The l4_mp_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn l4mpclk(&mut self) -> L4mpclkW<MainpllgrpMaindivSpec> {
        L4mpclkW::new(self, 4)
    }
    #[doc = "Bits 7:9 - The l4_sp_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn l4spclk(&mut self) -> L4spclkW<MainpllgrpMaindivSpec> {
        L4spclkW::new(self, 7)
    }
}
#[doc = "Contains fields that control clock dividers for main clocks derived from the Main PLL Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_maindiv::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_maindiv::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MainpllgrpMaindivSpec;
impl crate::RegisterSpec for MainpllgrpMaindivSpec {
    type Ux = u32;
    const OFFSET: u64 = 100u64;
}
#[doc = "`read()` method returns [`mainpllgrp_maindiv::R`](R) reader structure"]
impl crate::Readable for MainpllgrpMaindivSpec {}
#[doc = "`write(|w| ..)` method takes [`mainpllgrp_maindiv::W`](W) writer structure"]
impl crate::Writable for MainpllgrpMaindivSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mainpllgrp_maindiv to value 0"]
impl crate::Resettable for MainpllgrpMaindivSpec {
    const RESET_VALUE: u32 = 0;
}
