// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mainpllgrp_tracediv` reader"]
pub type R = crate::R<MainpllgrpTracedivSpec>;
#[doc = "Register `mainpllgrp_tracediv` writer"]
pub type W = crate::W<MainpllgrpTracedivSpec>;
#[doc = "The dbg_trace_clk is divided down from the C2 output of the Main PLL by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Traceclk {
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
impl From<Traceclk> for u8 {
    #[inline(always)]
    fn from(variant: Traceclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Traceclk {
    type Ux = u8;
}
#[doc = "Field `traceclk` reader - The dbg_trace_clk is divided down from the C2 output of the Main PLL by the value specified in this field."]
pub type TraceclkR = crate::FieldReader<Traceclk>;
impl TraceclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Traceclk {
        match self.bits {
            0 => Traceclk::Div1,
            1 => Traceclk::Div2,
            2 => Traceclk::Div4,
            3 => Traceclk::Div8,
            4 => Traceclk::Div16,
            5 => Traceclk::Reserved1,
            6 => Traceclk::Reserved2,
            7 => Traceclk::Reserved3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == Traceclk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == Traceclk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == Traceclk::Div4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_div8(&self) -> bool {
        *self == Traceclk::Div8
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_div16(&self) -> bool {
        *self == Traceclk::Div16
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved_1(&self) -> bool {
        *self == Traceclk::Reserved1
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_reserved_2(&self) -> bool {
        *self == Traceclk::Reserved2
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_reserved_3(&self) -> bool {
        *self == Traceclk::Reserved3
    }
}
#[doc = "Field `traceclk` writer - The dbg_trace_clk is divided down from the C2 output of the Main PLL by the value specified in this field."]
pub type TraceclkW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Traceclk>;
impl<'a, REG> TraceclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(Traceclk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(Traceclk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(Traceclk::Div4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn div8(self) -> &'a mut crate::W<REG> {
        self.variant(Traceclk::Div8)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn div16(self) -> &'a mut crate::W<REG> {
        self.variant(Traceclk::Div16)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved_1(self) -> &'a mut crate::W<REG> {
        self.variant(Traceclk::Reserved1)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn reserved_2(self) -> &'a mut crate::W<REG> {
        self.variant(Traceclk::Reserved2)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn reserved_3(self) -> &'a mut crate::W<REG> {
        self.variant(Traceclk::Reserved3)
    }
}
impl R {
    #[doc = "Bits 0:2 - The dbg_trace_clk is divided down from the C2 output of the Main PLL by the value specified in this field."]
    #[inline(always)]
    pub fn traceclk(&self) -> TraceclkR {
        TraceclkR::new((self.bits & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - The dbg_trace_clk is divided down from the C2 output of the Main PLL by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn traceclk(&mut self) -> TraceclkW<MainpllgrpTracedivSpec> {
        TraceclkW::new(self, 0)
    }
}
#[doc = "Contains a field that controls the clock divider for the debug trace clock derived from the Main PLL Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_tracediv::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_tracediv::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MainpllgrpTracedivSpec;
impl crate::RegisterSpec for MainpllgrpTracedivSpec {
    type Ux = u32;
    const OFFSET: u64 = 108u64;
}
#[doc = "`read()` method returns [`mainpllgrp_tracediv::R`](R) reader structure"]
impl crate::Readable for MainpllgrpTracedivSpec {}
#[doc = "`write(|w| ..)` method takes [`mainpllgrp_tracediv::W`](W) writer structure"]
impl crate::Writable for MainpllgrpTracedivSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mainpllgrp_tracediv to value 0"]
impl crate::Resettable for MainpllgrpTracedivSpec {
    const RESET_VALUE: u32 = 0;
}
