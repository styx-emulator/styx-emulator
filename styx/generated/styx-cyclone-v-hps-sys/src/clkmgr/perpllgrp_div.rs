// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `perpllgrp_div` reader"]
pub type R = crate::R<PerpllgrpDivSpec>;
#[doc = "Register `perpllgrp_div` writer"]
pub type W = crate::W<PerpllgrpDivSpec>;
#[doc = "The usb_mp_clk is divided down from the periph_base_clk by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Usbclk {
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
impl From<Usbclk> for u8 {
    #[inline(always)]
    fn from(variant: Usbclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Usbclk {
    type Ux = u8;
}
#[doc = "Field `usbclk` reader - The usb_mp_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type UsbclkR = crate::FieldReader<Usbclk>;
impl UsbclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Usbclk {
        match self.bits {
            0 => Usbclk::Div1,
            1 => Usbclk::Div2,
            2 => Usbclk::Div4,
            3 => Usbclk::Div8,
            4 => Usbclk::Div16,
            5 => Usbclk::Reserved1,
            6 => Usbclk::Reserved2,
            7 => Usbclk::Reserved3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == Usbclk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == Usbclk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == Usbclk::Div4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_div8(&self) -> bool {
        *self == Usbclk::Div8
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_div16(&self) -> bool {
        *self == Usbclk::Div16
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved_1(&self) -> bool {
        *self == Usbclk::Reserved1
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_reserved_2(&self) -> bool {
        *self == Usbclk::Reserved2
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_reserved_3(&self) -> bool {
        *self == Usbclk::Reserved3
    }
}
#[doc = "Field `usbclk` writer - The usb_mp_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type UsbclkW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Usbclk>;
impl<'a, REG> UsbclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(Usbclk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(Usbclk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(Usbclk::Div4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn div8(self) -> &'a mut crate::W<REG> {
        self.variant(Usbclk::Div8)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn div16(self) -> &'a mut crate::W<REG> {
        self.variant(Usbclk::Div16)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved_1(self) -> &'a mut crate::W<REG> {
        self.variant(Usbclk::Reserved1)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn reserved_2(self) -> &'a mut crate::W<REG> {
        self.variant(Usbclk::Reserved2)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn reserved_3(self) -> &'a mut crate::W<REG> {
        self.variant(Usbclk::Reserved3)
    }
}
#[doc = "The spi_m_clk is divided down from the periph_base_clk by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Spimclk {
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
impl From<Spimclk> for u8 {
    #[inline(always)]
    fn from(variant: Spimclk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Spimclk {
    type Ux = u8;
}
#[doc = "Field `spimclk` reader - The spi_m_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type SpimclkR = crate::FieldReader<Spimclk>;
impl SpimclkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Spimclk {
        match self.bits {
            0 => Spimclk::Div1,
            1 => Spimclk::Div2,
            2 => Spimclk::Div4,
            3 => Spimclk::Div8,
            4 => Spimclk::Div16,
            5 => Spimclk::Reserved1,
            6 => Spimclk::Reserved2,
            7 => Spimclk::Reserved3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == Spimclk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == Spimclk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == Spimclk::Div4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_div8(&self) -> bool {
        *self == Spimclk::Div8
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_div16(&self) -> bool {
        *self == Spimclk::Div16
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved_1(&self) -> bool {
        *self == Spimclk::Reserved1
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_reserved_2(&self) -> bool {
        *self == Spimclk::Reserved2
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_reserved_3(&self) -> bool {
        *self == Spimclk::Reserved3
    }
}
#[doc = "Field `spimclk` writer - The spi_m_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type SpimclkW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Spimclk>;
impl<'a, REG> SpimclkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(Spimclk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(Spimclk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(Spimclk::Div4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn div8(self) -> &'a mut crate::W<REG> {
        self.variant(Spimclk::Div8)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn div16(self) -> &'a mut crate::W<REG> {
        self.variant(Spimclk::Div16)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved_1(self) -> &'a mut crate::W<REG> {
        self.variant(Spimclk::Reserved1)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn reserved_2(self) -> &'a mut crate::W<REG> {
        self.variant(Spimclk::Reserved2)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn reserved_3(self) -> &'a mut crate::W<REG> {
        self.variant(Spimclk::Reserved3)
    }
}
#[doc = "The can0_clk is divided down from the periph_base_clk by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Can0clk {
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
impl From<Can0clk> for u8 {
    #[inline(always)]
    fn from(variant: Can0clk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Can0clk {
    type Ux = u8;
}
#[doc = "Field `can0clk` reader - The can0_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type Can0clkR = crate::FieldReader<Can0clk>;
impl Can0clkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Can0clk {
        match self.bits {
            0 => Can0clk::Div1,
            1 => Can0clk::Div2,
            2 => Can0clk::Div4,
            3 => Can0clk::Div8,
            4 => Can0clk::Div16,
            5 => Can0clk::Reserved1,
            6 => Can0clk::Reserved2,
            7 => Can0clk::Reserved3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == Can0clk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == Can0clk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == Can0clk::Div4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_div8(&self) -> bool {
        *self == Can0clk::Div8
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_div16(&self) -> bool {
        *self == Can0clk::Div16
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved_1(&self) -> bool {
        *self == Can0clk::Reserved1
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_reserved_2(&self) -> bool {
        *self == Can0clk::Reserved2
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_reserved_3(&self) -> bool {
        *self == Can0clk::Reserved3
    }
}
#[doc = "Field `can0clk` writer - The can0_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type Can0clkW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Can0clk>;
impl<'a, REG> Can0clkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(Can0clk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(Can0clk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(Can0clk::Div4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn div8(self) -> &'a mut crate::W<REG> {
        self.variant(Can0clk::Div8)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn div16(self) -> &'a mut crate::W<REG> {
        self.variant(Can0clk::Div16)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved_1(self) -> &'a mut crate::W<REG> {
        self.variant(Can0clk::Reserved1)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn reserved_2(self) -> &'a mut crate::W<REG> {
        self.variant(Can0clk::Reserved2)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn reserved_3(self) -> &'a mut crate::W<REG> {
        self.variant(Can0clk::Reserved3)
    }
}
#[doc = "The can1_clk is divided down from the periph_base_clk by the value specified in this field.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Can1clk {
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
impl From<Can1clk> for u8 {
    #[inline(always)]
    fn from(variant: Can1clk) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Can1clk {
    type Ux = u8;
}
#[doc = "Field `can1clk` reader - The can1_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type Can1clkR = crate::FieldReader<Can1clk>;
impl Can1clkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Can1clk {
        match self.bits {
            0 => Can1clk::Div1,
            1 => Can1clk::Div2,
            2 => Can1clk::Div4,
            3 => Can1clk::Div8,
            4 => Can1clk::Div16,
            5 => Can1clk::Reserved1,
            6 => Can1clk::Reserved2,
            7 => Can1clk::Reserved3,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div1(&self) -> bool {
        *self == Can1clk::Div1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div2(&self) -> bool {
        *self == Can1clk::Div2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == Can1clk::Div4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_div8(&self) -> bool {
        *self == Can1clk::Div8
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_div16(&self) -> bool {
        *self == Can1clk::Div16
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved_1(&self) -> bool {
        *self == Can1clk::Reserved1
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_reserved_2(&self) -> bool {
        *self == Can1clk::Reserved2
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_reserved_3(&self) -> bool {
        *self == Can1clk::Reserved3
    }
}
#[doc = "Field `can1clk` writer - The can1_clk is divided down from the periph_base_clk by the value specified in this field."]
pub type Can1clkW<'a, REG> = crate::FieldWriterSafe<'a, REG, 3, Can1clk>;
impl<'a, REG> Can1clkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div1(self) -> &'a mut crate::W<REG> {
        self.variant(Can1clk::Div1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div2(self) -> &'a mut crate::W<REG> {
        self.variant(Can1clk::Div2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(Can1clk::Div4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn div8(self) -> &'a mut crate::W<REG> {
        self.variant(Can1clk::Div8)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn div16(self) -> &'a mut crate::W<REG> {
        self.variant(Can1clk::Div16)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved_1(self) -> &'a mut crate::W<REG> {
        self.variant(Can1clk::Reserved1)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn reserved_2(self) -> &'a mut crate::W<REG> {
        self.variant(Can1clk::Reserved2)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn reserved_3(self) -> &'a mut crate::W<REG> {
        self.variant(Can1clk::Reserved3)
    }
}
impl R {
    #[doc = "Bits 0:2 - The usb_mp_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    pub fn usbclk(&self) -> UsbclkR {
        UsbclkR::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 3:5 - The spi_m_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    pub fn spimclk(&self) -> SpimclkR {
        SpimclkR::new(((self.bits >> 3) & 7) as u8)
    }
    #[doc = "Bits 6:8 - The can0_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    pub fn can0clk(&self) -> Can0clkR {
        Can0clkR::new(((self.bits >> 6) & 7) as u8)
    }
    #[doc = "Bits 9:11 - The can1_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    pub fn can1clk(&self) -> Can1clkR {
        Can1clkR::new(((self.bits >> 9) & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - The usb_mp_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn usbclk(&mut self) -> UsbclkW<PerpllgrpDivSpec> {
        UsbclkW::new(self, 0)
    }
    #[doc = "Bits 3:5 - The spi_m_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn spimclk(&mut self) -> SpimclkW<PerpllgrpDivSpec> {
        SpimclkW::new(self, 3)
    }
    #[doc = "Bits 6:8 - The can0_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn can0clk(&mut self) -> Can0clkW<PerpllgrpDivSpec> {
        Can0clkW::new(self, 6)
    }
    #[doc = "Bits 9:11 - The can1_clk is divided down from the periph_base_clk by the value specified in this field."]
    #[inline(always)]
    #[must_use]
    pub fn can1clk(&mut self) -> Can1clkW<PerpllgrpDivSpec> {
        Can1clkW::new(self, 9)
    }
}
#[doc = "Contains fields that control clock dividers for clocks derived from the Peripheral PLL Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_div::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_div::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PerpllgrpDivSpec;
impl crate::RegisterSpec for PerpllgrpDivSpec {
    type Ux = u32;
    const OFFSET: u64 = 164u64;
}
#[doc = "`read()` method returns [`perpllgrp_div::R`](R) reader structure"]
impl crate::Readable for PerpllgrpDivSpec {}
#[doc = "`write(|w| ..)` method takes [`perpllgrp_div::W`](W) writer structure"]
impl crate::Writable for PerpllgrpDivSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets perpllgrp_div to value 0"]
impl crate::Resettable for PerpllgrpDivSpec {
    const RESET_VALUE: u32 = 0;
}
