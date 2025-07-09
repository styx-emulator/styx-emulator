// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `timer1controlreg` reader"]
pub type R = crate::R<Timer1controlregSpec>;
#[doc = "Register `timer1controlreg` writer"]
pub type W = crate::W<Timer1controlregSpec>;
#[doc = "Timer1 enable/disable bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer1Enable {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Timer1Enable> for bool {
    #[inline(always)]
    fn from(variant: Timer1Enable) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `timer1_enable` reader - Timer1 enable/disable bit."]
pub type Timer1EnableR = crate::BitReader<Timer1Enable>;
impl Timer1EnableR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Timer1Enable {
        match self.bits {
            false => Timer1Enable::Disabled,
            true => Timer1Enable::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Timer1Enable::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Timer1Enable::Enabled
    }
}
#[doc = "Field `timer1_enable` writer - Timer1 enable/disable bit."]
pub type Timer1EnableW<'a, REG> = crate::BitWriter<'a, REG, Timer1Enable>;
impl<'a, REG> Timer1EnableW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Timer1Enable::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Timer1Enable::Enabled)
    }
}
#[doc = "Sets operating mode. NOTE: You must set the timer1loadcount register to all ones before enabling the timer in free-running mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer1Mode {
    #[doc = "0: `0`"]
    Freerun = 0,
    #[doc = "1: `1`"]
    Usedef = 1,
}
impl From<Timer1Mode> for bool {
    #[inline(always)]
    fn from(variant: Timer1Mode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `timer1_mode` reader - Sets operating mode. NOTE: You must set the timer1loadcount register to all ones before enabling the timer in free-running mode."]
pub type Timer1ModeR = crate::BitReader<Timer1Mode>;
impl Timer1ModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Timer1Mode {
        match self.bits {
            false => Timer1Mode::Freerun,
            true => Timer1Mode::Usedef,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_freerun(&self) -> bool {
        *self == Timer1Mode::Freerun
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_usedef(&self) -> bool {
        *self == Timer1Mode::Usedef
    }
}
#[doc = "Field `timer1_mode` writer - Sets operating mode. NOTE: You must set the timer1loadcount register to all ones before enabling the timer in free-running mode."]
pub type Timer1ModeW<'a, REG> = crate::BitWriter<'a, REG, Timer1Mode>;
impl<'a, REG> Timer1ModeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn freerun(self) -> &'a mut crate::W<REG> {
        self.variant(Timer1Mode::Freerun)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn usedef(self) -> &'a mut crate::W<REG> {
        self.variant(Timer1Mode::Usedef)
    }
}
#[doc = "Timer1 interrupt mask\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer1InterruptMask {
    #[doc = "0: `0`"]
    Notmasked = 0,
    #[doc = "1: `1`"]
    Masked = 1,
}
impl From<Timer1InterruptMask> for bool {
    #[inline(always)]
    fn from(variant: Timer1InterruptMask) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `timer1_interrupt_mask` reader - Timer1 interrupt mask"]
pub type Timer1InterruptMaskR = crate::BitReader<Timer1InterruptMask>;
impl Timer1InterruptMaskR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Timer1InterruptMask {
        match self.bits {
            false => Timer1InterruptMask::Notmasked,
            true => Timer1InterruptMask::Masked,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notmasked(&self) -> bool {
        *self == Timer1InterruptMask::Notmasked
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_masked(&self) -> bool {
        *self == Timer1InterruptMask::Masked
    }
}
#[doc = "Field `timer1_interrupt_mask` writer - Timer1 interrupt mask"]
pub type Timer1InterruptMaskW<'a, REG> = crate::BitWriter<'a, REG, Timer1InterruptMask>;
impl<'a, REG> Timer1InterruptMaskW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notmasked(self) -> &'a mut crate::W<REG> {
        self.variant(Timer1InterruptMask::Notmasked)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn masked(self) -> &'a mut crate::W<REG> {
        self.variant(Timer1InterruptMask::Masked)
    }
}
impl R {
    #[doc = "Bit 0 - Timer1 enable/disable bit."]
    #[inline(always)]
    pub fn timer1_enable(&self) -> Timer1EnableR {
        Timer1EnableR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Sets operating mode. NOTE: You must set the timer1loadcount register to all ones before enabling the timer in free-running mode."]
    #[inline(always)]
    pub fn timer1_mode(&self) -> Timer1ModeR {
        Timer1ModeR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Timer1 interrupt mask"]
    #[inline(always)]
    pub fn timer1_interrupt_mask(&self) -> Timer1InterruptMaskR {
        Timer1InterruptMaskR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Timer1 enable/disable bit."]
    #[inline(always)]
    #[must_use]
    pub fn timer1_enable(&mut self) -> Timer1EnableW<Timer1controlregSpec> {
        Timer1EnableW::new(self, 0)
    }
    #[doc = "Bit 1 - Sets operating mode. NOTE: You must set the timer1loadcount register to all ones before enabling the timer in free-running mode."]
    #[inline(always)]
    #[must_use]
    pub fn timer1_mode(&mut self) -> Timer1ModeW<Timer1controlregSpec> {
        Timer1ModeW::new(self, 1)
    }
    #[doc = "Bit 2 - Timer1 interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn timer1_interrupt_mask(&mut self) -> Timer1InterruptMaskW<Timer1controlregSpec> {
        Timer1InterruptMaskW::new(self, 2)
    }
}
#[doc = "This register controls enabling, operating mode (free-running or user-defined-count), and interrupt mask of Timer1. You can program this register to enable or disable Timer1 and to control its mode of operation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1controlreg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`timer1controlreg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Timer1controlregSpec;
impl crate::RegisterSpec for Timer1controlregSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`timer1controlreg::R`](R) reader structure"]
impl crate::Readable for Timer1controlregSpec {}
#[doc = "`write(|w| ..)` method takes [`timer1controlreg::W`](W) writer structure"]
impl crate::Writable for Timer1controlregSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets timer1controlreg to value 0"]
impl crate::Resettable for Timer1controlregSpec {
    const RESET_VALUE: u32 = 0;
}
