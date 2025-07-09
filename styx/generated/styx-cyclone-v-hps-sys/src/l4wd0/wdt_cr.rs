// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `wdt_cr` reader"]
pub type R = crate::R<WdtCrSpec>;
#[doc = "Register `wdt_cr` writer"]
pub type W = crate::W<WdtCrSpec>;
#[doc = "This bit is used to enable and disable the watchdog. When disabled, the counter does not decrement. Thus, no interrupts or warm reset requests are generated. Once this bit has been enabled, it can only be cleared only by resetting the watchdog.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WdtEn {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<WdtEn> for bool {
    #[inline(always)]
    fn from(variant: WdtEn) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wdt_en` reader - This bit is used to enable and disable the watchdog. When disabled, the counter does not decrement. Thus, no interrupts or warm reset requests are generated. Once this bit has been enabled, it can only be cleared only by resetting the watchdog."]
pub type WdtEnR = crate::BitReader<WdtEn>;
impl WdtEnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> WdtEn {
        match self.bits {
            false => WdtEn::Disabled,
            true => WdtEn::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == WdtEn::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == WdtEn::Enabled
    }
}
#[doc = "Field `wdt_en` writer - This bit is used to enable and disable the watchdog. When disabled, the counter does not decrement. Thus, no interrupts or warm reset requests are generated. Once this bit has been enabled, it can only be cleared only by resetting the watchdog."]
pub type WdtEnW<'a, REG> = crate::BitWriter<'a, REG, WdtEn>;
impl<'a, REG> WdtEnW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(WdtEn::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(WdtEn::Enabled)
    }
}
#[doc = "Selects the output response generated to a timeout.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rmod {
    #[doc = "0: `0`"]
    Rst = 0,
    #[doc = "1: `1`"]
    Irqrst = 1,
}
impl From<Rmod> for bool {
    #[inline(always)]
    fn from(variant: Rmod) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rmod` reader - Selects the output response generated to a timeout."]
pub type RmodR = crate::BitReader<Rmod>;
impl RmodR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rmod {
        match self.bits {
            false => Rmod::Rst,
            true => Rmod::Irqrst,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rst(&self) -> bool {
        *self == Rmod::Rst
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_irqrst(&self) -> bool {
        *self == Rmod::Irqrst
    }
}
#[doc = "Field `rmod` writer - Selects the output response generated to a timeout."]
pub type RmodW<'a, REG> = crate::BitWriter<'a, REG, Rmod>;
impl<'a, REG> RmodW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn rst(self) -> &'a mut crate::W<REG> {
        self.variant(Rmod::Rst)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn irqrst(self) -> &'a mut crate::W<REG> {
        self.variant(Rmod::Irqrst)
    }
}
impl R {
    #[doc = "Bit 0 - This bit is used to enable and disable the watchdog. When disabled, the counter does not decrement. Thus, no interrupts or warm reset requests are generated. Once this bit has been enabled, it can only be cleared only by resetting the watchdog."]
    #[inline(always)]
    pub fn wdt_en(&self) -> WdtEnR {
        WdtEnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Selects the output response generated to a timeout."]
    #[inline(always)]
    pub fn rmod(&self) -> RmodR {
        RmodR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is used to enable and disable the watchdog. When disabled, the counter does not decrement. Thus, no interrupts or warm reset requests are generated. Once this bit has been enabled, it can only be cleared only by resetting the watchdog."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_en(&mut self) -> WdtEnW<WdtCrSpec> {
        WdtEnW::new(self, 0)
    }
    #[doc = "Bit 1 - Selects the output response generated to a timeout."]
    #[inline(always)]
    #[must_use]
    pub fn rmod(&mut self) -> RmodW<WdtCrSpec> {
        RmodW::new(self, 1)
    }
}
#[doc = "Contains fields that control operating functions.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wdt_cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtCrSpec;
impl crate::RegisterSpec for WdtCrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`wdt_cr::R`](R) reader structure"]
impl crate::Readable for WdtCrSpec {}
#[doc = "`write(|w| ..)` method takes [`wdt_cr::W`](W) writer structure"]
impl crate::Writable for WdtCrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets wdt_cr to value 0x02"]
impl crate::Resettable for WdtCrSpec {
    const RESET_VALUE: u32 = 0x02;
}
