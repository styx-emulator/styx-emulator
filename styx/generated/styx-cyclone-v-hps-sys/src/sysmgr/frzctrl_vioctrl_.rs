// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `frzctrl_vioctrl_%s` reader"]
pub type R = crate::R<FrzctrlVioctrl_Spec>;
#[doc = "Register `frzctrl_vioctrl_%s` writer"]
pub type W = crate::W<FrzctrlVioctrl_Spec>;
#[doc = "Controls IO configuration\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cfg {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Cfg = 1,
}
impl From<Cfg> for bool {
    #[inline(always)]
    fn from(variant: Cfg) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cfg` reader - Controls IO configuration"]
pub type CfgR = crate::BitReader<Cfg>;
impl CfgR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cfg {
        match self.bits {
            false => Cfg::Disable,
            true => Cfg::Cfg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Cfg::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cfg(&self) -> bool {
        *self == Cfg::Cfg
    }
}
#[doc = "Field `cfg` writer - Controls IO configuration"]
pub type CfgW<'a, REG> = crate::BitWriter<'a, REG, Cfg>;
impl<'a, REG> CfgW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Cfg::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn cfg(self) -> &'a mut crate::W<REG> {
        self.variant(Cfg::Cfg)
    }
}
#[doc = "Controls bus hold circuit\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bushold {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Cfg = 1,
}
impl From<Bushold> for bool {
    #[inline(always)]
    fn from(variant: Bushold) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bushold` reader - Controls bus hold circuit"]
pub type BusholdR = crate::BitReader<Bushold>;
impl BusholdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bushold {
        match self.bits {
            false => Bushold::Disable,
            true => Bushold::Cfg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Bushold::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cfg(&self) -> bool {
        *self == Bushold::Cfg
    }
}
#[doc = "Field `bushold` writer - Controls bus hold circuit"]
pub type BusholdW<'a, REG> = crate::BitWriter<'a, REG, Bushold>;
impl<'a, REG> BusholdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Bushold::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn cfg(self) -> &'a mut crate::W<REG> {
        self.variant(Bushold::Cfg)
    }
}
#[doc = "Controls IO tri-state\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tristate {
    #[doc = "0: `0`"]
    Enable = 0,
    #[doc = "1: `1`"]
    Cfg = 1,
}
impl From<Tristate> for bool {
    #[inline(always)]
    fn from(variant: Tristate) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tristate` reader - Controls IO tri-state"]
pub type TristateR = crate::BitReader<Tristate>;
impl TristateR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tristate {
        match self.bits {
            false => Tristate::Enable,
            true => Tristate::Cfg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Tristate::Enable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cfg(&self) -> bool {
        *self == Tristate::Cfg
    }
}
#[doc = "Field `tristate` writer - Controls IO tri-state"]
pub type TristateW<'a, REG> = crate::BitWriter<'a, REG, Tristate>;
impl<'a, REG> TristateW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Tristate::Enable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn cfg(self) -> &'a mut crate::W<REG> {
        self.variant(Tristate::Cfg)
    }
}
#[doc = "Controls weak pullup resistor\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wkpullup {
    #[doc = "0: `0`"]
    Enable = 0,
    #[doc = "1: `1`"]
    Cfg = 1,
}
impl From<Wkpullup> for bool {
    #[inline(always)]
    fn from(variant: Wkpullup) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wkpullup` reader - Controls weak pullup resistor"]
pub type WkpullupR = crate::BitReader<Wkpullup>;
impl WkpullupR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Wkpullup {
        match self.bits {
            false => Wkpullup::Enable,
            true => Wkpullup::Cfg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Wkpullup::Enable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cfg(&self) -> bool {
        *self == Wkpullup::Cfg
    }
}
#[doc = "Field `wkpullup` writer - Controls weak pullup resistor"]
pub type WkpullupW<'a, REG> = crate::BitWriter<'a, REG, Wkpullup>;
impl<'a, REG> WkpullupW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Wkpullup::Enable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn cfg(self) -> &'a mut crate::W<REG> {
        self.variant(Wkpullup::Cfg)
    }
}
#[doc = "Controls IO slew-rate\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slew {
    #[doc = "0: `0`"]
    Slow = 0,
    #[doc = "1: `1`"]
    Cfg = 1,
}
impl From<Slew> for bool {
    #[inline(always)]
    fn from(variant: Slew) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `slew` reader - Controls IO slew-rate"]
pub type SlewR = crate::BitReader<Slew>;
impl SlewR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Slew {
        match self.bits {
            false => Slew::Slow,
            true => Slew::Cfg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_slow(&self) -> bool {
        *self == Slew::Slow
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cfg(&self) -> bool {
        *self == Slew::Cfg
    }
}
#[doc = "Field `slew` writer - Controls IO slew-rate"]
pub type SlewW<'a, REG> = crate::BitWriter<'a, REG, Slew>;
impl<'a, REG> SlewW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn slow(self) -> &'a mut crate::W<REG> {
        self.variant(Slew::Slow)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn cfg(self) -> &'a mut crate::W<REG> {
        self.variant(Slew::Cfg)
    }
}
impl R {
    #[doc = "Bit 0 - Controls IO configuration"]
    #[inline(always)]
    pub fn cfg(&self) -> CfgR {
        CfgR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls bus hold circuit"]
    #[inline(always)]
    pub fn bushold(&self) -> BusholdR {
        BusholdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controls IO tri-state"]
    #[inline(always)]
    pub fn tristate(&self) -> TristateR {
        TristateR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Controls weak pullup resistor"]
    #[inline(always)]
    pub fn wkpullup(&self) -> WkpullupR {
        WkpullupR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Controls IO slew-rate"]
    #[inline(always)]
    pub fn slew(&self) -> SlewR {
        SlewR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls IO configuration"]
    #[inline(always)]
    #[must_use]
    pub fn cfg(&mut self) -> CfgW<FrzctrlVioctrl_Spec> {
        CfgW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls bus hold circuit"]
    #[inline(always)]
    #[must_use]
    pub fn bushold(&mut self) -> BusholdW<FrzctrlVioctrl_Spec> {
        BusholdW::new(self, 1)
    }
    #[doc = "Bit 2 - Controls IO tri-state"]
    #[inline(always)]
    #[must_use]
    pub fn tristate(&mut self) -> TristateW<FrzctrlVioctrl_Spec> {
        TristateW::new(self, 2)
    }
    #[doc = "Bit 3 - Controls weak pullup resistor"]
    #[inline(always)]
    #[must_use]
    pub fn wkpullup(&mut self) -> WkpullupW<FrzctrlVioctrl_Spec> {
        WkpullupW::new(self, 3)
    }
    #[doc = "Bit 4 - Controls IO slew-rate"]
    #[inline(always)]
    #[must_use]
    pub fn slew(&mut self) -> SlewW<FrzctrlVioctrl_Spec> {
        SlewW::new(self, 4)
    }
}
#[doc = "Used to drive freeze signals to HPS VIO banks. The register array index corresponds to the freeze channel. Freeze channel 0 provides freeze signals to VIO bank 0 and 1. Freeze channel 1 provides freeze signals to VIO bank 2 and 3. Only drives freeze signals when SRC.VIO1 is set to SW. Freeze channel 2 provides freeze signals to VIO bank 4. All fields are only reset by a cold reset (ignore warm reset). The following equation determines when the weak pullup resistor is enabled: enabled = ~wkpullup | (CFF &amp; cfg &amp; tristate) where CFF is the value of weak pullup as set by IO configuration\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`frzctrl_vioctrl_::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`frzctrl_vioctrl_::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FrzctrlVioctrl_Spec;
impl crate::RegisterSpec for FrzctrlVioctrl_Spec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`frzctrl_vioctrl_::R`](R) reader structure"]
impl crate::Readable for FrzctrlVioctrl_Spec {}
#[doc = "`write(|w| ..)` method takes [`frzctrl_vioctrl_::W`](W) writer structure"]
impl crate::Writable for FrzctrlVioctrl_Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets frzctrl_vioctrl_%s to value 0"]
impl crate::Resettable for FrzctrlVioctrl_Spec {
    const RESET_VALUE: u32 = 0;
}
