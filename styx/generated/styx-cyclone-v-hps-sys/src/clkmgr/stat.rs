// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `stat` reader"]
pub type R = crate::R<StatSpec>;
#[doc = "Register `stat` writer"]
pub type W = crate::W<StatSpec>;
#[doc = "This read only bit indicates that the Hardware Managed clock's state machine is active. If the state machine is active, then the clocks are in transition. Software should poll this bit after changing the source of internal clocks when writing to the BYPASS, CTRL or DBCTRL registers. Immediately following writes to any of these registers, SW should wait until this bit is IDLE before proceeding with any other register writes in the Clock Manager. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Busy {
    #[doc = "0: `0`"]
    Idle = 0,
    #[doc = "1: `1`"]
    Busy = 1,
}
impl From<Busy> for bool {
    #[inline(always)]
    fn from(variant: Busy) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `busy` reader - This read only bit indicates that the Hardware Managed clock's state machine is active. If the state machine is active, then the clocks are in transition. Software should poll this bit after changing the source of internal clocks when writing to the BYPASS, CTRL or DBCTRL registers. Immediately following writes to any of these registers, SW should wait until this bit is IDLE before proceeding with any other register writes in the Clock Manager. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type BusyR = crate::BitReader<Busy>;
impl BusyR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Busy {
        match self.bits {
            false => Busy::Idle,
            true => Busy::Busy,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        *self == Busy::Idle
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_busy(&self) -> bool {
        *self == Busy::Busy
    }
}
#[doc = "Field `busy` writer - This read only bit indicates that the Hardware Managed clock's state machine is active. If the state machine is active, then the clocks are in transition. Software should poll this bit after changing the source of internal clocks when writing to the BYPASS, CTRL or DBCTRL registers. Immediately following writes to any of these registers, SW should wait until this bit is IDLE before proceeding with any other register writes in the Clock Manager. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
pub type BusyW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This read only bit indicates that the Hardware Managed clock's state machine is active. If the state machine is active, then the clocks are in transition. Software should poll this bit after changing the source of internal clocks when writing to the BYPASS, CTRL or DBCTRL registers. Immediately following writes to any of these registers, SW should wait until this bit is IDLE before proceeding with any other register writes in the Clock Manager. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    pub fn busy(&self) -> BusyR {
        BusyR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This read only bit indicates that the Hardware Managed clock's state machine is active. If the state machine is active, then the clocks are in transition. Software should poll this bit after changing the source of internal clocks when writing to the BYPASS, CTRL or DBCTRL registers. Immediately following writes to any of these registers, SW should wait until this bit is IDLE before proceeding with any other register writes in the Clock Manager. The reset value of this bit is applied on a cold reset; warm reset has no affect on this bit."]
    #[inline(always)]
    #[must_use]
    pub fn busy(&mut self) -> BusyW<StatSpec> {
        BusyW::new(self, 0)
    }
}
#[doc = "Provides status of Hardware Managed Clock transition State Machine.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stat::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatSpec;
impl crate::RegisterSpec for StatSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`stat::R`](R) reader structure"]
impl crate::Readable for StatSpec {}
#[doc = "`reset()` method sets stat to value 0"]
impl crate::Resettable for StatSpec {
    const RESET_VALUE: u32 = 0;
}
