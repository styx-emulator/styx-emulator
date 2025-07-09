// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DBGMCU_APB1_FZ` reader"]
pub type R = crate::R<DbgmcuApb1FzSpec>;
#[doc = "Register `DBGMCU_APB1_FZ` writer"]
pub type W = crate::W<DbgmcuApb1FzSpec>;
#[doc = "Field `DBG_TIM2_STOP` reader - DBG_TIM2_STOP"]
pub type DbgTim2StopR = crate::BitReader;
#[doc = "Field `DBG_TIM2_STOP` writer - DBG_TIM2_STOP"]
pub type DbgTim2StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM3_STOP` reader - DBG_TIM3 _STOP"]
pub type DbgTim3StopR = crate::BitReader;
#[doc = "Field `DBG_TIM3_STOP` writer - DBG_TIM3 _STOP"]
pub type DbgTim3StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM4_STOP` reader - DBG_TIM4_STOP"]
pub type DbgTim4StopR = crate::BitReader;
#[doc = "Field `DBG_TIM4_STOP` writer - DBG_TIM4_STOP"]
pub type DbgTim4StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM5_STOP` reader - DBG_TIM5_STOP"]
pub type DbgTim5StopR = crate::BitReader;
#[doc = "Field `DBG_TIM5_STOP` writer - DBG_TIM5_STOP"]
pub type DbgTim5StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM6_STOP` reader - DBG_TIM6_STOP"]
pub type DbgTim6StopR = crate::BitReader;
#[doc = "Field `DBG_TIM6_STOP` writer - DBG_TIM6_STOP"]
pub type DbgTim6StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM7_STOP` reader - DBG_TIM7_STOP"]
pub type DbgTim7StopR = crate::BitReader;
#[doc = "Field `DBG_TIM7_STOP` writer - DBG_TIM7_STOP"]
pub type DbgTim7StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM12_STOP` reader - DBG_TIM12_STOP"]
pub type DbgTim12StopR = crate::BitReader;
#[doc = "Field `DBG_TIM12_STOP` writer - DBG_TIM12_STOP"]
pub type DbgTim12StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM13_STOP` reader - DBG_TIM13_STOP"]
pub type DbgTim13StopR = crate::BitReader;
#[doc = "Field `DBG_TIM13_STOP` writer - DBG_TIM13_STOP"]
pub type DbgTim13StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM14_STOP` reader - DBG_TIM14_STOP"]
pub type DbgTim14StopR = crate::BitReader;
#[doc = "Field `DBG_TIM14_STOP` writer - DBG_TIM14_STOP"]
pub type DbgTim14StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_WWDG_STOP` reader - DBG_WWDG_STOP"]
pub type DbgWwdgStopR = crate::BitReader;
#[doc = "Field `DBG_WWDG_STOP` writer - DBG_WWDG_STOP"]
pub type DbgWwdgStopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_IWDEG_STOP` reader - DBG_IWDEG_STOP"]
pub type DbgIwdegStopR = crate::BitReader;
#[doc = "Field `DBG_IWDEG_STOP` writer - DBG_IWDEG_STOP"]
pub type DbgIwdegStopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_J2C1_SMBUS_TIMEOUT` reader - DBG_J2C1_SMBUS_TIMEOUT"]
pub type DbgJ2c1SmbusTimeoutR = crate::BitReader;
#[doc = "Field `DBG_J2C1_SMBUS_TIMEOUT` writer - DBG_J2C1_SMBUS_TIMEOUT"]
pub type DbgJ2c1SmbusTimeoutW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_J2C2_SMBUS_TIMEOUT` reader - DBG_J2C2_SMBUS_TIMEOUT"]
pub type DbgJ2c2SmbusTimeoutR = crate::BitReader;
#[doc = "Field `DBG_J2C2_SMBUS_TIMEOUT` writer - DBG_J2C2_SMBUS_TIMEOUT"]
pub type DbgJ2c2SmbusTimeoutW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_J2C3SMBUS_TIMEOUT` reader - DBG_J2C3SMBUS_TIMEOUT"]
pub type DbgJ2c3smbusTimeoutR = crate::BitReader;
#[doc = "Field `DBG_J2C3SMBUS_TIMEOUT` writer - DBG_J2C3SMBUS_TIMEOUT"]
pub type DbgJ2c3smbusTimeoutW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_CAN1_STOP` reader - DBG_CAN1_STOP"]
pub type DbgCan1StopR = crate::BitReader;
#[doc = "Field `DBG_CAN1_STOP` writer - DBG_CAN1_STOP"]
pub type DbgCan1StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_CAN2_STOP` reader - DBG_CAN2_STOP"]
pub type DbgCan2StopR = crate::BitReader;
#[doc = "Field `DBG_CAN2_STOP` writer - DBG_CAN2_STOP"]
pub type DbgCan2StopW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - DBG_TIM2_STOP"]
    #[inline(always)]
    pub fn dbg_tim2_stop(&self) -> DbgTim2StopR {
        DbgTim2StopR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - DBG_TIM3 _STOP"]
    #[inline(always)]
    pub fn dbg_tim3_stop(&self) -> DbgTim3StopR {
        DbgTim3StopR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - DBG_TIM4_STOP"]
    #[inline(always)]
    pub fn dbg_tim4_stop(&self) -> DbgTim4StopR {
        DbgTim4StopR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - DBG_TIM5_STOP"]
    #[inline(always)]
    pub fn dbg_tim5_stop(&self) -> DbgTim5StopR {
        DbgTim5StopR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - DBG_TIM6_STOP"]
    #[inline(always)]
    pub fn dbg_tim6_stop(&self) -> DbgTim6StopR {
        DbgTim6StopR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - DBG_TIM7_STOP"]
    #[inline(always)]
    pub fn dbg_tim7_stop(&self) -> DbgTim7StopR {
        DbgTim7StopR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - DBG_TIM12_STOP"]
    #[inline(always)]
    pub fn dbg_tim12_stop(&self) -> DbgTim12StopR {
        DbgTim12StopR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - DBG_TIM13_STOP"]
    #[inline(always)]
    pub fn dbg_tim13_stop(&self) -> DbgTim13StopR {
        DbgTim13StopR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - DBG_TIM14_STOP"]
    #[inline(always)]
    pub fn dbg_tim14_stop(&self) -> DbgTim14StopR {
        DbgTim14StopR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 11 - DBG_WWDG_STOP"]
    #[inline(always)]
    pub fn dbg_wwdg_stop(&self) -> DbgWwdgStopR {
        DbgWwdgStopR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - DBG_IWDEG_STOP"]
    #[inline(always)]
    pub fn dbg_iwdeg_stop(&self) -> DbgIwdegStopR {
        DbgIwdegStopR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 21 - DBG_J2C1_SMBUS_TIMEOUT"]
    #[inline(always)]
    pub fn dbg_j2c1_smbus_timeout(&self) -> DbgJ2c1SmbusTimeoutR {
        DbgJ2c1SmbusTimeoutR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - DBG_J2C2_SMBUS_TIMEOUT"]
    #[inline(always)]
    pub fn dbg_j2c2_smbus_timeout(&self) -> DbgJ2c2SmbusTimeoutR {
        DbgJ2c2SmbusTimeoutR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - DBG_J2C3SMBUS_TIMEOUT"]
    #[inline(always)]
    pub fn dbg_j2c3smbus_timeout(&self) -> DbgJ2c3smbusTimeoutR {
        DbgJ2c3smbusTimeoutR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 25 - DBG_CAN1_STOP"]
    #[inline(always)]
    pub fn dbg_can1_stop(&self) -> DbgCan1StopR {
        DbgCan1StopR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - DBG_CAN2_STOP"]
    #[inline(always)]
    pub fn dbg_can2_stop(&self) -> DbgCan2StopR {
        DbgCan2StopR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - DBG_TIM2_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim2_stop(&mut self) -> DbgTim2StopW<DbgmcuApb1FzSpec> {
        DbgTim2StopW::new(self, 0)
    }
    #[doc = "Bit 1 - DBG_TIM3 _STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim3_stop(&mut self) -> DbgTim3StopW<DbgmcuApb1FzSpec> {
        DbgTim3StopW::new(self, 1)
    }
    #[doc = "Bit 2 - DBG_TIM4_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim4_stop(&mut self) -> DbgTim4StopW<DbgmcuApb1FzSpec> {
        DbgTim4StopW::new(self, 2)
    }
    #[doc = "Bit 3 - DBG_TIM5_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim5_stop(&mut self) -> DbgTim5StopW<DbgmcuApb1FzSpec> {
        DbgTim5StopW::new(self, 3)
    }
    #[doc = "Bit 4 - DBG_TIM6_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim6_stop(&mut self) -> DbgTim6StopW<DbgmcuApb1FzSpec> {
        DbgTim6StopW::new(self, 4)
    }
    #[doc = "Bit 5 - DBG_TIM7_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim7_stop(&mut self) -> DbgTim7StopW<DbgmcuApb1FzSpec> {
        DbgTim7StopW::new(self, 5)
    }
    #[doc = "Bit 6 - DBG_TIM12_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim12_stop(&mut self) -> DbgTim12StopW<DbgmcuApb1FzSpec> {
        DbgTim12StopW::new(self, 6)
    }
    #[doc = "Bit 7 - DBG_TIM13_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim13_stop(&mut self) -> DbgTim13StopW<DbgmcuApb1FzSpec> {
        DbgTim13StopW::new(self, 7)
    }
    #[doc = "Bit 8 - DBG_TIM14_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim14_stop(&mut self) -> DbgTim14StopW<DbgmcuApb1FzSpec> {
        DbgTim14StopW::new(self, 8)
    }
    #[doc = "Bit 11 - DBG_WWDG_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_wwdg_stop(&mut self) -> DbgWwdgStopW<DbgmcuApb1FzSpec> {
        DbgWwdgStopW::new(self, 11)
    }
    #[doc = "Bit 12 - DBG_IWDEG_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_iwdeg_stop(&mut self) -> DbgIwdegStopW<DbgmcuApb1FzSpec> {
        DbgIwdegStopW::new(self, 12)
    }
    #[doc = "Bit 21 - DBG_J2C1_SMBUS_TIMEOUT"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_j2c1_smbus_timeout(&mut self) -> DbgJ2c1SmbusTimeoutW<DbgmcuApb1FzSpec> {
        DbgJ2c1SmbusTimeoutW::new(self, 21)
    }
    #[doc = "Bit 22 - DBG_J2C2_SMBUS_TIMEOUT"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_j2c2_smbus_timeout(&mut self) -> DbgJ2c2SmbusTimeoutW<DbgmcuApb1FzSpec> {
        DbgJ2c2SmbusTimeoutW::new(self, 22)
    }
    #[doc = "Bit 23 - DBG_J2C3SMBUS_TIMEOUT"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_j2c3smbus_timeout(&mut self) -> DbgJ2c3smbusTimeoutW<DbgmcuApb1FzSpec> {
        DbgJ2c3smbusTimeoutW::new(self, 23)
    }
    #[doc = "Bit 25 - DBG_CAN1_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_can1_stop(&mut self) -> DbgCan1StopW<DbgmcuApb1FzSpec> {
        DbgCan1StopW::new(self, 25)
    }
    #[doc = "Bit 26 - DBG_CAN2_STOP"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_can2_stop(&mut self) -> DbgCan2StopW<DbgmcuApb1FzSpec> {
        DbgCan2StopW::new(self, 26)
    }
}
#[doc = "Debug MCU APB1 Freeze registe\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbgmcu_apb1_fz::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbgmcu_apb1_fz::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DbgmcuApb1FzSpec;
impl crate::RegisterSpec for DbgmcuApb1FzSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`dbgmcu_apb1_fz::R`](R) reader structure"]
impl crate::Readable for DbgmcuApb1FzSpec {}
#[doc = "`write(|w| ..)` method takes [`dbgmcu_apb1_fz::W`](W) writer structure"]
impl crate::Writable for DbgmcuApb1FzSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DBGMCU_APB1_FZ to value 0"]
impl crate::Resettable for DbgmcuApb1FzSpec {
    const RESET_VALUE: u32 = 0;
}
