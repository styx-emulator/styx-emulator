// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `DBGMCU_APB2_FZ` reader"]
pub type R = crate::R<DbgmcuApb2FzSpec>;
#[doc = "Register `DBGMCU_APB2_FZ` writer"]
pub type W = crate::W<DbgmcuApb2FzSpec>;
#[doc = "Field `DBG_TIM1_STOP` reader - TIM1 counter stopped when core is halted"]
pub type DbgTim1StopR = crate::BitReader;
#[doc = "Field `DBG_TIM1_STOP` writer - TIM1 counter stopped when core is halted"]
pub type DbgTim1StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM8_STOP` reader - TIM8 counter stopped when core is halted"]
pub type DbgTim8StopR = crate::BitReader;
#[doc = "Field `DBG_TIM8_STOP` writer - TIM8 counter stopped when core is halted"]
pub type DbgTim8StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM9_STOP` reader - TIM9 counter stopped when core is halted"]
pub type DbgTim9StopR = crate::BitReader;
#[doc = "Field `DBG_TIM9_STOP` writer - TIM9 counter stopped when core is halted"]
pub type DbgTim9StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM10_STOP` reader - TIM10 counter stopped when core is halted"]
pub type DbgTim10StopR = crate::BitReader;
#[doc = "Field `DBG_TIM10_STOP` writer - TIM10 counter stopped when core is halted"]
pub type DbgTim10StopW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBG_TIM11_STOP` reader - TIM11 counter stopped when core is halted"]
pub type DbgTim11StopR = crate::BitReader;
#[doc = "Field `DBG_TIM11_STOP` writer - TIM11 counter stopped when core is halted"]
pub type DbgTim11StopW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - TIM1 counter stopped when core is halted"]
    #[inline(always)]
    pub fn dbg_tim1_stop(&self) -> DbgTim1StopR {
        DbgTim1StopR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - TIM8 counter stopped when core is halted"]
    #[inline(always)]
    pub fn dbg_tim8_stop(&self) -> DbgTim8StopR {
        DbgTim8StopR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 16 - TIM9 counter stopped when core is halted"]
    #[inline(always)]
    pub fn dbg_tim9_stop(&self) -> DbgTim9StopR {
        DbgTim9StopR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - TIM10 counter stopped when core is halted"]
    #[inline(always)]
    pub fn dbg_tim10_stop(&self) -> DbgTim10StopR {
        DbgTim10StopR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - TIM11 counter stopped when core is halted"]
    #[inline(always)]
    pub fn dbg_tim11_stop(&self) -> DbgTim11StopR {
        DbgTim11StopR::new(((self.bits >> 18) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - TIM1 counter stopped when core is halted"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim1_stop(&mut self) -> DbgTim1StopW<DbgmcuApb2FzSpec> {
        DbgTim1StopW::new(self, 0)
    }
    #[doc = "Bit 1 - TIM8 counter stopped when core is halted"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim8_stop(&mut self) -> DbgTim8StopW<DbgmcuApb2FzSpec> {
        DbgTim8StopW::new(self, 1)
    }
    #[doc = "Bit 16 - TIM9 counter stopped when core is halted"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim9_stop(&mut self) -> DbgTim9StopW<DbgmcuApb2FzSpec> {
        DbgTim9StopW::new(self, 16)
    }
    #[doc = "Bit 17 - TIM10 counter stopped when core is halted"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim10_stop(&mut self) -> DbgTim10StopW<DbgmcuApb2FzSpec> {
        DbgTim10StopW::new(self, 17)
    }
    #[doc = "Bit 18 - TIM11 counter stopped when core is halted"]
    #[inline(always)]
    #[must_use]
    pub fn dbg_tim11_stop(&mut self) -> DbgTim11StopW<DbgmcuApb2FzSpec> {
        DbgTim11StopW::new(self, 18)
    }
}
#[doc = "Debug MCU APB2 Freeze registe\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dbgmcu_apb2_fz::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dbgmcu_apb2_fz::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DbgmcuApb2FzSpec;
impl crate::RegisterSpec for DbgmcuApb2FzSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`dbgmcu_apb2_fz::R`](R) reader structure"]
impl crate::Readable for DbgmcuApb2FzSpec {}
#[doc = "`write(|w| ..)` method takes [`dbgmcu_apb2_fz::W`](W) writer structure"]
impl crate::Writable for DbgmcuApb2FzSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DBGMCU_APB2_FZ to value 0"]
impl crate::Resettable for DbgmcuApb2FzSpec {
    const RESET_VALUE: u32 = 0;
}
