// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_System_Time_Nanoseconds_Update` reader"]
pub type R = crate::R<GmacgrpSystemTimeNanosecondsUpdateSpec>;
#[doc = "Register `gmacgrp_System_Time_Nanoseconds_Update` writer"]
pub type W = crate::W<GmacgrpSystemTimeNanosecondsUpdateSpec>;
#[doc = "Field `tsss` reader - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When bit 9 (TSCTRLSSR) is set in Register 448 (Timestamp Control Register), each bit represents 1 ns and the programmed value should not exceed 0x3B9A_C9FF."]
pub type TsssR = crate::FieldReader<u32>;
#[doc = "Field `tsss` writer - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When bit 9 (TSCTRLSSR) is set in Register 448 (Timestamp Control Register), each bit represents 1 ns and the programmed value should not exceed 0x3B9A_C9FF."]
pub type TsssW<'a, REG> = crate::FieldWriter<'a, REG, 31, u32>;
#[doc = "When this bit is set, the time value is subtracted with the contents of the update register. When this bit is reset, the time value is added with the contents of the update register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addsub {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Addsub> for bool {
    #[inline(always)]
    fn from(variant: Addsub) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `addsub` reader - When this bit is set, the time value is subtracted with the contents of the update register. When this bit is reset, the time value is added with the contents of the update register."]
pub type AddsubR = crate::BitReader<Addsub>;
impl AddsubR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Addsub {
        match self.bits {
            false => Addsub::Disabled,
            true => Addsub::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Addsub::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Addsub::Enabled
    }
}
#[doc = "Field `addsub` writer - When this bit is set, the time value is subtracted with the contents of the update register. When this bit is reset, the time value is added with the contents of the update register."]
pub type AddsubW<'a, REG> = crate::BitWriter<'a, REG, Addsub>;
impl<'a, REG> AddsubW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Addsub::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Addsub::Enabled)
    }
}
impl R {
    #[doc = "Bits 0:30 - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When bit 9 (TSCTRLSSR) is set in Register 448 (Timestamp Control Register), each bit represents 1 ns and the programmed value should not exceed 0x3B9A_C9FF."]
    #[inline(always)]
    pub fn tsss(&self) -> TsssR {
        TsssR::new(self.bits & 0x7fff_ffff)
    }
    #[doc = "Bit 31 - When this bit is set, the time value is subtracted with the contents of the update register. When this bit is reset, the time value is added with the contents of the update register."]
    #[inline(always)]
    pub fn addsub(&self) -> AddsubR {
        AddsubR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:30 - The value in this field has the sub second representation of time, with an accuracy of 0.46 ns. When bit 9 (TSCTRLSSR) is set in Register 448 (Timestamp Control Register), each bit represents 1 ns and the programmed value should not exceed 0x3B9A_C9FF."]
    #[inline(always)]
    #[must_use]
    pub fn tsss(&mut self) -> TsssW<GmacgrpSystemTimeNanosecondsUpdateSpec> {
        TsssW::new(self, 0)
    }
    #[doc = "Bit 31 - When this bit is set, the time value is subtracted with the contents of the update register. When this bit is reset, the time value is added with the contents of the update register."]
    #[inline(always)]
    #[must_use]
    pub fn addsub(&mut self) -> AddsubW<GmacgrpSystemTimeNanosecondsUpdateSpec> {
        AddsubW::new(self, 31)
    }
}
#[doc = "Update system time\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_system_time_nanoseconds_update::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_system_time_nanoseconds_update::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpSystemTimeNanosecondsUpdateSpec;
impl crate::RegisterSpec for GmacgrpSystemTimeNanosecondsUpdateSpec {
    type Ux = u32;
    const OFFSET: u64 = 1812u64;
}
#[doc = "`read()` method returns [`gmacgrp_system_time_nanoseconds_update::R`](R) reader structure"]
impl crate::Readable for GmacgrpSystemTimeNanosecondsUpdateSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_system_time_nanoseconds_update::W`](W) writer structure"]
impl crate::Writable for GmacgrpSystemTimeNanosecondsUpdateSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_System_Time_Nanoseconds_Update to value 0"]
impl crate::Resettable for GmacgrpSystemTimeNanosecondsUpdateSpec {
    const RESET_VALUE: u32 = 0;
}
