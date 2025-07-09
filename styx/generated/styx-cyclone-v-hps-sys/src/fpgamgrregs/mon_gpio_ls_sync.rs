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
#[doc = "Register `mon_gpio_ls_sync` reader"]
pub type R = crate::R<MonGpioLsSyncSpec>;
#[doc = "Register `mon_gpio_ls_sync` writer"]
pub type W = crate::W<MonGpioLsSyncSpec>;
#[doc = "The level-sensitive interrupts is synchronized to l4_mp_clk.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpioLsSync {
    #[doc = "0: `0`"]
    Nosync = 0,
    #[doc = "1: `1`"]
    Sync = 1,
}
impl From<GpioLsSync> for bool {
    #[inline(always)]
    fn from(variant: GpioLsSync) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gpio_ls_sync` reader - The level-sensitive interrupts is synchronized to l4_mp_clk."]
pub type GpioLsSyncR = crate::BitReader<GpioLsSync>;
impl GpioLsSyncR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> GpioLsSync {
        match self.bits {
            false => GpioLsSync::Nosync,
            true => GpioLsSync::Sync,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nosync(&self) -> bool {
        *self == GpioLsSync::Nosync
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_sync(&self) -> bool {
        *self == GpioLsSync::Sync
    }
}
#[doc = "Field `gpio_ls_sync` writer - The level-sensitive interrupts is synchronized to l4_mp_clk."]
pub type GpioLsSyncW<'a, REG> = crate::BitWriter<'a, REG, GpioLsSync>;
impl<'a, REG> GpioLsSyncW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nosync(self) -> &'a mut crate::W<REG> {
        self.variant(GpioLsSync::Nosync)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn sync(self) -> &'a mut crate::W<REG> {
        self.variant(GpioLsSync::Sync)
    }
}
impl R {
    #[doc = "Bit 0 - The level-sensitive interrupts is synchronized to l4_mp_clk."]
    #[inline(always)]
    pub fn gpio_ls_sync(&self) -> GpioLsSyncR {
        GpioLsSyncR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - The level-sensitive interrupts is synchronized to l4_mp_clk."]
    #[inline(always)]
    #[must_use]
    pub fn gpio_ls_sync(&mut self) -> GpioLsSyncW<MonGpioLsSyncSpec> {
        GpioLsSyncW::new(self, 0)
    }
}
#[doc = "The Synchronization level register is used to synchronize inputs to the l4_mp_clk. All MON interrupts are already synchronized before the GPIO instance so it is not necessary to setup this register to enable synchronization.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mon_gpio_ls_sync::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mon_gpio_ls_sync::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MonGpioLsSyncSpec;
impl crate::RegisterSpec for MonGpioLsSyncSpec {
    type Ux = u32;
    const OFFSET: u64 = 2144u64;
}
#[doc = "`read()` method returns [`mon_gpio_ls_sync::R`](R) reader structure"]
impl crate::Readable for MonGpioLsSyncSpec {}
#[doc = "`write(|w| ..)` method takes [`mon_gpio_ls_sync::W`](W) writer structure"]
impl crate::Writable for MonGpioLsSyncSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mon_gpio_ls_sync to value 0"]
impl crate::Resettable for MonGpioLsSyncSpec {
    const RESET_VALUE: u32 = 0;
}
