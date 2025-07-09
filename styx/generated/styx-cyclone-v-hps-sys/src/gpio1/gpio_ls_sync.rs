// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gpio_ls_sync` reader"]
pub type R = crate::R<GpioLsSyncSpec>;
#[doc = "Register `gpio_ls_sync` writer"]
pub type W = crate::W<GpioLsSyncSpec>;
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
    pub fn gpio_ls_sync(&mut self) -> GpioLsSyncW<GpioLsSyncSpec> {
        GpioLsSyncW::new(self, 0)
    }
}
#[doc = "The Synchronization level register is used to synchronize input with l4_mp_clk\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gpio_ls_sync::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gpio_ls_sync::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GpioLsSyncSpec;
impl crate::RegisterSpec for GpioLsSyncSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`gpio_ls_sync::R`](R) reader structure"]
impl crate::Readable for GpioLsSyncSpec {}
#[doc = "`write(|w| ..)` method takes [`gpio_ls_sync::W`](W) writer structure"]
impl crate::Writable for GpioLsSyncSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gpio_ls_sync to value 0"]
impl crate::Resettable for GpioLsSyncSpec {
    const RESET_VALUE: u32 = 0;
}
