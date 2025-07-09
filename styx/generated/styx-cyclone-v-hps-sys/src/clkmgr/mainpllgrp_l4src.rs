// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mainpllgrp_l4src` reader"]
pub type R = crate::R<MainpllgrpL4srcSpec>;
#[doc = "Register `mainpllgrp_l4src` writer"]
pub type W = crate::W<MainpllgrpL4srcSpec>;
#[doc = "Selects the source for l4_mp_clk\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4mp {
    #[doc = "0: `0`"]
    MainPll = 0,
    #[doc = "1: `1`"]
    PeriphPll = 1,
}
impl From<L4mp> for bool {
    #[inline(always)]
    fn from(variant: L4mp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `l4mp` reader - Selects the source for l4_mp_clk"]
pub type L4mpR = crate::BitReader<L4mp>;
impl L4mpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> L4mp {
        match self.bits {
            false => L4mp::MainPll,
            true => L4mp::PeriphPll,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_main_pll(&self) -> bool {
        *self == L4mp::MainPll
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_periph_pll(&self) -> bool {
        *self == L4mp::PeriphPll
    }
}
#[doc = "Field `l4mp` writer - Selects the source for l4_mp_clk"]
pub type L4mpW<'a, REG> = crate::BitWriter<'a, REG, L4mp>;
impl<'a, REG> L4mpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn main_pll(self) -> &'a mut crate::W<REG> {
        self.variant(L4mp::MainPll)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn periph_pll(self) -> &'a mut crate::W<REG> {
        self.variant(L4mp::PeriphPll)
    }
}
#[doc = "Selects the source for l4_sp_clk\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4sp {
    #[doc = "0: `0`"]
    MainPll = 0,
    #[doc = "1: `1`"]
    PeriphPll = 1,
}
impl From<L4sp> for bool {
    #[inline(always)]
    fn from(variant: L4sp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `l4sp` reader - Selects the source for l4_sp_clk"]
pub type L4spR = crate::BitReader<L4sp>;
impl L4spR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> L4sp {
        match self.bits {
            false => L4sp::MainPll,
            true => L4sp::PeriphPll,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_main_pll(&self) -> bool {
        *self == L4sp::MainPll
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_periph_pll(&self) -> bool {
        *self == L4sp::PeriphPll
    }
}
#[doc = "Field `l4sp` writer - Selects the source for l4_sp_clk"]
pub type L4spW<'a, REG> = crate::BitWriter<'a, REG, L4sp>;
impl<'a, REG> L4spW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn main_pll(self) -> &'a mut crate::W<REG> {
        self.variant(L4sp::MainPll)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn periph_pll(self) -> &'a mut crate::W<REG> {
        self.variant(L4sp::PeriphPll)
    }
}
impl R {
    #[doc = "Bit 0 - Selects the source for l4_mp_clk"]
    #[inline(always)]
    pub fn l4mp(&self) -> L4mpR {
        L4mpR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Selects the source for l4_sp_clk"]
    #[inline(always)]
    pub fn l4sp(&self) -> L4spR {
        L4spR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Selects the source for l4_mp_clk"]
    #[inline(always)]
    #[must_use]
    pub fn l4mp(&mut self) -> L4mpW<MainpllgrpL4srcSpec> {
        L4mpW::new(self, 0)
    }
    #[doc = "Bit 1 - Selects the source for l4_sp_clk"]
    #[inline(always)]
    #[must_use]
    pub fn l4sp(&mut self) -> L4spW<MainpllgrpL4srcSpec> {
        L4spW::new(self, 1)
    }
}
#[doc = "Contains fields that select the clock source for L4 MP and SP APB interconnect Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_l4src::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_l4src::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MainpllgrpL4srcSpec;
impl crate::RegisterSpec for MainpllgrpL4srcSpec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`mainpllgrp_l4src::R`](R) reader structure"]
impl crate::Readable for MainpllgrpL4srcSpec {}
#[doc = "`write(|w| ..)` method takes [`mainpllgrp_l4src::W`](W) writer structure"]
impl crate::Writable for MainpllgrpL4srcSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mainpllgrp_l4src to value 0"]
impl crate::Resettable for MainpllgrpL4srcSpec {
    const RESET_VALUE: u32 = 0;
}
