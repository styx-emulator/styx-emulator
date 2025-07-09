// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `sdrpllgrp_en` reader"]
pub type R = crate::R<SdrpllgrpEnSpec>;
#[doc = "Register `sdrpllgrp_en` writer"]
pub type W = crate::W<SdrpllgrpEnSpec>;
#[doc = "Field `ddrdqsclk` reader - Enables clock ddr_dqs_clk output"]
pub type DdrdqsclkR = crate::BitReader;
#[doc = "Field `ddrdqsclk` writer - Enables clock ddr_dqs_clk output"]
pub type DdrdqsclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ddr2xdqsclk` reader - Enables clock ddr_2x_dqs_clk output"]
pub type Ddr2xdqsclkR = crate::BitReader;
#[doc = "Field `ddr2xdqsclk` writer - Enables clock ddr_2x_dqs_clk output"]
pub type Ddr2xdqsclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ddrdqclk` reader - Enables clock ddr_dq_clk output"]
pub type DdrdqclkR = crate::BitReader;
#[doc = "Field `ddrdqclk` writer - Enables clock ddr_dq_clk output"]
pub type DdrdqclkW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `s2fuser2clk` reader - Enables clock s2f_user2_clk output. Qsys and user documenation refer to s2f_user2_clk as h2f_user2_clk."]
pub type S2fuser2clkR = crate::BitReader;
#[doc = "Field `s2fuser2clk` writer - Enables clock s2f_user2_clk output. Qsys and user documenation refer to s2f_user2_clk as h2f_user2_clk."]
pub type S2fuser2clkW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enables clock ddr_dqs_clk output"]
    #[inline(always)]
    pub fn ddrdqsclk(&self) -> DdrdqsclkR {
        DdrdqsclkR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Enables clock ddr_2x_dqs_clk output"]
    #[inline(always)]
    pub fn ddr2xdqsclk(&self) -> Ddr2xdqsclkR {
        Ddr2xdqsclkR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Enables clock ddr_dq_clk output"]
    #[inline(always)]
    pub fn ddrdqclk(&self) -> DdrdqclkR {
        DdrdqclkR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Enables clock s2f_user2_clk output. Qsys and user documenation refer to s2f_user2_clk as h2f_user2_clk."]
    #[inline(always)]
    pub fn s2fuser2clk(&self) -> S2fuser2clkR {
        S2fuser2clkR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enables clock ddr_dqs_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn ddrdqsclk(&mut self) -> DdrdqsclkW<SdrpllgrpEnSpec> {
        DdrdqsclkW::new(self, 0)
    }
    #[doc = "Bit 1 - Enables clock ddr_2x_dqs_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn ddr2xdqsclk(&mut self) -> Ddr2xdqsclkW<SdrpllgrpEnSpec> {
        Ddr2xdqsclkW::new(self, 1)
    }
    #[doc = "Bit 2 - Enables clock ddr_dq_clk output"]
    #[inline(always)]
    #[must_use]
    pub fn ddrdqclk(&mut self) -> DdrdqclkW<SdrpllgrpEnSpec> {
        DdrdqclkW::new(self, 2)
    }
    #[doc = "Bit 3 - Enables clock s2f_user2_clk output. Qsys and user documenation refer to s2f_user2_clk as h2f_user2_clk."]
    #[inline(always)]
    #[must_use]
    pub fn s2fuser2clk(&mut self) -> S2fuser2clkW<SdrpllgrpEnSpec> {
        S2fuser2clkW::new(self, 3)
    }
}
#[doc = "Contains fields that control the SDRAM Clock Group enables generated from the SDRAM PLL clock outputs. 1: The clock is enabled. 0: The clock is disabled. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdrpllgrp_en::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdrpllgrp_en::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SdrpllgrpEnSpec;
impl crate::RegisterSpec for SdrpllgrpEnSpec {
    type Ux = u32;
    const OFFSET: u64 = 216u64;
}
#[doc = "`read()` method returns [`sdrpllgrp_en::R`](R) reader structure"]
impl crate::Readable for SdrpllgrpEnSpec {}
#[doc = "`write(|w| ..)` method takes [`sdrpllgrp_en::W`](W) writer structure"]
impl crate::Writable for SdrpllgrpEnSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets sdrpllgrp_en to value 0x0f"]
impl crate::Resettable for SdrpllgrpEnSpec {
    const RESET_VALUE: u32 = 0x0f;
}
