// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `clksrc` reader"]
pub type R = crate::R<ClksrcSpec>;
#[doc = "Register `clksrc` writer"]
pub type W = crate::W<ClksrcSpec>;
#[doc = "Selects among available clock dividers. The SD/MMC module is configured with just one clock divider so this register should always be set to choose clkdiv0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClkSource {
    #[doc = "0: `0`"]
    Clkdiv0 = 0,
}
impl From<ClkSource> for u8 {
    #[inline(always)]
    fn from(variant: ClkSource) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for ClkSource {
    type Ux = u8;
}
#[doc = "Field `clk_source` reader - Selects among available clock dividers. The SD/MMC module is configured with just one clock divider so this register should always be set to choose clkdiv0."]
pub type ClkSourceR = crate::FieldReader<ClkSource>;
impl ClkSourceR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<ClkSource> {
        match self.bits {
            0 => Some(ClkSource::Clkdiv0),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_clkdiv0(&self) -> bool {
        *self == ClkSource::Clkdiv0
    }
}
#[doc = "Field `clk_source` writer - Selects among available clock dividers. The SD/MMC module is configured with just one clock divider so this register should always be set to choose clkdiv0."]
pub type ClkSourceW<'a, REG> = crate::FieldWriter<'a, REG, 2, ClkSource>;
impl<'a, REG> ClkSourceW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn clkdiv0(self) -> &'a mut crate::W<REG> {
        self.variant(ClkSource::Clkdiv0)
    }
}
impl R {
    #[doc = "Bits 0:1 - Selects among available clock dividers. The SD/MMC module is configured with just one clock divider so this register should always be set to choose clkdiv0."]
    #[inline(always)]
    pub fn clk_source(&self) -> ClkSourceR {
        ClkSourceR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Selects among available clock dividers. The SD/MMC module is configured with just one clock divider so this register should always be set to choose clkdiv0."]
    #[inline(always)]
    #[must_use]
    pub fn clk_source(&mut self) -> ClkSourceW<ClksrcSpec> {
        ClkSourceW::new(self, 0)
    }
}
#[doc = "Selects among available clock dividers. The sdmmc_cclk_out is always from clock divider 0.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`clksrc::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`clksrc::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ClksrcSpec;
impl crate::RegisterSpec for ClksrcSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`clksrc::R`](R) reader structure"]
impl crate::Readable for ClksrcSpec {}
#[doc = "`write(|w| ..)` method takes [`clksrc::W`](W) writer structure"]
impl crate::Writable for ClksrcSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets clksrc to value 0"]
impl crate::Resettable for ClksrcSpec {
    const RESET_VALUE: u32 = 0;
}
