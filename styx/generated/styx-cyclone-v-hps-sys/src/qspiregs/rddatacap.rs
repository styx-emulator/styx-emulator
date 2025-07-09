// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rddatacap` reader"]
pub type R = crate::R<RddatacapSpec>;
#[doc = "Register `rddatacap` writer"]
pub type W = crate::W<RddatacapSpec>;
#[doc = "Controls bypass of the adapted loopback clock circuit\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Byp {
    #[doc = "0: `0`"]
    Nobypass = 0,
    #[doc = "1: `1`"]
    Bypass = 1,
}
impl From<Byp> for bool {
    #[inline(always)]
    fn from(variant: Byp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `byp` reader - Controls bypass of the adapted loopback clock circuit"]
pub type BypR = crate::BitReader<Byp>;
impl BypR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Byp {
        match self.bits {
            false => Byp::Nobypass,
            true => Byp::Bypass,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nobypass(&self) -> bool {
        *self == Byp::Nobypass
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_bypass(&self) -> bool {
        *self == Byp::Bypass
    }
}
#[doc = "Field `byp` writer - Controls bypass of the adapted loopback clock circuit"]
pub type BypW<'a, REG> = crate::BitWriter<'a, REG, Byp>;
impl<'a, REG> BypW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nobypass(self) -> &'a mut crate::W<REG> {
        self.variant(Byp::Nobypass)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn bypass(self) -> &'a mut crate::W<REG> {
        self.variant(Byp::Bypass)
    }
}
#[doc = "Field `delay` reader - Delay the read data capturing logic by the programmed number of qspi_clk cycles"]
pub type DelayR = crate::FieldReader;
#[doc = "Field `delay` writer - Delay the read data capturing logic by the programmed number of qspi_clk cycles"]
pub type DelayW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bit 0 - Controls bypass of the adapted loopback clock circuit"]
    #[inline(always)]
    pub fn byp(&self) -> BypR {
        BypR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:4 - Delay the read data capturing logic by the programmed number of qspi_clk cycles"]
    #[inline(always)]
    pub fn delay(&self) -> DelayR {
        DelayR::new(((self.bits >> 1) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Controls bypass of the adapted loopback clock circuit"]
    #[inline(always)]
    #[must_use]
    pub fn byp(&mut self) -> BypW<RddatacapSpec> {
        BypW::new(self, 0)
    }
    #[doc = "Bits 1:4 - Delay the read data capturing logic by the programmed number of qspi_clk cycles"]
    #[inline(always)]
    #[must_use]
    pub fn delay(&mut self) -> DelayW<RddatacapSpec> {
        DelayW::new(self, 1)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rddatacap::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rddatacap::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RddatacapSpec;
impl crate::RegisterSpec for RddatacapSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`rddatacap::R`](R) reader structure"]
impl crate::Readable for RddatacapSpec {}
#[doc = "`write(|w| ..)` method takes [`rddatacap::W`](W) writer structure"]
impl crate::Writable for RddatacapSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets rddatacap to value 0x01"]
impl crate::Resettable for RddatacapSpec {
    const RESET_VALUE: u32 = 0x01;
}
