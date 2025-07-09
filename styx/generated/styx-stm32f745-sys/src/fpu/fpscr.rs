// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FPSCR` reader"]
pub type R = crate::R<FpscrSpec>;
#[doc = "Register `FPSCR` writer"]
pub type W = crate::W<FpscrSpec>;
#[doc = "Field `IOC` reader - Invalid operation cumulative exception bit"]
pub type IocR = crate::BitReader;
#[doc = "Field `IOC` writer - Invalid operation cumulative exception bit"]
pub type IocW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DZC` reader - Division by zero cumulative exception bit."]
pub type DzcR = crate::BitReader;
#[doc = "Field `DZC` writer - Division by zero cumulative exception bit."]
pub type DzcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OFC` reader - Overflow cumulative exception bit"]
pub type OfcR = crate::BitReader;
#[doc = "Field `OFC` writer - Overflow cumulative exception bit"]
pub type OfcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UFC` reader - Underflow cumulative exception bit"]
pub type UfcR = crate::BitReader;
#[doc = "Field `UFC` writer - Underflow cumulative exception bit"]
pub type UfcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IXC` reader - Inexact cumulative exception bit"]
pub type IxcR = crate::BitReader;
#[doc = "Field `IXC` writer - Inexact cumulative exception bit"]
pub type IxcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDC` reader - Input denormal cumulative exception bit."]
pub type IdcR = crate::BitReader;
#[doc = "Field `IDC` writer - Input denormal cumulative exception bit."]
pub type IdcW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RMode` reader - Rounding Mode control field"]
pub type RmodeR = crate::FieldReader;
#[doc = "Field `RMode` writer - Rounding Mode control field"]
pub type RmodeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `FZ` reader - Flush-to-zero mode control bit:"]
pub type FzR = crate::BitReader;
#[doc = "Field `FZ` writer - Flush-to-zero mode control bit:"]
pub type FzW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DN` reader - Default NaN mode control bit"]
pub type DnR = crate::BitReader;
#[doc = "Field `DN` writer - Default NaN mode control bit"]
pub type DnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AHP` reader - Alternative half-precision control bit"]
pub type AhpR = crate::BitReader;
#[doc = "Field `AHP` writer - Alternative half-precision control bit"]
pub type AhpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `V` reader - Overflow condition code flag"]
pub type VR = crate::BitReader;
#[doc = "Field `V` writer - Overflow condition code flag"]
pub type VW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `C` reader - Carry condition code flag"]
pub type CR = crate::BitReader;
#[doc = "Field `C` writer - Carry condition code flag"]
pub type CW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `Z` reader - Zero condition code flag"]
pub type ZR = crate::BitReader;
#[doc = "Field `Z` writer - Zero condition code flag"]
pub type ZW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `N` reader - Negative condition code flag"]
pub type NR = crate::BitReader;
#[doc = "Field `N` writer - Negative condition code flag"]
pub type NW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Invalid operation cumulative exception bit"]
    #[inline(always)]
    pub fn ioc(&self) -> IocR {
        IocR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Division by zero cumulative exception bit."]
    #[inline(always)]
    pub fn dzc(&self) -> DzcR {
        DzcR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Overflow cumulative exception bit"]
    #[inline(always)]
    pub fn ofc(&self) -> OfcR {
        OfcR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Underflow cumulative exception bit"]
    #[inline(always)]
    pub fn ufc(&self) -> UfcR {
        UfcR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Inexact cumulative exception bit"]
    #[inline(always)]
    pub fn ixc(&self) -> IxcR {
        IxcR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 7 - Input denormal cumulative exception bit."]
    #[inline(always)]
    pub fn idc(&self) -> IdcR {
        IdcR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 22:23 - Rounding Mode control field"]
    #[inline(always)]
    pub fn rmode(&self) -> RmodeR {
        RmodeR::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bit 24 - Flush-to-zero mode control bit:"]
    #[inline(always)]
    pub fn fz(&self) -> FzR {
        FzR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Default NaN mode control bit"]
    #[inline(always)]
    pub fn dn(&self) -> DnR {
        DnR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Alternative half-precision control bit"]
    #[inline(always)]
    pub fn ahp(&self) -> AhpR {
        AhpR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 28 - Overflow condition code flag"]
    #[inline(always)]
    pub fn v(&self) -> VR {
        VR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Carry condition code flag"]
    #[inline(always)]
    pub fn c(&self) -> CR {
        CR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Zero condition code flag"]
    #[inline(always)]
    pub fn z(&self) -> ZR {
        ZR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Negative condition code flag"]
    #[inline(always)]
    pub fn n(&self) -> NR {
        NR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Invalid operation cumulative exception bit"]
    #[inline(always)]
    #[must_use]
    pub fn ioc(&mut self) -> IocW<FpscrSpec> {
        IocW::new(self, 0)
    }
    #[doc = "Bit 1 - Division by zero cumulative exception bit."]
    #[inline(always)]
    #[must_use]
    pub fn dzc(&mut self) -> DzcW<FpscrSpec> {
        DzcW::new(self, 1)
    }
    #[doc = "Bit 2 - Overflow cumulative exception bit"]
    #[inline(always)]
    #[must_use]
    pub fn ofc(&mut self) -> OfcW<FpscrSpec> {
        OfcW::new(self, 2)
    }
    #[doc = "Bit 3 - Underflow cumulative exception bit"]
    #[inline(always)]
    #[must_use]
    pub fn ufc(&mut self) -> UfcW<FpscrSpec> {
        UfcW::new(self, 3)
    }
    #[doc = "Bit 4 - Inexact cumulative exception bit"]
    #[inline(always)]
    #[must_use]
    pub fn ixc(&mut self) -> IxcW<FpscrSpec> {
        IxcW::new(self, 4)
    }
    #[doc = "Bit 7 - Input denormal cumulative exception bit."]
    #[inline(always)]
    #[must_use]
    pub fn idc(&mut self) -> IdcW<FpscrSpec> {
        IdcW::new(self, 7)
    }
    #[doc = "Bits 22:23 - Rounding Mode control field"]
    #[inline(always)]
    #[must_use]
    pub fn rmode(&mut self) -> RmodeW<FpscrSpec> {
        RmodeW::new(self, 22)
    }
    #[doc = "Bit 24 - Flush-to-zero mode control bit:"]
    #[inline(always)]
    #[must_use]
    pub fn fz(&mut self) -> FzW<FpscrSpec> {
        FzW::new(self, 24)
    }
    #[doc = "Bit 25 - Default NaN mode control bit"]
    #[inline(always)]
    #[must_use]
    pub fn dn(&mut self) -> DnW<FpscrSpec> {
        DnW::new(self, 25)
    }
    #[doc = "Bit 26 - Alternative half-precision control bit"]
    #[inline(always)]
    #[must_use]
    pub fn ahp(&mut self) -> AhpW<FpscrSpec> {
        AhpW::new(self, 26)
    }
    #[doc = "Bit 28 - Overflow condition code flag"]
    #[inline(always)]
    #[must_use]
    pub fn v(&mut self) -> VW<FpscrSpec> {
        VW::new(self, 28)
    }
    #[doc = "Bit 29 - Carry condition code flag"]
    #[inline(always)]
    #[must_use]
    pub fn c(&mut self) -> CW<FpscrSpec> {
        CW::new(self, 29)
    }
    #[doc = "Bit 30 - Zero condition code flag"]
    #[inline(always)]
    #[must_use]
    pub fn z(&mut self) -> ZW<FpscrSpec> {
        ZW::new(self, 30)
    }
    #[doc = "Bit 31 - Negative condition code flag"]
    #[inline(always)]
    #[must_use]
    pub fn n(&mut self) -> NW<FpscrSpec> {
        NW::new(self, 31)
    }
}
#[doc = "Floating-point status control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fpscr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fpscr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FpscrSpec;
impl crate::RegisterSpec for FpscrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`fpscr::R`](R) reader structure"]
impl crate::Readable for FpscrSpec {}
#[doc = "`write(|w| ..)` method takes [`fpscr::W`](W) writer structure"]
impl crate::Writable for FpscrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FPSCR to value 0"]
impl crate::Resettable for FpscrSpec {
    const RESET_VALUE: u32 = 0;
}
