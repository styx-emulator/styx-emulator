// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACA3HR` reader"]
pub type R = crate::R<Maca3hrSpec>;
#[doc = "Register `MACA3HR` writer"]
pub type W = crate::W<Maca3hrSpec>;
#[doc = "Field `MACA3H` reader - MACA3H"]
pub type Maca3hR = crate::FieldReader<u16>;
#[doc = "Field `MACA3H` writer - MACA3H"]
pub type Maca3hW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `MBC` reader - MBC"]
pub type MbcR = crate::FieldReader;
#[doc = "Field `MBC` writer - MBC"]
pub type MbcW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `SA` reader - SA"]
pub type SaR = crate::BitReader;
#[doc = "Field `SA` writer - SA"]
pub type SaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AE` reader - AE"]
pub type AeR = crate::BitReader;
#[doc = "Field `AE` writer - AE"]
pub type AeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - MACA3H"]
    #[inline(always)]
    pub fn maca3h(&self) -> Maca3hR {
        Maca3hR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 24:29 - MBC"]
    #[inline(always)]
    pub fn mbc(&self) -> MbcR {
        MbcR::new(((self.bits >> 24) & 0x3f) as u8)
    }
    #[doc = "Bit 30 - SA"]
    #[inline(always)]
    pub fn sa(&self) -> SaR {
        SaR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - AE"]
    #[inline(always)]
    pub fn ae(&self) -> AeR {
        AeR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - MACA3H"]
    #[inline(always)]
    #[must_use]
    pub fn maca3h(&mut self) -> Maca3hW<Maca3hrSpec> {
        Maca3hW::new(self, 0)
    }
    #[doc = "Bits 24:29 - MBC"]
    #[inline(always)]
    #[must_use]
    pub fn mbc(&mut self) -> MbcW<Maca3hrSpec> {
        MbcW::new(self, 24)
    }
    #[doc = "Bit 30 - SA"]
    #[inline(always)]
    #[must_use]
    pub fn sa(&mut self) -> SaW<Maca3hrSpec> {
        SaW::new(self, 30)
    }
    #[doc = "Bit 31 - AE"]
    #[inline(always)]
    #[must_use]
    pub fn ae(&mut self) -> AeW<Maca3hrSpec> {
        AeW::new(self, 31)
    }
}
#[doc = "Ethernet MAC address 3 high register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`maca3hr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`maca3hr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Maca3hrSpec;
impl crate::RegisterSpec for Maca3hrSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`maca3hr::R`](R) reader structure"]
impl crate::Readable for Maca3hrSpec {}
#[doc = "`write(|w| ..)` method takes [`maca3hr::W`](W) writer structure"]
impl crate::Writable for Maca3hrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACA3HR to value 0xffff"]
impl crate::Resettable for Maca3hrSpec {
    const RESET_VALUE: u32 = 0xffff;
}
