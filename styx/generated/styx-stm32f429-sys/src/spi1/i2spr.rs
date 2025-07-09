// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `I2SPR` reader"]
pub type R = crate::R<I2sprSpec>;
#[doc = "Register `I2SPR` writer"]
pub type W = crate::W<I2sprSpec>;
#[doc = "Field `I2SDIV` reader - I2S Linear prescaler"]
pub type I2sdivR = crate::FieldReader;
#[doc = "Field `I2SDIV` writer - I2S Linear prescaler"]
pub type I2sdivW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `ODD` reader - Odd factor for the prescaler"]
pub type OddR = crate::BitReader;
#[doc = "Field `ODD` writer - Odd factor for the prescaler"]
pub type OddW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MCKOE` reader - Master clock output enable"]
pub type MckoeR = crate::BitReader;
#[doc = "Field `MCKOE` writer - Master clock output enable"]
pub type MckoeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - I2S Linear prescaler"]
    #[inline(always)]
    pub fn i2sdiv(&self) -> I2sdivR {
        I2sdivR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bit 8 - Odd factor for the prescaler"]
    #[inline(always)]
    pub fn odd(&self) -> OddR {
        OddR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Master clock output enable"]
    #[inline(always)]
    pub fn mckoe(&self) -> MckoeR {
        MckoeR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - I2S Linear prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn i2sdiv(&mut self) -> I2sdivW<I2sprSpec> {
        I2sdivW::new(self, 0)
    }
    #[doc = "Bit 8 - Odd factor for the prescaler"]
    #[inline(always)]
    #[must_use]
    pub fn odd(&mut self) -> OddW<I2sprSpec> {
        OddW::new(self, 8)
    }
    #[doc = "Bit 9 - Master clock output enable"]
    #[inline(always)]
    #[must_use]
    pub fn mckoe(&mut self) -> MckoeW<I2sprSpec> {
        MckoeW::new(self, 9)
    }
}
#[doc = "I2S prescaler register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`i2spr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`i2spr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct I2sprSpec;
impl crate::RegisterSpec for I2sprSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`i2spr::R`](R) reader structure"]
impl crate::Readable for I2sprSpec {}
#[doc = "`write(|w| ..)` method takes [`i2spr::W`](W) writer structure"]
impl crate::Writable for I2sprSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets I2SPR to value 0x0a"]
impl crate::Resettable for I2sprSpec {
    const RESET_VALUE: u32 = 0x0a;
}
