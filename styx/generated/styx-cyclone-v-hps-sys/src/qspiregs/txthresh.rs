// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `txthresh` reader"]
pub type R = crate::R<TxthreshSpec>;
#[doc = "Register `txthresh` writer"]
pub type W = crate::W<TxthreshSpec>;
#[doc = "Field `level` reader - Defines the level at which the transmit FIFO not full interrupt is generated"]
pub type LevelR = crate::FieldReader;
#[doc = "Field `level` writer - Defines the level at which the transmit FIFO not full interrupt is generated"]
pub type LevelW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:3 - Defines the level at which the transmit FIFO not full interrupt is generated"]
    #[inline(always)]
    pub fn level(&self) -> LevelR {
        LevelR::new((self.bits & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Defines the level at which the transmit FIFO not full interrupt is generated"]
    #[inline(always)]
    #[must_use]
    pub fn level(&mut self) -> LevelW<TxthreshSpec> {
        LevelW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txthresh::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`txthresh::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TxthreshSpec;
impl crate::RegisterSpec for TxthreshSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`txthresh::R`](R) reader structure"]
impl crate::Readable for TxthreshSpec {}
#[doc = "`write(|w| ..)` method takes [`txthresh::W`](W) writer structure"]
impl crate::Writable for TxthreshSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets txthresh to value 0x01"]
impl crate::Resettable for TxthreshSpec {
    const RESET_VALUE: u32 = 0x01;
}
