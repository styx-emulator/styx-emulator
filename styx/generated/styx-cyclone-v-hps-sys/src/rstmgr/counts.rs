// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `counts` reader"]
pub type R = crate::R<CountsSpec>;
#[doc = "Register `counts` writer"]
pub type W = crate::W<CountsSpec>;
#[doc = "Field `warmrstcycles` reader - On a warm reset, the Reset Manager releases the reset to the Clock Manager, and then waits for the number of cycles specified in this register before releasing the rest of the hardware controlled resets. Value must be greater than 16."]
pub type WarmrstcyclesR = crate::FieldReader;
#[doc = "Field `warmrstcycles` writer - On a warm reset, the Reset Manager releases the reset to the Clock Manager, and then waits for the number of cycles specified in this register before releasing the rest of the hardware controlled resets. Value must be greater than 16."]
pub type WarmrstcyclesW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `nrstcnt` reader - The Reset Manager pulls down the nRST pin on a warm reset for the number of cycles specified in this register. A value of 0x0 prevents the Reset Manager from pulling down the nRST pin."]
pub type NrstcntR = crate::FieldReader<u32>;
#[doc = "Field `nrstcnt` writer - The Reset Manager pulls down the nRST pin on a warm reset for the number of cycles specified in this register. A value of 0x0 prevents the Reset Manager from pulling down the nRST pin."]
pub type NrstcntW<'a, REG> = crate::FieldWriter<'a, REG, 20, u32>;
impl R {
    #[doc = "Bits 0:7 - On a warm reset, the Reset Manager releases the reset to the Clock Manager, and then waits for the number of cycles specified in this register before releasing the rest of the hardware controlled resets. Value must be greater than 16."]
    #[inline(always)]
    pub fn warmrstcycles(&self) -> WarmrstcyclesR {
        WarmrstcyclesR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:27 - The Reset Manager pulls down the nRST pin on a warm reset for the number of cycles specified in this register. A value of 0x0 prevents the Reset Manager from pulling down the nRST pin."]
    #[inline(always)]
    pub fn nrstcnt(&self) -> NrstcntR {
        NrstcntR::new((self.bits >> 8) & 0x000f_ffff)
    }
}
impl W {
    #[doc = "Bits 0:7 - On a warm reset, the Reset Manager releases the reset to the Clock Manager, and then waits for the number of cycles specified in this register before releasing the rest of the hardware controlled resets. Value must be greater than 16."]
    #[inline(always)]
    #[must_use]
    pub fn warmrstcycles(&mut self) -> WarmrstcyclesW<CountsSpec> {
        WarmrstcyclesW::new(self, 0)
    }
    #[doc = "Bits 8:27 - The Reset Manager pulls down the nRST pin on a warm reset for the number of cycles specified in this register. A value of 0x0 prevents the Reset Manager from pulling down the nRST pin."]
    #[inline(always)]
    #[must_use]
    pub fn nrstcnt(&mut self) -> NrstcntW<CountsSpec> {
        NrstcntW::new(self, 8)
    }
}
#[doc = "The COUNTS register is used by software to control reset behavior.It includes fields for software to control the behavior of the warm reset and nRST pin. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`counts::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`counts::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CountsSpec;
impl crate::RegisterSpec for CountsSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`counts::R`](R) reader structure"]
impl crate::Readable for CountsSpec {}
#[doc = "`write(|w| ..)` method takes [`counts::W`](W) writer structure"]
impl crate::Writable for CountsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets counts to value 0x0008_0080"]
impl crate::Resettable for CountsSpec {
    const RESET_VALUE: u32 = 0x0008_0080;
}
