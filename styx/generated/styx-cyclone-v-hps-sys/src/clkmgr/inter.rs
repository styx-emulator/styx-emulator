// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `inter` reader"]
pub type R = crate::R<InterSpec>;
#[doc = "Register `inter` writer"]
pub type W = crate::W<InterSpec>;
#[doc = "Field `mainpllachieved` reader - If 1, the Main PLL has achieved lock at least once since this bit was cleared. If 0, the Main PLL has not achieved lock since this bit was cleared."]
pub type MainpllachievedR = crate::BitReader;
#[doc = "Field `mainpllachieved` writer - If 1, the Main PLL has achieved lock at least once since this bit was cleared. If 0, the Main PLL has not achieved lock since this bit was cleared."]
pub type MainpllachievedW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `perpllachieved` reader - If 1, the Peripheral PLL has achieved lock at least once since this bit was cleared. If 0, the Peripheral PLL has not achieved lock since this bit was cleared."]
pub type PerpllachievedR = crate::BitReader;
#[doc = "Field `perpllachieved` writer - If 1, the Peripheral PLL has achieved lock at least once since this bit was cleared. If 0, the Peripheral PLL has not achieved lock since this bit was cleared."]
pub type PerpllachievedW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `sdrpllachieved` reader - If 1, the SDRAM PLL has achieved lock at least once since this bit was cleared. If 0, the SDRAM PLL has not achieved lock since this bit was cleared."]
pub type SdrpllachievedR = crate::BitReader;
#[doc = "Field `sdrpllachieved` writer - If 1, the SDRAM PLL has achieved lock at least once since this bit was cleared. If 0, the SDRAM PLL has not achieved lock since this bit was cleared."]
pub type SdrpllachievedW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `mainplllost` reader - If 1, the Main PLL has lost lock at least once since this bit was cleared. If 0, the Main PLL has not lost lock since this bit was cleared."]
pub type MainplllostR = crate::BitReader;
#[doc = "Field `mainplllost` writer - If 1, the Main PLL has lost lock at least once since this bit was cleared. If 0, the Main PLL has not lost lock since this bit was cleared."]
pub type MainplllostW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `perplllost` reader - If 1, the Peripheral PLL has lost lock at least once since this bit was cleared. If 0, the Peripheral PLL has not lost lock since this bit was cleared."]
pub type PerplllostR = crate::BitReader;
#[doc = "Field `perplllost` writer - If 1, the Peripheral PLL has lost lock at least once since this bit was cleared. If 0, the Peripheral PLL has not lost lock since this bit was cleared."]
pub type PerplllostW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `sdrplllost` reader - If 1, the SDRAM PLL has lost lock at least once since this bit was cleared. If 0, the SDRAM PLL has not lost lock since this bit was cleared."]
pub type SdrplllostR = crate::BitReader;
#[doc = "Field `sdrplllost` writer - If 1, the SDRAM PLL has lost lock at least once since this bit was cleared. If 0, the SDRAM PLL has not lost lock since this bit was cleared."]
pub type SdrplllostW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `mainplllocked` reader - If 1, the Main PLL is currently locked. If 0, the Main PLL is currently not locked."]
pub type MainplllockedR = crate::BitReader;
#[doc = "Field `mainplllocked` writer - If 1, the Main PLL is currently locked. If 0, the Main PLL is currently not locked."]
pub type MainplllockedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `perplllocked` reader - If 1, the Peripheral PLL is currently locked. If 0, the Peripheral PLL is currently not locked."]
pub type PerplllockedR = crate::BitReader;
#[doc = "Field `perplllocked` writer - If 1, the Peripheral PLL is currently locked. If 0, the Peripheral PLL is currently not locked."]
pub type PerplllockedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdrplllocked` reader - If 1, the SDRAM PLL is currently locked. If 0, the SDRAM PLL is currently not locked."]
pub type SdrplllockedR = crate::BitReader;
#[doc = "Field `sdrplllocked` writer - If 1, the SDRAM PLL is currently locked. If 0, the SDRAM PLL is currently not locked."]
pub type SdrplllockedW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - If 1, the Main PLL has achieved lock at least once since this bit was cleared. If 0, the Main PLL has not achieved lock since this bit was cleared."]
    #[inline(always)]
    pub fn mainpllachieved(&self) -> MainpllachievedR {
        MainpllachievedR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - If 1, the Peripheral PLL has achieved lock at least once since this bit was cleared. If 0, the Peripheral PLL has not achieved lock since this bit was cleared."]
    #[inline(always)]
    pub fn perpllachieved(&self) -> PerpllachievedR {
        PerpllachievedR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - If 1, the SDRAM PLL has achieved lock at least once since this bit was cleared. If 0, the SDRAM PLL has not achieved lock since this bit was cleared."]
    #[inline(always)]
    pub fn sdrpllachieved(&self) -> SdrpllachievedR {
        SdrpllachievedR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - If 1, the Main PLL has lost lock at least once since this bit was cleared. If 0, the Main PLL has not lost lock since this bit was cleared."]
    #[inline(always)]
    pub fn mainplllost(&self) -> MainplllostR {
        MainplllostR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - If 1, the Peripheral PLL has lost lock at least once since this bit was cleared. If 0, the Peripheral PLL has not lost lock since this bit was cleared."]
    #[inline(always)]
    pub fn perplllost(&self) -> PerplllostR {
        PerplllostR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - If 1, the SDRAM PLL has lost lock at least once since this bit was cleared. If 0, the SDRAM PLL has not lost lock since this bit was cleared."]
    #[inline(always)]
    pub fn sdrplllost(&self) -> SdrplllostR {
        SdrplllostR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - If 1, the Main PLL is currently locked. If 0, the Main PLL is currently not locked."]
    #[inline(always)]
    pub fn mainplllocked(&self) -> MainplllockedR {
        MainplllockedR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - If 1, the Peripheral PLL is currently locked. If 0, the Peripheral PLL is currently not locked."]
    #[inline(always)]
    pub fn perplllocked(&self) -> PerplllockedR {
        PerplllockedR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - If 1, the SDRAM PLL is currently locked. If 0, the SDRAM PLL is currently not locked."]
    #[inline(always)]
    pub fn sdrplllocked(&self) -> SdrplllockedR {
        SdrplllockedR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - If 1, the Main PLL has achieved lock at least once since this bit was cleared. If 0, the Main PLL has not achieved lock since this bit was cleared."]
    #[inline(always)]
    #[must_use]
    pub fn mainpllachieved(&mut self) -> MainpllachievedW<InterSpec> {
        MainpllachievedW::new(self, 0)
    }
    #[doc = "Bit 1 - If 1, the Peripheral PLL has achieved lock at least once since this bit was cleared. If 0, the Peripheral PLL has not achieved lock since this bit was cleared."]
    #[inline(always)]
    #[must_use]
    pub fn perpllachieved(&mut self) -> PerpllachievedW<InterSpec> {
        PerpllachievedW::new(self, 1)
    }
    #[doc = "Bit 2 - If 1, the SDRAM PLL has achieved lock at least once since this bit was cleared. If 0, the SDRAM PLL has not achieved lock since this bit was cleared."]
    #[inline(always)]
    #[must_use]
    pub fn sdrpllachieved(&mut self) -> SdrpllachievedW<InterSpec> {
        SdrpllachievedW::new(self, 2)
    }
    #[doc = "Bit 3 - If 1, the Main PLL has lost lock at least once since this bit was cleared. If 0, the Main PLL has not lost lock since this bit was cleared."]
    #[inline(always)]
    #[must_use]
    pub fn mainplllost(&mut self) -> MainplllostW<InterSpec> {
        MainplllostW::new(self, 3)
    }
    #[doc = "Bit 4 - If 1, the Peripheral PLL has lost lock at least once since this bit was cleared. If 0, the Peripheral PLL has not lost lock since this bit was cleared."]
    #[inline(always)]
    #[must_use]
    pub fn perplllost(&mut self) -> PerplllostW<InterSpec> {
        PerplllostW::new(self, 4)
    }
    #[doc = "Bit 5 - If 1, the SDRAM PLL has lost lock at least once since this bit was cleared. If 0, the SDRAM PLL has not lost lock since this bit was cleared."]
    #[inline(always)]
    #[must_use]
    pub fn sdrplllost(&mut self) -> SdrplllostW<InterSpec> {
        SdrplllostW::new(self, 5)
    }
    #[doc = "Bit 6 - If 1, the Main PLL is currently locked. If 0, the Main PLL is currently not locked."]
    #[inline(always)]
    #[must_use]
    pub fn mainplllocked(&mut self) -> MainplllockedW<InterSpec> {
        MainplllockedW::new(self, 6)
    }
    #[doc = "Bit 7 - If 1, the Peripheral PLL is currently locked. If 0, the Peripheral PLL is currently not locked."]
    #[inline(always)]
    #[must_use]
    pub fn perplllocked(&mut self) -> PerplllockedW<InterSpec> {
        PerplllockedW::new(self, 7)
    }
    #[doc = "Bit 8 - If 1, the SDRAM PLL is currently locked. If 0, the SDRAM PLL is currently not locked."]
    #[inline(always)]
    #[must_use]
    pub fn sdrplllocked(&mut self) -> SdrplllockedW<InterSpec> {
        SdrplllockedW::new(self, 8)
    }
}
#[doc = "Contains fields that indicate the PLL lock status. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`inter::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`inter::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct InterSpec;
impl crate::RegisterSpec for InterSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`inter::R`](R) reader structure"]
impl crate::Readable for InterSpec {}
#[doc = "`write(|w| ..)` method takes [`inter::W`](W) writer structure"]
impl crate::Writable for InterSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x3f;
}
#[doc = "`reset()` method sets inter to value 0"]
impl crate::Resettable for InterSpec {
    const RESET_VALUE: u32 = 0;
}
