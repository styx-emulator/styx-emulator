// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `eccgrp_sdmmc` reader"]
pub type R = crate::R<EccgrpSdmmcSpec>;
#[doc = "Register `eccgrp_sdmmc` writer"]
pub type W = crate::W<EccgrpSdmmcSpec>;
#[doc = "Field `en` reader - Enable ECC for SDMMC RAM"]
pub type EnR = crate::BitReader;
#[doc = "Field `en` writer - Enable ECC for SDMMC RAM"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `injsporta` reader - Changing this bit from zero to one injects a single, correctable error into the SDMMC RAM at Port A. This only injects one error into the SDMMC RAM at Port A."]
pub type InjsportaR = crate::BitReader;
#[doc = "Field `injsporta` writer - Changing this bit from zero to one injects a single, correctable error into the SDMMC RAM at Port A. This only injects one error into the SDMMC RAM at Port A."]
pub type InjsportaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `injdporta` reader - Changing this bit from zero to one injects a double, non-correctable error into the SDMMC RAM at Port A. This only injects one double bit error into the SDMMC RAM at Port A."]
pub type InjdportaR = crate::BitReader;
#[doc = "Field `injdporta` writer - Changing this bit from zero to one injects a double, non-correctable error into the SDMMC RAM at Port A. This only injects one double bit error into the SDMMC RAM at Port A."]
pub type InjdportaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `injsportb` reader - Changing this bit from zero to one injects a single, correctable error into the SDMMC RAM at Port B. This only injects one error into the SDMMC RAM at Port B."]
pub type InjsportbR = crate::BitReader;
#[doc = "Field `injsportb` writer - Changing this bit from zero to one injects a single, correctable error into the SDMMC RAM at Port B. This only injects one error into the SDMMC RAM at Port B."]
pub type InjsportbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `injdportb` reader - Changing this bit from zero to one injects a double, non-correctable error into the SDMMC RAM at Port B. This only injects one double bit error into the SDMMC RAM at Port B."]
pub type InjdportbR = crate::BitReader;
#[doc = "Field `injdportb` writer - Changing this bit from zero to one injects a double, non-correctable error into the SDMMC RAM at Port B. This only injects one double bit error into the SDMMC RAM at Port B."]
pub type InjdportbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `serrporta` reader - This bit is an interrupt status bit for SDMMC Port A RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in SDMMC Port A RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type SerrportaR = crate::BitReader;
#[doc = "Field `serrporta` writer - This bit is an interrupt status bit for SDMMC Port A RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in SDMMC Port A RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type SerrportaW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `derrporta` reader - This bit is an interrupt status bit for SDMMC Port A RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in SDMMC Port A RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type DerrportaR = crate::BitReader;
#[doc = "Field `derrporta` writer - This bit is an interrupt status bit for SDMMC Port A RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in SDMMC Port A RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type DerrportaW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `serrportb` reader - This bit is an interrupt status bit for SDMMC Port B RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in SDMMC Port B RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type SerrportbR = crate::BitReader;
#[doc = "Field `serrportb` writer - This bit is an interrupt status bit for SDMMC Port B RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in SDMMC Port B RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type SerrportbW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `derrportb` reader - This bit is an interrupt status bit for SDMMC Port B RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in SDMMC Port B RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type DerrportbR = crate::BitReader;
#[doc = "Field `derrportb` writer - This bit is an interrupt status bit for SDMMC Port B RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in SDMMC Port B RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type DerrportbW<'a, REG> = crate::BitWriter1C<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enable ECC for SDMMC RAM"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the SDMMC RAM at Port A. This only injects one error into the SDMMC RAM at Port A."]
    #[inline(always)]
    pub fn injsporta(&self) -> InjsportaR {
        InjsportaR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the SDMMC RAM at Port A. This only injects one double bit error into the SDMMC RAM at Port A."]
    #[inline(always)]
    pub fn injdporta(&self) -> InjdportaR {
        InjdportaR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Changing this bit from zero to one injects a single, correctable error into the SDMMC RAM at Port B. This only injects one error into the SDMMC RAM at Port B."]
    #[inline(always)]
    pub fn injsportb(&self) -> InjsportbR {
        InjsportbR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Changing this bit from zero to one injects a double, non-correctable error into the SDMMC RAM at Port B. This only injects one double bit error into the SDMMC RAM at Port B."]
    #[inline(always)]
    pub fn injdportb(&self) -> InjdportbR {
        InjdportbR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is an interrupt status bit for SDMMC Port A RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in SDMMC Port A RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn serrporta(&self) -> SerrportaR {
        SerrportaR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit is an interrupt status bit for SDMMC Port A RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in SDMMC Port A RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn derrporta(&self) -> DerrportaR {
        DerrportaR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is an interrupt status bit for SDMMC Port B RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in SDMMC Port B RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn serrportb(&self) -> SerrportbR {
        SerrportbR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit is an interrupt status bit for SDMMC Port B RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in SDMMC Port B RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn derrportb(&self) -> DerrportbR {
        DerrportbR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enable ECC for SDMMC RAM"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<EccgrpSdmmcSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the SDMMC RAM at Port A. This only injects one error into the SDMMC RAM at Port A."]
    #[inline(always)]
    #[must_use]
    pub fn injsporta(&mut self) -> InjsportaW<EccgrpSdmmcSpec> {
        InjsportaW::new(self, 1)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the SDMMC RAM at Port A. This only injects one double bit error into the SDMMC RAM at Port A."]
    #[inline(always)]
    #[must_use]
    pub fn injdporta(&mut self) -> InjdportaW<EccgrpSdmmcSpec> {
        InjdportaW::new(self, 2)
    }
    #[doc = "Bit 3 - Changing this bit from zero to one injects a single, correctable error into the SDMMC RAM at Port B. This only injects one error into the SDMMC RAM at Port B."]
    #[inline(always)]
    #[must_use]
    pub fn injsportb(&mut self) -> InjsportbW<EccgrpSdmmcSpec> {
        InjsportbW::new(self, 3)
    }
    #[doc = "Bit 4 - Changing this bit from zero to one injects a double, non-correctable error into the SDMMC RAM at Port B. This only injects one double bit error into the SDMMC RAM at Port B."]
    #[inline(always)]
    #[must_use]
    pub fn injdportb(&mut self) -> InjdportbW<EccgrpSdmmcSpec> {
        InjdportbW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is an interrupt status bit for SDMMC Port A RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in SDMMC Port A RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn serrporta(&mut self) -> SerrportaW<EccgrpSdmmcSpec> {
        SerrportaW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit is an interrupt status bit for SDMMC Port A RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in SDMMC Port A RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn derrporta(&mut self) -> DerrportaW<EccgrpSdmmcSpec> {
        DerrportaW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is an interrupt status bit for SDMMC Port B RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in SDMMC Port B RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn serrportb(&mut self) -> SerrportbW<EccgrpSdmmcSpec> {
        SerrportbW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit is an interrupt status bit for SDMMC Port B RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in SDMMC Port B RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn derrportb(&mut self) -> DerrportbW<EccgrpSdmmcSpec> {
        DerrportbW::new(self, 8)
    }
}
#[doc = "This register is used to enable ECC on the SDMMC RAM.ECC errors can be injected into the write path using bits in this register. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_sdmmc::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_sdmmc::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EccgrpSdmmcSpec;
impl crate::RegisterSpec for EccgrpSdmmcSpec {
    type Ux = u32;
    const OFFSET: u64 = 364u64;
}
#[doc = "`read()` method returns [`eccgrp_sdmmc::R`](R) reader structure"]
impl crate::Readable for EccgrpSdmmcSpec {}
#[doc = "`write(|w| ..)` method takes [`eccgrp_sdmmc::W`](W) writer structure"]
impl crate::Writable for EccgrpSdmmcSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x01e0;
}
#[doc = "`reset()` method sets eccgrp_sdmmc to value 0"]
impl crate::Resettable for EccgrpSdmmcSpec {
    const RESET_VALUE: u32 = 0;
}
