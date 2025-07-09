// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `eccgrp_nand` reader"]
pub type R = crate::R<EccgrpNandSpec>;
#[doc = "Register `eccgrp_nand` writer"]
pub type W = crate::W<EccgrpNandSpec>;
#[doc = "Field `en` reader - Enable ECC for NAND RAM"]
pub type EnR = crate::BitReader;
#[doc = "Field `en` writer - Enable ECC for NAND RAM"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `eccbufinjs` reader - Changing this bit from zero to one injects a single, correctable error into the NAND ECCBUFFER RAM. This only injects one error into the NAND ECCBUFFER RAM."]
pub type EccbufinjsR = crate::BitReader;
#[doc = "Field `eccbufinjs` writer - Changing this bit from zero to one injects a single, correctable error into the NAND ECCBUFFER RAM. This only injects one error into the NAND ECCBUFFER RAM."]
pub type EccbufinjsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `eccbufinjd` reader - Changing this bit from zero to one injects a double, non-correctable error into the NAND ECCBUFFER RAM. This only injects one double bit error into the NAND ECCBUFFER RAM."]
pub type EccbufinjdR = crate::BitReader;
#[doc = "Field `eccbufinjd` writer - Changing this bit from zero to one injects a double, non-correctable error into the NAND ECCBUFFER RAM. This only injects one double bit error into the NAND ECCBUFFER RAM."]
pub type EccbufinjdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `wrfifoinjs` reader - Changing this bit from zero to one injects a single, correctable error into the NAND WRFIFO RAM. This only injects one error into the NAND WRFIFO RAM."]
pub type WrfifoinjsR = crate::BitReader;
#[doc = "Field `wrfifoinjs` writer - Changing this bit from zero to one injects a single, correctable error into the NAND WRFIFO RAM. This only injects one error into the NAND WRFIFO RAM."]
pub type WrfifoinjsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `wrfifoinjd` reader - Changing this bit from zero to one injects a double, non-correctable error into the NAND WRFIFO RAM. This only injects one double bit error into the NAND WRFIFO RAM."]
pub type WrfifoinjdR = crate::BitReader;
#[doc = "Field `wrfifoinjd` writer - Changing this bit from zero to one injects a double, non-correctable error into the NAND WRFIFO RAM. This only injects one double bit error into the NAND WRFIFO RAM."]
pub type WrfifoinjdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rdfifoinjs` reader - Changing this bit from zero to one injects a single, correctable error into the NAND RDFIFO RAM. This only injects one error into the NAND RDFIFO RAM."]
pub type RdfifoinjsR = crate::BitReader;
#[doc = "Field `rdfifoinjs` writer - Changing this bit from zero to one injects a single, correctable error into the NAND RDFIFO RAM. This only injects one error into the NAND RDFIFO RAM."]
pub type RdfifoinjsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rdfifoinjd` reader - Changing this bit from zero to one injects a double, non-correctable error into the NAND RDFIFO RAM. This only injects one double bit error into the NAND RDFIFO RAM."]
pub type RdfifoinjdR = crate::BitReader;
#[doc = "Field `rdfifoinjd` writer - Changing this bit from zero to one injects a double, non-correctable error into the NAND RDFIFO RAM. This only injects one double bit error into the NAND RDFIFO RAM."]
pub type RdfifoinjdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `eccbufserr` reader - This bit is an interrupt status bit for NAND ECCBUFFER RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND ECCBUFFER RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type EccbufserrR = crate::BitReader;
#[doc = "Field `eccbufserr` writer - This bit is an interrupt status bit for NAND ECCBUFFER RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND ECCBUFFER RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type EccbufserrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `eccbufderr` reader - This bit is an interrupt status bit for NAND ECCBUFFER RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND ECCBUFFER RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type EccbufderrR = crate::BitReader;
#[doc = "Field `eccbufderr` writer - This bit is an interrupt status bit for NAND ECCBUFFER RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND ECCBUFFER RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type EccbufderrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `wrfifoserr` reader - This bit is an interrupt status bit for NAND WRFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND WRFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type WrfifoserrR = crate::BitReader;
#[doc = "Field `wrfifoserr` writer - This bit is an interrupt status bit for NAND WRFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND WRFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type WrfifoserrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `wrfifoderr` reader - This bit is an interrupt status bit for NAND WRFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND WRFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type WrfifoderrR = crate::BitReader;
#[doc = "Field `wrfifoderr` writer - This bit is an interrupt status bit for NAND WRFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND WRFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type WrfifoderrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `rdfifoserr` reader - This bit is an interrupt status bit for NAND RDFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND RDFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type RdfifoserrR = crate::BitReader;
#[doc = "Field `rdfifoserr` writer - This bit is an interrupt status bit for NAND RDFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND RDFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type RdfifoserrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `rdfifoderr` reader - This bit is an interrupt status bit for NAND RDFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND RDFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type RdfifoderrR = crate::BitReader;
#[doc = "Field `rdfifoderr` writer - This bit is an interrupt status bit for NAND RDFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND RDFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type RdfifoderrW<'a, REG> = crate::BitWriter1C<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enable ECC for NAND RAM"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the NAND ECCBUFFER RAM. This only injects one error into the NAND ECCBUFFER RAM."]
    #[inline(always)]
    pub fn eccbufinjs(&self) -> EccbufinjsR {
        EccbufinjsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the NAND ECCBUFFER RAM. This only injects one double bit error into the NAND ECCBUFFER RAM."]
    #[inline(always)]
    pub fn eccbufinjd(&self) -> EccbufinjdR {
        EccbufinjdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Changing this bit from zero to one injects a single, correctable error into the NAND WRFIFO RAM. This only injects one error into the NAND WRFIFO RAM."]
    #[inline(always)]
    pub fn wrfifoinjs(&self) -> WrfifoinjsR {
        WrfifoinjsR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Changing this bit from zero to one injects a double, non-correctable error into the NAND WRFIFO RAM. This only injects one double bit error into the NAND WRFIFO RAM."]
    #[inline(always)]
    pub fn wrfifoinjd(&self) -> WrfifoinjdR {
        WrfifoinjdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Changing this bit from zero to one injects a single, correctable error into the NAND RDFIFO RAM. This only injects one error into the NAND RDFIFO RAM."]
    #[inline(always)]
    pub fn rdfifoinjs(&self) -> RdfifoinjsR {
        RdfifoinjsR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Changing this bit from zero to one injects a double, non-correctable error into the NAND RDFIFO RAM. This only injects one double bit error into the NAND RDFIFO RAM."]
    #[inline(always)]
    pub fn rdfifoinjd(&self) -> RdfifoinjdR {
        RdfifoinjdR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is an interrupt status bit for NAND ECCBUFFER RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND ECCBUFFER RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn eccbufserr(&self) -> EccbufserrR {
        EccbufserrR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit is an interrupt status bit for NAND ECCBUFFER RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND ECCBUFFER RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn eccbufderr(&self) -> EccbufderrR {
        EccbufderrR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit is an interrupt status bit for NAND WRFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND WRFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn wrfifoserr(&self) -> WrfifoserrR {
        WrfifoserrR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit is an interrupt status bit for NAND WRFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND WRFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn wrfifoderr(&self) -> WrfifoderrR {
        WrfifoderrR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit is an interrupt status bit for NAND RDFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND RDFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn rdfifoserr(&self) -> RdfifoserrR {
        RdfifoserrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - This bit is an interrupt status bit for NAND RDFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND RDFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn rdfifoderr(&self) -> RdfifoderrR {
        RdfifoderrR::new(((self.bits >> 12) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enable ECC for NAND RAM"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<EccgrpNandSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the NAND ECCBUFFER RAM. This only injects one error into the NAND ECCBUFFER RAM."]
    #[inline(always)]
    #[must_use]
    pub fn eccbufinjs(&mut self) -> EccbufinjsW<EccgrpNandSpec> {
        EccbufinjsW::new(self, 1)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the NAND ECCBUFFER RAM. This only injects one double bit error into the NAND ECCBUFFER RAM."]
    #[inline(always)]
    #[must_use]
    pub fn eccbufinjd(&mut self) -> EccbufinjdW<EccgrpNandSpec> {
        EccbufinjdW::new(self, 2)
    }
    #[doc = "Bit 3 - Changing this bit from zero to one injects a single, correctable error into the NAND WRFIFO RAM. This only injects one error into the NAND WRFIFO RAM."]
    #[inline(always)]
    #[must_use]
    pub fn wrfifoinjs(&mut self) -> WrfifoinjsW<EccgrpNandSpec> {
        WrfifoinjsW::new(self, 3)
    }
    #[doc = "Bit 4 - Changing this bit from zero to one injects a double, non-correctable error into the NAND WRFIFO RAM. This only injects one double bit error into the NAND WRFIFO RAM."]
    #[inline(always)]
    #[must_use]
    pub fn wrfifoinjd(&mut self) -> WrfifoinjdW<EccgrpNandSpec> {
        WrfifoinjdW::new(self, 4)
    }
    #[doc = "Bit 5 - Changing this bit from zero to one injects a single, correctable error into the NAND RDFIFO RAM. This only injects one error into the NAND RDFIFO RAM."]
    #[inline(always)]
    #[must_use]
    pub fn rdfifoinjs(&mut self) -> RdfifoinjsW<EccgrpNandSpec> {
        RdfifoinjsW::new(self, 5)
    }
    #[doc = "Bit 6 - Changing this bit from zero to one injects a double, non-correctable error into the NAND RDFIFO RAM. This only injects one double bit error into the NAND RDFIFO RAM."]
    #[inline(always)]
    #[must_use]
    pub fn rdfifoinjd(&mut self) -> RdfifoinjdW<EccgrpNandSpec> {
        RdfifoinjdW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is an interrupt status bit for NAND ECCBUFFER RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND ECCBUFFER RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn eccbufserr(&mut self) -> EccbufserrW<EccgrpNandSpec> {
        EccbufserrW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit is an interrupt status bit for NAND ECCBUFFER RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND ECCBUFFER RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn eccbufderr(&mut self) -> EccbufderrW<EccgrpNandSpec> {
        EccbufderrW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit is an interrupt status bit for NAND WRFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND WRFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn wrfifoserr(&mut self) -> WrfifoserrW<EccgrpNandSpec> {
        WrfifoserrW::new(self, 9)
    }
    #[doc = "Bit 10 - This bit is an interrupt status bit for NAND WRFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND WRFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn wrfifoderr(&mut self) -> WrfifoderrW<EccgrpNandSpec> {
        WrfifoderrW::new(self, 10)
    }
    #[doc = "Bit 11 - This bit is an interrupt status bit for NAND RDFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in NAND RDFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn rdfifoserr(&mut self) -> RdfifoserrW<EccgrpNandSpec> {
        RdfifoserrW::new(self, 11)
    }
    #[doc = "Bit 12 - This bit is an interrupt status bit for NAND RDFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in NAND RDFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn rdfifoderr(&mut self) -> RdfifoderrW<EccgrpNandSpec> {
        RdfifoderrW::new(self, 12)
    }
}
#[doc = "This register is used to enable ECC on the NAND RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_nand::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_nand::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EccgrpNandSpec;
impl crate::RegisterSpec for EccgrpNandSpec {
    type Ux = u32;
    const OFFSET: u64 = 356u64;
}
#[doc = "`read()` method returns [`eccgrp_nand::R`](R) reader structure"]
impl crate::Readable for EccgrpNandSpec {}
#[doc = "`write(|w| ..)` method takes [`eccgrp_nand::W`](W) writer structure"]
impl crate::Writable for EccgrpNandSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x1f80;
}
#[doc = "`reset()` method sets eccgrp_nand to value 0"]
impl crate::Resettable for EccgrpNandSpec {
    const RESET_VALUE: u32 = 0;
}
