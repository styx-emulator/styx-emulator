// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `eccgrp_emac1` reader"]
pub type R = crate::R<EccgrpEmac1Spec>;
#[doc = "Register `eccgrp_emac1` writer"]
pub type W = crate::W<EccgrpEmac1Spec>;
#[doc = "Field `en` reader - Enable ECC for EMAC1 RAM"]
pub type EnR = crate::BitReader;
#[doc = "Field `en` writer - Enable ECC for EMAC1 RAM"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `txfifoinjs` reader - Changing this bit from zero to one injects a single, correctable error into the EMAC1 TXFIFO RAM. This only injects one error into the EMAC1 TXFIFO RAM."]
pub type TxfifoinjsR = crate::BitReader;
#[doc = "Field `txfifoinjs` writer - Changing this bit from zero to one injects a single, correctable error into the EMAC1 TXFIFO RAM. This only injects one error into the EMAC1 TXFIFO RAM."]
pub type TxfifoinjsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `txfifoinjd` reader - Changing this bit from zero to one injects a double, non-correctable error into the EMAC1 TXFIFO RAM. This only injects one double bit error into the EMAC1 TXFIFO RAM."]
pub type TxfifoinjdR = crate::BitReader;
#[doc = "Field `txfifoinjd` writer - Changing this bit from zero to one injects a double, non-correctable error into the EMAC1 TXFIFO RAM. This only injects one double bit error into the EMAC1 TXFIFO RAM."]
pub type TxfifoinjdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rxfifoinjs` reader - Changing this bit from zero to one injects a single, correctable error into the EMAC1 RXFIFO RAM. This only injects one error into the EMAC1 RXFIFO RAM."]
pub type RxfifoinjsR = crate::BitReader;
#[doc = "Field `rxfifoinjs` writer - Changing this bit from zero to one injects a single, correctable error into the EMAC1 RXFIFO RAM. This only injects one error into the EMAC1 RXFIFO RAM."]
pub type RxfifoinjsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rxfifoinjd` reader - Changing this bit from zero to one injects a double, non-correctable error into the EMAC1 RXFIFO RAM. This only injects one double bit error into the EMAC1 RXFIFO RAM."]
pub type RxfifoinjdR = crate::BitReader;
#[doc = "Field `rxfifoinjd` writer - Changing this bit from zero to one injects a double, non-correctable error into the EMAC1 RXFIFO RAM. This only injects one double bit error into the EMAC1 RXFIFO RAM."]
pub type RxfifoinjdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `txfifoserr` reader - This bit is an interrupt status bit for EMAC1 TXFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in EMAC1 TXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type TxfifoserrR = crate::BitReader;
#[doc = "Field `txfifoserr` writer - This bit is an interrupt status bit for EMAC1 TXFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in EMAC1 TXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type TxfifoserrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `txfifoderr` reader - This bit is an interrupt status bit for EMAC1 TXFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in EMAC1 TXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type TxfifoderrR = crate::BitReader;
#[doc = "Field `txfifoderr` writer - This bit is an interrupt status bit for EMAC1 TXFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in EMAC1 TXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type TxfifoderrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `rxfifoserr` reader - This bit is an interrupt status bit for EMAC1 RXFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in EMAC1 RXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type RxfifoserrR = crate::BitReader;
#[doc = "Field `rxfifoserr` writer - This bit is an interrupt status bit for EMAC1 RXFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in EMAC1 RXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type RxfifoserrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `rxfifoderr` reader - This bit is an interrupt status bit for EMAC1 RXFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in EMAC1 RXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type RxfifoderrR = crate::BitReader;
#[doc = "Field `rxfifoderr` writer - This bit is an interrupt status bit for EMAC1 RXFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in EMAC1 RXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type RxfifoderrW<'a, REG> = crate::BitWriter1C<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enable ECC for EMAC1 RAM"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the EMAC1 TXFIFO RAM. This only injects one error into the EMAC1 TXFIFO RAM."]
    #[inline(always)]
    pub fn txfifoinjs(&self) -> TxfifoinjsR {
        TxfifoinjsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the EMAC1 TXFIFO RAM. This only injects one double bit error into the EMAC1 TXFIFO RAM."]
    #[inline(always)]
    pub fn txfifoinjd(&self) -> TxfifoinjdR {
        TxfifoinjdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Changing this bit from zero to one injects a single, correctable error into the EMAC1 RXFIFO RAM. This only injects one error into the EMAC1 RXFIFO RAM."]
    #[inline(always)]
    pub fn rxfifoinjs(&self) -> RxfifoinjsR {
        RxfifoinjsR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Changing this bit from zero to one injects a double, non-correctable error into the EMAC1 RXFIFO RAM. This only injects one double bit error into the EMAC1 RXFIFO RAM."]
    #[inline(always)]
    pub fn rxfifoinjd(&self) -> RxfifoinjdR {
        RxfifoinjdR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is an interrupt status bit for EMAC1 TXFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in EMAC1 TXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn txfifoserr(&self) -> TxfifoserrR {
        TxfifoserrR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit is an interrupt status bit for EMAC1 TXFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in EMAC1 TXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn txfifoderr(&self) -> TxfifoderrR {
        TxfifoderrR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is an interrupt status bit for EMAC1 RXFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in EMAC1 RXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn rxfifoserr(&self) -> RxfifoserrR {
        RxfifoserrR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit is an interrupt status bit for EMAC1 RXFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in EMAC1 RXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn rxfifoderr(&self) -> RxfifoderrR {
        RxfifoderrR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enable ECC for EMAC1 RAM"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<EccgrpEmac1Spec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the EMAC1 TXFIFO RAM. This only injects one error into the EMAC1 TXFIFO RAM."]
    #[inline(always)]
    #[must_use]
    pub fn txfifoinjs(&mut self) -> TxfifoinjsW<EccgrpEmac1Spec> {
        TxfifoinjsW::new(self, 1)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the EMAC1 TXFIFO RAM. This only injects one double bit error into the EMAC1 TXFIFO RAM."]
    #[inline(always)]
    #[must_use]
    pub fn txfifoinjd(&mut self) -> TxfifoinjdW<EccgrpEmac1Spec> {
        TxfifoinjdW::new(self, 2)
    }
    #[doc = "Bit 3 - Changing this bit from zero to one injects a single, correctable error into the EMAC1 RXFIFO RAM. This only injects one error into the EMAC1 RXFIFO RAM."]
    #[inline(always)]
    #[must_use]
    pub fn rxfifoinjs(&mut self) -> RxfifoinjsW<EccgrpEmac1Spec> {
        RxfifoinjsW::new(self, 3)
    }
    #[doc = "Bit 4 - Changing this bit from zero to one injects a double, non-correctable error into the EMAC1 RXFIFO RAM. This only injects one double bit error into the EMAC1 RXFIFO RAM."]
    #[inline(always)]
    #[must_use]
    pub fn rxfifoinjd(&mut self) -> RxfifoinjdW<EccgrpEmac1Spec> {
        RxfifoinjdW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is an interrupt status bit for EMAC1 TXFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in EMAC1 TXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn txfifoserr(&mut self) -> TxfifoserrW<EccgrpEmac1Spec> {
        TxfifoserrW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit is an interrupt status bit for EMAC1 TXFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in EMAC1 TXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn txfifoderr(&mut self) -> TxfifoderrW<EccgrpEmac1Spec> {
        TxfifoderrW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is an interrupt status bit for EMAC1 RXFIFO RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in EMAC1 RXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn rxfifoserr(&mut self) -> RxfifoserrW<EccgrpEmac1Spec> {
        RxfifoserrW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit is an interrupt status bit for EMAC1 RXFIFO RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in EMAC1 RXFIFO RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn rxfifoderr(&mut self) -> RxfifoderrW<EccgrpEmac1Spec> {
        RxfifoderrW::new(self, 8)
    }
}
#[doc = "This register is used to enable ECC on the EMAC1 RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_emac1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_emac1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EccgrpEmac1Spec;
impl crate::RegisterSpec for EccgrpEmac1Spec {
    type Ux = u32;
    const OFFSET: u64 = 340u64;
}
#[doc = "`read()` method returns [`eccgrp_emac1::R`](R) reader structure"]
impl crate::Readable for EccgrpEmac1Spec {}
#[doc = "`write(|w| ..)` method takes [`eccgrp_emac1::W`](W) writer structure"]
impl crate::Writable for EccgrpEmac1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x01e0;
}
#[doc = "`reset()` method sets eccgrp_emac1 to value 0"]
impl crate::Resettable for EccgrpEmac1Spec {
    const RESET_VALUE: u32 = 0;
}
