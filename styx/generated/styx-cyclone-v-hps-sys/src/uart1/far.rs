// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `far` reader"]
pub type R = crate::R<FarSpec>;
#[doc = "Register `far` writer"]
pub type W = crate::W<FarSpec>;
#[doc = "This register is used to enable a FIFO access mode for testing, so that the receive FIFO can be written by the master and the transmit FIFO can be read by the master when FIFO's are enabled. When FIFO's are not enabled it allows the RBR to be written by the master and the THR to be read by the master Note: That when the FIFO access mode is enabled/disabled, the control portion of the receive FIFO and transmit FIFO is reset and the FIFO's are treated as empty.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrbrSthr {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<SrbrSthr> for bool {
    #[inline(always)]
    fn from(variant: SrbrSthr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `srbr_sthr` reader - This register is used to enable a FIFO access mode for testing, so that the receive FIFO can be written by the master and the transmit FIFO can be read by the master when FIFO's are enabled. When FIFO's are not enabled it allows the RBR to be written by the master and the THR to be read by the master Note: That when the FIFO access mode is enabled/disabled, the control portion of the receive FIFO and transmit FIFO is reset and the FIFO's are treated as empty."]
pub type SrbrSthrR = crate::BitReader<SrbrSthr>;
impl SrbrSthrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> SrbrSthr {
        match self.bits {
            false => SrbrSthr::Disabled,
            true => SrbrSthr::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == SrbrSthr::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == SrbrSthr::Enabled
    }
}
#[doc = "Field `srbr_sthr` writer - This register is used to enable a FIFO access mode for testing, so that the receive FIFO can be written by the master and the transmit FIFO can be read by the master when FIFO's are enabled. When FIFO's are not enabled it allows the RBR to be written by the master and the THR to be read by the master Note: That when the FIFO access mode is enabled/disabled, the control portion of the receive FIFO and transmit FIFO is reset and the FIFO's are treated as empty."]
pub type SrbrSthrW<'a, REG> = crate::BitWriter<'a, REG, SrbrSthr>;
impl<'a, REG> SrbrSthrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(SrbrSthr::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(SrbrSthr::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - This register is used to enable a FIFO access mode for testing, so that the receive FIFO can be written by the master and the transmit FIFO can be read by the master when FIFO's are enabled. When FIFO's are not enabled it allows the RBR to be written by the master and the THR to be read by the master Note: That when the FIFO access mode is enabled/disabled, the control portion of the receive FIFO and transmit FIFO is reset and the FIFO's are treated as empty."]
    #[inline(always)]
    pub fn srbr_sthr(&self) -> SrbrSthrR {
        SrbrSthrR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This register is used to enable a FIFO access mode for testing, so that the receive FIFO can be written by the master and the transmit FIFO can be read by the master when FIFO's are enabled. When FIFO's are not enabled it allows the RBR to be written by the master and the THR to be read by the master Note: That when the FIFO access mode is enabled/disabled, the control portion of the receive FIFO and transmit FIFO is reset and the FIFO's are treated as empty."]
    #[inline(always)]
    #[must_use]
    pub fn srbr_sthr(&mut self) -> SrbrSthrW<FarSpec> {
        SrbrSthrW::new(self, 0)
    }
}
#[doc = "This register is used in FIFO access testing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`far::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`far::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FarSpec;
impl crate::RegisterSpec for FarSpec {
    type Ux = u32;
    const OFFSET: u64 = 112u64;
}
#[doc = "`read()` method returns [`far::R`](R) reader structure"]
impl crate::Readable for FarSpec {}
#[doc = "`write(|w| ..)` method takes [`far::W`](W) writer structure"]
impl crate::Writable for FarSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets far to value 0"]
impl crate::Resettable for FarSpec {
    const RESET_VALUE: u32 = 0;
}
