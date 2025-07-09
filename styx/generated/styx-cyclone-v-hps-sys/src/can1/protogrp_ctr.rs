// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `protogrp_CTR` reader"]
pub type R = crate::R<ProtogrpCtrSpec>;
#[doc = "Register `protogrp_CTR` writer"]
pub type W = crate::W<ProtogrpCtrSpec>;
#[doc = "Silent Mode\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Silent {
    #[doc = "0: `0`"]
    Normal = 0,
    #[doc = "1: `1`"]
    Silent = 1,
}
impl From<Silent> for bool {
    #[inline(always)]
    fn from(variant: Silent) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `Silent` reader - Silent Mode"]
pub type SilentR = crate::BitReader<Silent>;
impl SilentR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Silent {
        match self.bits {
            false => Silent::Normal,
            true => Silent::Silent,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_normal(&self) -> bool {
        *self == Silent::Normal
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_silent(&self) -> bool {
        *self == Silent::Silent
    }
}
#[doc = "Field `Silent` writer - Silent Mode"]
pub type SilentW<'a, REG> = crate::BitWriter<'a, REG, Silent>;
impl<'a, REG> SilentW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn normal(self) -> &'a mut crate::W<REG> {
        self.variant(Silent::Normal)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn silent(self) -> &'a mut crate::W<REG> {
        self.variant(Silent::Silent)
    }
}
#[doc = "Loop Back Mode\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lback {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Lback> for bool {
    #[inline(always)]
    fn from(variant: Lback) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `LBack` reader - Loop Back Mode"]
pub type LbackR = crate::BitReader<Lback>;
impl LbackR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Lback {
        match self.bits {
            false => Lback::Disabled,
            true => Lback::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Lback::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Lback::Enabled
    }
}
#[doc = "Field `LBack` writer - Loop Back Mode"]
pub type LbackW<'a, REG> = crate::BitWriter<'a, REG, Lback>;
impl<'a, REG> LbackW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lback::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Lback::Enabled)
    }
}
#[doc = "Controls CAN_TXD pin. Setting to non-zero disturbs message transfer.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tx {
    #[doc = "0: `0`"]
    Reset = 0,
    #[doc = "1: `1`"]
    Sample = 1,
    #[doc = "2: `10`"]
    Dominant = 2,
    #[doc = "3: `11`"]
    Recessive = 3,
}
impl From<Tx> for u8 {
    #[inline(always)]
    fn from(variant: Tx) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Tx {
    type Ux = u8;
}
#[doc = "Field `Tx` reader - Controls CAN_TXD pin. Setting to non-zero disturbs message transfer."]
pub type TxR = crate::FieldReader<Tx>;
impl TxR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tx {
        match self.bits {
            0 => Tx::Reset,
            1 => Tx::Sample,
            2 => Tx::Dominant,
            3 => Tx::Recessive,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_reset(&self) -> bool {
        *self == Tx::Reset
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_sample(&self) -> bool {
        *self == Tx::Sample
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_dominant(&self) -> bool {
        *self == Tx::Dominant
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_recessive(&self) -> bool {
        *self == Tx::Recessive
    }
}
#[doc = "Field `Tx` writer - Controls CAN_TXD pin. Setting to non-zero disturbs message transfer."]
pub type TxW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Tx>;
impl<'a, REG> TxW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn reset(self) -> &'a mut crate::W<REG> {
        self.variant(Tx::Reset)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn sample(self) -> &'a mut crate::W<REG> {
        self.variant(Tx::Sample)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn dominant(self) -> &'a mut crate::W<REG> {
        self.variant(Tx::Dominant)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn recessive(self) -> &'a mut crate::W<REG> {
        self.variant(Tx::Recessive)
    }
}
#[doc = "Monitors the actual value of the CAN_RXD pin.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx {
    #[doc = "0: `0`"]
    Dominant = 0,
    #[doc = "1: `1`"]
    Recessive = 1,
}
impl From<Rx> for bool {
    #[inline(always)]
    fn from(variant: Rx) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `Rx` reader - Monitors the actual value of the CAN_RXD pin."]
pub type RxR = crate::BitReader<Rx>;
impl RxR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rx {
        match self.bits {
            false => Rx::Dominant,
            true => Rx::Recessive,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_dominant(&self) -> bool {
        *self == Rx::Dominant
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_recessive(&self) -> bool {
        *self == Rx::Recessive
    }
}
#[doc = "Field `Rx` writer - Monitors the actual value of the CAN_RXD pin."]
pub type RxW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 3 - Silent Mode"]
    #[inline(always)]
    pub fn silent(&self) -> SilentR {
        SilentR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Loop Back Mode"]
    #[inline(always)]
    pub fn lback(&self) -> LbackR {
        LbackR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:6 - Controls CAN_TXD pin. Setting to non-zero disturbs message transfer."]
    #[inline(always)]
    pub fn tx(&self) -> TxR {
        TxR::new(((self.bits >> 5) & 3) as u8)
    }
    #[doc = "Bit 7 - Monitors the actual value of the CAN_RXD pin."]
    #[inline(always)]
    pub fn rx(&self) -> RxR {
        RxR::new(((self.bits >> 7) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 3 - Silent Mode"]
    #[inline(always)]
    #[must_use]
    pub fn silent(&mut self) -> SilentW<ProtogrpCtrSpec> {
        SilentW::new(self, 3)
    }
    #[doc = "Bit 4 - Loop Back Mode"]
    #[inline(always)]
    #[must_use]
    pub fn lback(&mut self) -> LbackW<ProtogrpCtrSpec> {
        LbackW::new(self, 4)
    }
    #[doc = "Bits 5:6 - Controls CAN_TXD pin. Setting to non-zero disturbs message transfer."]
    #[inline(always)]
    #[must_use]
    pub fn tx(&mut self) -> TxW<ProtogrpCtrSpec> {
        TxW::new(self, 5)
    }
    #[doc = "Bit 7 - Monitors the actual value of the CAN_RXD pin."]
    #[inline(always)]
    #[must_use]
    pub fn rx(&mut self) -> RxW<ProtogrpCtrSpec> {
        RxW::new(self, 7)
    }
}
#[doc = "The Test Mode is entered by setting bit CCTRL.Test to one. In Test Mode the bits EXL, Tx1, Tx0, LBack and Silent in the Test Register are writable. Bit Rx monitors the state of pin CAN_RXD and therefore is only readable. All Test Register functions are disabled when bit Test is reset to zero. Loop Back Mode and CAN_TXD Control Mode are hardware test modes, not to be used by application programs. Note: This register is only writable if bit CCTRL.Test is set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_ctr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`protogrp_ctr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ProtogrpCtrSpec;
impl crate::RegisterSpec for ProtogrpCtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`protogrp_ctr::R`](R) reader structure"]
impl crate::Readable for ProtogrpCtrSpec {}
#[doc = "`write(|w| ..)` method takes [`protogrp_ctr::W`](W) writer structure"]
impl crate::Writable for ProtogrpCtrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets protogrp_CTR to value 0"]
impl crate::Resettable for ProtogrpCtrSpec {
    const RESET_VALUE: u32 = 0;
}
