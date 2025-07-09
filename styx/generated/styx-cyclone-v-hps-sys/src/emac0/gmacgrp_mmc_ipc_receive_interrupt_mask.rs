// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_MMC_IPC_Receive_Interrupt_Mask` reader"]
pub type R = crate::R<GmacgrpMmcIpcReceiveInterruptMaskSpec>;
#[doc = "Register `gmacgrp_MMC_IPC_Receive_Interrupt_Mask` writer"]
pub type W = crate::W<GmacgrpMmcIpcReceiveInterruptMaskSpec>;
#[doc = "Setting this bit masks the interrupt when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4gfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4gfim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4gfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4gfim` reader - Setting this bit masks the interrupt when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4gfimR = crate::BitReader<Rxipv4gfim>;
impl Rxipv4gfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4gfim {
        match self.bits {
            false => Rxipv4gfim::Nomaskintr,
            true => Rxipv4gfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4gfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4gfim::Maskintr
    }
}
#[doc = "Field `rxipv4gfim` writer - Setting this bit masks the interrupt when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4gfimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4gfim>;
impl<'a, REG> Rxipv4gfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4gfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4gfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4herfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4herfim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4herfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4herfim` reader - Setting this bit masks the interrupt when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4herfimR = crate::BitReader<Rxipv4herfim>;
impl Rxipv4herfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4herfim {
        match self.bits {
            false => Rxipv4herfim::Nomaskintr,
            true => Rxipv4herfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4herfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4herfim::Maskintr
    }
}
#[doc = "Field `rxipv4herfim` writer - Setting this bit masks the interrupt when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4herfimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4herfim>;
impl<'a, REG> Rxipv4herfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4herfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4herfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4nopayfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4nopayfim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4nopayfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4nopayfim` reader - Setting this bit masks the interrupt when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4nopayfimR = crate::BitReader<Rxipv4nopayfim>;
impl Rxipv4nopayfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4nopayfim {
        match self.bits {
            false => Rxipv4nopayfim::Nomaskintr,
            true => Rxipv4nopayfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4nopayfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4nopayfim::Maskintr
    }
}
#[doc = "Field `rxipv4nopayfim` writer - Setting this bit masks the interrupt when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4nopayfimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4nopayfim>;
impl<'a, REG> Rxipv4nopayfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4nopayfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4nopayfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4fragfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4fragfim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4fragfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4fragfim` reader - Setting this bit masks the interrupt when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4fragfimR = crate::BitReader<Rxipv4fragfim>;
impl Rxipv4fragfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4fragfim {
        match self.bits {
            false => Rxipv4fragfim::Nomaskintr,
            true => Rxipv4fragfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4fragfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4fragfim::Maskintr
    }
}
#[doc = "Field `rxipv4fragfim` writer - Setting this bit masks the interrupt when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4fragfimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4fragfim>;
impl<'a, REG> Rxipv4fragfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4fragfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4fragfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4udsblfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4udsblfim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4udsblfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4udsblfim` reader - Setting this bit masks the interrupt when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4udsblfimR = crate::BitReader<Rxipv4udsblfim>;
impl Rxipv4udsblfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4udsblfim {
        match self.bits {
            false => Rxipv4udsblfim::Nomaskintr,
            true => Rxipv4udsblfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4udsblfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4udsblfim::Maskintr
    }
}
#[doc = "Field `rxipv4udsblfim` writer - Setting this bit masks the interrupt when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4udsblfimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4udsblfim>;
impl<'a, REG> Rxipv4udsblfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4udsblfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4udsblfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6gfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv6gfim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6gfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6gfim` reader - Setting this bit masks the interrupt when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6gfimR = crate::BitReader<Rxipv6gfim>;
impl Rxipv6gfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6gfim {
        match self.bits {
            false => Rxipv6gfim::Nomaskintr,
            true => Rxipv6gfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv6gfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv6gfim::Maskintr
    }
}
#[doc = "Field `rxipv6gfim` writer - Setting this bit masks the interrupt when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6gfimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv6gfim>;
impl<'a, REG> Rxipv6gfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6gfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6gfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6herfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv6herfim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6herfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6herfim` reader - Setting this bit masks the interrupt when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6herfimR = crate::BitReader<Rxipv6herfim>;
impl Rxipv6herfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6herfim {
        match self.bits {
            false => Rxipv6herfim::Nomaskintr,
            true => Rxipv6herfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv6herfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv6herfim::Maskintr
    }
}
#[doc = "Field `rxipv6herfim` writer - Setting this bit masks the interrupt when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6herfimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv6herfim>;
impl<'a, REG> Rxipv6herfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6herfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6herfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6nopayfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv6nopayfim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6nopayfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6nopayfim` reader - Setting this bit masks the interrupt when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6nopayfimR = crate::BitReader<Rxipv6nopayfim>;
impl Rxipv6nopayfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6nopayfim {
        match self.bits {
            false => Rxipv6nopayfim::Nomaskintr,
            true => Rxipv6nopayfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv6nopayfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv6nopayfim::Maskintr
    }
}
#[doc = "Field `rxipv6nopayfim` writer - Setting this bit masks the interrupt when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6nopayfimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv6nopayfim>;
impl<'a, REG> Rxipv6nopayfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6nopayfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6nopayfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxudpgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxudpgfim> for bool {
    #[inline(always)]
    fn from(variant: Rxudpgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxudpgfim` reader - Setting this bit masks the interrupt when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxudpgfimR = crate::BitReader<Rxudpgfim>;
impl RxudpgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxudpgfim {
        match self.bits {
            false => Rxudpgfim::Nomaskintr,
            true => Rxudpgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxudpgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxudpgfim::Maskintr
    }
}
#[doc = "Field `rxudpgfim` writer - Setting this bit masks the interrupt when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxudpgfimW<'a, REG> = crate::BitWriter<'a, REG, Rxudpgfim>;
impl<'a, REG> RxudpgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxudpgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxudpgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxudp_err_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxudperfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxudperfim> for bool {
    #[inline(always)]
    fn from(variant: Rxudperfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxudperfim` reader - Setting this bit masks the interrupt when the rxudp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxudperfimR = crate::BitReader<Rxudperfim>;
impl RxudperfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxudperfim {
        match self.bits {
            false => Rxudperfim::Nomaskintr,
            true => Rxudperfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxudperfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxudperfim::Maskintr
    }
}
#[doc = "Field `rxudperfim` writer - Setting this bit masks the interrupt when the rxudp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxudperfimW<'a, REG> = crate::BitWriter<'a, REG, Rxudperfim>;
impl<'a, REG> RxudperfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxudperfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxudperfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtcpgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxtcpgfim> for bool {
    #[inline(always)]
    fn from(variant: Rxtcpgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtcpgfim` reader - Setting this bit masks the interrupt when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxtcpgfimR = crate::BitReader<Rxtcpgfim>;
impl RxtcpgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtcpgfim {
        match self.bits {
            false => Rxtcpgfim::Nomaskintr,
            true => Rxtcpgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxtcpgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxtcpgfim::Maskintr
    }
}
#[doc = "Field `rxtcpgfim` writer - Setting this bit masks the interrupt when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxtcpgfimW<'a, REG> = crate::BitWriter<'a, REG, Rxtcpgfim>;
impl<'a, REG> RxtcpgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxtcpgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxtcpgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtcperfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxtcperfim> for bool {
    #[inline(always)]
    fn from(variant: Rxtcperfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtcperfim` reader - Setting this bit masks the interrupt when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxtcperfimR = crate::BitReader<Rxtcperfim>;
impl RxtcperfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtcperfim {
        match self.bits {
            false => Rxtcperfim::Nomaskintr,
            true => Rxtcperfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxtcperfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxtcperfim::Maskintr
    }
}
#[doc = "Field `rxtcperfim` writer - Setting this bit masks the interrupt when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxtcperfimW<'a, REG> = crate::BitWriter<'a, REG, Rxtcperfim>;
impl<'a, REG> RxtcperfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxtcperfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxtcperfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxicmpgfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxicmpgfim> for bool {
    #[inline(always)]
    fn from(variant: Rxicmpgfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxicmpgfim` reader - Setting this bit masks the interrupt when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxicmpgfimR = crate::BitReader<Rxicmpgfim>;
impl RxicmpgfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxicmpgfim {
        match self.bits {
            false => Rxicmpgfim::Nomaskintr,
            true => Rxicmpgfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxicmpgfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxicmpgfim::Maskintr
    }
}
#[doc = "Field `rxicmpgfim` writer - Setting this bit masks the interrupt when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxicmpgfimW<'a, REG> = crate::BitWriter<'a, REG, Rxicmpgfim>;
impl<'a, REG> RxicmpgfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxicmpgfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxicmpgfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxicmperfim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxicmperfim> for bool {
    #[inline(always)]
    fn from(variant: Rxicmperfim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxicmperfim` reader - Setting this bit masks the interrupt when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxicmperfimR = crate::BitReader<Rxicmperfim>;
impl RxicmperfimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxicmperfim {
        match self.bits {
            false => Rxicmperfim::Nomaskintr,
            true => Rxicmperfim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxicmperfim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxicmperfim::Maskintr
    }
}
#[doc = "Field `rxicmperfim` writer - Setting this bit masks the interrupt when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxicmperfimW<'a, REG> = crate::BitWriter<'a, REG, Rxicmperfim>;
impl<'a, REG> RxicmperfimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxicmperfim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxicmperfim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4goim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4goim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4goim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4goim` reader - Setting this bit masks the interrupt when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4goimR = crate::BitReader<Rxipv4goim>;
impl Rxipv4goimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4goim {
        match self.bits {
            false => Rxipv4goim::Nomaskintr,
            true => Rxipv4goim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4goim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4goim::Maskintr
    }
}
#[doc = "Field `rxipv4goim` writer - Setting this bit masks the interrupt when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4goimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4goim>;
impl<'a, REG> Rxipv4goimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4goim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4goim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4heroim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4heroim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4heroim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4heroim` reader - Setting this bit masks the interrupt when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4heroimR = crate::BitReader<Rxipv4heroim>;
impl Rxipv4heroimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4heroim {
        match self.bits {
            false => Rxipv4heroim::Nomaskintr,
            true => Rxipv4heroim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4heroim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4heroim::Maskintr
    }
}
#[doc = "Field `rxipv4heroim` writer - Setting this bit masks the interrupt when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4heroimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4heroim>;
impl<'a, REG> Rxipv4heroimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4heroim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4heroim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4nopayoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4nopayoim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4nopayoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4nopayoim` reader - Setting this bit masks the interrupt when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4nopayoimR = crate::BitReader<Rxipv4nopayoim>;
impl Rxipv4nopayoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4nopayoim {
        match self.bits {
            false => Rxipv4nopayoim::Nomaskintr,
            true => Rxipv4nopayoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4nopayoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4nopayoim::Maskintr
    }
}
#[doc = "Field `rxipv4nopayoim` writer - Setting this bit masks the interrupt when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4nopayoimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4nopayoim>;
impl<'a, REG> Rxipv4nopayoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4nopayoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4nopayoim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4fragoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4fragoim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4fragoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4fragoim` reader - Setting this bit masks the interrupt when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4fragoimR = crate::BitReader<Rxipv4fragoim>;
impl Rxipv4fragoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4fragoim {
        match self.bits {
            false => Rxipv4fragoim::Nomaskintr,
            true => Rxipv4fragoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4fragoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4fragoim::Maskintr
    }
}
#[doc = "Field `rxipv4fragoim` writer - Setting this bit masks the interrupt when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4fragoimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4fragoim>;
impl<'a, REG> Rxipv4fragoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4fragoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4fragoim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4udsbloim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv4udsbloim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4udsbloim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4udsbloim` reader - Setting this bit masks the interrupt when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4udsbloimR = crate::BitReader<Rxipv4udsbloim>;
impl Rxipv4udsbloimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4udsbloim {
        match self.bits {
            false => Rxipv4udsbloim::Nomaskintr,
            true => Rxipv4udsbloim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv4udsbloim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv4udsbloim::Maskintr
    }
}
#[doc = "Field `rxipv4udsbloim` writer - Setting this bit masks the interrupt when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4udsbloimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv4udsbloim>;
impl<'a, REG> Rxipv4udsbloimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4udsbloim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv4udsbloim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6goim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv6goim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6goim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6goim` reader - Setting this bit masks the interrupt when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6goimR = crate::BitReader<Rxipv6goim>;
impl Rxipv6goimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6goim {
        match self.bits {
            false => Rxipv6goim::Nomaskintr,
            true => Rxipv6goim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv6goim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv6goim::Maskintr
    }
}
#[doc = "Field `rxipv6goim` writer - Setting this bit masks the interrupt when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6goimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv6goim>;
impl<'a, REG> Rxipv6goimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6goim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6goim::Maskintr)
    }
}
#[doc = "Setting this bit masks interrupt when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6heroim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv6heroim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6heroim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6heroim` reader - Setting this bit masks interrupt when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6heroimR = crate::BitReader<Rxipv6heroim>;
impl Rxipv6heroimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6heroim {
        match self.bits {
            false => Rxipv6heroim::Nomaskintr,
            true => Rxipv6heroim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv6heroim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv6heroim::Maskintr
    }
}
#[doc = "Field `rxipv6heroim` writer - Setting this bit masks interrupt when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6heroimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv6heroim>;
impl<'a, REG> Rxipv6heroimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6heroim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6heroim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6nopayoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxipv6nopayoim> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6nopayoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6nopayoim` reader - Setting this bit masks the interrupt when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6nopayoimR = crate::BitReader<Rxipv6nopayoim>;
impl Rxipv6nopayoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6nopayoim {
        match self.bits {
            false => Rxipv6nopayoim::Nomaskintr,
            true => Rxipv6nopayoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxipv6nopayoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxipv6nopayoim::Maskintr
    }
}
#[doc = "Field `rxipv6nopayoim` writer - Setting this bit masks the interrupt when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6nopayoimW<'a, REG> = crate::BitWriter<'a, REG, Rxipv6nopayoim>;
impl<'a, REG> Rxipv6nopayoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6nopayoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxipv6nopayoim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxudpgoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxudpgoim> for bool {
    #[inline(always)]
    fn from(variant: Rxudpgoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxudpgoim` reader - Setting this bit masks the interrupt when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxudpgoimR = crate::BitReader<Rxudpgoim>;
impl RxudpgoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxudpgoim {
        match self.bits {
            false => Rxudpgoim::Nomaskintr,
            true => Rxudpgoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxudpgoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxudpgoim::Maskintr
    }
}
#[doc = "Field `rxudpgoim` writer - Setting this bit masks the interrupt when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxudpgoimW<'a, REG> = crate::BitWriter<'a, REG, Rxudpgoim>;
impl<'a, REG> RxudpgoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxudpgoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxudpgoim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxudp_err_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxudperoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxudperoim> for bool {
    #[inline(always)]
    fn from(variant: Rxudperoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxudperoim` reader - Setting this bit masks the interrupt when the rxudp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxudperoimR = crate::BitReader<Rxudperoim>;
impl RxudperoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxudperoim {
        match self.bits {
            false => Rxudperoim::Nomaskintr,
            true => Rxudperoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxudperoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxudperoim::Maskintr
    }
}
#[doc = "Field `rxudperoim` writer - Setting this bit masks the interrupt when the rxudp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxudperoimW<'a, REG> = crate::BitWriter<'a, REG, Rxudperoim>;
impl<'a, REG> RxudperoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxudperoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxudperoim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxtcp_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtcpgoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxtcpgoim> for bool {
    #[inline(always)]
    fn from(variant: Rxtcpgoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtcpgoim` reader - Setting this bit masks the interrupt when the rxtcp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxtcpgoimR = crate::BitReader<Rxtcpgoim>;
impl RxtcpgoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtcpgoim {
        match self.bits {
            false => Rxtcpgoim::Nomaskintr,
            true => Rxtcpgoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxtcpgoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxtcpgoim::Maskintr
    }
}
#[doc = "Field `rxtcpgoim` writer - Setting this bit masks the interrupt when the rxtcp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxtcpgoimW<'a, REG> = crate::BitWriter<'a, REG, Rxtcpgoim>;
impl<'a, REG> RxtcpgoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxtcpgoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxtcpgoim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtcperoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxtcperoim> for bool {
    #[inline(always)]
    fn from(variant: Rxtcperoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtcperoim` reader - Setting this bit masks the interrupt when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxtcperoimR = crate::BitReader<Rxtcperoim>;
impl RxtcperoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtcperoim {
        match self.bits {
            false => Rxtcperoim::Nomaskintr,
            true => Rxtcperoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxtcperoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxtcperoim::Maskintr
    }
}
#[doc = "Field `rxtcperoim` writer - Setting this bit masks the interrupt when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxtcperoimW<'a, REG> = crate::BitWriter<'a, REG, Rxtcperoim>;
impl<'a, REG> RxtcperoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxtcperoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxtcperoim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxicmpgoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxicmpgoim> for bool {
    #[inline(always)]
    fn from(variant: Rxicmpgoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxicmpgoim` reader - Setting this bit masks the interrupt when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxicmpgoimR = crate::BitReader<Rxicmpgoim>;
impl RxicmpgoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxicmpgoim {
        match self.bits {
            false => Rxicmpgoim::Nomaskintr,
            true => Rxicmpgoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxicmpgoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxicmpgoim::Maskintr
    }
}
#[doc = "Field `rxicmpgoim` writer - Setting this bit masks the interrupt when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxicmpgoimW<'a, REG> = crate::BitWriter<'a, REG, Rxicmpgoim>;
impl<'a, REG> RxicmpgoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxicmpgoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxicmpgoim::Maskintr)
    }
}
#[doc = "Setting this bit masks the interrupt when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxicmperoim {
    #[doc = "0: `0`"]
    Nomaskintr = 0,
    #[doc = "1: `1`"]
    Maskintr = 1,
}
impl From<Rxicmperoim> for bool {
    #[inline(always)]
    fn from(variant: Rxicmperoim) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxicmperoim` reader - Setting this bit masks the interrupt when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxicmperoimR = crate::BitReader<Rxicmperoim>;
impl RxicmperoimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxicmperoim {
        match self.bits {
            false => Rxicmperoim::Nomaskintr,
            true => Rxicmperoim::Maskintr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nomaskintr(&self) -> bool {
        *self == Rxicmperoim::Nomaskintr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_maskintr(&self) -> bool {
        *self == Rxicmperoim::Maskintr
    }
}
#[doc = "Field `rxicmperoim` writer - Setting this bit masks the interrupt when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxicmperoimW<'a, REG> = crate::BitWriter<'a, REG, Rxicmperoim>;
impl<'a, REG> RxicmperoimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nomaskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxicmperoim::Nomaskintr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn maskintr(self) -> &'a mut crate::W<REG> {
        self.variant(Rxicmperoim::Maskintr)
    }
}
impl R {
    #[doc = "Bit 0 - Setting this bit masks the interrupt when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4gfim(&self) -> Rxipv4gfimR {
        Rxipv4gfimR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Setting this bit masks the interrupt when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4herfim(&self) -> Rxipv4herfimR {
        Rxipv4herfimR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Setting this bit masks the interrupt when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4nopayfim(&self) -> Rxipv4nopayfimR {
        Rxipv4nopayfimR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Setting this bit masks the interrupt when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4fragfim(&self) -> Rxipv4fragfimR {
        Rxipv4fragfimR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Setting this bit masks the interrupt when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4udsblfim(&self) -> Rxipv4udsblfimR {
        Rxipv4udsblfimR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Setting this bit masks the interrupt when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6gfim(&self) -> Rxipv6gfimR {
        Rxipv6gfimR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Setting this bit masks the interrupt when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6herfim(&self) -> Rxipv6herfimR {
        Rxipv6herfimR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Setting this bit masks the interrupt when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6nopayfim(&self) -> Rxipv6nopayfimR {
        Rxipv6nopayfimR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Setting this bit masks the interrupt when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxudpgfim(&self) -> RxudpgfimR {
        RxudpgfimR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Setting this bit masks the interrupt when the rxudp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxudperfim(&self) -> RxudperfimR {
        RxudperfimR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Setting this bit masks the interrupt when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxtcpgfim(&self) -> RxtcpgfimR {
        RxtcpgfimR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Setting this bit masks the interrupt when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxtcperfim(&self) -> RxtcperfimR {
        RxtcperfimR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Setting this bit masks the interrupt when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxicmpgfim(&self) -> RxicmpgfimR {
        RxicmpgfimR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Setting this bit masks the interrupt when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxicmperfim(&self) -> RxicmperfimR {
        RxicmperfimR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 16 - Setting this bit masks the interrupt when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4goim(&self) -> Rxipv4goimR {
        Rxipv4goimR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Setting this bit masks the interrupt when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4heroim(&self) -> Rxipv4heroimR {
        Rxipv4heroimR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Setting this bit masks the interrupt when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4nopayoim(&self) -> Rxipv4nopayoimR {
        Rxipv4nopayoimR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Setting this bit masks the interrupt when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4fragoim(&self) -> Rxipv4fragoimR {
        Rxipv4fragoimR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Setting this bit masks the interrupt when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4udsbloim(&self) -> Rxipv4udsbloimR {
        Rxipv4udsbloimR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Setting this bit masks the interrupt when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6goim(&self) -> Rxipv6goimR {
        Rxipv6goimR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Setting this bit masks interrupt when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6heroim(&self) -> Rxipv6heroimR {
        Rxipv6heroimR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Setting this bit masks the interrupt when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6nopayoim(&self) -> Rxipv6nopayoimR {
        Rxipv6nopayoimR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Setting this bit masks the interrupt when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxudpgoim(&self) -> RxudpgoimR {
        RxudpgoimR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Setting this bit masks the interrupt when the rxudp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxudperoim(&self) -> RxudperoimR {
        RxudperoimR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Setting this bit masks the interrupt when the rxtcp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxtcpgoim(&self) -> RxtcpgoimR {
        RxtcpgoimR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Setting this bit masks the interrupt when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxtcperoim(&self) -> RxtcperoimR {
        RxtcperoimR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Setting this bit masks the interrupt when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxicmpgoim(&self) -> RxicmpgoimR {
        RxicmpgoimR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Setting this bit masks the interrupt when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxicmperoim(&self) -> RxicmperoimR {
        RxicmperoimR::new(((self.bits >> 29) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Setting this bit masks the interrupt when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4gfim(&mut self) -> Rxipv4gfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4gfimW::new(self, 0)
    }
    #[doc = "Bit 1 - Setting this bit masks the interrupt when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4herfim(&mut self) -> Rxipv4herfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4herfimW::new(self, 1)
    }
    #[doc = "Bit 2 - Setting this bit masks the interrupt when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4nopayfim(&mut self) -> Rxipv4nopayfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4nopayfimW::new(self, 2)
    }
    #[doc = "Bit 3 - Setting this bit masks the interrupt when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4fragfim(&mut self) -> Rxipv4fragfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4fragfimW::new(self, 3)
    }
    #[doc = "Bit 4 - Setting this bit masks the interrupt when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4udsblfim(&mut self) -> Rxipv4udsblfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4udsblfimW::new(self, 4)
    }
    #[doc = "Bit 5 - Setting this bit masks the interrupt when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6gfim(&mut self) -> Rxipv6gfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv6gfimW::new(self, 5)
    }
    #[doc = "Bit 6 - Setting this bit masks the interrupt when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6herfim(&mut self) -> Rxipv6herfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv6herfimW::new(self, 6)
    }
    #[doc = "Bit 7 - Setting this bit masks the interrupt when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6nopayfim(&mut self) -> Rxipv6nopayfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv6nopayfimW::new(self, 7)
    }
    #[doc = "Bit 8 - Setting this bit masks the interrupt when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxudpgfim(&mut self) -> RxudpgfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxudpgfimW::new(self, 8)
    }
    #[doc = "Bit 9 - Setting this bit masks the interrupt when the rxudp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxudperfim(&mut self) -> RxudperfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxudperfimW::new(self, 9)
    }
    #[doc = "Bit 10 - Setting this bit masks the interrupt when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxtcpgfim(&mut self) -> RxtcpgfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxtcpgfimW::new(self, 10)
    }
    #[doc = "Bit 11 - Setting this bit masks the interrupt when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxtcperfim(&mut self) -> RxtcperfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxtcperfimW::new(self, 11)
    }
    #[doc = "Bit 12 - Setting this bit masks the interrupt when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxicmpgfim(&mut self) -> RxicmpgfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxicmpgfimW::new(self, 12)
    }
    #[doc = "Bit 13 - Setting this bit masks the interrupt when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxicmperfim(&mut self) -> RxicmperfimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxicmperfimW::new(self, 13)
    }
    #[doc = "Bit 16 - Setting this bit masks the interrupt when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4goim(&mut self) -> Rxipv4goimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4goimW::new(self, 16)
    }
    #[doc = "Bit 17 - Setting this bit masks the interrupt when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4heroim(&mut self) -> Rxipv4heroimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4heroimW::new(self, 17)
    }
    #[doc = "Bit 18 - Setting this bit masks the interrupt when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4nopayoim(&mut self) -> Rxipv4nopayoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4nopayoimW::new(self, 18)
    }
    #[doc = "Bit 19 - Setting this bit masks the interrupt when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4fragoim(&mut self) -> Rxipv4fragoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4fragoimW::new(self, 19)
    }
    #[doc = "Bit 20 - Setting this bit masks the interrupt when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4udsbloim(&mut self) -> Rxipv4udsbloimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv4udsbloimW::new(self, 20)
    }
    #[doc = "Bit 21 - Setting this bit masks the interrupt when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6goim(&mut self) -> Rxipv6goimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv6goimW::new(self, 21)
    }
    #[doc = "Bit 22 - Setting this bit masks interrupt when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6heroim(&mut self) -> Rxipv6heroimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv6heroimW::new(self, 22)
    }
    #[doc = "Bit 23 - Setting this bit masks the interrupt when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6nopayoim(&mut self) -> Rxipv6nopayoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        Rxipv6nopayoimW::new(self, 23)
    }
    #[doc = "Bit 24 - Setting this bit masks the interrupt when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxudpgoim(&mut self) -> RxudpgoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxudpgoimW::new(self, 24)
    }
    #[doc = "Bit 25 - Setting this bit masks the interrupt when the rxudp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxudperoim(&mut self) -> RxudperoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxudperoimW::new(self, 25)
    }
    #[doc = "Bit 26 - Setting this bit masks the interrupt when the rxtcp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxtcpgoim(&mut self) -> RxtcpgoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxtcpgoimW::new(self, 26)
    }
    #[doc = "Bit 27 - Setting this bit masks the interrupt when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxtcperoim(&mut self) -> RxtcperoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxtcperoimW::new(self, 27)
    }
    #[doc = "Bit 28 - Setting this bit masks the interrupt when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxicmpgoim(&mut self) -> RxicmpgoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxicmpgoimW::new(self, 28)
    }
    #[doc = "Bit 29 - Setting this bit masks the interrupt when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxicmperoim(&mut self) -> RxicmperoimW<GmacgrpMmcIpcReceiveInterruptMaskSpec> {
        RxicmperoimW::new(self, 29)
    }
}
#[doc = "This register maintains the mask for the interrupt generated from the receive IPC statistic counters.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_ipc_receive_interrupt_mask::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_mmc_ipc_receive_interrupt_mask::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMmcIpcReceiveInterruptMaskSpec;
impl crate::RegisterSpec for GmacgrpMmcIpcReceiveInterruptMaskSpec {
    type Ux = u32;
    const OFFSET: u64 = 512u64;
}
#[doc = "`read()` method returns [`gmacgrp_mmc_ipc_receive_interrupt_mask::R`](R) reader structure"]
impl crate::Readable for GmacgrpMmcIpcReceiveInterruptMaskSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_mmc_ipc_receive_interrupt_mask::W`](W) writer structure"]
impl crate::Writable for GmacgrpMmcIpcReceiveInterruptMaskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_MMC_IPC_Receive_Interrupt_Mask to value 0"]
impl crate::Resettable for GmacgrpMmcIpcReceiveInterruptMaskSpec {
    const RESET_VALUE: u32 = 0;
}
