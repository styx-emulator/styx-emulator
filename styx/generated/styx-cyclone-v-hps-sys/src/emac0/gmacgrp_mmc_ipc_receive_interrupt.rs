// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_MMC_IPC_Receive_Interrupt` reader"]
pub type R = crate::R<GmacgrpMmcIpcReceiveInterruptSpec>;
#[doc = "Register `gmacgrp_MMC_IPC_Receive_Interrupt` writer"]
pub type W = crate::W<GmacgrpMmcIpcReceiveInterruptSpec>;
#[doc = "This bit is set when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4gfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4gfis> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4gfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4gfis` reader - This bit is set when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4gfisR = crate::BitReader<Rxipv4gfis>;
impl Rxipv4gfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4gfis {
        match self.bits {
            false => Rxipv4gfis::Nointerrupt,
            true => Rxipv4gfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4gfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4gfis::Interr
    }
}
#[doc = "Field `rxipv4gfis` writer - This bit is set when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4gfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4herfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4herfis> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4herfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4herfis` reader - This bit is set when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4herfisR = crate::BitReader<Rxipv4herfis>;
impl Rxipv4herfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4herfis {
        match self.bits {
            false => Rxipv4herfis::Nointerrupt,
            true => Rxipv4herfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4herfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4herfis::Interr
    }
}
#[doc = "Field `rxipv4herfis` writer - This bit is set when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4herfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4nopayfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4nopayfis> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4nopayfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4nopayfis` reader - This bit is set when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4nopayfisR = crate::BitReader<Rxipv4nopayfis>;
impl Rxipv4nopayfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4nopayfis {
        match self.bits {
            false => Rxipv4nopayfis::Nointerrupt,
            true => Rxipv4nopayfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4nopayfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4nopayfis::Interr
    }
}
#[doc = "Field `rxipv4nopayfis` writer - This bit is set when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4nopayfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4fragfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4fragfis> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4fragfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4fragfis` reader - This bit is set when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4fragfisR = crate::BitReader<Rxipv4fragfis>;
impl Rxipv4fragfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4fragfis {
        match self.bits {
            false => Rxipv4fragfis::Nointerrupt,
            true => Rxipv4fragfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4fragfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4fragfis::Interr
    }
}
#[doc = "Field `rxipv4fragfis` writer - This bit is set when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4fragfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4udsblfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4udsblfis> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4udsblfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4udsblfis` reader - This bit is set when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4udsblfisR = crate::BitReader<Rxipv4udsblfis>;
impl Rxipv4udsblfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4udsblfis {
        match self.bits {
            false => Rxipv4udsblfis::Nointerrupt,
            true => Rxipv4udsblfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4udsblfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4udsblfis::Interr
    }
}
#[doc = "Field `rxipv4udsblfis` writer - This bit is set when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4udsblfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6gfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv6gfis> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6gfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6gfis` reader - This bit is set when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6gfisR = crate::BitReader<Rxipv6gfis>;
impl Rxipv6gfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6gfis {
        match self.bits {
            false => Rxipv6gfis::Nointerrupt,
            true => Rxipv6gfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv6gfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv6gfis::Interr
    }
}
#[doc = "Field `rxipv6gfis` writer - This bit is set when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6gfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6herfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv6herfis> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6herfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6herfis` reader - This bit is set when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6herfisR = crate::BitReader<Rxipv6herfis>;
impl Rxipv6herfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6herfis {
        match self.bits {
            false => Rxipv6herfis::Nointerrupt,
            true => Rxipv6herfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv6herfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv6herfis::Interr
    }
}
#[doc = "Field `rxipv6herfis` writer - This bit is set when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6herfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6nopayfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv6nopayfis> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6nopayfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6nopayfis` reader - This bit is set when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6nopayfisR = crate::BitReader<Rxipv6nopayfis>;
impl Rxipv6nopayfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6nopayfis {
        match self.bits {
            false => Rxipv6nopayfis::Nointerrupt,
            true => Rxipv6nopayfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv6nopayfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv6nopayfis::Interr
    }
}
#[doc = "Field `rxipv6nopayfis` writer - This bit is set when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6nopayfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxudpgfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxudpgfis> for bool {
    #[inline(always)]
    fn from(variant: Rxudpgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxudpgfis` reader - This bit is set when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxudpgfisR = crate::BitReader<Rxudpgfis>;
impl RxudpgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxudpgfis {
        match self.bits {
            false => Rxudpgfis::Nointerrupt,
            true => Rxudpgfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxudpgfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxudpgfis::Interr
    }
}
#[doc = "Field `rxudpgfis` writer - This bit is set when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxudpgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxudp_err_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxudperfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxudperfis> for bool {
    #[inline(always)]
    fn from(variant: Rxudperfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxudperfis` reader - This bit is set when the rxudp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxudperfisR = crate::BitReader<Rxudperfis>;
impl RxudperfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxudperfis {
        match self.bits {
            false => Rxudperfis::Nointerrupt,
            true => Rxudperfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxudperfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxudperfis::Interr
    }
}
#[doc = "Field `rxudperfis` writer - This bit is set when the rxudp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxudperfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtcpgfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxtcpgfis> for bool {
    #[inline(always)]
    fn from(variant: Rxtcpgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtcpgfis` reader - This bit is set when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxtcpgfisR = crate::BitReader<Rxtcpgfis>;
impl RxtcpgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtcpgfis {
        match self.bits {
            false => Rxtcpgfis::Nointerrupt,
            true => Rxtcpgfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxtcpgfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxtcpgfis::Interr
    }
}
#[doc = "Field `rxtcpgfis` writer - This bit is set when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxtcpgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtcperfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxtcperfis> for bool {
    #[inline(always)]
    fn from(variant: Rxtcperfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtcperfis` reader - This bit is set when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxtcperfisR = crate::BitReader<Rxtcperfis>;
impl RxtcperfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtcperfis {
        match self.bits {
            false => Rxtcperfis::Nointerrupt,
            true => Rxtcperfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxtcperfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxtcperfis::Interr
    }
}
#[doc = "Field `rxtcperfis` writer - This bit is set when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxtcperfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxicmpgfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxicmpgfis> for bool {
    #[inline(always)]
    fn from(variant: Rxicmpgfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxicmpgfis` reader - This bit is set when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxicmpgfisR = crate::BitReader<Rxicmpgfis>;
impl RxicmpgfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxicmpgfis {
        match self.bits {
            false => Rxicmpgfis::Nointerrupt,
            true => Rxicmpgfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxicmpgfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxicmpgfis::Interr
    }
}
#[doc = "Field `rxicmpgfis` writer - This bit is set when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value."]
pub type RxicmpgfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxicmperfis {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxicmperfis> for bool {
    #[inline(always)]
    fn from(variant: Rxicmperfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxicmperfis` reader - This bit is set when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxicmperfisR = crate::BitReader<Rxicmperfis>;
impl RxicmperfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxicmperfis {
        match self.bits {
            false => Rxicmperfis::Nointerrupt,
            true => Rxicmperfis::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxicmperfis::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxicmperfis::Interr
    }
}
#[doc = "Field `rxicmperfis` writer - This bit is set when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value."]
pub type RxicmperfisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4gois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4gois> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4gois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4gois` reader - This bit is set when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4goisR = crate::BitReader<Rxipv4gois>;
impl Rxipv4goisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4gois {
        match self.bits {
            false => Rxipv4gois::Nointerrupt,
            true => Rxipv4gois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4gois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4gois::Interr
    }
}
#[doc = "Field `rxipv4gois` writer - This bit is set when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4goisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4herois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4herois> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4herois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4herois` reader - This bit is set when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4heroisR = crate::BitReader<Rxipv4herois>;
impl Rxipv4heroisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4herois {
        match self.bits {
            false => Rxipv4herois::Nointerrupt,
            true => Rxipv4herois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4herois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4herois::Interr
    }
}
#[doc = "Field `rxipv4herois` writer - This bit is set when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4heroisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4nopayois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4nopayois> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4nopayois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4nopayois` reader - This bit is set when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4nopayoisR = crate::BitReader<Rxipv4nopayois>;
impl Rxipv4nopayoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4nopayois {
        match self.bits {
            false => Rxipv4nopayois::Nointerrupt,
            true => Rxipv4nopayois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4nopayois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4nopayois::Interr
    }
}
#[doc = "Field `rxipv4nopayois` writer - This bit is set when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4nopayoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4fragois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4fragois> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4fragois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4fragois` reader - This bit is set when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4fragoisR = crate::BitReader<Rxipv4fragois>;
impl Rxipv4fragoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4fragois {
        match self.bits {
            false => Rxipv4fragois::Nointerrupt,
            true => Rxipv4fragois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4fragois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4fragois::Interr
    }
}
#[doc = "Field `rxipv4fragois` writer - This bit is set when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4fragoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv4udsblois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv4udsblois> for bool {
    #[inline(always)]
    fn from(variant: Rxipv4udsblois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv4udsblois` reader - This bit is set when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4udsbloisR = crate::BitReader<Rxipv4udsblois>;
impl Rxipv4udsbloisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv4udsblois {
        match self.bits {
            false => Rxipv4udsblois::Nointerrupt,
            true => Rxipv4udsblois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv4udsblois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv4udsblois::Interr
    }
}
#[doc = "Field `rxipv4udsblois` writer - This bit is set when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv4udsbloisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6gois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv6gois> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6gois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6gois` reader - This bit is set when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6goisR = crate::BitReader<Rxipv6gois>;
impl Rxipv6goisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6gois {
        match self.bits {
            false => Rxipv6gois::Nointerrupt,
            true => Rxipv6gois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv6gois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv6gois::Interr
    }
}
#[doc = "Field `rxipv6gois` writer - This bit is set when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6goisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6herois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv6herois> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6herois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6herois` reader - This bit is set when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6heroisR = crate::BitReader<Rxipv6herois>;
impl Rxipv6heroisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6herois {
        match self.bits {
            false => Rxipv6herois::Nointerrupt,
            true => Rxipv6herois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv6herois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv6herois::Interr
    }
}
#[doc = "Field `rxipv6herois` writer - This bit is set when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6heroisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxipv6nopayois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxipv6nopayois> for bool {
    #[inline(always)]
    fn from(variant: Rxipv6nopayois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxipv6nopayois` reader - This bit is set when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6nopayoisR = crate::BitReader<Rxipv6nopayois>;
impl Rxipv6nopayoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxipv6nopayois {
        match self.bits {
            false => Rxipv6nopayois::Nointerrupt,
            true => Rxipv6nopayois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxipv6nopayois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxipv6nopayois::Interr
    }
}
#[doc = "Field `rxipv6nopayois` writer - This bit is set when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value."]
pub type Rxipv6nopayoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxudpgois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxudpgois> for bool {
    #[inline(always)]
    fn from(variant: Rxudpgois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxudpgois` reader - This bit is set when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxudpgoisR = crate::BitReader<Rxudpgois>;
impl RxudpgoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxudpgois {
        match self.bits {
            false => Rxudpgois::Nointerrupt,
            true => Rxudpgois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxudpgois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxudpgois::Interr
    }
}
#[doc = "Field `rxudpgois` writer - This bit is set when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxudpgoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxudp_err_octets counter reaches half the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxudperois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxudperois> for bool {
    #[inline(always)]
    fn from(variant: Rxudperois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxudperois` reader - This bit is set when the rxudp_err_octets counter reaches half the maximum value or the maximum value."]
pub type RxudperoisR = crate::BitReader<Rxudperois>;
impl RxudperoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxudperois {
        match self.bits {
            false => Rxudperois::Nointerrupt,
            true => Rxudperois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxudperois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxudperois::Interr
    }
}
#[doc = "Field `rxudperois` writer - This bit is set when the rxudp_err_octets counter reaches half the maximum value or the maximum value."]
pub type RxudperoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxtcp_gd_octets counter reaches half the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtcpgois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxtcpgois> for bool {
    #[inline(always)]
    fn from(variant: Rxtcpgois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtcpgois` reader - This bit is set when the rxtcp_gd_octets counter reaches half the maximum value or the maximum value."]
pub type RxtcpgoisR = crate::BitReader<Rxtcpgois>;
impl RxtcpgoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtcpgois {
        match self.bits {
            false => Rxtcpgois::Nointerrupt,
            true => Rxtcpgois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxtcpgois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxtcpgois::Interr
    }
}
#[doc = "Field `rxtcpgois` writer - This bit is set when the rxtcp_gd_octets counter reaches half the maximum value or the maximum value."]
pub type RxtcpgoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxtcperois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxtcperois> for bool {
    #[inline(always)]
    fn from(variant: Rxtcperois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxtcperois` reader - This bit is set when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxtcperoisR = crate::BitReader<Rxtcperois>;
impl RxtcperoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxtcperois {
        match self.bits {
            false => Rxtcperois::Nointerrupt,
            true => Rxtcperois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxtcperois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxtcperois::Interr
    }
}
#[doc = "Field `rxtcperois` writer - This bit is set when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxtcperoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxicmpgois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxicmpgois> for bool {
    #[inline(always)]
    fn from(variant: Rxicmpgois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxicmpgois` reader - This bit is set when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxicmpgoisR = crate::BitReader<Rxicmpgois>;
impl RxicmpgoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxicmpgois {
        match self.bits {
            false => Rxicmpgois::Nointerrupt,
            true => Rxicmpgois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxicmpgois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxicmpgois::Interr
    }
}
#[doc = "Field `rxicmpgois` writer - This bit is set when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value."]
pub type RxicmpgoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is set when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxicmperois {
    #[doc = "0: `0`"]
    Nointerrupt = 0,
    #[doc = "1: `1`"]
    Interr = 1,
}
impl From<Rxicmperois> for bool {
    #[inline(always)]
    fn from(variant: Rxicmperois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxicmperois` reader - This bit is set when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxicmperoisR = crate::BitReader<Rxicmperois>;
impl RxicmperoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxicmperois {
        match self.bits {
            false => Rxicmperois::Nointerrupt,
            true => Rxicmperois::Interr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrupt(&self) -> bool {
        *self == Rxicmperois::Nointerrupt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interr(&self) -> bool {
        *self == Rxicmperois::Interr
    }
}
#[doc = "Field `rxicmperois` writer - This bit is set when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value."]
pub type RxicmperoisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit is set when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4gfis(&self) -> Rxipv4gfisR {
        Rxipv4gfisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit is set when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4herfis(&self) -> Rxipv4herfisR {
        Rxipv4herfisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit is set when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4nopayfis(&self) -> Rxipv4nopayfisR {
        Rxipv4nopayfisR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit is set when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4fragfis(&self) -> Rxipv4fragfisR {
        Rxipv4fragfisR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is set when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4udsblfis(&self) -> Rxipv4udsblfisR {
        Rxipv4udsblfisR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit is set when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6gfis(&self) -> Rxipv6gfisR {
        Rxipv6gfisR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit is set when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6herfis(&self) -> Rxipv6herfisR {
        Rxipv6herfisR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit is set when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6nopayfis(&self) -> Rxipv6nopayfisR {
        Rxipv6nopayfisR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit is set when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxudpgfis(&self) -> RxudpgfisR {
        RxudpgfisR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit is set when the rxudp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxudperfis(&self) -> RxudperfisR {
        RxudperfisR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit is set when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxtcpgfis(&self) -> RxtcpgfisR {
        RxtcpgfisR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit is set when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxtcperfis(&self) -> RxtcperfisR {
        RxtcperfisR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - This bit is set when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxicmpgfis(&self) -> RxicmpgfisR {
        RxicmpgfisR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - This bit is set when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxicmperfis(&self) -> RxicmperfisR {
        RxicmperfisR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 16 - This bit is set when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4gois(&self) -> Rxipv4goisR {
        Rxipv4goisR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - This bit is set when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4herois(&self) -> Rxipv4heroisR {
        Rxipv4heroisR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - This bit is set when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4nopayois(&self) -> Rxipv4nopayoisR {
        Rxipv4nopayoisR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - This bit is set when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4fragois(&self) -> Rxipv4fragoisR {
        Rxipv4fragoisR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - This bit is set when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv4udsblois(&self) -> Rxipv4udsbloisR {
        Rxipv4udsbloisR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - This bit is set when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6gois(&self) -> Rxipv6goisR {
        Rxipv6goisR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - This bit is set when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6herois(&self) -> Rxipv6heroisR {
        Rxipv6heroisR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - This bit is set when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxipv6nopayois(&self) -> Rxipv6nopayoisR {
        Rxipv6nopayoisR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - This bit is set when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxudpgois(&self) -> RxudpgoisR {
        RxudpgoisR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - This bit is set when the rxudp_err_octets counter reaches half the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxudperois(&self) -> RxudperoisR {
        RxudperoisR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - This bit is set when the rxtcp_gd_octets counter reaches half the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxtcpgois(&self) -> RxtcpgoisR {
        RxtcpgoisR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - This bit is set when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxtcperois(&self) -> RxtcperoisR {
        RxtcperoisR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - This bit is set when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxicmpgois(&self) -> RxicmpgoisR {
        RxicmpgoisR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - This bit is set when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    pub fn rxicmperois(&self) -> RxicmperoisR {
        RxicmperoisR::new(((self.bits >> 29) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is set when the rxipv4_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4gfis(&mut self) -> Rxipv4gfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4gfisW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit is set when the rxipv4_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4herfis(&mut self) -> Rxipv4herfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4herfisW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit is set when the rxipv4_nopay_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4nopayfis(&mut self) -> Rxipv4nopayfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4nopayfisW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit is set when the rxipv4_frag_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4fragfis(&mut self) -> Rxipv4fragfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4fragfisW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit is set when the rxipv4_udsbl_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4udsblfis(&mut self) -> Rxipv4udsblfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4udsblfisW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit is set when the rxipv6_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6gfis(&mut self) -> Rxipv6gfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv6gfisW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit is set when the rxipv6_hdrerr_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6herfis(&mut self) -> Rxipv6herfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv6herfisW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit is set when the rxipv6_nopay_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6nopayfis(&mut self) -> Rxipv6nopayfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv6nopayfisW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit is set when the rxudp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxudpgfis(&mut self) -> RxudpgfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxudpgfisW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit is set when the rxudp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxudperfis(&mut self) -> RxudperfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxudperfisW::new(self, 9)
    }
    #[doc = "Bit 10 - This bit is set when the rxtcp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxtcpgfis(&mut self) -> RxtcpgfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxtcpgfisW::new(self, 10)
    }
    #[doc = "Bit 11 - This bit is set when the rxtcp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxtcperfis(&mut self) -> RxtcperfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxtcperfisW::new(self, 11)
    }
    #[doc = "Bit 12 - This bit is set when the rxicmp_gd_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxicmpgfis(&mut self) -> RxicmpgfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxicmpgfisW::new(self, 12)
    }
    #[doc = "Bit 13 - This bit is set when the rxicmp_err_frms counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxicmperfis(&mut self) -> RxicmperfisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxicmperfisW::new(self, 13)
    }
    #[doc = "Bit 16 - This bit is set when the rxipv4_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4gois(&mut self) -> Rxipv4goisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4goisW::new(self, 16)
    }
    #[doc = "Bit 17 - This bit is set when the rxipv4_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4herois(&mut self) -> Rxipv4heroisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4heroisW::new(self, 17)
    }
    #[doc = "Bit 18 - This bit is set when the rxipv4_nopay_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4nopayois(&mut self) -> Rxipv4nopayoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4nopayoisW::new(self, 18)
    }
    #[doc = "Bit 19 - This bit is set when the rxipv4_frag_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4fragois(&mut self) -> Rxipv4fragoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4fragoisW::new(self, 19)
    }
    #[doc = "Bit 20 - This bit is set when the rxipv4_udsbl_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv4udsblois(&mut self) -> Rxipv4udsbloisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv4udsbloisW::new(self, 20)
    }
    #[doc = "Bit 21 - This bit is set when the rxipv6_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6gois(&mut self) -> Rxipv6goisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv6goisW::new(self, 21)
    }
    #[doc = "Bit 22 - This bit is set when the rxipv6_hdrerr_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6herois(&mut self) -> Rxipv6heroisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv6heroisW::new(self, 22)
    }
    #[doc = "Bit 23 - This bit is set when the rxipv6_nopay_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxipv6nopayois(&mut self) -> Rxipv6nopayoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        Rxipv6nopayoisW::new(self, 23)
    }
    #[doc = "Bit 24 - This bit is set when the rxudp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxudpgois(&mut self) -> RxudpgoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxudpgoisW::new(self, 24)
    }
    #[doc = "Bit 25 - This bit is set when the rxudp_err_octets counter reaches half the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxudperois(&mut self) -> RxudperoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxudperoisW::new(self, 25)
    }
    #[doc = "Bit 26 - This bit is set when the rxtcp_gd_octets counter reaches half the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxtcpgois(&mut self) -> RxtcpgoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxtcpgoisW::new(self, 26)
    }
    #[doc = "Bit 27 - This bit is set when the rxtcp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxtcperois(&mut self) -> RxtcperoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxtcperoisW::new(self, 27)
    }
    #[doc = "Bit 28 - This bit is set when the rxicmp_gd_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxicmpgois(&mut self) -> RxicmpgoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxicmpgoisW::new(self, 28)
    }
    #[doc = "Bit 29 - This bit is set when the rxicmp_err_octets counter reaches half of the maximum value or the maximum value."]
    #[inline(always)]
    #[must_use]
    pub fn rxicmperois(&mut self) -> RxicmperoisW<GmacgrpMmcIpcReceiveInterruptSpec> {
        RxicmperoisW::new(self, 29)
    }
}
#[doc = "This register maintains the interrupts generated when receive IPC statistic counters reach half their maximum values (0x8000_0000 for 32-bit counter and 0x8000 for 16-bit counter), and when they cross their maximum values (0xFFFF_FFFF for 32-bit counter and 0xFFFF for 16-bit counter). When Counter Stop Rollover is set, then interrupts are set but the counter remains at all-ones. The MMC Receive Checksum Offload Interrupt register is 32-bits wide. When the MMC IPC counter that caused the interrupt is read, its corresponding interrupt bit is cleared. The counter's least-significant byte lane (bits\\[7:0\\]) must be read to clear the interrupt bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_mmc_ipc_receive_interrupt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpMmcIpcReceiveInterruptSpec;
impl crate::RegisterSpec for GmacgrpMmcIpcReceiveInterruptSpec {
    type Ux = u32;
    const OFFSET: u64 = 520u64;
}
#[doc = "`read()` method returns [`gmacgrp_mmc_ipc_receive_interrupt::R`](R) reader structure"]
impl crate::Readable for GmacgrpMmcIpcReceiveInterruptSpec {}
#[doc = "`reset()` method sets gmacgrp_MMC_IPC_Receive_Interrupt to value 0"]
impl crate::Resettable for GmacgrpMmcIpcReceiveInterruptSpec {
    const RESET_VALUE: u32 = 0;
}
