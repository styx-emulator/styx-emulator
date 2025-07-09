// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_ghwcfg2` reader"]
pub type R = crate::R<GlobgrpGhwcfg2Spec>;
#[doc = "Register `globgrp_ghwcfg2` writer"]
pub type W = crate::W<GlobgrpGhwcfg2Spec>;
#[doc = "HNP- and SRP-Capable OTG (Device and Host).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Otgmode {
    #[doc = "0: `0`"]
    Hnpsrp = 0,
    #[doc = "1: `1`"]
    Srpotg = 1,
    #[doc = "2: `10`"]
    Nhnpnsrp = 2,
    #[doc = "3: `11`"]
    Srpcapd = 3,
    #[doc = "4: `100`"]
    Nonotgd = 4,
    #[doc = "5: `101`"]
    Srpcaph = 5,
    #[doc = "6: `110`"]
    Nonotgh = 6,
}
impl From<Otgmode> for u8 {
    #[inline(always)]
    fn from(variant: Otgmode) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Otgmode {
    type Ux = u8;
}
#[doc = "Field `otgmode` reader - HNP- and SRP-Capable OTG (Device and Host)."]
pub type OtgmodeR = crate::FieldReader<Otgmode>;
impl OtgmodeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Otgmode> {
        match self.bits {
            0 => Some(Otgmode::Hnpsrp),
            1 => Some(Otgmode::Srpotg),
            2 => Some(Otgmode::Nhnpnsrp),
            3 => Some(Otgmode::Srpcapd),
            4 => Some(Otgmode::Nonotgd),
            5 => Some(Otgmode::Srpcaph),
            6 => Some(Otgmode::Nonotgh),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_hnpsrp(&self) -> bool {
        *self == Otgmode::Hnpsrp
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_srpotg(&self) -> bool {
        *self == Otgmode::Srpotg
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_nhnpnsrp(&self) -> bool {
        *self == Otgmode::Nhnpnsrp
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_srpcapd(&self) -> bool {
        *self == Otgmode::Srpcapd
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_nonotgd(&self) -> bool {
        *self == Otgmode::Nonotgd
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_srpcaph(&self) -> bool {
        *self == Otgmode::Srpcaph
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_nonotgh(&self) -> bool {
        *self == Otgmode::Nonotgh
    }
}
#[doc = "Field `otgmode` writer - HNP- and SRP-Capable OTG (Device and Host)."]
pub type OtgmodeW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "DMA Architecture.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Otgarch {
    #[doc = "2: `10`"]
    Dmamode = 2,
}
impl From<Otgarch> for u8 {
    #[inline(always)]
    fn from(variant: Otgarch) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Otgarch {
    type Ux = u8;
}
#[doc = "Field `otgarch` reader - DMA Architecture."]
pub type OtgarchR = crate::FieldReader<Otgarch>;
impl OtgarchR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Otgarch> {
        match self.bits {
            2 => Some(Otgarch::Dmamode),
            _ => None,
        }
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_dmamode(&self) -> bool {
        *self == Otgarch::Dmamode
    }
}
#[doc = "Field `otgarch` writer - DMA Architecture."]
pub type OtgarchW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Single Point Only.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Singpnt {
    #[doc = "1: `1`"]
    Singlepoint = 1,
}
impl From<Singpnt> for bool {
    #[inline(always)]
    fn from(variant: Singpnt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `singpnt` reader - Single Point Only."]
pub type SingpntR = crate::BitReader<Singpnt>;
impl SingpntR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Singpnt> {
        match self.bits {
            true => Some(Singpnt::Singlepoint),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_singlepoint(&self) -> bool {
        *self == Singpnt::Singlepoint
    }
}
#[doc = "Field `singpnt` writer - Single Point Only."]
pub type SingpntW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies the High Speed PHY in use.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Hsphytype {
    #[doc = "0: `0`"]
    Nohs = 0,
    #[doc = "2: `10`"]
    Ulpi = 2,
}
impl From<Hsphytype> for u8 {
    #[inline(always)]
    fn from(variant: Hsphytype) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Hsphytype {
    type Ux = u8;
}
#[doc = "Field `hsphytype` reader - Specifies the High Speed PHY in use."]
pub type HsphytypeR = crate::FieldReader<Hsphytype>;
impl HsphytypeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Hsphytype> {
        match self.bits {
            0 => Some(Hsphytype::Nohs),
            2 => Some(Hsphytype::Ulpi),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nohs(&self) -> bool {
        *self == Hsphytype::Nohs
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_ulpi(&self) -> bool {
        *self == Hsphytype::Ulpi
    }
}
#[doc = "Field `hsphytype` writer - Specifies the High Speed PHY in use."]
pub type HsphytypeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Specifies the Full Speed PHY in use.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Fsphytype {
    #[doc = "2: `10`"]
    Fullspeed = 2,
}
impl From<Fsphytype> for u8 {
    #[inline(always)]
    fn from(variant: Fsphytype) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Fsphytype {
    type Ux = u8;
}
#[doc = "Field `fsphytype` reader - Specifies the Full Speed PHY in use."]
pub type FsphytypeR = crate::FieldReader<Fsphytype>;
impl FsphytypeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Fsphytype> {
        match self.bits {
            2 => Some(Fsphytype::Fullspeed),
            _ => None,
        }
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_fullspeed(&self) -> bool {
        *self == Fsphytype::Fullspeed
    }
}
#[doc = "Field `fsphytype` writer - Specifies the Full Speed PHY in use."]
pub type FsphytypeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "The number of endpoints is 1 to 15 in Device mode in addition to control endpoint 0.\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Numdeveps {
    #[doc = "0: `0`"]
    Endpt0 = 0,
    #[doc = "1: `1`"]
    Endpt1 = 1,
    #[doc = "2: `10`"]
    Endpt2 = 2,
    #[doc = "3: `11`"]
    Endpt3 = 3,
    #[doc = "4: `100`"]
    Endpt4 = 4,
    #[doc = "5: `101`"]
    Endpt5 = 5,
    #[doc = "6: `110`"]
    Endpt6 = 6,
    #[doc = "7: `111`"]
    Endpt7 = 7,
    #[doc = "8: `1000`"]
    Endpt8 = 8,
    #[doc = "9: `1001`"]
    Endpt9 = 9,
    #[doc = "10: `1010`"]
    Endpt10 = 10,
    #[doc = "11: `1011`"]
    Endpt11 = 11,
    #[doc = "12: `1100`"]
    Endpt12 = 12,
    #[doc = "13: `1101`"]
    Endpt13 = 13,
    #[doc = "14: `1110`"]
    Endpt14 = 14,
    #[doc = "15: `1111`"]
    Endpt15 = 15,
}
impl From<Numdeveps> for u8 {
    #[inline(always)]
    fn from(variant: Numdeveps) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Numdeveps {
    type Ux = u8;
}
#[doc = "Field `numdeveps` reader - The number of endpoints is 1 to 15 in Device mode in addition to control endpoint 0."]
pub type NumdevepsR = crate::FieldReader<Numdeveps>;
impl NumdevepsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Numdeveps {
        match self.bits {
            0 => Numdeveps::Endpt0,
            1 => Numdeveps::Endpt1,
            2 => Numdeveps::Endpt2,
            3 => Numdeveps::Endpt3,
            4 => Numdeveps::Endpt4,
            5 => Numdeveps::Endpt5,
            6 => Numdeveps::Endpt6,
            7 => Numdeveps::Endpt7,
            8 => Numdeveps::Endpt8,
            9 => Numdeveps::Endpt9,
            10 => Numdeveps::Endpt10,
            11 => Numdeveps::Endpt11,
            12 => Numdeveps::Endpt12,
            13 => Numdeveps::Endpt13,
            14 => Numdeveps::Endpt14,
            15 => Numdeveps::Endpt15,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_endpt0(&self) -> bool {
        *self == Numdeveps::Endpt0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_endpt1(&self) -> bool {
        *self == Numdeveps::Endpt1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_endpt2(&self) -> bool {
        *self == Numdeveps::Endpt2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_endpt3(&self) -> bool {
        *self == Numdeveps::Endpt3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_endpt4(&self) -> bool {
        *self == Numdeveps::Endpt4
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_endpt5(&self) -> bool {
        *self == Numdeveps::Endpt5
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_endpt6(&self) -> bool {
        *self == Numdeveps::Endpt6
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_endpt7(&self) -> bool {
        *self == Numdeveps::Endpt7
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_endpt8(&self) -> bool {
        *self == Numdeveps::Endpt8
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_endpt9(&self) -> bool {
        *self == Numdeveps::Endpt9
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_endpt10(&self) -> bool {
        *self == Numdeveps::Endpt10
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_endpt11(&self) -> bool {
        *self == Numdeveps::Endpt11
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_endpt12(&self) -> bool {
        *self == Numdeveps::Endpt12
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_endpt13(&self) -> bool {
        *self == Numdeveps::Endpt13
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_endpt14(&self) -> bool {
        *self == Numdeveps::Endpt14
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_endpt15(&self) -> bool {
        *self == Numdeveps::Endpt15
    }
}
#[doc = "Field `numdeveps` writer - The number of endpoints is 1 to 15 in Device mode in addition to control endpoint 0."]
pub type NumdevepsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Indicates the number of host channels supported by the core in Host mode.\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Numhstchnl {
    #[doc = "0: `0`"]
    Hostch0 = 0,
    #[doc = "1: `1`"]
    Hostch1 = 1,
    #[doc = "2: `10`"]
    Hostch2 = 2,
    #[doc = "3: `11`"]
    Hostch3 = 3,
    #[doc = "4: `100`"]
    Hostch4 = 4,
    #[doc = "5: `101`"]
    Hostch5 = 5,
    #[doc = "6: `110`"]
    Hostch6 = 6,
    #[doc = "7: `111`"]
    Hostch7 = 7,
    #[doc = "8: `1000`"]
    Hostch8 = 8,
    #[doc = "9: `1001`"]
    Hostch9 = 9,
    #[doc = "10: `1010`"]
    Hostch10 = 10,
    #[doc = "11: `1011`"]
    Hostch11 = 11,
    #[doc = "12: `1100`"]
    Hostch12 = 12,
    #[doc = "13: `1101`"]
    Hostch13 = 13,
    #[doc = "14: `1110`"]
    Hostch14 = 14,
    #[doc = "15: `1111`"]
    Hostch15 = 15,
}
impl From<Numhstchnl> for u8 {
    #[inline(always)]
    fn from(variant: Numhstchnl) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Numhstchnl {
    type Ux = u8;
}
#[doc = "Field `numhstchnl` reader - Indicates the number of host channels supported by the core in Host mode."]
pub type NumhstchnlR = crate::FieldReader<Numhstchnl>;
impl NumhstchnlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Numhstchnl {
        match self.bits {
            0 => Numhstchnl::Hostch0,
            1 => Numhstchnl::Hostch1,
            2 => Numhstchnl::Hostch2,
            3 => Numhstchnl::Hostch3,
            4 => Numhstchnl::Hostch4,
            5 => Numhstchnl::Hostch5,
            6 => Numhstchnl::Hostch6,
            7 => Numhstchnl::Hostch7,
            8 => Numhstchnl::Hostch8,
            9 => Numhstchnl::Hostch9,
            10 => Numhstchnl::Hostch10,
            11 => Numhstchnl::Hostch11,
            12 => Numhstchnl::Hostch12,
            13 => Numhstchnl::Hostch13,
            14 => Numhstchnl::Hostch14,
            15 => Numhstchnl::Hostch15,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_hostch0(&self) -> bool {
        *self == Numhstchnl::Hostch0
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_hostch1(&self) -> bool {
        *self == Numhstchnl::Hostch1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_hostch2(&self) -> bool {
        *self == Numhstchnl::Hostch2
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_hostch3(&self) -> bool {
        *self == Numhstchnl::Hostch3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_hostch4(&self) -> bool {
        *self == Numhstchnl::Hostch4
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_hostch5(&self) -> bool {
        *self == Numhstchnl::Hostch5
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_hostch6(&self) -> bool {
        *self == Numhstchnl::Hostch6
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_hostch7(&self) -> bool {
        *self == Numhstchnl::Hostch7
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_hostch8(&self) -> bool {
        *self == Numhstchnl::Hostch8
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_hostch9(&self) -> bool {
        *self == Numhstchnl::Hostch9
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_hostch10(&self) -> bool {
        *self == Numhstchnl::Hostch10
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_hostch11(&self) -> bool {
        *self == Numhstchnl::Hostch11
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_hostch12(&self) -> bool {
        *self == Numhstchnl::Hostch12
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_hostch13(&self) -> bool {
        *self == Numhstchnl::Hostch13
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_hostch14(&self) -> bool {
        *self == Numhstchnl::Hostch14
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_hostch15(&self) -> bool {
        *self == Numhstchnl::Hostch15
    }
}
#[doc = "Field `numhstchnl` writer - Indicates the number of host channels supported by the core in Host mode."]
pub type NumhstchnlW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Feature supported.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Periosupport {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Periosupport> for bool {
    #[inline(always)]
    fn from(variant: Periosupport) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `periosupport` reader - Feature supported."]
pub type PeriosupportR = crate::BitReader<Periosupport>;
impl PeriosupportR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Periosupport> {
        match self.bits {
            true => Some(Periosupport::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Periosupport::Enabled
    }
}
#[doc = "Field `periosupport` writer - Feature supported."]
pub type PeriosupportW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Feature supported.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dynfifosizing {
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Dynfifosizing> for bool {
    #[inline(always)]
    fn from(variant: Dynfifosizing) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `dynfifosizing` reader - Feature supported."]
pub type DynfifosizingR = crate::BitReader<Dynfifosizing>;
impl DynfifosizingR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Dynfifosizing> {
        match self.bits {
            true => Some(Dynfifosizing::Enabled),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Dynfifosizing::Enabled
    }
}
#[doc = "Field `dynfifosizing` writer - Feature supported."]
pub type DynfifosizingW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Not implemented.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Multiprocintrpt {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Multiprocintrpt> for bool {
    #[inline(always)]
    fn from(variant: Multiprocintrpt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `multiprocintrpt` reader - Not implemented."]
pub type MultiprocintrptR = crate::BitReader<Multiprocintrpt>;
impl MultiprocintrptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Multiprocintrpt> {
        match self.bits {
            false => Some(Multiprocintrpt::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Multiprocintrpt::Disabled
    }
}
#[doc = "Field `multiprocintrpt` writer - Not implemented."]
pub type MultiprocintrptW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Specifies the Non-periodic Request Queue depth, the maximum number of packets that can reside in the Non-periodic TxFIFO. In Device mode, the queue is used only in Shared FIFO Mode (Enable Dedicated Transmit FIFO for device IN Endpoints? =No). In this mode, there is one entry in the Non-periodic Request Queue for each packet in the Non-periodic TxFIFO. In Host mode, this queue holds one entry corresponding to each IN or OUT nonperiodic request. This queue is seven bits wide.\n\nValue on reset: 2"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Nptxqdepth {
    #[doc = "0: `0`"]
    Two = 0,
    #[doc = "1: `1`"]
    Four = 1,
    #[doc = "2: `10`"]
    Eight = 2,
}
impl From<Nptxqdepth> for u8 {
    #[inline(always)]
    fn from(variant: Nptxqdepth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Nptxqdepth {
    type Ux = u8;
}
#[doc = "Field `nptxqdepth` reader - Specifies the Non-periodic Request Queue depth, the maximum number of packets that can reside in the Non-periodic TxFIFO. In Device mode, the queue is used only in Shared FIFO Mode (Enable Dedicated Transmit FIFO for device IN Endpoints? =No). In this mode, there is one entry in the Non-periodic Request Queue for each packet in the Non-periodic TxFIFO. In Host mode, this queue holds one entry corresponding to each IN or OUT nonperiodic request. This queue is seven bits wide."]
pub type NptxqdepthR = crate::FieldReader<Nptxqdepth>;
impl NptxqdepthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Nptxqdepth> {
        match self.bits {
            0 => Some(Nptxqdepth::Two),
            1 => Some(Nptxqdepth::Four),
            2 => Some(Nptxqdepth::Eight),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_two(&self) -> bool {
        *self == Nptxqdepth::Two
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_four(&self) -> bool {
        *self == Nptxqdepth::Four
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_eight(&self) -> bool {
        *self == Nptxqdepth::Eight
    }
}
#[doc = "Field `nptxqdepth` writer - Specifies the Non-periodic Request Queue depth, the maximum number of packets that can reside in the Non-periodic TxFIFO. In Device mode, the queue is used only in Shared FIFO Mode (Enable Dedicated Transmit FIFO for device IN Endpoints? =No). In this mode, there is one entry in the Non-periodic Request Queue for each packet in the Non-periodic TxFIFO. In Host mode, this queue holds one entry corresponding to each IN or OUT nonperiodic request. This queue is seven bits wide."]
pub type NptxqdepthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Specifies the Host mode Periodic Request Queue depth.That is, the maximum number of packets that can reside in the Host Periodic TxFIFO. This queue holds one entry corresponding to each IN or OUT periodic request. This queue is 9 bits wide.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ptxqdepth {
    #[doc = "0: `0`"]
    Que2 = 0,
    #[doc = "1: `1`"]
    Que4 = 1,
    #[doc = "2: `10`"]
    Que8 = 2,
    #[doc = "3: `11`"]
    Que16 = 3,
}
impl From<Ptxqdepth> for u8 {
    #[inline(always)]
    fn from(variant: Ptxqdepth) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ptxqdepth {
    type Ux = u8;
}
#[doc = "Field `ptxqdepth` reader - Specifies the Host mode Periodic Request Queue depth.That is, the maximum number of packets that can reside in the Host Periodic TxFIFO. This queue holds one entry corresponding to each IN or OUT periodic request. This queue is 9 bits wide."]
pub type PtxqdepthR = crate::FieldReader<Ptxqdepth>;
impl PtxqdepthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ptxqdepth {
        match self.bits {
            0 => Ptxqdepth::Que2,
            1 => Ptxqdepth::Que4,
            2 => Ptxqdepth::Que8,
            3 => Ptxqdepth::Que16,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_que2(&self) -> bool {
        *self == Ptxqdepth::Que2
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_que4(&self) -> bool {
        *self == Ptxqdepth::Que4
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_que8(&self) -> bool {
        *self == Ptxqdepth::Que8
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_que16(&self) -> bool {
        *self == Ptxqdepth::Que16
    }
}
#[doc = "Field `ptxqdepth` writer - Specifies the Host mode Periodic Request Queue depth.That is, the maximum number of packets that can reside in the Host Periodic TxFIFO. This queue holds one entry corresponding to each IN or OUT periodic request. This queue is 9 bits wide."]
pub type PtxqdepthW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `tknqdepth` reader - Range: 0 to 30."]
pub type TknqdepthR = crate::FieldReader;
#[doc = "Field `tknqdepth` writer - Range: 0 to 30."]
pub type TknqdepthW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:2 - HNP- and SRP-Capable OTG (Device and Host)."]
    #[inline(always)]
    pub fn otgmode(&self) -> OtgmodeR {
        OtgmodeR::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 3:4 - DMA Architecture."]
    #[inline(always)]
    pub fn otgarch(&self) -> OtgarchR {
        OtgarchR::new(((self.bits >> 3) & 3) as u8)
    }
    #[doc = "Bit 5 - Single Point Only."]
    #[inline(always)]
    pub fn singpnt(&self) -> SingpntR {
        SingpntR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:7 - Specifies the High Speed PHY in use."]
    #[inline(always)]
    pub fn hsphytype(&self) -> HsphytypeR {
        HsphytypeR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bits 8:9 - Specifies the Full Speed PHY in use."]
    #[inline(always)]
    pub fn fsphytype(&self) -> FsphytypeR {
        FsphytypeR::new(((self.bits >> 8) & 3) as u8)
    }
    #[doc = "Bits 10:13 - The number of endpoints is 1 to 15 in Device mode in addition to control endpoint 0."]
    #[inline(always)]
    pub fn numdeveps(&self) -> NumdevepsR {
        NumdevepsR::new(((self.bits >> 10) & 0x0f) as u8)
    }
    #[doc = "Bits 14:17 - Indicates the number of host channels supported by the core in Host mode."]
    #[inline(always)]
    pub fn numhstchnl(&self) -> NumhstchnlR {
        NumhstchnlR::new(((self.bits >> 14) & 0x0f) as u8)
    }
    #[doc = "Bit 18 - Feature supported."]
    #[inline(always)]
    pub fn periosupport(&self) -> PeriosupportR {
        PeriosupportR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Feature supported."]
    #[inline(always)]
    pub fn dynfifosizing(&self) -> DynfifosizingR {
        DynfifosizingR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Not implemented."]
    #[inline(always)]
    pub fn multiprocintrpt(&self) -> MultiprocintrptR {
        MultiprocintrptR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bits 22:23 - Specifies the Non-periodic Request Queue depth, the maximum number of packets that can reside in the Non-periodic TxFIFO. In Device mode, the queue is used only in Shared FIFO Mode (Enable Dedicated Transmit FIFO for device IN Endpoints? =No). In this mode, there is one entry in the Non-periodic Request Queue for each packet in the Non-periodic TxFIFO. In Host mode, this queue holds one entry corresponding to each IN or OUT nonperiodic request. This queue is seven bits wide."]
    #[inline(always)]
    pub fn nptxqdepth(&self) -> NptxqdepthR {
        NptxqdepthR::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bits 24:25 - Specifies the Host mode Periodic Request Queue depth.That is, the maximum number of packets that can reside in the Host Periodic TxFIFO. This queue holds one entry corresponding to each IN or OUT periodic request. This queue is 9 bits wide."]
    #[inline(always)]
    pub fn ptxqdepth(&self) -> PtxqdepthR {
        PtxqdepthR::new(((self.bits >> 24) & 3) as u8)
    }
    #[doc = "Bits 26:30 - Range: 0 to 30."]
    #[inline(always)]
    pub fn tknqdepth(&self) -> TknqdepthR {
        TknqdepthR::new(((self.bits >> 26) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - HNP- and SRP-Capable OTG (Device and Host)."]
    #[inline(always)]
    #[must_use]
    pub fn otgmode(&mut self) -> OtgmodeW<GlobgrpGhwcfg2Spec> {
        OtgmodeW::new(self, 0)
    }
    #[doc = "Bits 3:4 - DMA Architecture."]
    #[inline(always)]
    #[must_use]
    pub fn otgarch(&mut self) -> OtgarchW<GlobgrpGhwcfg2Spec> {
        OtgarchW::new(self, 3)
    }
    #[doc = "Bit 5 - Single Point Only."]
    #[inline(always)]
    #[must_use]
    pub fn singpnt(&mut self) -> SingpntW<GlobgrpGhwcfg2Spec> {
        SingpntW::new(self, 5)
    }
    #[doc = "Bits 6:7 - Specifies the High Speed PHY in use."]
    #[inline(always)]
    #[must_use]
    pub fn hsphytype(&mut self) -> HsphytypeW<GlobgrpGhwcfg2Spec> {
        HsphytypeW::new(self, 6)
    }
    #[doc = "Bits 8:9 - Specifies the Full Speed PHY in use."]
    #[inline(always)]
    #[must_use]
    pub fn fsphytype(&mut self) -> FsphytypeW<GlobgrpGhwcfg2Spec> {
        FsphytypeW::new(self, 8)
    }
    #[doc = "Bits 10:13 - The number of endpoints is 1 to 15 in Device mode in addition to control endpoint 0."]
    #[inline(always)]
    #[must_use]
    pub fn numdeveps(&mut self) -> NumdevepsW<GlobgrpGhwcfg2Spec> {
        NumdevepsW::new(self, 10)
    }
    #[doc = "Bits 14:17 - Indicates the number of host channels supported by the core in Host mode."]
    #[inline(always)]
    #[must_use]
    pub fn numhstchnl(&mut self) -> NumhstchnlW<GlobgrpGhwcfg2Spec> {
        NumhstchnlW::new(self, 14)
    }
    #[doc = "Bit 18 - Feature supported."]
    #[inline(always)]
    #[must_use]
    pub fn periosupport(&mut self) -> PeriosupportW<GlobgrpGhwcfg2Spec> {
        PeriosupportW::new(self, 18)
    }
    #[doc = "Bit 19 - Feature supported."]
    #[inline(always)]
    #[must_use]
    pub fn dynfifosizing(&mut self) -> DynfifosizingW<GlobgrpGhwcfg2Spec> {
        DynfifosizingW::new(self, 19)
    }
    #[doc = "Bit 20 - Not implemented."]
    #[inline(always)]
    #[must_use]
    pub fn multiprocintrpt(&mut self) -> MultiprocintrptW<GlobgrpGhwcfg2Spec> {
        MultiprocintrptW::new(self, 20)
    }
    #[doc = "Bits 22:23 - Specifies the Non-periodic Request Queue depth, the maximum number of packets that can reside in the Non-periodic TxFIFO. In Device mode, the queue is used only in Shared FIFO Mode (Enable Dedicated Transmit FIFO for device IN Endpoints? =No). In this mode, there is one entry in the Non-periodic Request Queue for each packet in the Non-periodic TxFIFO. In Host mode, this queue holds one entry corresponding to each IN or OUT nonperiodic request. This queue is seven bits wide."]
    #[inline(always)]
    #[must_use]
    pub fn nptxqdepth(&mut self) -> NptxqdepthW<GlobgrpGhwcfg2Spec> {
        NptxqdepthW::new(self, 22)
    }
    #[doc = "Bits 24:25 - Specifies the Host mode Periodic Request Queue depth.That is, the maximum number of packets that can reside in the Host Periodic TxFIFO. This queue holds one entry corresponding to each IN or OUT periodic request. This queue is 9 bits wide."]
    #[inline(always)]
    #[must_use]
    pub fn ptxqdepth(&mut self) -> PtxqdepthW<GlobgrpGhwcfg2Spec> {
        PtxqdepthW::new(self, 24)
    }
    #[doc = "Bits 26:30 - Range: 0 to 30."]
    #[inline(always)]
    #[must_use]
    pub fn tknqdepth(&mut self) -> TknqdepthW<GlobgrpGhwcfg2Spec> {
        TknqdepthW::new(self, 26)
    }
}
#[doc = "This register contains configuration options.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ghwcfg2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGhwcfg2Spec;
impl crate::RegisterSpec for GlobgrpGhwcfg2Spec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`globgrp_ghwcfg2::R`](R) reader structure"]
impl crate::Readable for GlobgrpGhwcfg2Spec {}
#[doc = "`reset()` method sets globgrp_ghwcfg2 to value 0x208f_fc90"]
impl crate::Resettable for GlobgrpGhwcfg2Spec {
    const RESET_VALUE: u32 = 0x208f_fc90;
}
