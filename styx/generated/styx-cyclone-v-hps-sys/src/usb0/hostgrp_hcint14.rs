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
#[doc = "Register `hostgrp_hcint14` reader"]
pub type R = crate::R<HostgrpHcint14Spec>;
#[doc = "Register `hostgrp_hcint14` writer"]
pub type W = crate::W<HostgrpHcint14Spec>;
#[doc = "Transfer completed normally without any errors. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xfercompl {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Xfercompl> for bool {
    #[inline(always)]
    fn from(variant: Xfercompl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `xfercompl` reader - Transfer completed normally without any errors. This bit can be set only by the core and the application should write 1 to clear it."]
pub type XfercomplR = crate::BitReader<Xfercompl>;
impl XfercomplR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Xfercompl {
        match self.bits {
            false => Xfercompl::Inactive,
            true => Xfercompl::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Xfercompl::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Xfercompl::Active
    }
}
#[doc = "Field `xfercompl` writer - Transfer completed normally without any errors. This bit can be set only by the core and the application should write 1 to clear it."]
pub type XfercomplW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "In non Scatter/Gather DMA mode, it indicates the transfer completed abnormally either because of any USB transaction error or in response to disable request by the application or because of a completed transfer. In Scatter/gather DMA mode, this indicates that transfer completed due to any of the following . EOL being set in descriptor . AHB error . Excessive transaction errors . Babble . Stall\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chhltd {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Chhltd> for bool {
    #[inline(always)]
    fn from(variant: Chhltd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `chhltd` reader - In non Scatter/Gather DMA mode, it indicates the transfer completed abnormally either because of any USB transaction error or in response to disable request by the application or because of a completed transfer. In Scatter/gather DMA mode, this indicates that transfer completed due to any of the following . EOL being set in descriptor . AHB error . Excessive transaction errors . Babble . Stall"]
pub type ChhltdR = crate::BitReader<Chhltd>;
impl ChhltdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Chhltd {
        match self.bits {
            false => Chhltd::Inactive,
            true => Chhltd::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Chhltd::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Chhltd::Active
    }
}
#[doc = "Field `chhltd` writer - In non Scatter/Gather DMA mode, it indicates the transfer completed abnormally either because of any USB transaction error or in response to disable request by the application or because of a completed transfer. In Scatter/gather DMA mode, this indicates that transfer completed due to any of the following . EOL being set in descriptor . AHB error . Excessive transaction errors . Babble . Stall"]
pub type ChhltdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This is generated only in Internal DMA mode when there is an AHB error during AHB read/write. The application can read the corresponding channel's DMA address register to get the error address.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ahberr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ahberr> for bool {
    #[inline(always)]
    fn from(variant: Ahberr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ahberr` reader - This is generated only in Internal DMA mode when there is an AHB error during AHB read/write. The application can read the corresponding channel's DMA address register to get the error address."]
pub type AhberrR = crate::BitReader<Ahberr>;
impl AhberrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ahberr {
        match self.bits {
            false => Ahberr::Inactive,
            true => Ahberr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ahberr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ahberr::Active
    }
}
#[doc = "Field `ahberr` writer - This is generated only in Internal DMA mode when there is an AHB error during AHB read/write. The application can read the corresponding channel's DMA address register to get the error address."]
pub type AhberrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stall {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Stall> for bool {
    #[inline(always)]
    fn from(variant: Stall) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `stall` reader - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
pub type StallR = crate::BitReader<Stall>;
impl StallR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Stall {
        match self.bits {
            false => Stall::Inactive,
            true => Stall::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Stall::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Stall::Active
    }
}
#[doc = "Field `stall` writer - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
pub type StallW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nak {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Nak> for bool {
    #[inline(always)]
    fn from(variant: Nak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nak` reader - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it."]
pub type NakR = crate::BitReader<Nak>;
impl NakR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nak {
        match self.bits {
            false => Nak::Inactive,
            true => Nak::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Nak::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Nak::Active
    }
}
#[doc = "Field `nak` writer - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it."]
pub type NakW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Ack> for bool {
    #[inline(always)]
    fn from(variant: Ack) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ack` reader - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
pub type AckR = crate::BitReader<Ack>;
impl AckR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ack {
        match self.bits {
            false => Ack::Inactive,
            true => Ack::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Ack::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Ack::Active
    }
}
#[doc = "Field `ack` writer - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
pub type AckW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nyet {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Nyet> for bool {
    #[inline(always)]
    fn from(variant: Nyet) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nyet` reader - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it."]
pub type NyetR = crate::BitReader<Nyet>;
impl NyetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nyet {
        match self.bits {
            false => Nyet::Inactive,
            true => Nyet::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Nyet::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Nyet::Active
    }
}
#[doc = "Field `nyet` writer - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it."]
pub type NyetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates one of the following errors occurred on the USB.-CRC check failure -Timeout -Bit stuff error -False EOP In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xacterr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Xacterr> for bool {
    #[inline(always)]
    fn from(variant: Xacterr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `xacterr` reader - Indicates one of the following errors occurred on the USB.-CRC check failure -Timeout -Bit stuff error -False EOP In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
pub type XacterrR = crate::BitReader<Xacterr>;
impl XacterrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Xacterr {
        match self.bits {
            false => Xacterr::Inactive,
            true => Xacterr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Xacterr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Xacterr::Active
    }
}
#[doc = "Field `xacterr` writer - Indicates one of the following errors occurred on the USB.-CRC check failure -Timeout -Bit stuff error -False EOP In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
pub type XacterrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core..This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bblerr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Bblerr> for bool {
    #[inline(always)]
    fn from(variant: Bblerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bblerr` reader - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core..This bit can be set only by the core and the application should write 1 to clear it."]
pub type BblerrR = crate::BitReader<Bblerr>;
impl BblerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bblerr {
        match self.bits {
            false => Bblerr::Inactive,
            true => Bblerr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Bblerr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Bblerr::Active
    }
}
#[doc = "Field `bblerr` writer - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core..This bit can be set only by the core and the application should write 1 to clear it."]
pub type BblerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frmovrun {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Frmovrun> for bool {
    #[inline(always)]
    fn from(variant: Frmovrun) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `frmovrun` reader - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
pub type FrmovrunR = crate::BitReader<Frmovrun>;
impl FrmovrunR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Frmovrun {
        match self.bits {
            false => Frmovrun::Inactive,
            true => Frmovrun::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Frmovrun::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Frmovrun::Active
    }
}
#[doc = "Field `frmovrun` writer - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
pub type FrmovrunW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit can be set only by the core and the application should write 1 to clear it. In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Datatglerr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Datatglerr> for bool {
    #[inline(always)]
    fn from(variant: Datatglerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `datatglerr` reader - This bit can be set only by the core and the application should write 1 to clear it. In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core."]
pub type DatatglerrR = crate::BitReader<Datatglerr>;
impl DatatglerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Datatglerr {
        match self.bits {
            false => Datatglerr::Inactive,
            true => Datatglerr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Datatglerr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Datatglerr::Active
    }
}
#[doc = "Field `datatglerr` writer - This bit can be set only by the core and the application should write 1 to clear it. In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core."]
pub type DatatglerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process. BNA will not be generated for Isochronous channels. for non Scatter/Gather DMA mode, this bit is reserved.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bnaintr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Bnaintr> for bool {
    #[inline(always)]
    fn from(variant: Bnaintr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `bnaintr` reader - This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process. BNA will not be generated for Isochronous channels. for non Scatter/Gather DMA mode, this bit is reserved."]
pub type BnaintrR = crate::BitReader<Bnaintr>;
impl BnaintrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bnaintr {
        match self.bits {
            false => Bnaintr::Inactive,
            true => Bnaintr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Bnaintr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Bnaintr::Active
    }
}
#[doc = "Field `bnaintr` writer - This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process. BNA will not be generated for Isochronous channels. for non Scatter/Gather DMA mode, this bit is reserved."]
pub type BnaintrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when 3 consecutive transaction errors occurred on the USB bus. XCS_XACT_ERR will not be generated for Isochronous channels.for non Scatter/Gather DMA mode, this bit is reserved.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XcsXactErr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Acvtive = 1,
}
impl From<XcsXactErr> for bool {
    #[inline(always)]
    fn from(variant: XcsXactErr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `xcs_xact_err` reader - This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when 3 consecutive transaction errors occurred on the USB bus. XCS_XACT_ERR will not be generated for Isochronous channels.for non Scatter/Gather DMA mode, this bit is reserved."]
pub type XcsXactErrR = crate::BitReader<XcsXactErr>;
impl XcsXactErrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> XcsXactErr {
        match self.bits {
            false => XcsXactErr::Inactive,
            true => XcsXactErr::Acvtive,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == XcsXactErr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_acvtive(&self) -> bool {
        *self == XcsXactErr::Acvtive
    }
}
#[doc = "Field `xcs_xact_err` writer - This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when 3 consecutive transaction errors occurred on the USB bus. XCS_XACT_ERR will not be generated for Isochronous channels.for non Scatter/Gather DMA mode, this bit is reserved."]
pub type XcsXactErrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Descriptor rollover interrupt (DESC_LST_ROLLIntr)This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when the corresponding channel's descriptor list rolls over. for non Scatter/Gather DMA mode, this bit is reserved.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescLstRollintr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<DescLstRollintr> for bool {
    #[inline(always)]
    fn from(variant: DescLstRollintr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `desc_lst_rollintr` reader - Descriptor rollover interrupt (DESC_LST_ROLLIntr)This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when the corresponding channel's descriptor list rolls over. for non Scatter/Gather DMA mode, this bit is reserved."]
pub type DescLstRollintrR = crate::BitReader<DescLstRollintr>;
impl DescLstRollintrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> DescLstRollintr {
        match self.bits {
            false => DescLstRollintr::Inactive,
            true => DescLstRollintr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == DescLstRollintr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == DescLstRollintr::Active
    }
}
#[doc = "Field `desc_lst_rollintr` writer - Descriptor rollover interrupt (DESC_LST_ROLLIntr)This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when the corresponding channel's descriptor list rolls over. for non Scatter/Gather DMA mode, this bit is reserved."]
pub type DescLstRollintrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Transfer completed normally without any errors. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn xfercompl(&self) -> XfercomplR {
        XfercomplR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - In non Scatter/Gather DMA mode, it indicates the transfer completed abnormally either because of any USB transaction error or in response to disable request by the application or because of a completed transfer. In Scatter/gather DMA mode, this indicates that transfer completed due to any of the following . EOL being set in descriptor . AHB error . Excessive transaction errors . Babble . Stall"]
    #[inline(always)]
    pub fn chhltd(&self) -> ChhltdR {
        ChhltdR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This is generated only in Internal DMA mode when there is an AHB error during AHB read/write. The application can read the corresponding channel's DMA address register to get the error address."]
    #[inline(always)]
    pub fn ahberr(&self) -> AhberrR {
        AhberrR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn stall(&self) -> StallR {
        StallR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn nak(&self) -> NakR {
        NakR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn ack(&self) -> AckR {
        AckR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn nyet(&self) -> NyetR {
        NyetR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Indicates one of the following errors occurred on the USB.-CRC check failure -Timeout -Bit stuff error -False EOP In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn xacterr(&self) -> XacterrR {
        XacterrR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core..This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn bblerr(&self) -> BblerrR {
        BblerrR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    pub fn frmovrun(&self) -> FrmovrunR {
        FrmovrunR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit can be set only by the core and the application should write 1 to clear it. In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core."]
    #[inline(always)]
    pub fn datatglerr(&self) -> DatatglerrR {
        DatatglerrR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process. BNA will not be generated for Isochronous channels. for non Scatter/Gather DMA mode, this bit is reserved."]
    #[inline(always)]
    pub fn bnaintr(&self) -> BnaintrR {
        BnaintrR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when 3 consecutive transaction errors occurred on the USB bus. XCS_XACT_ERR will not be generated for Isochronous channels.for non Scatter/Gather DMA mode, this bit is reserved."]
    #[inline(always)]
    pub fn xcs_xact_err(&self) -> XcsXactErrR {
        XcsXactErrR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Descriptor rollover interrupt (DESC_LST_ROLLIntr)This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when the corresponding channel's descriptor list rolls over. for non Scatter/Gather DMA mode, this bit is reserved."]
    #[inline(always)]
    pub fn desc_lst_rollintr(&self) -> DescLstRollintrR {
        DescLstRollintrR::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Transfer completed normally without any errors. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn xfercompl(&mut self) -> XfercomplW<HostgrpHcint14Spec> {
        XfercomplW::new(self, 0)
    }
    #[doc = "Bit 1 - In non Scatter/Gather DMA mode, it indicates the transfer completed abnormally either because of any USB transaction error or in response to disable request by the application or because of a completed transfer. In Scatter/gather DMA mode, this indicates that transfer completed due to any of the following . EOL being set in descriptor . AHB error . Excessive transaction errors . Babble . Stall"]
    #[inline(always)]
    #[must_use]
    pub fn chhltd(&mut self) -> ChhltdW<HostgrpHcint14Spec> {
        ChhltdW::new(self, 1)
    }
    #[doc = "Bit 2 - This is generated only in Internal DMA mode when there is an AHB error during AHB read/write. The application can read the corresponding channel's DMA address register to get the error address."]
    #[inline(always)]
    #[must_use]
    pub fn ahberr(&mut self) -> AhberrW<HostgrpHcint14Spec> {
        AhberrW::new(self, 2)
    }
    #[doc = "Bit 3 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn stall(&mut self) -> StallW<HostgrpHcint14Spec> {
        StallW::new(self, 3)
    }
    #[doc = "Bit 4 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn nak(&mut self) -> NakW<HostgrpHcint14Spec> {
        NakW::new(self, 4)
    }
    #[doc = "Bit 5 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn ack(&mut self) -> AckW<HostgrpHcint14Spec> {
        AckW::new(self, 5)
    }
    #[doc = "Bit 6 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core.This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn nyet(&mut self) -> NyetW<HostgrpHcint14Spec> {
        NyetW::new(self, 6)
    }
    #[doc = "Bit 7 - Indicates one of the following errors occurred on the USB.-CRC check failure -Timeout -Bit stuff error -False EOP In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn xacterr(&mut self) -> XacterrW<HostgrpHcint14Spec> {
        XacterrW::new(self, 7)
    }
    #[doc = "Bit 8 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core..This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn bblerr(&mut self) -> BblerrW<HostgrpHcint14Spec> {
        BblerrW::new(self, 8)
    }
    #[doc = "Bit 9 - In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core. This bit can be set only by the core and the application should write 1 to clear it."]
    #[inline(always)]
    #[must_use]
    pub fn frmovrun(&mut self) -> FrmovrunW<HostgrpHcint14Spec> {
        FrmovrunW::new(self, 9)
    }
    #[doc = "Bit 10 - This bit can be set only by the core and the application should write 1 to clear it. In Scatter/Gather DMA mode, the interrupt due to this bit is masked in the core."]
    #[inline(always)]
    #[must_use]
    pub fn datatglerr(&mut self) -> DatatglerrW<HostgrpHcint14Spec> {
        DatatglerrW::new(self, 10)
    }
    #[doc = "Bit 11 - This bit is valid only when Scatter/Gather DMA mode is enabled. The core generates this interrupt when the descriptor accessed is not ready for the Core to process. BNA will not be generated for Isochronous channels. for non Scatter/Gather DMA mode, this bit is reserved."]
    #[inline(always)]
    #[must_use]
    pub fn bnaintr(&mut self) -> BnaintrW<HostgrpHcint14Spec> {
        BnaintrW::new(self, 11)
    }
    #[doc = "Bit 12 - This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when 3 consecutive transaction errors occurred on the USB bus. XCS_XACT_ERR will not be generated for Isochronous channels.for non Scatter/Gather DMA mode, this bit is reserved."]
    #[inline(always)]
    #[must_use]
    pub fn xcs_xact_err(&mut self) -> XcsXactErrW<HostgrpHcint14Spec> {
        XcsXactErrW::new(self, 12)
    }
    #[doc = "Bit 13 - Descriptor rollover interrupt (DESC_LST_ROLLIntr)This bit is valid only when Scatter/Gather DMA mode is enabled. The core sets this bit when the corresponding channel's descriptor list rolls over. for non Scatter/Gather DMA mode, this bit is reserved."]
    #[inline(always)]
    #[must_use]
    pub fn desc_lst_rollintr(&mut self) -> DescLstRollintrW<HostgrpHcint14Spec> {
        DescLstRollintrW::new(self, 13)
    }
}
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint14::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHcint14Spec;
impl crate::RegisterSpec for HostgrpHcint14Spec {
    type Ux = u32;
    const OFFSET: u64 = 1736u64;
}
#[doc = "`read()` method returns [`hostgrp_hcint14::R`](R) reader structure"]
impl crate::Readable for HostgrpHcint14Spec {}
#[doc = "`reset()` method sets hostgrp_hcint14 to value 0"]
impl crate::Resettable for HostgrpHcint14Spec {
    const RESET_VALUE: u32 = 0;
}
