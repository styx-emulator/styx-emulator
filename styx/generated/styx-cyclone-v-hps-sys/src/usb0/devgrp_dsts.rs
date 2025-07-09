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
#[doc = "Register `devgrp_dsts` reader"]
pub type R = crate::R<DevgrpDstsSpec>;
#[doc = "Register `devgrp_dsts` writer"]
pub type W = crate::W<DevgrpDstsSpec>;
#[doc = "In Device mode, this bit is Set as long as a Suspend condition is detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time. The core comes out of the suspend: -When there is any activity on the phy_line_state_i signal -When the application writes to the Remote Wakeup Signaling bit in the Device Control register (DCTL.RmtWkUpSig).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suspsts {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Suspsts> for bool {
    #[inline(always)]
    fn from(variant: Suspsts) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `suspsts` reader - In Device mode, this bit is Set as long as a Suspend condition is detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time. The core comes out of the suspend: -When there is any activity on the phy_line_state_i signal -When the application writes to the Remote Wakeup Signaling bit in the Device Control register (DCTL.RmtWkUpSig)."]
pub type SuspstsR = crate::BitReader<Suspsts>;
impl SuspstsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Suspsts {
        match self.bits {
            false => Suspsts::Inactive,
            true => Suspsts::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Suspsts::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Suspsts::Active
    }
}
#[doc = "Field `suspsts` writer - In Device mode, this bit is Set as long as a Suspend condition is detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time. The core comes out of the suspend: -When there is any activity on the phy_line_state_i signal -When the application writes to the Remote Wakeup Signaling bit in the Device Control register (DCTL.RmtWkUpSig)."]
pub type SuspstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Indicates the speed at which the otg core has come up after speed detection through a chirp sequence.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Enumspd {
    #[doc = "0: `0`"]
    Hs3060 = 0,
    #[doc = "1: `1`"]
    Fs3060 = 1,
    #[doc = "2: `10`"]
    Ls6 = 2,
    #[doc = "3: `11`"]
    Fs48 = 3,
}
impl From<Enumspd> for u8 {
    #[inline(always)]
    fn from(variant: Enumspd) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Enumspd {
    type Ux = u8;
}
#[doc = "Field `enumspd` reader - Indicates the speed at which the otg core has come up after speed detection through a chirp sequence."]
pub type EnumspdR = crate::FieldReader<Enumspd>;
impl EnumspdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enumspd {
        match self.bits {
            0 => Enumspd::Hs3060,
            1 => Enumspd::Fs3060,
            2 => Enumspd::Ls6,
            3 => Enumspd::Fs48,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_hs3060(&self) -> bool {
        *self == Enumspd::Hs3060
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fs3060(&self) -> bool {
        *self == Enumspd::Fs3060
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_ls6(&self) -> bool {
        *self == Enumspd::Ls6
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_fs48(&self) -> bool {
        *self == Enumspd::Fs48
    }
}
#[doc = "Field `enumspd` writer - Indicates the speed at which the otg core has come up after speed detection through a chirp sequence."]
pub type EnumspdW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "The core sets this bit to report any erratic errors (phy_rxvalid_i/phy_rxvldh_i or phy_rxactive_i is asserted for at least 2 ms, due to PHY error) seen on the UTMI+ . Due to erratic errors, the otg core goes into Suspended state and an interrupt is generated to the application with Early Suspend bit of the Core Interrupt register (GINTSTS.ErlySusp). If the early suspend is asserted due to an erratic error, the application can only perform a soft disconnect recover.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errticerr {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Errticerr> for bool {
    #[inline(always)]
    fn from(variant: Errticerr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `errticerr` reader - The core sets this bit to report any erratic errors (phy_rxvalid_i/phy_rxvldh_i or phy_rxactive_i is asserted for at least 2 ms, due to PHY error) seen on the UTMI+ . Due to erratic errors, the otg core goes into Suspended state and an interrupt is generated to the application with Early Suspend bit of the Core Interrupt register (GINTSTS.ErlySusp). If the early suspend is asserted due to an erratic error, the application can only perform a soft disconnect recover."]
pub type ErrticerrR = crate::BitReader<Errticerr>;
impl ErrticerrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Errticerr {
        match self.bits {
            false => Errticerr::Inactive,
            true => Errticerr::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Errticerr::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Errticerr::Active
    }
}
#[doc = "Field `errticerr` writer - The core sets this bit to report any erratic errors (phy_rxvalid_i/phy_rxvldh_i or phy_rxactive_i is asserted for at least 2 ms, due to PHY error) seen on the UTMI+ . Due to erratic errors, the otg core goes into Suspended state and an interrupt is generated to the application with Early Suspend bit of the Core Interrupt register (GINTSTS.ErlySusp). If the early suspend is asserted due to an erratic error, the application can only perform a soft disconnect recover."]
pub type ErrticerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `soffn` reader - When the core is operating at high speed, this field contains a microframe number. When the core is operating at full or low speed, this field contains a Frame number."]
pub type SoffnR = crate::FieldReader<u16>;
#[doc = "Field `soffn` writer - When the core is operating at high speed, this field contains a microframe number. When the core is operating at full or low speed, this field contains a Frame number."]
pub type SoffnW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bit 0 - In Device mode, this bit is Set as long as a Suspend condition is detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time. The core comes out of the suspend: -When there is any activity on the phy_line_state_i signal -When the application writes to the Remote Wakeup Signaling bit in the Device Control register (DCTL.RmtWkUpSig)."]
    #[inline(always)]
    pub fn suspsts(&self) -> SuspstsR {
        SuspstsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - Indicates the speed at which the otg core has come up after speed detection through a chirp sequence."]
    #[inline(always)]
    pub fn enumspd(&self) -> EnumspdR {
        EnumspdR::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bit 3 - The core sets this bit to report any erratic errors (phy_rxvalid_i/phy_rxvldh_i or phy_rxactive_i is asserted for at least 2 ms, due to PHY error) seen on the UTMI+ . Due to erratic errors, the otg core goes into Suspended state and an interrupt is generated to the application with Early Suspend bit of the Core Interrupt register (GINTSTS.ErlySusp). If the early suspend is asserted due to an erratic error, the application can only perform a soft disconnect recover."]
    #[inline(always)]
    pub fn errticerr(&self) -> ErrticerrR {
        ErrticerrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 8:21 - When the core is operating at high speed, this field contains a microframe number. When the core is operating at full or low speed, this field contains a Frame number."]
    #[inline(always)]
    pub fn soffn(&self) -> SoffnR {
        SoffnR::new(((self.bits >> 8) & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - In Device mode, this bit is Set as long as a Suspend condition is detected on the USB. The core enters the Suspended state when there is no activity on the phy_line_state_i signal for an extended period of time. The core comes out of the suspend: -When there is any activity on the phy_line_state_i signal -When the application writes to the Remote Wakeup Signaling bit in the Device Control register (DCTL.RmtWkUpSig)."]
    #[inline(always)]
    #[must_use]
    pub fn suspsts(&mut self) -> SuspstsW<DevgrpDstsSpec> {
        SuspstsW::new(self, 0)
    }
    #[doc = "Bits 1:2 - Indicates the speed at which the otg core has come up after speed detection through a chirp sequence."]
    #[inline(always)]
    #[must_use]
    pub fn enumspd(&mut self) -> EnumspdW<DevgrpDstsSpec> {
        EnumspdW::new(self, 1)
    }
    #[doc = "Bit 3 - The core sets this bit to report any erratic errors (phy_rxvalid_i/phy_rxvldh_i or phy_rxactive_i is asserted for at least 2 ms, due to PHY error) seen on the UTMI+ . Due to erratic errors, the otg core goes into Suspended state and an interrupt is generated to the application with Early Suspend bit of the Core Interrupt register (GINTSTS.ErlySusp). If the early suspend is asserted due to an erratic error, the application can only perform a soft disconnect recover."]
    #[inline(always)]
    #[must_use]
    pub fn errticerr(&mut self) -> ErrticerrW<DevgrpDstsSpec> {
        ErrticerrW::new(self, 3)
    }
    #[doc = "Bits 8:21 - When the core is operating at high speed, this field contains a microframe number. When the core is operating at full or low speed, this field contains a Frame number."]
    #[inline(always)]
    #[must_use]
    pub fn soffn(&mut self) -> SoffnW<DevgrpDstsSpec> {
        SoffnW::new(self, 8)
    }
}
#[doc = "This register indicates the status of the core with respect to USB-related events. It must be read on interrupts from Device All Interrupts (DAINT) register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dsts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDstsSpec;
impl crate::RegisterSpec for DevgrpDstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 2056u64;
}
#[doc = "`read()` method returns [`devgrp_dsts::R`](R) reader structure"]
impl crate::Readable for DevgrpDstsSpec {}
#[doc = "`reset()` method sets devgrp_dsts to value 0x02"]
impl crate::Resettable for DevgrpDstsSpec {
    const RESET_VALUE: u32 = 0x02;
}
