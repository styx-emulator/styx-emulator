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
#[doc = "Register `globgrp_gpvndctl` reader"]
pub type R = crate::R<GlobgrpGpvndctlSpec>;
#[doc = "Register `globgrp_gpvndctl` writer"]
pub type W = crate::W<GlobgrpGpvndctlSpec>;
#[doc = "Field `regdata` reader - Contains the write data for register write. Read data for register read, valid when VStatus Done is Set."]
pub type RegdataR = crate::FieldReader;
#[doc = "Field `regdata` writer - Contains the write data for register write. Read data for register read, valid when VStatus Done is Set."]
pub type RegdataW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `vctrl` reader - The 4-bit register address a vendor defined 4-bit parallel output bus. ULPI Extended Register Address and the 6-bit PHY extended register address."]
pub type VctrlR = crate::FieldReader;
#[doc = "Field `vctrl` writer - The 4-bit register address a vendor defined 4-bit parallel output bus. ULPI Extended Register Address and the 6-bit PHY extended register address."]
pub type VctrlW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `regaddr` reader - The 6-bit PHY register address for immediate PHY Register Set access. Set to 0x2F for Extended PHY Register Set access."]
pub type RegaddrR = crate::FieldReader;
#[doc = "Field `regaddr` writer - The 6-bit PHY register address for immediate PHY Register Set access. Set to 0x2F for Extended PHY Register Set access."]
pub type RegaddrW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Set this bit for register writes, and clear it for register reads.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regwr {
    #[doc = "0: `0`"]
    Read = 0,
    #[doc = "1: `1`"]
    Write = 1,
}
impl From<Regwr> for bool {
    #[inline(always)]
    fn from(variant: Regwr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `regwr` reader - Set this bit for register writes, and clear it for register reads."]
pub type RegwrR = crate::BitReader<Regwr>;
impl RegwrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Regwr {
        match self.bits {
            false => Regwr::Read,
            true => Regwr::Write,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_read(&self) -> bool {
        *self == Regwr::Read
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_write(&self) -> bool {
        *self == Regwr::Write
    }
}
#[doc = "Field `regwr` writer - Set this bit for register writes, and clear it for register reads."]
pub type RegwrW<'a, REG> = crate::BitWriter<'a, REG, Regwr>;
impl<'a, REG> RegwrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn read(self) -> &'a mut crate::W<REG> {
        self.variant(Regwr::Read)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn write(self) -> &'a mut crate::W<REG> {
        self.variant(Regwr::Write)
    }
}
#[doc = "The application sets this bit for a new vendor controlaccess.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Newregreq {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Newregreq> for bool {
    #[inline(always)]
    fn from(variant: Newregreq) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `newregreq` reader - The application sets this bit for a new vendor controlaccess."]
pub type NewregreqR = crate::BitReader<Newregreq>;
impl NewregreqR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Newregreq {
        match self.bits {
            false => Newregreq::Inactive,
            true => Newregreq::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Newregreq::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Newregreq::Active
    }
}
#[doc = "Field `newregreq` writer - The application sets this bit for a new vendor controlaccess."]
pub type NewregreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The core sets this bit when the vendor control access is in progress and clears this bit when done.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vstsbsy {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Vstsbsy> for bool {
    #[inline(always)]
    fn from(variant: Vstsbsy) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vstsbsy` reader - The core sets this bit when the vendor control access is in progress and clears this bit when done."]
pub type VstsbsyR = crate::BitReader<Vstsbsy>;
impl VstsbsyR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Vstsbsy {
        match self.bits {
            false => Vstsbsy::Inactive,
            true => Vstsbsy::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Vstsbsy::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Vstsbsy::Active
    }
}
#[doc = "Field `vstsbsy` writer - The core sets this bit when the vendor control access is in progress and clears this bit when done."]
pub type VstsbsyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The core sets this bit when the vendor control access isdone. This bit is cleared by the core when the application sets the New Register Request bit (bit 25).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vstsdone {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Vstsdone> for bool {
    #[inline(always)]
    fn from(variant: Vstsdone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `vstsdone` reader - The core sets this bit when the vendor control access isdone. This bit is cleared by the core when the application sets the New Register Request bit (bit 25)."]
pub type VstsdoneR = crate::BitReader<Vstsdone>;
impl VstsdoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Vstsdone {
        match self.bits {
            false => Vstsdone::Inactive,
            true => Vstsdone::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Vstsdone::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Vstsdone::Active
    }
}
#[doc = "Field `vstsdone` writer - The core sets this bit when the vendor control access isdone. This bit is cleared by the core when the application sets the New Register Request bit (bit 25)."]
pub type VstsdoneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "The application sets this bit when it has finished processing the ULPI Carkit Interrupt (GINTSTS.ULPICKINT). When Set, the otg core disables drivers for output signals and masks input signal for the ULPI interface. otg clears this bit before enabling the ULPI interface.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disulpidrvr {
    #[doc = "0: `0`"]
    Enabled = 0,
    #[doc = "1: `1`"]
    Disabled = 1,
}
impl From<Disulpidrvr> for bool {
    #[inline(always)]
    fn from(variant: Disulpidrvr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `disulpidrvr` reader - The application sets this bit when it has finished processing the ULPI Carkit Interrupt (GINTSTS.ULPICKINT). When Set, the otg core disables drivers for output signals and masks input signal for the ULPI interface. otg clears this bit before enabling the ULPI interface."]
pub type DisulpidrvrR = crate::BitReader<Disulpidrvr>;
impl DisulpidrvrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Disulpidrvr {
        match self.bits {
            false => Disulpidrvr::Enabled,
            true => Disulpidrvr::Disabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Disulpidrvr::Enabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Disulpidrvr::Disabled
    }
}
#[doc = "Field `disulpidrvr` writer - The application sets this bit when it has finished processing the ULPI Carkit Interrupt (GINTSTS.ULPICKINT). When Set, the otg core disables drivers for output signals and masks input signal for the ULPI interface. otg clears this bit before enabling the ULPI interface."]
pub type DisulpidrvrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - Contains the write data for register write. Read data for register read, valid when VStatus Done is Set."]
    #[inline(always)]
    pub fn regdata(&self) -> RegdataR {
        RegdataR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - The 4-bit register address a vendor defined 4-bit parallel output bus. ULPI Extended Register Address and the 6-bit PHY extended register address."]
    #[inline(always)]
    pub fn vctrl(&self) -> VctrlR {
        VctrlR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:21 - The 6-bit PHY register address for immediate PHY Register Set access. Set to 0x2F for Extended PHY Register Set access."]
    #[inline(always)]
    pub fn regaddr(&self) -> RegaddrR {
        RegaddrR::new(((self.bits >> 16) & 0x3f) as u8)
    }
    #[doc = "Bit 22 - Set this bit for register writes, and clear it for register reads."]
    #[inline(always)]
    pub fn regwr(&self) -> RegwrR {
        RegwrR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 25 - The application sets this bit for a new vendor controlaccess."]
    #[inline(always)]
    pub fn newregreq(&self) -> NewregreqR {
        NewregreqR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - The core sets this bit when the vendor control access is in progress and clears this bit when done."]
    #[inline(always)]
    pub fn vstsbsy(&self) -> VstsbsyR {
        VstsbsyR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - The core sets this bit when the vendor control access isdone. This bit is cleared by the core when the application sets the New Register Request bit (bit 25)."]
    #[inline(always)]
    pub fn vstsdone(&self) -> VstsdoneR {
        VstsdoneR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 31 - The application sets this bit when it has finished processing the ULPI Carkit Interrupt (GINTSTS.ULPICKINT). When Set, the otg core disables drivers for output signals and masks input signal for the ULPI interface. otg clears this bit before enabling the ULPI interface."]
    #[inline(always)]
    pub fn disulpidrvr(&self) -> DisulpidrvrR {
        DisulpidrvrR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - Contains the write data for register write. Read data for register read, valid when VStatus Done is Set."]
    #[inline(always)]
    #[must_use]
    pub fn regdata(&mut self) -> RegdataW<GlobgrpGpvndctlSpec> {
        RegdataW::new(self, 0)
    }
    #[doc = "Bits 8:15 - The 4-bit register address a vendor defined 4-bit parallel output bus. ULPI Extended Register Address and the 6-bit PHY extended register address."]
    #[inline(always)]
    #[must_use]
    pub fn vctrl(&mut self) -> VctrlW<GlobgrpGpvndctlSpec> {
        VctrlW::new(self, 8)
    }
    #[doc = "Bits 16:21 - The 6-bit PHY register address for immediate PHY Register Set access. Set to 0x2F for Extended PHY Register Set access."]
    #[inline(always)]
    #[must_use]
    pub fn regaddr(&mut self) -> RegaddrW<GlobgrpGpvndctlSpec> {
        RegaddrW::new(self, 16)
    }
    #[doc = "Bit 22 - Set this bit for register writes, and clear it for register reads."]
    #[inline(always)]
    #[must_use]
    pub fn regwr(&mut self) -> RegwrW<GlobgrpGpvndctlSpec> {
        RegwrW::new(self, 22)
    }
    #[doc = "Bit 25 - The application sets this bit for a new vendor controlaccess."]
    #[inline(always)]
    #[must_use]
    pub fn newregreq(&mut self) -> NewregreqW<GlobgrpGpvndctlSpec> {
        NewregreqW::new(self, 25)
    }
    #[doc = "Bit 26 - The core sets this bit when the vendor control access is in progress and clears this bit when done."]
    #[inline(always)]
    #[must_use]
    pub fn vstsbsy(&mut self) -> VstsbsyW<GlobgrpGpvndctlSpec> {
        VstsbsyW::new(self, 26)
    }
    #[doc = "Bit 27 - The core sets this bit when the vendor control access isdone. This bit is cleared by the core when the application sets the New Register Request bit (bit 25)."]
    #[inline(always)]
    #[must_use]
    pub fn vstsdone(&mut self) -> VstsdoneW<GlobgrpGpvndctlSpec> {
        VstsdoneW::new(self, 27)
    }
    #[doc = "Bit 31 - The application sets this bit when it has finished processing the ULPI Carkit Interrupt (GINTSTS.ULPICKINT). When Set, the otg core disables drivers for output signals and masks input signal for the ULPI interface. otg clears this bit before enabling the ULPI interface."]
    #[inline(always)]
    #[must_use]
    pub fn disulpidrvr(&mut self) -> DisulpidrvrW<GlobgrpGpvndctlSpec> {
        DisulpidrvrW::new(self, 31)
    }
}
#[doc = "The application can use this register to access PHY registers. for a ULPI PHY, the core uses the ULPI interface for PHY register access. The application sets Vendor Control register for PHY register access and times the PHY register access. The application polls the VStatus Done bit in this register for the completion of the PHY register access\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gpvndctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gpvndctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGpvndctlSpec;
impl crate::RegisterSpec for GlobgrpGpvndctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`globgrp_gpvndctl::R`](R) reader structure"]
impl crate::Readable for GlobgrpGpvndctlSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_gpvndctl::W`](W) writer structure"]
impl crate::Writable for GlobgrpGpvndctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_gpvndctl to value 0"]
impl crate::Resettable for GlobgrpGpvndctlSpec {
    const RESET_VALUE: u32 = 0;
}
