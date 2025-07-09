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
#[doc = "Register `hostgrp_hfir` reader"]
pub type R = crate::R<HostgrpHfirSpec>;
#[doc = "Register `hostgrp_hfir` writer"]
pub type W = crate::W<HostgrpHfirSpec>;
#[doc = "Field `frint` reader - The value that the application programs to this field specifies the interval between two consecutive SOFs (FS) or micro- SOFs (HS) or Keep-Alive tokens (HS). This field contains the number of PHY clocks that constitute the required frame interval. The Default value Set in this field for a FS operation when the PHY clock frequency is 60 MHz. The application can write a value to this register only after the Port Enable bit of the Host Port Control and Status register (HPRT.PrtEnaPort) has been Set. If no value is programmed, the core calculates the value based on the PHY clock specified in the FS/LS PHY Clock Select field of the Host Configuration register (HCFG.FSLSPclkSel). Do not change the value of this field after the initial configuration. 125 s * (PHY clock frequency for HS) 1 ms * (PHY clock frequency for FS/LS)"]
pub type FrintR = crate::FieldReader<u16>;
#[doc = "Field `frint` writer - The value that the application programs to this field specifies the interval between two consecutive SOFs (FS) or micro- SOFs (HS) or Keep-Alive tokens (HS). This field contains the number of PHY clocks that constitute the required frame interval. The Default value Set in this field for a FS operation when the PHY clock frequency is 60 MHz. The application can write a value to this register only after the Port Enable bit of the Host Port Control and Status register (HPRT.PrtEnaPort) has been Set. If no value is programmed, the core calculates the value based on the PHY clock specified in the FS/LS PHY Clock Select field of the Host Configuration register (HCFG.FSLSPclkSel). Do not change the value of this field after the initial configuration. 125 s * (PHY clock frequency for HS) 1 ms * (PHY clock frequency for FS/LS)"]
pub type FrintW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "This bit allows dynamic reloading of the HFIR register during run time. 0x0 : The HFIR cannot be reloaded dynamically0x1: the HFIR can be dynamically reloaded during runtime. This bit needs to be programmed during initial configuration and its value should not be changed during runtime.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hfirrldctrl {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Hfirrldctrl> for bool {
    #[inline(always)]
    fn from(variant: Hfirrldctrl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hfirrldctrl` reader - This bit allows dynamic reloading of the HFIR register during run time. 0x0 : The HFIR cannot be reloaded dynamically0x1: the HFIR can be dynamically reloaded during runtime. This bit needs to be programmed during initial configuration and its value should not be changed during runtime."]
pub type HfirrldctrlR = crate::BitReader<Hfirrldctrl>;
impl HfirrldctrlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hfirrldctrl {
        match self.bits {
            false => Hfirrldctrl::Disabled,
            true => Hfirrldctrl::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hfirrldctrl::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Hfirrldctrl::Enabled
    }
}
#[doc = "Field `hfirrldctrl` writer - This bit allows dynamic reloading of the HFIR register during run time. 0x0 : The HFIR cannot be reloaded dynamically0x1: the HFIR can be dynamically reloaded during runtime. This bit needs to be programmed during initial configuration and its value should not be changed during runtime."]
pub type HfirrldctrlW<'a, REG> = crate::BitWriter<'a, REG, Hfirrldctrl>;
impl<'a, REG> HfirrldctrlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hfirrldctrl::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hfirrldctrl::Enabled)
    }
}
impl R {
    #[doc = "Bits 0:15 - The value that the application programs to this field specifies the interval between two consecutive SOFs (FS) or micro- SOFs (HS) or Keep-Alive tokens (HS). This field contains the number of PHY clocks that constitute the required frame interval. The Default value Set in this field for a FS operation when the PHY clock frequency is 60 MHz. The application can write a value to this register only after the Port Enable bit of the Host Port Control and Status register (HPRT.PrtEnaPort) has been Set. If no value is programmed, the core calculates the value based on the PHY clock specified in the FS/LS PHY Clock Select field of the Host Configuration register (HCFG.FSLSPclkSel). Do not change the value of this field after the initial configuration. 125 s * (PHY clock frequency for HS) 1 ms * (PHY clock frequency for FS/LS)"]
    #[inline(always)]
    pub fn frint(&self) -> FrintR {
        FrintR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bit 16 - This bit allows dynamic reloading of the HFIR register during run time. 0x0 : The HFIR cannot be reloaded dynamically0x1: the HFIR can be dynamically reloaded during runtime. This bit needs to be programmed during initial configuration and its value should not be changed during runtime."]
    #[inline(always)]
    pub fn hfirrldctrl(&self) -> HfirrldctrlR {
        HfirrldctrlR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - The value that the application programs to this field specifies the interval between two consecutive SOFs (FS) or micro- SOFs (HS) or Keep-Alive tokens (HS). This field contains the number of PHY clocks that constitute the required frame interval. The Default value Set in this field for a FS operation when the PHY clock frequency is 60 MHz. The application can write a value to this register only after the Port Enable bit of the Host Port Control and Status register (HPRT.PrtEnaPort) has been Set. If no value is programmed, the core calculates the value based on the PHY clock specified in the FS/LS PHY Clock Select field of the Host Configuration register (HCFG.FSLSPclkSel). Do not change the value of this field after the initial configuration. 125 s * (PHY clock frequency for HS) 1 ms * (PHY clock frequency for FS/LS)"]
    #[inline(always)]
    #[must_use]
    pub fn frint(&mut self) -> FrintW<HostgrpHfirSpec> {
        FrintW::new(self, 0)
    }
    #[doc = "Bit 16 - This bit allows dynamic reloading of the HFIR register during run time. 0x0 : The HFIR cannot be reloaded dynamically0x1: the HFIR can be dynamically reloaded during runtime. This bit needs to be programmed during initial configuration and its value should not be changed during runtime."]
    #[inline(always)]
    #[must_use]
    pub fn hfirrldctrl(&mut self) -> HfirrldctrlW<HostgrpHfirSpec> {
        HfirrldctrlW::new(self, 16)
    }
}
#[doc = "This register stores the frame interval information for the current speed to which the otg core has enumerated\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hfir::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hfir::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHfirSpec;
impl crate::RegisterSpec for HostgrpHfirSpec {
    type Ux = u32;
    const OFFSET: u64 = 1028u64;
}
#[doc = "`read()` method returns [`hostgrp_hfir::R`](R) reader structure"]
impl crate::Readable for HostgrpHfirSpec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hfir::W`](W) writer structure"]
impl crate::Writable for HostgrpHfirSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hfir to value 0xea60"]
impl crate::Resettable for HostgrpHfirSpec {
    const RESET_VALUE: u32 = 0xea60;
}
