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
#[doc = "Register `romcodegrp_ctrl` reader"]
pub type R = crate::R<RomcodegrpCtrlSpec>;
#[doc = "Register `romcodegrp_ctrl` writer"]
pub type W = crate::W<RomcodegrpCtrlSpec>;
#[doc = "Specifies whether the Boot ROM code configures the pin mux for boot pins after a warm reset. Note that the Boot ROM code always configures the pin mux for boot pins after a cold reset. After the Boot ROM code configures the pin mux for boot pins, it always disables this field. It is up to user software to enable this field if it wants a different behavior.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warmrstcfgpinmux {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Warmrstcfgpinmux> for bool {
    #[inline(always)]
    fn from(variant: Warmrstcfgpinmux) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `warmrstcfgpinmux` reader - Specifies whether the Boot ROM code configures the pin mux for boot pins after a warm reset. Note that the Boot ROM code always configures the pin mux for boot pins after a cold reset. After the Boot ROM code configures the pin mux for boot pins, it always disables this field. It is up to user software to enable this field if it wants a different behavior."]
pub type WarmrstcfgpinmuxR = crate::BitReader<Warmrstcfgpinmux>;
impl WarmrstcfgpinmuxR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Warmrstcfgpinmux {
        match self.bits {
            false => Warmrstcfgpinmux::Disabled,
            true => Warmrstcfgpinmux::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Warmrstcfgpinmux::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Warmrstcfgpinmux::Enabled
    }
}
#[doc = "Field `warmrstcfgpinmux` writer - Specifies whether the Boot ROM code configures the pin mux for boot pins after a warm reset. Note that the Boot ROM code always configures the pin mux for boot pins after a cold reset. After the Boot ROM code configures the pin mux for boot pins, it always disables this field. It is up to user software to enable this field if it wants a different behavior."]
pub type WarmrstcfgpinmuxW<'a, REG> = crate::BitWriter<'a, REG, Warmrstcfgpinmux>;
impl<'a, REG> WarmrstcfgpinmuxW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Warmrstcfgpinmux::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Warmrstcfgpinmux::Enabled)
    }
}
#[doc = "Specifies whether the Boot ROM code configures the IOs used by boot after a warm reset. Note that the Boot ROM code always configures the IOs used by boot after a cold reset. After the Boot ROM code configures the IOs used by boot, it always disables this field. It is up to user software to enable this field if it wants a different behavior.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warmrstcfgio {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Warmrstcfgio> for bool {
    #[inline(always)]
    fn from(variant: Warmrstcfgio) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `warmrstcfgio` reader - Specifies whether the Boot ROM code configures the IOs used by boot after a warm reset. Note that the Boot ROM code always configures the IOs used by boot after a cold reset. After the Boot ROM code configures the IOs used by boot, it always disables this field. It is up to user software to enable this field if it wants a different behavior."]
pub type WarmrstcfgioR = crate::BitReader<Warmrstcfgio>;
impl WarmrstcfgioR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Warmrstcfgio {
        match self.bits {
            false => Warmrstcfgio::Disabled,
            true => Warmrstcfgio::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Warmrstcfgio::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Warmrstcfgio::Enabled
    }
}
#[doc = "Field `warmrstcfgio` writer - Specifies whether the Boot ROM code configures the IOs used by boot after a warm reset. Note that the Boot ROM code always configures the IOs used by boot after a cold reset. After the Boot ROM code configures the IOs used by boot, it always disables this field. It is up to user software to enable this field if it wants a different behavior."]
pub type WarmrstcfgioW<'a, REG> = crate::BitWriter<'a, REG, Warmrstcfgio>;
impl<'a, REG> WarmrstcfgioW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Warmrstcfgio::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Warmrstcfgio::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - Specifies whether the Boot ROM code configures the pin mux for boot pins after a warm reset. Note that the Boot ROM code always configures the pin mux for boot pins after a cold reset. After the Boot ROM code configures the pin mux for boot pins, it always disables this field. It is up to user software to enable this field if it wants a different behavior."]
    #[inline(always)]
    pub fn warmrstcfgpinmux(&self) -> WarmrstcfgpinmuxR {
        WarmrstcfgpinmuxR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Specifies whether the Boot ROM code configures the IOs used by boot after a warm reset. Note that the Boot ROM code always configures the IOs used by boot after a cold reset. After the Boot ROM code configures the IOs used by boot, it always disables this field. It is up to user software to enable this field if it wants a different behavior."]
    #[inline(always)]
    pub fn warmrstcfgio(&self) -> WarmrstcfgioR {
        WarmrstcfgioR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Specifies whether the Boot ROM code configures the pin mux for boot pins after a warm reset. Note that the Boot ROM code always configures the pin mux for boot pins after a cold reset. After the Boot ROM code configures the pin mux for boot pins, it always disables this field. It is up to user software to enable this field if it wants a different behavior."]
    #[inline(always)]
    #[must_use]
    pub fn warmrstcfgpinmux(&mut self) -> WarmrstcfgpinmuxW<RomcodegrpCtrlSpec> {
        WarmrstcfgpinmuxW::new(self, 0)
    }
    #[doc = "Bit 1 - Specifies whether the Boot ROM code configures the IOs used by boot after a warm reset. Note that the Boot ROM code always configures the IOs used by boot after a cold reset. After the Boot ROM code configures the IOs used by boot, it always disables this field. It is up to user software to enable this field if it wants a different behavior."]
    #[inline(always)]
    #[must_use]
    pub fn warmrstcfgio(&mut self) -> WarmrstcfgioW<RomcodegrpCtrlSpec> {
        WarmrstcfgioW::new(self, 1)
    }
}
#[doc = "Contains information used to control Boot ROM code.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpCtrlSpec;
impl crate::RegisterSpec for RomcodegrpCtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 192u64;
}
#[doc = "`read()` method returns [`romcodegrp_ctrl::R`](R) reader structure"]
impl crate::Readable for RomcodegrpCtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_ctrl::W`](W) writer structure"]
impl crate::Writable for RomcodegrpCtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_ctrl to value 0"]
impl crate::Resettable for RomcodegrpCtrlSpec {
    const RESET_VALUE: u32 = 0;
}
