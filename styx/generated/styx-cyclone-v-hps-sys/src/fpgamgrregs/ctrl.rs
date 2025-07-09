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
#[doc = "Register `ctrl` reader"]
pub type R = crate::R<CtrlSpec>;
#[doc = "Register `ctrl` writer"]
pub type W = crate::W<CtrlSpec>;
#[doc = "Controls whether the FPGA configuration pins or HPS FPGA Manager drive configuration inputs to the CB.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum En {
    #[doc = "0: `0`"]
    FpgaPinsControlCfg = 0,
    #[doc = "1: `1`"]
    FpgamgrControlsCfg = 1,
}
impl From<En> for bool {
    #[inline(always)]
    fn from(variant: En) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `en` reader - Controls whether the FPGA configuration pins or HPS FPGA Manager drive configuration inputs to the CB."]
pub type EnR = crate::BitReader<En>;
impl EnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> En {
        match self.bits {
            false => En::FpgaPinsControlCfg,
            true => En::FpgamgrControlsCfg,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fpga_pins_control_cfg(&self) -> bool {
        *self == En::FpgaPinsControlCfg
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fpgamgr_controls_cfg(&self) -> bool {
        *self == En::FpgamgrControlsCfg
    }
}
#[doc = "Field `en` writer - Controls whether the FPGA configuration pins or HPS FPGA Manager drive configuration inputs to the CB."]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG, En>;
impl<'a, REG> EnW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fpga_pins_control_cfg(self) -> &'a mut crate::W<REG> {
        self.variant(En::FpgaPinsControlCfg)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn fpgamgr_controls_cfg(self) -> &'a mut crate::W<REG> {
        self.variant(En::FpgamgrControlsCfg)
    }
}
#[doc = "This field drives the active-low Chip Enable (nCE) signal to the CB. It should be set to 0 (configuration enabled) before CTRL.EN is set. This field only effects the FPGA if CTRL.EN is 1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nce {
    #[doc = "0: `0`"]
    CfgEnabled = 0,
    #[doc = "1: `1`"]
    CfgDisabled = 1,
}
impl From<Nce> for bool {
    #[inline(always)]
    fn from(variant: Nce) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nce` reader - This field drives the active-low Chip Enable (nCE) signal to the CB. It should be set to 0 (configuration enabled) before CTRL.EN is set. This field only effects the FPGA if CTRL.EN is 1."]
pub type NceR = crate::BitReader<Nce>;
impl NceR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nce {
        match self.bits {
            false => Nce::CfgEnabled,
            true => Nce::CfgDisabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_cfg_enabled(&self) -> bool {
        *self == Nce::CfgEnabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_cfg_disabled(&self) -> bool {
        *self == Nce::CfgDisabled
    }
}
#[doc = "Field `nce` writer - This field drives the active-low Chip Enable (nCE) signal to the CB. It should be set to 0 (configuration enabled) before CTRL.EN is set. This field only effects the FPGA if CTRL.EN is 1."]
pub type NceW<'a, REG> = crate::BitWriter<'a, REG, Nce>;
impl<'a, REG> NceW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn cfg_enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Nce::CfgEnabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn cfg_disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Nce::CfgDisabled)
    }
}
#[doc = "The nCONFIG input is used to put the FPGA into its reset phase. If the FPGA was configured, its operation stops and it will have to be configured again to start operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nconfigpull {
    #[doc = "0: `0`"]
    DontPulldown = 0,
    #[doc = "1: `1`"]
    Pulldown = 1,
}
impl From<Nconfigpull> for bool {
    #[inline(always)]
    fn from(variant: Nconfigpull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nconfigpull` reader - The nCONFIG input is used to put the FPGA into its reset phase. If the FPGA was configured, its operation stops and it will have to be configured again to start operation."]
pub type NconfigpullR = crate::BitReader<Nconfigpull>;
impl NconfigpullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nconfigpull {
        match self.bits {
            false => Nconfigpull::DontPulldown,
            true => Nconfigpull::Pulldown,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_dont_pulldown(&self) -> bool {
        *self == Nconfigpull::DontPulldown
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pulldown(&self) -> bool {
        *self == Nconfigpull::Pulldown
    }
}
#[doc = "Field `nconfigpull` writer - The nCONFIG input is used to put the FPGA into its reset phase. If the FPGA was configured, its operation stops and it will have to be configured again to start operation."]
pub type NconfigpullW<'a, REG> = crate::BitWriter<'a, REG, Nconfigpull>;
impl<'a, REG> NconfigpullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn dont_pulldown(self) -> &'a mut crate::W<REG> {
        self.variant(Nconfigpull::DontPulldown)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn pulldown(self) -> &'a mut crate::W<REG> {
        self.variant(Nconfigpull::Pulldown)
    }
}
#[doc = "Pulls down nSTATUS input to the CB\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nstatuspull {
    #[doc = "0: `0`"]
    DontPulldown = 0,
    #[doc = "1: `1`"]
    Pulldown = 1,
}
impl From<Nstatuspull> for bool {
    #[inline(always)]
    fn from(variant: Nstatuspull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nstatuspull` reader - Pulls down nSTATUS input to the CB"]
pub type NstatuspullR = crate::BitReader<Nstatuspull>;
impl NstatuspullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nstatuspull {
        match self.bits {
            false => Nstatuspull::DontPulldown,
            true => Nstatuspull::Pulldown,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_dont_pulldown(&self) -> bool {
        *self == Nstatuspull::DontPulldown
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pulldown(&self) -> bool {
        *self == Nstatuspull::Pulldown
    }
}
#[doc = "Field `nstatuspull` writer - Pulls down nSTATUS input to the CB"]
pub type NstatuspullW<'a, REG> = crate::BitWriter<'a, REG, Nstatuspull>;
impl<'a, REG> NstatuspullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn dont_pulldown(self) -> &'a mut crate::W<REG> {
        self.variant(Nstatuspull::DontPulldown)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn pulldown(self) -> &'a mut crate::W<REG> {
        self.variant(Nstatuspull::Pulldown)
    }
}
#[doc = "Pulls down CONF_DONE input to the CB\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confdonepull {
    #[doc = "0: `0`"]
    DontPulldown = 0,
    #[doc = "1: `1`"]
    Pulldown = 1,
}
impl From<Confdonepull> for bool {
    #[inline(always)]
    fn from(variant: Confdonepull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `confdonepull` reader - Pulls down CONF_DONE input to the CB"]
pub type ConfdonepullR = crate::BitReader<Confdonepull>;
impl ConfdonepullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Confdonepull {
        match self.bits {
            false => Confdonepull::DontPulldown,
            true => Confdonepull::Pulldown,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_dont_pulldown(&self) -> bool {
        *self == Confdonepull::DontPulldown
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pulldown(&self) -> bool {
        *self == Confdonepull::Pulldown
    }
}
#[doc = "Field `confdonepull` writer - Pulls down CONF_DONE input to the CB"]
pub type ConfdonepullW<'a, REG> = crate::BitWriter<'a, REG, Confdonepull>;
impl<'a, REG> ConfdonepullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn dont_pulldown(self) -> &'a mut crate::W<REG> {
        self.variant(Confdonepull::DontPulldown)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn pulldown(self) -> &'a mut crate::W<REG> {
        self.variant(Confdonepull::Pulldown)
    }
}
#[doc = "This field is used to assert PR_REQUEST to request partial reconfiguration while the FPGA is in User Mode. This field only affects the FPGA if CTRL.EN is 1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prreq {
    #[doc = "0: `0`"]
    Deassert = 0,
    #[doc = "1: `1`"]
    Assert = 1,
}
impl From<Prreq> for bool {
    #[inline(always)]
    fn from(variant: Prreq) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `prreq` reader - This field is used to assert PR_REQUEST to request partial reconfiguration while the FPGA is in User Mode. This field only affects the FPGA if CTRL.EN is 1."]
pub type PrreqR = crate::BitReader<Prreq>;
impl PrreqR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Prreq {
        match self.bits {
            false => Prreq::Deassert,
            true => Prreq::Assert,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_deassert(&self) -> bool {
        *self == Prreq::Deassert
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_assert(&self) -> bool {
        *self == Prreq::Assert
    }
}
#[doc = "Field `prreq` writer - This field is used to assert PR_REQUEST to request partial reconfiguration while the FPGA is in User Mode. This field only affects the FPGA if CTRL.EN is 1."]
pub type PrreqW<'a, REG> = crate::BitWriter<'a, REG, Prreq>;
impl<'a, REG> PrreqW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn deassert(self) -> &'a mut crate::W<REG> {
        self.variant(Prreq::Deassert)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn assert(self) -> &'a mut crate::W<REG> {
        self.variant(Prreq::Assert)
    }
}
#[doc = "This field controls the Clock to Data Ratio (CDRATIO) for Normal Configuration and Partial Reconfiguration data transfer from the AXI Slave to the FPGA. For Normal Configuration, the value in this field must be set to be consistent to the implied CD ratio of the MSEL setting. For Partial Reconfiguration, the value in this field must be set to the same clock to data ratio in the options bits in the Normal Configuration file.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cdratio {
    #[doc = "0: `0`"]
    X1 = 0,
    #[doc = "1: `1`"]
    X2 = 1,
    #[doc = "2: `10`"]
    X4 = 2,
    #[doc = "3: `11`"]
    X8 = 3,
}
impl From<Cdratio> for u8 {
    #[inline(always)]
    fn from(variant: Cdratio) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Cdratio {
    type Ux = u8;
}
#[doc = "Field `cdratio` reader - This field controls the Clock to Data Ratio (CDRATIO) for Normal Configuration and Partial Reconfiguration data transfer from the AXI Slave to the FPGA. For Normal Configuration, the value in this field must be set to be consistent to the implied CD ratio of the MSEL setting. For Partial Reconfiguration, the value in this field must be set to the same clock to data ratio in the options bits in the Normal Configuration file."]
pub type CdratioR = crate::FieldReader<Cdratio>;
impl CdratioR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cdratio {
        match self.bits {
            0 => Cdratio::X1,
            1 => Cdratio::X2,
            2 => Cdratio::X4,
            3 => Cdratio::X8,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_x1(&self) -> bool {
        *self == Cdratio::X1
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_x2(&self) -> bool {
        *self == Cdratio::X2
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_x4(&self) -> bool {
        *self == Cdratio::X4
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_x8(&self) -> bool {
        *self == Cdratio::X8
    }
}
#[doc = "Field `cdratio` writer - This field controls the Clock to Data Ratio (CDRATIO) for Normal Configuration and Partial Reconfiguration data transfer from the AXI Slave to the FPGA. For Normal Configuration, the value in this field must be set to be consistent to the implied CD ratio of the MSEL setting. For Partial Reconfiguration, the value in this field must be set to the same clock to data ratio in the options bits in the Normal Configuration file."]
pub type CdratioW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Cdratio>;
impl<'a, REG> CdratioW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn x1(self) -> &'a mut crate::W<REG> {
        self.variant(Cdratio::X1)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn x2(self) -> &'a mut crate::W<REG> {
        self.variant(Cdratio::X2)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn x4(self) -> &'a mut crate::W<REG> {
        self.variant(Cdratio::X4)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn x8(self) -> &'a mut crate::W<REG> {
        self.variant(Cdratio::X8)
    }
}
#[doc = "There are strict SW initialization steps for configuration, partial configuration and error cases. When SW is sending configuration files, this bit must be set before the file is transferred on the AXI bus. This bit enables the DCLK during the AXI configuration data transfers. Note, the AXI and configuration datapaths remain active irregardless of the state of this bit. Simply, if the AXI slave is enabled, the DCLK to the CB will be active. If disabled, the DCLK to the CB will not be active. So AXI transfers destined to the FPGA Manager when AXIEN is 0, will complete normally from the HPS perspective. This field only affects the FPGA if CTRL.EN is 1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Axicfgen {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Axicfgen> for bool {
    #[inline(always)]
    fn from(variant: Axicfgen) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `axicfgen` reader - There are strict SW initialization steps for configuration, partial configuration and error cases. When SW is sending configuration files, this bit must be set before the file is transferred on the AXI bus. This bit enables the DCLK during the AXI configuration data transfers. Note, the AXI and configuration datapaths remain active irregardless of the state of this bit. Simply, if the AXI slave is enabled, the DCLK to the CB will be active. If disabled, the DCLK to the CB will not be active. So AXI transfers destined to the FPGA Manager when AXIEN is 0, will complete normally from the HPS perspective. This field only affects the FPGA if CTRL.EN is 1."]
pub type AxicfgenR = crate::BitReader<Axicfgen>;
impl AxicfgenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Axicfgen {
        match self.bits {
            false => Axicfgen::Disabled,
            true => Axicfgen::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Axicfgen::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Axicfgen::Enabled
    }
}
#[doc = "Field `axicfgen` writer - There are strict SW initialization steps for configuration, partial configuration and error cases. When SW is sending configuration files, this bit must be set before the file is transferred on the AXI bus. This bit enables the DCLK during the AXI configuration data transfers. Note, the AXI and configuration datapaths remain active irregardless of the state of this bit. Simply, if the AXI slave is enabled, the DCLK to the CB will be active. If disabled, the DCLK to the CB will not be active. So AXI transfers destined to the FPGA Manager when AXIEN is 0, will complete normally from the HPS perspective. This field only affects the FPGA if CTRL.EN is 1."]
pub type AxicfgenW<'a, REG> = crate::BitWriter<'a, REG, Axicfgen>;
impl<'a, REG> AxicfgenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Axicfgen::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Axicfgen::Enabled)
    }
}
#[doc = "This field determines the Configuration Passive Parallel data bus width when HPS configures the FPGA. Only 32-bit Passive Parallel or 16-bit Passive Parallel are supported. When HPS does Normal Configuration, configuration should use 32-bit Passive Parallel Mode. The external pins MSEL must be set appropriately for the configuration selected. For Partial Reconfiguration, 16-bit Passive Parallel must be used.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cfgwdth {
    #[doc = "0: `0`"]
    Ppx16 = 0,
    #[doc = "1: `1`"]
    Ppx32 = 1,
}
impl From<Cfgwdth> for bool {
    #[inline(always)]
    fn from(variant: Cfgwdth) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `cfgwdth` reader - This field determines the Configuration Passive Parallel data bus width when HPS configures the FPGA. Only 32-bit Passive Parallel or 16-bit Passive Parallel are supported. When HPS does Normal Configuration, configuration should use 32-bit Passive Parallel Mode. The external pins MSEL must be set appropriately for the configuration selected. For Partial Reconfiguration, 16-bit Passive Parallel must be used."]
pub type CfgwdthR = crate::BitReader<Cfgwdth>;
impl CfgwdthR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Cfgwdth {
        match self.bits {
            false => Cfgwdth::Ppx16,
            true => Cfgwdth::Ppx32,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ppx16(&self) -> bool {
        *self == Cfgwdth::Ppx16
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ppx32(&self) -> bool {
        *self == Cfgwdth::Ppx32
    }
}
#[doc = "Field `cfgwdth` writer - This field determines the Configuration Passive Parallel data bus width when HPS configures the FPGA. Only 32-bit Passive Parallel or 16-bit Passive Parallel are supported. When HPS does Normal Configuration, configuration should use 32-bit Passive Parallel Mode. The external pins MSEL must be set appropriately for the configuration selected. For Partial Reconfiguration, 16-bit Passive Parallel must be used."]
pub type CfgwdthW<'a, REG> = crate::BitWriter<'a, REG, Cfgwdth>;
impl<'a, REG> CfgwdthW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn ppx16(self) -> &'a mut crate::W<REG> {
        self.variant(Cfgwdth::Ppx16)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ppx32(self) -> &'a mut crate::W<REG> {
        self.variant(Cfgwdth::Ppx32)
    }
}
impl R {
    #[doc = "Bit 0 - Controls whether the FPGA configuration pins or HPS FPGA Manager drive configuration inputs to the CB."]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This field drives the active-low Chip Enable (nCE) signal to the CB. It should be set to 0 (configuration enabled) before CTRL.EN is set. This field only effects the FPGA if CTRL.EN is 1."]
    #[inline(always)]
    pub fn nce(&self) -> NceR {
        NceR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - The nCONFIG input is used to put the FPGA into its reset phase. If the FPGA was configured, its operation stops and it will have to be configured again to start operation."]
    #[inline(always)]
    pub fn nconfigpull(&self) -> NconfigpullR {
        NconfigpullR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Pulls down nSTATUS input to the CB"]
    #[inline(always)]
    pub fn nstatuspull(&self) -> NstatuspullR {
        NstatuspullR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Pulls down CONF_DONE input to the CB"]
    #[inline(always)]
    pub fn confdonepull(&self) -> ConfdonepullR {
        ConfdonepullR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This field is used to assert PR_REQUEST to request partial reconfiguration while the FPGA is in User Mode. This field only affects the FPGA if CTRL.EN is 1."]
    #[inline(always)]
    pub fn prreq(&self) -> PrreqR {
        PrreqR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:7 - This field controls the Clock to Data Ratio (CDRATIO) for Normal Configuration and Partial Reconfiguration data transfer from the AXI Slave to the FPGA. For Normal Configuration, the value in this field must be set to be consistent to the implied CD ratio of the MSEL setting. For Partial Reconfiguration, the value in this field must be set to the same clock to data ratio in the options bits in the Normal Configuration file."]
    #[inline(always)]
    pub fn cdratio(&self) -> CdratioR {
        CdratioR::new(((self.bits >> 6) & 3) as u8)
    }
    #[doc = "Bit 8 - There are strict SW initialization steps for configuration, partial configuration and error cases. When SW is sending configuration files, this bit must be set before the file is transferred on the AXI bus. This bit enables the DCLK during the AXI configuration data transfers. Note, the AXI and configuration datapaths remain active irregardless of the state of this bit. Simply, if the AXI slave is enabled, the DCLK to the CB will be active. If disabled, the DCLK to the CB will not be active. So AXI transfers destined to the FPGA Manager when AXIEN is 0, will complete normally from the HPS perspective. This field only affects the FPGA if CTRL.EN is 1."]
    #[inline(always)]
    pub fn axicfgen(&self) -> AxicfgenR {
        AxicfgenR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This field determines the Configuration Passive Parallel data bus width when HPS configures the FPGA. Only 32-bit Passive Parallel or 16-bit Passive Parallel are supported. When HPS does Normal Configuration, configuration should use 32-bit Passive Parallel Mode. The external pins MSEL must be set appropriately for the configuration selected. For Partial Reconfiguration, 16-bit Passive Parallel must be used."]
    #[inline(always)]
    pub fn cfgwdth(&self) -> CfgwdthR {
        CfgwdthR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Controls whether the FPGA configuration pins or HPS FPGA Manager drive configuration inputs to the CB."]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<CtrlSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - This field drives the active-low Chip Enable (nCE) signal to the CB. It should be set to 0 (configuration enabled) before CTRL.EN is set. This field only effects the FPGA if CTRL.EN is 1."]
    #[inline(always)]
    #[must_use]
    pub fn nce(&mut self) -> NceW<CtrlSpec> {
        NceW::new(self, 1)
    }
    #[doc = "Bit 2 - The nCONFIG input is used to put the FPGA into its reset phase. If the FPGA was configured, its operation stops and it will have to be configured again to start operation."]
    #[inline(always)]
    #[must_use]
    pub fn nconfigpull(&mut self) -> NconfigpullW<CtrlSpec> {
        NconfigpullW::new(self, 2)
    }
    #[doc = "Bit 3 - Pulls down nSTATUS input to the CB"]
    #[inline(always)]
    #[must_use]
    pub fn nstatuspull(&mut self) -> NstatuspullW<CtrlSpec> {
        NstatuspullW::new(self, 3)
    }
    #[doc = "Bit 4 - Pulls down CONF_DONE input to the CB"]
    #[inline(always)]
    #[must_use]
    pub fn confdonepull(&mut self) -> ConfdonepullW<CtrlSpec> {
        ConfdonepullW::new(self, 4)
    }
    #[doc = "Bit 5 - This field is used to assert PR_REQUEST to request partial reconfiguration while the FPGA is in User Mode. This field only affects the FPGA if CTRL.EN is 1."]
    #[inline(always)]
    #[must_use]
    pub fn prreq(&mut self) -> PrreqW<CtrlSpec> {
        PrreqW::new(self, 5)
    }
    #[doc = "Bits 6:7 - This field controls the Clock to Data Ratio (CDRATIO) for Normal Configuration and Partial Reconfiguration data transfer from the AXI Slave to the FPGA. For Normal Configuration, the value in this field must be set to be consistent to the implied CD ratio of the MSEL setting. For Partial Reconfiguration, the value in this field must be set to the same clock to data ratio in the options bits in the Normal Configuration file."]
    #[inline(always)]
    #[must_use]
    pub fn cdratio(&mut self) -> CdratioW<CtrlSpec> {
        CdratioW::new(self, 6)
    }
    #[doc = "Bit 8 - There are strict SW initialization steps for configuration, partial configuration and error cases. When SW is sending configuration files, this bit must be set before the file is transferred on the AXI bus. This bit enables the DCLK during the AXI configuration data transfers. Note, the AXI and configuration datapaths remain active irregardless of the state of this bit. Simply, if the AXI slave is enabled, the DCLK to the CB will be active. If disabled, the DCLK to the CB will not be active. So AXI transfers destined to the FPGA Manager when AXIEN is 0, will complete normally from the HPS perspective. This field only affects the FPGA if CTRL.EN is 1."]
    #[inline(always)]
    #[must_use]
    pub fn axicfgen(&mut self) -> AxicfgenW<CtrlSpec> {
        AxicfgenW::new(self, 8)
    }
    #[doc = "Bit 9 - This field determines the Configuration Passive Parallel data bus width when HPS configures the FPGA. Only 32-bit Passive Parallel or 16-bit Passive Parallel are supported. When HPS does Normal Configuration, configuration should use 32-bit Passive Parallel Mode. The external pins MSEL must be set appropriately for the configuration selected. For Partial Reconfiguration, 16-bit Passive Parallel must be used."]
    #[inline(always)]
    #[must_use]
    pub fn cfgwdth(&mut self) -> CfgwdthW<CtrlSpec> {
        CfgwdthW::new(self, 9)
    }
}
#[doc = "Allows HPS to control FPGA configuration. The NCONFIGPULL, NSTATUSPULL, and CONFDONEPULL fields drive signals to the FPGA Control Block that are logically ORed into their respective pins. These signals are always driven independent of the value of EN. The polarity of the NCONFIGPULL, NSTATUSPULL, and CONFDONEPULL fields is inverted relative to their associated pins. The MSEL (external pins), CDRATIO and CFGWDTH signals determine the mode of operation for Normal Configuration. For Partial Reconfiguration, CDRATIO is used to set the appropriate clock to data ratio, and CFGWDTH should always be set to 16-bit Passive Parallel. AXICFGEN is used to enable transfer of configuration data by enabling or disabling DCLK during data transfers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlSpec;
impl crate::RegisterSpec for CtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`ctrl::R`](R) reader structure"]
impl crate::Readable for CtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrl::W`](W) writer structure"]
impl crate::Writable for CtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrl to value 0x0200"]
impl crate::Resettable for CtrlSpec {
    const RESET_VALUE: u32 = 0x0200;
}
