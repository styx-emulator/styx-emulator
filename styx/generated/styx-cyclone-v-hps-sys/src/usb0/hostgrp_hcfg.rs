// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `hostgrp_hcfg` reader"]
pub type R = crate::R<HostgrpHcfgSpec>;
#[doc = "Register `hostgrp_hcfg` writer"]
pub type W = crate::W<HostgrpHcfgSpec>;
#[doc = "When the core is in FS Host mode. The internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 48MHZ for 1.1 FS transceiver Interface When the core is in LS Host mode, the internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 6 MHZ and the external clock is running at 48MHZ. When you select a 6 MHz clock during LS Mode, you must do a soft reset for 1.1 FS transceiver Interface. * When Core in FS mode, the internal and external clocks have the same frequency. * When Core in LS mode, - If fslspclksel is 30/60 Mhz internal and external clocks have the same frequency. - If fslspclksel is 6Mhz the internal clock is divided by eight of external 48 MHz clock (utmifs_clk).\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Fslspclksel {
    #[doc = "0: `0`"]
    Clk3060 = 0,
    #[doc = "1: `1`"]
    Clk48 = 1,
    #[doc = "2: `10`"]
    Clk6 = 2,
}
impl From<Fslspclksel> for u8 {
    #[inline(always)]
    fn from(variant: Fslspclksel) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Fslspclksel {
    type Ux = u8;
}
#[doc = "Field `fslspclksel` reader - When the core is in FS Host mode. The internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 48MHZ for 1.1 FS transceiver Interface When the core is in LS Host mode, the internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 6 MHZ and the external clock is running at 48MHZ. When you select a 6 MHz clock during LS Mode, you must do a soft reset for 1.1 FS transceiver Interface. * When Core in FS mode, the internal and external clocks have the same frequency. * When Core in LS mode, - If fslspclksel is 30/60 Mhz internal and external clocks have the same frequency. - If fslspclksel is 6Mhz the internal clock is divided by eight of external 48 MHz clock (utmifs_clk)."]
pub type FslspclkselR = crate::FieldReader<Fslspclksel>;
impl FslspclkselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Fslspclksel> {
        match self.bits {
            0 => Some(Fslspclksel::Clk3060),
            1 => Some(Fslspclksel::Clk48),
            2 => Some(Fslspclksel::Clk6),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_clk3060(&self) -> bool {
        *self == Fslspclksel::Clk3060
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_clk48(&self) -> bool {
        *self == Fslspclksel::Clk48
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_clk6(&self) -> bool {
        *self == Fslspclksel::Clk6
    }
}
#[doc = "Field `fslspclksel` writer - When the core is in FS Host mode. The internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 48MHZ for 1.1 FS transceiver Interface When the core is in LS Host mode, the internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 6 MHZ and the external clock is running at 48MHZ. When you select a 6 MHz clock during LS Mode, you must do a soft reset for 1.1 FS transceiver Interface. * When Core in FS mode, the internal and external clocks have the same frequency. * When Core in LS mode, - If fslspclksel is 30/60 Mhz internal and external clocks have the same frequency. - If fslspclksel is 6Mhz the internal clock is divided by eight of external 48 MHz clock (utmifs_clk)."]
pub type FslspclkselW<'a, REG> = crate::FieldWriter<'a, REG, 2, Fslspclksel>;
impl<'a, REG> FslspclkselW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn clk3060(self) -> &'a mut crate::W<REG> {
        self.variant(Fslspclksel::Clk3060)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn clk48(self) -> &'a mut crate::W<REG> {
        self.variant(Fslspclksel::Clk48)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn clk6(self) -> &'a mut crate::W<REG> {
        self.variant(Fslspclksel::Clk6)
    }
}
#[doc = "The application uses this bit to control the core's enumeration speed. Using this bit, the application can make the core enumerate as a FS host, even If the connected device supports HS traffic. Do not make changes to this field after initial programming.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fslssupp {
    #[doc = "0: `0`"]
    Hsfsls = 0,
    #[doc = "1: `1`"]
    Fsls = 1,
}
impl From<Fslssupp> for bool {
    #[inline(always)]
    fn from(variant: Fslssupp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fslssupp` reader - The application uses this bit to control the core's enumeration speed. Using this bit, the application can make the core enumerate as a FS host, even If the connected device supports HS traffic. Do not make changes to this field after initial programming."]
pub type FslssuppR = crate::BitReader<Fslssupp>;
impl FslssuppR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fslssupp {
        match self.bits {
            false => Fslssupp::Hsfsls,
            true => Fslssupp::Fsls,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_hsfsls(&self) -> bool {
        *self == Fslssupp::Hsfsls
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fsls(&self) -> bool {
        *self == Fslssupp::Fsls
    }
}
#[doc = "Field `fslssupp` writer - The application uses this bit to control the core's enumeration speed. Using this bit, the application can make the core enumerate as a FS host, even If the connected device supports HS traffic. Do not make changes to this field after initial programming."]
pub type FslssuppW<'a, REG> = crate::BitWriter<'a, REG, Fslssupp>;
impl<'a, REG> FslssuppW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn hsfsls(self) -> &'a mut crate::W<REG> {
        self.variant(Fslssupp::Hsfsls)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn fsls(self) -> &'a mut crate::W<REG> {
        self.variant(Fslssupp::Fsls)
    }
}
#[doc = "This bit can only be set if the USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero. When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ena32khzs {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ena32khzs> for bool {
    #[inline(always)]
    fn from(variant: Ena32khzs) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ena32khzs` reader - This bit can only be set if the USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero. When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend."]
pub type Ena32khzsR = crate::BitReader<Ena32khzs>;
impl Ena32khzsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ena32khzs {
        match self.bits {
            false => Ena32khzs::Disabled,
            true => Ena32khzs::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ena32khzs::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ena32khzs::Enabled
    }
}
#[doc = "Field `ena32khzs` writer - This bit can only be set if the USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero. When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend."]
pub type Ena32khzsW<'a, REG> = crate::BitWriter<'a, REG, Ena32khzs>;
impl<'a, REG> Ena32khzsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ena32khzs::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ena32khzs::Enabled)
    }
}
#[doc = "Field `resvalid` reader - This field is effective only when HCFG.Ena32KHzS is set. It will control the resume period when the core resumes from suspend. The core counts for ResValid number of clock cycles to detect a valid resume when this is set."]
pub type ResvalidR = crate::FieldReader;
#[doc = "Field `resvalid` writer - This field is effective only when HCFG.Ena32KHzS is set. It will control the resume period when the core resumes from suspend. The core counts for ResValid number of clock cycles to detect a valid resume when this is set."]
pub type ResvalidW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "The application can set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset. The following combinations are available for programming: GAHBCFG.DMAEn=0,HCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,HCFG.DescDMA=1 => InvalidGAHBCFG.DMAEn=1,HCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,HCFG.DescDMA=1 => Scatter/Gather DMA mode\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Descdma {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Descdma> for bool {
    #[inline(always)]
    fn from(variant: Descdma) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `descdma` reader - The application can set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset. The following combinations are available for programming: GAHBCFG.DMAEn=0,HCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,HCFG.DescDMA=1 => InvalidGAHBCFG.DMAEn=1,HCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,HCFG.DescDMA=1 => Scatter/Gather DMA mode"]
pub type DescdmaR = crate::BitReader<Descdma>;
impl DescdmaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Descdma {
        match self.bits {
            false => Descdma::Disabled,
            true => Descdma::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Descdma::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Descdma::Enabled
    }
}
#[doc = "Field `descdma` writer - The application can set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset. The following combinations are available for programming: GAHBCFG.DMAEn=0,HCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,HCFG.DescDMA=1 => InvalidGAHBCFG.DMAEn=1,HCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,HCFG.DescDMA=1 => Scatter/Gather DMA mode"]
pub type DescdmaW<'a, REG> = crate::BitWriter<'a, REG, Descdma>;
impl<'a, REG> DescdmaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Descdma::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Descdma::Enabled)
    }
}
#[doc = "The value in the register specifies the number of entries in the Frame list. This field is valid only in Scatter/Gather DMA mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Frlisten {
    #[doc = "1: `1`"]
    Entry8 = 1,
    #[doc = "2: `10`"]
    Entry16 = 2,
    #[doc = "3: `11`"]
    Entry32 = 3,
}
impl From<Frlisten> for u8 {
    #[inline(always)]
    fn from(variant: Frlisten) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Frlisten {
    type Ux = u8;
}
#[doc = "Field `frlisten` reader - The value in the register specifies the number of entries in the Frame list. This field is valid only in Scatter/Gather DMA mode."]
pub type FrlistenR = crate::FieldReader<Frlisten>;
impl FrlistenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Frlisten {
        match self.bits {
            1 => Frlisten::Entry8,
            2 => Frlisten::Entry16,
            3 => Frlisten::Entry32,
            _ => unreachable!(),
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_entry8(&self) -> bool {
        *self == Frlisten::Entry8
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_entry16(&self) -> bool {
        *self == Frlisten::Entry16
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_entry32(&self) -> bool {
        *self == Frlisten::Entry32
    }
}
#[doc = "Field `frlisten` writer - The value in the register specifies the number of entries in the Frame list. This field is valid only in Scatter/Gather DMA mode."]
pub type FrlistenW<'a, REG> = crate::FieldWriter<'a, REG, 2, Frlisten>;
impl<'a, REG> FrlistenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn entry8(self) -> &'a mut crate::W<REG> {
        self.variant(Frlisten::Entry8)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn entry16(self) -> &'a mut crate::W<REG> {
        self.variant(Frlisten::Entry16)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn entry32(self) -> &'a mut crate::W<REG> {
        self.variant(Frlisten::Entry32)
    }
}
#[doc = "Applicable in Scatter/Gather DMA mode only. Enables periodic scheduling within the core. Initially, the bit is reset. The core will not process any periodic channels. As soon as this bit is set, the core will get ready to start scheduling periodic channels. In non Scatter/Gather DMA mode, this bit is reserved.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perschedena {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Perschedena> for bool {
    #[inline(always)]
    fn from(variant: Perschedena) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `perschedena` reader - Applicable in Scatter/Gather DMA mode only. Enables periodic scheduling within the core. Initially, the bit is reset. The core will not process any periodic channels. As soon as this bit is set, the core will get ready to start scheduling periodic channels. In non Scatter/Gather DMA mode, this bit is reserved."]
pub type PerschedenaR = crate::BitReader<Perschedena>;
impl PerschedenaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Perschedena {
        match self.bits {
            false => Perschedena::Disabled,
            true => Perschedena::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Perschedena::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Perschedena::Enabled
    }
}
#[doc = "Field `perschedena` writer - Applicable in Scatter/Gather DMA mode only. Enables periodic scheduling within the core. Initially, the bit is reset. The core will not process any periodic channels. As soon as this bit is set, the core will get ready to start scheduling periodic channels. In non Scatter/Gather DMA mode, this bit is reserved."]
pub type PerschedenaW<'a, REG> = crate::BitWriter<'a, REG, Perschedena>;
impl<'a, REG> PerschedenaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Perschedena::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Perschedena::Enabled)
    }
}
#[doc = "This bit is used to enable or disable the host core to wait for 200 PHY clock cycles at the end of Resume to change the opmode signal to the PHY to 00 after Suspend or LPM.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modechtimen {
    #[doc = "0: `0`"]
    Enabled = 0,
    #[doc = "1: `1`"]
    Disabled = 1,
}
impl From<Modechtimen> for bool {
    #[inline(always)]
    fn from(variant: Modechtimen) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `modechtimen` reader - This bit is used to enable or disable the host core to wait for 200 PHY clock cycles at the end of Resume to change the opmode signal to the PHY to 00 after Suspend or LPM."]
pub type ModechtimenR = crate::BitReader<Modechtimen>;
impl ModechtimenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Modechtimen {
        match self.bits {
            false => Modechtimen::Enabled,
            true => Modechtimen::Disabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Modechtimen::Enabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Modechtimen::Disabled
    }
}
#[doc = "Field `modechtimen` writer - This bit is used to enable or disable the host core to wait for 200 PHY clock cycles at the end of Resume to change the opmode signal to the PHY to 00 after Suspend or LPM."]
pub type ModechtimenW<'a, REG> = crate::BitWriter<'a, REG, Modechtimen>;
impl<'a, REG> ModechtimenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Modechtimen::Enabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Modechtimen::Disabled)
    }
}
impl R {
    #[doc = "Bits 0:1 - When the core is in FS Host mode. The internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 48MHZ for 1.1 FS transceiver Interface When the core is in LS Host mode, the internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 6 MHZ and the external clock is running at 48MHZ. When you select a 6 MHz clock during LS Mode, you must do a soft reset for 1.1 FS transceiver Interface. * When Core in FS mode, the internal and external clocks have the same frequency. * When Core in LS mode, - If fslspclksel is 30/60 Mhz internal and external clocks have the same frequency. - If fslspclksel is 6Mhz the internal clock is divided by eight of external 48 MHz clock (utmifs_clk)."]
    #[inline(always)]
    pub fn fslspclksel(&self) -> FslspclkselR {
        FslspclkselR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - The application uses this bit to control the core's enumeration speed. Using this bit, the application can make the core enumerate as a FS host, even If the connected device supports HS traffic. Do not make changes to this field after initial programming."]
    #[inline(always)]
    pub fn fslssupp(&self) -> FslssuppR {
        FslssuppR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit can only be set if the USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero. When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend."]
    #[inline(always)]
    pub fn ena32khzs(&self) -> Ena32khzsR {
        Ena32khzsR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:15 - This field is effective only when HCFG.Ena32KHzS is set. It will control the resume period when the core resumes from suspend. The core counts for ResValid number of clock cycles to detect a valid resume when this is set."]
    #[inline(always)]
    pub fn resvalid(&self) -> ResvalidR {
        ResvalidR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bit 23 - The application can set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset. The following combinations are available for programming: GAHBCFG.DMAEn=0,HCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,HCFG.DescDMA=1 => InvalidGAHBCFG.DMAEn=1,HCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,HCFG.DescDMA=1 => Scatter/Gather DMA mode"]
    #[inline(always)]
    pub fn descdma(&self) -> DescdmaR {
        DescdmaR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bits 24:25 - The value in the register specifies the number of entries in the Frame list. This field is valid only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn frlisten(&self) -> FrlistenR {
        FrlistenR::new(((self.bits >> 24) & 3) as u8)
    }
    #[doc = "Bit 26 - Applicable in Scatter/Gather DMA mode only. Enables periodic scheduling within the core. Initially, the bit is reset. The core will not process any periodic channels. As soon as this bit is set, the core will get ready to start scheduling periodic channels. In non Scatter/Gather DMA mode, this bit is reserved."]
    #[inline(always)]
    pub fn perschedena(&self) -> PerschedenaR {
        PerschedenaR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 31 - This bit is used to enable or disable the host core to wait for 200 PHY clock cycles at the end of Resume to change the opmode signal to the PHY to 00 after Suspend or LPM."]
    #[inline(always)]
    pub fn modechtimen(&self) -> ModechtimenR {
        ModechtimenR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:1 - When the core is in FS Host mode. The internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 48MHZ for 1.1 FS transceiver Interface When the core is in LS Host mode, the internal PHY clock is running at 30/60 MHZ for ULPI PHY Interfaces. The internal PHY clock is running at 6 MHZ and the external clock is running at 48MHZ. When you select a 6 MHz clock during LS Mode, you must do a soft reset for 1.1 FS transceiver Interface. * When Core in FS mode, the internal and external clocks have the same frequency. * When Core in LS mode, - If fslspclksel is 30/60 Mhz internal and external clocks have the same frequency. - If fslspclksel is 6Mhz the internal clock is divided by eight of external 48 MHz clock (utmifs_clk)."]
    #[inline(always)]
    #[must_use]
    pub fn fslspclksel(&mut self) -> FslspclkselW<HostgrpHcfgSpec> {
        FslspclkselW::new(self, 0)
    }
    #[doc = "Bit 2 - The application uses this bit to control the core's enumeration speed. Using this bit, the application can make the core enumerate as a FS host, even If the connected device supports HS traffic. Do not make changes to this field after initial programming."]
    #[inline(always)]
    #[must_use]
    pub fn fslssupp(&mut self) -> FslssuppW<HostgrpHcfgSpec> {
        FslssuppW::new(self, 2)
    }
    #[doc = "Bit 7 - This bit can only be set if the USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero. When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend."]
    #[inline(always)]
    #[must_use]
    pub fn ena32khzs(&mut self) -> Ena32khzsW<HostgrpHcfgSpec> {
        Ena32khzsW::new(self, 7)
    }
    #[doc = "Bits 8:15 - This field is effective only when HCFG.Ena32KHzS is set. It will control the resume period when the core resumes from suspend. The core counts for ResValid number of clock cycles to detect a valid resume when this is set."]
    #[inline(always)]
    #[must_use]
    pub fn resvalid(&mut self) -> ResvalidW<HostgrpHcfgSpec> {
        ResvalidW::new(self, 8)
    }
    #[doc = "Bit 23 - The application can set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset. The following combinations are available for programming: GAHBCFG.DMAEn=0,HCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,HCFG.DescDMA=1 => InvalidGAHBCFG.DMAEn=1,HCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,HCFG.DescDMA=1 => Scatter/Gather DMA mode"]
    #[inline(always)]
    #[must_use]
    pub fn descdma(&mut self) -> DescdmaW<HostgrpHcfgSpec> {
        DescdmaW::new(self, 23)
    }
    #[doc = "Bits 24:25 - The value in the register specifies the number of entries in the Frame list. This field is valid only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn frlisten(&mut self) -> FrlistenW<HostgrpHcfgSpec> {
        FrlistenW::new(self, 24)
    }
    #[doc = "Bit 26 - Applicable in Scatter/Gather DMA mode only. Enables periodic scheduling within the core. Initially, the bit is reset. The core will not process any periodic channels. As soon as this bit is set, the core will get ready to start scheduling periodic channels. In non Scatter/Gather DMA mode, this bit is reserved."]
    #[inline(always)]
    #[must_use]
    pub fn perschedena(&mut self) -> PerschedenaW<HostgrpHcfgSpec> {
        PerschedenaW::new(self, 26)
    }
    #[doc = "Bit 31 - This bit is used to enable or disable the host core to wait for 200 PHY clock cycles at the end of Resume to change the opmode signal to the PHY to 00 after Suspend or LPM."]
    #[inline(always)]
    #[must_use]
    pub fn modechtimen(&mut self) -> ModechtimenW<HostgrpHcfgSpec> {
        ModechtimenW::new(self, 31)
    }
}
#[doc = "Host Mode control. This register must be programmed every time the core changes to Host mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHcfgSpec;
impl crate::RegisterSpec for HostgrpHcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 1024u64;
}
#[doc = "`read()` method returns [`hostgrp_hcfg::R`](R) reader structure"]
impl crate::Readable for HostgrpHcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hcfg::W`](W) writer structure"]
impl crate::Writable for HostgrpHcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hcfg to value 0x0200"]
impl crate::Resettable for HostgrpHcfgSpec {
    const RESET_VALUE: u32 = 0x0200;
}
