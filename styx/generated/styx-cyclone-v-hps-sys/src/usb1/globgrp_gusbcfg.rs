// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `globgrp_gusbcfg` reader"]
pub type R = crate::R<GlobgrpGusbcfgSpec>;
#[doc = "Register `globgrp_gusbcfg` writer"]
pub type W = crate::W<GlobgrpGusbcfgSpec>;
#[doc = "Field `toutcal` reader - Mode:Host and Device. The number of PHY clocks that the application programs in this field is added to the high-speed/full-speed interpacket timeout duration in the core to account for any additional delays introduced by the PHY. This can be required, because the delay introduced by the PHY in generating the linestate condition can vary from one PHY to another. The USB standard timeout value for high-speed operation is 736 to 816 (inclusive) bit times. The USB standard timeout value for full-speed operation is 16 to 18 (inclusive) bit times. The application must program this field based on the speed of enumeration. The number of bit times added per PHY clock are: High-speed operation: -One 30-MHz PHY clock = 16 bit times -One 60-MHz PHY clock = 8 bit times Full-speed operation: -One 30-MHz PHY clock = 0.4 bit times -One 60-MHz PHY clock = 0.2 bit times -One 48-MHz PHY clock = 0.25 bit times"]
pub type ToutcalR = crate::FieldReader;
#[doc = "Field `toutcal` writer - Mode:Host and Device. The number of PHY clocks that the application programs in this field is added to the high-speed/full-speed interpacket timeout duration in the core to account for any additional delays introduced by the PHY. This can be required, because the delay introduced by the PHY in generating the linestate condition can vary from one PHY to another. The USB standard timeout value for high-speed operation is 736 to 816 (inclusive) bit times. The USB standard timeout value for full-speed operation is 16 to 18 (inclusive) bit times. The application must program this field based on the speed of enumeration. The number of bit times added per PHY clock are: High-speed operation: -One 30-MHz PHY clock = 16 bit times -One 60-MHz PHY clock = 8 bit times Full-speed operation: -One 30-MHz PHY clock = 0.4 bit times -One 60-MHz PHY clock = 0.2 bit times -One 48-MHz PHY clock = 0.25 bit times"]
pub type ToutcalW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Mode:Host and Device. This application uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phyif {
    #[doc = "0: `0`"]
    Bits8 = 0,
}
impl From<Phyif> for bool {
    #[inline(always)]
    fn from(variant: Phyif) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `phyif` reader - Mode:Host and Device. This application uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled."]
pub type PhyifR = crate::BitReader<Phyif>;
impl PhyifR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Phyif> {
        match self.bits {
            false => Some(Phyif::Bits8),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_bits8(&self) -> bool {
        *self == Phyif::Bits8
    }
}
#[doc = "Field `phyif` writer - Mode:Host and Device. This application uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled."]
pub type PhyifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. The application uses ULPI Only in 8bit mode.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UlpiUtmiSel {
    #[doc = "0: `0`"]
    Ulpi = 0,
}
impl From<UlpiUtmiSel> for bool {
    #[inline(always)]
    fn from(variant: UlpiUtmiSel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ulpi_utmi_sel` reader - Mode:Host and Device. The application uses ULPI Only in 8bit mode."]
pub type UlpiUtmiSelR = crate::BitReader<UlpiUtmiSel>;
impl UlpiUtmiSelR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<UlpiUtmiSel> {
        match self.bits {
            false => Some(UlpiUtmiSel::Ulpi),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ulpi(&self) -> bool {
        *self == UlpiUtmiSel::Ulpi
    }
}
#[doc = "Field `ulpi_utmi_sel` writer - Mode:Host and Device. The application uses ULPI Only in 8bit mode."]
pub type UlpiUtmiSelW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. The application can Set this bit to select between the 3- and 6-pin interfaces, and access is Read and Write.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fsintf {
    #[doc = "0: `0`"]
    Fs6pin = 0,
    #[doc = "1: `1`"]
    Fs3pin = 1,
}
impl From<Fsintf> for bool {
    #[inline(always)]
    fn from(variant: Fsintf) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fsintf` reader - Mode:Host and Device. The application can Set this bit to select between the 3- and 6-pin interfaces, and access is Read and Write."]
pub type FsintfR = crate::BitReader<Fsintf>;
impl FsintfR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fsintf {
        match self.bits {
            false => Fsintf::Fs6pin,
            true => Fsintf::Fs3pin,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fs6pin(&self) -> bool {
        *self == Fsintf::Fs6pin
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fs3pin(&self) -> bool {
        *self == Fsintf::Fs3pin
    }
}
#[doc = "Field `fsintf` writer - Mode:Host and Device. The application can Set this bit to select between the 3- and 6-pin interfaces, and access is Read and Write."]
pub type FsintfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. The application uses USB 2.0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Physel {
    #[doc = "0: `0`"]
    Usb20 = 0,
}
impl From<Physel> for bool {
    #[inline(always)]
    fn from(variant: Physel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `physel` reader - Mode:Host and Device. The application uses USB 2.0."]
pub type PhyselR = crate::BitReader<Physel>;
impl PhyselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Physel> {
        match self.bits {
            false => Some(Physel::Usb20),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_usb20(&self) -> bool {
        *self == Physel::Usb20
    }
}
#[doc = "Field `physel` writer - Mode:Host and Device. The application uses USB 2.0."]
pub type PhyselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Mode:Host and Device. The application uses this bit to select a Single Data Rate (SDR) or Double Data Rate (DDR) or ULPI interface.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ddrsel {
    #[doc = "0: `0`"]
    Sdr = 0,
    #[doc = "1: `1`"]
    Ddr = 1,
}
impl From<Ddrsel> for bool {
    #[inline(always)]
    fn from(variant: Ddrsel) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ddrsel` reader - Mode:Host and Device. The application uses this bit to select a Single Data Rate (SDR) or Double Data Rate (DDR) or ULPI interface."]
pub type DdrselR = crate::BitReader<Ddrsel>;
impl DdrselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ddrsel {
        match self.bits {
            false => Ddrsel::Sdr,
            true => Ddrsel::Ddr,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_sdr(&self) -> bool {
        *self == Ddrsel::Sdr
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ddr(&self) -> bool {
        *self == Ddrsel::Ddr
    }
}
#[doc = "Field `ddrsel` writer - Mode:Host and Device. The application uses this bit to select a Single Data Rate (SDR) or Double Data Rate (DDR) or ULPI interface."]
pub type DdrselW<'a, REG> = crate::BitWriter<'a, REG, Ddrsel>;
impl<'a, REG> DdrselW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn sdr(self) -> &'a mut crate::W<REG> {
        self.variant(Ddrsel::Sdr)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ddr(self) -> &'a mut crate::W<REG> {
        self.variant(Ddrsel::Ddr)
    }
}
#[doc = "Mode:Host and Device. The application uses this bit to control the otg core SRP capabilities. If the core operates as a non-SRP-capable B-device, it cannot request the connected A-device (host) to activate VBUS and start a session. This bit is writable only If an SRP mode was specified for Mode of Operation in coreConsultant (parameter OTG_MODE). Otherwise, reads Return 0.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Srpcap {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Srpcap> for bool {
    #[inline(always)]
    fn from(variant: Srpcap) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `srpcap` reader - Mode:Host and Device. The application uses this bit to control the otg core SRP capabilities. If the core operates as a non-SRP-capable B-device, it cannot request the connected A-device (host) to activate VBUS and start a session. This bit is writable only If an SRP mode was specified for Mode of Operation in coreConsultant (parameter OTG_MODE). Otherwise, reads Return 0."]
pub type SrpcapR = crate::BitReader<Srpcap>;
impl SrpcapR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Srpcap {
        match self.bits {
            false => Srpcap::Disabled,
            true => Srpcap::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Srpcap::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Srpcap::Enabled
    }
}
#[doc = "Field `srpcap` writer - Mode:Host and Device. The application uses this bit to control the otg core SRP capabilities. If the core operates as a non-SRP-capable B-device, it cannot request the connected A-device (host) to activate VBUS and start a session. This bit is writable only If an SRP mode was specified for Mode of Operation in coreConsultant (parameter OTG_MODE). Otherwise, reads Return 0."]
pub type SrpcapW<'a, REG> = crate::BitWriter<'a, REG, Srpcap>;
impl<'a, REG> SrpcapW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Srpcap::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Srpcap::Enabled)
    }
}
#[doc = "Mode:Host and Device. The application uses this bit to control the otg core's HNP capabilities.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hnpcap {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Hnpcap> for bool {
    #[inline(always)]
    fn from(variant: Hnpcap) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `hnpcap` reader - Mode:Host and Device. The application uses this bit to control the otg core's HNP capabilities."]
pub type HnpcapR = crate::BitReader<Hnpcap>;
impl HnpcapR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Hnpcap {
        match self.bits {
            false => Hnpcap::Disabled,
            true => Hnpcap::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Hnpcap::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Hnpcap::Enabled
    }
}
#[doc = "Field `hnpcap` writer - Mode:Host and Device. The application uses this bit to control the otg core's HNP capabilities."]
pub type HnpcapW<'a, REG> = crate::BitWriter<'a, REG, Hnpcap>;
impl<'a, REG> HnpcapW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hnpcap::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Hnpcap::Enabled)
    }
}
#[doc = "Mode: Device only. Sets the turnaround time in PHY clocks. Specifies the response time for a MAC request to the Packet FIFO Controller (PFC) to fetch data from the DFIFO (SPRAM). The value is calculated for the minimum AHB frequency of 30 MHz. USB turnaround time is critical for certification where long cables and 5-Hubs are used, so If you need the AHB to run at less than 30 MHz, and If USB turnaround time is not critical, these bits can be programmed to a larger value.\n\nValue on reset: 5"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Usbtrdtim {
    #[doc = "9: `1001`"]
    Turntime = 9,
}
impl From<Usbtrdtim> for u8 {
    #[inline(always)]
    fn from(variant: Usbtrdtim) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Usbtrdtim {
    type Ux = u8;
}
#[doc = "Field `usbtrdtim` reader - Mode: Device only. Sets the turnaround time in PHY clocks. Specifies the response time for a MAC request to the Packet FIFO Controller (PFC) to fetch data from the DFIFO (SPRAM). The value is calculated for the minimum AHB frequency of 30 MHz. USB turnaround time is critical for certification where long cables and 5-Hubs are used, so If you need the AHB to run at less than 30 MHz, and If USB turnaround time is not critical, these bits can be programmed to a larger value."]
pub type UsbtrdtimR = crate::FieldReader<Usbtrdtim>;
impl UsbtrdtimR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Usbtrdtim> {
        match self.bits {
            9 => Some(Usbtrdtim::Turntime),
            _ => None,
        }
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_turntime(&self) -> bool {
        *self == Usbtrdtim::Turntime
    }
}
#[doc = "Field `usbtrdtim` writer - Mode: Device only. Sets the turnaround time in PHY clocks. Specifies the response time for a MAC request to the Packet FIFO Controller (PFC) to fetch data from the DFIFO (SPRAM). The value is calculated for the minimum AHB frequency of 30 MHz. USB turnaround time is critical for certification where long cables and 5-Hubs are used, so If you need the AHB to run at less than 30 MHz, and If USB turnaround time is not critical, these bits can be programmed to a larger value."]
pub type UsbtrdtimW<'a, REG> = crate::FieldWriter<'a, REG, 4, Usbtrdtim>;
impl<'a, REG> UsbtrdtimW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn turntime(self) -> &'a mut crate::W<REG> {
        self.variant(Usbtrdtim::Turntime)
    }
}
#[doc = "Mode:Host and Device. This bit sets the AutoResume bit in the Interface Control register on the ULPI PHY.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ulpiautores {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ulpiautores> for bool {
    #[inline(always)]
    fn from(variant: Ulpiautores) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ulpiautores` reader - Mode:Host and Device. This bit sets the AutoResume bit in the Interface Control register on the ULPI PHY."]
pub type UlpiautoresR = crate::BitReader<Ulpiautores>;
impl UlpiautoresR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ulpiautores {
        match self.bits {
            false => Ulpiautores::Disabled,
            true => Ulpiautores::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ulpiautores::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ulpiautores::Enabled
    }
}
#[doc = "Field `ulpiautores` writer - Mode:Host and Device. This bit sets the AutoResume bit in the Interface Control register on the ULPI PHY."]
pub type UlpiautoresW<'a, REG> = crate::BitWriter<'a, REG, Ulpiautores>;
impl<'a, REG> UlpiautoresW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpiautores::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpiautores::Enabled)
    }
}
#[doc = "Mode:Host and Device. This bit sets the ClockSuspendM bit in the Interface Control register on the ULPI PHY. This bit applies only in serial or carkit modes.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ulpiclksusm {
    #[doc = "0: `0`"]
    Pwdclk = 0,
    #[doc = "1: `1`"]
    Nonpwdclk = 1,
}
impl From<Ulpiclksusm> for bool {
    #[inline(always)]
    fn from(variant: Ulpiclksusm) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ulpiclksusm` reader - Mode:Host and Device. This bit sets the ClockSuspendM bit in the Interface Control register on the ULPI PHY. This bit applies only in serial or carkit modes."]
pub type UlpiclksusmR = crate::BitReader<Ulpiclksusm>;
impl UlpiclksusmR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ulpiclksusm {
        match self.bits {
            false => Ulpiclksusm::Pwdclk,
            true => Ulpiclksusm::Nonpwdclk,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_pwdclk(&self) -> bool {
        *self == Ulpiclksusm::Pwdclk
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nonpwdclk(&self) -> bool {
        *self == Ulpiclksusm::Nonpwdclk
    }
}
#[doc = "Field `ulpiclksusm` writer - Mode:Host and Device. This bit sets the ClockSuspendM bit in the Interface Control register on the ULPI PHY. This bit applies only in serial or carkit modes."]
pub type UlpiclksusmW<'a, REG> = crate::BitWriter<'a, REG, Ulpiclksusm>;
impl<'a, REG> UlpiclksusmW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn pwdclk(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpiclksusm::Pwdclk)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonpwdclk(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpiclksusm::Nonpwdclk)
    }
}
#[doc = "Mode:Host only. This bit selects between internal or external supply to drive 5V on VBUS, in ULPI PHY.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ulpiextvbusdrv {
    #[doc = "0: `0`"]
    Intern = 0,
    #[doc = "1: `1`"]
    Extern = 1,
}
impl From<Ulpiextvbusdrv> for bool {
    #[inline(always)]
    fn from(variant: Ulpiextvbusdrv) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ulpiextvbusdrv` reader - Mode:Host only. This bit selects between internal or external supply to drive 5V on VBUS, in ULPI PHY."]
pub type UlpiextvbusdrvR = crate::BitReader<Ulpiextvbusdrv>;
impl UlpiextvbusdrvR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ulpiextvbusdrv {
        match self.bits {
            false => Ulpiextvbusdrv::Intern,
            true => Ulpiextvbusdrv::Extern,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_intern(&self) -> bool {
        *self == Ulpiextvbusdrv::Intern
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_extern(&self) -> bool {
        *self == Ulpiextvbusdrv::Extern
    }
}
#[doc = "Field `ulpiextvbusdrv` writer - Mode:Host only. This bit selects between internal or external supply to drive 5V on VBUS, in ULPI PHY."]
pub type UlpiextvbusdrvW<'a, REG> = crate::BitWriter<'a, REG, Ulpiextvbusdrv>;
impl<'a, REG> UlpiextvbusdrvW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn intern(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpiextvbusdrv::Intern)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn extern_(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpiextvbusdrv::Extern)
    }
}
#[doc = "Mode:Host only. This bit indicates to the ULPI PHY to use an external VBUS overcurrent indicator.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ulpiextvbusindicator {
    #[doc = "0: `0`"]
    Intern = 0,
    #[doc = "1: `1`"]
    Extern = 1,
}
impl From<Ulpiextvbusindicator> for bool {
    #[inline(always)]
    fn from(variant: Ulpiextvbusindicator) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ulpiextvbusindicator` reader - Mode:Host only. This bit indicates to the ULPI PHY to use an external VBUS overcurrent indicator."]
pub type UlpiextvbusindicatorR = crate::BitReader<Ulpiextvbusindicator>;
impl UlpiextvbusindicatorR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ulpiextvbusindicator {
        match self.bits {
            false => Ulpiextvbusindicator::Intern,
            true => Ulpiextvbusindicator::Extern,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_intern(&self) -> bool {
        *self == Ulpiextvbusindicator::Intern
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_extern(&self) -> bool {
        *self == Ulpiextvbusindicator::Extern
    }
}
#[doc = "Field `ulpiextvbusindicator` writer - Mode:Host only. This bit indicates to the ULPI PHY to use an external VBUS overcurrent indicator."]
pub type UlpiextvbusindicatorW<'a, REG> = crate::BitWriter<'a, REG, Ulpiextvbusindicator>;
impl<'a, REG> UlpiextvbusindicatorW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn intern(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpiextvbusindicator::Intern)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn extern_(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpiextvbusindicator::Extern)
    }
}
#[doc = "Mode:Device only. This bit selects utmi_termselect to drive data line pulse during SRP.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Termseldlpulse {
    #[doc = "0: `0`"]
    Txvalid = 0,
    #[doc = "1: `1`"]
    Termsel = 1,
}
impl From<Termseldlpulse> for bool {
    #[inline(always)]
    fn from(variant: Termseldlpulse) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `termseldlpulse` reader - Mode:Device only. This bit selects utmi_termselect to drive data line pulse during SRP."]
pub type TermseldlpulseR = crate::BitReader<Termseldlpulse>;
impl TermseldlpulseR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Termseldlpulse {
        match self.bits {
            false => Termseldlpulse::Txvalid,
            true => Termseldlpulse::Termsel,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_txvalid(&self) -> bool {
        *self == Termseldlpulse::Txvalid
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_termsel(&self) -> bool {
        *self == Termseldlpulse::Termsel
    }
}
#[doc = "Field `termseldlpulse` writer - Mode:Device only. This bit selects utmi_termselect to drive data line pulse during SRP."]
pub type TermseldlpulseW<'a, REG> = crate::BitWriter<'a, REG, Termseldlpulse>;
impl<'a, REG> TermseldlpulseW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn txvalid(self) -> &'a mut crate::W<REG> {
        self.variant(Termseldlpulse::Txvalid)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn termsel(self) -> &'a mut crate::W<REG> {
        self.variant(Termseldlpulse::Termsel)
    }
}
#[doc = "Mode:Host only. Controls the PHY to invert the ExternalVbusIndicator inputsignal, generating the ComplementOutput. Please refer to the ULPI Spec for more detail.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Complement {
    #[doc = "0: `0`"]
    Noninvert = 0,
    #[doc = "1: `1`"]
    Invert = 1,
}
impl From<Complement> for bool {
    #[inline(always)]
    fn from(variant: Complement) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `complement` reader - Mode:Host only. Controls the PHY to invert the ExternalVbusIndicator inputsignal, generating the ComplementOutput. Please refer to the ULPI Spec for more detail."]
pub type ComplementR = crate::BitReader<Complement>;
impl ComplementR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Complement {
        match self.bits {
            false => Complement::Noninvert,
            true => Complement::Invert,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noninvert(&self) -> bool {
        *self == Complement::Noninvert
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_invert(&self) -> bool {
        *self == Complement::Invert
    }
}
#[doc = "Field `complement` writer - Mode:Host only. Controls the PHY to invert the ExternalVbusIndicator inputsignal, generating the ComplementOutput. Please refer to the ULPI Spec for more detail."]
pub type ComplementW<'a, REG> = crate::BitWriter<'a, REG, Complement>;
impl<'a, REG> ComplementW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noninvert(self) -> &'a mut crate::W<REG> {
        self.variant(Complement::Noninvert)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn invert(self) -> &'a mut crate::W<REG> {
        self.variant(Complement::Invert)
    }
}
#[doc = "Mode:Host only. Controls wether the Complement Output is qualified with the Internal Vbus Valid comparator before being used in the Vbus State in the RX CMD.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indicator {
    #[doc = "0: `0`"]
    Qualified = 0,
    #[doc = "1: `1`"]
    Nonqualified = 1,
}
impl From<Indicator> for bool {
    #[inline(always)]
    fn from(variant: Indicator) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indicator` reader - Mode:Host only. Controls wether the Complement Output is qualified with the Internal Vbus Valid comparator before being used in the Vbus State in the RX CMD."]
pub type IndicatorR = crate::BitReader<Indicator>;
impl IndicatorR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indicator {
        match self.bits {
            false => Indicator::Qualified,
            true => Indicator::Nonqualified,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_qualified(&self) -> bool {
        *self == Indicator::Qualified
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_nonqualified(&self) -> bool {
        *self == Indicator::Nonqualified
    }
}
#[doc = "Field `indicator` writer - Mode:Host only. Controls wether the Complement Output is qualified with the Internal Vbus Valid comparator before being used in the Vbus State in the RX CMD."]
pub type IndicatorW<'a, REG> = crate::BitWriter<'a, REG, Indicator>;
impl<'a, REG> IndicatorW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn qualified(self) -> &'a mut crate::W<REG> {
        self.variant(Indicator::Qualified)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn nonqualified(self) -> &'a mut crate::W<REG> {
        self.variant(Indicator::Nonqualified)
    }
}
#[doc = "Mode:Host only. Controls circuitry built into the PHY for protecting the ULPI interface when the link tri-states STP and data. Any pull-ups or pull-downs employed by this feature can be disabled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ulpi {
    #[doc = "0: `0`"]
    Enabled = 0,
    #[doc = "1: `1`"]
    Disabled = 1,
}
impl From<Ulpi> for bool {
    #[inline(always)]
    fn from(variant: Ulpi) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ulpi` reader - Mode:Host only. Controls circuitry built into the PHY for protecting the ULPI interface when the link tri-states STP and data. Any pull-ups or pull-downs employed by this feature can be disabled."]
pub type UlpiR = crate::BitReader<Ulpi>;
impl UlpiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ulpi {
        match self.bits {
            false => Ulpi::Enabled,
            true => Ulpi::Disabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ulpi::Enabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ulpi::Disabled
    }
}
#[doc = "Field `ulpi` writer - Mode:Host only. Controls circuitry built into the PHY for protecting the ULPI interface when the link tri-states STP and data. Any pull-ups or pull-downs employed by this feature can be disabled."]
pub type UlpiW<'a, REG> = crate::BitWriter<'a, REG, Ulpi>;
impl<'a, REG> UlpiW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpi::Enabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ulpi::Disabled)
    }
}
#[doc = "Mode: Device only. Set to non UTMI+.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txenddelay {
    #[doc = "0: `0`"]
    Disabled = 0,
}
impl From<Txenddelay> for bool {
    #[inline(always)]
    fn from(variant: Txenddelay) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txenddelay` reader - Mode: Device only. Set to non UTMI+."]
pub type TxenddelayR = crate::BitReader<Txenddelay>;
impl TxenddelayR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Txenddelay> {
        match self.bits {
            false => Some(Txenddelay::Disabled),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Txenddelay::Disabled
    }
}
#[doc = "Field `txenddelay` writer - Mode: Device only. Set to non UTMI+."]
pub type TxenddelayW<'a, REG> = crate::BitWriter<'a, REG, Txenddelay>;
impl<'a, REG> TxenddelayW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Txenddelay::Disabled)
    }
}
#[doc = "Mode:Host and device. Writing a 1 to this bit forces the core to host mode After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forcehstmode {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Forcehstmode> for bool {
    #[inline(always)]
    fn from(variant: Forcehstmode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `forcehstmode` reader - Mode:Host and device. Writing a 1 to this bit forces the core to host mode After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient."]
pub type ForcehstmodeR = crate::BitReader<Forcehstmode>;
impl ForcehstmodeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Forcehstmode {
        match self.bits {
            false => Forcehstmode::Disabled,
            true => Forcehstmode::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Forcehstmode::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Forcehstmode::Enabled
    }
}
#[doc = "Field `forcehstmode` writer - Mode:Host and device. Writing a 1 to this bit forces the core to host mode After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient."]
pub type ForcehstmodeW<'a, REG> = crate::BitWriter<'a, REG, Forcehstmode>;
impl<'a, REG> ForcehstmodeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Forcehstmode::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Forcehstmode::Enabled)
    }
}
#[doc = "Mode:Host and device. Writing a 1 to this bit forces the core to device mode. After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forcedevmode {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Forcedevmode> for bool {
    #[inline(always)]
    fn from(variant: Forcedevmode) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `forcedevmode` reader - Mode:Host and device. Writing a 1 to this bit forces the core to device mode. After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient."]
pub type ForcedevmodeR = crate::BitReader<Forcedevmode>;
impl ForcedevmodeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Forcedevmode {
        match self.bits {
            false => Forcedevmode::Disabled,
            true => Forcedevmode::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Forcedevmode::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Forcedevmode::Enabled
    }
}
#[doc = "Field `forcedevmode` writer - Mode:Host and device. Writing a 1 to this bit forces the core to device mode. After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient."]
pub type ForcedevmodeW<'a, REG> = crate::BitWriter<'a, REG, Forcedevmode>;
impl<'a, REG> ForcedevmodeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Forcedevmode::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Forcedevmode::Enabled)
    }
}
#[doc = "Field `corrupttxpkt` reader - Mode: Host and device. This bit is for debug purposes only. Never Set this bit to 1. The application should always write 0 to this bit."]
pub type CorrupttxpktR = crate::BitReader;
#[doc = "Mode: Host and device. This bit is for debug purposes only. Never Set this bit to 1. The application should always write 0 to this bit.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Corrupttxpkt {
    #[doc = "0: `0`"]
    Nodebug = 0,
    #[doc = "1: `1`"]
    Debug = 1,
}
impl From<Corrupttxpkt> for bool {
    #[inline(always)]
    fn from(variant: Corrupttxpkt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `corrupttxpkt` writer - Mode: Host and device. This bit is for debug purposes only. Never Set this bit to 1. The application should always write 0 to this bit."]
pub type CorrupttxpktW<'a, REG> = crate::BitWriter<'a, REG, Corrupttxpkt>;
impl<'a, REG> CorrupttxpktW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nodebug(self) -> &'a mut crate::W<REG> {
        self.variant(Corrupttxpkt::Nodebug)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn debug(self) -> &'a mut crate::W<REG> {
        self.variant(Corrupttxpkt::Debug)
    }
}
impl R {
    #[doc = "Bits 0:2 - Mode:Host and Device. The number of PHY clocks that the application programs in this field is added to the high-speed/full-speed interpacket timeout duration in the core to account for any additional delays introduced by the PHY. This can be required, because the delay introduced by the PHY in generating the linestate condition can vary from one PHY to another. The USB standard timeout value for high-speed operation is 736 to 816 (inclusive) bit times. The USB standard timeout value for full-speed operation is 16 to 18 (inclusive) bit times. The application must program this field based on the speed of enumeration. The number of bit times added per PHY clock are: High-speed operation: -One 30-MHz PHY clock = 16 bit times -One 60-MHz PHY clock = 8 bit times Full-speed operation: -One 30-MHz PHY clock = 0.4 bit times -One 60-MHz PHY clock = 0.2 bit times -One 48-MHz PHY clock = 0.25 bit times"]
    #[inline(always)]
    pub fn toutcal(&self) -> ToutcalR {
        ToutcalR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 3 - Mode:Host and Device. This application uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled."]
    #[inline(always)]
    pub fn phyif(&self) -> PhyifR {
        PhyifR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Mode:Host and Device. The application uses ULPI Only in 8bit mode."]
    #[inline(always)]
    pub fn ulpi_utmi_sel(&self) -> UlpiUtmiSelR {
        UlpiUtmiSelR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Mode:Host and Device. The application can Set this bit to select between the 3- and 6-pin interfaces, and access is Read and Write."]
    #[inline(always)]
    pub fn fsintf(&self) -> FsintfR {
        FsintfR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Mode:Host and Device. The application uses USB 2.0."]
    #[inline(always)]
    pub fn physel(&self) -> PhyselR {
        PhyselR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Mode:Host and Device. The application uses this bit to select a Single Data Rate (SDR) or Double Data Rate (DDR) or ULPI interface."]
    #[inline(always)]
    pub fn ddrsel(&self) -> DdrselR {
        DdrselR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Mode:Host and Device. The application uses this bit to control the otg core SRP capabilities. If the core operates as a non-SRP-capable B-device, it cannot request the connected A-device (host) to activate VBUS and start a session. This bit is writable only If an SRP mode was specified for Mode of Operation in coreConsultant (parameter OTG_MODE). Otherwise, reads Return 0."]
    #[inline(always)]
    pub fn srpcap(&self) -> SrpcapR {
        SrpcapR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Mode:Host and Device. The application uses this bit to control the otg core's HNP capabilities."]
    #[inline(always)]
    pub fn hnpcap(&self) -> HnpcapR {
        HnpcapR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bits 10:13 - Mode: Device only. Sets the turnaround time in PHY clocks. Specifies the response time for a MAC request to the Packet FIFO Controller (PFC) to fetch data from the DFIFO (SPRAM). The value is calculated for the minimum AHB frequency of 30 MHz. USB turnaround time is critical for certification where long cables and 5-Hubs are used, so If you need the AHB to run at less than 30 MHz, and If USB turnaround time is not critical, these bits can be programmed to a larger value."]
    #[inline(always)]
    pub fn usbtrdtim(&self) -> UsbtrdtimR {
        UsbtrdtimR::new(((self.bits >> 10) & 0x0f) as u8)
    }
    #[doc = "Bit 18 - Mode:Host and Device. This bit sets the AutoResume bit in the Interface Control register on the ULPI PHY."]
    #[inline(always)]
    pub fn ulpiautores(&self) -> UlpiautoresR {
        UlpiautoresR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Mode:Host and Device. This bit sets the ClockSuspendM bit in the Interface Control register on the ULPI PHY. This bit applies only in serial or carkit modes."]
    #[inline(always)]
    pub fn ulpiclksusm(&self) -> UlpiclksusmR {
        UlpiclksusmR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Mode:Host only. This bit selects between internal or external supply to drive 5V on VBUS, in ULPI PHY."]
    #[inline(always)]
    pub fn ulpiextvbusdrv(&self) -> UlpiextvbusdrvR {
        UlpiextvbusdrvR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Mode:Host only. This bit indicates to the ULPI PHY to use an external VBUS overcurrent indicator."]
    #[inline(always)]
    pub fn ulpiextvbusindicator(&self) -> UlpiextvbusindicatorR {
        UlpiextvbusindicatorR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Mode:Device only. This bit selects utmi_termselect to drive data line pulse during SRP."]
    #[inline(always)]
    pub fn termseldlpulse(&self) -> TermseldlpulseR {
        TermseldlpulseR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Mode:Host only. Controls the PHY to invert the ExternalVbusIndicator inputsignal, generating the ComplementOutput. Please refer to the ULPI Spec for more detail."]
    #[inline(always)]
    pub fn complement(&self) -> ComplementR {
        ComplementR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Mode:Host only. Controls wether the Complement Output is qualified with the Internal Vbus Valid comparator before being used in the Vbus State in the RX CMD."]
    #[inline(always)]
    pub fn indicator(&self) -> IndicatorR {
        IndicatorR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Mode:Host only. Controls circuitry built into the PHY for protecting the ULPI interface when the link tri-states STP and data. Any pull-ups or pull-downs employed by this feature can be disabled."]
    #[inline(always)]
    pub fn ulpi(&self) -> UlpiR {
        UlpiR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 28 - Mode: Device only. Set to non UTMI+."]
    #[inline(always)]
    pub fn txenddelay(&self) -> TxenddelayR {
        TxenddelayR::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Mode:Host and device. Writing a 1 to this bit forces the core to host mode After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient."]
    #[inline(always)]
    pub fn forcehstmode(&self) -> ForcehstmodeR {
        ForcehstmodeR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Mode:Host and device. Writing a 1 to this bit forces the core to device mode. After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient."]
    #[inline(always)]
    pub fn forcedevmode(&self) -> ForcedevmodeR {
        ForcedevmodeR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Mode: Host and device. This bit is for debug purposes only. Never Set this bit to 1. The application should always write 0 to this bit."]
    #[inline(always)]
    pub fn corrupttxpkt(&self) -> CorrupttxpktR {
        CorrupttxpktR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - Mode:Host and Device. The number of PHY clocks that the application programs in this field is added to the high-speed/full-speed interpacket timeout duration in the core to account for any additional delays introduced by the PHY. This can be required, because the delay introduced by the PHY in generating the linestate condition can vary from one PHY to another. The USB standard timeout value for high-speed operation is 736 to 816 (inclusive) bit times. The USB standard timeout value for full-speed operation is 16 to 18 (inclusive) bit times. The application must program this field based on the speed of enumeration. The number of bit times added per PHY clock are: High-speed operation: -One 30-MHz PHY clock = 16 bit times -One 60-MHz PHY clock = 8 bit times Full-speed operation: -One 30-MHz PHY clock = 0.4 bit times -One 60-MHz PHY clock = 0.2 bit times -One 48-MHz PHY clock = 0.25 bit times"]
    #[inline(always)]
    #[must_use]
    pub fn toutcal(&mut self) -> ToutcalW<GlobgrpGusbcfgSpec> {
        ToutcalW::new(self, 0)
    }
    #[doc = "Bit 3 - Mode:Host and Device. This application uses a ULPI interface only. Hence only 8-bit setting is relevant. This setting should not matter since UTMI is not enabled."]
    #[inline(always)]
    #[must_use]
    pub fn phyif(&mut self) -> PhyifW<GlobgrpGusbcfgSpec> {
        PhyifW::new(self, 3)
    }
    #[doc = "Bit 4 - Mode:Host and Device. The application uses ULPI Only in 8bit mode."]
    #[inline(always)]
    #[must_use]
    pub fn ulpi_utmi_sel(&mut self) -> UlpiUtmiSelW<GlobgrpGusbcfgSpec> {
        UlpiUtmiSelW::new(self, 4)
    }
    #[doc = "Bit 5 - Mode:Host and Device. The application can Set this bit to select between the 3- and 6-pin interfaces, and access is Read and Write."]
    #[inline(always)]
    #[must_use]
    pub fn fsintf(&mut self) -> FsintfW<GlobgrpGusbcfgSpec> {
        FsintfW::new(self, 5)
    }
    #[doc = "Bit 6 - Mode:Host and Device. The application uses USB 2.0."]
    #[inline(always)]
    #[must_use]
    pub fn physel(&mut self) -> PhyselW<GlobgrpGusbcfgSpec> {
        PhyselW::new(self, 6)
    }
    #[doc = "Bit 7 - Mode:Host and Device. The application uses this bit to select a Single Data Rate (SDR) or Double Data Rate (DDR) or ULPI interface."]
    #[inline(always)]
    #[must_use]
    pub fn ddrsel(&mut self) -> DdrselW<GlobgrpGusbcfgSpec> {
        DdrselW::new(self, 7)
    }
    #[doc = "Bit 8 - Mode:Host and Device. The application uses this bit to control the otg core SRP capabilities. If the core operates as a non-SRP-capable B-device, it cannot request the connected A-device (host) to activate VBUS and start a session. This bit is writable only If an SRP mode was specified for Mode of Operation in coreConsultant (parameter OTG_MODE). Otherwise, reads Return 0."]
    #[inline(always)]
    #[must_use]
    pub fn srpcap(&mut self) -> SrpcapW<GlobgrpGusbcfgSpec> {
        SrpcapW::new(self, 8)
    }
    #[doc = "Bit 9 - Mode:Host and Device. The application uses this bit to control the otg core's HNP capabilities."]
    #[inline(always)]
    #[must_use]
    pub fn hnpcap(&mut self) -> HnpcapW<GlobgrpGusbcfgSpec> {
        HnpcapW::new(self, 9)
    }
    #[doc = "Bits 10:13 - Mode: Device only. Sets the turnaround time in PHY clocks. Specifies the response time for a MAC request to the Packet FIFO Controller (PFC) to fetch data from the DFIFO (SPRAM). The value is calculated for the minimum AHB frequency of 30 MHz. USB turnaround time is critical for certification where long cables and 5-Hubs are used, so If you need the AHB to run at less than 30 MHz, and If USB turnaround time is not critical, these bits can be programmed to a larger value."]
    #[inline(always)]
    #[must_use]
    pub fn usbtrdtim(&mut self) -> UsbtrdtimW<GlobgrpGusbcfgSpec> {
        UsbtrdtimW::new(self, 10)
    }
    #[doc = "Bit 18 - Mode:Host and Device. This bit sets the AutoResume bit in the Interface Control register on the ULPI PHY."]
    #[inline(always)]
    #[must_use]
    pub fn ulpiautores(&mut self) -> UlpiautoresW<GlobgrpGusbcfgSpec> {
        UlpiautoresW::new(self, 18)
    }
    #[doc = "Bit 19 - Mode:Host and Device. This bit sets the ClockSuspendM bit in the Interface Control register on the ULPI PHY. This bit applies only in serial or carkit modes."]
    #[inline(always)]
    #[must_use]
    pub fn ulpiclksusm(&mut self) -> UlpiclksusmW<GlobgrpGusbcfgSpec> {
        UlpiclksusmW::new(self, 19)
    }
    #[doc = "Bit 20 - Mode:Host only. This bit selects between internal or external supply to drive 5V on VBUS, in ULPI PHY."]
    #[inline(always)]
    #[must_use]
    pub fn ulpiextvbusdrv(&mut self) -> UlpiextvbusdrvW<GlobgrpGusbcfgSpec> {
        UlpiextvbusdrvW::new(self, 20)
    }
    #[doc = "Bit 21 - Mode:Host only. This bit indicates to the ULPI PHY to use an external VBUS overcurrent indicator."]
    #[inline(always)]
    #[must_use]
    pub fn ulpiextvbusindicator(&mut self) -> UlpiextvbusindicatorW<GlobgrpGusbcfgSpec> {
        UlpiextvbusindicatorW::new(self, 21)
    }
    #[doc = "Bit 22 - Mode:Device only. This bit selects utmi_termselect to drive data line pulse during SRP."]
    #[inline(always)]
    #[must_use]
    pub fn termseldlpulse(&mut self) -> TermseldlpulseW<GlobgrpGusbcfgSpec> {
        TermseldlpulseW::new(self, 22)
    }
    #[doc = "Bit 23 - Mode:Host only. Controls the PHY to invert the ExternalVbusIndicator inputsignal, generating the ComplementOutput. Please refer to the ULPI Spec for more detail."]
    #[inline(always)]
    #[must_use]
    pub fn complement(&mut self) -> ComplementW<GlobgrpGusbcfgSpec> {
        ComplementW::new(self, 23)
    }
    #[doc = "Bit 24 - Mode:Host only. Controls wether the Complement Output is qualified with the Internal Vbus Valid comparator before being used in the Vbus State in the RX CMD."]
    #[inline(always)]
    #[must_use]
    pub fn indicator(&mut self) -> IndicatorW<GlobgrpGusbcfgSpec> {
        IndicatorW::new(self, 24)
    }
    #[doc = "Bit 25 - Mode:Host only. Controls circuitry built into the PHY for protecting the ULPI interface when the link tri-states STP and data. Any pull-ups or pull-downs employed by this feature can be disabled."]
    #[inline(always)]
    #[must_use]
    pub fn ulpi(&mut self) -> UlpiW<GlobgrpGusbcfgSpec> {
        UlpiW::new(self, 25)
    }
    #[doc = "Bit 28 - Mode: Device only. Set to non UTMI+."]
    #[inline(always)]
    #[must_use]
    pub fn txenddelay(&mut self) -> TxenddelayW<GlobgrpGusbcfgSpec> {
        TxenddelayW::new(self, 28)
    }
    #[doc = "Bit 29 - Mode:Host and device. Writing a 1 to this bit forces the core to host mode After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient."]
    #[inline(always)]
    #[must_use]
    pub fn forcehstmode(&mut self) -> ForcehstmodeW<GlobgrpGusbcfgSpec> {
        ForcehstmodeW::new(self, 29)
    }
    #[doc = "Bit 30 - Mode:Host and device. Writing a 1 to this bit forces the core to device mode. After setting the force bit, the application must wait at least 25 ms before the change to take effect. When the simulation is in scale down mode, waiting for 500 micro-sec is sufficient."]
    #[inline(always)]
    #[must_use]
    pub fn forcedevmode(&mut self) -> ForcedevmodeW<GlobgrpGusbcfgSpec> {
        ForcedevmodeW::new(self, 30)
    }
    #[doc = "Bit 31 - Mode: Host and device. This bit is for debug purposes only. Never Set this bit to 1. The application should always write 0 to this bit."]
    #[inline(always)]
    #[must_use]
    pub fn corrupttxpkt(&mut self) -> CorrupttxpktW<GlobgrpGusbcfgSpec> {
        CorrupttxpktW::new(self, 31)
    }
}
#[doc = "This register can be used to configure the core after power-on or a changing to Host mode or Device mode. It contains USB and USB-PHY related configuration parameters. The application must program this register before starting any transactions on either the AHB or the USB. Do not make changes to this register after the initial programming.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gusbcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gusbcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGusbcfgSpec;
impl crate::RegisterSpec for GlobgrpGusbcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`globgrp_gusbcfg::R`](R) reader structure"]
impl crate::Readable for GlobgrpGusbcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`globgrp_gusbcfg::W`](W) writer structure"]
impl crate::Writable for GlobgrpGusbcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets globgrp_gusbcfg to value 0x1410"]
impl crate::Resettable for GlobgrpGusbcfgSpec {
    const RESET_VALUE: u32 = 0x1410;
}
