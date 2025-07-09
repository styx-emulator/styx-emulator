// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `cfg` reader"]
pub type R = crate::R<CfgSpec>;
#[doc = "Register `cfg` writer"]
pub type W = crate::W<CfgSpec>;
#[doc = "If this bit is disabled, the QSPI will finish the current transfer of the data word (FF_W) and stop sending. When Enabled, and qspi_n_mo_en = 0, all output enables are inactive and all pins are set to input mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum En {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<En> for bool {
    #[inline(always)]
    fn from(variant: En) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `en` reader - If this bit is disabled, the QSPI will finish the current transfer of the data word (FF_W) and stop sending. When Enabled, and qspi_n_mo_en = 0, all output enables are inactive and all pins are set to input mode."]
pub type EnR = crate::BitReader<En>;
impl EnR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> En {
        match self.bits {
            false => En::Disable,
            true => En::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == En::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == En::Enable
    }
}
#[doc = "Field `en` writer - If this bit is disabled, the QSPI will finish the current transfer of the data word (FF_W) and stop sending. When Enabled, and qspi_n_mo_en = 0, all output enables are inactive and all pins are set to input mode."]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG, En>;
impl<'a, REG> EnW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(En::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(En::Enable)
    }
}
#[doc = "Controls spiclk modes of operation.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selclkpol {
    #[doc = "1: `1`"]
    Low = 1,
    #[doc = "0: `0`"]
    High = 0,
}
impl From<Selclkpol> for bool {
    #[inline(always)]
    fn from(variant: Selclkpol) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `selclkpol` reader - Controls spiclk modes of operation."]
pub type SelclkpolR = crate::BitReader<Selclkpol>;
impl SelclkpolR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Selclkpol {
        match self.bits {
            true => Selclkpol::Low,
            false => Selclkpol::High,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_low(&self) -> bool {
        *self == Selclkpol::Low
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_high(&self) -> bool {
        *self == Selclkpol::High
    }
}
#[doc = "Field `selclkpol` writer - Controls spiclk modes of operation."]
pub type SelclkpolW<'a, REG> = crate::BitWriter<'a, REG, Selclkpol>;
impl<'a, REG> SelclkpolW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn low(self) -> &'a mut crate::W<REG> {
        self.variant(Selclkpol::Low)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn high(self) -> &'a mut crate::W<REG> {
        self.variant(Selclkpol::High)
    }
}
#[doc = "Selects whether the clock is in an active or inactive phase outside the SPI word.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selclkphase {
    #[doc = "0: `0`"]
    Active = 0,
    #[doc = "1: `1`"]
    Inactive = 1,
}
impl From<Selclkphase> for bool {
    #[inline(always)]
    fn from(variant: Selclkphase) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `selclkphase` reader - Selects whether the clock is in an active or inactive phase outside the SPI word."]
pub type SelclkphaseR = crate::BitReader<Selclkphase>;
impl SelclkphaseR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Selclkphase {
        match self.bits {
            false => Selclkphase::Active,
            true => Selclkphase::Inactive,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Selclkphase::Active
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Selclkphase::Inactive
    }
}
#[doc = "Field `selclkphase` writer - Selects whether the clock is in an active or inactive phase outside the SPI word."]
pub type SelclkphaseW<'a, REG> = crate::BitWriter<'a, REG, Selclkphase>;
impl<'a, REG> SelclkphaseW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn active(self) -> &'a mut crate::W<REG> {
        self.variant(Selclkphase::Active)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn inactive(self) -> &'a mut crate::W<REG> {
        self.variant(Selclkphase::Inactive)
    }
}
#[doc = "If disabled, the Direct Access Controller becomes inactive once the current transfer of the data word (FF_W) is complete. When the Direct Access Controller and Indirect Access Controller are both disabled, all AHB requests are completed with an error response.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endiracc {
    #[doc = "0: `0`"]
    Disable = 0,
    #[doc = "1: `1`"]
    Enable = 1,
}
impl From<Endiracc> for bool {
    #[inline(always)]
    fn from(variant: Endiracc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `endiracc` reader - If disabled, the Direct Access Controller becomes inactive once the current transfer of the data word (FF_W) is complete. When the Direct Access Controller and Indirect Access Controller are both disabled, all AHB requests are completed with an error response."]
pub type EndiraccR = crate::BitReader<Endiracc>;
impl EndiraccR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Endiracc {
        match self.bits {
            false => Endiracc::Disable,
            true => Endiracc::Enable,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Endiracc::Disable
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Endiracc::Enable
    }
}
#[doc = "Field `endiracc` writer - If disabled, the Direct Access Controller becomes inactive once the current transfer of the data word (FF_W) is complete. When the Direct Access Controller and Indirect Access Controller are both disabled, all AHB requests are completed with an error response."]
pub type EndiraccW<'a, REG> = crate::BitWriter<'a, REG, Endiracc>;
impl<'a, REG> EndiraccW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Endiracc::Disable)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Endiracc::Enable)
    }
}
#[doc = "This bit can select the Direct Access Controller/Indirect Access Controller or legacy mode.If legacy mode is selected, any write to the controller via the AHB interface is serialized and sent to the FLASH device. Any valid AHB read will pop the internal RX-FIFO, retrieving data that was forwarded by the external FLASH device on the SPI lines, byte transfers of 4, 2 or 1 are permitted and controlled via the HSIZE input.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enlegacyip {
    #[doc = "1: `1`"]
    Legmode = 1,
    #[doc = "0: `0`"]
    Dimode = 0,
}
impl From<Enlegacyip> for bool {
    #[inline(always)]
    fn from(variant: Enlegacyip) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enlegacyip` reader - This bit can select the Direct Access Controller/Indirect Access Controller or legacy mode.If legacy mode is selected, any write to the controller via the AHB interface is serialized and sent to the FLASH device. Any valid AHB read will pop the internal RX-FIFO, retrieving data that was forwarded by the external FLASH device on the SPI lines, byte transfers of 4, 2 or 1 are permitted and controlled via the HSIZE input."]
pub type EnlegacyipR = crate::BitReader<Enlegacyip>;
impl EnlegacyipR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enlegacyip {
        match self.bits {
            true => Enlegacyip::Legmode,
            false => Enlegacyip::Dimode,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_legmode(&self) -> bool {
        *self == Enlegacyip::Legmode
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_dimode(&self) -> bool {
        *self == Enlegacyip::Dimode
    }
}
#[doc = "Field `enlegacyip` writer - This bit can select the Direct Access Controller/Indirect Access Controller or legacy mode.If legacy mode is selected, any write to the controller via the AHB interface is serialized and sent to the FLASH device. Any valid AHB read will pop the internal RX-FIFO, retrieving data that was forwarded by the external FLASH device on the SPI lines, byte transfers of 4, 2 or 1 are permitted and controlled via the HSIZE input."]
pub type EnlegacyipW<'a, REG> = crate::BitWriter<'a, REG, Enlegacyip>;
impl<'a, REG> EnlegacyipW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn legmode(self) -> &'a mut crate::W<REG> {
        self.variant(Enlegacyip::Legmode)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn dimode(self) -> &'a mut crate::W<REG> {
        self.variant(Enlegacyip::Dimode)
    }
}
#[doc = "Select between '1 of 4 selects' or 'external 4-to-16 decode'. The qspi_n_ss_out\\[3:0\\]
output signals are controlled.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perseldec {
    #[doc = "1: `1`"]
    Sel4to16 = 1,
    #[doc = "0: `0`"]
    Sel1of4 = 0,
}
impl From<Perseldec> for bool {
    #[inline(always)]
    fn from(variant: Perseldec) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `perseldec` reader - Select between '1 of 4 selects' or 'external 4-to-16 decode'. The qspi_n_ss_out\\[3:0\\]
output signals are controlled."]
pub type PerseldecR = crate::BitReader<Perseldec>;
impl PerseldecR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Perseldec {
        match self.bits {
            true => Perseldec::Sel4to16,
            false => Perseldec::Sel1of4,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_sel4to16(&self) -> bool {
        *self == Perseldec::Sel4to16
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_sel1of4(&self) -> bool {
        *self == Perseldec::Sel1of4
    }
}
#[doc = "Field `perseldec` writer - Select between '1 of 4 selects' or 'external 4-to-16 decode'. The qspi_n_ss_out\\[3:0\\]
output signals are controlled."]
pub type PerseldecW<'a, REG> = crate::BitWriter<'a, REG, Perseldec>;
impl<'a, REG> PerseldecW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn sel4to16(self) -> &'a mut crate::W<REG> {
        self.variant(Perseldec::Sel4to16)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn sel1of4(self) -> &'a mut crate::W<REG> {
        self.variant(Perseldec::Sel1of4)
    }
}
#[doc = "Field `percslines` reader - Peripheral chip select line output decode type. As per perseldec, if perseldec = 0, the decode is select 1 of 4 decoding on signals, qspi_n_ss_out\\[3:0\\], The asserted decode line goes to 0. If perseldec = 1, the signals qspi_n_ss_out\\[3:0\\]
require an external 4 to 16 decoder."]
pub type PercslinesR = crate::FieldReader;
#[doc = "Field `percslines` writer - Peripheral chip select line output decode type. As per perseldec, if perseldec = 0, the decode is select 1 of 4 decoding on signals, qspi_n_ss_out\\[3:0\\], The asserted decode line goes to 0. If perseldec = 1, the signals qspi_n_ss_out\\[3:0\\]
require an external 4 to 16 decoder."]
pub type PercslinesW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "This bit controls the write protect pin of the flash devices. The signal qspi_mo2_wpn needs to be resynchronized to the generated memory clock as necessary.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wp {
    #[doc = "1: `1`"]
    Wrproton = 1,
    #[doc = "0: `0`"]
    Wrtprotoff = 0,
}
impl From<Wp> for bool {
    #[inline(always)]
    fn from(variant: Wp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `wp` reader - This bit controls the write protect pin of the flash devices. The signal qspi_mo2_wpn needs to be resynchronized to the generated memory clock as necessary."]
pub type WpR = crate::BitReader<Wp>;
impl WpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Wp {
        match self.bits {
            true => Wp::Wrproton,
            false => Wp::Wrtprotoff,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_wrproton(&self) -> bool {
        *self == Wp::Wrproton
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_wrtprotoff(&self) -> bool {
        *self == Wp::Wrtprotoff
    }
}
#[doc = "Field `wp` writer - This bit controls the write protect pin of the flash devices. The signal qspi_mo2_wpn needs to be resynchronized to the generated memory clock as necessary."]
pub type WpW<'a, REG> = crate::BitWriter<'a, REG, Wp>;
impl<'a, REG> WpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn wrproton(self) -> &'a mut crate::W<REG> {
        self.variant(Wp::Wrproton)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn wrtprotoff(self) -> &'a mut crate::W<REG> {
        self.variant(Wp::Wrtprotoff)
    }
}
#[doc = "Allows DMA handshaking mode. When enabled the QSPI will trigger DMA transfer requests via the DMA peripheral interface.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endma {
    #[doc = "1: `1`"]
    Enable = 1,
    #[doc = "0: `0`"]
    Disable = 0,
}
impl From<Endma> for bool {
    #[inline(always)]
    fn from(variant: Endma) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `endma` reader - Allows DMA handshaking mode. When enabled the QSPI will trigger DMA transfer requests via the DMA peripheral interface."]
pub type EndmaR = crate::BitReader<Endma>;
impl EndmaR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Endma {
        match self.bits {
            true => Endma::Enable,
            false => Endma::Disable,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Endma::Enable
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Endma::Disable
    }
}
#[doc = "Field `endma` writer - Allows DMA handshaking mode. When enabled the QSPI will trigger DMA transfer requests via the DMA peripheral interface."]
pub type EndmaW<'a, REG> = crate::BitWriter<'a, REG, Endma>;
impl<'a, REG> EndmaW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Endma::Enable)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Endma::Disable)
    }
}
#[doc = "(Direct Access Mode Only) When enabled, the incoming AHB address will be adapted and sent to the FLASH device as (address + N), where N is the value stored in the remap address register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enahbremap {
    #[doc = "1: `1`"]
    Enable = 1,
    #[doc = "0: `0`"]
    Disable = 0,
}
impl From<Enahbremap> for bool {
    #[inline(always)]
    fn from(variant: Enahbremap) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enahbremap` reader - (Direct Access Mode Only) When enabled, the incoming AHB address will be adapted and sent to the FLASH device as (address + N), where N is the value stored in the remap address register."]
pub type EnahbremapR = crate::BitReader<Enahbremap>;
impl EnahbremapR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enahbremap {
        match self.bits {
            true => Enahbremap::Enable,
            false => Enahbremap::Disable,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Enahbremap::Enable
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Enahbremap::Disable
    }
}
#[doc = "Field `enahbremap` writer - (Direct Access Mode Only) When enabled, the incoming AHB address will be adapted and sent to the FLASH device as (address + N), where N is the value stored in the remap address register."]
pub type EnahbremapW<'a, REG> = crate::BitWriter<'a, REG, Enahbremap>;
impl<'a, REG> EnahbremapW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Enahbremap::Enable)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Enahbremap::Disable)
    }
}
#[doc = "If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting to enabled will inform the controller that the device is ready to enter XIP on the next READ instruction. The controller will therefore send the appropriate command sequence, including mode bits to cause the device to enter XIP mode. Use this register after the controller has ensured the FLASH device has been configured to be ready to enter XIP mode. Note : To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only AFTER the next READ instruction is executed. Software should therefore ensure that at least one READ instruction is requested after resetting this bit before it can be sure XIP mode in the device is exited.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enterxipnextrd {
    #[doc = "1: `1`"]
    Enable = 1,
    #[doc = "0: `0`"]
    Disable = 0,
}
impl From<Enterxipnextrd> for bool {
    #[inline(always)]
    fn from(variant: Enterxipnextrd) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enterxipnextrd` reader - If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting to enabled will inform the controller that the device is ready to enter XIP on the next READ instruction. The controller will therefore send the appropriate command sequence, including mode bits to cause the device to enter XIP mode. Use this register after the controller has ensured the FLASH device has been configured to be ready to enter XIP mode. Note : To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only AFTER the next READ instruction is executed. Software should therefore ensure that at least one READ instruction is requested after resetting this bit before it can be sure XIP mode in the device is exited."]
pub type EnterxipnextrdR = crate::BitReader<Enterxipnextrd>;
impl EnterxipnextrdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enterxipnextrd {
        match self.bits {
            true => Enterxipnextrd::Enable,
            false => Enterxipnextrd::Disable,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Enterxipnextrd::Enable
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Enterxipnextrd::Disable
    }
}
#[doc = "Field `enterxipnextrd` writer - If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting to enabled will inform the controller that the device is ready to enter XIP on the next READ instruction. The controller will therefore send the appropriate command sequence, including mode bits to cause the device to enter XIP mode. Use this register after the controller has ensured the FLASH device has been configured to be ready to enter XIP mode. Note : To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only AFTER the next READ instruction is executed. Software should therefore ensure that at least one READ instruction is requested after resetting this bit before it can be sure XIP mode in the device is exited."]
pub type EnterxipnextrdW<'a, REG> = crate::BitWriter<'a, REG, Enterxipnextrd>;
impl<'a, REG> EnterxipnextrdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Enterxipnextrd::Enable)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Enterxipnextrd::Disable)
    }
}
#[doc = "If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting enable will operate the device in XIP mode immediately. Use this register when the external device wakes up in XIP mode (as per the contents of its non- volatile configuration register). The controller will assume the next READ instruction will be passed to the device as an XIP instruction, and therefore will not require the READ opcode to be transferred. Note: To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only after the next READ instruction is executed. Software therefore should ensure that at least one READ instruction is requested after resetting this bit in order to be sure that XIP mode is exited.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enterxipimm {
    #[doc = "1: `1`"]
    Enable = 1,
    #[doc = "0: `0`"]
    Disable = 0,
}
impl From<Enterxipimm> for bool {
    #[inline(always)]
    fn from(variant: Enterxipimm) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `enterxipimm` reader - If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting enable will operate the device in XIP mode immediately. Use this register when the external device wakes up in XIP mode (as per the contents of its non- volatile configuration register). The controller will assume the next READ instruction will be passed to the device as an XIP instruction, and therefore will not require the READ opcode to be transferred. Note: To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only after the next READ instruction is executed. Software therefore should ensure that at least one READ instruction is requested after resetting this bit in order to be sure that XIP mode is exited."]
pub type EnterxipimmR = crate::BitReader<Enterxipimm>;
impl EnterxipimmR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Enterxipimm {
        match self.bits {
            true => Enterxipimm::Enable,
            false => Enterxipimm::Disable,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enable(&self) -> bool {
        *self == Enterxipimm::Enable
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disable(&self) -> bool {
        *self == Enterxipimm::Disable
    }
}
#[doc = "Field `enterxipimm` writer - If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting enable will operate the device in XIP mode immediately. Use this register when the external device wakes up in XIP mode (as per the contents of its non- volatile configuration register). The controller will assume the next READ instruction will be passed to the device as an XIP instruction, and therefore will not require the READ opcode to be transferred. Note: To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only after the next READ instruction is executed. Software therefore should ensure that at least one READ instruction is requested after resetting this bit in order to be sure that XIP mode is exited."]
pub type EnterxipimmW<'a, REG> = crate::BitWriter<'a, REG, Enterxipimm>;
impl<'a, REG> EnterxipimmW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enable(self) -> &'a mut crate::W<REG> {
        self.variant(Enterxipimm::Enable)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disable(self) -> &'a mut crate::W<REG> {
        self.variant(Enterxipimm::Disable)
    }
}
#[doc = "SPI baud rate = ref_clk / (2 * baud_rate_divisor)\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Bauddiv {
    #[doc = "0: `0`"]
    Baud2 = 0,
    #[doc = "1: `1`"]
    Baud4 = 1,
    #[doc = "2: `10`"]
    Baud6 = 2,
    #[doc = "3: `11`"]
    Baud8 = 3,
    #[doc = "4: `100`"]
    Baud10 = 4,
    #[doc = "5: `101`"]
    Baud12 = 5,
    #[doc = "6: `110`"]
    Baud14 = 6,
    #[doc = "7: `111`"]
    Baud16 = 7,
    #[doc = "8: `1000`"]
    Baud18 = 8,
    #[doc = "9: `1001`"]
    Baud20 = 9,
    #[doc = "10: `1010`"]
    Baud22 = 10,
    #[doc = "11: `1011`"]
    Baud24 = 11,
    #[doc = "12: `1100`"]
    Baud26 = 12,
    #[doc = "13: `1101`"]
    Baud28 = 13,
    #[doc = "14: `1110`"]
    Baud30 = 14,
    #[doc = "15: `1111`"]
    Baud32 = 15,
}
impl From<Bauddiv> for u8 {
    #[inline(always)]
    fn from(variant: Bauddiv) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Bauddiv {
    type Ux = u8;
}
#[doc = "Field `bauddiv` reader - SPI baud rate = ref_clk / (2 * baud_rate_divisor)"]
pub type BauddivR = crate::FieldReader<Bauddiv>;
impl BauddivR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Bauddiv {
        match self.bits {
            0 => Bauddiv::Baud2,
            1 => Bauddiv::Baud4,
            2 => Bauddiv::Baud6,
            3 => Bauddiv::Baud8,
            4 => Bauddiv::Baud10,
            5 => Bauddiv::Baud12,
            6 => Bauddiv::Baud14,
            7 => Bauddiv::Baud16,
            8 => Bauddiv::Baud18,
            9 => Bauddiv::Baud20,
            10 => Bauddiv::Baud22,
            11 => Bauddiv::Baud24,
            12 => Bauddiv::Baud26,
            13 => Bauddiv::Baud28,
            14 => Bauddiv::Baud30,
            15 => Bauddiv::Baud32,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_baud2(&self) -> bool {
        *self == Bauddiv::Baud2
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_baud4(&self) -> bool {
        *self == Bauddiv::Baud4
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_baud6(&self) -> bool {
        *self == Bauddiv::Baud6
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_baud8(&self) -> bool {
        *self == Bauddiv::Baud8
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_baud10(&self) -> bool {
        *self == Bauddiv::Baud10
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_baud12(&self) -> bool {
        *self == Bauddiv::Baud12
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_baud14(&self) -> bool {
        *self == Bauddiv::Baud14
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_baud16(&self) -> bool {
        *self == Bauddiv::Baud16
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_baud18(&self) -> bool {
        *self == Bauddiv::Baud18
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_baud20(&self) -> bool {
        *self == Bauddiv::Baud20
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_baud22(&self) -> bool {
        *self == Bauddiv::Baud22
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_baud24(&self) -> bool {
        *self == Bauddiv::Baud24
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_baud26(&self) -> bool {
        *self == Bauddiv::Baud26
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_baud28(&self) -> bool {
        *self == Bauddiv::Baud28
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_baud30(&self) -> bool {
        *self == Bauddiv::Baud30
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_baud32(&self) -> bool {
        *self == Bauddiv::Baud32
    }
}
#[doc = "Field `bauddiv` writer - SPI baud rate = ref_clk / (2 * baud_rate_divisor)"]
pub type BauddivW<'a, REG> = crate::FieldWriterSafe<'a, REG, 4, Bauddiv>;
impl<'a, REG> BauddivW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn baud2(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud2)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn baud4(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud4)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn baud6(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud6)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn baud8(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud8)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn baud10(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud10)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn baud12(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud12)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn baud14(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud14)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn baud16(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud16)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn baud18(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud18)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn baud20(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud20)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn baud22(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud22)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn baud24(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud24)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn baud26(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud26)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn baud28(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud28)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn baud30(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud30)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn baud32(self) -> &'a mut crate::W<REG> {
        self.variant(Bauddiv::Baud32)
    }
}
#[doc = "This is a STATUS read-only bit. Note this is a retimed signal, so there will be some inherent delay on the generation of this status signal.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Idle {
    #[doc = "1: `1`"]
    Set = 1,
    #[doc = "0: `0`"]
    Notset = 0,
}
impl From<Idle> for bool {
    #[inline(always)]
    fn from(variant: Idle) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `idle` reader - This is a STATUS read-only bit. Note this is a retimed signal, so there will be some inherent delay on the generation of this status signal."]
pub type IdleR = crate::BitReader<Idle>;
impl IdleR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Idle {
        match self.bits {
            true => Idle::Set,
            false => Idle::Notset,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_set(&self) -> bool {
        *self == Idle::Set
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notset(&self) -> bool {
        *self == Idle::Notset
    }
}
#[doc = "Field `idle` writer - This is a STATUS read-only bit. Note this is a retimed signal, so there will be some inherent delay on the generation of this status signal."]
pub type IdleW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - If this bit is disabled, the QSPI will finish the current transfer of the data word (FF_W) and stop sending. When Enabled, and qspi_n_mo_en = 0, all output enables are inactive and all pins are set to input mode."]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Controls spiclk modes of operation."]
    #[inline(always)]
    pub fn selclkpol(&self) -> SelclkpolR {
        SelclkpolR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Selects whether the clock is in an active or inactive phase outside the SPI word."]
    #[inline(always)]
    pub fn selclkphase(&self) -> SelclkphaseR {
        SelclkphaseR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 7 - If disabled, the Direct Access Controller becomes inactive once the current transfer of the data word (FF_W) is complete. When the Direct Access Controller and Indirect Access Controller are both disabled, all AHB requests are completed with an error response."]
    #[inline(always)]
    pub fn endiracc(&self) -> EndiraccR {
        EndiraccR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit can select the Direct Access Controller/Indirect Access Controller or legacy mode.If legacy mode is selected, any write to the controller via the AHB interface is serialized and sent to the FLASH device. Any valid AHB read will pop the internal RX-FIFO, retrieving data that was forwarded by the external FLASH device on the SPI lines, byte transfers of 4, 2 or 1 are permitted and controlled via the HSIZE input."]
    #[inline(always)]
    pub fn enlegacyip(&self) -> EnlegacyipR {
        EnlegacyipR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Select between '1 of 4 selects' or 'external 4-to-16 decode'. The qspi_n_ss_out\\[3:0\\]
output signals are controlled."]
    #[inline(always)]
    pub fn perseldec(&self) -> PerseldecR {
        PerseldecR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bits 10:13 - Peripheral chip select line output decode type. As per perseldec, if perseldec = 0, the decode is select 1 of 4 decoding on signals, qspi_n_ss_out\\[3:0\\], The asserted decode line goes to 0. If perseldec = 1, the signals qspi_n_ss_out\\[3:0\\]
require an external 4 to 16 decoder."]
    #[inline(always)]
    pub fn percslines(&self) -> PercslinesR {
        PercslinesR::new(((self.bits >> 10) & 0x0f) as u8)
    }
    #[doc = "Bit 14 - This bit controls the write protect pin of the flash devices. The signal qspi_mo2_wpn needs to be resynchronized to the generated memory clock as necessary."]
    #[inline(always)]
    pub fn wp(&self) -> WpR {
        WpR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Allows DMA handshaking mode. When enabled the QSPI will trigger DMA transfer requests via the DMA peripheral interface."]
    #[inline(always)]
    pub fn endma(&self) -> EndmaR {
        EndmaR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - (Direct Access Mode Only) When enabled, the incoming AHB address will be adapted and sent to the FLASH device as (address + N), where N is the value stored in the remap address register."]
    #[inline(always)]
    pub fn enahbremap(&self) -> EnahbremapR {
        EnahbremapR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting to enabled will inform the controller that the device is ready to enter XIP on the next READ instruction. The controller will therefore send the appropriate command sequence, including mode bits to cause the device to enter XIP mode. Use this register after the controller has ensured the FLASH device has been configured to be ready to enter XIP mode. Note : To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only AFTER the next READ instruction is executed. Software should therefore ensure that at least one READ instruction is requested after resetting this bit before it can be sure XIP mode in the device is exited."]
    #[inline(always)]
    pub fn enterxipnextrd(&self) -> EnterxipnextrdR {
        EnterxipnextrdR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting enable will operate the device in XIP mode immediately. Use this register when the external device wakes up in XIP mode (as per the contents of its non- volatile configuration register). The controller will assume the next READ instruction will be passed to the device as an XIP instruction, and therefore will not require the READ opcode to be transferred. Note: To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only after the next READ instruction is executed. Software therefore should ensure that at least one READ instruction is requested after resetting this bit in order to be sure that XIP mode is exited."]
    #[inline(always)]
    pub fn enterxipimm(&self) -> EnterxipimmR {
        EnterxipimmR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bits 19:22 - SPI baud rate = ref_clk / (2 * baud_rate_divisor)"]
    #[inline(always)]
    pub fn bauddiv(&self) -> BauddivR {
        BauddivR::new(((self.bits >> 19) & 0x0f) as u8)
    }
    #[doc = "Bit 31 - This is a STATUS read-only bit. Note this is a retimed signal, so there will be some inherent delay on the generation of this status signal."]
    #[inline(always)]
    pub fn idle(&self) -> IdleR {
        IdleR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - If this bit is disabled, the QSPI will finish the current transfer of the data word (FF_W) and stop sending. When Enabled, and qspi_n_mo_en = 0, all output enables are inactive and all pins are set to input mode."]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<CfgSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - Controls spiclk modes of operation."]
    #[inline(always)]
    #[must_use]
    pub fn selclkpol(&mut self) -> SelclkpolW<CfgSpec> {
        SelclkpolW::new(self, 1)
    }
    #[doc = "Bit 2 - Selects whether the clock is in an active or inactive phase outside the SPI word."]
    #[inline(always)]
    #[must_use]
    pub fn selclkphase(&mut self) -> SelclkphaseW<CfgSpec> {
        SelclkphaseW::new(self, 2)
    }
    #[doc = "Bit 7 - If disabled, the Direct Access Controller becomes inactive once the current transfer of the data word (FF_W) is complete. When the Direct Access Controller and Indirect Access Controller are both disabled, all AHB requests are completed with an error response."]
    #[inline(always)]
    #[must_use]
    pub fn endiracc(&mut self) -> EndiraccW<CfgSpec> {
        EndiraccW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit can select the Direct Access Controller/Indirect Access Controller or legacy mode.If legacy mode is selected, any write to the controller via the AHB interface is serialized and sent to the FLASH device. Any valid AHB read will pop the internal RX-FIFO, retrieving data that was forwarded by the external FLASH device on the SPI lines, byte transfers of 4, 2 or 1 are permitted and controlled via the HSIZE input."]
    #[inline(always)]
    #[must_use]
    pub fn enlegacyip(&mut self) -> EnlegacyipW<CfgSpec> {
        EnlegacyipW::new(self, 8)
    }
    #[doc = "Bit 9 - Select between '1 of 4 selects' or 'external 4-to-16 decode'. The qspi_n_ss_out\\[3:0\\]
output signals are controlled."]
    #[inline(always)]
    #[must_use]
    pub fn perseldec(&mut self) -> PerseldecW<CfgSpec> {
        PerseldecW::new(self, 9)
    }
    #[doc = "Bits 10:13 - Peripheral chip select line output decode type. As per perseldec, if perseldec = 0, the decode is select 1 of 4 decoding on signals, qspi_n_ss_out\\[3:0\\], The asserted decode line goes to 0. If perseldec = 1, the signals qspi_n_ss_out\\[3:0\\]
require an external 4 to 16 decoder."]
    #[inline(always)]
    #[must_use]
    pub fn percslines(&mut self) -> PercslinesW<CfgSpec> {
        PercslinesW::new(self, 10)
    }
    #[doc = "Bit 14 - This bit controls the write protect pin of the flash devices. The signal qspi_mo2_wpn needs to be resynchronized to the generated memory clock as necessary."]
    #[inline(always)]
    #[must_use]
    pub fn wp(&mut self) -> WpW<CfgSpec> {
        WpW::new(self, 14)
    }
    #[doc = "Bit 15 - Allows DMA handshaking mode. When enabled the QSPI will trigger DMA transfer requests via the DMA peripheral interface."]
    #[inline(always)]
    #[must_use]
    pub fn endma(&mut self) -> EndmaW<CfgSpec> {
        EndmaW::new(self, 15)
    }
    #[doc = "Bit 16 - (Direct Access Mode Only) When enabled, the incoming AHB address will be adapted and sent to the FLASH device as (address + N), where N is the value stored in the remap address register."]
    #[inline(always)]
    #[must_use]
    pub fn enahbremap(&mut self) -> EnahbremapW<CfgSpec> {
        EnahbremapW::new(self, 16)
    }
    #[doc = "Bit 17 - If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting to enabled will inform the controller that the device is ready to enter XIP on the next READ instruction. The controller will therefore send the appropriate command sequence, including mode bits to cause the device to enter XIP mode. Use this register after the controller has ensured the FLASH device has been configured to be ready to enter XIP mode. Note : To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only AFTER the next READ instruction is executed. Software should therefore ensure that at least one READ instruction is requested after resetting this bit before it can be sure XIP mode in the device is exited."]
    #[inline(always)]
    #[must_use]
    pub fn enterxipnextrd(&mut self) -> EnterxipnextrdW<CfgSpec> {
        EnterxipnextrdW::new(self, 17)
    }
    #[doc = "Bit 18 - If XIP is enabled, then setting to disabled will cause the controller to exit XIP mode on the next READ instruction. If XIP is disabled, then setting enable will operate the device in XIP mode immediately. Use this register when the external device wakes up in XIP mode (as per the contents of its non- volatile configuration register). The controller will assume the next READ instruction will be passed to the device as an XIP instruction, and therefore will not require the READ opcode to be transferred. Note: To exit XIP mode, this bit should be set to 0. This will take effect in the attached device only after the next READ instruction is executed. Software therefore should ensure that at least one READ instruction is requested after resetting this bit in order to be sure that XIP mode is exited."]
    #[inline(always)]
    #[must_use]
    pub fn enterxipimm(&mut self) -> EnterxipimmW<CfgSpec> {
        EnterxipimmW::new(self, 18)
    }
    #[doc = "Bits 19:22 - SPI baud rate = ref_clk / (2 * baud_rate_divisor)"]
    #[inline(always)]
    #[must_use]
    pub fn bauddiv(&mut self) -> BauddivW<CfgSpec> {
        BauddivW::new(self, 19)
    }
    #[doc = "Bit 31 - This is a STATUS read-only bit. Note this is a retimed signal, so there will be some inherent delay on the generation of this status signal."]
    #[inline(always)]
    #[must_use]
    pub fn idle(&mut self) -> IdleW<CfgSpec> {
        IdleW::new(self, 31)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CfgSpec;
impl crate::RegisterSpec for CfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cfg::R`](R) reader structure"]
impl crate::Readable for CfgSpec {}
#[doc = "`write(|w| ..)` method takes [`cfg::W`](W) writer structure"]
impl crate::Writable for CfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets cfg to value 0x0078_0000"]
impl crate::Resettable for CfgSpec {
    const RESET_VALUE: u32 = 0x0078_0000;
}
