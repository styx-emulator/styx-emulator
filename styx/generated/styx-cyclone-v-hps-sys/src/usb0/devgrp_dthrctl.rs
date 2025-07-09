// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_dthrctl` reader"]
pub type R = crate::R<DevgrpDthrctlSpec>;
#[doc = "Register `devgrp_dthrctl` writer"]
pub type W = crate::W<DevgrpDthrctlSpec>;
#[doc = "When this bit is Set, the core enables thresholding for Non Isochronous IN endpoints.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nonisothren {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Nonisothren> for bool {
    #[inline(always)]
    fn from(variant: Nonisothren) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nonisothren` reader - When this bit is Set, the core enables thresholding for Non Isochronous IN endpoints."]
pub type NonisothrenR = crate::BitReader<Nonisothren>;
impl NonisothrenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nonisothren {
        match self.bits {
            false => Nonisothren::Disabled,
            true => Nonisothren::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Nonisothren::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Nonisothren::Enabled
    }
}
#[doc = "Field `nonisothren` writer - When this bit is Set, the core enables thresholding for Non Isochronous IN endpoints."]
pub type NonisothrenW<'a, REG> = crate::BitWriter<'a, REG, Nonisothren>;
impl<'a, REG> NonisothrenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Nonisothren::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Nonisothren::Enabled)
    }
}
#[doc = "When this bit is Set, the core enables thresholding for isochronous IN endpoints.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isothren {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Isothren> for bool {
    #[inline(always)]
    fn from(variant: Isothren) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `isothren` reader - When this bit is Set, the core enables thresholding for isochronous IN endpoints."]
pub type IsothrenR = crate::BitReader<Isothren>;
impl IsothrenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Isothren {
        match self.bits {
            false => Isothren::Disabled,
            true => Isothren::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Isothren::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Isothren::Enabled
    }
}
#[doc = "Field `isothren` writer - When this bit is Set, the core enables thresholding for isochronous IN endpoints."]
pub type IsothrenW<'a, REG> = crate::BitWriter<'a, REG, Isothren>;
impl<'a, REG> IsothrenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Isothren::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Isothren::Enabled)
    }
}
#[doc = "Field `txthrlen` reader - This field specifies Transmit thresholding size in DWORDS. This also forms the MAC threshold and specifies the amount of data in bytes to be in the corresponding endpoint transmit FIFO, before the core can start transmit on the USB. The threshold length has to be at least eight DWORDS when the value of AHBThrRatio is 0. In case the AHBThrRatio is non zero the application needs to ensure that the AHB Threshold value does not go below the recommended eight DWORD. This field controls both isochronous and non-isochronous IN endpoint thresholds. The recommended value for ThrLen is to be the same as the programmed AHB Burst Length (GAHBCFG.HBstLen)."]
pub type TxthrlenR = crate::FieldReader<u16>;
#[doc = "Field `txthrlen` writer - This field specifies Transmit thresholding size in DWORDS. This also forms the MAC threshold and specifies the amount of data in bytes to be in the corresponding endpoint transmit FIFO, before the core can start transmit on the USB. The threshold length has to be at least eight DWORDS when the value of AHBThrRatio is 0. In case the AHBThrRatio is non zero the application needs to ensure that the AHB Threshold value does not go below the recommended eight DWORD. This field controls both isochronous and non-isochronous IN endpoint thresholds. The recommended value for ThrLen is to be the same as the programmed AHB Burst Length (GAHBCFG.HBstLen)."]
pub type TxthrlenW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "These bits define the ratio between the AHB threshold and the MAC threshold for the transmit path only. The AHB threshold always remains less than or equal to the USB threshold, because this does not increase overhead. Both the AHB and the MAC threshold must be DWORD-aligned. The application needs to program TxThrLen and the AHBThrRatio to make the AHB Threshold value DWORD aligned. If the AHB threshold value is not DWORD aligned, the core might not behave correctly. When programming the TxThrLen and AHBThrRatio, the application must ensure that the minimum AHB threshold value does not go below 8 DWORDS to meet the USB turnaround time requirements.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ahbthrratio {
    #[doc = "0: `0`"]
    Threszero = 0,
    #[doc = "1: `1`"]
    Thresone = 1,
    #[doc = "2: `10`"]
    Threstwo = 2,
    #[doc = "3: `11`"]
    Thresthree = 3,
}
impl From<Ahbthrratio> for u8 {
    #[inline(always)]
    fn from(variant: Ahbthrratio) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ahbthrratio {
    type Ux = u8;
}
#[doc = "Field `ahbthrratio` reader - These bits define the ratio between the AHB threshold and the MAC threshold for the transmit path only. The AHB threshold always remains less than or equal to the USB threshold, because this does not increase overhead. Both the AHB and the MAC threshold must be DWORD-aligned. The application needs to program TxThrLen and the AHBThrRatio to make the AHB Threshold value DWORD aligned. If the AHB threshold value is not DWORD aligned, the core might not behave correctly. When programming the TxThrLen and AHBThrRatio, the application must ensure that the minimum AHB threshold value does not go below 8 DWORDS to meet the USB turnaround time requirements."]
pub type AhbthrratioR = crate::FieldReader<Ahbthrratio>;
impl AhbthrratioR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ahbthrratio {
        match self.bits {
            0 => Ahbthrratio::Threszero,
            1 => Ahbthrratio::Thresone,
            2 => Ahbthrratio::Threstwo,
            3 => Ahbthrratio::Thresthree,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_threszero(&self) -> bool {
        *self == Ahbthrratio::Threszero
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_thresone(&self) -> bool {
        *self == Ahbthrratio::Thresone
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_threstwo(&self) -> bool {
        *self == Ahbthrratio::Threstwo
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_thresthree(&self) -> bool {
        *self == Ahbthrratio::Thresthree
    }
}
#[doc = "Field `ahbthrratio` writer - These bits define the ratio between the AHB threshold and the MAC threshold for the transmit path only. The AHB threshold always remains less than or equal to the USB threshold, because this does not increase overhead. Both the AHB and the MAC threshold must be DWORD-aligned. The application needs to program TxThrLen and the AHBThrRatio to make the AHB Threshold value DWORD aligned. If the AHB threshold value is not DWORD aligned, the core might not behave correctly. When programming the TxThrLen and AHBThrRatio, the application must ensure that the minimum AHB threshold value does not go below 8 DWORDS to meet the USB turnaround time requirements."]
pub type AhbthrratioW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Ahbthrratio>;
impl<'a, REG> AhbthrratioW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn threszero(self) -> &'a mut crate::W<REG> {
        self.variant(Ahbthrratio::Threszero)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn thresone(self) -> &'a mut crate::W<REG> {
        self.variant(Ahbthrratio::Thresone)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn threstwo(self) -> &'a mut crate::W<REG> {
        self.variant(Ahbthrratio::Threstwo)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn thresthree(self) -> &'a mut crate::W<REG> {
        self.variant(Ahbthrratio::Thresthree)
    }
}
#[doc = "When this bit is Set, the core enables thresholding in the receive direction.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxthren {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Rxthren> for bool {
    #[inline(always)]
    fn from(variant: Rxthren) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxthren` reader - When this bit is Set, the core enables thresholding in the receive direction."]
pub type RxthrenR = crate::BitReader<Rxthren>;
impl RxthrenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxthren {
        match self.bits {
            false => Rxthren::Disabled,
            true => Rxthren::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Rxthren::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Rxthren::Enabled
    }
}
#[doc = "Field `rxthren` writer - When this bit is Set, the core enables thresholding in the receive direction."]
pub type RxthrenW<'a, REG> = crate::BitWriter<'a, REG, Rxthren>;
impl<'a, REG> RxthrenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxthren::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Rxthren::Enabled)
    }
}
#[doc = "Field `rxthrlen` reader - This field specifies Receive thresholding size in DWORDS.This field also specifies the amount of data received on the USB before the core can start transmitting on the AHB. The threshold length has to be at least eight DWORDS. The recommended value for ThrLen is to be the same as the programmed AHB Burst Length (GAHBCFG.HBstLen)."]
pub type RxthrlenR = crate::FieldReader<u16>;
#[doc = "Field `rxthrlen` writer - This field specifies Receive thresholding size in DWORDS.This field also specifies the amount of data received on the USB before the core can start transmitting on the AHB. The threshold length has to be at least eight DWORDS. The recommended value for ThrLen is to be the same as the programmed AHB Burst Length (GAHBCFG.HBstLen)."]
pub type RxthrlenW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
#[doc = "This bit controls internal DMA arbiter parking for IN endpoints. When thresholding is enabled and this bit is Set to one, Then the arbiter parks on the IN endpoint for which there is a token received on the USB. This is done to avoid getting into underrun conditions. By Default the parking is enabled.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arbprken {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Arbprken> for bool {
    #[inline(always)]
    fn from(variant: Arbprken) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `arbprken` reader - This bit controls internal DMA arbiter parking for IN endpoints. When thresholding is enabled and this bit is Set to one, Then the arbiter parks on the IN endpoint for which there is a token received on the USB. This is done to avoid getting into underrun conditions. By Default the parking is enabled."]
pub type ArbprkenR = crate::BitReader<Arbprken>;
impl ArbprkenR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Arbprken {
        match self.bits {
            false => Arbprken::Disabled,
            true => Arbprken::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Arbprken::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Arbprken::Enabled
    }
}
#[doc = "Field `arbprken` writer - This bit controls internal DMA arbiter parking for IN endpoints. When thresholding is enabled and this bit is Set to one, Then the arbiter parks on the IN endpoint for which there is a token received on the USB. This is done to avoid getting into underrun conditions. By Default the parking is enabled."]
pub type ArbprkenW<'a, REG> = crate::BitWriter<'a, REG, Arbprken>;
impl<'a, REG> ArbprkenW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Arbprken::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Arbprken::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - When this bit is Set, the core enables thresholding for Non Isochronous IN endpoints."]
    #[inline(always)]
    pub fn nonisothren(&self) -> NonisothrenR {
        NonisothrenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When this bit is Set, the core enables thresholding for isochronous IN endpoints."]
    #[inline(always)]
    pub fn isothren(&self) -> IsothrenR {
        IsothrenR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:10 - This field specifies Transmit thresholding size in DWORDS. This also forms the MAC threshold and specifies the amount of data in bytes to be in the corresponding endpoint transmit FIFO, before the core can start transmit on the USB. The threshold length has to be at least eight DWORDS when the value of AHBThrRatio is 0. In case the AHBThrRatio is non zero the application needs to ensure that the AHB Threshold value does not go below the recommended eight DWORD. This field controls both isochronous and non-isochronous IN endpoint thresholds. The recommended value for ThrLen is to be the same as the programmed AHB Burst Length (GAHBCFG.HBstLen)."]
    #[inline(always)]
    pub fn txthrlen(&self) -> TxthrlenR {
        TxthrlenR::new(((self.bits >> 2) & 0x01ff) as u16)
    }
    #[doc = "Bits 11:12 - These bits define the ratio between the AHB threshold and the MAC threshold for the transmit path only. The AHB threshold always remains less than or equal to the USB threshold, because this does not increase overhead. Both the AHB and the MAC threshold must be DWORD-aligned. The application needs to program TxThrLen and the AHBThrRatio to make the AHB Threshold value DWORD aligned. If the AHB threshold value is not DWORD aligned, the core might not behave correctly. When programming the TxThrLen and AHBThrRatio, the application must ensure that the minimum AHB threshold value does not go below 8 DWORDS to meet the USB turnaround time requirements."]
    #[inline(always)]
    pub fn ahbthrratio(&self) -> AhbthrratioR {
        AhbthrratioR::new(((self.bits >> 11) & 3) as u8)
    }
    #[doc = "Bit 16 - When this bit is Set, the core enables thresholding in the receive direction."]
    #[inline(always)]
    pub fn rxthren(&self) -> RxthrenR {
        RxthrenR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:25 - This field specifies Receive thresholding size in DWORDS.This field also specifies the amount of data received on the USB before the core can start transmitting on the AHB. The threshold length has to be at least eight DWORDS. The recommended value for ThrLen is to be the same as the programmed AHB Burst Length (GAHBCFG.HBstLen)."]
    #[inline(always)]
    pub fn rxthrlen(&self) -> RxthrlenR {
        RxthrlenR::new(((self.bits >> 17) & 0x01ff) as u16)
    }
    #[doc = "Bit 27 - This bit controls internal DMA arbiter parking for IN endpoints. When thresholding is enabled and this bit is Set to one, Then the arbiter parks on the IN endpoint for which there is a token received on the USB. This is done to avoid getting into underrun conditions. By Default the parking is enabled."]
    #[inline(always)]
    pub fn arbprken(&self) -> ArbprkenR {
        ArbprkenR::new(((self.bits >> 27) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When this bit is Set, the core enables thresholding for Non Isochronous IN endpoints."]
    #[inline(always)]
    #[must_use]
    pub fn nonisothren(&mut self) -> NonisothrenW<DevgrpDthrctlSpec> {
        NonisothrenW::new(self, 0)
    }
    #[doc = "Bit 1 - When this bit is Set, the core enables thresholding for isochronous IN endpoints."]
    #[inline(always)]
    #[must_use]
    pub fn isothren(&mut self) -> IsothrenW<DevgrpDthrctlSpec> {
        IsothrenW::new(self, 1)
    }
    #[doc = "Bits 2:10 - This field specifies Transmit thresholding size in DWORDS. This also forms the MAC threshold and specifies the amount of data in bytes to be in the corresponding endpoint transmit FIFO, before the core can start transmit on the USB. The threshold length has to be at least eight DWORDS when the value of AHBThrRatio is 0. In case the AHBThrRatio is non zero the application needs to ensure that the AHB Threshold value does not go below the recommended eight DWORD. This field controls both isochronous and non-isochronous IN endpoint thresholds. The recommended value for ThrLen is to be the same as the programmed AHB Burst Length (GAHBCFG.HBstLen)."]
    #[inline(always)]
    #[must_use]
    pub fn txthrlen(&mut self) -> TxthrlenW<DevgrpDthrctlSpec> {
        TxthrlenW::new(self, 2)
    }
    #[doc = "Bits 11:12 - These bits define the ratio between the AHB threshold and the MAC threshold for the transmit path only. The AHB threshold always remains less than or equal to the USB threshold, because this does not increase overhead. Both the AHB and the MAC threshold must be DWORD-aligned. The application needs to program TxThrLen and the AHBThrRatio to make the AHB Threshold value DWORD aligned. If the AHB threshold value is not DWORD aligned, the core might not behave correctly. When programming the TxThrLen and AHBThrRatio, the application must ensure that the minimum AHB threshold value does not go below 8 DWORDS to meet the USB turnaround time requirements."]
    #[inline(always)]
    #[must_use]
    pub fn ahbthrratio(&mut self) -> AhbthrratioW<DevgrpDthrctlSpec> {
        AhbthrratioW::new(self, 11)
    }
    #[doc = "Bit 16 - When this bit is Set, the core enables thresholding in the receive direction."]
    #[inline(always)]
    #[must_use]
    pub fn rxthren(&mut self) -> RxthrenW<DevgrpDthrctlSpec> {
        RxthrenW::new(self, 16)
    }
    #[doc = "Bits 17:25 - This field specifies Receive thresholding size in DWORDS.This field also specifies the amount of data received on the USB before the core can start transmitting on the AHB. The threshold length has to be at least eight DWORDS. The recommended value for ThrLen is to be the same as the programmed AHB Burst Length (GAHBCFG.HBstLen)."]
    #[inline(always)]
    #[must_use]
    pub fn rxthrlen(&mut self) -> RxthrlenW<DevgrpDthrctlSpec> {
        RxthrlenW::new(self, 17)
    }
    #[doc = "Bit 27 - This bit controls internal DMA arbiter parking for IN endpoints. When thresholding is enabled and this bit is Set to one, Then the arbiter parks on the IN endpoint for which there is a token received on the USB. This is done to avoid getting into underrun conditions. By Default the parking is enabled."]
    #[inline(always)]
    #[must_use]
    pub fn arbprken(&mut self) -> ArbprkenW<DevgrpDthrctlSpec> {
        ArbprkenW::new(self, 27)
    }
}
#[doc = "Thresholding is not supported in Slave mode and so this register must not be programmed in Slave mode. for threshold support, the AHB must be run at 60 MHz or higher.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dthrctl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dthrctl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDthrctlSpec;
impl crate::RegisterSpec for DevgrpDthrctlSpec {
    type Ux = u32;
    const OFFSET: u64 = 2096u64;
}
#[doc = "`read()` method returns [`devgrp_dthrctl::R`](R) reader structure"]
impl crate::Readable for DevgrpDthrctlSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_dthrctl::W`](W) writer structure"]
impl crate::Writable for DevgrpDthrctlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_dthrctl to value 0x0810_0020"]
impl crate::Resettable for DevgrpDthrctlSpec {
    const RESET_VALUE: u32 = 0x0810_0020;
}
