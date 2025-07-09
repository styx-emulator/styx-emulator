// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_dcfg` reader"]
pub type R = crate::R<DevgrpDcfgSpec>;
#[doc = "Register `devgrp_dcfg` writer"]
pub type W = crate::W<DevgrpDcfgSpec>;
#[doc = "Indicates the speed at which the application requires the core to enumerate, or the maximum speed the application can support. However, the actual bus speed is determined only after the chirp sequence is completed, and is based on the speed of the USB host to which the core is connected.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Devspd {
    #[doc = "0: `0`"]
    Usbhs20 = 0,
    #[doc = "1: `1`"]
    Usbfs20 = 1,
    #[doc = "2: `10`"]
    Usbls116 = 2,
    #[doc = "3: `11`"]
    Usbls1148 = 3,
}
impl From<Devspd> for u8 {
    #[inline(always)]
    fn from(variant: Devspd) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Devspd {
    type Ux = u8;
}
#[doc = "Field `devspd` reader - Indicates the speed at which the application requires the core to enumerate, or the maximum speed the application can support. However, the actual bus speed is determined only after the chirp sequence is completed, and is based on the speed of the USB host to which the core is connected."]
pub type DevspdR = crate::FieldReader<Devspd>;
impl DevspdR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Devspd {
        match self.bits {
            0 => Devspd::Usbhs20,
            1 => Devspd::Usbfs20,
            2 => Devspd::Usbls116,
            3 => Devspd::Usbls1148,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_usbhs20(&self) -> bool {
        *self == Devspd::Usbhs20
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_usbfs20(&self) -> bool {
        *self == Devspd::Usbfs20
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_usbls116(&self) -> bool {
        *self == Devspd::Usbls116
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_usbls1148(&self) -> bool {
        *self == Devspd::Usbls1148
    }
}
#[doc = "Field `devspd` writer - Indicates the speed at which the application requires the core to enumerate, or the maximum speed the application can support. However, the actual bus speed is determined only after the chirp sequence is completed, and is based on the speed of the USB host to which the core is connected."]
pub type DevspdW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Devspd>;
impl<'a, REG> DevspdW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn usbhs20(self) -> &'a mut crate::W<REG> {
        self.variant(Devspd::Usbhs20)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn usbfs20(self) -> &'a mut crate::W<REG> {
        self.variant(Devspd::Usbfs20)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn usbls116(self) -> &'a mut crate::W<REG> {
        self.variant(Devspd::Usbls116)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn usbls1148(self) -> &'a mut crate::W<REG> {
        self.variant(Devspd::Usbls1148)
    }
}
#[doc = "The application can use this field to select the handshake the core sends on receiving a nonzero-length data packet during the OUT transaction of a control transfer's Status stage. 1: Send a STALL handshake on a nonzero-length statusOUT transaction and do not send the received OUT packet tothe application. 0: Send the received OUT packet to the application (zerolengthor nonzero-length) and send a handshake based onthe NAK and STALL bits for the endpoint in the DeviceEndpoint Control register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nzstsouthshk {
    #[doc = "0: `0`"]
    Sendout = 0,
    #[doc = "1: `1`"]
    Sendstall = 1,
}
impl From<Nzstsouthshk> for bool {
    #[inline(always)]
    fn from(variant: Nzstsouthshk) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `nzstsouthshk` reader - The application can use this field to select the handshake the core sends on receiving a nonzero-length data packet during the OUT transaction of a control transfer's Status stage. 1: Send a STALL handshake on a nonzero-length statusOUT transaction and do not send the received OUT packet tothe application. 0: Send the received OUT packet to the application (zerolengthor nonzero-length) and send a handshake based onthe NAK and STALL bits for the endpoint in the DeviceEndpoint Control register."]
pub type NzstsouthshkR = crate::BitReader<Nzstsouthshk>;
impl NzstsouthshkR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Nzstsouthshk {
        match self.bits {
            false => Nzstsouthshk::Sendout,
            true => Nzstsouthshk::Sendstall,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_sendout(&self) -> bool {
        *self == Nzstsouthshk::Sendout
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_sendstall(&self) -> bool {
        *self == Nzstsouthshk::Sendstall
    }
}
#[doc = "Field `nzstsouthshk` writer - The application can use this field to select the handshake the core sends on receiving a nonzero-length data packet during the OUT transaction of a control transfer's Status stage. 1: Send a STALL handshake on a nonzero-length statusOUT transaction and do not send the received OUT packet tothe application. 0: Send the received OUT packet to the application (zerolengthor nonzero-length) and send a handshake based onthe NAK and STALL bits for the endpoint in the DeviceEndpoint Control register."]
pub type NzstsouthshkW<'a, REG> = crate::BitWriter<'a, REG, Nzstsouthshk>;
impl<'a, REG> NzstsouthshkW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn sendout(self) -> &'a mut crate::W<REG> {
        self.variant(Nzstsouthshk::Sendout)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn sendstall(self) -> &'a mut crate::W<REG> {
        self.variant(Nzstsouthshk::Sendstall)
    }
}
#[doc = "When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend. This bit can only be set if USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ena32khzsusp {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Ena32khzsusp> for bool {
    #[inline(always)]
    fn from(variant: Ena32khzsusp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ena32khzsusp` reader - When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend. This bit can only be set if USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero."]
pub type Ena32khzsuspR = crate::BitReader<Ena32khzsusp>;
impl Ena32khzsuspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ena32khzsusp {
        match self.bits {
            false => Ena32khzsusp::Disabled,
            true => Ena32khzsusp::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Ena32khzsusp::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Ena32khzsusp::Enabled
    }
}
#[doc = "Field `ena32khzsusp` writer - When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend. This bit can only be set if USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero."]
pub type Ena32khzsuspW<'a, REG> = crate::BitWriter<'a, REG, Ena32khzsusp>;
impl<'a, REG> Ena32khzsuspW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ena32khzsusp::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Ena32khzsusp::Enabled)
    }
}
#[doc = "Field `devaddr` reader - The application must program this field after every SetAddress control command."]
pub type DevaddrR = crate::FieldReader;
#[doc = "Field `devaddr` writer - The application must program this field after every SetAddress control command."]
pub type DevaddrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Indicates the time within a (micro)frame at which the application must be notified using the End Of Periodic Frame Interrupt. This can be used to determine If all the isochronous traffic for that (micro)frame is complete. 0x0: 80% of the (micro)frame interval 0x1: 85% 0x2: 90% 0x3: 95%\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Perfrint {
    #[doc = "0: `0`"]
    Eopf80 = 0,
    #[doc = "1: `1`"]
    Eopf85 = 1,
    #[doc = "2: `10`"]
    Eopf90 = 2,
    #[doc = "3: `11`"]
    Eopf95 = 3,
}
impl From<Perfrint> for u8 {
    #[inline(always)]
    fn from(variant: Perfrint) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Perfrint {
    type Ux = u8;
}
#[doc = "Field `perfrint` reader - Indicates the time within a (micro)frame at which the application must be notified using the End Of Periodic Frame Interrupt. This can be used to determine If all the isochronous traffic for that (micro)frame is complete. 0x0: 80% of the (micro)frame interval 0x1: 85% 0x2: 90% 0x3: 95%"]
pub type PerfrintR = crate::FieldReader<Perfrint>;
impl PerfrintR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Perfrint {
        match self.bits {
            0 => Perfrint::Eopf80,
            1 => Perfrint::Eopf85,
            2 => Perfrint::Eopf90,
            3 => Perfrint::Eopf95,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_eopf80(&self) -> bool {
        *self == Perfrint::Eopf80
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_eopf85(&self) -> bool {
        *self == Perfrint::Eopf85
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_eopf90(&self) -> bool {
        *self == Perfrint::Eopf90
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_eopf95(&self) -> bool {
        *self == Perfrint::Eopf95
    }
}
#[doc = "Field `perfrint` writer - Indicates the time within a (micro)frame at which the application must be notified using the End Of Periodic Frame Interrupt. This can be used to determine If all the isochronous traffic for that (micro)frame is complete. 0x0: 80% of the (micro)frame interval 0x1: 85% 0x2: 90% 0x3: 95%"]
pub type PerfrintW<'a, REG> = crate::FieldWriterSafe<'a, REG, 2, Perfrint>;
impl<'a, REG> PerfrintW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn eopf80(self) -> &'a mut crate::W<REG> {
        self.variant(Perfrint::Eopf80)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn eopf85(self) -> &'a mut crate::W<REG> {
        self.variant(Perfrint::Eopf85)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn eopf90(self) -> &'a mut crate::W<REG> {
        self.variant(Perfrint::Eopf90)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn eopf95(self) -> &'a mut crate::W<REG> {
        self.variant(Perfrint::Eopf95)
    }
}
#[doc = "This bit enables setting NAK for Bulk OUT endpoints after the transfer is completed for Device mode Descriptor DMA It is one time programmable after reset like any other DCFG register bits.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endevoutnak {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Endevoutnak> for bool {
    #[inline(always)]
    fn from(variant: Endevoutnak) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `endevoutnak` reader - This bit enables setting NAK for Bulk OUT endpoints after the transfer is completed for Device mode Descriptor DMA It is one time programmable after reset like any other DCFG register bits."]
pub type EndevoutnakR = crate::BitReader<Endevoutnak>;
impl EndevoutnakR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Endevoutnak {
        match self.bits {
            false => Endevoutnak::Disabled,
            true => Endevoutnak::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Endevoutnak::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Endevoutnak::Enabled
    }
}
#[doc = "Field `endevoutnak` writer - This bit enables setting NAK for Bulk OUT endpoints after the transfer is completed for Device mode Descriptor DMA It is one time programmable after reset like any other DCFG register bits."]
pub type EndevoutnakW<'a, REG> = crate::BitWriter<'a, REG, Endevoutnak>;
impl<'a, REG> EndevoutnakW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Endevoutnak::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Endevoutnak::Enabled)
    }
}
#[doc = "When the Scatter/Gather DMA option selected during configuration of the RTL, the application can Set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset.The following combinations are available for programming: GAHBCFG.DMAEn=0,DCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,DCFG.DescDMA=1 => Invalid GAHBCFG.DMAEn=1,DCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,DCFG.DescDMA=1 => Scatter/Gather DMA mode\n\nValue on reset: 0"]
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
#[doc = "Field `descdma` reader - When the Scatter/Gather DMA option selected during configuration of the RTL, the application can Set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset.The following combinations are available for programming: GAHBCFG.DMAEn=0,DCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,DCFG.DescDMA=1 => Invalid GAHBCFG.DMAEn=1,DCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,DCFG.DescDMA=1 => Scatter/Gather DMA mode"]
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
#[doc = "Field `descdma` writer - When the Scatter/Gather DMA option selected during configuration of the RTL, the application can Set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset.The following combinations are available for programming: GAHBCFG.DMAEn=0,DCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,DCFG.DescDMA=1 => Invalid GAHBCFG.DMAEn=1,DCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,DCFG.DescDMA=1 => Scatter/Gather DMA mode"]
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
#[doc = "PerSchIntvl must be programmed only for Scatter/Gather DMAmode. Description: This field specifies the amount of time the Internal DMA engine must allocate for fetching periodic IN endpoint data. Based on the number of periodic endpoints, this value must be specified as 25,50 or 75% of (micro)frame. When any periodic endpoints are active, the internal DMA engine allocates the specified amount of time in fetching periodic IN endpoint data . When no periodic endpoints are active, Then the internal DMA engine services non-periodic endpoints, ignoring this field. After the specified time within a (micro)frame, the DMA switches to fetching for non-periodic endpoints. 2'b00: 25% of (micro)frame. 2'b01: 50% of (micro)frame. 2'b10: 75% of (micro)frame. 2'b11: Reserved.Reset: 2'b00Access: read-write\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Perschintvl {
    #[doc = "0: `0`"]
    Mf25 = 0,
    #[doc = "1: `1`"]
    Mf50 = 1,
    #[doc = "2: `10`"]
    Mf75 = 2,
}
impl From<Perschintvl> for u8 {
    #[inline(always)]
    fn from(variant: Perschintvl) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Perschintvl {
    type Ux = u8;
}
#[doc = "Field `perschintvl` reader - PerSchIntvl must be programmed only for Scatter/Gather DMAmode. Description: This field specifies the amount of time the Internal DMA engine must allocate for fetching periodic IN endpoint data. Based on the number of periodic endpoints, this value must be specified as 25,50 or 75% of (micro)frame. When any periodic endpoints are active, the internal DMA engine allocates the specified amount of time in fetching periodic IN endpoint data . When no periodic endpoints are active, Then the internal DMA engine services non-periodic endpoints, ignoring this field. After the specified time within a (micro)frame, the DMA switches to fetching for non-periodic endpoints. 2'b00: 25% of (micro)frame. 2'b01: 50% of (micro)frame. 2'b10: 75% of (micro)frame. 2'b11: Reserved.Reset: 2'b00Access: read-write"]
pub type PerschintvlR = crate::FieldReader<Perschintvl>;
impl PerschintvlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Perschintvl {
        match self.bits {
            0 => Perschintvl::Mf25,
            1 => Perschintvl::Mf50,
            2 => Perschintvl::Mf75,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_mf25(&self) -> bool {
        *self == Perschintvl::Mf25
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_mf50(&self) -> bool {
        *self == Perschintvl::Mf50
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_mf75(&self) -> bool {
        *self == Perschintvl::Mf75
    }
}
#[doc = "Field `perschintvl` writer - PerSchIntvl must be programmed only for Scatter/Gather DMAmode. Description: This field specifies the amount of time the Internal DMA engine must allocate for fetching periodic IN endpoint data. Based on the number of periodic endpoints, this value must be specified as 25,50 or 75% of (micro)frame. When any periodic endpoints are active, the internal DMA engine allocates the specified amount of time in fetching periodic IN endpoint data . When no periodic endpoints are active, Then the internal DMA engine services non-periodic endpoints, ignoring this field. After the specified time within a (micro)frame, the DMA switches to fetching for non-periodic endpoints. 2'b00: 25% of (micro)frame. 2'b01: 50% of (micro)frame. 2'b10: 75% of (micro)frame. 2'b11: Reserved.Reset: 2'b00Access: read-write"]
pub type PerschintvlW<'a, REG> = crate::FieldWriter<'a, REG, 2, Perschintvl>;
impl<'a, REG> PerschintvlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn mf25(self) -> &'a mut crate::W<REG> {
        self.variant(Perschintvl::Mf25)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn mf50(self) -> &'a mut crate::W<REG> {
        self.variant(Perschintvl::Mf50)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn mf75(self) -> &'a mut crate::W<REG> {
        self.variant(Perschintvl::Mf75)
    }
}
#[doc = "Field `resvalid` reader - This field is effective only when DCFG.Ena32KHzSusp is set. It will control the resume period when the core resumes from suspend. The core counts for ResValid number of clock cycles to detect a valid resume when this is set"]
pub type ResvalidR = crate::FieldReader;
#[doc = "Field `resvalid` writer - This field is effective only when DCFG.Ena32KHzSusp is set. It will control the resume period when the core resumes from suspend. The core counts for ResValid number of clock cycles to detect a valid resume when this is set"]
pub type ResvalidW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bits 0:1 - Indicates the speed at which the application requires the core to enumerate, or the maximum speed the application can support. However, the actual bus speed is determined only after the chirp sequence is completed, and is based on the speed of the USB host to which the core is connected."]
    #[inline(always)]
    pub fn devspd(&self) -> DevspdR {
        DevspdR::new((self.bits & 3) as u8)
    }
    #[doc = "Bit 2 - The application can use this field to select the handshake the core sends on receiving a nonzero-length data packet during the OUT transaction of a control transfer's Status stage. 1: Send a STALL handshake on a nonzero-length statusOUT transaction and do not send the received OUT packet tothe application. 0: Send the received OUT packet to the application (zerolengthor nonzero-length) and send a handshake based onthe NAK and STALL bits for the endpoint in the DeviceEndpoint Control register."]
    #[inline(always)]
    pub fn nzstsouthshk(&self) -> NzstsouthshkR {
        NzstsouthshkR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend. This bit can only be set if USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero."]
    #[inline(always)]
    pub fn ena32khzsusp(&self) -> Ena32khzsuspR {
        Ena32khzsuspR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 4:10 - The application must program this field after every SetAddress control command."]
    #[inline(always)]
    pub fn devaddr(&self) -> DevaddrR {
        DevaddrR::new(((self.bits >> 4) & 0x7f) as u8)
    }
    #[doc = "Bits 11:12 - Indicates the time within a (micro)frame at which the application must be notified using the End Of Periodic Frame Interrupt. This can be used to determine If all the isochronous traffic for that (micro)frame is complete. 0x0: 80% of the (micro)frame interval 0x1: 85% 0x2: 90% 0x3: 95%"]
    #[inline(always)]
    pub fn perfrint(&self) -> PerfrintR {
        PerfrintR::new(((self.bits >> 11) & 3) as u8)
    }
    #[doc = "Bit 13 - This bit enables setting NAK for Bulk OUT endpoints after the transfer is completed for Device mode Descriptor DMA It is one time programmable after reset like any other DCFG register bits."]
    #[inline(always)]
    pub fn endevoutnak(&self) -> EndevoutnakR {
        EndevoutnakR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 23 - When the Scatter/Gather DMA option selected during configuration of the RTL, the application can Set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset.The following combinations are available for programming: GAHBCFG.DMAEn=0,DCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,DCFG.DescDMA=1 => Invalid GAHBCFG.DMAEn=1,DCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,DCFG.DescDMA=1 => Scatter/Gather DMA mode"]
    #[inline(always)]
    pub fn descdma(&self) -> DescdmaR {
        DescdmaR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bits 24:25 - PerSchIntvl must be programmed only for Scatter/Gather DMAmode. Description: This field specifies the amount of time the Internal DMA engine must allocate for fetching periodic IN endpoint data. Based on the number of periodic endpoints, this value must be specified as 25,50 or 75% of (micro)frame. When any periodic endpoints are active, the internal DMA engine allocates the specified amount of time in fetching periodic IN endpoint data . When no periodic endpoints are active, Then the internal DMA engine services non-periodic endpoints, ignoring this field. After the specified time within a (micro)frame, the DMA switches to fetching for non-periodic endpoints. 2'b00: 25% of (micro)frame. 2'b01: 50% of (micro)frame. 2'b10: 75% of (micro)frame. 2'b11: Reserved.Reset: 2'b00Access: read-write"]
    #[inline(always)]
    pub fn perschintvl(&self) -> PerschintvlR {
        PerschintvlR::new(((self.bits >> 24) & 3) as u8)
    }
    #[doc = "Bits 26:31 - This field is effective only when DCFG.Ena32KHzSusp is set. It will control the resume period when the core resumes from suspend. The core counts for ResValid number of clock cycles to detect a valid resume when this is set"]
    #[inline(always)]
    pub fn resvalid(&self) -> ResvalidR {
        ResvalidR::new(((self.bits >> 26) & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Indicates the speed at which the application requires the core to enumerate, or the maximum speed the application can support. However, the actual bus speed is determined only after the chirp sequence is completed, and is based on the speed of the USB host to which the core is connected."]
    #[inline(always)]
    #[must_use]
    pub fn devspd(&mut self) -> DevspdW<DevgrpDcfgSpec> {
        DevspdW::new(self, 0)
    }
    #[doc = "Bit 2 - The application can use this field to select the handshake the core sends on receiving a nonzero-length data packet during the OUT transaction of a control transfer's Status stage. 1: Send a STALL handshake on a nonzero-length statusOUT transaction and do not send the received OUT packet tothe application. 0: Send the received OUT packet to the application (zerolengthor nonzero-length) and send a handshake based onthe NAK and STALL bits for the endpoint in the DeviceEndpoint Control register."]
    #[inline(always)]
    #[must_use]
    pub fn nzstsouthshk(&mut self) -> NzstsouthshkW<DevgrpDcfgSpec> {
        NzstsouthshkW::new(self, 2)
    }
    #[doc = "Bit 3 - When the USB 1.1 Full-Speed Serial Transceiver Interface is chosen and this bit is set, the core expects the 48-MHz PHY clock to be switched to 32 KHz during a suspend. This bit can only be set if USB 1.1 Full-Speed Serial Transceiver Interface has been selected. If USB 1.1 Full-Speed Serial Transceiver Interface has not been selected, this bit must be zero."]
    #[inline(always)]
    #[must_use]
    pub fn ena32khzsusp(&mut self) -> Ena32khzsuspW<DevgrpDcfgSpec> {
        Ena32khzsuspW::new(self, 3)
    }
    #[doc = "Bits 4:10 - The application must program this field after every SetAddress control command."]
    #[inline(always)]
    #[must_use]
    pub fn devaddr(&mut self) -> DevaddrW<DevgrpDcfgSpec> {
        DevaddrW::new(self, 4)
    }
    #[doc = "Bits 11:12 - Indicates the time within a (micro)frame at which the application must be notified using the End Of Periodic Frame Interrupt. This can be used to determine If all the isochronous traffic for that (micro)frame is complete. 0x0: 80% of the (micro)frame interval 0x1: 85% 0x2: 90% 0x3: 95%"]
    #[inline(always)]
    #[must_use]
    pub fn perfrint(&mut self) -> PerfrintW<DevgrpDcfgSpec> {
        PerfrintW::new(self, 11)
    }
    #[doc = "Bit 13 - This bit enables setting NAK for Bulk OUT endpoints after the transfer is completed for Device mode Descriptor DMA It is one time programmable after reset like any other DCFG register bits."]
    #[inline(always)]
    #[must_use]
    pub fn endevoutnak(&mut self) -> EndevoutnakW<DevgrpDcfgSpec> {
        EndevoutnakW::new(self, 13)
    }
    #[doc = "Bit 23 - When the Scatter/Gather DMA option selected during configuration of the RTL, the application can Set this bit during initialization to enable the Scatter/Gather DMA operation. This bit must be modified only once after a reset.The following combinations are available for programming: GAHBCFG.DMAEn=0,DCFG.DescDMA=0 => Slave mode GAHBCFG.DMAEn=0,DCFG.DescDMA=1 => Invalid GAHBCFG.DMAEn=1,DCFG.DescDMA=0 => Buffered DMA mode GAHBCFG.DMAEn=1,DCFG.DescDMA=1 => Scatter/Gather DMA mode"]
    #[inline(always)]
    #[must_use]
    pub fn descdma(&mut self) -> DescdmaW<DevgrpDcfgSpec> {
        DescdmaW::new(self, 23)
    }
    #[doc = "Bits 24:25 - PerSchIntvl must be programmed only for Scatter/Gather DMAmode. Description: This field specifies the amount of time the Internal DMA engine must allocate for fetching periodic IN endpoint data. Based on the number of periodic endpoints, this value must be specified as 25,50 or 75% of (micro)frame. When any periodic endpoints are active, the internal DMA engine allocates the specified amount of time in fetching periodic IN endpoint data . When no periodic endpoints are active, Then the internal DMA engine services non-periodic endpoints, ignoring this field. After the specified time within a (micro)frame, the DMA switches to fetching for non-periodic endpoints. 2'b00: 25% of (micro)frame. 2'b01: 50% of (micro)frame. 2'b10: 75% of (micro)frame. 2'b11: Reserved.Reset: 2'b00Access: read-write"]
    #[inline(always)]
    #[must_use]
    pub fn perschintvl(&mut self) -> PerschintvlW<DevgrpDcfgSpec> {
        PerschintvlW::new(self, 24)
    }
    #[doc = "Bits 26:31 - This field is effective only when DCFG.Ena32KHzSusp is set. It will control the resume period when the core resumes from suspend. The core counts for ResValid number of clock cycles to detect a valid resume when this is set"]
    #[inline(always)]
    #[must_use]
    pub fn resvalid(&mut self) -> ResvalidW<DevgrpDcfgSpec> {
        ResvalidW::new(self, 26)
    }
}
#[doc = "This register configures the core in Device mode after power-on or after certain control commands or enumeration. Do not make changes to this register after initial programming.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDcfgSpec;
impl crate::RegisterSpec for DevgrpDcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 2048u64;
}
#[doc = "`read()` method returns [`devgrp_dcfg::R`](R) reader structure"]
impl crate::Readable for DevgrpDcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_dcfg::W`](W) writer structure"]
impl crate::Writable for DevgrpDcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets devgrp_dcfg to value 0x0800_0000"]
impl crate::Resettable for DevgrpDcfgSpec {
    const RESET_VALUE: u32 = 0x0800_0000;
}
