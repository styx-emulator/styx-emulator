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
#[doc = "Register `dmagrp_Status` reader"]
pub type R = crate::R<DmagrpStatusSpec>;
#[doc = "Register `dmagrp_Status` writer"]
pub type W = crate::W<DmagrpStatusSpec>;
#[doc = "Field `ti` reader - This bit indicates that the frame transmission is complete. When transmission is complete, the Bit 31 (Interrupt on Completion) of TDES1 is reset in the first descriptor, and the specific frame status information is updated in the descriptor."]
pub type TiR = crate::BitReader;
#[doc = "Field `ti` writer - This bit indicates that the frame transmission is complete. When transmission is complete, the Bit 31 (Interrupt on Completion) of TDES1 is reset in the first descriptor, and the specific frame status information is updated in the descriptor."]
pub type TiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `tps` reader - This bit is set when the transmission is stopped."]
pub type TpsR = crate::BitReader;
#[doc = "Field `tps` writer - This bit is set when the transmission is stopped."]
pub type TpsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `tu` reader - This bit indicates that the host owns the Next Descriptor in the Transmit List and the DMA cannot acquire it. Transmission is suspended. Bits\\[22:20\\]
explain the Transmit Process state transitions. To resume processing Transmit descriptors, the host should change the ownership of the descriptor by setting TDES0\\[31\\]
and then issue a Transmit Poll Demand command."]
pub type TuR = crate::BitReader;
#[doc = "Field `tu` writer - This bit indicates that the host owns the Next Descriptor in the Transmit List and the DMA cannot acquire it. Transmission is suspended. Bits\\[22:20\\]
explain the Transmit Process state transitions. To resume processing Transmit descriptors, the host should change the ownership of the descriptor by setting TDES0\\[31\\]
and then issue a Transmit Poll Demand command."]
pub type TuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `tjt` reader - This bit indicates that the Transmit Jabber Timer expired, which happens when the frame size exceeds 2,048 (10,240 bytes when the Jumbo frame is enabled). When the Jabber Timeout occurs, the transmission process is aborted and placed in the Stopped state. This causes the Transmit Jabber Timeout TDES0\\[14\\]
flag to assert."]
pub type TjtR = crate::BitReader;
#[doc = "Field `tjt` writer - This bit indicates that the Transmit Jabber Timer expired, which happens when the frame size exceeds 2,048 (10,240 bytes when the Jumbo frame is enabled). When the Jabber Timeout occurs, the transmission process is aborted and placed in the Stopped state. This causes the Transmit Jabber Timeout TDES0\\[14\\]
flag to assert."]
pub type TjtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ovf` reader - This bit indicates that the Receive Buffer had an Overflow during frame reception. If the partial frame is transferred to the application, the overflow status is set in RDES0\\[11\\]."]
pub type OvfR = crate::BitReader;
#[doc = "Field `ovf` writer - This bit indicates that the Receive Buffer had an Overflow during frame reception. If the partial frame is transferred to the application, the overflow status is set in RDES0\\[11\\]."]
pub type OvfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `unf` reader - This bit indicates that the Transmit Buffer had an Underflow during frame transmission. Transmission is suspended and an Underflow Error TDES0\\[1\\]
is set."]
pub type UnfR = crate::BitReader;
#[doc = "Field `unf` writer - This bit indicates that the Transmit Buffer had an Underflow during frame transmission. Transmission is suspended and an Underflow Error TDES0\\[1\\]
is set."]
pub type UnfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ri` reader - This bit indicates that the frame reception is complete. When reception is complete, the Bit 31 of RDES1 (Disable Interrupt on Completion) is reset in the last Descriptor, and the specific frame status information is updated in the descriptor. The reception remains in the Running state."]
pub type RiR = crate::BitReader;
#[doc = "Field `ri` writer - This bit indicates that the frame reception is complete. When reception is complete, the Bit 31 of RDES1 (Disable Interrupt on Completion) is reset in the last Descriptor, and the specific frame status information is updated in the descriptor. The reception remains in the Running state."]
pub type RiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ru` reader - This bit indicates that the host owns the Next Descriptor in the Receive List and the DMA cannot acquire it. The Receive Process is suspended. To resume processing Receive descriptors, the host should change the ownership of the descriptor and issue a Receive Poll Demand command. If no Receive Poll Demand is issued, the Receive Process resumes when the next recognized incoming frame is received. This bit is set only when the previous Receive Descriptor is owned by the DMA."]
pub type RuR = crate::BitReader;
#[doc = "Field `ru` writer - This bit indicates that the host owns the Next Descriptor in the Receive List and the DMA cannot acquire it. The Receive Process is suspended. To resume processing Receive descriptors, the host should change the ownership of the descriptor and issue a Receive Poll Demand command. If no Receive Poll Demand is issued, the Receive Process resumes when the next recognized incoming frame is received. This bit is set only when the previous Receive Descriptor is owned by the DMA."]
pub type RuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rps` reader - This bit is asserted when the Receive Process enters the Stopped state."]
pub type RpsR = crate::BitReader;
#[doc = "Field `rps` writer - This bit is asserted when the Receive Process enters the Stopped state."]
pub type RpsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `rwt` reader - This bit is asserted when a frame with length greater than 2,048 bytes is received (10, 240 when Jumbo Frame mode is enabled)."]
pub type RwtR = crate::BitReader;
#[doc = "Field `rwt` writer - This bit is asserted when a frame with length greater than 2,048 bytes is received (10, 240 when Jumbo Frame mode is enabled)."]
pub type RwtW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `eti` reader - This bit indicates that the frame to be transmitted is fully transferred to the MTL Transmit FIFO."]
pub type EtiR = crate::BitReader;
#[doc = "Field `eti` writer - This bit indicates that the frame to be transmitted is fully transferred to the MTL Transmit FIFO."]
pub type EtiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fbi` reader - This bit indicates that a bus error occurred, as described in Bits\\[25:23\\]. When this bit is set, the corresponding DMA engine disables all of its bus accesses."]
pub type FbiR = crate::BitReader;
#[doc = "Field `fbi` writer - This bit indicates that a bus error occurred, as described in Bits\\[25:23\\]. When this bit is set, the corresponding DMA engine disables all of its bus accesses."]
pub type FbiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `eri` reader - This bit indicates that the DMA had filled the first data buffer of the packet. Bit 6 (RI) of this register automatically clears this bit."]
pub type EriR = crate::BitReader;
#[doc = "Field `eri` writer - This bit indicates that the DMA had filled the first data buffer of the packet. Bit 6 (RI) of this register automatically clears this bit."]
pub type EriW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ais` reader - Abnormal Interrupt Summary bit value is the logical OR of the following when the corresponding interrupt bits are enabled in Register 7 (Interrupt Enable Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive FIFO Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error Only unmasked bits affect the Abnormal Interrupt Summary bit. This is a sticky bit and must be cleared each time a corresponding bit, which causes AIS to be set, is cleared."]
pub type AisR = crate::BitReader;
#[doc = "Field `ais` writer - Abnormal Interrupt Summary bit value is the logical OR of the following when the corresponding interrupt bits are enabled in Register 7 (Interrupt Enable Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive FIFO Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error Only unmasked bits affect the Abnormal Interrupt Summary bit. This is a sticky bit and must be cleared each time a corresponding bit, which causes AIS to be set, is cleared."]
pub type AisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `nis` reader - Normal Interrupt Summary bit value is the logical OR of the following when the corresponding interrupt bits are enabled in Register 7 (Interrupt Enable Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt Only unmasked bits (interrupts for which interrupt enable is set in Register 7) affect the Normal Interrupt Summary bit. This is a sticky bit and must be cleared (by writing 1 to this bit) each time a corresponding bit, which causes NIS to be set, is cleared."]
pub type NisR = crate::BitReader;
#[doc = "Field `nis` writer - Normal Interrupt Summary bit value is the logical OR of the following when the corresponding interrupt bits are enabled in Register 7 (Interrupt Enable Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt Only unmasked bits (interrupts for which interrupt enable is set in Register 7) affect the Normal Interrupt Summary bit. This is a sticky bit and must be cleared (by writing 1 to this bit) each time a corresponding bit, which causes NIS to be set, is cleared."]
pub type NisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This field indicates the Receive DMA FSM state. This field does not generate an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rs {
    #[doc = "0: `0`"]
    Stopped = 0,
    #[doc = "1: `1`"]
    Runfetch = 1,
    #[doc = "2: `10`"]
    Reserve = 2,
    #[doc = "3: `11`"]
    Runwait = 3,
    #[doc = "4: `100`"]
    Suspend = 4,
    #[doc = "5: `101`"]
    Runclose = 5,
    #[doc = "6: `110`"]
    Timestmp = 6,
    #[doc = "7: `111`"]
    Runtrans = 7,
}
impl From<Rs> for u8 {
    #[inline(always)]
    fn from(variant: Rs) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rs {
    type Ux = u8;
}
#[doc = "Field `rs` reader - This field indicates the Receive DMA FSM state. This field does not generate an interrupt."]
pub type RsR = crate::FieldReader<Rs>;
impl RsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rs {
        match self.bits {
            0 => Rs::Stopped,
            1 => Rs::Runfetch,
            2 => Rs::Reserve,
            3 => Rs::Runwait,
            4 => Rs::Suspend,
            5 => Rs::Runclose,
            6 => Rs::Timestmp,
            7 => Rs::Runtrans,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_stopped(&self) -> bool {
        *self == Rs::Stopped
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_runfetch(&self) -> bool {
        *self == Rs::Runfetch
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_reserve(&self) -> bool {
        *self == Rs::Reserve
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_runwait(&self) -> bool {
        *self == Rs::Runwait
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_suspend(&self) -> bool {
        *self == Rs::Suspend
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_runclose(&self) -> bool {
        *self == Rs::Runclose
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_timestmp(&self) -> bool {
        *self == Rs::Timestmp
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_runtrans(&self) -> bool {
        *self == Rs::Runtrans
    }
}
#[doc = "Field `rs` writer - This field indicates the Receive DMA FSM state. This field does not generate an interrupt."]
pub type RsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "This field indicates the Transmit DMA FSM state. This field does not generate an interrupt.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ts {
    #[doc = "0: `0`"]
    Stopped = 0,
    #[doc = "1: `1`"]
    Runfetch = 1,
    #[doc = "2: `10`"]
    Runwait = 2,
    #[doc = "3: `11`"]
    Runread = 3,
    #[doc = "4: `100`"]
    Timestmp = 4,
    #[doc = "5: `101`"]
    Reserve = 5,
    #[doc = "6: `110`"]
    Susptx = 6,
    #[doc = "7: `111`"]
    Runclose = 7,
}
impl From<Ts> for u8 {
    #[inline(always)]
    fn from(variant: Ts) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ts {
    type Ux = u8;
}
#[doc = "Field `ts` reader - This field indicates the Transmit DMA FSM state. This field does not generate an interrupt."]
pub type TsR = crate::FieldReader<Ts>;
impl TsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Ts {
        match self.bits {
            0 => Ts::Stopped,
            1 => Ts::Runfetch,
            2 => Ts::Runwait,
            3 => Ts::Runread,
            4 => Ts::Timestmp,
            5 => Ts::Reserve,
            6 => Ts::Susptx,
            7 => Ts::Runclose,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_stopped(&self) -> bool {
        *self == Ts::Stopped
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_runfetch(&self) -> bool {
        *self == Ts::Runfetch
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_runwait(&self) -> bool {
        *self == Ts::Runwait
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_runread(&self) -> bool {
        *self == Ts::Runread
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_timestmp(&self) -> bool {
        *self == Ts::Timestmp
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserve(&self) -> bool {
        *self == Ts::Reserve
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_susptx(&self) -> bool {
        *self == Ts::Susptx
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_runclose(&self) -> bool {
        *self == Ts::Runclose
    }
}
#[doc = "Field `ts` writer - This field indicates the Transmit DMA FSM state. This field does not generate an interrupt."]
pub type TsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `eb` reader - This field indicates the type of error that caused a Bus Error, for example, error response on the AHB or AXI interface. This field is valid only when Bit 13 (FBI) is set. This field does not generate an interrupt. * Bit 23 - 1'b1: Error during data transfer by the Tx DMA - 1'b0: Error during data transfer by the Rx DMA * Bit 24 - 1'b1: Error during read transfer - 1'b0: Error during write transfer * Bit 25 - 1'b1: Error during descriptor access - 1'b0: Error during data buffer access"]
pub type EbR = crate::FieldReader;
#[doc = "Field `eb` writer - This field indicates the type of error that caused a Bus Error, for example, error response on the AHB or AXI interface. This field is valid only when Bit 13 (FBI) is set. This field does not generate an interrupt. * Bit 23 - 1'b1: Error during data transfer by the Tx DMA - 1'b0: Error during data transfer by the Rx DMA * Bit 24 - 1'b1: Error during read transfer - 1'b0: Error during write transfer * Bit 25 - 1'b1: Error during descriptor access - 1'b0: Error during data buffer access"]
pub type EbW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "This bit reflects an interrupt event in the PCS (link change and AN complete), SMII (link change), or RGMII (link change) interface block of the EMAC. The software must read the corresponding registers (Register 49 for PCS or Register 54 for SMII or RGMII) in the EMAC to get the exact cause of the interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gli {
    #[doc = "0: `0`"]
    Nointerrup = 0,
    #[doc = "1: `1`"]
    Interrup = 1,
}
impl From<Gli> for bool {
    #[inline(always)]
    fn from(variant: Gli) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gli` reader - This bit reflects an interrupt event in the PCS (link change and AN complete), SMII (link change), or RGMII (link change) interface block of the EMAC. The software must read the corresponding registers (Register 49 for PCS or Register 54 for SMII or RGMII) in the EMAC to get the exact cause of the interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high."]
pub type GliR = crate::BitReader<Gli>;
impl GliR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Gli {
        match self.bits {
            false => Gli::Nointerrup,
            true => Gli::Interrup,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrup(&self) -> bool {
        *self == Gli::Nointerrup
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interrup(&self) -> bool {
        *self == Gli::Interrup
    }
}
#[doc = "Field `gli` writer - This bit reflects an interrupt event in the PCS (link change and AN complete), SMII (link change), or RGMII (link change) interface block of the EMAC. The software must read the corresponding registers (Register 49 for PCS or Register 54 for SMII or RGMII) in the EMAC to get the exact cause of the interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high."]
pub type GliW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit reflects an interrupt event in the MMC block of the EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gmi {
    #[doc = "0: `0`"]
    Nointerrup = 0,
    #[doc = "1: `1`"]
    Interrup = 1,
}
impl From<Gmi> for bool {
    #[inline(always)]
    fn from(variant: Gmi) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gmi` reader - This bit reflects an interrupt event in the MMC block of the EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high."]
pub type GmiR = crate::BitReader<Gmi>;
impl GmiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Gmi {
        match self.bits {
            false => Gmi::Nointerrup,
            true => Gmi::Interrup,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrup(&self) -> bool {
        *self == Gmi::Nointerrup
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interrup(&self) -> bool {
        *self == Gmi::Interrup
    }
}
#[doc = "Field `gmi` writer - This bit reflects an interrupt event in the MMC block of the EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high."]
pub type GmiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit indicates an interrupt event in the Timestamp Generator block of EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear its source to reset this bit to 1'b0. When this bit is high, the interrupt signal from the EMAC subsystem (sbd_intr_o) is high.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tti {
    #[doc = "0: `0`"]
    Nointerrup = 0,
    #[doc = "1: `1`"]
    Interrup = 1,
}
impl From<Tti> for bool {
    #[inline(always)]
    fn from(variant: Tti) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `tti` reader - This bit indicates an interrupt event in the Timestamp Generator block of EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear its source to reset this bit to 1'b0. When this bit is high, the interrupt signal from the EMAC subsystem (sbd_intr_o) is high."]
pub type TtiR = crate::BitReader<Tti>;
impl TtiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Tti {
        match self.bits {
            false => Tti::Nointerrup,
            true => Tti::Interrup,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrup(&self) -> bool {
        *self == Tti::Nointerrup
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interrup(&self) -> bool {
        *self == Tti::Interrup
    }
}
#[doc = "Field `tti` writer - This bit indicates an interrupt event in the Timestamp Generator block of EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear its source to reset this bit to 1'b0. When this bit is high, the interrupt signal from the EMAC subsystem (sbd_intr_o) is high."]
pub type TtiW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "This bit indicates an interrupt event in the LPI logic of the EMAC. To reset this bit to 1'b0, the software must read the corresponding registers in the EMAC to get the exact cause of the interrupt and clear its source. When this bit is high, the interrupt signal from the MAC (sbd_intr_o) is high.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glpii {
    #[doc = "0: `0`"]
    Nointerrup = 0,
    #[doc = "1: `1`"]
    Interrup = 1,
}
impl From<Glpii> for bool {
    #[inline(always)]
    fn from(variant: Glpii) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `glpii` reader - This bit indicates an interrupt event in the LPI logic of the EMAC. To reset this bit to 1'b0, the software must read the corresponding registers in the EMAC to get the exact cause of the interrupt and clear its source. When this bit is high, the interrupt signal from the MAC (sbd_intr_o) is high."]
pub type GlpiiR = crate::BitReader<Glpii>;
impl GlpiiR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Glpii {
        match self.bits {
            false => Glpii::Nointerrup,
            true => Glpii::Interrup,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nointerrup(&self) -> bool {
        *self == Glpii::Nointerrup
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_interrup(&self) -> bool {
        *self == Glpii::Interrup
    }
}
#[doc = "Field `glpii` writer - This bit indicates an interrupt event in the LPI logic of the EMAC. To reset this bit to 1'b0, the software must read the corresponding registers in the EMAC to get the exact cause of the interrupt and clear its source. When this bit is high, the interrupt signal from the MAC (sbd_intr_o) is high."]
pub type GlpiiW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit indicates that the frame transmission is complete. When transmission is complete, the Bit 31 (Interrupt on Completion) of TDES1 is reset in the first descriptor, and the specific frame status information is updated in the descriptor."]
    #[inline(always)]
    pub fn ti(&self) -> TiR {
        TiR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit is set when the transmission is stopped."]
    #[inline(always)]
    pub fn tps(&self) -> TpsR {
        TpsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - This bit indicates that the host owns the Next Descriptor in the Transmit List and the DMA cannot acquire it. Transmission is suspended. Bits\\[22:20\\]
explain the Transmit Process state transitions. To resume processing Transmit descriptors, the host should change the ownership of the descriptor by setting TDES0\\[31\\]
and then issue a Transmit Poll Demand command."]
    #[inline(always)]
    pub fn tu(&self) -> TuR {
        TuR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit indicates that the Transmit Jabber Timer expired, which happens when the frame size exceeds 2,048 (10,240 bytes when the Jumbo frame is enabled). When the Jabber Timeout occurs, the transmission process is aborted and placed in the Stopped state. This causes the Transmit Jabber Timeout TDES0\\[14\\]
flag to assert."]
    #[inline(always)]
    pub fn tjt(&self) -> TjtR {
        TjtR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit indicates that the Receive Buffer had an Overflow during frame reception. If the partial frame is transferred to the application, the overflow status is set in RDES0\\[11\\]."]
    #[inline(always)]
    pub fn ovf(&self) -> OvfR {
        OvfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - This bit indicates that the Transmit Buffer had an Underflow during frame transmission. Transmission is suspended and an Underflow Error TDES0\\[1\\]
is set."]
    #[inline(always)]
    pub fn unf(&self) -> UnfR {
        UnfR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This bit indicates that the frame reception is complete. When reception is complete, the Bit 31 of RDES1 (Disable Interrupt on Completion) is reset in the last Descriptor, and the specific frame status information is updated in the descriptor. The reception remains in the Running state."]
    #[inline(always)]
    pub fn ri(&self) -> RiR {
        RiR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This bit indicates that the host owns the Next Descriptor in the Receive List and the DMA cannot acquire it. The Receive Process is suspended. To resume processing Receive descriptors, the host should change the ownership of the descriptor and issue a Receive Poll Demand command. If no Receive Poll Demand is issued, the Receive Process resumes when the next recognized incoming frame is received. This bit is set only when the previous Receive Descriptor is owned by the DMA."]
    #[inline(always)]
    pub fn ru(&self) -> RuR {
        RuR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - This bit is asserted when the Receive Process enters the Stopped state."]
    #[inline(always)]
    pub fn rps(&self) -> RpsR {
        RpsR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - This bit is asserted when a frame with length greater than 2,048 bytes is received (10, 240 when Jumbo Frame mode is enabled)."]
    #[inline(always)]
    pub fn rwt(&self) -> RwtR {
        RwtR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This bit indicates that the frame to be transmitted is fully transferred to the MTL Transmit FIFO."]
    #[inline(always)]
    pub fn eti(&self) -> EtiR {
        EtiR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 13 - This bit indicates that a bus error occurred, as described in Bits\\[25:23\\]. When this bit is set, the corresponding DMA engine disables all of its bus accesses."]
    #[inline(always)]
    pub fn fbi(&self) -> FbiR {
        FbiR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - This bit indicates that the DMA had filled the first data buffer of the packet. Bit 6 (RI) of this register automatically clears this bit."]
    #[inline(always)]
    pub fn eri(&self) -> EriR {
        EriR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Abnormal Interrupt Summary bit value is the logical OR of the following when the corresponding interrupt bits are enabled in Register 7 (Interrupt Enable Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive FIFO Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error Only unmasked bits affect the Abnormal Interrupt Summary bit. This is a sticky bit and must be cleared each time a corresponding bit, which causes AIS to be set, is cleared."]
    #[inline(always)]
    pub fn ais(&self) -> AisR {
        AisR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Normal Interrupt Summary bit value is the logical OR of the following when the corresponding interrupt bits are enabled in Register 7 (Interrupt Enable Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt Only unmasked bits (interrupts for which interrupt enable is set in Register 7) affect the Normal Interrupt Summary bit. This is a sticky bit and must be cleared (by writing 1 to this bit) each time a corresponding bit, which causes NIS to be set, is cleared."]
    #[inline(always)]
    pub fn nis(&self) -> NisR {
        NisR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:19 - This field indicates the Receive DMA FSM state. This field does not generate an interrupt."]
    #[inline(always)]
    pub fn rs(&self) -> RsR {
        RsR::new(((self.bits >> 17) & 7) as u8)
    }
    #[doc = "Bits 20:22 - This field indicates the Transmit DMA FSM state. This field does not generate an interrupt."]
    #[inline(always)]
    pub fn ts(&self) -> TsR {
        TsR::new(((self.bits >> 20) & 7) as u8)
    }
    #[doc = "Bits 23:25 - This field indicates the type of error that caused a Bus Error, for example, error response on the AHB or AXI interface. This field is valid only when Bit 13 (FBI) is set. This field does not generate an interrupt. * Bit 23 - 1'b1: Error during data transfer by the Tx DMA - 1'b0: Error during data transfer by the Rx DMA * Bit 24 - 1'b1: Error during read transfer - 1'b0: Error during write transfer * Bit 25 - 1'b1: Error during descriptor access - 1'b0: Error during data buffer access"]
    #[inline(always)]
    pub fn eb(&self) -> EbR {
        EbR::new(((self.bits >> 23) & 7) as u8)
    }
    #[doc = "Bit 26 - This bit reflects an interrupt event in the PCS (link change and AN complete), SMII (link change), or RGMII (link change) interface block of the EMAC. The software must read the corresponding registers (Register 49 for PCS or Register 54 for SMII or RGMII) in the EMAC to get the exact cause of the interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high."]
    #[inline(always)]
    pub fn gli(&self) -> GliR {
        GliR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - This bit reflects an interrupt event in the MMC block of the EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high."]
    #[inline(always)]
    pub fn gmi(&self) -> GmiR {
        GmiR::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 29 - This bit indicates an interrupt event in the Timestamp Generator block of EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear its source to reset this bit to 1'b0. When this bit is high, the interrupt signal from the EMAC subsystem (sbd_intr_o) is high."]
    #[inline(always)]
    pub fn tti(&self) -> TtiR {
        TtiR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - This bit indicates an interrupt event in the LPI logic of the EMAC. To reset this bit to 1'b0, the software must read the corresponding registers in the EMAC to get the exact cause of the interrupt and clear its source. When this bit is high, the interrupt signal from the MAC (sbd_intr_o) is high."]
    #[inline(always)]
    pub fn glpii(&self) -> GlpiiR {
        GlpiiR::new(((self.bits >> 30) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit indicates that the frame transmission is complete. When transmission is complete, the Bit 31 (Interrupt on Completion) of TDES1 is reset in the first descriptor, and the specific frame status information is updated in the descriptor."]
    #[inline(always)]
    #[must_use]
    pub fn ti(&mut self) -> TiW<DmagrpStatusSpec> {
        TiW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit is set when the transmission is stopped."]
    #[inline(always)]
    #[must_use]
    pub fn tps(&mut self) -> TpsW<DmagrpStatusSpec> {
        TpsW::new(self, 1)
    }
    #[doc = "Bit 2 - This bit indicates that the host owns the Next Descriptor in the Transmit List and the DMA cannot acquire it. Transmission is suspended. Bits\\[22:20\\]
explain the Transmit Process state transitions. To resume processing Transmit descriptors, the host should change the ownership of the descriptor by setting TDES0\\[31\\]
and then issue a Transmit Poll Demand command."]
    #[inline(always)]
    #[must_use]
    pub fn tu(&mut self) -> TuW<DmagrpStatusSpec> {
        TuW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit indicates that the Transmit Jabber Timer expired, which happens when the frame size exceeds 2,048 (10,240 bytes when the Jumbo frame is enabled). When the Jabber Timeout occurs, the transmission process is aborted and placed in the Stopped state. This causes the Transmit Jabber Timeout TDES0\\[14\\]
flag to assert."]
    #[inline(always)]
    #[must_use]
    pub fn tjt(&mut self) -> TjtW<DmagrpStatusSpec> {
        TjtW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit indicates that the Receive Buffer had an Overflow during frame reception. If the partial frame is transferred to the application, the overflow status is set in RDES0\\[11\\]."]
    #[inline(always)]
    #[must_use]
    pub fn ovf(&mut self) -> OvfW<DmagrpStatusSpec> {
        OvfW::new(self, 4)
    }
    #[doc = "Bit 5 - This bit indicates that the Transmit Buffer had an Underflow during frame transmission. Transmission is suspended and an Underflow Error TDES0\\[1\\]
is set."]
    #[inline(always)]
    #[must_use]
    pub fn unf(&mut self) -> UnfW<DmagrpStatusSpec> {
        UnfW::new(self, 5)
    }
    #[doc = "Bit 6 - This bit indicates that the frame reception is complete. When reception is complete, the Bit 31 of RDES1 (Disable Interrupt on Completion) is reset in the last Descriptor, and the specific frame status information is updated in the descriptor. The reception remains in the Running state."]
    #[inline(always)]
    #[must_use]
    pub fn ri(&mut self) -> RiW<DmagrpStatusSpec> {
        RiW::new(self, 6)
    }
    #[doc = "Bit 7 - This bit indicates that the host owns the Next Descriptor in the Receive List and the DMA cannot acquire it. The Receive Process is suspended. To resume processing Receive descriptors, the host should change the ownership of the descriptor and issue a Receive Poll Demand command. If no Receive Poll Demand is issued, the Receive Process resumes when the next recognized incoming frame is received. This bit is set only when the previous Receive Descriptor is owned by the DMA."]
    #[inline(always)]
    #[must_use]
    pub fn ru(&mut self) -> RuW<DmagrpStatusSpec> {
        RuW::new(self, 7)
    }
    #[doc = "Bit 8 - This bit is asserted when the Receive Process enters the Stopped state."]
    #[inline(always)]
    #[must_use]
    pub fn rps(&mut self) -> RpsW<DmagrpStatusSpec> {
        RpsW::new(self, 8)
    }
    #[doc = "Bit 9 - This bit is asserted when a frame with length greater than 2,048 bytes is received (10, 240 when Jumbo Frame mode is enabled)."]
    #[inline(always)]
    #[must_use]
    pub fn rwt(&mut self) -> RwtW<DmagrpStatusSpec> {
        RwtW::new(self, 9)
    }
    #[doc = "Bit 10 - This bit indicates that the frame to be transmitted is fully transferred to the MTL Transmit FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn eti(&mut self) -> EtiW<DmagrpStatusSpec> {
        EtiW::new(self, 10)
    }
    #[doc = "Bit 13 - This bit indicates that a bus error occurred, as described in Bits\\[25:23\\]. When this bit is set, the corresponding DMA engine disables all of its bus accesses."]
    #[inline(always)]
    #[must_use]
    pub fn fbi(&mut self) -> FbiW<DmagrpStatusSpec> {
        FbiW::new(self, 13)
    }
    #[doc = "Bit 14 - This bit indicates that the DMA had filled the first data buffer of the packet. Bit 6 (RI) of this register automatically clears this bit."]
    #[inline(always)]
    #[must_use]
    pub fn eri(&mut self) -> EriW<DmagrpStatusSpec> {
        EriW::new(self, 14)
    }
    #[doc = "Bit 15 - Abnormal Interrupt Summary bit value is the logical OR of the following when the corresponding interrupt bits are enabled in Register 7 (Interrupt Enable Register): * Register 5\\[1\\]: Transmit Process Stopped * Register 5\\[3\\]: Transmit Jabber Timeout * Register 5\\[4\\]: Receive FIFO Overflow * Register 5\\[5\\]: Transmit Underflow * Register 5\\[7\\]: Receive Buffer Unavailable * Register 5\\[8\\]: Receive Process Stopped * Register 5\\[9\\]: Receive Watchdog Timeout * Register 5\\[10\\]: Early Transmit Interrupt * Register 5\\[13\\]: Fatal Bus Error Only unmasked bits affect the Abnormal Interrupt Summary bit. This is a sticky bit and must be cleared each time a corresponding bit, which causes AIS to be set, is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn ais(&mut self) -> AisW<DmagrpStatusSpec> {
        AisW::new(self, 15)
    }
    #[doc = "Bit 16 - Normal Interrupt Summary bit value is the logical OR of the following when the corresponding interrupt bits are enabled in Register 7 (Interrupt Enable Register): * Register 5\\[0\\]: Transmit Interrupt * Register 5\\[2\\]: Transmit Buffer Unavailable * Register 5\\[6\\]: Receive Interrupt * Register 5\\[14\\]: Early Receive Interrupt Only unmasked bits (interrupts for which interrupt enable is set in Register 7) affect the Normal Interrupt Summary bit. This is a sticky bit and must be cleared (by writing 1 to this bit) each time a corresponding bit, which causes NIS to be set, is cleared."]
    #[inline(always)]
    #[must_use]
    pub fn nis(&mut self) -> NisW<DmagrpStatusSpec> {
        NisW::new(self, 16)
    }
    #[doc = "Bits 17:19 - This field indicates the Receive DMA FSM state. This field does not generate an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn rs(&mut self) -> RsW<DmagrpStatusSpec> {
        RsW::new(self, 17)
    }
    #[doc = "Bits 20:22 - This field indicates the Transmit DMA FSM state. This field does not generate an interrupt."]
    #[inline(always)]
    #[must_use]
    pub fn ts(&mut self) -> TsW<DmagrpStatusSpec> {
        TsW::new(self, 20)
    }
    #[doc = "Bits 23:25 - This field indicates the type of error that caused a Bus Error, for example, error response on the AHB or AXI interface. This field is valid only when Bit 13 (FBI) is set. This field does not generate an interrupt. * Bit 23 - 1'b1: Error during data transfer by the Tx DMA - 1'b0: Error during data transfer by the Rx DMA * Bit 24 - 1'b1: Error during read transfer - 1'b0: Error during write transfer * Bit 25 - 1'b1: Error during descriptor access - 1'b0: Error during data buffer access"]
    #[inline(always)]
    #[must_use]
    pub fn eb(&mut self) -> EbW<DmagrpStatusSpec> {
        EbW::new(self, 23)
    }
    #[doc = "Bit 26 - This bit reflects an interrupt event in the PCS (link change and AN complete), SMII (link change), or RGMII (link change) interface block of the EMAC. The software must read the corresponding registers (Register 49 for PCS or Register 54 for SMII or RGMII) in the EMAC to get the exact cause of the interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high."]
    #[inline(always)]
    #[must_use]
    pub fn gli(&mut self) -> GliW<DmagrpStatusSpec> {
        GliW::new(self, 26)
    }
    #[doc = "Bit 27 - This bit reflects an interrupt event in the MMC block of the EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear the source of interrupt to make this bit as 1'b0. The interrupt signal from the EMAC subsystem (sbd_intr_o) is high when this bit is high."]
    #[inline(always)]
    #[must_use]
    pub fn gmi(&mut self) -> GmiW<DmagrpStatusSpec> {
        GmiW::new(self, 27)
    }
    #[doc = "Bit 29 - This bit indicates an interrupt event in the Timestamp Generator block of EMAC. The software must read the corresponding registers in the EMAC to get the exact cause of interrupt and clear its source to reset this bit to 1'b0. When this bit is high, the interrupt signal from the EMAC subsystem (sbd_intr_o) is high."]
    #[inline(always)]
    #[must_use]
    pub fn tti(&mut self) -> TtiW<DmagrpStatusSpec> {
        TtiW::new(self, 29)
    }
    #[doc = "Bit 30 - This bit indicates an interrupt event in the LPI logic of the EMAC. To reset this bit to 1'b0, the software must read the corresponding registers in the EMAC to get the exact cause of the interrupt and clear its source. When this bit is high, the interrupt signal from the MAC (sbd_intr_o) is high."]
    #[inline(always)]
    #[must_use]
    pub fn glpii(&mut self) -> GlpiiW<DmagrpStatusSpec> {
        GlpiiW::new(self, 30)
    }
}
#[doc = "The Status register contains all status bits that the DMA reports to the host. The software driver reads this register during an interrupt service routine or polling. Most of the fields in this register cause the host to be interrupted. The bits of this register are not cleared when read. Writing 1'b1 to (unreserved) Bits\\[16:0\\]
of this register clears these bits and writing 1'b0 has no effect. Each field (Bits\\[16:0\\]) can be masked by masking the appropriate bit in Register 7 (Interrupt Enable Register).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_status::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_status::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpStatusSpec;
impl crate::RegisterSpec for DmagrpStatusSpec {
    type Ux = u32;
    const OFFSET: u64 = 4116u64;
}
#[doc = "`read()` method returns [`dmagrp_status::R`](R) reader structure"]
impl crate::Readable for DmagrpStatusSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_status::W`](W) writer structure"]
impl crate::Writable for DmagrpStatusSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Status to value 0"]
impl crate::Resettable for DmagrpStatusSpec {
    const RESET_VALUE: u32 = 0;
}
