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
#[doc = "Register `dmagrp_Bus_Mode` reader"]
pub type R = crate::R<DmagrpBusModeSpec>;
#[doc = "Register `dmagrp_Bus_Mode` writer"]
pub type W = crate::W<DmagrpBusModeSpec>;
#[doc = "When this bit is set, the MAC DMA Controller resets the logic and all internal registers of the MAC. It is cleared automatically after the reset operation has completed in all of the EMAC clock domains. Before reprogramming any register of the EMAC, you should read a zero (0) value in this bit . Note: * The Software reset function is driven only by this bit. Bit 0 of Register 64 (Channel 1 Bus Mode Register) or Register 128 (Channel 2 Bus Mode Register) has no impact on the Software reset function. * The reset operation is completed only when all resets in all active clock domains are de-asserted. Therefore, it is essential that all the PHY inputs clocks (applicable for the selected PHY interface) are present for the software reset completion.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Swr {
    #[doc = "0: `0`"]
    Clearrst = 0,
    #[doc = "1: `1`"]
    Reset = 1,
}
impl From<Swr> for bool {
    #[inline(always)]
    fn from(variant: Swr) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `swr` reader - When this bit is set, the MAC DMA Controller resets the logic and all internal registers of the MAC. It is cleared automatically after the reset operation has completed in all of the EMAC clock domains. Before reprogramming any register of the EMAC, you should read a zero (0) value in this bit . Note: * The Software reset function is driven only by this bit. Bit 0 of Register 64 (Channel 1 Bus Mode Register) or Register 128 (Channel 2 Bus Mode Register) has no impact on the Software reset function. * The reset operation is completed only when all resets in all active clock domains are de-asserted. Therefore, it is essential that all the PHY inputs clocks (applicable for the selected PHY interface) are present for the software reset completion."]
pub type SwrR = crate::BitReader<Swr>;
impl SwrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Swr {
        match self.bits {
            false => Swr::Clearrst,
            true => Swr::Reset,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_clearrst(&self) -> bool {
        *self == Swr::Clearrst
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_reset(&self) -> bool {
        *self == Swr::Reset
    }
}
#[doc = "Field `swr` writer - When this bit is set, the MAC DMA Controller resets the logic and all internal registers of the MAC. It is cleared automatically after the reset operation has completed in all of the EMAC clock domains. Before reprogramming any register of the EMAC, you should read a zero (0) value in this bit . Note: * The Software reset function is driven only by this bit. Bit 0 of Register 64 (Channel 1 Bus Mode Register) or Register 128 (Channel 2 Bus Mode Register) has no impact on the Software reset function. * The reset operation is completed only when all resets in all active clock domains are de-asserted. Therefore, it is essential that all the PHY inputs clocks (applicable for the selected PHY interface) are present for the software reset completion."]
pub type SwrW<'a, REG> = crate::BitWriter<'a, REG, Swr>;
impl<'a, REG> SwrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn clearrst(self) -> &'a mut crate::W<REG> {
        self.variant(Swr::Clearrst)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset(self) -> &'a mut crate::W<REG> {
        self.variant(Swr::Reset)
    }
}
#[doc = "Field `dsl` reader - This bit specifies the number of Word, Dword, or Lword (depending on the 32-bit, 64-bit, or 128-bit bus) to skip between two unchained descriptors. The address skipping starts from the end of current descriptor to the start of next descriptor. When the DSL value is equal to zero, then the descriptor table is taken as contiguous by the DMA in Ring mode."]
pub type DslR = crate::FieldReader;
#[doc = "Field `dsl` writer - This bit specifies the number of Word, Dword, or Lword (depending on the 32-bit, 64-bit, or 128-bit bus) to skip between two unchained descriptors. The address skipping starts from the end of current descriptor to the start of next descriptor. When the DSL value is equal to zero, then the descriptor table is taken as contiguous by the DMA in Ring mode."]
pub type DslW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "When set, the size of the alternate descriptor increases to 32 bytes (8 DWORDS). This is required when the Advanced Timestamp feature or the IPC Full Offload Engine (Type 2) is enabled in the receiver. The enhanced descriptor is not required if the Advanced Timestamp and IPC Full Checksum Offload (Type 2) features are not enabled. In such cases, you can use the 16 bytes descriptor to save 4 bytes of memory. When reset, the descriptor size reverts back to 4 DWORDs (16 bytes). This bit preserves the backward compatibility for the descriptor size. In versions prior to 3.50a, the descriptor size is 16 bytes for both normal and enhanced descriptor. In version 3.50a, descriptor size is increased to 32 bytes because of the Advanced Timestamp and IPC Full Checksum Offload Engine (Type 2) features.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Atds {
    #[doc = "0: `0`"]
    Clearrst = 0,
    #[doc = "1: `1`"]
    Reset = 1,
}
impl From<Atds> for bool {
    #[inline(always)]
    fn from(variant: Atds) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `atds` reader - When set, the size of the alternate descriptor increases to 32 bytes (8 DWORDS). This is required when the Advanced Timestamp feature or the IPC Full Offload Engine (Type 2) is enabled in the receiver. The enhanced descriptor is not required if the Advanced Timestamp and IPC Full Checksum Offload (Type 2) features are not enabled. In such cases, you can use the 16 bytes descriptor to save 4 bytes of memory. When reset, the descriptor size reverts back to 4 DWORDs (16 bytes). This bit preserves the backward compatibility for the descriptor size. In versions prior to 3.50a, the descriptor size is 16 bytes for both normal and enhanced descriptor. In version 3.50a, descriptor size is increased to 32 bytes because of the Advanced Timestamp and IPC Full Checksum Offload Engine (Type 2) features."]
pub type AtdsR = crate::BitReader<Atds>;
impl AtdsR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Atds {
        match self.bits {
            false => Atds::Clearrst,
            true => Atds::Reset,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_clearrst(&self) -> bool {
        *self == Atds::Clearrst
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_reset(&self) -> bool {
        *self == Atds::Reset
    }
}
#[doc = "Field `atds` writer - When set, the size of the alternate descriptor increases to 32 bytes (8 DWORDS). This is required when the Advanced Timestamp feature or the IPC Full Offload Engine (Type 2) is enabled in the receiver. The enhanced descriptor is not required if the Advanced Timestamp and IPC Full Checksum Offload (Type 2) features are not enabled. In such cases, you can use the 16 bytes descriptor to save 4 bytes of memory. When reset, the descriptor size reverts back to 4 DWORDs (16 bytes). This bit preserves the backward compatibility for the descriptor size. In versions prior to 3.50a, the descriptor size is 16 bytes for both normal and enhanced descriptor. In version 3.50a, descriptor size is increased to 32 bytes because of the Advanced Timestamp and IPC Full Checksum Offload Engine (Type 2) features."]
pub type AtdsW<'a, REG> = crate::BitWriter<'a, REG, Atds>;
impl<'a, REG> AtdsW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn clearrst(self) -> &'a mut crate::W<REG> {
        self.variant(Atds::Clearrst)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset(self) -> &'a mut crate::W<REG> {
        self.variant(Atds::Reset)
    }
}
#[doc = "Field `pbl` reader - These bits indicate the maximum number of beats to be transferred in one DMA transaction. This is the maximum value that is used in a single block Read or Write. The DMA always attempts to burst as specified in PBL each time it starts a Burst transfer on the host bus. PBL can be programmed with permissible values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. When USP is set high, this PBL value is applicable only for Tx DMA transactions. If the number of beats to be transferred is more than 32, then perform the following steps: 1. Set the 8xPBL mode. 2. Set the PBL. For example, if the maximum number of beats to be transferred is 64, then first set 8xPBL to 1 and then set PBL to 8. The PBL values have the following limitation: The maximum number of possible beats (PBL) is limited by the size of the Tx FIFO and Rx FIFO in the MTL layer and the data bus width on the DMA. The FIFO has a constraint that the maximum beat supported is half the depth of the FIFO, except when specified."]
pub type PblR = crate::FieldReader;
#[doc = "Field `pbl` writer - These bits indicate the maximum number of beats to be transferred in one DMA transaction. This is the maximum value that is used in a single block Read or Write. The DMA always attempts to burst as specified in PBL each time it starts a Burst transfer on the host bus. PBL can be programmed with permissible values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. When USP is set high, this PBL value is applicable only for Tx DMA transactions. If the number of beats to be transferred is more than 32, then perform the following steps: 1. Set the 8xPBL mode. 2. Set the PBL. For example, if the maximum number of beats to be transferred is 64, then first set 8xPBL to 1 and then set PBL to 8. The PBL values have the following limitation: The maximum number of possible beats (PBL) is limited by the size of the Tx FIFO and Rx FIFO in the MTL layer and the data bus width on the DMA. The FIFO has a constraint that the maximum beat supported is half the depth of the FIFO, except when specified."]
pub type PblW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "This bit controls whether the AXI Master interface performs fixed burst transfers or not. When set, the AXI interface uses FIXED bursts during the start of the normal burst transfers. When reset, the AXI interface uses SINGLE and INCR burst transfer operations. For more information, see Bit 0 (UNDEFINED) of the AXI Bus Mode register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fb {
    #[doc = "0: `0`"]
    Nonfb = 0,
    #[doc = "1: `1`"]
    Fb1_4_8_16 = 1,
}
impl From<Fb> for bool {
    #[inline(always)]
    fn from(variant: Fb) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `fb` reader - This bit controls whether the AXI Master interface performs fixed burst transfers or not. When set, the AXI interface uses FIXED bursts during the start of the normal burst transfers. When reset, the AXI interface uses SINGLE and INCR burst transfer operations. For more information, see Bit 0 (UNDEFINED) of the AXI Bus Mode register."]
pub type FbR = crate::BitReader<Fb>;
impl FbR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Fb {
        match self.bits {
            false => Fb::Nonfb,
            true => Fb::Fb1_4_8_16,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nonfb(&self) -> bool {
        *self == Fb::Nonfb
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_fb1_4_8_16(&self) -> bool {
        *self == Fb::Fb1_4_8_16
    }
}
#[doc = "Field `fb` writer - This bit controls whether the AXI Master interface performs fixed burst transfers or not. When set, the AXI interface uses FIXED bursts during the start of the normal burst transfers. When reset, the AXI interface uses SINGLE and INCR burst transfer operations. For more information, see Bit 0 (UNDEFINED) of the AXI Bus Mode register."]
pub type FbW<'a, REG> = crate::BitWriter<'a, REG, Fb>;
impl<'a, REG> FbW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nonfb(self) -> &'a mut crate::W<REG> {
        self.variant(Fb::Nonfb)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn fb1_4_8_16(self) -> &'a mut crate::W<REG> {
        self.variant(Fb::Fb1_4_8_16)
    }
}
#[doc = "This field indicates the maximum number of beats to be transferred in one Rx DMA transaction. This is the maximum value that is used in a single block Read or Write. The Rx DMA always attempts to burst as specified in the RPBL bit each time it starts a Burst transfer on the host bus. You can program RPBL with values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. This field is valid and applicable only when USP is set high.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rpbl {
    #[doc = "1: `1`"]
    Rxdmapbl1 = 1,
    #[doc = "2: `10`"]
    Rxdmapbl2 = 2,
    #[doc = "4: `100`"]
    Rxdmapbl4 = 4,
    #[doc = "8: `1000`"]
    Rxdmapbl8 = 8,
    #[doc = "16: `10000`"]
    Rxdmapbl6 = 16,
    #[doc = "32: `100000`"]
    Rxdmapbl32 = 32,
}
impl From<Rpbl> for u8 {
    #[inline(always)]
    fn from(variant: Rpbl) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Rpbl {
    type Ux = u8;
}
#[doc = "Field `rpbl` reader - This field indicates the maximum number of beats to be transferred in one Rx DMA transaction. This is the maximum value that is used in a single block Read or Write. The Rx DMA always attempts to burst as specified in the RPBL bit each time it starts a Burst transfer on the host bus. You can program RPBL with values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. This field is valid and applicable only when USP is set high."]
pub type RpblR = crate::FieldReader<Rpbl>;
impl RpblR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Rpbl> {
        match self.bits {
            1 => Some(Rpbl::Rxdmapbl1),
            2 => Some(Rpbl::Rxdmapbl2),
            4 => Some(Rpbl::Rxdmapbl4),
            8 => Some(Rpbl::Rxdmapbl8),
            16 => Some(Rpbl::Rxdmapbl6),
            32 => Some(Rpbl::Rxdmapbl32),
            _ => None,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rxdmapbl1(&self) -> bool {
        *self == Rpbl::Rxdmapbl1
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_rxdmapbl2(&self) -> bool {
        *self == Rpbl::Rxdmapbl2
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_rxdmapbl4(&self) -> bool {
        *self == Rpbl::Rxdmapbl4
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_rxdmapbl8(&self) -> bool {
        *self == Rpbl::Rxdmapbl8
    }
    #[doc = "`10000`"]
    #[inline(always)]
    pub fn is_rxdmapbl6(&self) -> bool {
        *self == Rpbl::Rxdmapbl6
    }
    #[doc = "`100000`"]
    #[inline(always)]
    pub fn is_rxdmapbl32(&self) -> bool {
        *self == Rpbl::Rxdmapbl32
    }
}
#[doc = "Field `rpbl` writer - This field indicates the maximum number of beats to be transferred in one Rx DMA transaction. This is the maximum value that is used in a single block Read or Write. The Rx DMA always attempts to burst as specified in the RPBL bit each time it starts a Burst transfer on the host bus. You can program RPBL with values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. This field is valid and applicable only when USP is set high."]
pub type RpblW<'a, REG> = crate::FieldWriter<'a, REG, 6, Rpbl>;
impl<'a, REG> RpblW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn rxdmapbl1(self) -> &'a mut crate::W<REG> {
        self.variant(Rpbl::Rxdmapbl1)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn rxdmapbl2(self) -> &'a mut crate::W<REG> {
        self.variant(Rpbl::Rxdmapbl2)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn rxdmapbl4(self) -> &'a mut crate::W<REG> {
        self.variant(Rpbl::Rxdmapbl4)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn rxdmapbl8(self) -> &'a mut crate::W<REG> {
        self.variant(Rpbl::Rxdmapbl8)
    }
    #[doc = "`10000`"]
    #[inline(always)]
    pub fn rxdmapbl6(self) -> &'a mut crate::W<REG> {
        self.variant(Rpbl::Rxdmapbl6)
    }
    #[doc = "`100000`"]
    #[inline(always)]
    pub fn rxdmapbl32(self) -> &'a mut crate::W<REG> {
        self.variant(Rpbl::Rxdmapbl32)
    }
}
#[doc = "When set high, this bit configures the Rx DMA to use the value configured in Bits\\[22:17\\]
as PBL. The PBL value in Bits\\[13:8\\]
is applicable only to the Tx DMA operations. When reset to low, the PBL value in Bits\\[13:8\\]
is applicable for both DMA engines.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usp {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Usp> for bool {
    #[inline(always)]
    fn from(variant: Usp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `usp` reader - When set high, this bit configures the Rx DMA to use the value configured in Bits\\[22:17\\]
as PBL. The PBL value in Bits\\[13:8\\]
is applicable only to the Tx DMA operations. When reset to low, the PBL value in Bits\\[13:8\\]
is applicable for both DMA engines."]
pub type UspR = crate::BitReader<Usp>;
impl UspR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Usp {
        match self.bits {
            false => Usp::Disabled,
            true => Usp::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Usp::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Usp::Enabled
    }
}
#[doc = "Field `usp` writer - When set high, this bit configures the Rx DMA to use the value configured in Bits\\[22:17\\]
as PBL. The PBL value in Bits\\[13:8\\]
is applicable only to the Tx DMA operations. When reset to low, the PBL value in Bits\\[13:8\\]
is applicable for both DMA engines."]
pub type UspW<'a, REG> = crate::BitWriter<'a, REG, Usp>;
impl<'a, REG> UspW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Usp::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Usp::Enabled)
    }
}
#[doc = "When set high, this bit multiplies the programmed PBL value (Bits\\[22:17\\]
and Bits\\[13:8\\]) eight times. Therefore, the DMA transfers the data in 8, 16, 32, 64, 128, and 256 beats depending on the PBL value.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eightxpbl {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Eightxpbl> for bool {
    #[inline(always)]
    fn from(variant: Eightxpbl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `eightxpbl` reader - When set high, this bit multiplies the programmed PBL value (Bits\\[22:17\\]
and Bits\\[13:8\\]) eight times. Therefore, the DMA transfers the data in 8, 16, 32, 64, 128, and 256 beats depending on the PBL value."]
pub type EightxpblR = crate::BitReader<Eightxpbl>;
impl EightxpblR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Eightxpbl {
        match self.bits {
            false => Eightxpbl::Disabled,
            true => Eightxpbl::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Eightxpbl::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Eightxpbl::Enabled
    }
}
#[doc = "Field `eightxpbl` writer - When set high, this bit multiplies the programmed PBL value (Bits\\[22:17\\]
and Bits\\[13:8\\]) eight times. Therefore, the DMA transfers the data in 8, 16, 32, 64, 128, and 256 beats depending on the PBL value."]
pub type EightxpblW<'a, REG> = crate::BitWriter<'a, REG, Eightxpbl>;
impl<'a, REG> EightxpblW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Eightxpbl::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Eightxpbl::Enabled)
    }
}
#[doc = "When this bit is set high and the FB bit is equal to 1, the AHB or AXI interface generates all bursts aligned to the start address LS bits. If the FB bit is equal to 0, the first burst (accessing the data buffer's start address) is not aligned, but subsequent bursts are aligned to the address.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aal {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Aal> for bool {
    #[inline(always)]
    fn from(variant: Aal) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `aal` reader - When this bit is set high and the FB bit is equal to 1, the AHB or AXI interface generates all bursts aligned to the start address LS bits. If the FB bit is equal to 0, the first burst (accessing the data buffer's start address) is not aligned, but subsequent bursts are aligned to the address."]
pub type AalR = crate::BitReader<Aal>;
impl AalR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Aal {
        match self.bits {
            false => Aal::Disabled,
            true => Aal::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Aal::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Aal::Enabled
    }
}
#[doc = "Field `aal` writer - When this bit is set high and the FB bit is equal to 1, the AHB or AXI interface generates all bursts aligned to the start address LS bits. If the FB bit is equal to 0, the first burst (accessing the data buffer's start address) is not aligned, but subsequent bursts are aligned to the address."]
pub type AalW<'a, REG> = crate::BitWriter<'a, REG, Aal>;
impl<'a, REG> AalW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Aal::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Aal::Enabled)
    }
}
impl R {
    #[doc = "Bit 0 - When this bit is set, the MAC DMA Controller resets the logic and all internal registers of the MAC. It is cleared automatically after the reset operation has completed in all of the EMAC clock domains. Before reprogramming any register of the EMAC, you should read a zero (0) value in this bit . Note: * The Software reset function is driven only by this bit. Bit 0 of Register 64 (Channel 1 Bus Mode Register) or Register 128 (Channel 2 Bus Mode Register) has no impact on the Software reset function. * The reset operation is completed only when all resets in all active clock domains are de-asserted. Therefore, it is essential that all the PHY inputs clocks (applicable for the selected PHY interface) are present for the software reset completion."]
    #[inline(always)]
    pub fn swr(&self) -> SwrR {
        SwrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 2:6 - This bit specifies the number of Word, Dword, or Lword (depending on the 32-bit, 64-bit, or 128-bit bus) to skip between two unchained descriptors. The address skipping starts from the end of current descriptor to the start of next descriptor. When the DSL value is equal to zero, then the descriptor table is taken as contiguous by the DMA in Ring mode."]
    #[inline(always)]
    pub fn dsl(&self) -> DslR {
        DslR::new(((self.bits >> 2) & 0x1f) as u8)
    }
    #[doc = "Bit 7 - When set, the size of the alternate descriptor increases to 32 bytes (8 DWORDS). This is required when the Advanced Timestamp feature or the IPC Full Offload Engine (Type 2) is enabled in the receiver. The enhanced descriptor is not required if the Advanced Timestamp and IPC Full Checksum Offload (Type 2) features are not enabled. In such cases, you can use the 16 bytes descriptor to save 4 bytes of memory. When reset, the descriptor size reverts back to 4 DWORDs (16 bytes). This bit preserves the backward compatibility for the descriptor size. In versions prior to 3.50a, the descriptor size is 16 bytes for both normal and enhanced descriptor. In version 3.50a, descriptor size is increased to 32 bytes because of the Advanced Timestamp and IPC Full Checksum Offload Engine (Type 2) features."]
    #[inline(always)]
    pub fn atds(&self) -> AtdsR {
        AtdsR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:13 - These bits indicate the maximum number of beats to be transferred in one DMA transaction. This is the maximum value that is used in a single block Read or Write. The DMA always attempts to burst as specified in PBL each time it starts a Burst transfer on the host bus. PBL can be programmed with permissible values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. When USP is set high, this PBL value is applicable only for Tx DMA transactions. If the number of beats to be transferred is more than 32, then perform the following steps: 1. Set the 8xPBL mode. 2. Set the PBL. For example, if the maximum number of beats to be transferred is 64, then first set 8xPBL to 1 and then set PBL to 8. The PBL values have the following limitation: The maximum number of possible beats (PBL) is limited by the size of the Tx FIFO and Rx FIFO in the MTL layer and the data bus width on the DMA. The FIFO has a constraint that the maximum beat supported is half the depth of the FIFO, except when specified."]
    #[inline(always)]
    pub fn pbl(&self) -> PblR {
        PblR::new(((self.bits >> 8) & 0x3f) as u8)
    }
    #[doc = "Bit 16 - This bit controls whether the AXI Master interface performs fixed burst transfers or not. When set, the AXI interface uses FIXED bursts during the start of the normal burst transfers. When reset, the AXI interface uses SINGLE and INCR burst transfer operations. For more information, see Bit 0 (UNDEFINED) of the AXI Bus Mode register."]
    #[inline(always)]
    pub fn fb(&self) -> FbR {
        FbR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:22 - This field indicates the maximum number of beats to be transferred in one Rx DMA transaction. This is the maximum value that is used in a single block Read or Write. The Rx DMA always attempts to burst as specified in the RPBL bit each time it starts a Burst transfer on the host bus. You can program RPBL with values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. This field is valid and applicable only when USP is set high."]
    #[inline(always)]
    pub fn rpbl(&self) -> RpblR {
        RpblR::new(((self.bits >> 17) & 0x3f) as u8)
    }
    #[doc = "Bit 23 - When set high, this bit configures the Rx DMA to use the value configured in Bits\\[22:17\\]
as PBL. The PBL value in Bits\\[13:8\\]
is applicable only to the Tx DMA operations. When reset to low, the PBL value in Bits\\[13:8\\]
is applicable for both DMA engines."]
    #[inline(always)]
    pub fn usp(&self) -> UspR {
        UspR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - When set high, this bit multiplies the programmed PBL value (Bits\\[22:17\\]
and Bits\\[13:8\\]) eight times. Therefore, the DMA transfers the data in 8, 16, 32, 64, 128, and 256 beats depending on the PBL value."]
    #[inline(always)]
    pub fn eightxpbl(&self) -> EightxpblR {
        EightxpblR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - When this bit is set high and the FB bit is equal to 1, the AHB or AXI interface generates all bursts aligned to the start address LS bits. If the FB bit is equal to 0, the first burst (accessing the data buffer's start address) is not aligned, but subsequent bursts are aligned to the address."]
    #[inline(always)]
    pub fn aal(&self) -> AalR {
        AalR::new(((self.bits >> 25) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When this bit is set, the MAC DMA Controller resets the logic and all internal registers of the MAC. It is cleared automatically after the reset operation has completed in all of the EMAC clock domains. Before reprogramming any register of the EMAC, you should read a zero (0) value in this bit . Note: * The Software reset function is driven only by this bit. Bit 0 of Register 64 (Channel 1 Bus Mode Register) or Register 128 (Channel 2 Bus Mode Register) has no impact on the Software reset function. * The reset operation is completed only when all resets in all active clock domains are de-asserted. Therefore, it is essential that all the PHY inputs clocks (applicable for the selected PHY interface) are present for the software reset completion."]
    #[inline(always)]
    #[must_use]
    pub fn swr(&mut self) -> SwrW<DmagrpBusModeSpec> {
        SwrW::new(self, 0)
    }
    #[doc = "Bits 2:6 - This bit specifies the number of Word, Dword, or Lword (depending on the 32-bit, 64-bit, or 128-bit bus) to skip between two unchained descriptors. The address skipping starts from the end of current descriptor to the start of next descriptor. When the DSL value is equal to zero, then the descriptor table is taken as contiguous by the DMA in Ring mode."]
    #[inline(always)]
    #[must_use]
    pub fn dsl(&mut self) -> DslW<DmagrpBusModeSpec> {
        DslW::new(self, 2)
    }
    #[doc = "Bit 7 - When set, the size of the alternate descriptor increases to 32 bytes (8 DWORDS). This is required when the Advanced Timestamp feature or the IPC Full Offload Engine (Type 2) is enabled in the receiver. The enhanced descriptor is not required if the Advanced Timestamp and IPC Full Checksum Offload (Type 2) features are not enabled. In such cases, you can use the 16 bytes descriptor to save 4 bytes of memory. When reset, the descriptor size reverts back to 4 DWORDs (16 bytes). This bit preserves the backward compatibility for the descriptor size. In versions prior to 3.50a, the descriptor size is 16 bytes for both normal and enhanced descriptor. In version 3.50a, descriptor size is increased to 32 bytes because of the Advanced Timestamp and IPC Full Checksum Offload Engine (Type 2) features."]
    #[inline(always)]
    #[must_use]
    pub fn atds(&mut self) -> AtdsW<DmagrpBusModeSpec> {
        AtdsW::new(self, 7)
    }
    #[doc = "Bits 8:13 - These bits indicate the maximum number of beats to be transferred in one DMA transaction. This is the maximum value that is used in a single block Read or Write. The DMA always attempts to burst as specified in PBL each time it starts a Burst transfer on the host bus. PBL can be programmed with permissible values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. When USP is set high, this PBL value is applicable only for Tx DMA transactions. If the number of beats to be transferred is more than 32, then perform the following steps: 1. Set the 8xPBL mode. 2. Set the PBL. For example, if the maximum number of beats to be transferred is 64, then first set 8xPBL to 1 and then set PBL to 8. The PBL values have the following limitation: The maximum number of possible beats (PBL) is limited by the size of the Tx FIFO and Rx FIFO in the MTL layer and the data bus width on the DMA. The FIFO has a constraint that the maximum beat supported is half the depth of the FIFO, except when specified."]
    #[inline(always)]
    #[must_use]
    pub fn pbl(&mut self) -> PblW<DmagrpBusModeSpec> {
        PblW::new(self, 8)
    }
    #[doc = "Bit 16 - This bit controls whether the AXI Master interface performs fixed burst transfers or not. When set, the AXI interface uses FIXED bursts during the start of the normal burst transfers. When reset, the AXI interface uses SINGLE and INCR burst transfer operations. For more information, see Bit 0 (UNDEFINED) of the AXI Bus Mode register."]
    #[inline(always)]
    #[must_use]
    pub fn fb(&mut self) -> FbW<DmagrpBusModeSpec> {
        FbW::new(self, 16)
    }
    #[doc = "Bits 17:22 - This field indicates the maximum number of beats to be transferred in one Rx DMA transaction. This is the maximum value that is used in a single block Read or Write. The Rx DMA always attempts to burst as specified in the RPBL bit each time it starts a Burst transfer on the host bus. You can program RPBL with values of 1, 2, 4, 8, 16, and 32. Any other value results in undefined behavior. This field is valid and applicable only when USP is set high."]
    #[inline(always)]
    #[must_use]
    pub fn rpbl(&mut self) -> RpblW<DmagrpBusModeSpec> {
        RpblW::new(self, 17)
    }
    #[doc = "Bit 23 - When set high, this bit configures the Rx DMA to use the value configured in Bits\\[22:17\\]
as PBL. The PBL value in Bits\\[13:8\\]
is applicable only to the Tx DMA operations. When reset to low, the PBL value in Bits\\[13:8\\]
is applicable for both DMA engines."]
    #[inline(always)]
    #[must_use]
    pub fn usp(&mut self) -> UspW<DmagrpBusModeSpec> {
        UspW::new(self, 23)
    }
    #[doc = "Bit 24 - When set high, this bit multiplies the programmed PBL value (Bits\\[22:17\\]
and Bits\\[13:8\\]) eight times. Therefore, the DMA transfers the data in 8, 16, 32, 64, 128, and 256 beats depending on the PBL value."]
    #[inline(always)]
    #[must_use]
    pub fn eightxpbl(&mut self) -> EightxpblW<DmagrpBusModeSpec> {
        EightxpblW::new(self, 24)
    }
    #[doc = "Bit 25 - When this bit is set high and the FB bit is equal to 1, the AHB or AXI interface generates all bursts aligned to the start address LS bits. If the FB bit is equal to 0, the first burst (accessing the data buffer's start address) is not aligned, but subsequent bursts are aligned to the address."]
    #[inline(always)]
    #[must_use]
    pub fn aal(&mut self) -> AalW<DmagrpBusModeSpec> {
        AalW::new(self, 25)
    }
}
#[doc = "The Bus Mode register establishes the bus operating modes for the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_bus_mode::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_bus_mode::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpBusModeSpec;
impl crate::RegisterSpec for DmagrpBusModeSpec {
    type Ux = u32;
    const OFFSET: u64 = 4096u64;
}
#[doc = "`read()` method returns [`dmagrp_bus_mode::R`](R) reader structure"]
impl crate::Readable for DmagrpBusModeSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_bus_mode::W`](W) writer structure"]
impl crate::Writable for DmagrpBusModeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Bus_Mode to value 0x0002_0101"]
impl crate::Resettable for DmagrpBusModeSpec {
    const RESET_VALUE: u32 = 0x0002_0101;
}
