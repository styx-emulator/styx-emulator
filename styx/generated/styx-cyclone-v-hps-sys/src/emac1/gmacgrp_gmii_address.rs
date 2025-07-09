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
#[doc = "Register `gmacgrp_GMII_Address` reader"]
pub type R = crate::R<GmacgrpGmiiAddressSpec>;
#[doc = "Register `gmacgrp_GMII_Address` writer"]
pub type W = crate::W<GmacgrpGmiiAddressSpec>;
#[doc = "This bit should read logic 0 before writing to Register 4 and Register 5. During a PHY or RevMII register access, the software sets this bit to 1'b1 to indicate that a Read or Write access is in progress. The Register 5 is invalid until this bit is cleared by the MAC. Therefore, Register 5 (GMII Data) should be kept valid until the MAC clears this bit during a PHY Write operation. Similarly for a read operation, the contents of Register 5 are not valid until this bit is cleared. The subsequent read or write operation should happen only after the previous operation is complete. Because there is no acknowledgment from the PHY to MAC after a read or write operation is completed, there is no change in the functionality of this bit even when the PHY is not present.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gb {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Gb> for bool {
    #[inline(always)]
    fn from(variant: Gb) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gb` reader - This bit should read logic 0 before writing to Register 4 and Register 5. During a PHY or RevMII register access, the software sets this bit to 1'b1 to indicate that a Read or Write access is in progress. The Register 5 is invalid until this bit is cleared by the MAC. Therefore, Register 5 (GMII Data) should be kept valid until the MAC clears this bit during a PHY Write operation. Similarly for a read operation, the contents of Register 5 are not valid until this bit is cleared. The subsequent read or write operation should happen only after the previous operation is complete. Because there is no acknowledgment from the PHY to MAC after a read or write operation is completed, there is no change in the functionality of this bit even when the PHY is not present."]
pub type GbR = crate::BitReader<Gb>;
impl GbR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Gb {
        match self.bits {
            false => Gb::Disabled,
            true => Gb::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Gb::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Gb::Enabled
    }
}
#[doc = "Field `gb` writer - This bit should read logic 0 before writing to Register 4 and Register 5. During a PHY or RevMII register access, the software sets this bit to 1'b1 to indicate that a Read or Write access is in progress. The Register 5 is invalid until this bit is cleared by the MAC. Therefore, Register 5 (GMII Data) should be kept valid until the MAC clears this bit during a PHY Write operation. Similarly for a read operation, the contents of Register 5 are not valid until this bit is cleared. The subsequent read or write operation should happen only after the previous operation is complete. Because there is no acknowledgment from the PHY to MAC after a read or write operation is completed, there is no change in the functionality of this bit even when the PHY is not present."]
pub type GbW<'a, REG> = crate::BitWriter<'a, REG, Gb>;
impl<'a, REG> GbW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Gb::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Gb::Enabled)
    }
}
#[doc = "When set, this bit indicates to the PHY or RevMII that this is a Write operation using the GMII Data register. If this bit is not set, it indicates that this is a Read operation, that is, placing the data in the GMII Data register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gw {
    #[doc = "0: `0`"]
    Disabled = 0,
    #[doc = "1: `1`"]
    Enabled = 1,
}
impl From<Gw> for bool {
    #[inline(always)]
    fn from(variant: Gw) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `gw` reader - When set, this bit indicates to the PHY or RevMII that this is a Write operation using the GMII Data register. If this bit is not set, it indicates that this is a Read operation, that is, placing the data in the GMII Data register."]
pub type GwR = crate::BitReader<Gw>;
impl GwR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Gw {
        match self.bits {
            false => Gw::Disabled,
            true => Gw::Enabled,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        *self == Gw::Disabled
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        *self == Gw::Enabled
    }
}
#[doc = "Field `gw` writer - When set, this bit indicates to the PHY or RevMII that this is a Write operation using the GMII Data register. If this bit is not set, it indicates that this is a Read operation, that is, placing the data in the GMII Data register."]
pub type GwW<'a, REG> = crate::BitWriter<'a, REG, Gw>;
impl<'a, REG> GwW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn disabled(self) -> &'a mut crate::W<REG> {
        self.variant(Gw::Disabled)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn enabled(self) -> &'a mut crate::W<REG> {
        self.variant(Gw::Enabled)
    }
}
#[doc = "The CSR Clock Range selection determines the frequency of the MDC clock according to the l3_sp_clk frequency used in your design. The suggested range of l3_sp_clk frequency applicable for each value (when Bit\\[5\\]
= 0) ensures that the MDC clock is approximately between the frequency range 1.0 MHz - 2.5 MHz. When Bit 5 is set, you can achieve MDC clock of frequency higher than the IEEE 802.3 specified frequency limit of 2.5 MHz and program a clock divider of lower value. For example, when l3_sp_clk is of 100 MHz frequency and you program these bits as 1010, then the resultant MDC clock is of 12.5 MHz which is outside the limit of IEEE 802.3 specified range. Only use the values larger than 7 if the interfacing chips support faster MDC clocks.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cr {
    #[doc = "0: `0`"]
    Div42 = 0,
    #[doc = "1: `1`"]
    Div62 = 1,
    #[doc = "2: `10`"]
    Div16 = 2,
    #[doc = "3: `11`"]
    Div26 = 3,
    #[doc = "4: `100`"]
    Div102 = 4,
    #[doc = "5: `101`"]
    Div124 = 5,
    #[doc = "8: `1000`"]
    Div4 = 8,
    #[doc = "9: `1001`"]
    Div6 = 9,
    #[doc = "10: `1010`"]
    Div8 = 10,
    #[doc = "11: `1011`"]
    Div10 = 11,
    #[doc = "12: `1100`"]
    Div12 = 12,
    #[doc = "13: `1101`"]
    Div14 = 13,
    #[doc = "14: `1110`"]
    Div16again = 14,
    #[doc = "15: `1111`"]
    Div18 = 15,
}
impl From<Cr> for u8 {
    #[inline(always)]
    fn from(variant: Cr) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Cr {
    type Ux = u8;
}
#[doc = "Field `cr` reader - The CSR Clock Range selection determines the frequency of the MDC clock according to the l3_sp_clk frequency used in your design. The suggested range of l3_sp_clk frequency applicable for each value (when Bit\\[5\\]
= 0) ensures that the MDC clock is approximately between the frequency range 1.0 MHz - 2.5 MHz. When Bit 5 is set, you can achieve MDC clock of frequency higher than the IEEE 802.3 specified frequency limit of 2.5 MHz and program a clock divider of lower value. For example, when l3_sp_clk is of 100 MHz frequency and you program these bits as 1010, then the resultant MDC clock is of 12.5 MHz which is outside the limit of IEEE 802.3 specified range. Only use the values larger than 7 if the interfacing chips support faster MDC clocks."]
pub type CrR = crate::FieldReader<Cr>;
impl CrR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Cr> {
        match self.bits {
            0 => Some(Cr::Div42),
            1 => Some(Cr::Div62),
            2 => Some(Cr::Div16),
            3 => Some(Cr::Div26),
            4 => Some(Cr::Div102),
            5 => Some(Cr::Div124),
            8 => Some(Cr::Div4),
            9 => Some(Cr::Div6),
            10 => Some(Cr::Div8),
            11 => Some(Cr::Div10),
            12 => Some(Cr::Div12),
            13 => Some(Cr::Div14),
            14 => Some(Cr::Div16again),
            15 => Some(Cr::Div18),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_div42(&self) -> bool {
        *self == Cr::Div42
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_div62(&self) -> bool {
        *self == Cr::Div62
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_div16(&self) -> bool {
        *self == Cr::Div16
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_div26(&self) -> bool {
        *self == Cr::Div26
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_div102(&self) -> bool {
        *self == Cr::Div102
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_div124(&self) -> bool {
        *self == Cr::Div124
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_div4(&self) -> bool {
        *self == Cr::Div4
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_div6(&self) -> bool {
        *self == Cr::Div6
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_div8(&self) -> bool {
        *self == Cr::Div8
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_div10(&self) -> bool {
        *self == Cr::Div10
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_div12(&self) -> bool {
        *self == Cr::Div12
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_div14(&self) -> bool {
        *self == Cr::Div14
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_div16again(&self) -> bool {
        *self == Cr::Div16again
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_div18(&self) -> bool {
        *self == Cr::Div18
    }
}
#[doc = "Field `cr` writer - The CSR Clock Range selection determines the frequency of the MDC clock according to the l3_sp_clk frequency used in your design. The suggested range of l3_sp_clk frequency applicable for each value (when Bit\\[5\\]
= 0) ensures that the MDC clock is approximately between the frequency range 1.0 MHz - 2.5 MHz. When Bit 5 is set, you can achieve MDC clock of frequency higher than the IEEE 802.3 specified frequency limit of 2.5 MHz and program a clock divider of lower value. For example, when l3_sp_clk is of 100 MHz frequency and you program these bits as 1010, then the resultant MDC clock is of 12.5 MHz which is outside the limit of IEEE 802.3 specified range. Only use the values larger than 7 if the interfacing chips support faster MDC clocks."]
pub type CrW<'a, REG> = crate::FieldWriter<'a, REG, 4, Cr>;
impl<'a, REG> CrW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn div42(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div42)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn div62(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div62)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn div16(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div16)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn div26(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div26)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn div102(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div102)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn div124(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div124)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn div4(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div4)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn div6(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div6)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn div8(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div8)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn div10(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div10)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn div12(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div12)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn div14(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div14)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn div16again(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div16again)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn div18(self) -> &'a mut crate::W<REG> {
        self.variant(Cr::Div18)
    }
}
#[doc = "Field `gr` reader - These bits select the desired GMII register in the selected PHY device. For RevMII, these bits select the desired CSR register in the RevMII Registers set."]
pub type GrR = crate::FieldReader;
#[doc = "Field `gr` writer - These bits select the desired GMII register in the selected PHY device. For RevMII, these bits select the desired CSR register in the RevMII Registers set."]
pub type GrW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `pa` reader - This field indicates which of the 32 possible PHY devices are being accessed. For RevMII, this field gives the PHY Address of the RevMII block."]
pub type PaR = crate::FieldReader;
#[doc = "Field `pa` writer - This field indicates which of the 32 possible PHY devices are being accessed. For RevMII, this field gives the PHY Address of the RevMII block."]
pub type PaW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bit 0 - This bit should read logic 0 before writing to Register 4 and Register 5. During a PHY or RevMII register access, the software sets this bit to 1'b1 to indicate that a Read or Write access is in progress. The Register 5 is invalid until this bit is cleared by the MAC. Therefore, Register 5 (GMII Data) should be kept valid until the MAC clears this bit during a PHY Write operation. Similarly for a read operation, the contents of Register 5 are not valid until this bit is cleared. The subsequent read or write operation should happen only after the previous operation is complete. Because there is no acknowledgment from the PHY to MAC after a read or write operation is completed, there is no change in the functionality of this bit even when the PHY is not present."]
    #[inline(always)]
    pub fn gb(&self) -> GbR {
        GbR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - When set, this bit indicates to the PHY or RevMII that this is a Write operation using the GMII Data register. If this bit is not set, it indicates that this is a Read operation, that is, placing the data in the GMII Data register."]
    #[inline(always)]
    pub fn gw(&self) -> GwR {
        GwR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:5 - The CSR Clock Range selection determines the frequency of the MDC clock according to the l3_sp_clk frequency used in your design. The suggested range of l3_sp_clk frequency applicable for each value (when Bit\\[5\\]
= 0) ensures that the MDC clock is approximately between the frequency range 1.0 MHz - 2.5 MHz. When Bit 5 is set, you can achieve MDC clock of frequency higher than the IEEE 802.3 specified frequency limit of 2.5 MHz and program a clock divider of lower value. For example, when l3_sp_clk is of 100 MHz frequency and you program these bits as 1010, then the resultant MDC clock is of 12.5 MHz which is outside the limit of IEEE 802.3 specified range. Only use the values larger than 7 if the interfacing chips support faster MDC clocks."]
    #[inline(always)]
    pub fn cr(&self) -> CrR {
        CrR::new(((self.bits >> 2) & 0x0f) as u8)
    }
    #[doc = "Bits 6:10 - These bits select the desired GMII register in the selected PHY device. For RevMII, these bits select the desired CSR register in the RevMII Registers set."]
    #[inline(always)]
    pub fn gr(&self) -> GrR {
        GrR::new(((self.bits >> 6) & 0x1f) as u8)
    }
    #[doc = "Bits 11:15 - This field indicates which of the 32 possible PHY devices are being accessed. For RevMII, this field gives the PHY Address of the RevMII block."]
    #[inline(always)]
    pub fn pa(&self) -> PaR {
        PaR::new(((self.bits >> 11) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - This bit should read logic 0 before writing to Register 4 and Register 5. During a PHY or RevMII register access, the software sets this bit to 1'b1 to indicate that a Read or Write access is in progress. The Register 5 is invalid until this bit is cleared by the MAC. Therefore, Register 5 (GMII Data) should be kept valid until the MAC clears this bit during a PHY Write operation. Similarly for a read operation, the contents of Register 5 are not valid until this bit is cleared. The subsequent read or write operation should happen only after the previous operation is complete. Because there is no acknowledgment from the PHY to MAC after a read or write operation is completed, there is no change in the functionality of this bit even when the PHY is not present."]
    #[inline(always)]
    #[must_use]
    pub fn gb(&mut self) -> GbW<GmacgrpGmiiAddressSpec> {
        GbW::new(self, 0)
    }
    #[doc = "Bit 1 - When set, this bit indicates to the PHY or RevMII that this is a Write operation using the GMII Data register. If this bit is not set, it indicates that this is a Read operation, that is, placing the data in the GMII Data register."]
    #[inline(always)]
    #[must_use]
    pub fn gw(&mut self) -> GwW<GmacgrpGmiiAddressSpec> {
        GwW::new(self, 1)
    }
    #[doc = "Bits 2:5 - The CSR Clock Range selection determines the frequency of the MDC clock according to the l3_sp_clk frequency used in your design. The suggested range of l3_sp_clk frequency applicable for each value (when Bit\\[5\\]
= 0) ensures that the MDC clock is approximately between the frequency range 1.0 MHz - 2.5 MHz. When Bit 5 is set, you can achieve MDC clock of frequency higher than the IEEE 802.3 specified frequency limit of 2.5 MHz and program a clock divider of lower value. For example, when l3_sp_clk is of 100 MHz frequency and you program these bits as 1010, then the resultant MDC clock is of 12.5 MHz which is outside the limit of IEEE 802.3 specified range. Only use the values larger than 7 if the interfacing chips support faster MDC clocks."]
    #[inline(always)]
    #[must_use]
    pub fn cr(&mut self) -> CrW<GmacgrpGmiiAddressSpec> {
        CrW::new(self, 2)
    }
    #[doc = "Bits 6:10 - These bits select the desired GMII register in the selected PHY device. For RevMII, these bits select the desired CSR register in the RevMII Registers set."]
    #[inline(always)]
    #[must_use]
    pub fn gr(&mut self) -> GrW<GmacgrpGmiiAddressSpec> {
        GrW::new(self, 6)
    }
    #[doc = "Bits 11:15 - This field indicates which of the 32 possible PHY devices are being accessed. For RevMII, this field gives the PHY Address of the RevMII block."]
    #[inline(always)]
    #[must_use]
    pub fn pa(&mut self) -> PaW<GmacgrpGmiiAddressSpec> {
        PaW::new(self, 11)
    }
}
#[doc = "The GMII Address register controls the management cycles to the external PHY through the management interface.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_gmii_address::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_gmii_address::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpGmiiAddressSpec;
impl crate::RegisterSpec for GmacgrpGmiiAddressSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`gmacgrp_gmii_address::R`](R) reader structure"]
impl crate::Readable for GmacgrpGmiiAddressSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_gmii_address::W`](W) writer structure"]
impl crate::Writable for GmacgrpGmiiAddressSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_GMII_Address to value 0"]
impl crate::Resettable for GmacgrpGmiiAddressSpec {
    const RESET_VALUE: u32 = 0;
}
