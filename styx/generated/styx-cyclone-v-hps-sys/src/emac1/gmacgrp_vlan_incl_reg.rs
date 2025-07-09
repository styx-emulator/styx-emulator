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
#[doc = "Register `gmacgrp_VLAN_Incl_Reg` reader"]
pub type R = crate::R<GmacgrpVlanInclRegSpec>;
#[doc = "Register `gmacgrp_VLAN_Incl_Reg` writer"]
pub type W = crate::W<GmacgrpVlanInclRegSpec>;
#[doc = "Field `vlt` reader - This field contains the value of the VLAN tag to be inserted or replaced. The value must only be changed when the transmit lines are inactive or during the initialization phase. Bits\\[15:13\\]
are the User Priority, Bit 12 is the CFI/DEI, and Bits\\[11:0\\]
are the VLAN tag's VID field."]
pub type VltR = crate::FieldReader<u16>;
#[doc = "Field `vlt` writer - This field contains the value of the VLAN tag to be inserted or replaced. The value must only be changed when the transmit lines are inactive or during the initialization phase. Bits\\[15:13\\]
are the User Priority, Bit 12 is the CFI/DEI, and Bits\\[11:0\\]
are the VLAN tag's VID field."]
pub type VltW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `vlc` reader - * 2'b00: No VLAN tag deletion, insertion, or replacement * 2'b01: VLAN tag deletion The MAC removes the VLAN type (bytes 13 and 14) and VLAN tag (bytes 15 and 16) of all transmitted frames with VLAN tags. * 2'b10: VLAN tag insertion The MAC inserts VLT in bytes 15 and 16 of the frame after inserting the Type value (0x8100/0x88a8) in bytes 13 and 14. This operation is performed on all transmitted frames, irrespective of whether they already have a VLAN tag. * 2'b11: VLAN tag replacement The MAC replaces VLT in bytes 15 and 16 of all VLAN-type transmitted frames (Bytes 13 and 14 are 0x8100/0x88a8). Note: Changes to this field take effect only on the start of a frame. If you write this register field when a frame is being transmitted, only the subsequent frame can use the updated value, that is, the current frame does not use the updated value."]
pub type VlcR = crate::FieldReader;
#[doc = "Field `vlc` writer - * 2'b00: No VLAN tag deletion, insertion, or replacement * 2'b01: VLAN tag deletion The MAC removes the VLAN type (bytes 13 and 14) and VLAN tag (bytes 15 and 16) of all transmitted frames with VLAN tags. * 2'b10: VLAN tag insertion The MAC inserts VLT in bytes 15 and 16 of the frame after inserting the Type value (0x8100/0x88a8) in bytes 13 and 14. This operation is performed on all transmitted frames, irrespective of whether they already have a VLAN tag. * 2'b11: VLAN tag replacement The MAC replaces VLT in bytes 15 and 16 of all VLAN-type transmitted frames (Bytes 13 and 14 are 0x8100/0x88a8). Note: Changes to this field take effect only on the start of a frame. If you write this register field when a frame is being transmitted, only the subsequent frame can use the updated value, that is, the current frame does not use the updated value."]
pub type VlcW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `vlp` reader - When this bit is set, the control Bits \\[17:16\\]
are used for VLAN deletion, insertion, or replacement. When this bit is reset, the mti_vlan_ctrl_i control input is used, and Bits \\[17:16\\]
are ignored."]
pub type VlpR = crate::BitReader;
#[doc = "Field `vlp` writer - When this bit is set, the control Bits \\[17:16\\]
are used for VLAN deletion, insertion, or replacement. When this bit is reset, the mti_vlan_ctrl_i control input is used, and Bits \\[17:16\\]
are ignored."]
pub type VlpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `csvl` reader - When this bit is set, S-VLAN type (0x88A8) is inserted or replaced in the 13th and 14th bytes of transmitted frames. When this bit is reset, C-VLAN type (0x8100) is inserted or replaced in the transmitted frames."]
pub type CsvlR = crate::BitReader;
#[doc = "Field `csvl` writer - When this bit is set, S-VLAN type (0x88A8) is inserted or replaced in the 13th and 14th bytes of transmitted frames. When this bit is reset, C-VLAN type (0x8100) is inserted or replaced in the transmitted frames."]
pub type CsvlW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:15 - This field contains the value of the VLAN tag to be inserted or replaced. The value must only be changed when the transmit lines are inactive or during the initialization phase. Bits\\[15:13\\]
are the User Priority, Bit 12 is the CFI/DEI, and Bits\\[11:0\\]
are the VLAN tag's VID field."]
    #[inline(always)]
    pub fn vlt(&self) -> VltR {
        VltR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:17 - * 2'b00: No VLAN tag deletion, insertion, or replacement * 2'b01: VLAN tag deletion The MAC removes the VLAN type (bytes 13 and 14) and VLAN tag (bytes 15 and 16) of all transmitted frames with VLAN tags. * 2'b10: VLAN tag insertion The MAC inserts VLT in bytes 15 and 16 of the frame after inserting the Type value (0x8100/0x88a8) in bytes 13 and 14. This operation is performed on all transmitted frames, irrespective of whether they already have a VLAN tag. * 2'b11: VLAN tag replacement The MAC replaces VLT in bytes 15 and 16 of all VLAN-type transmitted frames (Bytes 13 and 14 are 0x8100/0x88a8). Note: Changes to this field take effect only on the start of a frame. If you write this register field when a frame is being transmitted, only the subsequent frame can use the updated value, that is, the current frame does not use the updated value."]
    #[inline(always)]
    pub fn vlc(&self) -> VlcR {
        VlcR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bit 18 - When this bit is set, the control Bits \\[17:16\\]
are used for VLAN deletion, insertion, or replacement. When this bit is reset, the mti_vlan_ctrl_i control input is used, and Bits \\[17:16\\]
are ignored."]
    #[inline(always)]
    pub fn vlp(&self) -> VlpR {
        VlpR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - When this bit is set, S-VLAN type (0x88A8) is inserted or replaced in the 13th and 14th bytes of transmitted frames. When this bit is reset, C-VLAN type (0x8100) is inserted or replaced in the transmitted frames."]
    #[inline(always)]
    pub fn csvl(&self) -> CsvlR {
        CsvlR::new(((self.bits >> 19) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:15 - This field contains the value of the VLAN tag to be inserted or replaced. The value must only be changed when the transmit lines are inactive or during the initialization phase. Bits\\[15:13\\]
are the User Priority, Bit 12 is the CFI/DEI, and Bits\\[11:0\\]
are the VLAN tag's VID field."]
    #[inline(always)]
    #[must_use]
    pub fn vlt(&mut self) -> VltW<GmacgrpVlanInclRegSpec> {
        VltW::new(self, 0)
    }
    #[doc = "Bits 16:17 - * 2'b00: No VLAN tag deletion, insertion, or replacement * 2'b01: VLAN tag deletion The MAC removes the VLAN type (bytes 13 and 14) and VLAN tag (bytes 15 and 16) of all transmitted frames with VLAN tags. * 2'b10: VLAN tag insertion The MAC inserts VLT in bytes 15 and 16 of the frame after inserting the Type value (0x8100/0x88a8) in bytes 13 and 14. This operation is performed on all transmitted frames, irrespective of whether they already have a VLAN tag. * 2'b11: VLAN tag replacement The MAC replaces VLT in bytes 15 and 16 of all VLAN-type transmitted frames (Bytes 13 and 14 are 0x8100/0x88a8). Note: Changes to this field take effect only on the start of a frame. If you write this register field when a frame is being transmitted, only the subsequent frame can use the updated value, that is, the current frame does not use the updated value."]
    #[inline(always)]
    #[must_use]
    pub fn vlc(&mut self) -> VlcW<GmacgrpVlanInclRegSpec> {
        VlcW::new(self, 16)
    }
    #[doc = "Bit 18 - When this bit is set, the control Bits \\[17:16\\]
are used for VLAN deletion, insertion, or replacement. When this bit is reset, the mti_vlan_ctrl_i control input is used, and Bits \\[17:16\\]
are ignored."]
    #[inline(always)]
    #[must_use]
    pub fn vlp(&mut self) -> VlpW<GmacgrpVlanInclRegSpec> {
        VlpW::new(self, 18)
    }
    #[doc = "Bit 19 - When this bit is set, S-VLAN type (0x88A8) is inserted or replaced in the 13th and 14th bytes of transmitted frames. When this bit is reset, C-VLAN type (0x8100) is inserted or replaced in the transmitted frames."]
    #[inline(always)]
    #[must_use]
    pub fn csvl(&mut self) -> CsvlW<GmacgrpVlanInclRegSpec> {
        CsvlW::new(self, 19)
    }
}
#[doc = "The VLAN Tag Inclusion or Replacement register contains the VLAN tag for insertion or replacement in the transmit frames.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_vlan_incl_reg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_vlan_incl_reg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpVlanInclRegSpec;
impl crate::RegisterSpec for GmacgrpVlanInclRegSpec {
    type Ux = u32;
    const OFFSET: u64 = 1412u64;
}
#[doc = "`read()` method returns [`gmacgrp_vlan_incl_reg::R`](R) reader structure"]
impl crate::Readable for GmacgrpVlanInclRegSpec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_vlan_incl_reg::W`](W) writer structure"]
impl crate::Writable for GmacgrpVlanInclRegSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_VLAN_Incl_Reg to value 0"]
impl crate::Resettable for GmacgrpVlanInclRegSpec {
    const RESET_VALUE: u32 = 0;
}
