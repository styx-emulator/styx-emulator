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
#[doc = "Register `gmacgrp_L3_L4_Control2` reader"]
pub type R = crate::R<GmacgrpL3L4Control2Spec>;
#[doc = "Register `gmacgrp_L3_L4_Control2` writer"]
pub type W = crate::W<GmacgrpL3L4Control2Spec>;
#[doc = "Field `l3pen2` reader - When set, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv6 frames. When reset, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv4 frames. The Layer 3 matching is done only when either L3SAM2 or L3DAM2 bit is set high."]
pub type L3pen2R = crate::BitReader;
#[doc = "Field `l3pen2` writer - When set, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv6 frames. When reset, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv4 frames. The Layer 3 matching is done only when either L3SAM2 or L3DAM2 bit is set high."]
pub type L3pen2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3sam2` reader - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Source Address field for matching. Note: When Bit 0 (L3PEN2) is set, you should set either this bit or Bit 4 (L3DAM2) because either IPv6 SA or DA can be checked for filtering."]
pub type L3sam2R = crate::BitReader;
#[doc = "Field `l3sam2` writer - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Source Address field for matching. Note: When Bit 0 (L3PEN2) is set, you should set either this bit or Bit 4 (L3DAM2) because either IPv6 SA or DA can be checked for filtering."]
pub type L3sam2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3saim2` reader - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Source Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 2 (L3SAM2) is set high."]
pub type L3saim2R = crate::BitReader;
#[doc = "Field `l3saim2` writer - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Source Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 2 (L3SAM2) is set high."]
pub type L3saim2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3dam2` reader - When set, this bit indicates that Layer 3 IP Destination Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Destination Address field for matching. Note: When Bit 0 (L3PEN2) is set, you should set either this bit or Bit 2 (L3SAM2) because either IPv6 DA or SA can be checked for filtering."]
pub type L3dam2R = crate::BitReader;
#[doc = "Field `l3dam2` writer - When set, this bit indicates that Layer 3 IP Destination Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Destination Address field for matching. Note: When Bit 0 (L3PEN2) is set, you should set either this bit or Bit 2 (L3SAM2) because either IPv6 DA or SA can be checked for filtering."]
pub type L3dam2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3daim2` reader - When set, this bit indicates that the Layer 3 IP Destination Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Destination Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 4 (L3DAM2) is set high."]
pub type L3daim2R = crate::BitReader;
#[doc = "Field `l3daim2` writer - When set, this bit indicates that the Layer 3 IP Destination Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Destination Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 4 (L3DAM2) is set high."]
pub type L3daim2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3hsbm2` reader - Layer 3 IP SA Higher Bits Match IPv4 Frames: This field contains the number of lower bits of IP Source Address that are masked for matching in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: This field contains Bits \\[4:0\\]
of the field that indicates the number of higher bits of IP Source or Destination Address matched in the IPv6 frames. This field is valid and applicable only if L3DAM2 or L3SAM2 is set high."]
pub type L3hsbm2R = crate::FieldReader;
#[doc = "Field `l3hsbm2` writer - Layer 3 IP SA Higher Bits Match IPv4 Frames: This field contains the number of lower bits of IP Source Address that are masked for matching in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: This field contains Bits \\[4:0\\]
of the field that indicates the number of higher bits of IP Source or Destination Address matched in the IPv6 frames. This field is valid and applicable only if L3DAM2 or L3SAM2 is set high."]
pub type L3hsbm2W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `l3hdbm2` reader - IPv4 Frames: This field contains the number of higher bits of IP Destination Address that are matched in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: Bits \\[12:11\\]
of this field correspond to Bits \\[6:5\\]
of L3HSBM2, which indicate the number of lower bits of IP Source or Destination Address that are masked in the IPv6 frames. The following list describes the concatenated values of the L3HDBM2\\[1:0\\]
and L3HSBM2 bits: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 127: All bits except MSb are masked. This field is valid and applicable only if L3DAM2 or L3SAM2 is set high."]
pub type L3hdbm2R = crate::FieldReader;
#[doc = "Field `l3hdbm2` writer - IPv4 Frames: This field contains the number of higher bits of IP Destination Address that are matched in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: Bits \\[12:11\\]
of this field correspond to Bits \\[6:5\\]
of L3HSBM2, which indicate the number of lower bits of IP Source or Destination Address that are masked in the IPv6 frames. The following list describes the concatenated values of the L3HDBM2\\[1:0\\]
and L3HSBM2 bits: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 127: All bits except MSb are masked. This field is valid and applicable only if L3DAM2 or L3SAM2 is set high."]
pub type L3hdbm2W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `l4pen2` reader - When set, this bit indicates that the Source and Destination Port number fields for UDP frames are used for matching. When reset, this bit indicates that the Source and Destination Port number fields for TCP frames are used for matching. The Layer 4 matching is done only when either L4SPM2 or L4DPM2 bit is set high."]
pub type L4pen2R = crate::BitReader;
#[doc = "Field `l4pen2` writer - When set, this bit indicates that the Source and Destination Port number fields for UDP frames are used for matching. When reset, this bit indicates that the Source and Destination Port number fields for TCP frames are used for matching. The Layer 4 matching is done only when either L4SPM2 or L4DPM2 bit is set high."]
pub type L4pen2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4spm2` reader - When set, this bit indicates that the Layer 4 Source Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Source Port number field for matching."]
pub type L4spm2R = crate::BitReader;
#[doc = "Field `l4spm2` writer - When set, this bit indicates that the Layer 4 Source Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Source Port number field for matching."]
pub type L4spm2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4spim2` reader - When set, this bit indicates that the Layer 4 Source Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Source Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 18 (L4SPM2) is set high."]
pub type L4spim2R = crate::BitReader;
#[doc = "Field `l4spim2` writer - When set, this bit indicates that the Layer 4 Source Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Source Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 18 (L4SPM2) is set high."]
pub type L4spim2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4dpm2` reader - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Destination Port number field for matching."]
pub type L4dpm2R = crate::BitReader;
#[doc = "Field `l4dpm2` writer - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Destination Port number field for matching."]
pub type L4dpm2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4dpim2` reader - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Destination Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 20 (L4DPM0) is set high."]
pub type L4dpim2R = crate::BitReader;
#[doc = "Field `l4dpim2` writer - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Destination Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 20 (L4DPM0) is set high."]
pub type L4dpim2W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When set, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv6 frames. When reset, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv4 frames. The Layer 3 matching is done only when either L3SAM2 or L3DAM2 bit is set high."]
    #[inline(always)]
    pub fn l3pen2(&self) -> L3pen2R {
        L3pen2R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 2 - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Source Address field for matching. Note: When Bit 0 (L3PEN2) is set, you should set either this bit or Bit 4 (L3DAM2) because either IPv6 SA or DA can be checked for filtering."]
    #[inline(always)]
    pub fn l3sam2(&self) -> L3sam2R {
        L3sam2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Source Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 2 (L3SAM2) is set high."]
    #[inline(always)]
    pub fn l3saim2(&self) -> L3saim2R {
        L3saim2R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - When set, this bit indicates that Layer 3 IP Destination Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Destination Address field for matching. Note: When Bit 0 (L3PEN2) is set, you should set either this bit or Bit 2 (L3SAM2) because either IPv6 DA or SA can be checked for filtering."]
    #[inline(always)]
    pub fn l3dam2(&self) -> L3dam2R {
        L3dam2R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When set, this bit indicates that the Layer 3 IP Destination Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Destination Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 4 (L3DAM2) is set high."]
    #[inline(always)]
    pub fn l3daim2(&self) -> L3daim2R {
        L3daim2R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:10 - Layer 3 IP SA Higher Bits Match IPv4 Frames: This field contains the number of lower bits of IP Source Address that are masked for matching in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: This field contains Bits \\[4:0\\]
of the field that indicates the number of higher bits of IP Source or Destination Address matched in the IPv6 frames. This field is valid and applicable only if L3DAM2 or L3SAM2 is set high."]
    #[inline(always)]
    pub fn l3hsbm2(&self) -> L3hsbm2R {
        L3hsbm2R::new(((self.bits >> 6) & 0x1f) as u8)
    }
    #[doc = "Bits 11:15 - IPv4 Frames: This field contains the number of higher bits of IP Destination Address that are matched in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: Bits \\[12:11\\]
of this field correspond to Bits \\[6:5\\]
of L3HSBM2, which indicate the number of lower bits of IP Source or Destination Address that are masked in the IPv6 frames. The following list describes the concatenated values of the L3HDBM2\\[1:0\\]
and L3HSBM2 bits: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 127: All bits except MSb are masked. This field is valid and applicable only if L3DAM2 or L3SAM2 is set high."]
    #[inline(always)]
    pub fn l3hdbm2(&self) -> L3hdbm2R {
        L3hdbm2R::new(((self.bits >> 11) & 0x1f) as u8)
    }
    #[doc = "Bit 16 - When set, this bit indicates that the Source and Destination Port number fields for UDP frames are used for matching. When reset, this bit indicates that the Source and Destination Port number fields for TCP frames are used for matching. The Layer 4 matching is done only when either L4SPM2 or L4DPM2 bit is set high."]
    #[inline(always)]
    pub fn l4pen2(&self) -> L4pen2R {
        L4pen2R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 18 - When set, this bit indicates that the Layer 4 Source Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Source Port number field for matching."]
    #[inline(always)]
    pub fn l4spm2(&self) -> L4spm2R {
        L4spm2R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - When set, this bit indicates that the Layer 4 Source Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Source Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 18 (L4SPM2) is set high."]
    #[inline(always)]
    pub fn l4spim2(&self) -> L4spim2R {
        L4spim2R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Destination Port number field for matching."]
    #[inline(always)]
    pub fn l4dpm2(&self) -> L4dpm2R {
        L4dpm2R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Destination Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 20 (L4DPM0) is set high."]
    #[inline(always)]
    pub fn l4dpim2(&self) -> L4dpim2R {
        L4dpim2R::new(((self.bits >> 21) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When set, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv6 frames. When reset, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv4 frames. The Layer 3 matching is done only when either L3SAM2 or L3DAM2 bit is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3pen2(&mut self) -> L3pen2W<GmacgrpL3L4Control2Spec> {
        L3pen2W::new(self, 0)
    }
    #[doc = "Bit 2 - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Source Address field for matching. Note: When Bit 0 (L3PEN2) is set, you should set either this bit or Bit 4 (L3DAM2) because either IPv6 SA or DA can be checked for filtering."]
    #[inline(always)]
    #[must_use]
    pub fn l3sam2(&mut self) -> L3sam2W<GmacgrpL3L4Control2Spec> {
        L3sam2W::new(self, 2)
    }
    #[doc = "Bit 3 - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Source Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 2 (L3SAM2) is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3saim2(&mut self) -> L3saim2W<GmacgrpL3L4Control2Spec> {
        L3saim2W::new(self, 3)
    }
    #[doc = "Bit 4 - When set, this bit indicates that Layer 3 IP Destination Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Destination Address field for matching. Note: When Bit 0 (L3PEN2) is set, you should set either this bit or Bit 2 (L3SAM2) because either IPv6 DA or SA can be checked for filtering."]
    #[inline(always)]
    #[must_use]
    pub fn l3dam2(&mut self) -> L3dam2W<GmacgrpL3L4Control2Spec> {
        L3dam2W::new(self, 4)
    }
    #[doc = "Bit 5 - When set, this bit indicates that the Layer 3 IP Destination Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Destination Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 4 (L3DAM2) is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3daim2(&mut self) -> L3daim2W<GmacgrpL3L4Control2Spec> {
        L3daim2W::new(self, 5)
    }
    #[doc = "Bits 6:10 - Layer 3 IP SA Higher Bits Match IPv4 Frames: This field contains the number of lower bits of IP Source Address that are masked for matching in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: This field contains Bits \\[4:0\\]
of the field that indicates the number of higher bits of IP Source or Destination Address matched in the IPv6 frames. This field is valid and applicable only if L3DAM2 or L3SAM2 is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3hsbm2(&mut self) -> L3hsbm2W<GmacgrpL3L4Control2Spec> {
        L3hsbm2W::new(self, 6)
    }
    #[doc = "Bits 11:15 - IPv4 Frames: This field contains the number of higher bits of IP Destination Address that are matched in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: Bits \\[12:11\\]
of this field correspond to Bits \\[6:5\\]
of L3HSBM2, which indicate the number of lower bits of IP Source or Destination Address that are masked in the IPv6 frames. The following list describes the concatenated values of the L3HDBM2\\[1:0\\]
and L3HSBM2 bits: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 127: All bits except MSb are masked. This field is valid and applicable only if L3DAM2 or L3SAM2 is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3hdbm2(&mut self) -> L3hdbm2W<GmacgrpL3L4Control2Spec> {
        L3hdbm2W::new(self, 11)
    }
    #[doc = "Bit 16 - When set, this bit indicates that the Source and Destination Port number fields for UDP frames are used for matching. When reset, this bit indicates that the Source and Destination Port number fields for TCP frames are used for matching. The Layer 4 matching is done only when either L4SPM2 or L4DPM2 bit is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l4pen2(&mut self) -> L4pen2W<GmacgrpL3L4Control2Spec> {
        L4pen2W::new(self, 16)
    }
    #[doc = "Bit 18 - When set, this bit indicates that the Layer 4 Source Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Source Port number field for matching."]
    #[inline(always)]
    #[must_use]
    pub fn l4spm2(&mut self) -> L4spm2W<GmacgrpL3L4Control2Spec> {
        L4spm2W::new(self, 18)
    }
    #[doc = "Bit 19 - When set, this bit indicates that the Layer 4 Source Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Source Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 18 (L4SPM2) is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l4spim2(&mut self) -> L4spim2W<GmacgrpL3L4Control2Spec> {
        L4spim2W::new(self, 19)
    }
    #[doc = "Bit 20 - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Destination Port number field for matching."]
    #[inline(always)]
    #[must_use]
    pub fn l4dpm2(&mut self) -> L4dpm2W<GmacgrpL3L4Control2Spec> {
        L4dpm2W::new(self, 20)
    }
    #[doc = "Bit 21 - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Destination Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 20 (L4DPM0) is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l4dpim2(&mut self) -> L4dpim2W<GmacgrpL3L4Control2Spec> {
        L4dpim2W::new(self, 21)
    }
}
#[doc = "This register controls the operations of the filter 2 of Layer 3 and Layer 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_l3_l4_control2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_l3_l4_control2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpL3L4Control2Spec;
impl crate::RegisterSpec for GmacgrpL3L4Control2Spec {
    type Ux = u32;
    const OFFSET: u64 = 1120u64;
}
#[doc = "`read()` method returns [`gmacgrp_l3_l4_control2::R`](R) reader structure"]
impl crate::Readable for GmacgrpL3L4Control2Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_l3_l4_control2::W`](W) writer structure"]
impl crate::Writable for GmacgrpL3L4Control2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_L3_L4_Control2 to value 0"]
impl crate::Resettable for GmacgrpL3L4Control2Spec {
    const RESET_VALUE: u32 = 0;
}
