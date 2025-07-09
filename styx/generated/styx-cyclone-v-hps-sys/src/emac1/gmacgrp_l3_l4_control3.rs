// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_L3_L4_Control3` reader"]
pub type R = crate::R<GmacgrpL3L4Control3Spec>;
#[doc = "Register `gmacgrp_L3_L4_Control3` writer"]
pub type W = crate::W<GmacgrpL3L4Control3Spec>;
#[doc = "Field `l3pen3` reader - When set, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv6 frames. When reset, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv4 frames. The Layer 3 matching is done only when either L3SAM3 or L3DAM3 bit is set high."]
pub type L3pen3R = crate::BitReader;
#[doc = "Field `l3pen3` writer - When set, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv6 frames. When reset, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv4 frames. The Layer 3 matching is done only when either L3SAM3 or L3DAM3 bit is set high."]
pub type L3pen3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3sam3` reader - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Source Address field for matching. Note: When Bit 0 (L3PEN3) is set, you should set either this bit or Bit 4 (L3DAM3) because either IPv6 SA or DA can be checked for filtering."]
pub type L3sam3R = crate::BitReader;
#[doc = "Field `l3sam3` writer - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Source Address field for matching. Note: When Bit 0 (L3PEN3) is set, you should set either this bit or Bit 4 (L3DAM3) because either IPv6 SA or DA can be checked for filtering."]
pub type L3sam3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3saim3` reader - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Source Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 2 (L3SAM3) is set high."]
pub type L3saim3R = crate::BitReader;
#[doc = "Field `l3saim3` writer - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Source Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 2 (L3SAM3) is set high."]
pub type L3saim3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3dam3` reader - When set, this bit indicates that Layer 3 IP Destination Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Destination Address field for matching. Note: When Bit 0 (L3PEN3) is set, you should set either this bit or Bit 2 (L3SAM3) because either IPv6 DA or SA can be checked for filtering."]
pub type L3dam3R = crate::BitReader;
#[doc = "Field `l3dam3` writer - When set, this bit indicates that Layer 3 IP Destination Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Destination Address field for matching. Note: When Bit 0 (L3PEN3) is set, you should set either this bit or Bit 2 (L3SAM3) because either IPv6 DA or SA can be checked for filtering."]
pub type L3dam3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3daim3` reader - When set, this bit indicates that the Layer 3 IP Destination Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Destination Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 4 (L3DAM3) is set high."]
pub type L3daim3R = crate::BitReader;
#[doc = "Field `l3daim3` writer - When set, this bit indicates that the Layer 3 IP Destination Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Destination Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 4 (L3DAM3) is set high."]
pub type L3daim3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l3hsbm3` reader - IPv4 Frames: This field contains the number of lower bits of IP Source Address that are masked for matching in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: This field contains Bits \\[4:0\\]
of the field that indicates the number of higher bits of IP Source or Destination Address matched in the IPv6 frames. This field is valid and applicable only if L3DAM3 or L3SAM3 is set high."]
pub type L3hsbm3R = crate::FieldReader;
#[doc = "Field `l3hsbm3` writer - IPv4 Frames: This field contains the number of lower bits of IP Source Address that are masked for matching in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: This field contains Bits \\[4:0\\]
of the field that indicates the number of higher bits of IP Source or Destination Address matched in the IPv6 frames. This field is valid and applicable only if L3DAM3 or L3SAM3 is set high."]
pub type L3hsbm3W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `l3hdbm3` reader - Layer 3 IP DA Higher Bits Match IPv4 Frames: This field contains the number of higher bits of IP Destination Address that are matched in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: Bits \\[12:11\\]
of this field correspond to Bits \\[6:5\\]
of L3HSBM3, which indicate the number of lower bits of IP Source or Destination Address that are masked in the IPv6 frames. The following list describes the concatenated values of the L3HDBM3\\[1:0\\]
and L3HSBM3 bits: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 127: All bits except MSb are masked. This field is valid and applicable only if L3DAM3 or L3SAM3 is set high."]
pub type L3hdbm3R = crate::FieldReader;
#[doc = "Field `l3hdbm3` writer - Layer 3 IP DA Higher Bits Match IPv4 Frames: This field contains the number of higher bits of IP Destination Address that are matched in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: Bits \\[12:11\\]
of this field correspond to Bits \\[6:5\\]
of L3HSBM3, which indicate the number of lower bits of IP Source or Destination Address that are masked in the IPv6 frames. The following list describes the concatenated values of the L3HDBM3\\[1:0\\]
and L3HSBM3 bits: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 127: All bits except MSb are masked. This field is valid and applicable only if L3DAM3 or L3SAM3 is set high."]
pub type L3hdbm3W<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `l4pen3` reader - When set, this bit indicates that the Source and Destination Port number fields for UDP frames are used for matching. When reset, this bit indicates that the Source and Destination Port number fields for TCP frames are used for matching. The Layer 4 matching is done only when either L4SPM3 or L4DPM3 bit is set high."]
pub type L4pen3R = crate::BitReader;
#[doc = "Field `l4pen3` writer - When set, this bit indicates that the Source and Destination Port number fields for UDP frames are used for matching. When reset, this bit indicates that the Source and Destination Port number fields for TCP frames are used for matching. The Layer 4 matching is done only when either L4SPM3 or L4DPM3 bit is set high."]
pub type L4pen3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4spm3` reader - When set, this bit indicates that the Layer 4 Source Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Source Port number field for matching."]
pub type L4spm3R = crate::BitReader;
#[doc = "Field `l4spm3` writer - When set, this bit indicates that the Layer 4 Source Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Source Port number field for matching."]
pub type L4spm3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4spim3` reader - When set, this bit indicates that the Layer 4 Source Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Source Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 18 (L4SPM3) is set high."]
pub type L4spim3R = crate::BitReader;
#[doc = "Field `l4spim3` writer - When set, this bit indicates that the Layer 4 Source Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Source Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 18 (L4SPM3) is set high."]
pub type L4spim3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4dpm3` reader - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Destination Port number field for matching."]
pub type L4dpm3R = crate::BitReader;
#[doc = "Field `l4dpm3` writer - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Destination Port number field for matching."]
pub type L4dpm3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `l4dpim3` reader - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Destination Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 20 (L4DPM3) is set high."]
pub type L4dpim3R = crate::BitReader;
#[doc = "Field `l4dpim3` writer - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Destination Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 20 (L4DPM3) is set high."]
pub type L4dpim3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - When set, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv6 frames. When reset, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv4 frames. The Layer 3 matching is done only when either L3SAM3 or L3DAM3 bit is set high."]
    #[inline(always)]
    pub fn l3pen3(&self) -> L3pen3R {
        L3pen3R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 2 - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Source Address field for matching. Note: When Bit 0 (L3PEN3) is set, you should set either this bit or Bit 4 (L3DAM3) because either IPv6 SA or DA can be checked for filtering."]
    #[inline(always)]
    pub fn l3sam3(&self) -> L3sam3R {
        L3sam3R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Source Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 2 (L3SAM3) is set high."]
    #[inline(always)]
    pub fn l3saim3(&self) -> L3saim3R {
        L3saim3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - When set, this bit indicates that Layer 3 IP Destination Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Destination Address field for matching. Note: When Bit 0 (L3PEN3) is set, you should set either this bit or Bit 2 (L3SAM3) because either IPv6 DA or SA can be checked for filtering."]
    #[inline(always)]
    pub fn l3dam3(&self) -> L3dam3R {
        L3dam3R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - When set, this bit indicates that the Layer 3 IP Destination Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Destination Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 4 (L3DAM3) is set high."]
    #[inline(always)]
    pub fn l3daim3(&self) -> L3daim3R {
        L3daim3R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bits 6:10 - IPv4 Frames: This field contains the number of lower bits of IP Source Address that are masked for matching in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: This field contains Bits \\[4:0\\]
of the field that indicates the number of higher bits of IP Source or Destination Address matched in the IPv6 frames. This field is valid and applicable only if L3DAM3 or L3SAM3 is set high."]
    #[inline(always)]
    pub fn l3hsbm3(&self) -> L3hsbm3R {
        L3hsbm3R::new(((self.bits >> 6) & 0x1f) as u8)
    }
    #[doc = "Bits 11:15 - Layer 3 IP DA Higher Bits Match IPv4 Frames: This field contains the number of higher bits of IP Destination Address that are matched in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: Bits \\[12:11\\]
of this field correspond to Bits \\[6:5\\]
of L3HSBM3, which indicate the number of lower bits of IP Source or Destination Address that are masked in the IPv6 frames. The following list describes the concatenated values of the L3HDBM3\\[1:0\\]
and L3HSBM3 bits: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 127: All bits except MSb are masked. This field is valid and applicable only if L3DAM3 or L3SAM3 is set high."]
    #[inline(always)]
    pub fn l3hdbm3(&self) -> L3hdbm3R {
        L3hdbm3R::new(((self.bits >> 11) & 0x1f) as u8)
    }
    #[doc = "Bit 16 - When set, this bit indicates that the Source and Destination Port number fields for UDP frames are used for matching. When reset, this bit indicates that the Source and Destination Port number fields for TCP frames are used for matching. The Layer 4 matching is done only when either L4SPM3 or L4DPM3 bit is set high."]
    #[inline(always)]
    pub fn l4pen3(&self) -> L4pen3R {
        L4pen3R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 18 - When set, this bit indicates that the Layer 4 Source Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Source Port number field for matching."]
    #[inline(always)]
    pub fn l4spm3(&self) -> L4spm3R {
        L4spm3R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - When set, this bit indicates that the Layer 4 Source Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Source Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 18 (L4SPM3) is set high."]
    #[inline(always)]
    pub fn l4spim3(&self) -> L4spim3R {
        L4spim3R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Destination Port number field for matching."]
    #[inline(always)]
    pub fn l4dpm3(&self) -> L4dpm3R {
        L4dpm3R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Destination Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 20 (L4DPM3) is set high."]
    #[inline(always)]
    pub fn l4dpim3(&self) -> L4dpim3R {
        L4dpim3R::new(((self.bits >> 21) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When set, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv6 frames. When reset, this bit indicates that the Layer 3 IP Source or Destination Address matching is enabled for the IPv4 frames. The Layer 3 matching is done only when either L3SAM3 or L3DAM3 bit is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3pen3(&mut self) -> L3pen3W<GmacgrpL3L4Control3Spec> {
        L3pen3W::new(self, 0)
    }
    #[doc = "Bit 2 - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Source Address field for matching. Note: When Bit 0 (L3PEN3) is set, you should set either this bit or Bit 4 (L3DAM3) because either IPv6 SA or DA can be checked for filtering."]
    #[inline(always)]
    #[must_use]
    pub fn l3sam3(&mut self) -> L3sam3W<GmacgrpL3L4Control3Spec> {
        L3sam3W::new(self, 2)
    }
    #[doc = "Bit 3 - When set, this bit indicates that the Layer 3 IP Source Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Source Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 2 (L3SAM3) is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3saim3(&mut self) -> L3saim3W<GmacgrpL3L4Control3Spec> {
        L3saim3W::new(self, 3)
    }
    #[doc = "Bit 4 - When set, this bit indicates that Layer 3 IP Destination Address field is enabled for matching. When reset, the MAC ignores the Layer 3 IP Destination Address field for matching. Note: When Bit 0 (L3PEN3) is set, you should set either this bit or Bit 2 (L3SAM3) because either IPv6 DA or SA can be checked for filtering."]
    #[inline(always)]
    #[must_use]
    pub fn l3dam3(&mut self) -> L3dam3W<GmacgrpL3L4Control3Spec> {
        L3dam3W::new(self, 4)
    }
    #[doc = "Bit 5 - When set, this bit indicates that the Layer 3 IP Destination Address field is enabled for inverse matching. When reset, this bit indicates that the Layer 3 IP Destination Address field is enabled for perfect matching. This bit is valid and applicable only when Bit 4 (L3DAM3) is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3daim3(&mut self) -> L3daim3W<GmacgrpL3L4Control3Spec> {
        L3daim3W::new(self, 5)
    }
    #[doc = "Bits 6:10 - IPv4 Frames: This field contains the number of lower bits of IP Source Address that are masked for matching in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: This field contains Bits \\[4:0\\]
of the field that indicates the number of higher bits of IP Source or Destination Address matched in the IPv6 frames. This field is valid and applicable only if L3DAM3 or L3SAM3 is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3hsbm3(&mut self) -> L3hsbm3W<GmacgrpL3L4Control3Spec> {
        L3hsbm3W::new(self, 6)
    }
    #[doc = "Bits 11:15 - Layer 3 IP DA Higher Bits Match IPv4 Frames: This field contains the number of higher bits of IP Destination Address that are matched in the IPv4 frames. The following list describes the values of this field: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 31: All bits except MSb are masked. IPv6 Frames: Bits \\[12:11\\]
of this field correspond to Bits \\[6:5\\]
of L3HSBM3, which indicate the number of lower bits of IP Source or Destination Address that are masked in the IPv6 frames. The following list describes the concatenated values of the L3HDBM3\\[1:0\\]
and L3HSBM3 bits: * 0: No bits are masked. * 1: LSb\\[0\\]
is masked. * 2: Two LSbs \\[1:0\\]
are masked. * ... * 127: All bits except MSb are masked. This field is valid and applicable only if L3DAM3 or L3SAM3 is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l3hdbm3(&mut self) -> L3hdbm3W<GmacgrpL3L4Control3Spec> {
        L3hdbm3W::new(self, 11)
    }
    #[doc = "Bit 16 - When set, this bit indicates that the Source and Destination Port number fields for UDP frames are used for matching. When reset, this bit indicates that the Source and Destination Port number fields for TCP frames are used for matching. The Layer 4 matching is done only when either L4SPM3 or L4DPM3 bit is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l4pen3(&mut self) -> L4pen3W<GmacgrpL3L4Control3Spec> {
        L4pen3W::new(self, 16)
    }
    #[doc = "Bit 18 - When set, this bit indicates that the Layer 4 Source Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Source Port number field for matching."]
    #[inline(always)]
    #[must_use]
    pub fn l4spm3(&mut self) -> L4spm3W<GmacgrpL3L4Control3Spec> {
        L4spm3W::new(self, 18)
    }
    #[doc = "Bit 19 - When set, this bit indicates that the Layer 4 Source Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Source Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 18 (L4SPM3) is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l4spim3(&mut self) -> L4spim3W<GmacgrpL3L4Control3Spec> {
        L4spim3W::new(self, 19)
    }
    #[doc = "Bit 20 - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for matching. When reset, the MAC ignores the Layer 4 Destination Port number field for matching."]
    #[inline(always)]
    #[must_use]
    pub fn l4dpm3(&mut self) -> L4dpm3W<GmacgrpL3L4Control3Spec> {
        L4dpm3W::new(self, 20)
    }
    #[doc = "Bit 21 - When set, this bit indicates that the Layer 4 Destination Port number field is enabled for inverse matching. When reset, this bit indicates that the Layer 4 Destination Port number field is enabled for perfect matching. This bit is valid and applicable only when Bit 20 (L4DPM3) is set high."]
    #[inline(always)]
    #[must_use]
    pub fn l4dpim3(&mut self) -> L4dpim3W<GmacgrpL3L4Control3Spec> {
        L4dpim3W::new(self, 21)
    }
}
#[doc = "This register controls the operations of the filter 0 of Layer 3 and Layer 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_l3_l4_control3::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`gmacgrp_l3_l4_control3::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpL3L4Control3Spec;
impl crate::RegisterSpec for GmacgrpL3L4Control3Spec {
    type Ux = u32;
    const OFFSET: u64 = 1168u64;
}
#[doc = "`read()` method returns [`gmacgrp_l3_l4_control3::R`](R) reader structure"]
impl crate::Readable for GmacgrpL3L4Control3Spec {}
#[doc = "`write(|w| ..)` method takes [`gmacgrp_l3_l4_control3::W`](W) writer structure"]
impl crate::Writable for GmacgrpL3L4Control3Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets gmacgrp_L3_L4_Control3 to value 0"]
impl crate::Resettable for GmacgrpL3L4Control3Spec {
    const RESET_VALUE: u32 = 0;
}
