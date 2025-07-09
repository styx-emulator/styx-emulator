// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_tx_tl` reader"]
pub type R = crate::R<IcTxTlSpec>;
#[doc = "Register `ic_tx_tl` writer"]
pub type W = crate::W<IcTxTlSpec>;
#[doc = "Field `tx_tl` reader - Controls the level of entries (or below) that trigger the TX_EMPTY interrupt (bit 4 in ic_raw_intr_stat register). The valid range is 0-255, with the additional restriction that it may not be set to value larger than the depth of the buffer. If an attempt is made to do that, the actual value set will be the maximum depth of the buffer. A value of 0 sets the threshold for 0 entries, and a value of 255 sets the threshold for 255 entries."]
pub type TxTlR = crate::FieldReader;
#[doc = "Field `tx_tl` writer - Controls the level of entries (or below) that trigger the TX_EMPTY interrupt (bit 4 in ic_raw_intr_stat register). The valid range is 0-255, with the additional restriction that it may not be set to value larger than the depth of the buffer. If an attempt is made to do that, the actual value set will be the maximum depth of the buffer. A value of 0 sets the threshold for 0 entries, and a value of 255 sets the threshold for 255 entries."]
pub type TxTlW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Controls the level of entries (or below) that trigger the TX_EMPTY interrupt (bit 4 in ic_raw_intr_stat register). The valid range is 0-255, with the additional restriction that it may not be set to value larger than the depth of the buffer. If an attempt is made to do that, the actual value set will be the maximum depth of the buffer. A value of 0 sets the threshold for 0 entries, and a value of 255 sets the threshold for 255 entries."]
    #[inline(always)]
    pub fn tx_tl(&self) -> TxTlR {
        TxTlR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Controls the level of entries (or below) that trigger the TX_EMPTY interrupt (bit 4 in ic_raw_intr_stat register). The valid range is 0-255, with the additional restriction that it may not be set to value larger than the depth of the buffer. If an attempt is made to do that, the actual value set will be the maximum depth of the buffer. A value of 0 sets the threshold for 0 entries, and a value of 255 sets the threshold for 255 entries."]
    #[inline(always)]
    #[must_use]
    pub fn tx_tl(&mut self) -> TxTlW<IcTxTlSpec> {
        TxTlW::new(self, 0)
    }
}
#[doc = "Sets FIFO depth for Interrupt.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_tx_tl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_tx_tl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcTxTlSpec;
impl crate::RegisterSpec for IcTxTlSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`ic_tx_tl::R`](R) reader structure"]
impl crate::Readable for IcTxTlSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_tx_tl::W`](W) writer structure"]
impl crate::Writable for IcTxTlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_tx_tl to value 0"]
impl crate::Resettable for IcTxTlSpec {
    const RESET_VALUE: u32 = 0;
}
