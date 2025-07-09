// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_rx_tl` reader"]
pub type R = crate::R<IcRxTlSpec>;
#[doc = "Register `ic_rx_tl` writer"]
pub type W = crate::W<IcRxTlSpec>;
#[doc = "Field `rx_tl` reader - Controls the level of entries (or above) that triggers the RX_FULL interrupt (bit 2 in IC_RAW_INTR_STAT register). The valid range is 0-255, with the additional restriction that hardware does not allow this value to be set to a value larger than the depth of the buffer. If an attempt is made to do that, the actual value set will be the maximum depth of the buffer. A value of 0 sets the threshold for 1 entry, and a value of 255 sets the threshold for 256 entries."]
pub type RxTlR = crate::FieldReader;
#[doc = "Field `rx_tl` writer - Controls the level of entries (or above) that triggers the RX_FULL interrupt (bit 2 in IC_RAW_INTR_STAT register). The valid range is 0-255, with the additional restriction that hardware does not allow this value to be set to a value larger than the depth of the buffer. If an attempt is made to do that, the actual value set will be the maximum depth of the buffer. A value of 0 sets the threshold for 1 entry, and a value of 255 sets the threshold for 256 entries."]
pub type RxTlW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Controls the level of entries (or above) that triggers the RX_FULL interrupt (bit 2 in IC_RAW_INTR_STAT register). The valid range is 0-255, with the additional restriction that hardware does not allow this value to be set to a value larger than the depth of the buffer. If an attempt is made to do that, the actual value set will be the maximum depth of the buffer. A value of 0 sets the threshold for 1 entry, and a value of 255 sets the threshold for 256 entries."]
    #[inline(always)]
    pub fn rx_tl(&self) -> RxTlR {
        RxTlR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Controls the level of entries (or above) that triggers the RX_FULL interrupt (bit 2 in IC_RAW_INTR_STAT register). The valid range is 0-255, with the additional restriction that hardware does not allow this value to be set to a value larger than the depth of the buffer. If an attempt is made to do that, the actual value set will be the maximum depth of the buffer. A value of 0 sets the threshold for 1 entry, and a value of 255 sets the threshold for 256 entries."]
    #[inline(always)]
    #[must_use]
    pub fn rx_tl(&mut self) -> RxTlW<IcRxTlSpec> {
        RxTlW::new(self, 0)
    }
}
#[doc = "I2C Receive FIFO Threshold Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_rx_tl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_rx_tl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcRxTlSpec;
impl crate::RegisterSpec for IcRxTlSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`ic_rx_tl::R`](R) reader structure"]
impl crate::Readable for IcRxTlSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_rx_tl::W`](W) writer structure"]
impl crate::Writable for IcRxTlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_rx_tl to value 0"]
impl crate::Resettable for IcRxTlSpec {
    const RESET_VALUE: u32 = 0;
}
