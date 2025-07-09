// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `RFW` reader"]
pub type R = crate::R<RfwSpec>;
#[doc = "Register `RFW` writer"]
pub type W = crate::W<RfwSpec>;
#[doc = "Field `rfwd` reader - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, the data that is written to the RFWD is pushed into the receive FIFO. Each consecutive write pushes the new data to the next write location in the receive FIFO. When FIFO's are not enabled, the data that is written to the RFWD is pushed into the RBR."]
pub type RfwdR = crate::FieldReader;
#[doc = "Field `rfwd` writer - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, the data that is written to the RFWD is pushed into the receive FIFO. Each consecutive write pushes the new data to the next write location in the receive FIFO. When FIFO's are not enabled, the data that is written to the RFWD is pushed into the RBR."]
pub type RfwdW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `rfpe` reader - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, this bit is used to write parity error detection information to the receive FIFO. When FIFO's are not enabled, this bit is used to write parity error detection information to the RBR."]
pub type RfpeR = crate::BitReader;
#[doc = "Field `rfpe` writer - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, this bit is used to write parity error detection information to the receive FIFO. When FIFO's are not enabled, this bit is used to write parity error detection information to the RBR."]
pub type RfpeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RFFE` reader - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, this bit is used to write framing error detection information to the receive FIFO. When FIFO's are not enabled, this bit is used to write framing error detection information to the RBR."]
pub type RffeR = crate::BitReader;
#[doc = "Field `RFFE` writer - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, this bit is used to write framing error detection information to the receive FIFO. When FIFO's are not enabled, this bit is used to write framing error detection information to the RBR."]
pub type RffeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:7 - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, the data that is written to the RFWD is pushed into the receive FIFO. Each consecutive write pushes the new data to the next write location in the receive FIFO. When FIFO's are not enabled, the data that is written to the RFWD is pushed into the RBR."]
    #[inline(always)]
    pub fn rfwd(&self) -> RfwdR {
        RfwdR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bit 8 - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, this bit is used to write parity error detection information to the receive FIFO. When FIFO's are not enabled, this bit is used to write parity error detection information to the RBR."]
    #[inline(always)]
    pub fn rfpe(&self) -> RfpeR {
        RfpeR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, this bit is used to write framing error detection information to the receive FIFO. When FIFO's are not enabled, this bit is used to write framing error detection information to the RBR."]
    #[inline(always)]
    pub fn rffe(&self) -> RffeR {
        RffeR::new(((self.bits >> 9) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:7 - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, the data that is written to the RFWD is pushed into the receive FIFO. Each consecutive write pushes the new data to the next write location in the receive FIFO. When FIFO's are not enabled, the data that is written to the RFWD is pushed into the RBR."]
    #[inline(always)]
    #[must_use]
    pub fn rfwd(&mut self) -> RfwdW<RfwSpec> {
        RfwdW::new(self, 0)
    }
    #[doc = "Bit 8 - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, this bit is used to write parity error detection information to the receive FIFO. When FIFO's are not enabled, this bit is used to write parity error detection information to the RBR."]
    #[inline(always)]
    #[must_use]
    pub fn rfpe(&mut self) -> RfpeW<RfwSpec> {
        RfpeW::new(self, 8)
    }
    #[doc = "Bit 9 - These bits are only valid when FIFO access mode is enabled (FAR\\[0\\]
is set to one). When FIFO's are enabled, this bit is used to write framing error detection information to the receive FIFO. When FIFO's are not enabled, this bit is used to write framing error detection information to the RBR."]
    #[inline(always)]
    #[must_use]
    pub fn rffe(&mut self) -> RffeW<RfwSpec> {
        RffeW::new(self, 9)
    }
}
#[doc = "Used only with FIFO access test mode.\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rfw::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RfwSpec;
impl crate::RegisterSpec for RfwSpec {
    type Ux = u32;
    const OFFSET: u64 = 120u64;
}
#[doc = "`write(|w| ..)` method takes [`rfw::W`](W) writer structure"]
impl crate::Writable for RfwSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets RFW to value 0"]
impl crate::Resettable for RfwSpec {
    const RESET_VALUE: u32 = 0;
}
