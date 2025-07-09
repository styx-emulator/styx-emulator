// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_ack_general_call` reader"]
pub type R = crate::R<IcAckGeneralCallSpec>;
#[doc = "Register `ic_ack_general_call` writer"]
pub type W = crate::W<IcAckGeneralCallSpec>;
#[doc = "When an ACK is asserted, (by asserting i2c_out_data) when it receives a General call. Otherwise, i2c responds with a NACK (by negating i2c_out_data).\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckGenCall {
    #[doc = "0: `0`"]
    Nack = 0,
    #[doc = "1: `1`"]
    Ack = 1,
}
impl From<AckGenCall> for bool {
    #[inline(always)]
    fn from(variant: AckGenCall) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `ack_gen_call` reader - When an ACK is asserted, (by asserting i2c_out_data) when it receives a General call. Otherwise, i2c responds with a NACK (by negating i2c_out_data)."]
pub type AckGenCallR = crate::BitReader<AckGenCall>;
impl AckGenCallR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> AckGenCall {
        match self.bits {
            false => AckGenCall::Nack,
            true => AckGenCall::Ack,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nack(&self) -> bool {
        *self == AckGenCall::Nack
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_ack(&self) -> bool {
        *self == AckGenCall::Ack
    }
}
#[doc = "Field `ack_gen_call` writer - When an ACK is asserted, (by asserting i2c_out_data) when it receives a General call. Otherwise, i2c responds with a NACK (by negating i2c_out_data)."]
pub type AckGenCallW<'a, REG> = crate::BitWriter<'a, REG, AckGenCall>;
impl<'a, REG> AckGenCallW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nack(self) -> &'a mut crate::W<REG> {
        self.variant(AckGenCall::Nack)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn ack(self) -> &'a mut crate::W<REG> {
        self.variant(AckGenCall::Ack)
    }
}
impl R {
    #[doc = "Bit 0 - When an ACK is asserted, (by asserting i2c_out_data) when it receives a General call. Otherwise, i2c responds with a NACK (by negating i2c_out_data)."]
    #[inline(always)]
    pub fn ack_gen_call(&self) -> AckGenCallR {
        AckGenCallR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - When an ACK is asserted, (by asserting i2c_out_data) when it receives a General call. Otherwise, i2c responds with a NACK (by negating i2c_out_data)."]
    #[inline(always)]
    #[must_use]
    pub fn ack_gen_call(&mut self) -> AckGenCallW<IcAckGeneralCallSpec> {
        AckGenCallW::new(self, 0)
    }
}
#[doc = "The register controls whether i2c responds with a ACK or NACK when it receives an I2C General Call address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_ack_general_call::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ic_ack_general_call::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcAckGeneralCallSpec;
impl crate::RegisterSpec for IcAckGeneralCallSpec {
    type Ux = u32;
    const OFFSET: u64 = 152u64;
}
#[doc = "`read()` method returns [`ic_ack_general_call::R`](R) reader structure"]
impl crate::Readable for IcAckGeneralCallSpec {}
#[doc = "`write(|w| ..)` method takes [`ic_ack_general_call::W`](W) writer structure"]
impl crate::Writable for IcAckGeneralCallSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ic_ack_general_call to value 0x01"]
impl crate::Resettable for IcAckGeneralCallSpec {
    const RESET_VALUE: u32 = 0x01;
}
