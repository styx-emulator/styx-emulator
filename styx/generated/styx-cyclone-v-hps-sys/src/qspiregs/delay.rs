// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `delay` reader"]
pub type R = crate::R<DelaySpec>;
#[doc = "Register `delay` writer"]
pub type W = crate::W<DelaySpec>;
#[doc = "Field `init` reader - Delay in master reference clocks between setting qspi_n_ss_out low and first bit transfer."]
pub type InitR = crate::FieldReader;
#[doc = "Field `init` writer - Delay in master reference clocks between setting qspi_n_ss_out low and first bit transfer."]
pub type InitW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `after` reader - Delay in master reference clocks between last bit of current transaction and deasserting the device chip select (qspi_n_ss_out). By default, the chip select will be deasserted on the cycle following the completion of the current transaction."]
pub type AfterR = crate::FieldReader;
#[doc = "Field `after` writer - Delay in master reference clocks between last bit of current transaction and deasserting the device chip select (qspi_n_ss_out). By default, the chip select will be deasserted on the cycle following the completion of the current transaction."]
pub type AfterW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `btwn` reader - Delay in master reference clocks between one chip select being de-activated and the activation of another. This is used to ensure a quiet period between the selection of two different slaves and requires the transmit FIFO to be empty."]
pub type BtwnR = crate::FieldReader;
#[doc = "Field `btwn` writer - Delay in master reference clocks between one chip select being de-activated and the activation of another. This is used to ensure a quiet period between the selection of two different slaves and requires the transmit FIFO to be empty."]
pub type BtwnW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `nss` reader - Delay in master reference clocks for the length that the master mode chip select outputs are de-asserted between transactions. The minimum delay is always qspi_sck_out period to ensure the chip select is never re-asserted within an qspi_sck_out period."]
pub type NssR = crate::FieldReader;
#[doc = "Field `nss` writer - Delay in master reference clocks for the length that the master mode chip select outputs are de-asserted between transactions. The minimum delay is always qspi_sck_out period to ensure the chip select is never re-asserted within an qspi_sck_out period."]
pub type NssW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Delay in master reference clocks between setting qspi_n_ss_out low and first bit transfer."]
    #[inline(always)]
    pub fn init(&self) -> InitR {
        InitR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Delay in master reference clocks between last bit of current transaction and deasserting the device chip select (qspi_n_ss_out). By default, the chip select will be deasserted on the cycle following the completion of the current transaction."]
    #[inline(always)]
    pub fn after(&self) -> AfterR {
        AfterR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bits 16:23 - Delay in master reference clocks between one chip select being de-activated and the activation of another. This is used to ensure a quiet period between the selection of two different slaves and requires the transmit FIFO to be empty."]
    #[inline(always)]
    pub fn btwn(&self) -> BtwnR {
        BtwnR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:31 - Delay in master reference clocks for the length that the master mode chip select outputs are de-asserted between transactions. The minimum delay is always qspi_sck_out period to ensure the chip select is never re-asserted within an qspi_sck_out period."]
    #[inline(always)]
    pub fn nss(&self) -> NssR {
        NssR::new(((self.bits >> 24) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Delay in master reference clocks between setting qspi_n_ss_out low and first bit transfer."]
    #[inline(always)]
    #[must_use]
    pub fn init(&mut self) -> InitW<DelaySpec> {
        InitW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Delay in master reference clocks between last bit of current transaction and deasserting the device chip select (qspi_n_ss_out). By default, the chip select will be deasserted on the cycle following the completion of the current transaction."]
    #[inline(always)]
    #[must_use]
    pub fn after(&mut self) -> AfterW<DelaySpec> {
        AfterW::new(self, 8)
    }
    #[doc = "Bits 16:23 - Delay in master reference clocks between one chip select being de-activated and the activation of another. This is used to ensure a quiet period between the selection of two different slaves and requires the transmit FIFO to be empty."]
    #[inline(always)]
    #[must_use]
    pub fn btwn(&mut self) -> BtwnW<DelaySpec> {
        BtwnW::new(self, 16)
    }
    #[doc = "Bits 24:31 - Delay in master reference clocks for the length that the master mode chip select outputs are de-asserted between transactions. The minimum delay is always qspi_sck_out period to ensure the chip select is never re-asserted within an qspi_sck_out period."]
    #[inline(always)]
    #[must_use]
    pub fn nss(&mut self) -> NssW<DelaySpec> {
        NssW::new(self, 24)
    }
}
#[doc = "This register is used to introduce relative delays into the generation of the master output signals. All timings are defined in cycles of the qspi_clk.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`delay::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`delay::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DelaySpec;
impl crate::RegisterSpec for DelaySpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`delay::R`](R) reader structure"]
impl crate::Readable for DelaySpec {}
#[doc = "`write(|w| ..)` method takes [`delay::W`](W) writer structure"]
impl crate::Writable for DelaySpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets delay to value 0"]
impl crate::Resettable for DelaySpec {
    const RESET_VALUE: u32 = 0;
}
