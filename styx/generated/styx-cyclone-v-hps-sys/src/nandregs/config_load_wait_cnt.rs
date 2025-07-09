// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `config_load_wait_cnt` reader"]
pub type R = crate::R<ConfigLoadWaitCntSpec>;
#[doc = "Register `config_load_wait_cnt` writer"]
pub type W = crate::W<ConfigLoadWaitCntSpec>;
#[doc = "Field `value` reader - Number of clock cycles after issue of load operation before NAND Flash Controller polls for status. This values is of relevance for status polling mode of operation and has been provided to minimize redundant polling after issuing a command. After a load command, the first polling will happen after this many number of cycles have elapsed and then on polling will happen every int_mon_cyccnt cycles. The default values is equal to the default value of int_mon_cyccnt"]
pub type ValueR = crate::FieldReader<u16>;
#[doc = "Field `value` writer - Number of clock cycles after issue of load operation before NAND Flash Controller polls for status. This values is of relevance for status polling mode of operation and has been provided to minimize redundant polling after issuing a command. After a load command, the first polling will happen after this many number of cycles have elapsed and then on polling will happen every int_mon_cyccnt cycles. The default values is equal to the default value of int_mon_cyccnt"]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Number of clock cycles after issue of load operation before NAND Flash Controller polls for status. This values is of relevance for status polling mode of operation and has been provided to minimize redundant polling after issuing a command. After a load command, the first polling will happen after this many number of cycles have elapsed and then on polling will happen every int_mon_cyccnt cycles. The default values is equal to the default value of int_mon_cyccnt"]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Number of clock cycles after issue of load operation before NAND Flash Controller polls for status. This values is of relevance for status polling mode of operation and has been provided to minimize redundant polling after issuing a command. After a load command, the first polling will happen after this many number of cycles have elapsed and then on polling will happen every int_mon_cyccnt cycles. The default values is equal to the default value of int_mon_cyccnt"]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<ConfigLoadWaitCntSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Wait count value for Load operation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_load_wait_cnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_load_wait_cnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigLoadWaitCntSpec;
impl crate::RegisterSpec for ConfigLoadWaitCntSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`config_load_wait_cnt::R`](R) reader structure"]
impl crate::Readable for ConfigLoadWaitCntSpec {}
#[doc = "`write(|w| ..)` method takes [`config_load_wait_cnt::W`](W) writer structure"]
impl crate::Writable for ConfigLoadWaitCntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_load_wait_cnt to value 0x01f4"]
impl crate::Resettable for ConfigLoadWaitCntSpec {
    const RESET_VALUE: u32 = 0x01f4;
}
