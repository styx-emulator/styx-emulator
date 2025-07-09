// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CR` reader"]
pub type R = crate::R<CrSpec>;
#[doc = "Register `CR` writer"]
pub type W = crate::W<CrSpec>;
#[doc = "Field `CECEN` reader - CEC Enable"]
pub type CecenR = crate::BitReader;
#[doc = "Field `CECEN` writer - CEC Enable"]
pub type CecenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXSOM` reader - Tx start of message"]
pub type TxsomR = crate::BitReader;
#[doc = "Field `TXSOM` writer - Tx start of message"]
pub type TxsomW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TXEOM` reader - Tx End Of Message"]
pub type TxeomR = crate::BitReader;
#[doc = "Field `TXEOM` writer - Tx End Of Message"]
pub type TxeomW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - CEC Enable"]
    #[inline(always)]
    pub fn cecen(&self) -> CecenR {
        CecenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Tx start of message"]
    #[inline(always)]
    pub fn txsom(&self) -> TxsomR {
        TxsomR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Tx End Of Message"]
    #[inline(always)]
    pub fn txeom(&self) -> TxeomR {
        TxeomR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - CEC Enable"]
    #[inline(always)]
    #[must_use]
    pub fn cecen(&mut self) -> CecenW<CrSpec> {
        CecenW::new(self, 0)
    }
    #[doc = "Bit 1 - Tx start of message"]
    #[inline(always)]
    #[must_use]
    pub fn txsom(&mut self) -> TxsomW<CrSpec> {
        TxsomW::new(self, 1)
    }
    #[doc = "Bit 2 - Tx End Of Message"]
    #[inline(always)]
    #[must_use]
    pub fn txeom(&mut self) -> TxeomW<CrSpec> {
        TxeomW::new(self, 2)
    }
}
#[doc = "control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CrSpec;
impl crate::RegisterSpec for CrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr::R`](R) reader structure"]
impl crate::Readable for CrSpec {}
#[doc = "`write(|w| ..)` method takes [`cr::W`](W) writer structure"]
impl crate::Writable for CrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR to value 0"]
impl crate::Resettable for CrSpec {
    const RESET_VALUE: u32 = 0;
}
