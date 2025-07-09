// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ecc_ECCCorInfo_b01` reader"]
pub type R = crate::R<EccEcccorInfoB01Spec>;
#[doc = "Register `ecc_ECCCorInfo_b01` writer"]
pub type W = crate::W<EccEcccorInfoB01Spec>;
#[doc = "Field `max_errors_b0` reader - Maximum of number of errors corrected per sector in Bank0. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
pub type MaxErrorsB0R = crate::FieldReader;
#[doc = "Field `max_errors_b0` writer - Maximum of number of errors corrected per sector in Bank0. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
pub type MaxErrorsB0W<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `uncor_err_b0` reader - Uncorrectable error occurred while reading pages for last transaction in Bank0. Uncorrectable errors also generate interrupts in intr_statusx register."]
pub type UncorErrB0R = crate::BitReader;
#[doc = "Field `uncor_err_b0` writer - Uncorrectable error occurred while reading pages for last transaction in Bank0. Uncorrectable errors also generate interrupts in intr_statusx register."]
pub type UncorErrB0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `max_errors_b1` reader - Maximum of number of errors corrected per sector in Bank1. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
pub type MaxErrorsB1R = crate::FieldReader;
#[doc = "Field `max_errors_b1` writer - Maximum of number of errors corrected per sector in Bank1. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
pub type MaxErrorsB1W<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `uncor_err_b1` reader - Uncorrectable error occurred while reading pages for last transaction in Bank1. Uncorrectable errors also generate interrupts in intr_statusx register."]
pub type UncorErrB1R = crate::BitReader;
#[doc = "Field `uncor_err_b1` writer - Uncorrectable error occurred while reading pages for last transaction in Bank1. Uncorrectable errors also generate interrupts in intr_statusx register."]
pub type UncorErrB1W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:6 - Maximum of number of errors corrected per sector in Bank0. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
    #[inline(always)]
    pub fn max_errors_b0(&self) -> MaxErrorsB0R {
        MaxErrorsB0R::new((self.bits & 0x7f) as u8)
    }
    #[doc = "Bit 7 - Uncorrectable error occurred while reading pages for last transaction in Bank0. Uncorrectable errors also generate interrupts in intr_statusx register."]
    #[inline(always)]
    pub fn uncor_err_b0(&self) -> UncorErrB0R {
        UncorErrB0R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:14 - Maximum of number of errors corrected per sector in Bank1. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
    #[inline(always)]
    pub fn max_errors_b1(&self) -> MaxErrorsB1R {
        MaxErrorsB1R::new(((self.bits >> 8) & 0x7f) as u8)
    }
    #[doc = "Bit 15 - Uncorrectable error occurred while reading pages for last transaction in Bank1. Uncorrectable errors also generate interrupts in intr_statusx register."]
    #[inline(always)]
    pub fn uncor_err_b1(&self) -> UncorErrB1R {
        UncorErrB1R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:6 - Maximum of number of errors corrected per sector in Bank0. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
    #[inline(always)]
    #[must_use]
    pub fn max_errors_b0(&mut self) -> MaxErrorsB0W<EccEcccorInfoB01Spec> {
        MaxErrorsB0W::new(self, 0)
    }
    #[doc = "Bit 7 - Uncorrectable error occurred while reading pages for last transaction in Bank0. Uncorrectable errors also generate interrupts in intr_statusx register."]
    #[inline(always)]
    #[must_use]
    pub fn uncor_err_b0(&mut self) -> UncorErrB0W<EccEcccorInfoB01Spec> {
        UncorErrB0W::new(self, 7)
    }
    #[doc = "Bits 8:14 - Maximum of number of errors corrected per sector in Bank1. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
    #[inline(always)]
    #[must_use]
    pub fn max_errors_b1(&mut self) -> MaxErrorsB1W<EccEcccorInfoB01Spec> {
        MaxErrorsB1W::new(self, 8)
    }
    #[doc = "Bit 15 - Uncorrectable error occurred while reading pages for last transaction in Bank1. Uncorrectable errors also generate interrupts in intr_statusx register."]
    #[inline(always)]
    #[must_use]
    pub fn uncor_err_b1(&mut self) -> UncorErrB1W<EccEcccorInfoB01Spec> {
        UncorErrB1W::new(self, 15)
    }
}
#[doc = "ECC Error correction Information register. Controller updates this register when it completes a transaction. The values are held in this register till a new transaction completes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ecc_ecccor_info_b01::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EccEcccorInfoB01Spec;
impl crate::RegisterSpec for EccEcccorInfoB01Spec {
    type Ux = u32;
    const OFFSET: u64 = 1616u64;
}
#[doc = "`read()` method returns [`ecc_ecccor_info_b01::R`](R) reader structure"]
impl crate::Readable for EccEcccorInfoB01Spec {}
#[doc = "`reset()` method sets ecc_ECCCorInfo_b01 to value 0"]
impl crate::Resettable for EccEcccorInfoB01Spec {
    const RESET_VALUE: u32 = 0;
}
