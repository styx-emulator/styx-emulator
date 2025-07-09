// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ecc_ECCCorInfo_b23` reader"]
pub type R = crate::R<EccEcccorInfoB23Spec>;
#[doc = "Register `ecc_ECCCorInfo_b23` writer"]
pub type W = crate::W<EccEcccorInfoB23Spec>;
#[doc = "Field `max_errors_b2` reader - Maximum of number of errors corrected per sector in Bank2. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
pub type MaxErrorsB2R = crate::FieldReader;
#[doc = "Field `max_errors_b2` writer - Maximum of number of errors corrected per sector in Bank2. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
pub type MaxErrorsB2W<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `uncor_err_b2` reader - Uncorrectable error occurred while reading pages for last transaction in Bank2. Uncorrectable errors also generate interrupts in intr_statusx register."]
pub type UncorErrB2R = crate::BitReader;
#[doc = "Field `uncor_err_b2` writer - Uncorrectable error occurred while reading pages for last transaction in Bank2. Uncorrectable errors also generate interrupts in intr_statusx register."]
pub type UncorErrB2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `max_errors_b3` reader - Maximum of number of errors corrected per sector in Bank3. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
pub type MaxErrorsB3R = crate::FieldReader;
#[doc = "Field `max_errors_b3` writer - Maximum of number of errors corrected per sector in Bank3. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
pub type MaxErrorsB3W<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `uncor_err_b3` reader - Uncorrectable error occurred while reading pages for last transaction in Bank3. Uncorrectable errors also generate interrupts in intr_statusx register."]
pub type UncorErrB3R = crate::BitReader;
#[doc = "Field `uncor_err_b3` writer - Uncorrectable error occurred while reading pages for last transaction in Bank3. Uncorrectable errors also generate interrupts in intr_statusx register."]
pub type UncorErrB3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:6 - Maximum of number of errors corrected per sector in Bank2. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
    #[inline(always)]
    pub fn max_errors_b2(&self) -> MaxErrorsB2R {
        MaxErrorsB2R::new((self.bits & 0x7f) as u8)
    }
    #[doc = "Bit 7 - Uncorrectable error occurred while reading pages for last transaction in Bank2. Uncorrectable errors also generate interrupts in intr_statusx register."]
    #[inline(always)]
    pub fn uncor_err_b2(&self) -> UncorErrB2R {
        UncorErrB2R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:14 - Maximum of number of errors corrected per sector in Bank3. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
    #[inline(always)]
    pub fn max_errors_b3(&self) -> MaxErrorsB3R {
        MaxErrorsB3R::new(((self.bits >> 8) & 0x7f) as u8)
    }
    #[doc = "Bit 15 - Uncorrectable error occurred while reading pages for last transaction in Bank3. Uncorrectable errors also generate interrupts in intr_statusx register."]
    #[inline(always)]
    pub fn uncor_err_b3(&self) -> UncorErrB3R {
        UncorErrB3R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:6 - Maximum of number of errors corrected per sector in Bank2. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
    #[inline(always)]
    #[must_use]
    pub fn max_errors_b2(&mut self) -> MaxErrorsB2W<EccEcccorInfoB23Spec> {
        MaxErrorsB2W::new(self, 0)
    }
    #[doc = "Bit 7 - Uncorrectable error occurred while reading pages for last transaction in Bank2. Uncorrectable errors also generate interrupts in intr_statusx register."]
    #[inline(always)]
    #[must_use]
    pub fn uncor_err_b2(&mut self) -> UncorErrB2W<EccEcccorInfoB23Spec> {
        UncorErrB2W::new(self, 7)
    }
    #[doc = "Bits 8:14 - Maximum of number of errors corrected per sector in Bank3. This field is not valid for uncorrectable errors. A value of zero indicates that no ECC error occurred in last completed transaction."]
    #[inline(always)]
    #[must_use]
    pub fn max_errors_b3(&mut self) -> MaxErrorsB3W<EccEcccorInfoB23Spec> {
        MaxErrorsB3W::new(self, 8)
    }
    #[doc = "Bit 15 - Uncorrectable error occurred while reading pages for last transaction in Bank3. Uncorrectable errors also generate interrupts in intr_statusx register."]
    #[inline(always)]
    #[must_use]
    pub fn uncor_err_b3(&mut self) -> UncorErrB3W<EccEcccorInfoB23Spec> {
        UncorErrB3W::new(self, 15)
    }
}
#[doc = "ECC Error correction Information register. Controller updates this register when it completes a transaction. The values are held in this register till a new transaction completes.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ecc_ecccor_info_b23::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EccEcccorInfoB23Spec;
impl crate::RegisterSpec for EccEcccorInfoB23Spec {
    type Ux = u32;
    const OFFSET: u64 = 1632u64;
}
#[doc = "`read()` method returns [`ecc_ecccor_info_b23::R`](R) reader structure"]
impl crate::Readable for EccEcccorInfoB23Spec {}
#[doc = "`reset()` method sets ecc_ECCCorInfo_b23 to value 0"]
impl crate::Resettable for EccEcccorInfoB23Spec {
    const RESET_VALUE: u32 = 0;
}
