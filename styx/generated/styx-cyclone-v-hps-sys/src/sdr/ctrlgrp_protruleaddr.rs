// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_protruleaddr` reader"]
pub type R = crate::R<CtrlgrpProtruleaddrSpec>;
#[doc = "Register `ctrlgrp_protruleaddr` writer"]
pub type W = crate::W<CtrlgrpProtruleaddrSpec>;
#[doc = "Field `lowaddr` reader - Lower 12 bits of the address for a check. Address is compared to be less than or equal to the address of a transaction. Note that since AXI transactions cannot cross a 4K byte boundary, the transaction start and transaction end address must also fall within the same 1MByte block pointed to by this address pointer."]
pub type LowaddrR = crate::FieldReader<u16>;
#[doc = "Field `lowaddr` writer - Lower 12 bits of the address for a check. Address is compared to be less than or equal to the address of a transaction. Note that since AXI transactions cannot cross a 4K byte boundary, the transaction start and transaction end address must also fall within the same 1MByte block pointed to by this address pointer."]
pub type LowaddrW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `highaddr` reader - Upper 12 bits of the address for a check. Address is compared to be greater than or equal to the address of a transaction. Note that since AXI transactions cannot cross a 4K byte boundary, the transaction start and transaction end address must also fall within the same 1MByte block pointed to by this address pointer."]
pub type HighaddrR = crate::FieldReader<u16>;
#[doc = "Field `highaddr` writer - Upper 12 bits of the address for a check. Address is compared to be greater than or equal to the address of a transaction. Note that since AXI transactions cannot cross a 4K byte boundary, the transaction start and transaction end address must also fall within the same 1MByte block pointed to by this address pointer."]
pub type HighaddrW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
impl R {
    #[doc = "Bits 0:11 - Lower 12 bits of the address for a check. Address is compared to be less than or equal to the address of a transaction. Note that since AXI transactions cannot cross a 4K byte boundary, the transaction start and transaction end address must also fall within the same 1MByte block pointed to by this address pointer."]
    #[inline(always)]
    pub fn lowaddr(&self) -> LowaddrR {
        LowaddrR::new((self.bits & 0x0fff) as u16)
    }
    #[doc = "Bits 12:23 - Upper 12 bits of the address for a check. Address is compared to be greater than or equal to the address of a transaction. Note that since AXI transactions cannot cross a 4K byte boundary, the transaction start and transaction end address must also fall within the same 1MByte block pointed to by this address pointer."]
    #[inline(always)]
    pub fn highaddr(&self) -> HighaddrR {
        HighaddrR::new(((self.bits >> 12) & 0x0fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:11 - Lower 12 bits of the address for a check. Address is compared to be less than or equal to the address of a transaction. Note that since AXI transactions cannot cross a 4K byte boundary, the transaction start and transaction end address must also fall within the same 1MByte block pointed to by this address pointer."]
    #[inline(always)]
    #[must_use]
    pub fn lowaddr(&mut self) -> LowaddrW<CtrlgrpProtruleaddrSpec> {
        LowaddrW::new(self, 0)
    }
    #[doc = "Bits 12:23 - Upper 12 bits of the address for a check. Address is compared to be greater than or equal to the address of a transaction. Note that since AXI transactions cannot cross a 4K byte boundary, the transaction start and transaction end address must also fall within the same 1MByte block pointed to by this address pointer."]
    #[inline(always)]
    #[must_use]
    pub fn highaddr(&mut self) -> HighaddrW<CtrlgrpProtruleaddrSpec> {
        HighaddrW::new(self, 12)
    }
}
#[doc = "This register is used to control the memory protection for port 0 transactions. Address ranges can either be used to allow access to memory regions or disallow access to memory regions. If trustzone is being used, access can be enabled for protected transactions or disabled for unprotected transactions. The default state of this register is to allow all access. Address values used for protection are only physical addresses.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_protruleaddr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_protruleaddr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpProtruleaddrSpec;
impl crate::RegisterSpec for CtrlgrpProtruleaddrSpec {
    type Ux = u32;
    const OFFSET: u64 = 20624u64;
}
#[doc = "`read()` method returns [`ctrlgrp_protruleaddr::R`](R) reader structure"]
impl crate::Readable for CtrlgrpProtruleaddrSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_protruleaddr::W`](W) writer structure"]
impl crate::Writable for CtrlgrpProtruleaddrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_protruleaddr to value 0"]
impl crate::Resettable for CtrlgrpProtruleaddrSpec {
    const RESET_VALUE: u32 = 0;
}
