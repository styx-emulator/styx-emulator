// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdma5` reader"]
pub type R = crate::R<DevgrpDiepdma5Spec>;
#[doc = "Register `devgrp_diepdma5` writer"]
pub type W = crate::W<DevgrpDiepdma5Spec>;
#[doc = "Field `diepdma5` reader - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
pub type Diepdma5R = crate::FieldReader<u32>;
#[doc = "Field `diepdma5` writer - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
pub type Diepdma5W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
    #[inline(always)]
    pub fn diepdma5(&self) -> Diepdma5R {
        Diepdma5R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
    #[inline(always)]
    #[must_use]
    pub fn diepdma5(&mut self) -> Diepdma5W<DevgrpDiepdma5Spec> {
        Diepdma5W::new(self, 0)
    }
}
#[doc = "DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma5::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma5::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdma5Spec;
impl crate::RegisterSpec for DevgrpDiepdma5Spec {
    type Ux = u32;
    const OFFSET: u64 = 2484u64;
}
#[doc = "`read()` method returns [`devgrp_diepdma5::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdma5Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_diepdma5::W`](W) writer structure"]
impl crate::Writable for DevgrpDiepdma5Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
