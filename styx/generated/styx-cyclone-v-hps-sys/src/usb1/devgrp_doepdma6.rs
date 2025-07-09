// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdma6` reader"]
pub type R = crate::R<DevgrpDoepdma6Spec>;
#[doc = "Register `devgrp_doepdma6` writer"]
pub type W = crate::W<DevgrpDoepdma6Spec>;
#[doc = "Field `doepdma6` reader - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
pub type Doepdma6R = crate::FieldReader<u32>;
#[doc = "Field `doepdma6` writer - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
pub type Doepdma6W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
    #[inline(always)]
    pub fn doepdma6(&self) -> Doepdma6R {
        Doepdma6R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
    #[inline(always)]
    #[must_use]
    pub fn doepdma6(&mut self) -> Doepdma6W<DevgrpDoepdma6Spec> {
        Doepdma6W::new(self, 0)
    }
}
#[doc = "DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma6::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma6::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdma6Spec;
impl crate::RegisterSpec for DevgrpDoepdma6Spec {
    type Ux = u32;
    const OFFSET: u64 = 3028u64;
}
#[doc = "`read()` method returns [`devgrp_doepdma6::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdma6Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_doepdma6::W`](W) writer structure"]
impl crate::Writable for DevgrpDoepdma6Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
