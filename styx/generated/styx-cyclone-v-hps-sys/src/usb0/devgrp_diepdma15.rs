// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdma15` reader"]
pub type R = crate::R<DevgrpDiepdma15Spec>;
#[doc = "Register `devgrp_diepdma15` writer"]
pub type W = crate::W<DevgrpDiepdma15Spec>;
#[doc = "Field `diepdma15` reader - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
pub type Diepdma15R = crate::FieldReader<u32>;
#[doc = "Field `diepdma15` writer - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
pub type Diepdma15W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
    #[inline(always)]
    pub fn diepdma15(&self) -> Diepdma15R {
        Diepdma15R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
    #[inline(always)]
    #[must_use]
    pub fn diepdma15(&mut self) -> Diepdma15W<DevgrpDiepdma15Spec> {
        Diepdma15W::new(self, 0)
    }
}
#[doc = "DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma15::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma15::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdma15Spec;
impl crate::RegisterSpec for DevgrpDiepdma15Spec {
    type Ux = u32;
    const OFFSET: u64 = 2804u64;
}
#[doc = "`read()` method returns [`devgrp_diepdma15::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdma15Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_diepdma15::W`](W) writer structure"]
impl crate::Writable for DevgrpDiepdma15Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
