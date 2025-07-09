// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdma10` reader"]
pub type R = crate::R<DevgrpDoepdma10Spec>;
#[doc = "Register `devgrp_doepdma10` writer"]
pub type W = crate::W<DevgrpDoepdma10Spec>;
#[doc = "Field `doepdma10` reader - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
pub type Doepdma10R = crate::FieldReader<u32>;
#[doc = "Field `doepdma10` writer - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
pub type Doepdma10W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
    #[inline(always)]
    pub fn doepdma10(&self) -> Doepdma10R {
        Doepdma10R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the start address of the external memory for storing or fetching endpoint data. for control endpoints, this field stores control OUT data packets as well as SETUP transaction data packets. When more than three SETUP packets are received back-to-back, the SETUP data packet in the memory is overwritten. This register is incremented on every AHB transaction. The application can give only a DWORD-aligned address. When Scatter/Gather DMA mode is not enabled, the application programs the start address value in this field. When Scatter/Gather DMA mode is enabled, this field indicates the base pointer for the descriptor list."]
    #[inline(always)]
    #[must_use]
    pub fn doepdma10(&mut self) -> Doepdma10W<DevgrpDoepdma10Spec> {
        Doepdma10W::new(self, 0)
    }
}
#[doc = "DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma10::R`](R).  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma10::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdma10Spec;
impl crate::RegisterSpec for DevgrpDoepdma10Spec {
    type Ux = u32;
    const OFFSET: u64 = 3156u64;
}
#[doc = "`read()` method returns [`devgrp_doepdma10::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdma10Spec {}
#[doc = "`write(|w| ..)` method takes [`devgrp_doepdma10::W`](W) writer structure"]
impl crate::Writable for DevgrpDoepdma10Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
