// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[doc = "Register `hostgrp_hcdma7` reader"]
pub type R = crate::R<HostgrpHcdma7Spec>;
#[doc = "Register `hostgrp_hcdma7` writer"]
pub type W = crate::W<HostgrpHcdma7Spec>;
#[doc = "Field `hcdma7` reader - Non-Isochronous: This field holds the start address of the 512 bytes page. The first descriptor in the list should be located in this address. The first descriptor may be or may not be ready. The core starts processing the list from the CTD value. This field holds the address of the 2*(nTD+1) bytes of locations in which the isochronous descriptors are present where N is based on nTD as per Table below \\[31:N\\]
Base Address \\[N-1:3\\]
Offset \\[2:0\\]
000 HS ISOC FS ISOC nTD N nTD N 7 6 1 4 15 7 3 5 31 8 7 6 63 9 15 7 127 10 31 8 255 11 63 9 \\[N-1:3\\]
(Isoc):\\[8:3\\]
(Non Isoc): Current Transfer Desc(CTD): Non Isochronous: This value is in terms of number of descriptors. The values can be from 0 to 63. 0 - 1 descriptor. 63 - 64 descriptors. This field indicates the current descriptor processed in the list. This field is updated both by application and the core. for example, if the application enables the channel after programming CTD=5, then the core will start processing the 6th descriptor. The address is obtained by adding a value of (8bytes*5=) 40(decimal) to DMAAddr. Isochronous: CTD for isochronous is based on the current frame/microframe value. Need to be set to zero by application."]
pub type Hcdma7R = crate::FieldReader<u32>;
#[doc = "Field `hcdma7` writer - Non-Isochronous: This field holds the start address of the 512 bytes page. The first descriptor in the list should be located in this address. The first descriptor may be or may not be ready. The core starts processing the list from the CTD value. This field holds the address of the 2*(nTD+1) bytes of locations in which the isochronous descriptors are present where N is based on nTD as per Table below \\[31:N\\]
Base Address \\[N-1:3\\]
Offset \\[2:0\\]
000 HS ISOC FS ISOC nTD N nTD N 7 6 1 4 15 7 3 5 31 8 7 6 63 9 15 7 127 10 31 8 255 11 63 9 \\[N-1:3\\]
(Isoc):\\[8:3\\]
(Non Isoc): Current Transfer Desc(CTD): Non Isochronous: This value is in terms of number of descriptors. The values can be from 0 to 63. 0 - 1 descriptor. 63 - 64 descriptors. This field indicates the current descriptor processed in the list. This field is updated both by application and the core. for example, if the application enables the channel after programming CTD=5, then the core will start processing the 6th descriptor. The address is obtained by adding a value of (8bytes*5=) 40(decimal) to DMAAddr. Isochronous: CTD for isochronous is based on the current frame/microframe value. Need to be set to zero by application."]
pub type Hcdma7W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Non-Isochronous: This field holds the start address of the 512 bytes page. The first descriptor in the list should be located in this address. The first descriptor may be or may not be ready. The core starts processing the list from the CTD value. This field holds the address of the 2*(nTD+1) bytes of locations in which the isochronous descriptors are present where N is based on nTD as per Table below \\[31:N\\]
Base Address \\[N-1:3\\]
Offset \\[2:0\\]
000 HS ISOC FS ISOC nTD N nTD N 7 6 1 4 15 7 3 5 31 8 7 6 63 9 15 7 127 10 31 8 255 11 63 9 \\[N-1:3\\]
(Isoc):\\[8:3\\]
(Non Isoc): Current Transfer Desc(CTD): Non Isochronous: This value is in terms of number of descriptors. The values can be from 0 to 63. 0 - 1 descriptor. 63 - 64 descriptors. This field indicates the current descriptor processed in the list. This field is updated both by application and the core. for example, if the application enables the channel after programming CTD=5, then the core will start processing the 6th descriptor. The address is obtained by adding a value of (8bytes*5=) 40(decimal) to DMAAddr. Isochronous: CTD for isochronous is based on the current frame/microframe value. Need to be set to zero by application."]
    #[inline(always)]
    pub fn hcdma7(&self) -> Hcdma7R {
        Hcdma7R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Non-Isochronous: This field holds the start address of the 512 bytes page. The first descriptor in the list should be located in this address. The first descriptor may be or may not be ready. The core starts processing the list from the CTD value. This field holds the address of the 2*(nTD+1) bytes of locations in which the isochronous descriptors are present where N is based on nTD as per Table below \\[31:N\\]
Base Address \\[N-1:3\\]
Offset \\[2:0\\]
000 HS ISOC FS ISOC nTD N nTD N 7 6 1 4 15 7 3 5 31 8 7 6 63 9 15 7 127 10 31 8 255 11 63 9 \\[N-1:3\\]
(Isoc):\\[8:3\\]
(Non Isoc): Current Transfer Desc(CTD): Non Isochronous: This value is in terms of number of descriptors. The values can be from 0 to 63. 0 - 1 descriptor. 63 - 64 descriptors. This field indicates the current descriptor processed in the list. This field is updated both by application and the core. for example, if the application enables the channel after programming CTD=5, then the core will start processing the 6th descriptor. The address is obtained by adding a value of (8bytes*5=) 40(decimal) to DMAAddr. Isochronous: CTD for isochronous is based on the current frame/microframe value. Need to be set to zero by application."]
    #[inline(always)]
    #[must_use]
    pub fn hcdma7(&mut self) -> Hcdma7W<HostgrpHcdma7Spec> {
        Hcdma7W::new(self, 0)
    }
}
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma7::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma7::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHcdma7Spec;
impl crate::RegisterSpec for HostgrpHcdma7Spec {
    type Ux = u32;
    const OFFSET: u64 = 1524u64;
}
#[doc = "`read()` method returns [`hostgrp_hcdma7::R`](R) reader structure"]
impl crate::Readable for HostgrpHcdma7Spec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hcdma7::W`](W) writer structure"]
impl crate::Writable for HostgrpHcdma7Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hcdma7 to value 0"]
impl crate::Resettable for HostgrpHcdma7Spec {
    const RESET_VALUE: u32 = 0;
}
