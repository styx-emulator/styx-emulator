// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FS_GNPTXFSIZ_Device` reader"]
pub type R = crate::R<FsGnptxfsizDeviceSpec>;
#[doc = "Register `FS_GNPTXFSIZ_Device` writer"]
pub type W = crate::W<FsGnptxfsizDeviceSpec>;
#[doc = "Field `TX0FSA` reader - Endpoint 0 transmit RAM start address"]
pub type Tx0fsaR = crate::FieldReader<u16>;
#[doc = "Field `TX0FSA` writer - Endpoint 0 transmit RAM start address"]
pub type Tx0fsaW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `TX0FD` reader - Endpoint 0 TxFIFO depth"]
pub type Tx0fdR = crate::FieldReader<u16>;
#[doc = "Field `TX0FD` writer - Endpoint 0 TxFIFO depth"]
pub type Tx0fdW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Endpoint 0 transmit RAM start address"]
    #[inline(always)]
    pub fn tx0fsa(&self) -> Tx0fsaR {
        Tx0fsaR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - Endpoint 0 TxFIFO depth"]
    #[inline(always)]
    pub fn tx0fd(&self) -> Tx0fdR {
        Tx0fdR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Endpoint 0 transmit RAM start address"]
    #[inline(always)]
    #[must_use]
    pub fn tx0fsa(&mut self) -> Tx0fsaW<FsGnptxfsizDeviceSpec> {
        Tx0fsaW::new(self, 0)
    }
    #[doc = "Bits 16:31 - Endpoint 0 TxFIFO depth"]
    #[inline(always)]
    #[must_use]
    pub fn tx0fd(&mut self) -> Tx0fdW<FsGnptxfsizDeviceSpec> {
        Tx0fdW::new(self, 16)
    }
}
#[doc = "OTG_FS non-periodic transmit FIFO size register (Device mode)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_gnptxfsiz_device::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fs_gnptxfsiz_device::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsGnptxfsizDeviceSpec;
impl crate::RegisterSpec for FsGnptxfsizDeviceSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`fs_gnptxfsiz_device::R`](R) reader structure"]
impl crate::Readable for FsGnptxfsizDeviceSpec {}
#[doc = "`write(|w| ..)` method takes [`fs_gnptxfsiz_device::W`](W) writer structure"]
impl crate::Writable for FsGnptxfsizDeviceSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FS_GNPTXFSIZ_Device to value 0x0200"]
impl crate::Resettable for FsGnptxfsizDeviceSpec {
    const RESET_VALUE: u32 = 0x0200;
}
