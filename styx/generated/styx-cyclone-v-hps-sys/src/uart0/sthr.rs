// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `sthr` reader"]
pub type R = crate::R<SthrSpec>;
#[doc = "Register `sthr` writer"]
pub type W = crate::W<SthrSpec>;
#[doc = "Field `sthr` reader - This is a shadow register for the THR and has been allocated sixteen 32-bit locations so as to accommodate burst accesses from the master. This register contains data to be transmitted on the serial output port (sout). Data should only be written to the THR when the THR Empty (THRE) bit (LSR\\[5\\]) is set. If FIFO's are disabled bit \\[0\\]
of register FCR set to zero and THRE is set, writing a single character to the THR clears the THRE. Any additional writes to the THR before the THRE is set again causes the THR data to be overwritten. If FIFO's are enabled bit \\[0\\]
of register FCR set to one and THRE is set, 128 characters of data may be written to the THR before the FIFO is full. The UART FIFO depth is configured for 128 characters. Any attempt to write data when the FIFO is full results in the write data being lost."]
pub type SthrR = crate::FieldReader;
#[doc = "Field `sthr` writer - This is a shadow register for the THR and has been allocated sixteen 32-bit locations so as to accommodate burst accesses from the master. This register contains data to be transmitted on the serial output port (sout). Data should only be written to the THR when the THR Empty (THRE) bit (LSR\\[5\\]) is set. If FIFO's are disabled bit \\[0\\]
of register FCR set to zero and THRE is set, writing a single character to the THR clears the THRE. Any additional writes to the THR before the THRE is set again causes the THR data to be overwritten. If FIFO's are enabled bit \\[0\\]
of register FCR set to one and THRE is set, 128 characters of data may be written to the THR before the FIFO is full. The UART FIFO depth is configured for 128 characters. Any attempt to write data when the FIFO is full results in the write data being lost."]
pub type SthrW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - This is a shadow register for the THR and has been allocated sixteen 32-bit locations so as to accommodate burst accesses from the master. This register contains data to be transmitted on the serial output port (sout). Data should only be written to the THR when the THR Empty (THRE) bit (LSR\\[5\\]) is set. If FIFO's are disabled bit \\[0\\]
of register FCR set to zero and THRE is set, writing a single character to the THR clears the THRE. Any additional writes to the THR before the THRE is set again causes the THR data to be overwritten. If FIFO's are enabled bit \\[0\\]
of register FCR set to one and THRE is set, 128 characters of data may be written to the THR before the FIFO is full. The UART FIFO depth is configured for 128 characters. Any attempt to write data when the FIFO is full results in the write data being lost."]
    #[inline(always)]
    pub fn sthr(&self) -> SthrR {
        SthrR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - This is a shadow register for the THR and has been allocated sixteen 32-bit locations so as to accommodate burst accesses from the master. This register contains data to be transmitted on the serial output port (sout). Data should only be written to the THR when the THR Empty (THRE) bit (LSR\\[5\\]) is set. If FIFO's are disabled bit \\[0\\]
of register FCR set to zero and THRE is set, writing a single character to the THR clears the THRE. Any additional writes to the THR before the THRE is set again causes the THR data to be overwritten. If FIFO's are enabled bit \\[0\\]
of register FCR set to one and THRE is set, 128 characters of data may be written to the THR before the FIFO is full. The UART FIFO depth is configured for 128 characters. Any attempt to write data when the FIFO is full results in the write data being lost."]
    #[inline(always)]
    #[must_use]
    pub fn sthr(&mut self) -> SthrW<SthrSpec> {
        SthrW::new(self, 0)
    }
}
#[doc = "Used to accomadate burst accesses from the master.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sthr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sthr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SthrSpec;
impl crate::RegisterSpec for SthrSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`sthr::R`](R) reader structure"]
impl crate::Readable for SthrSpec {}
#[doc = "`write(|w| ..)` method takes [`sthr::W`](W) writer structure"]
impl crate::Writable for SthrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets sthr to value 0"]
impl crate::Resettable for SthrSpec {
    const RESET_VALUE: u32 = 0;
}
