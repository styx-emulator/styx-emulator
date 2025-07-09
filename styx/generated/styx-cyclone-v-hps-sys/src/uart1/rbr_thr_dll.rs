// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rbr_thr_dll` reader"]
pub type R = crate::R<RbrThrDllSpec>;
#[doc = "Register `rbr_thr_dll` writer"]
pub type W = crate::W<RbrThrDllSpec>;
#[doc = "Field `value` reader - Receive Buffer Register: This register contains the data byte received on the serial input port (uart_rxd). The data in this register is valid only if the Data Ready ( bit \\[0\\]
in the Line Status Register(LSR)) is set to 1. If FIFOs are disabled(bit\\[0\\]
of Register FCR is set to 0) the data in the RBR must be read before the next data arrives, otherwise it will be overwritten, resulting in an overrun error. If FIFOs are enabled(bit \\[0\\]
of Register FCR is set to 1) this register accesses the head of the receive FIFO. If the receive FIFO is full, and this register is not read before the next data character arrives, then the data already in the FIFO will be preserved but any incoming data will be lost. An overrun error will also occur. Transmit Holding Register: This register contains data to be transmitted on the serial output port. Data should only be written to the THR when the THR Empty bit \\[5\\]
of the LSR Register is set to 1. If FIFOs are disabled (bit \\[0\\]
of Register FCR) is set to 0 and THRE is set to 1, writing a single character to the THR clears the THRE. Any additional writes to the THR before the THRE is set again causes the THR data to be overwritten. If FIFO's are enabled bit \\[0\\]
of Register FCR is set to 1 and THRE is set up to 128 characters of data may be written to the THR before the FIFO is full. Any attempt to write data when the FIFO is full results in the write data being lost. Divisor Latch Low: This register makes up the lower 8-bits of a 16-bit, Read/write, Divisor Latch register that contains the baud rate divisor for the UART. This register may only be accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 1. The output baud rate is equal to the serial clock l4_sp_clk frequency divided by sixteen times the value of the baud rate divisor, as follows: baud rate = (serial clock freq) / (16 * divisor) Note that with the Divisor Latch Registers (DLL and DLH) set to zero, the baud clock is disabled and no serial communications will occur. Also, once the DLL is set, at least 8 l4_sp_clk clock cycles should be allowed to pass before transmitting or receiving data."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Receive Buffer Register: This register contains the data byte received on the serial input port (uart_rxd). The data in this register is valid only if the Data Ready ( bit \\[0\\]
in the Line Status Register(LSR)) is set to 1. If FIFOs are disabled(bit\\[0\\]
of Register FCR is set to 0) the data in the RBR must be read before the next data arrives, otherwise it will be overwritten, resulting in an overrun error. If FIFOs are enabled(bit \\[0\\]
of Register FCR is set to 1) this register accesses the head of the receive FIFO. If the receive FIFO is full, and this register is not read before the next data character arrives, then the data already in the FIFO will be preserved but any incoming data will be lost. An overrun error will also occur. Transmit Holding Register: This register contains data to be transmitted on the serial output port. Data should only be written to the THR when the THR Empty bit \\[5\\]
of the LSR Register is set to 1. If FIFOs are disabled (bit \\[0\\]
of Register FCR) is set to 0 and THRE is set to 1, writing a single character to the THR clears the THRE. Any additional writes to the THR before the THRE is set again causes the THR data to be overwritten. If FIFO's are enabled bit \\[0\\]
of Register FCR is set to 1 and THRE is set up to 128 characters of data may be written to the THR before the FIFO is full. Any attempt to write data when the FIFO is full results in the write data being lost. Divisor Latch Low: This register makes up the lower 8-bits of a 16-bit, Read/write, Divisor Latch register that contains the baud rate divisor for the UART. This register may only be accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 1. The output baud rate is equal to the serial clock l4_sp_clk frequency divided by sixteen times the value of the baud rate divisor, as follows: baud rate = (serial clock freq) / (16 * divisor) Note that with the Divisor Latch Registers (DLL and DLH) set to zero, the baud clock is disabled and no serial communications will occur. Also, once the DLL is set, at least 8 l4_sp_clk clock cycles should be allowed to pass before transmitting or receiving data."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Receive Buffer Register: This register contains the data byte received on the serial input port (uart_rxd). The data in this register is valid only if the Data Ready ( bit \\[0\\]
in the Line Status Register(LSR)) is set to 1. If FIFOs are disabled(bit\\[0\\]
of Register FCR is set to 0) the data in the RBR must be read before the next data arrives, otherwise it will be overwritten, resulting in an overrun error. If FIFOs are enabled(bit \\[0\\]
of Register FCR is set to 1) this register accesses the head of the receive FIFO. If the receive FIFO is full, and this register is not read before the next data character arrives, then the data already in the FIFO will be preserved but any incoming data will be lost. An overrun error will also occur. Transmit Holding Register: This register contains data to be transmitted on the serial output port. Data should only be written to the THR when the THR Empty bit \\[5\\]
of the LSR Register is set to 1. If FIFOs are disabled (bit \\[0\\]
of Register FCR) is set to 0 and THRE is set to 1, writing a single character to the THR clears the THRE. Any additional writes to the THR before the THRE is set again causes the THR data to be overwritten. If FIFO's are enabled bit \\[0\\]
of Register FCR is set to 1 and THRE is set up to 128 characters of data may be written to the THR before the FIFO is full. Any attempt to write data when the FIFO is full results in the write data being lost. Divisor Latch Low: This register makes up the lower 8-bits of a 16-bit, Read/write, Divisor Latch register that contains the baud rate divisor for the UART. This register may only be accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 1. The output baud rate is equal to the serial clock l4_sp_clk frequency divided by sixteen times the value of the baud rate divisor, as follows: baud rate = (serial clock freq) / (16 * divisor) Note that with the Divisor Latch Registers (DLL and DLH) set to zero, the baud clock is disabled and no serial communications will occur. Also, once the DLL is set, at least 8 l4_sp_clk clock cycles should be allowed to pass before transmitting or receiving data."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Receive Buffer Register: This register contains the data byte received on the serial input port (uart_rxd). The data in this register is valid only if the Data Ready ( bit \\[0\\]
in the Line Status Register(LSR)) is set to 1. If FIFOs are disabled(bit\\[0\\]
of Register FCR is set to 0) the data in the RBR must be read before the next data arrives, otherwise it will be overwritten, resulting in an overrun error. If FIFOs are enabled(bit \\[0\\]
of Register FCR is set to 1) this register accesses the head of the receive FIFO. If the receive FIFO is full, and this register is not read before the next data character arrives, then the data already in the FIFO will be preserved but any incoming data will be lost. An overrun error will also occur. Transmit Holding Register: This register contains data to be transmitted on the serial output port. Data should only be written to the THR when the THR Empty bit \\[5\\]
of the LSR Register is set to 1. If FIFOs are disabled (bit \\[0\\]
of Register FCR) is set to 0 and THRE is set to 1, writing a single character to the THR clears the THRE. Any additional writes to the THR before the THRE is set again causes the THR data to be overwritten. If FIFO's are enabled bit \\[0\\]
of Register FCR is set to 1 and THRE is set up to 128 characters of data may be written to the THR before the FIFO is full. Any attempt to write data when the FIFO is full results in the write data being lost. Divisor Latch Low: This register makes up the lower 8-bits of a 16-bit, Read/write, Divisor Latch register that contains the baud rate divisor for the UART. This register may only be accessed when the DLAB bit \\[7\\]
of the LCR Register is set to 1. The output baud rate is equal to the serial clock l4_sp_clk frequency divided by sixteen times the value of the baud rate divisor, as follows: baud rate = (serial clock freq) / (16 * divisor) Note that with the Divisor Latch Registers (DLL and DLH) set to zero, the baud clock is disabled and no serial communications will occur. Also, once the DLL is set, at least 8 l4_sp_clk clock cycles should be allowed to pass before transmitting or receiving data."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<RbrThrDllSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "This is a multi-function register. This register holds receives and transmit data and controls the least-signficant 8 bits of the baud rate divisor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rbr_thr_dll::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`rbr_thr_dll::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RbrThrDllSpec;
impl crate::RegisterSpec for RbrThrDllSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`rbr_thr_dll::R`](R) reader structure"]
impl crate::Readable for RbrThrDllSpec {}
#[doc = "`write(|w| ..)` method takes [`rbr_thr_dll::W`](W) writer structure"]
impl crate::Writable for RbrThrDllSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets rbr_thr_dll to value 0"]
impl crate::Resettable for RbrThrDllSpec {
    const RESET_VALUE: u32 = 0;
}
