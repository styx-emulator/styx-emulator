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
//! Memory hooks for the STM32F405 UART/USART ports
//! See the STM32F405 Technical Reference Manual's
//! **[USART Registers Section](https://www.st.com/resource/en/reference_manual/dm00031020-stm32f405-415-stm32f407-417-stm32f427-437-and-stm32f429-439-advanced-arm-based-32-bit-mcus-stmicroelectronics.pdf#page=1010)**

use std::ops::DerefMut;

use styx_core::prelude::*;
use tracing::debug;
use tracing::error;
use tracing::trace;

use super::inner::UartPortInner;

//  - Status Register (sr)
//      - All bits readable, some clearable.
//      - Contains the various USART status flags.
//      - Register values change from software writes and automatic hardware writes.
//      - The flags tracked by this emulation are as follows:
//
//      - - Bit 7 TXE: Transmit data register empty
//      - - - This bit is set by hardware when the content of the TDR register has been transferred into
//      - - - the shift register. An interrupt is generated if the TXEIE bit =1 in the USART_CR1 register. It
//      - - - is cleared by a write to the USART_DR register.
//      - - - - 0: Data is not transferred to the shift register
//      - - - - 1: Data is transferred to the shift register)
//      - - - Note: This bit is used during single buffer transmission.
//
//      - - Bit 6 TC: Transmission complete
//      - - - This bit is set by hardware if the transmission of a frame containing data is complete and if
//      - - - TXE is set. An interrupt is generated if TCIE=1 in the USART_CR1 register. It is cleared by
//      - - - a software sequence (a read from the USART_SR register followed by a write to the
//      - - - USART_DR register). The TC bit can also be cleared by writing a '0' to it. This clearing
//      - - - sequence is recommended only for multibuffer communication.
//      - - - - 0: Transmission is not complete
//      - - - - 1: Transmission is complete
//
//      - - Bit 5 RXNE: Read data register not empty
//      - -  - This bit is set by hardware when the content of the RDR shift register has been transferred
//      - -  - to the USART_DR register. An interrupt is generated if RXNEIE=1 in the USART_CR1
//      - -  - register. It is cleared by a read to the USART_DR register. The RXNE flag can also be
//      - -  - cleared by writing a zero to it. This clearing sequence is recommended only for multibuffer
//      - -  - communication.
//      - -  - - 0: Data is not received
//      - -  - - 1: Received data is ready to be read.
//
//      - - Bit 3 ORE: Overrun error
//      - - - This bit is set by hardware when the word currently being received in the shift register is
//      - - - ready to be transferred into the RDR register while RXNE=1. An interrupt is generated if
//      - - - RXNEIE=1 in the USART_CR1 register. It is cleared by a software sequence (an read to the
//      - - - USART_SR register followed by a read to the USART_DR register).
//      - - - - 0: No Overrun error
//      - - - - 1: Overrun error is detected
//      - - - Note: When this bit is set, the RDR register content is not lost but the shift register is
//      - - - overwritten. An interrupt is generated on ORE flag in case of Multi Buffer
//      - - - communication if the EIE bit is set.
//
//      - To see the other flags, see the STM32F405 Technical Reference Manual

//  - Receive Data Register (rdr)
//      - reads
//      - Contains the received data byte.
//      - The data in this register is valid only if the RXNE (Read Data Register Not Empty) bit
//      - in the USART Status Register is set.
//      - If data is received into RDR while RXNE is set, an overrun error interrupt is
//      - generated. The data in RDR is still valid, but the internal shift register the data
//      - was received into is overwritten.
//  - Transmit Data Register (tdr)
//      - writes
//      - This register contains the byte to be transmitted.
//      - Data should only be written to the THR when the TXE (Transmit Data Register Empty) bit of
//      - the USART Status Register is set.
//      - Note that because we abstract over the bit-by-bit transmission of data at the baud rate,
//      - the TXE and TC (Transmission Complete) interrupts will occur at the same time.
//      - If data is written to the tdr before the TXE bit is set, the original data in the tdr
//      - will be overwritten.

//  - Control Register 1 (cr1)
//      - Readable and writable.
//      - Contains various control flags to control the USART/UART behavior
//      - Register values are changed by software.
//      - The flags tracked by this emulation are as follows:
//
//      - - Bit 13 UE: USART/UART Enable
//      - - - When this bit is cleared, the USART prescalers and outputs are stopped and the end of the
//      - - - current byte transfer in order to reduce power consumption. This bit is set and cleared by
//      - - - software.
//      - - - - 0: USART/UART prescaler and outputs disabled.
//      - - - - 1: USART/UART enabled.
//
//      - - Bit 7 TXEIE: TXE interrupt enable
//      - - - This bit is set and cleared by software.
//      - - - - 0: Interrupt is inhibited
//      - - - - 1: An USART interrupt is generated whenever TXE=1 in the USART_SR register
//
//      - - Bit 6 TCIE: Transmission complete interrupt enable
//      - - - This bit is set and cleared by software.
//      - - - - 0: Interrupt is inhibited
//      - - - - 1: An USART interrupt is generated whenever TC=1 in the USART_SR register
//
//      - - Bit 5 RXNEIE: RXNE interrupt enable
//      - - - This bit is set and cleared by software.
//      - - - - 0: Interrupt is inhibited
//      - - - - 1: An USART interrupt is generated whenever ORE=1 or RXNE=1 in the USART_SR
//      - - - - register
//
//      - - Bit 3 TE: Transmitter enable
//      - - - This bit enables the transmitter. It is set and cleared by software.
//      - - - - 0: Transmitter is disabled
//      - - - - 1: Transmitter is enabled
//      - - - Note: During transmission, a “0” pulse on the TE bit (“0” followed by “1”) sends a preamble
//      - - - (idle line) after the current word, except in smartcard mode.
//      - - - When TE is set, there is a 1 bit-time delay before the transmission starts.
//
//      - To see the other flags, see the STM32F405 Technical Reference Manual

/// Guest write to USART_DR register.
/// When writing to this register, data is actually routed to the internal USART TDR
/// (Transmission Data Register) register. The TXE status bit is then cleared until the data
/// in the TDR register is transmitted out. The data in the TDR is overwritten if USART_DR
/// is written to while TXE is still set.
///
/// If the transmitter enable (TE) bit is set and there is a connected USART/UART client
/// awaiting data, this memory hook will trigger a transmission.
pub(crate) fn usart_port_dr_w_hook(
    _cpu: &mut dyn CpuBackend,
    ev: &mut dyn EventControllerImpl,
    _address: u64,
    size: u32,
    data: &[u8],
    port: &mut UartPortInner,
) -> Result<(), UnknownError> {
    if size != 2 && size != 4 {
        error!(
            "UART{:?}: Guest write to dr of improper size: {}. STM32F405 peripheral \
            registers must be accessed as half-words or as words",
            port, size
        );
    }

    println!("writing to dr!");

    let mut binding = port.inner_hal();
    let hal = binding.deref_mut();

    let byte = data[0];

    // update the hal data and clear the tx complete interrupt/flag if warranted
    hal.data_terminals.write_to_tdr(byte);
    if hal.interrupt_control.recent_sr_read() {
        // clear tc interrupt and status flag
        hal.data_terminals.clear_tx_complete();
        hal.interrupt_control.int_tc.clear();
    }

    hal.interrupt_control.int_txe.clear();
    hal.interrupt_control.clear_recent_sr_read();

    // determine whether to transmit data or not
    if hal.data_terminals.tx_enabled() && !hal.data_terminals.tdr_empty() && hal.enabled() {
        // transmit
        let byte = hal
            .data_terminals
            .send_from_tdr()
            .expect("tdr should have data during the execution of the dr_w memory hook");

        port.guest_transmit_data(byte);

        port.checked_generate_transmit_interrupt(ev);
    }

    trace!("USART{:?}: Guest write to dr: {:#x}", port, byte);
    Ok(())
}

/// Guest read from USART_DR register.
///
/// When reading from this register, data is actually routed from the internal USART RDR
/// (Receive Data Register) register. The RXNE status bit is cleared by a read to the DR,
/// and its associated interrupt is cleared if the SR was read from just prior. If data
/// is received into the RDR while the RXNE bit is set, an overrun error occurs. The RDR
/// data is not lost, but the data transmitted that tripped the error is lost.
///
/// Note: reading from the DR should free up space to receive another byte, so this hook may
/// trigger the USART/UART to receive another byte.
///
/// # TODO:
///
/// Note that the RDR, given our bit-by-bit transmission/receiving abstraction into moving
/// whole bytes, the RDR essentially behaves like a 2-byte FIFO. When one byte is stored
/// awaiting a CPU/DMA read, and another byte is received first, an overrun error occurs but
/// the second is saved in the Rx shift register. Subsequent bytes received will overwrite the
/// shift register. Our emulation does not implement this 2-byte buffer behavior however, it
/// just uses one buffer and any overrunning data is immediately lost.
pub(crate) fn usart_port_dr_r_hook(
    _cpu: &mut dyn CpuBackend,
    _ev: &mut dyn EventControllerImpl,
    _address: u64,
    size: u32,
    data: &mut [u8],
    port: &mut UartPortInner,
) -> Result<(), UnknownError> {
    if size != 2 && size != 4 {
        error!(
            "UART{:?}: Guest read from dr of improper size: {}. STM32F405 peripheral \
            registers must be accessed as half-words or as words",
            port, size
        );
    }

    println!("reading from dr!");

    let mut binding = port.inner_hal();
    let hal = binding.deref_mut();

    // In this read-hook, the source of truth is no longer the CPU memory, but the USART model.
    // We need to use its interface to read from the USART data register, clear the relevant
    // interrupts, and modify the read data to be consistent with the source of truth

    // data defaults to the out-of-date cpu memory byte
    let true_byte = hal.data_terminals.read_from_rdr().unwrap_or(data[0]);
    data[0] = true_byte;

    // clear the overrun interrupt if the status register was recently read from
    if hal.interrupt_control.recent_sr_read() {
        // clear ore interrupt
        hal.interrupt_control.int_rxne.clear();
        debug!("RXNE interrupt cleared!");
    }

    hal.interrupt_control.int_rxne.clear();

    hal.interrupt_control.clear_recent_sr_read();

    trace!(
        "USART{:?}: Guest read to dr, read the byte: {:#}",
        port,
        true_byte
    );
    Ok(())
}

/// Guest write to USART_SR register.
///
/// A couple fields of the USART status register are actually clearable by software,
/// but they are not recommended to be written to except when using multibuffer (ex: DMA)
/// communication. These are the TC, and RXNE bits. All other bits of the status
/// register are left unchanged after a write attempt.
pub(crate) fn usart_port_sr_w_hook(
    _cpu: &mut dyn CpuBackend,
    _ev: &mut dyn EventControllerImpl,
    _address: u64,
    size: u32,
    data: &[u8],
    port: &mut UartPortInner,
) -> Result<(), UnknownError> {
    if size != 2 && size != 4 {
        error!(
            "UART{:?}: Guest write to sr of improper size: {}. STM32F405 peripheral \
            registers must be accessed as half-words or as words",
            port, size
        );
    }

    println!("writing to sr!");

    let mut binding = port.inner_hal();
    let hal = binding.deref_mut();

    // because software can clear a couple bits of this register and not others, and this
    // can not be changed as a write occurs, the status register's source of truth is
    // the USART model and not CPU memory.

    // if any clearable status bits are being cleared, update the hal model
    let sr = u16::from_le_bytes([data[0], data[1]]); // only the first half-word matters
    let (mut tx_cleared, mut rxne_cleared) = (false, false);
    if sr & (1 << 5) == 0 {
        // RXNE cleared by software
        rxne_cleared = true;

        hal.data_terminals.clear_rdr_not_empty();
        hal.interrupt_control.int_rxne.clear();
    }
    if sr & (1 << 6) == 0 {
        // TC cleared by software
        tx_cleared = true;

        hal.data_terminals.clear_tx_complete();
        hal.interrupt_control.int_tc.clear();
    }

    // generate tracing information
    let trace = match (tx_cleared, rxne_cleared) {
        (true, true) => {
            "rxne (read data register not empty) and tc (transmit complete) \
            flags were cleared"
        }
        (true, false) => "tc (transmit complete) flag was cleared",
        (false, true) => "rxne (read data register not empty) flag was cleared",
        (false, false) => "no status flags were changed",
    };

    hal.interrupt_control.clear_recent_sr_read();

    trace!("USART{:?}: Guest write to sr, {}", port, trace,);
    Ok(())
}

/// Guest read to USART_SR register.
///
/// Reading the USART_SR register is a precondition to clearing certain interrupts, notably
/// the TC (transmission complete) and ORE (overrun error) interrupts, among others that this
/// emulation does not consider.
pub(crate) fn usart_port_sr_r_hook(
    _cpu: &mut dyn CpuBackend,
    _ev: &mut dyn EventControllerImpl,
    _address: u64,
    size: u32,
    data: &mut [u8],
    port: &mut UartPortInner,
) -> Result<(), UnknownError> {
    if size != 2 && size != 4 {
        error!(
            "UART{:?}: Guest read from sr of improper size: {}. STM32F405 peripheral \
            registers must be accessed as half-words or as words",
            port, size
        );
    }

    let mut binding = port.inner_hal();
    let hal = binding.deref_mut();

    // because software can clear a couple bits of this register and not others, and this
    // can only be changed in this read hook, the status register's source of truth is
    // the USART model and not CPU memory.

    // also note: many of the status register fields are currently ignored by emulation due to
    // abstraction over their functions, such as the IDLE line detected bit. Running firmware
    // that depends on these status bits may require removing those abstractions.

    // update the sr register value with bit-masking
    let mut sr: u16 = u16::from_le_bytes([data[0], data[1]]); // only the first half-word matters
    sr = (sr & !(1 << 7)) | ((hal.data_terminals.tdr_empty() as u16) << 7);
    sr = (sr & !(1 << 6)) | ((hal.data_terminals.tx_complete() as u16) << 6);
    sr = (sr & !(1 << 5)) | ((hal.data_terminals.rdr_not_empty() as u16) << 5);
    sr = (sr & !(1 << 3)) | ((hal.data_terminals.overrun_condition() as u16) << 3);

    data[0] = sr as u8;
    data[1] = (sr >> 8) as u8;

    hal.interrupt_control.set_recent_sr_read();

    trace!("USART{:?}: Guest read to sr, read half-word{}", port, sr,);
    Ok(())
}

/// Guest write to USART_CR1 register.
///
/// The control flags in this register that this emulation tracks are all interrupt enables and
/// hardware enables. This hook updates these fields.
///
/// Note: if there is data in the data register (DR) and a USART/UART client is connected and
/// awaiting data, this hook will trigger a transmission. If there are pending interrupt flags
/// that this data write enables, these interrupts will be queued.
pub(crate) fn usart_port_cr1_w_hook(
    _cpu: &mut dyn CpuBackend,
    ev: &mut dyn EventControllerImpl,
    _address: u64,
    size: u32,
    data: &[u8],
    port: &mut UartPortInner,
) -> Result<(), UnknownError> {
    if size != 2 && size != 4 {
        error!(
            "UART{:?}: Guest write to sr of improper size: {}. STM32F405 peripheral \
            registers must be accessed as half-words or as words",
            port, size
        );
    }

    println!("writing to cr1!");

    // generate tracing information while updating hal model control flags
    let mut usart_en = "disabled";
    let mut txe_int_en = "disabled";
    let mut tc_int_en = "disabled";
    let mut rxne_int_en = "disabled";
    let mut tx_en = "disabled";
    let mut rx_en = "disabled";

    let cr1 = u16::from_le_bytes([data[0], data[1]]); // only the first half-word matters
    if (cr1 & (1 << 13)) != 0x0000 {
        // USART enabled
        port.inner_hal().enable();
        usart_en = "enabled";
    } else {
        // USART disabled
        port.inner_hal().disable();
    }
    if (cr1 & (1 << 7)) != 0x0000 {
        // TXE interrupt enabled
        port.inner_hal().interrupt_control.int_txe.enable();
        txe_int_en = "enabled";

        if port.inner_hal().interrupt_control.int_txe.triggered() {
            // queue interrupt
            port.queue_interrupt(ev);
        }
    } else {
        // TXE interrupt disabled
        port.inner_hal().interrupt_control.int_txe.disable();
    }
    if (cr1 & (1 << 6)) != 0x0000 {
        // TC interrupt enabled
        port.inner_hal().interrupt_control.int_tc.enable();
        tc_int_en = "enabled";

        if port.inner_hal().interrupt_control.int_tc.triggered() {
            // queue interrupt
            port.queue_interrupt(ev);
        }
    } else {
        // TC interrupt disabled
        port.inner_hal().interrupt_control.int_tc.disable();
    }
    if (cr1 & (1 << 5)) != 0x0000 {
        // RXNE interrupt enabled
        port.inner_hal().interrupt_control.int_rxne.enable();
        rxne_int_en = "enabled";

        if port.inner_hal().interrupt_control.int_rxne.triggered() {
            // queue interrupt
            port.queue_interrupt(ev);
        }
    } else {
        // RXNE interrupt disabled
        port.inner_hal().interrupt_control.int_rxne.disable();
    }
    if (cr1 & (1 << 3)) != 0x0000 {
        // Transmitter enabled
        port.inner_hal().data_terminals.tx_enable();
        tx_en = "enabled";

        // determine whether to transmit data or not
        if port.inner_hal().data_terminals.tx_enabled()
            && !port.inner_hal().data_terminals.tdr_empty()
            && port.inner_hal().enabled()
        {
            let dd = port
                .inner_hal()
                .data_terminals
                .send_from_tdr()
                .expect("tdr should have data during the execution of the dr_w memory hook");
            // transmit
            port.guest_transmit_data(dd);
        }
    } else {
        // Transmitter disabled
        port.inner_hal().data_terminals.tx_disable();
    }
    if (cr1 & (1 << 2)) != 0x0000 {
        // Receiver enabled
        port.inner_hal().data_terminals.rx_enable();
        rx_en = "enabled";
    } else {
        // Reciever disabled
        port.inner_hal().disable();
    }

    port.inner_hal().interrupt_control.clear_recent_sr_read();

    trace!(
        "USART{:?}: Guest write to sr, {}. USART peripheral {}. \
        TXE interrupt {}. TC interrupt {}. RXNE interrupt \
        {}. Transmitter {}. Receiver {}.\
        \nThe data written was: {:#b}",
        port,
        cr1,
        usart_en,
        txe_int_en,
        tc_int_en,
        rxne_int_en,
        tx_en,
        rx_en,
        cr1
    );
    Ok(())
}

/// Guest read to USART_CR1 register.
/// The control flags in this register that this emulation tracks are all interrupt enables and
/// hardware enables. This hook maintains the hardware abstraction model as the source
/// of truth rather than the CPU memory.
pub(crate) fn usart_port_cr1_r_hook(
    _cpu: &mut dyn CpuBackend,
    _ev: &mut dyn EventControllerImpl,
    _address: u64,
    size: u32,
    data: &mut [u8],
    port: &mut UartPortInner,
) -> Result<(), UnknownError> {
    if size != 2 && size != 4 {
        error!(
            "UART{:?}: Guest read to sr of improper size: {}. STM32F405 peripheral \
            registers must be accessed as half-words or as words",
            port, size
        );
    }

    println!("reading from cr1!");

    let mut binding = port.inner_hal();
    let hal = binding.deref_mut();

    // update the cr1 register value with bit-masking
    let mut cr1: u16 = u16::from_le_bytes([data[0], data[1]]); // only the first half-word matters
    cr1 = (cr1 & !(1 << 13)) | ((hal.enabled() as u16) << 13);
    cr1 = (cr1 & !(1 << 7)) | ((hal.interrupt_control.int_txe.enabled() as u16) << 7);
    cr1 = (cr1 & !(1 << 6)) | ((hal.interrupt_control.int_tc.enabled() as u16) << 6);
    cr1 = (cr1 & !(1 << 5)) | ((hal.interrupt_control.int_rxne.enabled() as u16) << 5);
    cr1 = (cr1 & !(1 << 3)) | ((hal.data_terminals.tx_enabled() as u16) << 3);
    cr1 = (cr1 & !(1 << 2)) | ((hal.data_terminals.rx_enabled() as u16) << 2);

    data[0] = cr1 as u8;
    data[1] = (cr1 >> 8) as u8;

    hal.interrupt_control.clear_recent_sr_read();

    trace!("USART{:?}: Guest read to sr, {}.", port, cr1,);
    Ok(())
}

/// Unit tests for the STM32F405 USART implementation
#[cfg(test)]
mod tests {
    use crate::uart::get_uarts;
    use crate::uart::inner::UartPortInner;
    use std::ops::DerefMut;
    use styx_core::core::builder::DummyProcessorBuilder;
    use styx_core::prelude::ProcessorBuilder;
    use styx_peripherals::uart::UartController;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn dr_read_clears_rx_interrupt_conditions() {
        // create dummy CPU
        let mut proc = ProcessorBuilder::default()
            .with_builder(DummyProcessorBuilder)
            .build()
            .unwrap();
        let mut uarts = UartController::new(get_uarts());
        // create a USART port
        let port = uarts.get::<UartPortInner>("1").unwrap();

        // pretend the USART has received too much data and is in overrrun
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .receive_to_rdr(0x11);
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .receive_to_rdr(0x22);

        let mut data: [u8; 2] = [0x00, 0x00];

        // read from the port
        super::usart_port_dr_r_hook(
            proc.core.cpu.as_mut(),
            proc.core.event_controller.inner.as_mut(),
            0x0000_0000,
            2,
            &mut data,
            port,
        )
        .unwrap();

        // assert that the proper data was read and that overrun and RXNE is cleared
        assert!(!port
            .inner_hal()
            .deref_mut()
            .data_terminals
            .overrun_condition());
        assert!(!port.inner_hal().deref_mut().data_terminals.rdr_not_empty());
        assert_eq!(data[0], 0x11);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn dr_write_clears_tx_interrupt_conditions() {
        // create dummy CPU
        let mut proc = ProcessorBuilder::default()
            .with_builder(DummyProcessorBuilder)
            .build()
            .unwrap();
        let mut uarts = UartController::new(get_uarts());
        // create a USART port
        let port = uarts.get::<UartPortInner>("1").unwrap();

        // pretend the USART has sent data and is empty
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .write_to_tdr(0x11);
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .send_from_tdr()
            .unwrap(); // make sure it does actually send
        port.inner_hal()
            .deref_mut()
            .interrupt_control
            .set_recent_sr_read();

        // write new data to clear the interrupts
        super::usart_port_dr_w_hook(
            proc.core.cpu.as_mut(),
            proc.core.event_controller.inner.as_mut(),
            0x0000_0000,
            2,
            &[0xAA, 0x00],
            port,
        )
        .unwrap();

        // assert that the data was written and the interrupts are cleared
        assert!(!port.inner_hal().deref_mut().data_terminals.tdr_empty());
        assert!(!port.inner_hal().deref_mut().data_terminals.tx_complete());
        assert_eq!(
            port.inner_hal()
                .deref_mut()
                .data_terminals
                .send_from_tdr()
                .unwrap(),
            0xAA
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sr_write_clears_clearable_bits() {
        // create dummy CPU
        let mut proc = ProcessorBuilder::default()
            .with_builder(DummyProcessorBuilder)
            .build()
            .unwrap();
        let mut uarts = UartController::new(get_uarts());
        // create a USART port
        let port = uarts.get::<UartPortInner>("1").unwrap();

        // set the status bits TC and RXNE that are clearable by software
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .set_rdr_not_empty();
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .set_tx_complete();

        // write new data to clear the status bits
        super::usart_port_sr_w_hook(
            proc.core.cpu.as_mut(),
            proc.core.event_controller.inner.as_mut(),
            0x0000_0000,
            2,
            &[0x00, 0x00],
            port,
        )
        .unwrap();

        // assert that the TXE and TC status fields are cleared
        assert!(!port.inner_hal().deref_mut().data_terminals.tx_complete());
        assert!(!port.inner_hal().deref_mut().data_terminals.rdr_not_empty());

        // set the status bits again
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .set_rdr_not_empty();
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .set_tx_complete();

        // this write should not clear anything
        super::usart_port_sr_w_hook(
            proc.core.cpu.as_mut(),
            proc.core.event_controller.inner.as_mut(),
            0x0000_0000,
            2,
            &[0xFF, 0xFF],
            port,
        )
        .unwrap();

        // assert that the TXE and TC status fields are still set
        assert!(port.inner_hal().deref_mut().data_terminals.tx_complete());
        assert!(port.inner_hal().deref_mut().data_terminals.rdr_not_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sr_read_trips_tracking_flag() {
        // create dummy CPU
        let mut proc = ProcessorBuilder::default()
            .with_builder(DummyProcessorBuilder)
            .build()
            .unwrap();
        let mut uarts = UartController::new(get_uarts());
        // create a USART port
        let port = uarts.get::<UartPortInner>("1").unwrap();

        // set and clear some status bits
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .set_rdr_not_empty();
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .set_tx_complete();
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .set_overrun_condition();
        port.inner_hal()
            .deref_mut()
            .data_terminals
            .clear_tdr_empty();

        // read status register
        let mut sr = [0x00, 0x00];
        super::usart_port_sr_r_hook(
            proc.core.cpu.as_mut(),
            proc.core.event_controller.inner.as_mut(),
            0x0000_0000,
            2,
            &mut sr,
            port,
        )
        .unwrap();

        // assert that the proper sr value is given, and the sr-recently-read flag is set
        assert!(port
            .inner_hal()
            .deref_mut()
            .interrupt_control
            .recent_sr_read());
        assert_eq!(sr[0], 0b01101000);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn cr1_read_follows_hal_model() {
        // create dummy CPU
        let mut proc = ProcessorBuilder::default()
            .with_builder(DummyProcessorBuilder)
            .build()
            .unwrap();
        let mut uarts = UartController::new(get_uarts());
        // create a USART port
        let port = uarts.get::<UartPortInner>("1").unwrap();

        // set some control bits
        port.inner_hal().deref_mut().data_terminals.rx_enable();
        port.inner_hal().deref_mut().data_terminals.tx_enable();
        port.inner_hal().deref_mut().enable();

        // read cr1 register
        let mut cr1 = [0x00, 0x00];
        super::usart_port_cr1_r_hook(
            proc.core.cpu.as_mut(),
            proc.core.event_controller.inner.as_mut(),
            0x0000_0000,
            2,
            &mut cr1,
            port,
        )
        .unwrap();

        // assert that the read data matches the hal control flags from earlier
        assert_eq!(cr1[0], 0b00001100);
        assert_eq!(cr1[1], 0b00100000);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn cr1_write_updates_hal_model() {
        // create dummy CPU
        let mut proc = ProcessorBuilder::default()
            .with_builder(DummyProcessorBuilder)
            .build()
            .unwrap();
        let mut uarts = UartController::new(get_uarts());
        // create a USART port
        let port = uarts.get::<UartPortInner>("1").unwrap();

        // write to the cr1 register to enable some control flags
        let cr1 = [0x6C, 0x00];
        super::usart_port_cr1_w_hook(
            proc.core.cpu.as_mut(),
            proc.core.event_controller.inner.as_mut(),
            0x0000_0000,
            2,
            &cr1,
            port,
        )
        .unwrap();

        // assert that the hal control flags were updated correctly
        assert!(port.inner_hal().deref_mut().data_terminals.tx_enabled());
        assert!(port.inner_hal().deref_mut().data_terminals.rx_enabled());
        assert!(port
            .inner_hal()
            .deref_mut()
            .interrupt_control
            .int_rxne
            .enabled());
        assert!(port
            .inner_hal()
            .deref_mut()
            .interrupt_control
            .int_tc
            .enabled());
    }
}
