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
use styx_core::{
    hooks::{MemoryReadHook, MemoryWriteHook},
    prelude::*,
};
use styx_cyclone_v_hps_sys::uart0;
use styx_peripherals::uart::UartController;
use tracing::{debug, error, trace};

use super::{
    inner::{CycloneVInterruptIds, UartHalLayer, TX_RX_FIFO_BUFFERS_SIZE},
    UartPortInner,
};

// UART-Module, Cyclone V HPS Register Address Map and Definitions"
// UART - Register Layout Typedef
// - Reference: https://www.intel.com/content/www/us/en/programmable/hps/cyclone-v/hps.html
// NOTE: To simplify the code (for now), we are currently ignoring:
//      - DMA
//      - non-FIFO mode

// rbr_thr_dll
//  - Receive Buffer Register (rbr)
//      - reads
//      - Contains the received data byte.
//      - The data in this register is valid only if the Data Ready ( bit 0 in the Line Status
//        Register(LSR)) is set to 1.
//      - If FIFOs are disabled (bit 0 of Register FCR is set to 0) the data in the RBR must be
//        read before the next data arrives, otherwise it will be overwritten, resulting in an
//        overrun error.
//      - If FIFOs are enabled(bit 0 of Register FCR is set to 1) this register accesses the head
//        of the receive FIFO. If the receive FIFO is full, and this register is not read before
//        the next data character arrives, then the data already in the FIFO will be preserved but
//        any incoming data will be lost. An overrun error will also occur.
//  - Transmit Holding Register (thr)
//      - writes
//      - This register contains the byte to be transmitted.
//      - Data should only be written to the THR when the THR Empty bit 5 of the LSR Register is
//        set to 1.
//      - If FIFOs are disabled (bit 0 of Register FCR is set to 0) and THRE is set to 1, writing
//        a single character to the THR clears the THRE. Any additional writes to the THR before
//        the THRE is set again causes the THR data to be overwritten.
//      - If FIFO's are enabled (bit 0 of Register FCR is set to 1) and THRE is set up to 128
//        characters of data may be written to the THR before the FIFO is full. Any attempt to
//        write data when the FIFO is full results in the write data being lost.
//  - Divisor Latch Low (dll)
//      - Accessible in dlab mode only.
//      - This register makes up the lower 8-bits of a 16-bit, Read/write, Divisor Latch register
//        that contains the baud rate divisor for the UART.
//      - This register may only be accessed when the DLAB bit 7 of the LCR Register is set to 1.

/// Guest write to rbr_thr_dll - Rx Buffer, Tx Holding, and Divisor Latch Low
///     There are two possible write views for this register:
///     - Transmit Holding Register (thr)
///         - This register contains the byte to be transmitted.
///         - Data should only be written to the THR when the THR Empty bit 5 of the LSR Register is
///           set to 1.
///         - If FIFOs are disabled (bit 0 of Register FCR is set to 0) and THRE is set to 1, writing
///           a single character to the THR clears the THRE. Any additional writes to the THR before
///           the THRE is set again causes the THR data to be overwritten.
///         - If FIFO's are enabled (bit 0 of Register FCR is set to 1) and THRE is set up to 128
///           characters of data may be written to the THR before the FIFO is full. Any attempt to
///           write data when the FIFO is full results in the write data being lost.
///     - Divisor Latch Low (dll)
///         - Accessible in dlab mode only.
///         - This register makes up the lower 8-bits of a 16-bit, Read/write, Divisor Latch register
///           that contains the baud rate divisor for the UART.
///         - This register may only be accessed when the DLAB bit 7 of the LCR Register is set to 1.
fn uart_port_rbr_thr_dll_w_hook(
    id: &String,
    proc: CoreHandle,
    _address: u64,
    size: u32,
    data: &[u8],
) {
    if size != 4 {
        error!(
            "UART{}: Guest write to rbr_thr_dll of improper size: {}",
            id, size
        );
    }

    // convert the byte array into a u32
    let data = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // If we are in the dlab state, this write is setting the divisor latch register value, dll,
    // involved in setting the baud rate. Otherwise, the write is setting Transmit Holding Register
    // (thr) value.  We save the divisor latch values so they can persist after the mode is
    // switched out of the dlab state.
    if port.inner_hal.dlab_state {
        port.inner_hal.shadow_regs.dll_val = data;
    } else {
        // thr write - send the transmitted byte.
        // Write the new data into the register.
        unsafe {
            port.inner_hal
                .registers
                .rbr_thr_dll()
                .write(|w| w.bits(data))
        };

        // Parse the resulting ier fields.
        let rbr_thr_dll = unsafe { port.inner_hal.registers.rbr_thr_dll().sys_read() };

        // Send the thr value to the UART client.
        port.guest_transmit_data(rbr_thr_dll.value().bits());

        // Writing into thr clears the interrupt (Cyclone V TRM Table 22-4). Note, we never
        // actually put anything into the TX FIFO, so we don't need to check the empty threshold.
        port.inner_hal
            .interrupt_control
            .int_tx_holding_empty
            .clear();
    }

    trace!("UART{}: Guest write to rbr_thr_dll: {:#x}", id, data);
}

/// Guest read from rbr_thr_dll - Rx Buffer, Tx Holding, and Divisor Latch Low
///     There are two possible read views for this register:
///     - Receive Buffer Register (rbr)
///         - Contains the received data byte.
///         - The data in this register is valid only if the Data Ready ( bit 0 in the Line Status
///           Register(LSR)) is set to 1.
///         - If FIFOs are disabled (bit 0 of Register FCR is set to 0) the data in the RBR must be
///           read before the next data arrives, otherwise it will be overwritten, resulting in an
///           overrun error.
///         - If FIFOs are enabled(bit 0 of Register FCR is set to 1) this register accesses the head
///           of the receive FIFO. If the receive FIFO is full, and this register is not read before
///           the next data character arrives, then the data already in the FIFO will be preserved but
///           any incoming data will be lost. An overrun error will also occur.
///     - Divisor Latch Low (dll)
///         - Accessible in dlab mode only.
///         - This register makes up the lower 8-bits of a 16-bit, Read/write, Divisor Latch register
///           that contains the baud rate divisor for the UART.
///         - This register may only be accessed when the DLAB bit 7 of the LCR Register is set to 1.
fn uart_port_rbr_thr_dll_r_hook(
    id: &String,
    proc: CoreHandle,
    _address: u64,
    size: u32,
    data: &mut [u8],
) {
    if size != 4 {
        error!(
            "UART{}: Guest read from rbr_thr_dll of improper size: {}",
            id, size
        );
    }

    // convert the byte array into a u32
    let mut reg_val = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // If we are in the dlab state, this read is for the divisor latch register value, dll.
    // Otherwise, the rbr value is being accessed.
    // Make sure the data being returned to the guest matches the current state, as the last write
    // to the register could have been during a different state.
    if port.inner_hal.dlab_state {
        if reg_val != port.inner_hal.shadow_regs.dll_val {
            reg_val = port.inner_hal.shadow_regs.dll_val;
            data[0..4].copy_from_slice(&reg_val.to_le_bytes()[..]);
        }
    } else {
        // rbr read - retrieve a received byte for the guest.
        reg_val = port.inner_hal.fifo.rx_get() as u32;
        data[0..4].copy_from_slice(&reg_val.to_le_bytes()[..]);

        clear_rx_data_interrupts(&mut port.inner_hal);
    }

    trace!("UART{}: Guest read from rbr_thr_dll: {:#x}", id, reg_val);
}

/// Guest write to ier_dlh - Interrupt Enable and Divisor Latch High
fn uart_port_ier_dlh_w_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &[u8]) {
    if size != 4 {
        error!(
            "UART{}: Guest write to ier_dlh of improper size: {}",
            id, size
        );
    }

    // convert the byte array into a u32
    let data = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let mut do_interrupt = None;

    {
        let port = proc
            .event_controller
            .peripherals
            .get::<UartController>()
            .unwrap()
            .get::<UartPortInner>(id)
            .unwrap();

        // If we are in the dlab state, this write is setting the divisor latch register value, dlh,
        // involved in setting the baud rate. Otherwise, the interrupt enable register is being
        // modified. We save both so we can return the correct one during register reads.
        if port.inner_hal.dlab_state {
            port.inner_hal.shadow_regs.dll_val = data;
        } else {
            port.inner_hal.shadow_regs.ier_val = data;

            // We are not in dlab state, so this is an IER access, so we check for the new interrupt
            // configuration.
            store_ier_state(&mut port.inner_hal, data);

            // If changes in enabled interrupts trigger a new interrupt, we queue it with the event
            // handler.
            let int_ctl = &port.inner_hal.interrupt_control;
            if int_ctl.int_thre.triggered()
                || int_ctl.int_modem_status.triggered()
                || int_ctl.int_rx_line_status.triggered()
                || int_ctl.int_tx_holding_empty.triggered()
                || int_ctl.int_rx_data_aval_and_char_timeout.triggered()
            {
                do_interrupt = Some(port.tx_rx_irqn);
            }
        }
    }

    if let Some(i) = do_interrupt {
        proc.event_controller.latch(i).unwrap();
    }

    trace!("UART{}: Guest write to ier_dlh: {:#x}", id, data);
}

/// Guest read from ier_dlh - Interrupt Enable and Divisor Latch High
fn uart_port_ier_dlh_r_hook(
    id: &String,
    proc: CoreHandle,
    _address: u64,
    size: u32,
    data: &mut [u8],
) {
    if size != 4 {
        error!(
            "UART{}: Guest read from ier_dlh of improper size: {}",
            id, size
        );
    }

    // convert the byte array into a u32
    let mut reg_val = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // If we are in the dlab state, this read is for the divisor latch register value, dlh.
    // Otherwise, the interrupt enable register is being accessed.
    // Make sure the data being returned to the guest matches the current state, as the last write
    // to the register could have been during a different state.
    if port.inner_hal.dlab_state {
        // DLAB state
        if reg_val != port.inner_hal.shadow_regs.dlh_val {
            data[0..4].copy_from_slice(&port.inner_hal.shadow_regs.dlh_val.to_le_bytes()[..]);
            reg_val = port.inner_hal.shadow_regs.dlh_val;
        }
    } else if reg_val != port.inner_hal.shadow_regs.ier_val {
        // IER state, so we want to make sure the returned value matches our saved value.
        data[0..4].copy_from_slice(&port.inner_hal.shadow_regs.ier_val.to_le_bytes()[..]);
        reg_val = port.inner_hal.shadow_regs.ier_val;
    }

    trace!("UART{}: Guest read from ier_dlh: {:#x}", id, reg_val);
}

// iir & fcr - These registers share the same offset in the register bank. This is possible since
// iir is read-only and fcr is write-only.
/// FIFO Control (when written) - fcr
fn uart_port_iir_w_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &[u8]) {
    if size != 4 {
        error!("UART{}: Guest write to fcr of improper size: {}", id, size);
    }

    // convert the byte array into a u32
    let data = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    port.inner_hal.shadow_regs.fcr_val = data;
    update_fifo_state(&mut port.inner_hal, data);
    trace!("UART{}: Guest write to fcr: {:#x}", id, data);
}

/// Interrupt Identity Register (when read) - iir
fn uart_port_iir_r_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &mut [u8]) {
    if size != 4 {
        error!("UART{}: Guest read from iir of improper size: {}", id, size);
    }

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // Generate an iir value.
    let iir = generate_iir(&mut port.inner_hal);

    // Copy the iir value out for the guest to access.
    data[0..4].copy_from_slice(&iir.to_le_bytes()[..]);
    trace!("UART{}: Guest read from iir: {:#x}", id, iir);
}

/// Guest write to lcr - Line Control Register (When Written)
fn uart_port_lcr_w_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &[u8]) {
    if size != 4 {
        error!("UART{}: Guest write to lcr of improper size: {}", id, size);
    }

    // convert the byte array into a u32
    let data = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    store_dlab_state(&mut port.inner_hal, data);
    trace!("UART{}: Guest write to lcr: {:#x}", id, data);
}

/// Guest write to mcr - Modem Control Register
fn uart_port_mcr_w_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &[u8]) {
    if size != 4 {
        error!("UART{}: Guest write to mcr of improper size: {}", id, size);
    }

    // convert the byte array into a u32
    let data = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    store_mcr_state(&mut port.inner_hal, data);
    port.inner_hal.shadow_regs.fcr_val = data;

    trace!("UART{}: Guest write to mcr: {:#x}", id, data);
}

/// Guest read from lsr - Line Status Register
fn uart_port_lsr_r_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &mut [u8]) {
    if size != 4 {
        error!("UART{}: Guest read from lsr of improper size: {}", id, size);
    }

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // Generate an lsr value.
    let lsr = generate_lsr(&mut port.inner_hal);

    // Reading the Line Status Register clears the Receiver Line Status Interrupt (Cyclone V TRM
    // Table 22-4).
    port.inner_hal.interrupt_control.int_rx_line_status.clear();

    // Copy the lsr value out for the guest to access.
    data[0..4].copy_from_slice(&lsr.to_le_bytes()[..]);
    trace!("UART{}: Guest read from lsr: {:#x}", id, lsr);
}

/// Guest read from msr - Modem Status Register
fn uart_port_msr_r_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &mut [u8]) {
    if size != 4 {
        error!("UART{}: Guest read from msr of improper size: {}", id, size);
    }

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // Generate a msr value.
    let client_connected = port.inner_hal.client_connected();
    let msr = generate_msr(&mut port.inner_hal, client_connected);

    // Reading the Modem Status Register clears the Modem Status Interrupt (Cyclone V TRM Table
    // 22-4).
    port.inner_hal.interrupt_control.int_modem_status.clear();

    // Copy the msr value out for the guest to access.
    data[0..4].copy_from_slice(&msr.to_le_bytes()[..]);
    trace!("UART{}: Guest read from msr: {:#x}", id, msr);
}

/// Guest read from srbr - Shadow Receive Buffer Register
fn uart_port_srbr_r_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &mut [u8]) {
    if size != 4 {
        error!(
            "UART{}: Guest read from srbr of improper size: {}",
            id, size
        );
    }

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // rbr read - retrieve a received byte for the guest.
    let rbr = port.inner_hal.fifo.rx_get() as u32;
    data[0..4].copy_from_slice(&rbr.to_le_bytes()[..]);

    clear_rx_data_interrupts(&mut port.inner_hal);

    trace!("UART{}: Guest read from srbr: {:#x}", id, rbr);
}

/// Guest write to sthr - Shadow Transmit Buffer Register
fn uart_port_sthr_w_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &[u8]) {
    if size != 4 {
        error!("UART{}: Guest write to sthr of improper size: {}", id, size);
    }

    // convert the byte array into a u32
    let data = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // shadow thr write - send the transmitted byte.

    // Write the new data into the register.
    unsafe { port.inner_hal.registers.sthr().write(|w| w.bits(data)) };

    // Parse the resulting ier fields.
    let sthr = unsafe { port.inner_hal.registers.sthr().sys_read() };

    // Send the thr value to the UART client.
    port.guest_transmit_data(sthr.sthr().bits());

    // Writing into thr clears the interrupt (Cyclone V TRM Table 22-4). Note, we never actually
    // put anything into the TX FIFO, so we don't need to check the empty threshold.
    port.inner_hal
        .interrupt_control
        .int_tx_holding_empty
        .clear();

    trace!("UART{}: Guest write to sthr: {:#x}", id, data);
}

/// Guest read from usr - UART Status Register
fn uart_port_usr_r_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &mut [u8]) {
    if size != 4 {
        error!("UART{}: Guest read from usr of improper size: {}", id, size);
    }

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // Generate a usr value.
    let usr = generate_usr(&mut port.inner_hal);

    // Copy the usr value out for the guest to access.
    data[0..4].copy_from_slice(&usr.to_le_bytes()[..]);
    trace!("UART{}: Guest read from usr: {:#x}", id, usr);
}

/// Guest read from tfl - Transmit FIFO Level
/// - tfl (bits 7:0)
///     - This indicates the number of data entries in the transmit FIFO.
fn uart_port_tfl_r_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &mut [u8]) {
    if size != 4 {
        error!("UART{}: Guest read from tfl of improper size: {}", id, size);
    }

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    let tfl = port.inner_hal.fifo.size as u32;
    data[0..4].copy_from_slice(&tfl.to_le_bytes()[..]);

    trace!("UART{}: Guest read from tfl: {:#x}", id, tfl);
}

/// Guest read from rfl - Receive FIFO Level Guest write
/// - rfl (bits 7:0)
///     - This indicates the number of data entries in the receive FIFO.
fn uart_port_rfl_r_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &mut [u8]) {
    if size != 4 {
        error!("UART{}: Guest read from rfl of improper size: {}", id, size);
    }

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    let rfl = std::cmp::min(port.inner_hal.fifo.rx_len(), port.inner_hal.fifo.size) as u32;
    data[0..4].copy_from_slice(&rfl.to_le_bytes()[..]);

    trace!("UART{}: Guest read from rfl: {:#x}", id, rfl);
}

/// Guest write to srr - Software Reset Register
fn uart_port_srr_w_hook(id: &String, proc: CoreHandle, _address: u64, size: u32, data: &[u8]) {
    if size != 4 {
        error!("UART{}: Guest write to srr of improper size: {}", id, size);
    }

    // convert the byte array into a u32
    let data = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert {data:?} into u32")),
    );

    let port = proc
        .event_controller
        .peripherals
        .get::<UartController>()
        .unwrap()
        .get::<UartPortInner>(id)
        .unwrap();

    // # Safety
    //
    // srr:
    //  - xfr (bit 2):
    //      - This is a shadow register for the Tx FIFO Reset bit (FCR bit 2). This resets the control
    //        portion of the transmit FIFO and treats the FIFO as empty.
    //  - rfr (bit 1):
    //      - This is a shadow register for the Rx FIFO Reset bit (FCR bit 1). This resets the control
    //        portion of the receive FIFO and treats the FIFO as empty.
    //  - ur (bit 0):
    //      - This asynchronously resets the UART and synchronously removes the reset assertion.
    //
    // Write the new data into the register.
    unsafe { port.inner_hal.registers.srr().write(|w| w.bits(data)) };

    // Parse the resulting srr fields.
    //
    // # Safety
    // srr is a readonly register, we need to check if certain fields are set to handle the
    // behaviour of it, srr is normally handled by hardware hence the `sys_read`
    let srr = unsafe { port.inner_hal.registers.srr().sys_read() };

    if srr.rfr().bit_is_set() {
        port.inner_hal.fifo.rx_clear();
    }

    if srr.ur().bit_is_set() {
        // TODO: Do we also need to do anything at the port layer? We should probably reset any
        // client connections.
        port.inner_hal.reset(proc.mmu).unwrap();
    }

    trace!("UART{}: Guest write to srr: {:#x}", id, data);
}

/// Clear character timeout and receive data available interrupts.
fn clear_rx_data_interrupts(hal: &mut UartHalLayer) {
    // From Cyclone V TRM Table 22-4:
    // Reading from the receive buffer register (rbr) clears character timeout interrupts.
    hal.interrupt_control.char_timeout = false;
    // The FIFO dropping below the trigger level clears the received data available interrupt.
    if !hal.fifo.rx_trigger_level_reached() {
        hal.interrupt_control
            .int_rx_data_aval_and_char_timeout
            .clear();
    }
}

/// ier_dlh
/// ier:
///  - ptime_dlh7 (bit 7)
///      - Interrupt Enable Register: This is used to enable/disable the generation of THRE Interrupt.
///  - edssi_dhl3 (bit 3)
///      - Interrupt Enable Register: This is used to enable/disable the generation of Modem Status
///        Interrupt.
///  - elsi_dhl2 (bit 2)
///      - Interrupt Enable Register: This is used to enable/disable the generation of Receiver Line
///        Status Interrupt.
///      - This is the highest priority interrupt.
///  - etbei_dlhl (bit 1)
///      - Interrupt Enable Register: Enable Transmit Holding Register Empty Interrupt. This is used
///        to enable/disable the generation of Transmitter Holding Register Empty Interrupt.
///      - This is the third highest priority interrupt.
///  - erbfi_dlh0 (bit 0)
///      - Interrupt Enable Register: Used to enable/disable the generation of the Receive Data
///        Available Interrupt and the Character Timeout Interrupt (if FIFO's enabled).
///      - These are the second highest priority interrupts.
fn store_ier_state(hal: &mut UartHalLayer, data: u32) {
    // Write the new data into the register.
    unsafe { hal.registers.ier_dlh().write(|w| w.bits(data)) };

    // Parse the resulting ier fields.
    let ier = unsafe { hal.registers.ier_dlh().sys_read() };

    hal.interrupt_control
        .int_thre
        .set_enabled(ier.ptime_dlh7().bit_is_set());
    hal.interrupt_control
        .int_modem_status
        .set_enabled(ier.edssi_dhl3().bit_is_set());
    hal.interrupt_control
        .int_rx_line_status
        .set_enabled(ier.elsi_dhl2().bit_is_set());
    hal.interrupt_control
        .int_tx_holding_empty
        .set_enabled(ier.etbei_dlhl().bit_is_set());
    hal.interrupt_control
        .int_rx_data_aval_and_char_timeout
        .set_enabled(ier.erbfi_dlh0().bit_is_set());
}

/// fcr:
///  - fifoe (bit 0)
///      - Enables/disables the transmit (Tx) and receive (Rx) FIFO's.
///      - Whenever the value of this bit is changed both the Tx and Rx controller portion of FIFO's
///        will be reset.
///  - rfifor (bit 1) - Clear RX FIFO.
///  - xfifor (bit 2) - Clear TX FIFO.
///  - tet (bits 5:4)
///      - This is used to select the empty threshold level at which the THRE Interrupts will be
///        generated when the mode is active.
///      - It also determines when the uart DMA transmit request signal uart_dma_tx_req_n will be
///        asserted when in certain modes of operation.
///      - Values:
///         - 0x0 - FIFO empty
///         - 0x1 - Two characters in FIFO
///         - 0x2 - FIFO 1/4 full
///         - 0x3 - FIFO 1/2 full
///  - rt (bits 7:6)
///      - This is used to select the trigger level in the receiver FIFO at which the Received Data
///        Available Interrupt will be generated.
///      - It also determines when the uart_dma_rx_req_n signal will be asserted when in certain
///        modes of operation.
///         - 0x0 - one character in fifo
///         - 0x1 - FIFO 1/4 full
///         - 0x2 - FIFO 1/2 full
///         - 0x3 - FIFO 2 less than full
fn update_fifo_state(hal: &mut UartHalLayer, data: u32) {
    // Write the new data into the register.
    unsafe { hal.registers.fcr().write(|w| w.bits(data)) };

    // Parse the resulting fcr fields.
    let fcr = unsafe { hal.registers.fcr().sys_read() };

    // Check fifoe setting.
    hal.fifo.enabled = fcr.fifoe().bit_is_set();

    // Clear RX FIFO if rfifor is set.
    if fcr.rfifor().bit_is_set() {
        hal.fifo.rx_clear();
    }

    // rt check (bits 7:6)
    hal.fifo.rx_trigger_level = match fcr.rt().bits() {
        0 => 1,
        1 => TX_RX_FIFO_BUFFERS_SIZE / 4,
        2 => TX_RX_FIFO_BUFFERS_SIZE / 2,
        3 => TX_RX_FIFO_BUFFERS_SIZE - 2,
        _ => panic!("This is an impossible case."),
    };

    // tet check (bits 5:4)
    hal.fifo.tx_empty_threshold = match fcr.tet().bits() {
        0 => 0,
        1 => 2,
        2 => TX_RX_FIFO_BUFFERS_SIZE / 4,
        3 => TX_RX_FIFO_BUFFERS_SIZE / 2,
        _ => panic!("This is an impossible case."),
    };
}

/// iir:
///  - fifoen (bits 7:6)
///      - Indicates whether the FIFOs are enabled or disabled.
///          - 0x0 - disabled
///          - 0x3 - enabled
///  - id (bits 3:0)
///      - Indicates the highest priority pending interrupt.
///          - 0x0 - Modem status
///          - 0x1 - No Interrupt pending
///          - 0x2 - THR empty
///          - 0x4 - Receive data available
///          - 0x6 - Receive line status
///          - 0xc - Character timeout
fn generate_iir(hal: &mut UartHalLayer) -> u32 {
    // Start with the register's reset value.
    unsafe {
        hal.registers.iir().sys_reset();
    }

    // Set fifoen and id.
    // TODO: _Actually_ set id to something valid.
    let fifoen: u8 = if hal.fifo.enabled { 0x3 } else { 0 };

    let id = hal.interrupt_control.highest_priority_active();

    if id == CycloneVInterruptIds::Thrempty {
        // If the Transmit Holding Register Empty interrupt is the source of an interrupt,
        // reading the IIR register clears the interrupt (Cyclone V TRM Table 22-4).
        hal.interrupt_control.int_tx_holding_empty.clear();
    }

    unsafe {
        hal.registers
            .iir()
            .sys_modify(|_r, w| w.fifoen().bits(fifoen).id().variant(id as u8));
    }
    hal.registers.iir().read().bits()
}

/// Certain registers can have multiple meanings and values depending on the processors state.
/// The dlab state determines whether or not the divisor latch view is being accessed for the
/// corresponding registers ier_dlh and rbr_thr_dll.
fn store_dlab_state(hal: &mut UartHalLayer, data: u32) {
    let lcr = hal.registers.lcr();
    unsafe { lcr.write(|w| w.bits(data)) };

    // dlab - divisor latch register (dll and dlh) - for setting baud rate.
    // - 0 - disabled
    // - 1 - enabled
    //
    // This switches the mode of the corresponding registers (rbr_thr_dll and ier_dlh).
    hal.dlab_state = lcr.read().dlab().bit_is_set();
}

/// mcr:
///  - Request to Send (rts) (bit 1)
///      - Signals that the UART is ready to accept new data.
///  - Data Terminal Ready (dtr) (bit 0)
///      - Signals that the UART is ready to connect to client devices.
fn store_mcr_state(hal: &mut UartHalLayer, data: u32) {
    // Write the new data into the register.
    unsafe { hal.registers.mcr().write(|w| w.bits(data)) };

    // Parse the resulting mcr fields.
    let mcr = unsafe { hal.registers.mcr().sys_read() };

    hal.request_to_send = mcr.rts().bit_is_set();
    hal.data_terminal_ready = mcr.dtr().bit_is_set();
}

/// lsr:
///  - data ready (dr)
///      - This is used to indicate that the receiver contains at least one character in the RBR
///        or the receiver FIFO. This bit is cleared when the RBR is read in the non-FIFO mode, or
///        when the receiver FIFO is empty, in the FIFO mode.
///      - read only
///  - tx hold register empty (thre)
///      - If THRE mode is disabled (IER bit 7 set to zero) this bit indicates that the THR or Tx
///        FIFO is empty. This bit is set whenever data is transferred from the THR or Tx FIFO to
///        the transmitter shift register and no new data has been written to the THR or Tx FIFO.
///        This also causes a THRE Interrupt to occur, if the THRE Interrupt is enabled.
///      - If both THRE and FIFOs are enabled, both (IER bit 7 set to one and FCR bit 0 set to one
///        respectively), the functionality will indicate the transmitter FIFO is full, and no
///        longer controls THRE interrupts, which are then controlled by the FCR bits 5:4
///        thresholdsetting.
///      - read only
///  - transmit empty (temt)
///      - If in FIFO mode and FIFO's enabled (FCR bit 0 set to one), this bit is set whenever the
///        Transmitter Shift Register and the FIFO are both empty.
///      - If FIFO's are disabled, this bit is set whenever the Transmitter Holding Register and the
///        Transmitter Shift Register are both empty.
///      - read only
fn generate_lsr(hal: &mut UartHalLayer) -> u32 {
    // NOTE, we only handle FIFO mode.
    let dr = hal.fifo.enabled && !hal.fifo.rx_is_empty();

    unsafe {
        hal.registers.lsr().sys_modify(|_r, w| w.dr().bit(dr));
    }

    hal.registers.lsr().read().bits()
}

/// msr:
///  - dcd (bit 7)
///      - Data Carrier Detect (dcd) input `uart_dcd_n` indicates that the carrier has been
///        detected by the modem or data set.
///  - ri (bit 6)
///      - Ring Indicator (ri) input `uart_ri_n` indicates that a telephone ringing signal has
///        been received by the modem or data set.
///      - We ignore this one for now.
///  - dsr (bit 5)
///      - Data Set Ready (dsr) input `uart_dsr_n` indicates that the modem or data set is ready
///        to establish communications with the uart.
///  - cts (bit 4)
///      - Clear to Send (cts) input `uart_cts_n` indicates that the modem or data set is ready to
///        exchange data with the uart.
///  - ddcd (bit 3)
///      - Indicates that the modem control line `uart_dcd_n` has changed since the last time the MSR was
///        read.
///      - Reading the MSR clears the DDCD bit.
///  - teri (bit 2)
///      - Indicates that a change on the input `uart_ri_n` has occurred since the last time the MSR
///        was read.
///      - Reading the MSR clears the TERI bit.
///      - We ignore this one for now.
///  - ddsr (bit 1)
///      - Indicates that the modem control line `uart_dsr_n` has changed since the last time the MSR
///        was read.
///      - Reading the MSR clears the DDSR bit.
///  - dcts (bit 0)
///      - Indicates that the modem control line `uart_cts_n` has changed since the last time the
///        MSR was read.
///      - Reading the MSR clears the DCTS bit.
fn generate_msr(hal: &mut UartHalLayer, client_connected: bool) -> u32 {
    // Start with the register's reset value.
    let msr = hal.registers.msr().read();

    // These are only set if there was a difference from the last time the register was read.
    let ddcd = msr.dcd().bit_is_set() ^ client_connected;
    let ddsr = msr.dsr().bit_is_set() ^ client_connected;
    let dcts = msr.cts().bit_is_set() ^ client_connected;

    unsafe {
        hal.registers.msr().sys_modify(|_r, w| {
            w.dcd()
                .bit(client_connected)
                .dsr()
                .bit(client_connected)
                .cts()
                .bit(client_connected)
                .ddcd()
                .bit(ddcd)
                .ddsr()
                .bit(ddsr)
                .dcts()
                .bit(dcts)
        });
    }
    hal.registers.msr().read().bits()
}

/// usr:
///  - rff: This Bit is used to indicate that the receive FIFO is completely full.
///  - rfne: This Bit is used to indicate that the receive FIFO contains one or more entries.
///  - tfe: This is used to indicate that the transmit FIFO is completely empty.
///  - tfnf: This Bit is used to indicate that the transmit FIFO in not full.
fn generate_usr(hal: &mut UartHalLayer) -> u32 {
    // Start with the register's reset value.
    unsafe {
        hal.registers.usr().sys_reset();
    }

    let rff = hal.fifo.rx_is_full();
    let rfne = !hal.fifo.rx_is_empty();

    unsafe {
        hal.registers
            .usr()
            .sys_modify(|_r, w| w.rff().bit(rff).rfne().bit(rfne));
    }
    hal.registers.usr().read().bits()
}

const UART_THR_DLL_OFFSET: u64 = uart0::RbrThrDll::offset();
const UART_DLH_OFFSET: u64 = uart0::IerDlh::offset();
const UART_IIR_OFFSET: u64 = uart0::Iir::offset();
const UART_LCR_OFFSET: u64 = uart0::Lcr::offset();
const UART_MCR_OFFSET: u64 = uart0::Mcr::offset();
const UART_LSR_OFFSET: u64 = uart0::Lsr::offset();
const UART_MSR_OFFSET: u64 = uart0::Msr::offset();
const UART_SRBR_OFFSET: u64 = uart0::Srbr::offset();
const UART_STHR_OFFSET: u64 = uart0::Sthr::offset();
const UART_USR_OFFSET: u64 = uart0::Usr::offset();
const UART_TFL_OFFSET: u64 = uart0::Tfl::offset();
const UART_RFL_OFFSET: u64 = uart0::Rfl::offset();
const UART_SRR_OFFSET: u64 = uart0::Srr::offset();

pub struct UartMMRHook {
    base_addr: u64,
    id: String,
}

impl UartMMRHook {
    pub fn new(base: u64, id: String) -> Self {
        Self {
            base_addr: base,
            id,
        }
    }

    /// For the moment this is used for debugging to see if we miss any mmio
    /// registers that the guest is writing to, at the moment we're ignoring
    /// a couple registers so this is still here
    fn log_unhandled_read(&self, address: u64, size: u32) {
        debug!(
            "(R) UART{} read {} bytes from {:#08X}",
            self.id, size, address
        );
    }

    /// see previous comment
    fn log_unhandled_write(&self, address: u64, size: u32) {
        debug!(
            "(W) UART{} wrote {} bytes from {:#08X}",
            self.id, size, address
        );
    }
}

impl MemoryReadHook for UartMMRHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        // this should never underflow, but if it does we want it to panic because something is wrong
        let offset = address - self.base_addr;

        match offset {
            UART_THR_DLL_OFFSET => {
                uart_port_rbr_thr_dll_r_hook(&self.id, proc, address, size, data)
            }
            UART_DLH_OFFSET => uart_port_ier_dlh_r_hook(&self.id, proc, address, size, data),
            UART_IIR_OFFSET => uart_port_iir_r_hook(&self.id, proc, address, size, data),
            UART_LSR_OFFSET => uart_port_lsr_r_hook(&self.id, proc, address, size, data),
            UART_MSR_OFFSET => uart_port_msr_r_hook(&self.id, proc, address, size, data),
            UART_SRBR_OFFSET => uart_port_srbr_r_hook(&self.id, proc, address, size, data),
            UART_USR_OFFSET => uart_port_usr_r_hook(&self.id, proc, address, size, data),
            UART_TFL_OFFSET => uart_port_tfl_r_hook(&self.id, proc, address, size, data),
            UART_RFL_OFFSET => uart_port_rfl_r_hook(&self.id, proc, address, size, data),
            _ => self.log_unhandled_read(address, size),
        }

        Ok(())
    }
}

impl MemoryWriteHook for UartMMRHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        // this should never underflow, but if it does we want it to panic because something is wrong
        let offset = address - self.base_addr;

        match offset {
            UART_THR_DLL_OFFSET => {
                uart_port_rbr_thr_dll_w_hook(&self.id, proc, address, size, data)
            }
            UART_DLH_OFFSET => uart_port_ier_dlh_w_hook(&self.id, proc, address, size, data),
            UART_IIR_OFFSET => uart_port_iir_w_hook(&self.id, proc, address, size, data),
            UART_LCR_OFFSET => uart_port_lcr_w_hook(&self.id, proc, address, size, data),
            UART_MCR_OFFSET => uart_port_mcr_w_hook(&self.id, proc, address, size, data),
            UART_STHR_OFFSET => uart_port_sthr_w_hook(&self.id, proc, address, size, data),
            UART_SRR_OFFSET => uart_port_srr_w_hook(&self.id, proc, address, size, data),
            _ => self.log_unhandled_write(address, size),
        }

        Ok(())
    }
}
