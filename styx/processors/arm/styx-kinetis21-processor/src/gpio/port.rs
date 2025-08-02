// SPDX-License-Identifier: BSD-2-Clause
//! The [`GPIOPort`] is our abstraction of an individual GPIO port in a target device. This is
//! where the logic for implementing a GPIO port lives. This structure owns and manages the
//! [`Register`] and [`Pin`] structures.
use super::{
    constants::{GPIOPortMap, GpioRegister, GPIO_PORT_NPINS, GPIO_REGISTERS},
    pin::Pin,
};
use std::{collections::BTreeMap, ops::RangeInclusive};
use styx_core::prelude::*;
use tracing::{trace, warn};

/// Helper function for tracing GPIO register writes.
fn trace_reg_write(gpio_name: &str, reg_name: &str, regval: u32) {
    trace!("GPIO_{} write to {} = {:#08x}", gpio_name, reg_name, regval);
}

/// Helper function for tracing GPIO register reads.
fn trace_reg_read(gpio_name: &str, reg: GpioRegister) {
    trace!("GPIO_{} read from {}", gpio_name, reg);
}

/// Contains metadata for a register within a GPIO port.
#[derive(Clone)]
struct Register {
    /// Memory-mapped address for the register.
    address: u64,
    /// Reset value for the register.
    reset_bytes: [u8; 4],
}

pub struct GPIOPort {
    name: &'static str,
    pub addr_range: RangeInclusive<u64>,
    regs: BTreeMap<GpioRegister, Register>,
    pins: Vec<Pin>,
}

impl GPIOPort {
    /// Static initialization of a GPIO port: allocate registers and pins.
    pub fn new(name: &'static str, port_map: &GPIOPortMap) -> Self {
        trace!("Initialize GPIO{}", name);
        let addr_range: RangeInclusive<u64> = port_map.base..=port_map.end;
        let pins: Vec<Pin> = (0..GPIO_PORT_NPINS).map(Pin::new).collect();

        let mut regs: BTreeMap<GpioRegister, Register> = BTreeMap::new();
        for (reg_name, def) in GPIO_REGISTERS {
            debug_assert_eq!(def.size / 8, 4, "We assume 4-byte registers here.");
            regs.insert(
                reg_name,
                Register {
                    address: port_map.base + def.offset,
                    reset_bytes: def.reset_value.to_be_bytes(),
                },
            );
        }

        Self {
            name,
            addr_range,
            regs,
            pins,
        }
    }

    /// Set initial register state.
    pub fn reset_state(&self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // Initialize registers to `reset` state.
        self.regs.clone().into_iter().for_each(|(_, r)| {
            mmu.write_data(r.address, &r.reset_bytes).unwrap();
        });
        Ok(())
    }

    fn get_reg(&self, reg_name: GpioRegister) -> &Register {
        match self.regs.get(&reg_name) {
            Some(register) => register,
            None => unreachable!("{reg_name} missing from constants. This should never happen!"),
        }
    }

    /// Port Data Output Register (GPIOx_PDOR): Configures the logic levels that are driven on
    /// each general-purpose output pin. Provided the specified pin is configured for general
    /// purpose _output_:
    ///   - A 0 value bit causes the corresponding pin to be driven to a logic 0.
    ///   - A 1 value bit causes the corresponding pin to be driven to a logic 1.
    fn pdor_written(&mut self, regval: u32) {
        trace_reg_write(self.name, "PDOR", regval);

        for i in 0..u32::BITS {
            let pin = &mut self.pins[i as usize];
            if pin.is_output() {
                if (regval >> i & 1) == 1 {
                    pin.set_bit();
                } else {
                    pin.clear_bit();
                }
            }
        }
    }

    /// Port Set Output Register (GPIOx_PSOR): Causes the corresponding bits in the PDOR to be
    /// set.
    ///   - A 0 value bit causes no change.
    ///   - A 1 value bit causes the corresponding PDOR bit to be set to a logic 1.
    fn psor_written(&mut self, regval: u32) {
        // When read, these return 0, so we don't need to store this value in memory.
        trace_reg_write(self.name, "PSOR", regval);

        // We only care about bits that are set to 1, since a 0 is no change.
        for i in 0..u32::BITS {
            let pin = &mut self.pins[i as usize];
            if ((regval >> i & 1) == 1) && pin.is_output() {
                pin.set_bit();
            }
        }
    }

    /// Port Clear Output Register (GPIOx_PCOR): Causes the corresponding bits in the PDOR to
    /// be cleared.
    ///   - A 0 value bit causes no change.
    ///   - A 1 value bit causes the corresponding PDOR bit to be cleared to a logic 0.
    fn pcor_written(&mut self, regval: u32) {
        // When read, these return 0, so we don't need to store this value in memory.
        trace_reg_write(self.name, "PCOR", regval);

        // We only care about bits that are set to 1, since a 0 is no change.
        for i in 0..u32::BITS {
            let pin = &mut self.pins[i as usize];
            if ((regval >> i & 1) == 1) && pin.is_output() {
                pin.clear_bit();
            }
        }
    }

    /// Port Toggle Output Register (GPIOx_PTOR): Causes the corresponding bits in the PDOR to
    /// be set to the inverse of their existing logic state.
    ///   - A 0 value bit causes no change.
    ///   - A 1 value bit causes the corresponding PDOR bit's value to be toggled.
    fn ptor_written(&mut self, regval: u32) {
        // When read, these return 0, so we don't need to store this value in memory.
        trace_reg_write(self.name, "PTOR", regval);

        // We only care about bits that are set to 1, since a 0 is no change.
        for i in 0..u32::BITS {
            let pin = &mut self.pins[i as usize];
            if ((regval >> i & 1) == 1) && pin.is_output() {
                pin.toggle_bit();
            }
        }
    }

    /// Port Data Direction Register (GPIOx_PDDR): Configures individual port pins for input or
    /// output.
    ///   - A 0 value bit causes the corresponding pin to be configured as general-purpose
    ///     input.
    ///   - A 1 value bit causes the corresponding pin to be configured as general-purpose
    ///     output.
    fn pddr_written(&mut self, regval: u32) {
        trace_reg_write(self.name, "PDDR", regval);

        for i in 0..u32::BITS {
            let pin = &mut self.pins[i as usize];
            if (regval >> i & 1) == 1 {
                pin.set_to_output();
            } else {
                pin.set_to_input();
            }
        }
    }

    /// Port Data Output Register (GPIOx_PDOR): Reflects the logic level we are driving at the pin.
    fn pdor_read(&self, mmu: &mut Mmu) {
        trace_reg_read(self.name, GpioRegister::PDOR);
        let mut pdor_val: u32 = 0;
        for i in 0..u32::BITS {
            let pin = &self.pins[i as usize];
            // NOTE: In the future, the mode may also contain information reflecting whether the
            // pin is even configured or exists on the current device... BUT the reference does not
            // specify what the read value would be in this situation. We are just assuming zero.
            if pin.is_output() && pin.is_set() {
                pdor_val += pin.mask;
            }
        }
        let pdor_bytes: [u8; 4] = pdor_val.to_le_bytes();
        mmu.write_data(self.get_reg(GpioRegister::PDOR).address, &pdor_bytes)
            .unwrap();
    }

    /// Port Data Input Register (GPIOx_PDIR): Reflects the logic level at the pin. A bit will
    /// also read as 0 if:
    ///   - The pin is unimplemented on a given device.
    ///   - The pin is not configured for a digital function.
    ///
    /// If the Port Control and Interrupt module is disabled, the corresponding pin in PDIR
    /// does not update.
    fn pdir_read(&self, mmu: &mut Mmu) {
        trace_reg_read(self.name, GpioRegister::PDIR);
        let mut pdir_val: u32 = 0;

        for i in 0..u32::BITS {
            let pin = &self.pins[i as usize];
            // NOTE: In the future, the mode may also contain information reflecting whether the
            // pin is even configured or exists on the current device... BUT the reference does not
            // specify what the read value would be in this situation. We are just assuming zero.
            if pin.is_input() && pin.is_set() {
                pdir_val += pin.mask;
            }
        }
        let pdir_bytes: [u8; 4] = pdir_val.to_le_bytes();
        mmu.write_data(self.get_reg(GpioRegister::PDIR).address, &pdir_bytes)
            .unwrap();
    }

    /// Called by the GPIO's memory write hook.
    /// Identify the appropriate register based on the address.
    pub fn mem_write_callback(
        &mut self,
        address: u64, // Accessed Address
        size: u32,    // Number of bytes accessed
        value: &[u8], // Write Value
    ) {
        // convert the byte array into a u32
        let value = u32::from_le_bytes(
            value[0..4]
                .try_into()
                .unwrap_or_else(|_| panic!("unable to convert {value:?} into u32")),
        );

        if address == self.get_reg(GpioRegister::PDOR).address {
            self.pdor_written(value);
        } else if address == self.get_reg(GpioRegister::PSOR).address {
            self.psor_written(value);
        } else if address == self.get_reg(GpioRegister::PCOR).address {
            self.pcor_written(value);
        } else if address == self.get_reg(GpioRegister::PTOR).address {
            self.ptor_written(value);
        } else if address == self.get_reg(GpioRegister::PDDR).address {
            self.pddr_written(value);
        } else {
            // FIXME: this should be a bus error.
            warn!(
                "UNHANDLED: MEM_WRITE: REG_{}_{} {:#x} size: {}, value: {:?}",
                self.name,
                &format!("{:4.4}", "@@@@"),
                address,
                size,
                value
            );
        }
    }

    /// Called by the GPIO's memory read hook.
    /// Identify the appropriate register based on the address.
    pub fn mem_read_callback(
        &self,
        mmu: &mut Mmu, // Emulator
        address: u64,  // Accessed Address
        size: u32,     // Number of bytes accessed
        value: &[u8],  // Write Value
    ) {
        // convert the byte array into a u32
        let value = u32::from_le_bytes(
            value[0..4]
                .try_into()
                .unwrap_or_else(|_| panic!("unable to convert {value:?} into u32")),
        );

        if address == self.get_reg(GpioRegister::PDIR).address {
            // We need to construct the value from the individual bits.
            self.pdir_read(mmu);
        } else if address == self.get_reg(GpioRegister::PDOR).address {
            // PDOR is readable. We need to construct the value from the individual bits. We need
            // to do this because, besides writes to PDOR, output values can also be changed by
            // writes to PTOR, PCOR or PSOR.
            self.pdor_read(mmu);
        } else if address == self.get_reg(GpioRegister::PDDR).address {
            // PDDR is readable.
            trace_reg_read(self.name, GpioRegister::PDDR);
        } else if self.addr_range.contains(&address) {
            // All other registers (PSOR, PCOR and PTOR) return zero when read.
            trace!(
                "GPIO_{} read from PSOR, PCOR or PTOR register ({:#08x}) - always read as zero.",
                self.name,
                address
            );
        } else {
            // FIXME: this should be a bus error.
            warn!(
                "UNHANDLED: MEM_WRITE: REG_{}_{} {:#x} size: {}, value: {:?}",
                self.name,
                &format!("{:4.4}", "@@@@"),
                address,
                size,
                value
            );
        }
    }
}
