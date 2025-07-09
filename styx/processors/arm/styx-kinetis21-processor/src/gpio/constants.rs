// SPDX-License-Identifier: BSD-2-Clause
//! Provides GPIO Constants for the NXP Kinetis K21 family of processors.
use super::super::mk21f12_sys;

//////////////////// GPIO Port Constants ////////////////////
/// Number of pins per GPIO port.
pub const GPIO_PORT_NPINS: u32 = 32;

/// There are GPIO_NUM_REGS 32-bit GPIO registers.
const GPIO_NUM_REGS: u32 = 5;
/// The number of bytes in the memory region mapped for a GPIO port's registers.
const REG_BLOCK_SIZE: u64 = GPIO_NUM_REGS as u64 * 4;

/// Number of GPIO ports (A..E).
const GPIO_NUM_PORTS: usize = 5;

/// Describe a GPIO port's memory map.
#[derive(Eq, PartialEq, Debug)]
pub struct GPIOPortMap {
    pub base: u64,
    pub end: u64,
}

/// The start of the GPIO memory region for the device.
pub const GPIO_BASE: u64 = mk21f12_sys::GPIOA_BASE as u64;
/// The end of the GPIO memory region for the device (includes all ports).
pub const GPIO_END: u64 = 0x400F_FFFF;

/// Describes the GPIO ports and their memory regions.
pub const GPIO_PORTS: [(&str, GPIOPortMap); GPIO_NUM_PORTS] = [
    (
        "A",
        GPIOPortMap {
            base: mk21f12_sys::GPIOA_BASE as u64,
            end: mk21f12_sys::GPIOA_BASE as u64 + REG_BLOCK_SIZE,
        },
    ),
    (
        "B",
        GPIOPortMap {
            base: mk21f12_sys::GPIOB_BASE as u64,
            end: mk21f12_sys::GPIOB_BASE as u64 + REG_BLOCK_SIZE,
        },
    ),
    (
        "C",
        GPIOPortMap {
            base: mk21f12_sys::GPIOC_BASE as u64,
            end: mk21f12_sys::GPIOC_BASE as u64 + REG_BLOCK_SIZE,
        },
    ),
    (
        "D",
        GPIOPortMap {
            base: mk21f12_sys::GPIOD_BASE as u64,
            end: mk21f12_sys::GPIOD_BASE as u64 + REG_BLOCK_SIZE,
        },
    ),
    (
        "E",
        GPIOPortMap {
            base: mk21f12_sys::GPIOE_BASE as u64,
            end: mk21f12_sys::GPIOE_BASE as u64 + REG_BLOCK_SIZE,
        },
    ),
];

//////////////////// GPIO Register Constants ////////////////////
/// Describe a GPIO register's constants.
pub struct GPIORegisterDef {
    /// Offset address within the port mapping.
    pub offset: u64,
    /// Number of bits in the register.
    pub size: u32,
    /// Reset value for the register.
    pub reset_value: u32,
}

/// The registers in a GPIO port on the target device.
///
/// Port Data Output Register (GPIOx_PDOR): Configures the logic levels that are driven on each
/// general-purpose output pin. Provided the specified pin is configured for general purpose
/// _output_:
///   - A 0 value bit causes the corresponding pin to be driven to a logic 0.
///   - A 1 value bit causes the corresponding pin to be driven to a logic 1.
///
/// Port Set Output Register (GPIOx_PSOR): Causes the corresponding bits in the PDOR to be set.
///   - A 0 value bit causes no change.
///   - A 1 value bit causes the corresponding PDOR bit to be set to a logic 1.
///
/// Port Clear Output Register (GPIOx_PCOR): Causes the corresponding bits in the PDOR to be
/// cleared.
///   - A 0 value bit causes no change.
///   - A 1 value bit causes the corresponding PDOR bit to be cleared to a logic 0.
///
/// Port Toggle Output Register (GPIOx_PTOR): Causes the corresponding bits in the PDOR to be set
/// to the inverse of their existing logic state.
///   - A 0 value bit causes no change.
///   - A 1 value bit causes the corresponding PDOR bit to be toggled.
///
/// Port Data Input Register (GPIOx_PDIR): Reflects the logic level at the pin. A bit will also
/// read as 0 if:
///   - The pin is unimplemented on a given device.
///   - The pin is not configured for a digital function.
///
/// If the Port Control and Interrupt module is disabled, the corresponding pin in PDIR does not
/// update.
///
/// Port Data Direction Register (GPIOx_PDDR): Configures individual port pins for input or output.
///   - A 0 value bit causes the corresponding pin to be configured as general-purpose input.
///   - A 1 value bit causes the corresponding pin to be configured as general-purpose output.
#[allow(clippy::upper_case_acronyms)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Debug)]
pub enum GpioRegister {
    PDOR,
    PSOR,
    PCOR,
    PTOR,
    PDIR,
    PDDR,
}

impl std::fmt::Display for GpioRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GpioRegister::PDOR => write!(f, "PDOR"),
            GpioRegister::PSOR => write!(f, "PSOR"),
            GpioRegister::PCOR => write!(f, "PCOR"),
            GpioRegister::PTOR => write!(f, "PTOR"),
            GpioRegister::PDIR => write!(f, "PDIR"),
            GpioRegister::PDDR => write!(f, "PDDR"),
        }
    }
}

/// Constants for GPIO registers.
pub const GPIO_REGISTERS: [(GpioRegister, GPIORegisterDef); 6] = [
    (
        GpioRegister::PDOR,
        GPIORegisterDef {
            offset: 0x00,
            size: 32,
            reset_value: 0x00000000,
        },
    ),
    (
        GpioRegister::PSOR,
        GPIORegisterDef {
            offset: 0x04,
            size: 32,
            reset_value: 0x00000000,
        },
    ),
    (
        GpioRegister::PCOR,
        GPIORegisterDef {
            offset: 0x08,
            size: 32,
            reset_value: 0x00000000,
        },
    ),
    (
        GpioRegister::PTOR,
        GPIORegisterDef {
            offset: 0x0C,
            size: 32,
            reset_value: 0x00000000,
        },
    ),
    (
        GpioRegister::PDIR,
        GPIORegisterDef {
            offset: 0x10,
            size: 32,
            reset_value: 0x00000000,
        },
    ),
    (
        GpioRegister::PDDR,
        GPIORegisterDef {
            offset: 0x14,
            size: 32,
            reset_value: 0x00000000,
        },
    ),
];
