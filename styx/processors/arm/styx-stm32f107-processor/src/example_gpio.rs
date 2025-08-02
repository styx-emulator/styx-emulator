// SPDX-License-Identifier: BSD-2-Clause
//! Example GPIO [Gpio] peripheral implementation.
//!
//! Provides a rudimentary example of an approach for implementing the peripheral,
//! along with simple abstractions for [Port], [Reg], and [Pin]
//!
//! ## Notes
//! GPIO elements: ports, registers, pins, and memory callbacks
//! for STM32F101xx, STM32F102xx, STM32F103xx, STM32F105xx and
//! STM32F107xx advanced Arm®-based 32-bit MCUs.
//! # Resources:
//! - [Technical Reference Manual](https://www.st.com/resource/en/reference_manual/rm0008-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-armbased-32bit-mcus-stmicroelectronics.pdf)
use tracing::{debug, info};

use styx_core::prelude::*;

pub mod gpio_constants {
    /// Address constants for GPIO ports.
    /// ```rust
    /// use std::error::Error;
    /// use styx_core::cpu;
    /// # use styx_stm32f107_processor::example_gpio::gpio_constants::portdefs::*;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let start_addr = GPIOPORTA_BASE;
    /// let end_addr = GPIOPORTA_END;
    /// println!(
    ///     "GPIO Port A: start: {:#x}, end: {:#x}",
    ///                    start_addr, end_addr
    /// );
    /// #  Ok(())
    /// # }
    pub mod portdefs {

        // GPIO Port addresses. `*_BASE` is the start
        // address, `*_END` end address for ports
        // A,B, ..., G
        /// A GPIO port
        #[derive(Eq, PartialEq, Debug)]
        pub struct GPIOPort {
            pub name: &'static str,
            pub base: u32,
            pub end: u32,
        }

        pub const GPIOPORTA_BASE: u32 = 0x40010800;
        pub const GPIOPORTA_END: u32 = 0x40010BFF;
        pub const GPIOPORTB_BASE: u32 = 0x40010C00;
        pub const GPIOPORTB_END: u32 = 0x40010FFF;
        pub const GPIOPORTC_BASE: u32 = 0x40011000;
        pub const GPIOPORTC_END: u32 = 0x400113FF;
        pub const GPIOPORTD_BASE: u32 = 0x40011400;
        pub const GPIOPORTD_END: u32 = 0x400117FF;
        pub const GPIOPORTE_BASE: u32 = 0x40011800;
        pub const GPIOPORTE_END: u32 = 0x40011BFF;
        pub const GPIOPORTF_BASE: u32 = 0x40011C00;
        pub const GPIOPORTF_END: u32 = 0x40011FFF;
        pub const GPIOPORTG_BASE: u32 = 0x40012000;
        pub const GPIOPORTG_END: u32 = 0x400123FF;

        pub const GPIO_PORT_A: GPIOPort = GPIOPort {
            name: "A",
            base: GPIOPORTA_BASE,
            end: GPIOPORTA_END,
        };
        pub const GPIO_PORT_B: GPIOPort = GPIOPort {
            name: "B",
            base: GPIOPORTB_BASE,
            end: GPIOPORTB_END,
        };
        pub const GPIO_PORT_C: GPIOPort = GPIOPort {
            name: "C",
            base: GPIOPORTC_BASE,
            end: GPIOPORTC_END,
        };
        pub const GPIO_PORT_D: GPIOPort = GPIOPort {
            name: "D",
            base: GPIOPORTD_BASE,
            end: GPIOPORTD_END,
        };
        pub const GPIO_PORT_E: GPIOPort = GPIOPort {
            name: "E",
            base: GPIOPORTE_BASE,
            end: GPIOPORTE_END,
        };
        pub const GPIO_PORT_F: GPIOPort = GPIOPort {
            name: "F",
            base: GPIOPORTF_BASE,
            end: GPIOPORTF_END,
        };
        pub const GPIO_PORT_G: GPIOPort = GPIOPort {
            name: "G",
            base: GPIOPORTG_BASE,
            end: GPIOPORTG_END,
        };
        /// The total number of ports
        pub const NUMPORTS: usize = 7;
        /// A constant array of GPIOPort
        pub const GPIO_PORTS: [&GPIOPort; NUMPORTS] = [
            &GPIO_PORT_A,
            &GPIO_PORT_B,
            &GPIO_PORT_C,
            &GPIO_PORT_D,
            &GPIO_PORT_E,
            &GPIO_PORT_F,
            &GPIO_PORT_G,
        ];

        #[cfg(test)]
        /// the address range for ports A to G
        pub const ADDRESS_RANGE: std::ops::RangeInclusive<u32> = GPIOPORTA_BASE..=GPIOPORTG_END;

        #[cfg(test)]
        pub fn is_valid_addr_u32(addr: u32) -> bool {
            ADDRESS_RANGE.contains(&addr)
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            #[test]
            fn test_ranges() {
                // make sure all ports are in ascending memory order and make sure
                // all addresses are in range
                let mut last_addr: u32 = 0x0;
                for port in GPIO_PORTS {
                    assert!(is_valid_addr_u32(port.base));
                    assert!(is_valid_addr_u32(port.end));
                    assert!(port.base < port.end);
                    assert!(port.base > last_addr);
                    last_addr = port.end;
                }

                // also make sure is_valid_addr_u32 recognizes an invalid addr
                assert!(!is_valid_addr_u32(GPIO_PORT_A.base - 1));
                assert!(!is_valid_addr_u32(GPIO_PORT_G.end + 1));
            }
        }
    }

    pub mod regdefs {
        pub struct GPIORegister {
            pub name: &'static str,
            pub offset: u32, // offset addr from GPIOPort
            pub size: u32,
            pub reset: u32,
        }

        pub const CRL: GPIORegister = GPIORegister {
            name: "CRL",
            size: 32,
            offset: 0x00,
            reset: 0x44444444,
        };

        pub const CRH: GPIORegister = GPIORegister {
            name: "CRH",
            size: 32,
            offset: 0x04,
            reset: 0x44444444,
        };

        pub const IDR: GPIORegister = GPIORegister {
            name: "IDR",
            size: 32,
            offset: 0x08,
            reset: 0x00000000,
        };

        pub const ODR: GPIORegister = GPIORegister {
            name: "ODR",
            size: 32,
            offset: 0x0C,
            reset: 0x00000000,
        };
        pub const BSRR: GPIORegister = GPIORegister {
            name: "BSRR",
            size: 32,
            offset: 0x10,
            reset: 0x00000000,
        };
        pub const BRR: GPIORegister = GPIORegister {
            name: "BRR",
            size: 32,
            offset: 0x14,
            reset: 0x00000000,
        };

        pub const LCKR: GPIORegister = GPIORegister {
            name: "LCKR",
            size: 32,
            offset: 0x18,
            reset: 0x00000000,
        };
        pub const NREGISTERS: usize = 7;

        /// Const list of GPIO registers. Each GPIOPort has
        /// each register.
        pub const GPIO_REGISTERS: [&GPIORegister; NREGISTERS] =
            [&CRL, &CRH, &IDR, &ODR, &BSRR, &BRR, &LCKR];

        /// Indices for GPIO_REGISTERS
        pub const REG_IDX_CRL: usize = 1;
        pub const REG_IDX_CRH: usize = 2;
        pub const REG_IDX_IDR: usize = 3;
        pub const REG_IDX_ODR: usize = 4;
        pub const REG_IDX_BSRR: usize = 5;
        pub const REG_IDX_BRR: usize = 6;
        pub const REG_IDX_LCKR: usize = 7;
    }
    pub mod pindefs {
        use std::ops::RangeInclusive;

        /// The total number of pins per port
        pub const NPINS: usize = 16;

        #[allow(dead_code)]
        /// bit masks for pins 0..15
        pub const PIN_SETS: [u16; NPINS] = [
            0x0001, 0x0002, 0x0004, 0x0008, // 0..3
            0x0010, 0x0020, 0x0040, 0x0080, // 4..7
            0x0100, 0x0200, 0x0400, 0x0800, // 8..11
            0x1000, 0x2000, 0x4000, 0x8000, // 12..16
        ];
        pub const LOW_PINS: core::ops::RangeInclusive<usize> = 0..=7; // half open (s,e]
        pub const HIGH_PINS: core::ops::RangeInclusive<usize> = 8..=NPINS; // half open (s,e]

        /// An array of size NPINS [0..15] of inclusive range tuples that are the bits
        /// used to interpret port Config (registers CRL, CRH) values. Each pin
        /// has a tuple (configuration bits, mode(speed) bits).
        /// ```rust
        /// use styx_stm32f107_processor::example_gpio::gpio_constants::pindefs::CONFIGS;
        /// // Receive register write for REGCRL (regval: u32)
        /// let pno = 4; // pin 4
        /// let speed_range = *CONFIGS[pno].0.start()..=*CONFIGS[pno].0.end();
        /// let cfg_range = *CONFIGS[pno].1.start()..=*CONFIGS[pno].1.end();
        /// assert_eq!(16..=17, speed_range); // 2 bits for speed
        /// assert_eq!(18..=19, cfg_range); // 2 bits for configuration
        /// // Get et the values for speed and cfg from regval
        /// // ...
        pub const CONFIGS: [(RangeInclusive<usize>, RangeInclusive<usize>); NPINS] = [
            // Low side (CRL)
            (0..=1, 2..=3),     // Pin0 (mode, cnf)
            (4..=5, 6..=7),     // Pin1 (mode, cnf)
            (8..=9, 10..=11),   // Pin2 (mode, cnf)
            (2..=13, 14..=15),  // Pin3 (mode, cnf)
            (16..=17, 18..=19), // Pin4 (mode, cnf)
            (20..=21, 22..=23), // Pin5 (mode, cnf)
            (24..=25, 26..=27), // Pin6 (mode, cnf)
            (28..=29, 30..=31), // Pin7 (mode, cnf)
            // High side (CRH)
            (0..=1, 2..=3),     // Pin8 (mode, cnf)
            (4..=5, 6..=7),     // Pin9 (mode, cnf)
            (8..=9, 10..=11),   // Pin10 (mode, cnf)
            (2..=13, 14..=15),  // Pin11 (mode, cnf)
            (16..=17, 18..=19), // Pin12 (mode, cnf)
            (20..=21, 22..=23), // Pin13 (mode, cnf)
            (24..=25, 26..=27), // Pin14 (mode, cnf)
            (28..=29, 30..=31), // Pin15 (mode, cnf)
        ];
    }
} // End gpio_constants

pub mod pin {
    use super::gpio_constants::pindefs;
    use styx_core::util::{bit_range, high_low_u32};

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Pin {
        // pin number
        pub pno: usize,
        // pin speed
        pub speed: Speed,
        // pin mode
        pub mode: Mode,
        // is the pin set
        pub is_set: bool,
    }

    #[allow(dead_code)]
    impl Pin {
        /// Construct a new `struct Pin` with pno as the pin number (pno).
        pub fn new(pno: usize) -> Self {
            Self {
                pno,
                ..Default::default()
            }
        }

        /// is the pin in default (reset) state
        pub fn is_default(&self) -> bool {
            self.speed == Speed::MegHz10 && self.mode == Mode::InFloating && !self.is_set
        }

        /// is the pin in some input mode
        pub fn is_input(&self) -> bool {
            self.mode == Mode::InFloating
                || self.mode == Mode::InputPullDown
                || self.mode == Mode::InputPullUp
        }

        /// Static method to return the raw (mode,speed) values for the
        /// pin with pin numbberReturns raw config values for the pno as a tuple (speed, mode)
        pub fn static_get_pin_raw_config(pno: usize, regval: u32) -> (u8, u8) {
            (
                bit_range(
                    regval,
                    *pindefs::CONFIGS[pno].0.start()..=*pindefs::CONFIGS[pno].0.end(),
                ) as u8,
                bit_range(
                    regval,
                    *pindefs::CONFIGS[pno].1.start()..=*pindefs::CONFIGS[pno].1.end(),
                ) as u8,
            )
        }

        /// is the pin in some output mode
        pub fn is_output(&self) -> bool {
            self.mode == Mode::OutOD || self.mode == Mode::OutPP
        }

        /// is the pin in some alternate mode
        pub fn is_alternate(&self) -> bool {
            self.mode == Mode::AltFuncOpenDrain || self.mode == Mode::AltFuncPushPull
        }

        /// is the pin in analog mode
        pub fn is_analog(&self) -> bool {
            self.mode == Mode::Analog
        }

        /// Based on the raw value `val`, get the raw values of the configuration
        /// (mode,speed) for this pin using the static method
        fn get_config_bits(&self, val: u32) -> (u8, u8) {
            Self::static_get_pin_raw_config(self.pno, val)
        }

        /// Is the pin configured from CRL?
        pub fn is_cfg_low(&self) -> bool {
            pindefs::LOW_PINS.contains(&self.pno)
        }

        /// Is the pin configured from CRH?
        #[inline(always)]
        pub fn is_cfg_high(&self) -> bool {
            pindefs::HIGH_PINS.contains(&self.pno)
        }

        /// Set the pin configuration from the registry value `regval` as per
        /// the registry value `regval`
        ///    if from_low is true: treat the regval as a CRL value
        ///    if from_low is false: treat the regval as a CRH value
        /// Return true if the value actually sets the pin configuration
        pub fn set_config(&mut self, cfgreg_val: u32, from_low: bool) -> bool {
            let from_high = !from_low;
            if self.is_cfg_high() && from_high || self.is_cfg_low() && from_low {
                // Get the bits from the raw value of the register for THIS pin
                let (spd, cfg) = self.get_config_bits(cfgreg_val);
                if spd > 0 || cfg > 0 {
                    self.speed = Speed::from(spd);
                    self.mode = Mode::from_u8(self.speed, cfg);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        }

        /// Set/reset the pin (ODRx) based on regval. Return true if a change was
        /// made, false otherwise.
        ///
        /// Bits 31:16 BRy: Port x Reset bit y (y= 0 .. 15)
        ///
        ///   0: No action on the corresponding ODRx bit
        ///   1: Reset the corresponding ODRx bit
        ///
        /// Bits 15:0 BSy: Port x Set bit y (y= 0 .. 15)
        ///
        ///   0: No action on the corresponding ODRx bit
        ///   1: Set the corresponding ODRx bit
        ///
        ///  Note: If both BSx and BRx are set, BSx has priority.
        #[inline(always)]
        pub fn bsrr(&mut self, regval: u32) -> (bool, bool) {
            let (br, bs) = self.get_br_bs(regval);
            // tracing::warn!("      PinImpl:BSRR::pno{} BR:{br}, BS: {bs}", self.pno);
            if br || bs {
                if bs {
                    self.is_set = true;
                } else if br {
                    self.is_set = false;
                }
            }
            (br, bs)
        }

        /// Get (BR, BS) flags from a BSSR value.
        /// BR is on the high 16, BS on the low 16
        pub fn get_br_bs(&self, regval: u32) -> (bool, bool) {
            let (hbits, lbits) = high_low_u32(regval);
            ((hbits & (1 << self.pno)) > 0, (lbits & (1 << self.pno)) > 0)
        }

        #[inline(always)]
        pub fn brr(&mut self, regval: &u32) -> bool {
            let mut chg: bool = false;
            let (_, lbits) = high_low_u32(*regval);
            let reset = (lbits & (1 << self.pno)) > 0;
            if reset {
                self.is_set = false;
                chg = true;
            }
            chg
        }
    }

    #[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
    pub enum Speed {
        NotSet = 0, // Input mode
        #[default]
        MegHz10 = 0x1,
        MegHz2 = 0x2,
        MegHz50 = 0x3,
    }

    impl From<u8> for Speed {
        fn from(value: u8) -> Speed {
            match value {
                0 => Speed::NotSet,
                1 => Speed::MegHz10,
                2 => Speed::MegHz2,
                3 => Speed::MegHz50,
                _ => {
                    tracing::warn!("Invalid raw speed: {value}");
                    Speed::default()
                }
            }
        }
    }

    impl std::fmt::Display for Speed {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Speed::NotSet => write!(f, "NoSpeed"),
                Speed::MegHz10 => write!(f, "10MHz"),
                Speed::MegHz2 => write!(f, "2MHz"),
                Speed::MegHz50 => write!(f, "50MHz"),
            }
        }
    }

    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Mode {
        /// "Analog"
        Analog = 0x0,
        /// "Input floating "
        #[default]
        InFloating = 0x04,
        /// "Input-pull-down"
        InputPullDown = 0x28,
        /// "Input pull-up"
        InputPullUp = 0x48,
        /// "Output open-drain"
        OutOD = 0x14,
        /// "Output push-pull"
        OutPP = 0x10,
        /// "Alternate function open-drain"
        AltFuncOpenDrain = 0x1C,
        /// "Alternate function push-pull"
        AltFuncPushPull = 0x18,
    }

    impl Mode {
        pub fn from_u8(s: Speed, v: u8) -> Mode {
            if s == Speed::NotSet {
                // Input or Analog
                match v {
                    // Analog
                    0 => Mode::Analog,
                    // Input
                    0x1 => Mode::InFloating,
                    0x2 => Mode::InputPullDown,
                    0x3 => Mode::InputPullUp,
                    _ => Mode::default(),
                }
            } else {
                // Output
                match v {
                    0x0 => Mode::OutPP,
                    0x1 => Mode::OutOD,
                    0x2 => Mode::OutPP,
                    0x3 => Mode::AltFuncOpenDrain,
                    _ => Mode::default(),
                }
            }
        }
    }

    impl std::fmt::Display for Mode {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Mode::Analog => write!(f, "AIN = 0x0"),
                Mode::InFloating => write!(f, "InFloating = 0x04"),
                Mode::InputPullDown => write!(f, "IPD = 0x28"),
                Mode::InputPullUp => write!(f, "IPU = 0x48"),
                Mode::OutOD => write!(f, "OutOD = 0x14"),
                Mode::OutPP => write!(f, "OutPP = 0x10"),
                Mode::AltFuncOpenDrain => write!(f, "AFOD = 0x1C"),
                Mode::AltFuncPushPull => write!(f, "AFPP = 0x18"),
            }
        }
    }

    impl std::fmt::Display for Pin {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "{}:{}:{}:{}",
                self.pno, self.speed, self.mode, self.is_set
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::gpio_constants::pindefs::NPINS;
        use super::*;
        #[test]
        fn test_default_config() {
            for i in 0..NPINS {
                let pin = Pin::new(i);
                assert!(pin.pno == i);
                assert!(pin.is_default());
                if pin.pno <= 7 {
                    assert!(pin.is_cfg_low());
                    assert!(!pin.is_cfg_high());
                } else if pin.pno >= 8 {
                    assert!(pin.is_cfg_high());
                    assert!(!pin.is_cfg_low());
                }
            }
        }
    }
} // end mod pin

pub mod port {
    use super::super::example_gpio::{
        gpio_constants::{
            regdefs::{BRR, BSRR, LCKR},
            *,
        },
        pin::*,
        reg::Reg,
    };
    use styx_core::{
        hooks::StyxHook,
        prelude::*,
        tracebus::{strace, MemWriteEvent, TraceEventType},
    };
    use tracing::{debug, info, warn};

    pub struct Port {
        // pub ptdef: GPIOPort;
        pub name: String,
        pub base: u32,
        pub end: u32,
        pub regs: Vec<Reg>,
        pub pins: Vec<Pin>,
    }

    impl Port {
        pub fn new(from_const: &portdefs::GPIOPort, pins: Vec<Pin>, regs: Vec<Reg>) -> Self {
            Self {
                name: String::from(from_const.name),
                base: from_const.base,
                end: from_const.end,
                pins,
                regs,
            }
        }

        /// Get pin state (a copy of all the pins in a vector)
        pub fn get_state(&self) -> Vec<Pin> {
            let mut pins: Vec<Pin> = Vec::new();
            for i in 0..pindefs::NPINS {
                pins.push(self.pins[i]);
            }
            pins
        }

        /// Register a callback with emulator for each register
        /// associated with this port
        pub fn set_hooks(&self, emu: &mut dyn CpuBackend) {
            info!("port set_hooks: {}", self.name);

            for reg in &[
                regdefs::CRL,
                regdefs::CRH,
                regdefs::IDR,
                regdefs::ODR,
                regdefs::BSRR,
                regdefs::BRR,
                regdefs::LCKR,
            ] {
                let addr = self.base as u64 + reg.offset as u64;
                let s: String = format!(
                    "Set write hook GPIO{}{} at {:#8x}",
                    self.name, reg.name, addr
                );

                emu.add_hook(StyxHook::memory_write(addr..=addr, super::emu_mem_accessed))
                    .unwrap();

                debug!("{s}")
            }
        }

        // Returs a Copy of the pin
        #[allow(dead_code)]
        pub fn get_pin_state(&self, pno: usize) -> Pin {
            self.pins[pno]
        }

        /// CRL written - call when the CRL register is written to. It will set pin
        /// configurations for all pins configured by the CRL register
        pub fn crl_written(&mut self, regval: u32) {
            self.regs[regdefs::REG_IDX_CRL].reg_value = regval;
            for pin in &mut self.pins.iter_mut() {
                if pin.set_config(regval, true) {
                    info!("    => CRL: Configures port {} pin {}", self.name, pin.pno);
                }
            }
        }

        /// CRH written - call when the CRL register is written to. It will set pin
        /// configurations for all pins configured by the CRH register
        pub fn crh_written(&mut self, regval: u32) {
            self.regs[regdefs::REG_IDX_CRH].reg_value = regval;
            // pin only takes action if configured by CRH
            for pin in &mut self.pins.iter_mut() {
                if pin.set_config(regval, false) {
                    info!("    => CRH: Configures port {} pin {}", self.name, pin.pno);
                }
            }
        }

        /// IDR written
        pub fn idr_written(&mut self, regval: u32) {
            self.regs[regdefs::REG_IDX_IDR].reg_value = regval;
            warn!("TODO: IDR");
        }

        /// ODR written
        pub fn odr_written(&mut self, regval: u32) {
            self.regs[regdefs::REG_IDX_ODR].reg_value = regval;
            warn!("TODO: ODR");
        }

        /// Called when the BSRR register is written. Bits 0..15 are bit set,
        /// bits 16..31 are bit reset.
        pub fn bsrr_written(&mut self, regval: u32) {
            self.regs[regdefs::REG_IDX_BSRR].reg_value = regval;
            strace!(MemWriteEvent {
                etype: TraceEventType::MEM_WRT,
                size_bytes: 4,
                pc: 0xdead,
                address: self.base + BSRR.offset,
                value: regval,
                ..Default::default()
            });

            for pin in &mut self.pins.iter_mut() {
                let (br, bs) = pin.bsrr(regval);
                if bs {
                    info!("    => BSSR: Sets port {} pin {}", self.name, pin.pno);
                } else if br {
                    info!("    => BSSR: Resets port {} pin {}", self.name, pin.pno);
                }
            }
        }

        /// Called when the BRR register is written. Bits 0..15 are bit reset
        /// for corresponding ODR bit.
        pub fn brr_written(&mut self, regval: u32) {
            self.regs[regdefs::REG_IDX_BRR].reg_value = regval;
            strace!(MemWriteEvent {
                etype: TraceEventType::MEM_WRT,
                size_bytes: 4,
                pc: 0xdead,
                address: self.base + BRR.offset,
                value: regval,
                ..Default::default()
            });
            for pin in &mut self.pins.iter_mut() {
                if pin.brr(&regval) {
                    info!("    => BRR: Resets port {} pin {}", self.name, pin.pno);
                }
            }
        }

        /// LCKR access
        pub fn lckr_written(&mut self, regval: u32) {
            self.regs[regdefs::REG_IDX_LCKR].reg_value = regval;
            strace!(MemWriteEvent {
                etype: TraceEventType::MEM_WRT,
                size_bytes: 4,
                pc: 0xdead,
                address: self.base + LCKR.offset,
                value: regval,
                ..Default::default()
            });
            warn!("TODO: LCKR");
        }

        /// Test if `addr` is within the ports address range
        pub fn within(&self, addr: u64) -> bool {
            addr >= self.base as u64 && addr <= self.end as u64
        }

        /// Called when memory is accessed (r/w)
        /// Identify the register based on address hit
        pub fn mem_callback(
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

            if address == (self.base as u64 + regdefs::CRL.offset as u64) {
                self.crl_written(value);
            } else if address == (self.base as u64 + regdefs::CRH.offset as u64) {
                self.crh_written(value);
            } else if address == (self.base as u64 + regdefs::IDR.offset as u64) {
                self.idr_written(value);
            } else if address == (self.base as u64 + regdefs::ODR.offset as u64) {
                self.odr_written(value);
            } else if address == (self.base as u64 + regdefs::LCKR.offset as u64) {
                self.lckr_written(value);
            } else if address == (self.base as u64 + regdefs::BSRR.offset as u64) {
                self.bsrr_written(value);
            } else if address == (self.base as u64 + regdefs::BRR.offset as u64) {
                self.brr_written(value);
            } else {
                tracing::warn!(
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
} // end mod port

pub mod reg {
    use super::gpio_constants::*;

    #[derive(Eq, PartialEq, Debug)]
    pub struct Reg {
        pub name: String,
        pub offset: u32, // offset addr from GPIOPort
        pub size: u32,
        pub reset: u32,
        pub reg_value: u32,
    }

    impl Reg {
        pub fn new(from_const: regdefs::GPIORegister) -> Self {
            Self {
                name: String::from(from_const.name),
                offset: from_const.offset,
                size: from_const.size,
                reset: from_const.reset,
                reg_value: from_const.reset,
            }
        }

        #[allow(dead_code)]
        pub fn get_value(&self) -> u32 {
            self.reg_value
        }
    }
} // end mod reg

use gpio_constants::{pindefs, portdefs, regdefs};
use pin::Pin;
use port::Port;
use reg::Reg;

/// Notional example of a GPIO peripheral for `stm32f107`.
pub struct Gpio {
    pub a: Port,
    pub b: Port,
    pub c: Port,
    pub d: Port,
    pub e: Port,
    pub f: Port,
    pub g: Port,
}

impl Gpio {
    /// static initialization of the GPIO
    /// allocate ports, registers, and pins
    pub fn new() -> Gpio {
        info!("Init GPIO");

        let mut ports: Vec<Port> = Vec::new();

        for port_def in portdefs::GPIO_PORTS {
            let mut pins: Vec<Pin> = Vec::new();
            (0..pindefs::NPINS).for_each(|i| pins.push(Pin::new(i)));
            let regs = vec![
                Reg::new(regdefs::CRL),
                Reg::new(regdefs::CRH),
                Reg::new(regdefs::IDR),
                Reg::new(regdefs::ODR),
                Reg::new(regdefs::BSRR),
                Reg::new(regdefs::BRR),
                Reg::new(regdefs::LCKR),
            ];

            let port = Port::new(port_def, pins, regs);

            ports.push(port);

            assert!(ports.last().unwrap().regs.len() == regdefs::NREGISTERS);
            assert!(ports.last().unwrap().regs.len() == regdefs::GPIO_REGISTERS.len());
        }

        Gpio {
            // Removing the ports from the vector
            // takes ownership of the port ref
            a: ports.remove(0),
            b: ports.remove(0),
            c: ports.remove(0),
            d: ports.remove(0),
            e: ports.remove(0),
            f: ports.remove(0),
            g: ports.remove(0),
        }
    }

    /// Return an array slice of the ports
    fn ports(&self) -> [&Port; portdefs::NUMPORTS] {
        [
            &self.a, &self.b, &self.c, &self.d, &self.e, &self.f, &self.g,
        ]
    }

    fn ports_mut(&mut self) -> [&mut Port; portdefs::NUMPORTS] {
        [
            &mut self.a,
            &mut self.b,
            &mut self.c,
            &mut self.d,
            &mut self.e,
            &mut self.f,
            &mut self.g,
        ]
    }

    /// Get a safe reference to the port at the given address
    ///
    /// Panics if the port is not found
    fn get_guarded_port(&mut self, address: u64) -> &mut Port {
        for port in self.ports_mut() {
            if port.within(address) {
                return port;
            }
        }
        panic!("Expected to find port")
    }

    /// Set R/W memory hooks for all ports/registers
    fn set_all_hooks(&self, emu: &mut dyn CpuBackend) {
        self.ports().into_iter().for_each(|p| p.set_hooks(emu));
    }
}

impl Default for Gpio {
    fn default() -> Self {
        Self::new()
    }
}

impl Peripheral for Gpio {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        self.set_all_hooks(proc.core.cpu.as_mut());
        Ok(())
    }

    fn name(&self) -> &str {
        "Stm32 Gpio"
    }
}

///////////////////////////////////// CRATE  /////////////////////////////////////////////////////////
/// Call back function for memory access to GPIO register. Based on the address,
/// find the port its for and call it's instances mem_callback function.
pub fn emu_mem_accessed(
    proc: CoreHandle, // Emulator
    address: u64,     // Accessed Address
    size: u32,        // Number of bytes accessed
    value: &[u8],     // Write Value
) -> Result<(), UnknownError> {
    let gpio = proc.event_controller.peripherals.get_expect::<Gpio>()?;
    // If the port is in a valid PortA..PortG address range,
    // find the port for this address
    //   - Unicorn::emu callbacks insufficient
    //   - HashMap<address, Port> leads to ownership issues
    // Replace this with macro

    // todo: need to <T> - pretty much hard-coded to u32
    assert!(size == 4);

    let msg: String = format!(
        "GPIO memory access {:#08x}, value: {:#08x}",
        address,
        u32::from_le_bytes(value[0..4].try_into().unwrap())
    );
    debug!("{msg}");

    // get the port instance, then call it's mem_callback
    gpio.get_guarded_port(address)
        .mem_callback(address, size, value);
    Ok(())
}

///////////////////////////////////// TESTS ////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {

    use super::pin::*;
    use super::*;

    #[test]
    fn pin_high_or_low() {
        assert!(Pin::new(0).is_cfg_low());
        assert!(Pin::new(7).is_cfg_low());
        assert!(Pin::new(8).is_cfg_high());
        assert!(Pin::new(15).is_cfg_high());
    }

    #[test]
    fn test_crh() {
        let mut gpio = Gpio::new();

        gpio.a.crh_written(0x10000);
        assert_eq!(gpio.a.regs[regdefs::REG_IDX_CRH].get_value(), 0x10000);
    }

    #[test]
    fn test_get_br_bs() {
        // (BS, BR)
        assert_eq!(Pin::new(12).get_br_bs(0x1000), (false, true));
        assert_eq!(Pin::new(12).get_br_bs(0x1000_1000), (true, true));
        assert_eq!(Pin::new(12).get_br_bs(0x1000_0000), (true, false));
    }

    #[test]
    fn test_get_guarded_port() {
        use super::gpio_constants::*;

        let mut gpio = Gpio::new();
        assert_eq!(
            gpio.get_guarded_port(portdefs::GPIOPORTA_BASE as u64).name,
            "A"
        );
    }

    #[test]
    fn test_sequence() {
        let mut gpio = Gpio::new();

        // Initial States are at default values
        for pin in gpio.c.get_state() {
            assert!(pin.is_default());
            assert!(pin.is_input());
            assert!(!pin.is_set);
        }

        // Set port C pin 12 with BSRR
        gpio.c.bsrr_written(0x1000);
        for pin in gpio.c.get_state() {
            // pin 12 is set
            if pin.pno == 12 {
                assert!(pin.is_set);
            } else {
                assert!(!pin.is_set)
            }
            // has not been configured, should still be at defauilts.
            assert_eq!(pin.mode, Mode::default());
            assert_eq!(pin.speed, Speed::default());
        }

        // Configures port C pin 12 with CRH, 0x30000
        //  Pin { pno: 12, speed: MegHz50, mode: OutPP, is_set: true }
        gpio.c.crh_written(0x30000);
        for pin in gpio.c.get_state() {
            if pin.pno == 12 {
                assert!(pin.is_output());
                assert_eq!(pin.mode, Mode::OutPP);
                assert_eq!(pin.speed, Speed::MegHz50);
            } else {
                assert!(pin.is_default());
                assert!(pin.is_input());
                assert!(!pin.is_set);
            }
        }

        // Set port C pin 12 with BSRR
        gpio.c.bsrr_written(0x1000);
        for pin in gpio.c.get_state() {
            if pin.pno == 12 {
                assert!(pin.is_set);
                assert!(pin.is_output());
                assert_eq!(pin.mode, Mode::OutPP);
                assert_eq!(pin.speed, Speed::MegHz50);
            } else {
                assert!(pin.is_default());
                assert!(pin.is_input());
                assert!(!pin.is_set);
            }
        }

        // Re-Set port C pin 12 with BRR
        gpio.c.brr_written(0x1000);
        for pin in gpio.c.get_state() {
            if pin.pno == 12 {
                // pin not set, but configuration in tact
                assert!(!pin.is_set);
                assert!(pin.is_output());
                assert_eq!(pin.mode, Mode::OutPP);
                assert_eq!(pin.speed, Speed::MegHz50);
            } else {
                assert!(pin.is_default());
                assert!(pin.is_input());
                assert!(!pin.is_set);
            }
        }
    }
}
