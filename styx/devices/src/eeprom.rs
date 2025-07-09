// SPDX-License-Identifier: BSD-2-Clause
//! AT25HP512
//! datasheet: <https://mm.digikey.com/Volume0/opasdata/d220001/medias/docus/2090/AT25HP256_512_Rev1113L_3-21-06.pdf>
//!
//! Instruction Name | Instruction Format | Operation
//! ===================================================================
//! WREN             | 0000 X110          | Set Write Enable Latch
//! WRDI             | 0000 X100          | Reset Write Enable Latch
//! RDSR             | 0000 X101          | Read Status Register
//! WRSR             | 0000 X001          | Write Status Register
//! READ             | 0000 X011          | Read Data from Memory Array
//! WRITE            | 0000 X010          | Write Data to Memory Array
//!
use styx_core::peripheral_clients::spi::SPIDevice;
use thiserror::Error;
use tracing::{error, warn};

#[derive(Debug)]
enum Command {
    Rdsr,
    Read,
    Wrdi,
    Wren,
    Write,
    Wrsr,
}

#[derive(Debug, Error)]
pub enum EepromError {
    #[error("Invalid command: {0}")]
    InvalidCommandError(u8),
}

impl TryFrom<u8> for Command {
    type Error = EepromError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b111 {
            0b0000_0110 => Ok(Self::Wren),
            0b0000_0100 => Ok(Self::Wrdi),
            0b0000_0101 => Ok(Self::Rdsr),
            0b0000_0001 => Ok(Self::Wrsr),
            0b0000_0011 => Ok(Self::Read),
            0b0000_0010 => Ok(Self::Write),
            _ => Err(EepromError::InvalidCommandError(value)),
        }
    }
}

enum WriteProtect {
    // entire memory
    Full,
    /// upper half
    Half,
    /// nothing protected
    None,
    /// upper quarter
    Quarter,
}

impl WriteProtect {
    fn is_protected(&self, address: u16) -> bool {
        match self {
            WriteProtect::None => false,
            WriteProtect::Quarter => address >= 0xC000,
            WriteProtect::Half => address >= 0x8000,
            WriteProtect::Full => true,
        }
    }
}

impl From<u8> for WriteProtect {
    fn from(value: u8) -> Self {
        match value & 0x3 {
            0b00 => WriteProtect::None,
            0b01 => WriteProtect::Quarter,
            0b10 => WriteProtect::Half,
            0b11 => WriteProtect::Full,
            _ => unreachable!(),
        }
    }
}

struct Status {
    write_enabled: bool,
    write_prot: WriteProtect,
    write_prot_en: bool,
}

impl Status {
    fn as_u8(&self) -> u8 {
        0
    }
}

impl From<u8> for Status {
    fn from(value: u8) -> Self {
        Self {
            write_enabled: (value & 0x2) > 0,
            write_prot: ((value >> 0x2) & 0x3).into(),
            write_prot_en: (value & 0x80) > 0,
        }
    }
}

impl Default for Status {
    fn default() -> Self {
        Self {
            write_enabled: false,
            write_prot: WriteProtect::None,
            write_prot_en: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DeviceState {
    Idle,
    Write,
    Read,
    WriteStatus,
    ReadStatus,
}

/// addressable memory: 0000h - FFFFh
/// pagesize: 128 bytes
pub struct AT25HP512 {
    status: Status,
    memory: [u8; 0x10000],
    device_state: DeviceState,
    address_pointer_msb: u8,
    address_pointer_lsb: u8,
    address_count: usize,
}

impl Default for AT25HP512 {
    fn default() -> Self {
        Self::new()
    }
}

impl SPIDevice for AT25HP512 {
    fn get_name(&self) -> &str {
        "EEPROM"
    }

    fn write_data(&mut self, data: u8) {
        if self.device_state == DeviceState::Idle {
            self.eval_cmd(data);
        } else {
            self.handle_write(data);
        }
    }

    fn read_data(&mut self) -> Option<u8> {
        match self.device_state {
            DeviceState::ReadStatus => Some(self.status.as_u8()),
            DeviceState::Read => {
                let ap =
                    ((self.address_pointer_msb as usize) << 8) | self.address_pointer_lsb as usize;
                let d = self.memory[ap];

                let (new_lsb, overflow) = self.address_pointer_lsb.overflowing_add(1);
                if overflow {
                    self.address_pointer_msb = self.address_pointer_msb.overflowing_add(1).0;
                }
                self.address_pointer_lsb = new_lsb;
                Some(d)
            }
            _ => None,
        }
    }
}

impl AT25HP512 {
    pub fn new() -> Self {
        Self {
            status: Status::default(),
            memory: [0_u8; 0x10000],
            device_state: DeviceState::Idle,
            address_pointer_msb: 0,
            address_pointer_lsb: 0,
            address_count: 0,
        }
    }

    fn handle_write(&mut self, data: u8) {
        match self.device_state {
            DeviceState::WriteStatus => self.status = data.into(),
            DeviceState::Write => {
                if self.address_count == 0 {
                    self.address_pointer_msb = data;
                    self.address_count = 1;
                    return;
                } else if self.address_count == 1 {
                    self.address_pointer_lsb = data;
                    self.address_count = 2;
                    return;
                }

                let ap =
                    ((self.address_pointer_msb as usize) << 8) | self.address_pointer_lsb as usize;

                if !self.status.write_prot_en && !self.status.write_prot.is_protected(ap as u16) {
                    self.memory[ap] = data;
                }
                self.address_pointer_lsb = self.address_pointer_lsb.overflowing_add(1).0;
            }
            DeviceState::Read => {
                if self.address_count == 0 {
                    self.address_pointer_msb = data;
                    self.address_count = 1;
                } else if self.address_count == 1 {
                    self.address_pointer_lsb = data;
                    self.address_count = 2;
                }
            }
            _ => {
                // ignore writes in other states
            }
        }
    }

    fn eval_cmd(&mut self, inst: u8) {
        let cmd: Result<Command, EepromError> = inst.try_into();

        match cmd {
            Ok(c) => match c {
                Command::Wren => self.status.write_enabled = true,
                Command::Wrdi => self.status.write_enabled = false,
                Command::Rdsr => self.device_state = DeviceState::ReadStatus,
                Command::Wrsr => self.device_state = DeviceState::WriteStatus,
                Command::Read => {
                    self.device_state = DeviceState::Read;
                    self.address_count = 0;
                }
                Command::Write => {
                    self.device_state = DeviceState::Write;
                    self.address_count = 0;
                }
            },
            Err(e) => {
                warn!("received unknown command: {:?}", e);
                self.device_state = DeviceState::Idle;
            }
        }
    }
}
