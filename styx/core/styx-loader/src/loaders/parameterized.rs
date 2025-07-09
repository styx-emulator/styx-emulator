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
//! Perform a series of load actions provided in a YAML file.
//!
//! Valid actions are:
//!   - FileElf - load an ELF
//!   - FileRaw - load a raw file
//!   - MemoryRegion - map a memory region
//!   - RegisterImmediate - initialize a register with an immediate value
//!   - RegisterMemoryAddress - initialize a register with a value read from memory.
//!   - EnvironmentStateVariable - define a processor-specific environment state variable for the
//!     processor.
//!
//! See `src/styx-loader/example-input/parameterized.yaml` for an example file.
use crate::loaders::elf::ElfLoaderConfig;
use crate::{Loader, LoaderHints, MemoryLoaderDesc, RegisterMap};
use log::warn;
use serde::Deserialize;
use std::{borrow::Cow, collections::HashMap, fs, path::Path};
use styx_cpu_type::arch::backends::ArchRegister;
use styx_cpu_type::arch::Arch;
use styx_errors::anyhow::Context;
use styx_memory::{MemoryPermissions, MemoryRegion};

use super::elf::load_elf;
use super::raw::load_raw_with_base;

/// This record structure specifies the parameters for a load of an ELF.
#[derive(Deserialize, PartialEq, Debug)]
struct LoadFileElf {
    /// Base address for the ELF.
    /// XXX: Not yet implemented.
    base: u64,
    /// Path to the ELF to be loaded.
    file: String,
}

/// This enumeration is specifies the memory permissions for an allocated memory region.
/// Note, we need the permissions to be deserializable, so we couldn't just use
/// [`MemoryPermissions`] in this context.
#[derive(Deserialize, PartialEq, Debug)]
enum LoadMemoryPermissions {
    AllowAll,
    ExecuteOnly,
    ReadExecute,
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

/// Convert from our deserialized enumeration to the official memory permissions.
impl From<LoadMemoryPermissions> for MemoryPermissions {
    fn from(value: LoadMemoryPermissions) -> Self {
        match value {
            LoadMemoryPermissions::ReadOnly => MemoryPermissions::READ,
            LoadMemoryPermissions::WriteOnly => MemoryPermissions::WRITE,
            LoadMemoryPermissions::ExecuteOnly => MemoryPermissions::EXEC,
            LoadMemoryPermissions::AllowAll => MemoryPermissions::all(),
            LoadMemoryPermissions::ReadWrite => MemoryPermissions::RW,
            LoadMemoryPermissions::ReadExecute => MemoryPermissions::RX,
        }
    }
}

/// This record structure specifies the parameters for a load of an raw file.  A raw file is mapped
/// to a single memory region with the specified permissions.
#[derive(Deserialize, PartialEq, Debug)]
struct LoadFileRaw {
    /// Base address for the mapped memory region.
    base: u64,
    /// Path to the raw file to be loaded.
    file: String,
    /// Permissions to be applied to the memory region. If provided, a memory region is allocated.
    /// If not provided, it is expected that the memory region already exists.
    perms: Option<LoadMemoryPermissions>,
}

/// This record structure specifies the parameters for mapping a memory region. The memory region
/// is created with the specified permissions.
#[derive(Deserialize, PartialEq, Debug)]
struct LoadMemoryRegion {
    /// Base address for the mapped memory region.
    base: u64,
    /// Size of the requested region.
    size: u64,
    /// Permissions to be applied to the memory region.
    perms: LoadMemoryPermissions,
}

/// This record structure specifies the parameters initializing a register from a memory read.
#[derive(Deserialize, PartialEq, Debug)]
struct LoadRegisterMemoryAddress {
    /// Target register name.
    register: String,
    /// Absolute address from which to load the register value.
    address: u64,
}

/// This record structure specifies the parameters initializing a register with an immediate value.
#[derive(Deserialize, PartialEq, Debug)]
struct LoadRegisterImmediate {
    /// Target register name.
    register: String,
    /// Immediate value to load into the register.
    value: u64,
}

// TODO: Make the "value" more generic than u64.
/// This record structure specifies an architecture-specific state environment variable.
#[derive(Deserialize, PartialEq, Debug)]
struct LoadEnvStateVariable(String, u64);

/// Record types supported by the parameterized loader.
#[derive(Deserialize, PartialEq, Debug)]
enum LoadRecordType {
    EnvironmentStateVariable(LoadEnvStateVariable),
    FileElf(LoadFileElf),
    FileRaw(LoadFileRaw),
    MemoryRegion(LoadMemoryRegion),
    RegisterImmediate(LoadRegisterImmediate),
    RegisterMemoryAddress(LoadRegisterMemoryAddress),
}

type LoadRecords = Vec<LoadRecordType>;

/// Warn the user of overwritten registers.
fn warn_key_overwrite(old_map: &RegisterMap, new_map: &RegisterMap) {
    for key in new_map.keys() {
        if old_map.contains_key(key) {
            warn!("Register value for {} is being overwritten.", key);
        }
    }
}

/// Loader for parameterized data files. These YAML files can specify files to be loaded (ELF and
/// raw), memory regions to be mapped and register initializations.
#[derive(Debug, Default)]
pub struct ParameterizedLoader;

impl Loader for ParameterizedLoader {
    /// Returns the name of the [`Loader`]
    ///
    /// ```rust
    /// use styx_loader::{Loader, ParameterizedLoader};
    ///
    /// assert_eq!("parameterized", ParameterizedLoader.name());
    /// ```
    fn name(&self) -> &'static str {
        // This is only a half lie.
        "parameterized"
    }

    /// Given parameter data in YAML, perform the specified load actions.  The YAML data must
    /// contain a list of [`LoadRecordType`] structures. These structures describe the action to be
    /// performed. The available actions are:
    /// - Load an ELF file.
    /// - Load a raw data file to a specified address with provided permissions.
    /// - Map a memory region to the specified address with provided permissions.
    /// - Initialize a register with an immediate value.
    /// - Initialize a register from data at a given memory address.
    fn load_bytes(
        &self,
        data: Cow<[u8]>,
        hints: LoaderHints,
    ) -> Result<MemoryLoaderDesc, crate::StyxLoaderError> {
        let arch: &Arch;
        if let Some(arch_hint) = hints_contain!(hints, "arch", Arch)? {
            arch = arch_hint;
        } else {
            return Err(crate::StyxLoaderError::MissingHintInfo(
                "No architecture provided.".to_string(),
            ));
        }
        let mut registers: RegisterMap = HashMap::new();
        let mut regions: Vec<MemoryRegion> = Vec::new();
        let mut reg_address_updates: Vec<(String, u64)> = Vec::new();
        let mut env_state_variables: LoaderHints = LoaderHints::new();

        let records: LoadRecords =
            serde_yaml::from_slice(&data[..]).with_context(|| "failed to parse loader yaml")?;

        for record in records {
            match record {
                LoadRecordType::FileElf(elf_record) => {
                    // Load the ELF into the memory space using ELF loader.
                    // FIXME: We will ultimately need to support rebasing an ELF. Until then, we
                    // cannot do anything with the base address.
                    let path = Path::new(&elf_record.file);
                    let data = fs::read(path)?;
                    let mut elf_desc: MemoryLoaderDesc =
                        load_elf(&ElfLoaderConfig::default(), &data, HashMap::new()).unwrap();

                    // Save generated regions and register values to add to our final descriptor.
                    warn_key_overwrite(&registers, &elf_desc.registers);
                    registers.extend(elf_desc.take_registers());
                    regions.extend(elf_desc.take_memory_regions());
                }
                LoadRecordType::FileRaw(raw_record) => {
                    // Load the raw file into memory using the raw file loader.
                    let path = Path::new(&raw_record.file);
                    let data = fs::read(path)?;
                    match raw_record.perms {
                        Some(perms) => {
                            let mut raw_desc: MemoryLoaderDesc =
                                load_raw_with_base(data, raw_record.base, perms.into()).unwrap();

                            // Save the generated region to add to our final descriptor.
                            regions.extend(raw_desc.take_memory_regions());
                        }
                        None => {
                            // Read the data from the file.
                            let raw_data = fs::read(raw_record.file).unwrap();
                            let end_addr = raw_record.base + raw_data.len() as u64;
                            // Find the appropriate memory region and copy in the data.
                            let matching_region = regions
                                .iter_mut()
                                .find(|reg| reg.start() <= raw_record.base && end_addr <= reg.end())
                                .expect("Memory for raw data should be pre-allocated.");
                            unsafe {
                                matching_region
                                    .write_data_unchecked(raw_record.base, &raw_data[..])
                                    .unwrap();
                            }
                        }
                    };
                }
                LoadRecordType::MemoryRegion(region_record) => {
                    // Save the generated region to add to our final descriptor.
                    regions.push(
                        MemoryRegion::new(
                            region_record.base,
                            region_record.size,
                            region_record.perms.into(),
                        )
                        .unwrap(),
                    );
                }
                LoadRecordType::RegisterImmediate(reg_record) => {
                    // Save the generated register values to add to our final descriptor.
                    let reg = arch.get_register(&reg_record.register).into();
                    if registers.contains_key(&reg) {
                        warn!(
                            "Register value for {} is being overwritten.",
                            reg_record.register
                        );
                    }
                    registers.insert(reg, reg_record.value);
                }
                LoadRecordType::RegisterMemoryAddress(reg_record) => {
                    // We defer until we are done parsing records (and allocating memory regions)
                    // before we try and do any memory reads.
                    reg_address_updates.push((reg_record.register, reg_record.address));
                }
                LoadRecordType::EnvironmentStateVariable(env_var) => {
                    // We collect these to add as the environment state for the generated
                    // [`MemoryLoaderDesc`].
                    let val_box: Box<u64> = Box::new(env_var.1);
                    env_state_variables.insert(env_var.0.into_boxed_str(), val_box);
                }
            }
        }

        // FIXME: do something more better than this.
        // Handle deferred memory reads for register initializations.
        for (reg_name, address) in reg_address_updates {
            for region in regions.iter() {
                // Attempt to read the data from this region. If it succeeds, we found the right
                // one, so we move on to the next register.
                if let Ok(raw_val) = region.read_data(address, 4) {
                    // FIXME: Check endianness.
                    // FIXME: We are arbitrarily doing 32-bit operations.
                    let val =
                        u32::from_le_bytes(raw_val[0..4].try_into().unwrap_or_else(|_| {
                            panic!("unable to convert {:?} into u32", raw_val)
                        }));

                    // Save the generated register values to add to our final descriptor.
                    let reg: ArchRegister = arch.get_register(&reg_name).into();
                    if registers.contains_key(&reg) {
                        warn!("Register value for {} is being overwritten.", reg_name);
                    }
                    registers.insert(reg, val as u64);
                    break;
                }
            }
        }

        // Construct the descriptor from the collected regions and register data.
        let mut desc = MemoryLoaderDesc::with_regions(regions).unwrap();
        desc.registers.extend(registers);
        desc.env_state.extend(env_state_variables);
        Ok(desc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_parameters() {
        let records: Vec<LoadRecordType> = vec![
            LoadRecordType::FileElf(LoadFileElf {
                base: 0x10000,
                file: "foo.elf".to_string(),
            }),
            LoadRecordType::FileRaw(LoadFileRaw {
                base: 0x80000,
                file: "bar.bin".to_string(),
                perms: Some(LoadMemoryPermissions::ReadWrite),
            }),
            LoadRecordType::FileRaw(LoadFileRaw {
                base: 0x90000,
                file: "baz.bin".to_string(),
                perms: Some(LoadMemoryPermissions::ReadExecute),
            }),
            LoadRecordType::FileRaw(LoadFileRaw {
                base: 0x90040,
                file: "hurr.bin".to_string(),
                perms: None,
            }),
            LoadRecordType::MemoryRegion(LoadMemoryRegion {
                base: 0x100000,
                size: 0x800000,
                perms: LoadMemoryPermissions::ReadWrite,
            }),
            LoadRecordType::MemoryRegion(LoadMemoryRegion {
                base: 0x1000000,
                size: 0x2000000,
                perms: LoadMemoryPermissions::AllowAll,
            }),
            LoadRecordType::RegisterImmediate(LoadRegisterImmediate {
                register: "pc".to_string(),
                value: 0x1000,
            }),
            LoadRecordType::RegisterMemoryAddress(LoadRegisterMemoryAddress {
                register: "r4".to_string(),
                address: 0x40000,
            }),
            LoadRecordType::EnvironmentStateVariable(LoadEnvStateVariable(
                "derp".to_string(),
                0xF00BA8,
            )),
        ];

        // We do this in this manner to mimic how the target file will get opened by styx.
        let f = std::fs::read("example-input/parameterized.yaml").unwrap();
        let loaded_records: LoadRecords = serde_yaml::from_slice(&f[..]).unwrap();

        assert_eq!(
            loaded_records.len(),
            records.len(),
            "Mismatch in the length of the record list."
        );

        for (i, record) in records.iter().enumerate() {
            assert_eq!(
                &loaded_records[i], record,
                "Record {i} does not match the expected result."
            );
        }
    }
}
