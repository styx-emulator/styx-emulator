// SPDX-License-Identifier: BSD-2-Clause
//! Loads an ELF compatible object into something usable by `styx`

use crate::{Loader, LoaderHints, MemoryLoaderDesc, StyxLoaderError};
use goblin::elf::Elf;
use std::borrow::Cow;
use styx_cpu_type::arch::{Arch, ArchEndian};
use styx_errors::anyhow::Context;
use styx_memory::{MemoryPermissions, MemoryRegion};

struct ElfMachine(u16);

impl From<u16> for ElfMachine {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<ElfMachine> for Arch {
    /// Returns the register used as the program counter for styx
    fn from(value: ElfMachine) -> Self {
        use goblin::elf::header::*;

        // update as needed
        match value.0 {
            EM_SPARC | EM_SPARC32PLUS => Arch::Sparc,
            EM_68K | EM_88K => Arch::M68k,
            EM_PPC => Arch::Ppc32,
            EM_ARM => Arch::Arm,
            EM_BLACKFIN => Arch::Blackfin,
            EM_SHARC => Arch::Sharc,
            EM_TI_C6000 => Arch::Tms320C6x,
            EM_TI_C2000 => Arch::Tms320C2x,
            EM_TI_C5500 => Arch::Tms320C5x,
            EM_8051 => Arch::Arch80xx,
            EM_MICROBLAZE => Arch::Microblaze,
            EM_RISCV => Arch::Riscv,
            EM_SH => Arch::SuperH,
            EM_AVR | EM_AVR32 => Arch::Avr,
            EM_QDSP6 => Arch::Hexagon,
            arch => panic!(
                "{} is currently unsupported to load from goblin",
                machine_to_str(arch)
            ),
        }
    }
}

/// Configure the [`ElfLoader`].
#[derive(Debug)]
pub struct ElfLoaderConfig {
    /// Log a warning if the provided ELF has no loadable segments. Defaults to true.
    pub warn_no_loadable_segments: bool,
}

impl Default for ElfLoaderConfig {
    fn default() -> Self {
        Self {
            warn_no_loadable_segments: true,
        }
    }
}

/// Implements the logic to load ELF's into styx
///
/// While implemented as largely architecture-agnostic, this loaders
/// is technically limited by some nifty auto-coversion [`From`] trait
/// impl's, namely [`From<ElfMachine> for Arch`], and [`styx_cpu_type::Arch::pc`].
///
/// # Available Hint's
/// - if provided, an `endian` hint of type [`styx_cpu_type::ArchEndian`] can be provided,
///   it will not override the header, but will warn you if there is a disagreement
/// - if provided, an `arch` hint of type [`styx_cpu_type::Arch`] can be provided,
///   it will not override the header, but will warn you if there is a disagreement
/// - if provided, a `pc` hint of type [`u64`] can be provided, this *will* override
///   the header.
///
/// TODO: test all the hints
/// TODO: add integration tests for this loader
#[derive(Debug, Default)]
pub struct ElfLoader {
    config: ElfLoaderConfig,
}

impl ElfLoader {
    pub fn new(config: ElfLoaderConfig) -> Self {
        Self { config }
    }
}

impl Loader for ElfLoader {
    /// Returns the name of the [`Loader`]
    ///
    /// ```rust
    /// use styx_loader::{Loader, ElfLoader};
    ///
    /// assert_eq!("elf", ElfLoader::default().name());
    /// ```
    fn name(&self) -> &'static str {
        "elf"
    }

    fn load_bytes(
        &self,
        data: Cow<[u8]>,
        hints: LoaderHints,
    ) -> Result<MemoryLoaderDesc, StyxLoaderError> {
        load_elf(&self.config, &data, hints)
    }
}

/// Load the provided ELF data. Breaking this out into a helper allows us to call it from other
/// loaders.
pub(crate) fn load_elf(
    config: &ElfLoaderConfig,
    data: &[u8],
    hints: LoaderHints,
) -> Result<MemoryLoaderDesc, StyxLoaderError> {
    let elf = Elf::parse(data)?;

    // get endianess from the binary
    let parsed_endian = if elf.little_endian {
        ArchEndian::LittleEndian
    } else {
        ArchEndian::BigEndian
    };

    log::trace!("Parsed file endian is `{parsed_endian}`");

    // if an endianness hint was provided, complain if
    // it's not the same
    if let Some(endian_hint) = hints_contain!(hints, "endian", ArchEndian)? {
        if endian_hint != &parsed_endian {
            log::warn!("Parsed Elf endian: `{parsed_endian}` is not equal to hinted endian: `{endian_hint}`");
        }
    }

    // get architecture from the binary
    let arch: Arch = ElfMachine(elf.header.e_machine).into();
    log::trace!("File arch is  `{arch}`");

    // if an architecture hint was provided, complain if
    // it's not the same
    if let Some(arch_hint) = hints_contain!(hints, "arch", Arch)? {
        if arch_hint != &arch {
            log::warn!("Parsed Elf arch: `{arch}` is not equal to hinted arch: `{arch_hint}`");
        }
    }

    // collect all the regions we need to load
    let mut regions = Vec::new();
    for ph in elf.program_headers {
        // Look only for loadable segments, see `man 5 elf` for more
        //
        // Note that `PT_LOAD` segments are described by
        // `p_filesz` and `p_memsz`. If the segment's memory size
        // `p_memsz` is larger than the file size `p_filesz`,
        // the "extra" bytes are defined to hold the value
        // 0 and to follow the segment's initialized area.
        // The file size may not be larger than the memory size.
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            // note that in general we load firmware files,
            // so the `p_vaddr` and the `p_paddr` should both
            // be set to the same exact value. And elf's in
            // general don't need to sent `p_paddr`.
            let base_address: u64 = ph.p_vaddr;

            // number of bytes to copy from the file
            let src_size: u64 = ph.p_filesz;

            // for all bytes memsz - filesz, we're going to null populate them
            let dst_size: u64 = ph.p_memsz;

            // get the data for the source tests
            let src_mem_range = (ph.p_offset as usize)..((ph.p_offset + src_size) as usize);
            let mut src_data = data
                .get(src_mem_range)
                .ok_or_else(|| {
                    StyxLoaderError::MalformedInput(format!(
                        "Segment size `{src_size:X}` cannot be sourced from file"
                    ))
                })?
                .to_vec();

            // append the required number of null bytes
            if dst_size > src_size {
                src_data.extend(vec![0; (dst_size - src_size) as usize]);
            }

            // now get permissions
            let mut perms = MemoryPermissions::empty();
            if ph.p_flags & goblin::elf::program_header::PF_R > 0 {
                perms = perms.union(MemoryPermissions::READ);
            }
            if ph.p_flags & goblin::elf::program_header::PF_W > 0 {
                perms = perms.union(MemoryPermissions::WRITE);
            }
            if ph.p_flags & goblin::elf::program_header::PF_X > 0 {
                perms = perms.union(MemoryPermissions::EXEC);
            }

            // add region to collection
            let region = MemoryRegion::new_with_data(base_address, dst_size, perms, src_data)?;
            log::trace!("Adding {region:?}");
            regions.push(region);
        }
    }

    log::trace!("File has `{}` loadable segments", regions.len());
    if config.warn_no_loadable_segments && regions.is_empty() {
        log::warn!(
            "File has zero loadable segments! This probably means that your ELF was not \
        built correctly. If you intended to have zero loadable segments, you can turn remove this \
        warning by setting the warn_no_loadable_segments option on the ElfLoader."
        );
    }

    // construct the description with the information we have so far
    let mut desc =
        MemoryLoaderDesc::with_regions(regions).with_context(|| "could not add an elf region")?;

    let header_pc = elf.entry;
    log::trace!("Elf header specifies entry as: `{:X}`", elf.entry);

    // if an entry address was provided, warn that the provided value is
    // overriding the input elf `e_entry`
    if let Some(hint_pc) = hints_contain!(hints, "pc", u64)? {
        if *hint_pc != header_pc {
            log::warn!("Hint pc != to pc from elf header, hint is OVERRIDING header");
        }

        desc.add_register(arch.pc(), *hint_pc)
            .with_context(|| "failed to set pc to hint")?;
    } else {
        desc.add_register(arch.pc(), header_pc)
            .with_context(|| "failed to set pc to elf header")?;
    }

    Ok(desc)
}
