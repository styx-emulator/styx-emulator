// SPDX-License-Identifier: BSD-2-Clause
use std::{
    borrow::Cow,
    fmt::Debug,
    io::{Cursor, Read, Seek},
};

use crate::{Loader, LoaderHints, MemoryLoaderDesc};
use binrw::{BinRead, BinResult, Endian};
use log::{debug, warn};
use styx_cpu_type::arch::blackfin::BlackfinRegister;
use styx_errors::{anyhow::Context, styx_loader::StyxLoaderError};
use styx_memory::{MemoryPermissions, MemoryRegion};

const BLACKFIN_LDR_MAGIC: i8 = -83;

/// Loader for the Blackfin LDR file format
///
/// From [ldr-utils](https://github.com/neuschaefer/ldr-utils):
///
/// > To put it simply, LDRs are just a container format for DXEs (which are just a
/// > fancy name for programs in the Blackfin binary object code format).  A single
/// > LDR is made up of an arbitrary number of DXEs and a single DXE is made up of
/// > an arbitrary number of blocks (each block contains starting address and some
/// > flags).
///
/// In this implementation we only handle a single DXE and.
///
/// Also a possible fixme is that the whole ROM should be loaded in at 0x2000_0000.
#[derive(Debug, Default)]
pub struct BlackfinLDRLoader;

impl Loader for BlackfinLDRLoader {
    fn name(&self) -> &'static str {
        "blackfin boot stream"
    }

    fn load_bytes(
        &self,
        data: Cow<[u8]>,
        _hints: LoaderHints,
    ) -> Result<MemoryLoaderDesc, StyxLoaderError> {
        // note: we don't use any hints
        load_blackfin(&data)
    }
}

fn load_blackfin(data: &[u8]) -> Result<MemoryLoaderDesc, StyxLoaderError> {
    let blocks = parse_blocks(data)?;

    // work in progress description
    let mut working_description = MemoryLoaderDesc::default();
    for block in blocks.into_iter() {
        let target_address = block.target_address as u64;
        if block.flags.contains(BlockHeaderFlags::FIRST) {
            // bh.argument: start of next stream
            // bh.targetAddress: entry point
            debug!("FIRST block found with target entry pc 0x{target_address:X}");

            // set pc to entry point address
            working_description
                .add_register(BlackfinRegister::Pc, target_address)
                .with_context(|| "failed to set pc to BlockHeaderFlags::FIRST")?;
        }
        if block.flags.contains(BlockHeaderFlags::INIT) {
            // bh.argument: start of next stream
            // bh.targetAddress: entry point
            debug!("INIT block found with target entry pc 0x{target_address:X}");

            // set pc to entry point address
            working_description
                .add_register(BlackfinRegister::Pc, target_address)
                .with_context(|| "failed to set pc to BlockHeaderFlags::INIT")?;
        }

        // block IS NOT FILL and NOT IGNORE
        if block.byte_count > 0
            && !block
                .flags
                .intersects(BlockHeaderFlags::FILL | BlockHeaderFlags::IGNORE)
        {
            // make a new region with the block's data bytes

            let base = target_address;
            let size = block.byte_count as u64;
            let data = block.data;
            let new_region =
                MemoryRegion::new_with_data(base, size, MemoryPermissions::all(), data)?;

            working_description
                .add_region(new_region)
                .with_context(|| "failed to add region")?;
        }

        if block.flags.contains(BlockHeaderFlags::FILL) {
            // fill region with bytes in argument repeating
            let argument_bytes = block.argument.to_le_bytes();
            let fill_bytes: Vec<u8> = argument_bytes
                .into_iter()
                .cycle()
                .take(block.byte_count as usize)
                .collect();

            let base = target_address;
            let size = block.byte_count as u64;
            let new_region =
                MemoryRegion::new_with_data(base, size, MemoryPermissions::all(), fill_bytes)?;

            working_description
                .add_region(new_region)
                .with_context(|| "failed to add FILL region")?;
        }

        if block.flags.contains(BlockHeaderFlags::CALLBACK) {
            warn!("Block with flag 'CALLBACK' might contain encrypted or compressed data.")
        }
    }

    Ok(working_description)
}

fn parse_blocks(data: &[u8]) -> Result<Vec<BlockRaw>, StyxLoaderError> {
    let mut cursor = Cursor::new(data);

    let mut blocks = Vec::new();
    loop {
        // FIXME does not validate checksum
        let raw_block = BlockRaw::read(&mut cursor)
            .map_err(|err| StyxLoaderError::LoadFirmwareError(err.to_string()))?;

        if raw_block.flags.is_final() {
            let all_bytes_consumed = cursor.position() == data.len() as u64 - 1;
            if !all_bytes_consumed {
                // This is OKAY
                warn!(
                    "Final blocked reached without all bytes consumed at offset 0x{:X}",
                    cursor.position()
                );
            }
            break;
        }

        blocks.push(raw_block);
    }

    Ok(blocks)
}

#[derive(BinRead, Debug)]
#[br(little)]
struct BlockRaw {
    flags: BlockHeaderFlags,
    _checksum: u8, // never checked
    _magic: Magic, // checked on creation
    target_address: u32,
    byte_count: u32,
    argument: u32,
    #[br(count = byte_count, if(!flags.contains(BlockHeaderFlags::FILL)))]
    data: Vec<u8>,
}

bitflags::bitflags! {
    #[repr(C)]
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
    pub struct BlockHeaderFlags: u16 {
        const FINAL = 0x8000;
        const FIRST = 0x4000;
        const INDIRECT = 0x2000;
        const IGNORE = 0x1000;
        const INIT = 0x800;
        const CALLBACK = 0x400;
        const QUICK_BOOK = 0x200;
        const FILL = 0x100;

        const AUX = 0x20;
        const SAVE = 0x10;

        // The source may set any bits
        const __ = !0;
    }
}

impl BlockHeaderFlags {
    /// Does this have the [BlockHeaderFlags::FINAL] flag set.
    fn is_final(&self) -> bool {
        self.contains(Self::FINAL)
    }
}

// basically just parses as a u16 into the bitflags
impl BinRead for BlockHeaderFlags {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let inner = u16::read_options(reader, endian, ())?;

        Self::from_bits(inner).ok_or(binrw::Error::Custom {
            pos: reader.stream_position()?,
            err: Box::new("bad flags"),
        })
    }
}

/// Blackfin boot loader magic value. Can only be constructed if valid.
struct Magic;
impl BinRead for Magic {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _endian: Endian, // no endian for i8
        _args: Self::Args<'_>,
    ) -> BinResult<Self> {
        match i8::read(reader)? {
            BLACKFIN_LDR_MAGIC => Ok(Magic),
            bad_magic => Err(binrw::Error::BadMagic {
                pos: reader.stream_position()?,
                found: Box::new(bad_magic),
            }),
        }
    }
}

impl Debug for Magic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ValidMagic")
    }
}
