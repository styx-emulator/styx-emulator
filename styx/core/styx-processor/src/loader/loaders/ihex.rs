// SPDX-License-Identifier: BSD-2-Clause
//! Intel HEX file loader for the Styx Emulator
//!
//! This loader supports the full Intel HEX specification including:
//! - Data records (00)
//! - End of File records (01)
//! - Extended Segment Address records (02)
//! - Start Segment Address records (03)
//! - Extended Linear Address records (04)
//! - Start Linear Address records (05)

use crate::{
    loader::{Loader, LoaderHints, MemoryLoaderDesc, StyxLoaderError},
    processor::Config,
};
use std::borrow::Cow;
use std::collections::BTreeMap;
use styx_cpu_type::Arch;
use styx_errors::anyhow::Context;
use styx_memory::{MemoryPermissions, MemoryRegion};

/// Intel HEX record types
#[derive(Debug, Clone, Copy, PartialEq)]
enum RecordType {
    Data = 0x00,
    EndOfFile = 0x01,
    ExtendedSegmentAddress = 0x02,
    StartSegmentAddress = 0x03,
    ExtendedLinearAddress = 0x04,
    StartLinearAddress = 0x05,
}

impl TryFrom<u8> for RecordType {
    type Error = StyxLoaderError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(RecordType::Data),
            0x01 => Ok(RecordType::EndOfFile),
            0x02 => Ok(RecordType::ExtendedSegmentAddress),
            0x03 => Ok(RecordType::StartSegmentAddress),
            0x04 => Ok(RecordType::ExtendedLinearAddress),
            0x05 => Ok(RecordType::StartLinearAddress),
            _ => Err(StyxLoaderError::MalformedInput(format!(
                "Unknown Intel HEX record type: 0x{value:02X}"
            ))),
        }
    }
}

/// Represents a parsed Intel HEX record
#[derive(Debug)]
struct IhexRecord {
    #[allow(dead_code)]
    byte_count: u8,
    address: u16,
    record_type: RecordType,
    data: Vec<u8>,
}

/// Loader for Intel HEX files
///
/// Intel HEX is a file format that conveys binary information in ASCII text form.
/// It is commonly used for programming microcontrollers, EPROMs, and other programmable logic devices.
///
/// # Available Hints
/// - if provided, a `pc` hint of type [`u64`] can be provided to override the start address
///   from the HEX file. the record type 05 (start address) will be used if not provided.
/// - if provided, an `arch` hint of type [`Arch`] can be provided
///
/// # Usage
/// The loader can be used to load Intel HEX files into memory regions, with the start address
/// determined by the file contents or overridden by hints.
///
/// If the pc is provided in the hints, it will override the start address from the HEX file
/// if and only if the Arch hint is provided.
///
/// # Other Notes
/// If you are hand making new ihex files, remember that `objcopy` will only consider
/// the file offset in your linker script (the `AT` directive) when populating the ihex.
///
/// ihex files are really only used for physically mapped things, any attempt at emitting
/// what you deem to be "correct" ihex files might take a lot of work or custom tooling.
#[derive(Debug, Default)]
pub struct IhexLoader;

impl IhexLoader {
    /// Parse a single line of Intel HEX format
    fn parse_line(line: &str) -> Result<IhexRecord, StyxLoaderError> {
        let line = line.trim();

        // Skip empty lines
        if line.is_empty() {
            return Err(StyxLoaderError::MalformedInput(
                "Empty line in Intel HEX file".to_string(),
            ));
        }

        // Check start code
        if !line.starts_with(':') {
            return Err(StyxLoaderError::MalformedInput(format!(
                "Intel HEX line must start with ':', found: {}",
                line.chars().next().unwrap_or(' ')
            )));
        }

        let line = &line[1..]; // Skip the ':'

        // Parse hex string to bytes
        let bytes = Self::parse_hex_string(line)?;

        // Minimum record size is 5 bytes (count + address + type + checksum)
        if bytes.len() < 5 {
            return Err(StyxLoaderError::MalformedInput(
                "Intel HEX record too short".to_string(),
            ));
        }

        let byte_count = bytes[0];
        let address = u16::from_be_bytes([bytes[1], bytes[2]]);
        let record_type = RecordType::try_from(bytes[3])?;

        // Verify the byte count matches the actual data length
        let expected_len = 5 + byte_count as usize; // 1 (count) + 2 (addr) + 1 (type) + data + 1 (checksum)
        if bytes.len() != expected_len {
            return Err(StyxLoaderError::MalformedInput(format!(
                "Intel HEX record length mismatch: expected {} bytes, got {}",
                expected_len,
                bytes.len()
            )));
        }

        // Extract data (if any)
        let data = if byte_count > 0 {
            bytes[4..4 + byte_count as usize].to_vec()
        } else {
            Vec::new()
        };

        // Verify checksum
        let checksum_offset = bytes.len() - 1;
        let checksum = bytes[checksum_offset];
        Self::verify_checksum(&bytes[..checksum_offset], checksum)?;

        Ok(IhexRecord {
            byte_count,
            address,
            record_type,
            data,
        })
    }

    /// Convert an upper-hex string to a vector of u8
    ///
    /// This function will return an error if the string has an odd length
    /// or contains invalid hex characters.
    fn parse_hex_string(hex_str: &str) -> Result<Vec<u8>, StyxLoaderError> {
        // Check if the string has an even length
        if hex_str.len() % 2 != 0 || hex_str.is_empty() {
            return Err(StyxLoaderError::MalformedInput(
                "Intel HEX string must have an even number of characters greater than 0"
                    .to_string(),
            ));
        }

        let mut bytes = Vec::with_capacity(hex_str.len() / 2);

        // Here we use a for loop instead of an iterator since
        // we want to essentially abort the operation on the first
        // error, doing it in an iterator would lead to less graceful
        // and tidy handling of errors.
        for chunk in hex_str.as_bytes().chunks(2) {
            let hex_str = std::str::from_utf8(chunk).map_err(|e| {
                StyxLoaderError::MalformedInput(format!("Invalid UTF-8 in hex string: {e}"))
            })?;

            let byte = u8::from_str_radix(hex_str, 16).map_err(|e| {
                StyxLoaderError::MalformedInput(format!("Invalid hex byte '{hex_str}': {e}"))
            })?;

            bytes.push(byte);
        }

        Ok(bytes)
    }

    /// Verify the checksum of a record
    fn verify_checksum(data: &[u8], checksum: u8) -> Result<(), StyxLoaderError> {
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        let calculated_checksum = (!(sum as u8)).wrapping_add(1); // Two's complement

        if calculated_checksum != checksum {
            return Err(StyxLoaderError::MalformedInput(format!(
                "Intel HEX checksum mismatch: expected 0x{checksum:02X}, calculated 0x{calculated_checksum:02X}"
            )));
        }

        Ok(())
    }

    /// Merge contiguous memory regions
    fn merge_regions(data_map: BTreeMap<u64, Vec<u8>>) -> Vec<(u64, Vec<u8>)> {
        let mut regions = Vec::new();
        let mut current_base: Option<u64> = None;
        let mut current_data = Vec::new();

        for (addr, data) in data_map {
            if let Some(base) = current_base {
                // Check if this address is contiguous with the current region
                if addr == base + current_data.len() as u64 {
                    // Extend current region
                    current_data.extend(data);
                } else {
                    // Start new region
                    regions.push((base, current_data));
                    current_base = Some(addr);
                    current_data = data;
                }
            } else {
                // First region
                current_base = Some(addr);
                current_data = data;
            }
        }

        // Add the last region
        if let Some(base) = current_base {
            regions.push((base, current_data));
        }

        regions
    }
}

impl Loader for IhexLoader {
    fn name(&self) -> &'static str {
        "ihex"
    }

    fn load_bytes(
        &self,
        data: Cow<[u8]>,
        hints: LoaderHints,
        _config: &Config,
    ) -> Result<MemoryLoaderDesc, StyxLoaderError> {
        // Convert bytes to string for parsing
        let content = std::str::from_utf8(&data).map_err(|e| {
            StyxLoaderError::MalformedInput(format!("Invalid UTF-8 in hex string: {e}"))
        })?;

        // State for address calculation
        let mut extended_segment_address: u16 = 0; // Upper 4 bits of 20-bit address
        let mut extended_linear_address: u16 = 0; // Upper 16 bits of 32-bit address
        let mut start_address: Option<u64> = None;
        let mut start_segment: Option<(u16, u16)> = None;

        // Map to store all data by absolute address
        let mut data_map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut found_eof = false;

        // Parse each line
        for (line_num, line) in content.lines().enumerate() {
            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            let record = Self::parse_line(line)
                .with_context(|| format!("Failed to parse Intel HEX line {}", line_num + 1))?;

            // Don't process records after EOF
            if found_eof {
                log::warn!(
                    "Intel HEX: Found record after End of File at line {}",
                    line_num + 1
                );
                break;
            }

            match record.record_type {
                RecordType::Data => {
                    // Calculate absolute address
                    let abs_address = if extended_linear_address != 0 {
                        // 32-bit addressing
                        ((extended_linear_address as u64) << 16) | (record.address as u64)
                    } else if extended_segment_address != 0 {
                        // 20-bit segmented addressing
                        ((extended_segment_address as u64) << 4) + (record.address as u64)
                    } else {
                        // 16-bit addressing
                        record.address as u64
                    };

                    // Store data at this address
                    data_map.insert(abs_address, record.data);
                }
                RecordType::EndOfFile => {
                    found_eof = true;
                    log::trace!(
                        "Intel HEX: Found End of File record at line {}",
                        line_num + 1
                    );
                }
                RecordType::ExtendedSegmentAddress => {
                    if record.data.len() != 2 {
                        return Err(StyxLoaderError::MalformedInput(format!(
                            "Extended Segment Address record must have 2 data bytes, got {}",
                            record.data.len()
                        )));
                    }
                    extended_segment_address = u16::from_be_bytes([record.data[0], record.data[1]]);
                    extended_linear_address = 0; // Reset linear address
                    log::trace!(
                        "Intel HEX: Set extended segment address to 0x{extended_segment_address:04X}"
                    );
                }
                RecordType::StartSegmentAddress => {
                    if record.data.len() != 4 {
                        return Err(StyxLoaderError::MalformedInput(format!(
                            "Start Segment Address record must have 4 data bytes, got {}",
                            record.data.len()
                        )));
                    }
                    let cs = u16::from_be_bytes([record.data[0], record.data[1]]);
                    let ip = u16::from_be_bytes([record.data[2], record.data[3]]);
                    start_segment = Some((cs, ip));
                    log::trace!("Intel HEX: Set start segment address to {cs:04X}:{ip:04X}");
                }
                RecordType::ExtendedLinearAddress => {
                    if record.data.len() != 2 {
                        return Err(StyxLoaderError::MalformedInput(format!(
                            "Extended Linear Address record must have 2 data bytes, got {}",
                            record.data.len()
                        )));
                    }
                    extended_linear_address = u16::from_be_bytes([record.data[0], record.data[1]]);
                    extended_segment_address = 0; // Reset segment address
                    log::trace!(
                        "Intel HEX: Set extended linear address to 0x{extended_linear_address:04X}"
                    );
                }
                RecordType::StartLinearAddress => {
                    if record.data.len() != 4 {
                        return Err(StyxLoaderError::MalformedInput(format!(
                            "Start Linear Address record must have 4 data bytes, got {}",
                            record.data.len()
                        )));
                    }
                    start_address = Some(u32::from_be_bytes([
                        record.data[0],
                        record.data[1],
                        record.data[2],
                        record.data[3],
                    ]) as u64);
                    log::trace!(
                        "Intel HEX: Set start linear address to 0x{:08X}",
                        start_address.unwrap()
                    );
                }
            }
        }

        if !found_eof {
            log::warn!("Intel HEX: No End of File record found");
        }

        // Merge contiguous regions
        let regions = Self::merge_regions(data_map);

        if regions.is_empty() {
            return Err(StyxLoaderError::MalformedInput(
                "Intel HEX file contains no data".to_string(),
            ));
        }

        // Create memory regions
        let mut desc = MemoryLoaderDesc::default();

        for (base, data) in regions {
            let region = MemoryRegion::new_with_data(
                base,
                data.len() as u64,
                MemoryPermissions::all(), // Intel HEX files are typically firmware, so RWX
                data,
            )?;

            desc.add_region(region)
                .with_context(|| format!("Failed to add Intel HEX region at 0x{base:X}"))?;
        }

        // Set program counter if available
        if let Some(pc_hint) = hints_contain!(hints, "pc", u64)? {
            // PC hint requires arch hint
            let arch = hints_contain!(hints, "arch", Arch)?
                .ok_or_else(|| {
                    StyxLoaderError::MalformedInput(
                        "PC hint provided but arch hint is missing. The 'arch' hint is required when using 'pc' hint.".to_string(),
                    )
                })?;

            desc.add_register(arch.pc(), *pc_hint)
                .with_context(|| "Failed to set PC from hint")?;
        } else if let Some(start) = start_address {
            // Use start address from file
            if let Some(arch) = hints_contain!(hints, "arch", Arch)? {
                desc.add_register(arch.pc(), start)
                    .with_context(|| "Failed to set PC from Intel HEX file start address")?;
            }
        } else if let Some((cs, ip)) = start_segment {
            // Convert segmented address to linear for PC
            let linear_start = ((cs as u64) << 4) + (ip as u64);
            if let Some(arch) = hints_contain!(hints, "arch", Arch)? {
                desc.add_register(arch.pc(), linear_start)
                    .with_context(|| "Failed to set PC from Intel HEX segment address")?;
            }
        }

        Ok(desc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use test_case::test_case;

    #[test]
    fn test_parse_hex_string() {
        assert_eq!(
            IhexLoader::parse_hex_string("0102ABCD").unwrap(),
            vec![0x01, 0x02, 0xAB, 0xCD]
        );

        assert_eq!(IhexLoader::parse_hex_string("00").unwrap(), vec![0x00]);

        // Test lowercase hex
        assert_eq!(
            IhexLoader::parse_hex_string("abcdef").unwrap(),
            vec![0xAB, 0xCD, 0xEF]
        );

        // Test invalid hex character
        assert!(IhexLoader::parse_hex_string("0G").is_err());

        // Test odd length string
        assert!(IhexLoader::parse_hex_string("010").is_err());
    }

    #[test]
    fn test_checksum_calculation() {
        // Example: :10010000214601360121470136007EFE09D21940
        // Data bytes: 10 01 00 00 21 46 01 36 01 21 47 01 36 00 7E FE 09 D2 19
        // Sum: 0x03BF, Two's complement of 0xBF = 0x41, but checksum is 0x40
        // Let's create a simpler example

        let data = vec![0x10, 0x00, 0x00, 0x00]; // count=16, addr=0, type=0 (data)
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        let checksum = (!(sum as u8)).wrapping_add(1);

        assert!(IhexLoader::verify_checksum(&data, checksum).is_ok());
        assert!(IhexLoader::verify_checksum(&data, checksum.wrapping_add(1)).is_err());
    }

    #[test]
    fn test_parse_data_record() {
        // Create a simple data record with correct checksum
        // Format: :LLAAAATTDD...CC
        // LL = 02 (2 bytes), AAAA = 0100 (address), TT = 00 (data record), DD = 0102 (data)
        // Sum = 02 + 01 + 00 + 00 + 01 + 02 = 06
        // Checksum = two's complement of 06 = FA
        let line = ":020100000102FA";
        let record = IhexLoader::parse_line(line).unwrap();

        assert_eq!(record.byte_count, 0x02);
        assert_eq!(record.address, 0x0100);
        assert_eq!(record.record_type, RecordType::Data);
        assert_eq!(record.data.len(), 2);
        assert_eq!(record.data[0], 0x01);
        assert_eq!(record.data[1], 0x02);
    }

    #[test]
    fn test_parse_eof_record() {
        // :00000001FF
        let line = ":00000001FF";
        let record = IhexLoader::parse_line(line).unwrap();

        assert_eq!(record.byte_count, 0);
        assert_eq!(record.address, 0);
        assert_eq!(record.record_type, RecordType::EndOfFile);
        assert_eq!(record.data.len(), 0);
    }

    #[test]
    fn test_parse_extended_linear_address() {
        // :020000040800F2
        let line = ":020000040800F2";
        let record = IhexLoader::parse_line(line).unwrap();

        assert_eq!(record.byte_count, 2);
        assert_eq!(record.address, 0);
        assert_eq!(record.record_type, RecordType::ExtendedLinearAddress);
        assert_eq!(record.data, vec![0x08, 0x00]); // Upper 16 bits = 0x0800
    }

    #[test]
    fn test_parse_start_linear_address() {
        // :0400000508000000EF
        let line = ":0400000508000000EF";
        let record = IhexLoader::parse_line(line).unwrap();

        assert_eq!(record.byte_count, 4);
        assert_eq!(record.address, 0);
        assert_eq!(record.record_type, RecordType::StartLinearAddress);
        assert_eq!(record.data, vec![0x08, 0x00, 0x00, 0x00]); // Start address = 0x08000000
    }

    #[test]
    fn test_load_simple_hex() {
        // Create a simple hex file with correct checksums
        // Line 1: Extended Linear Address (0x0000)
        // Line 2: Data record at address 0x0000 with 4 bytes
        // Line 3: End of File
        let hex_content = b":020000040000FA\n:0400000001020304F2\n:00000001FF\n";

        let loader = IhexLoader;
        let mut desc = loader
            .load_bytes(
                Cow::Borrowed(hex_content),
                HashMap::new(),
                &Config::default(),
            )
            .unwrap();

        let regions = desc.take_memory_regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].base(), 0);
        assert_eq!(regions[0].size(), 4);
    }

    #[test]
    fn test_merge_regions() {
        let mut data_map = BTreeMap::new();
        data_map.insert(0x0000, vec![0x01, 0x02]);
        data_map.insert(0x0002, vec![0x03, 0x04]);
        data_map.insert(0x0004, vec![0x05, 0x06]);
        data_map.insert(0x0100, vec![0x07, 0x08]);

        let regions = IhexLoader::merge_regions(data_map);

        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].0, 0x0000);
        assert_eq!(regions[0].1, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(regions[1].0, 0x0100);
        assert_eq!(regions[1].1, vec![0x07, 0x08]);
    }

    #[test]
    fn test_pc_hint_requires_arch() {
        // Create a simple hex file with data and EOF
        let hex_content = b":020000040000FA\n:0400000001020304F2\n:00000001FF\n";

        let loader = IhexLoader;

        // Test: PC hint without arch hint should error
        let mut hints = HashMap::new();
        hints.insert(
            Box::from("pc"),
            Box::new(0x8000u64) as Box<dyn std::any::Any>,
        );

        let result = loader.load_bytes(Cow::Borrowed(hex_content), hints, &Config::default());
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("arch hint is missing"));
    }

    #[test_case(
        vec![(0x0000, vec![0x01, 0x02]), (0x0002, vec![0x03, 0x04])],
        vec![(0x0000, vec![0x01, 0x02, 0x03, 0x04])]
        ; "two contiguous regions merge into one"
    )]
    #[test_case(
        vec![(0x0000, vec![0x01, 0x02]), (0x0003, vec![0x03, 0x04])],
        vec![(0x0000, vec![0x01, 0x02]), (0x0003, vec![0x03, 0x04])]
        ; "two non-contiguous regions remain separate"
    )]
    #[test_case(
        vec![(0x0000, vec![0x01]), (0x0001, vec![0x02]), (0x0002, vec![0x03])],
        vec![(0x0000, vec![0x01, 0x02, 0x03])]
        ; "multiple single-byte contiguous regions merge"
    )]
    #[test_case(
        vec![],
        vec![]
        ; "empty input produces empty output"
    )]
    #[test_case(
        vec![(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD])],
        vec![(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD])]
        ; "single region passes through unchanged"
    )]
    fn test_merge_regions_parameterized(input: Vec<(u64, Vec<u8>)>, expected: Vec<(u64, Vec<u8>)>) {
        let mut data_map = BTreeMap::new();
        for (addr, data) in input {
            data_map.insert(addr, data);
        }

        let regions = IhexLoader::merge_regions(data_map);
        assert_eq!(regions, expected);
    }

    #[test_case(
        vec![(0x0000, 2), (0x0002, 2), (0x0004, 2), (0x0100, 2)],
        vec![(0x0000, 6), (0x0100, 2)]
        ; "contiguous regions with gap"
    )]
    #[test_case(
        vec![(0x0000, 4), (0x0008, 4), (0x0010, 4)],
        vec![(0x0000, 4), (0x0008, 4), (0x0010, 4)]
        ; "all separate regions with gaps"
    )]
    #[test_case(
        vec![(0x0000, 100), (0x0064, 100), (0x00C8, 100)],
        vec![(0x0000, 300)]
        ; "large contiguous regions"
    )]
    fn test_merge_regions_with_sizes(
        input: Vec<(u64, usize)>,
        expected_regions: Vec<(u64, usize)>,
    ) {
        let mut data_map = BTreeMap::new();
        for (addr, size) in input {
            let data = vec![0xFF; size];
            data_map.insert(addr, data);
        }

        let regions = IhexLoader::merge_regions(data_map);

        assert_eq!(regions.len(), expected_regions.len());
        for (i, (expected_addr, expected_size)) in expected_regions.iter().enumerate() {
            assert_eq!(regions[i].0, *expected_addr);
            assert_eq!(regions[i].1.len(), *expected_size);
        }
    }
}
