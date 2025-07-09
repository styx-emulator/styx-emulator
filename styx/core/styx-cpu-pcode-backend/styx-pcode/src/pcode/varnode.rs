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
use std::fmt::{Debug, Display};
use styx_cpu_type::ArchEndian;
use styx_sync::sync::Arc;

/// Pcode "variable" indicating space, offset, and size into memory.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VarnodeData {
    /// Name of the address space.
    pub space: SpaceName,
    /// Offset into the address space in bytes.
    pub offset: u64,
    /// Size of selection in bytes.
    pub size: u32,
}

impl Debug for VarnodeData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:02X}, {})", self.space, self.offset, self.size,)
    }
}

impl Display for VarnodeData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {}, {})", self.space, self.offset, self.size)
    }
}

/// Space identifier, agnostic to any particular cpu.
///
/// Most spaces are either register, ram, constant, or unique but theoretically a space can have any
/// name. Use [SpaceName::from<&str>] for an easy string -> space name conversion. This will try to
/// convert the string into an enum variant. If the string doesn't match any of the main space names
/// then a [SpaceName::Other] will be created with the custom name.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Clone)]
pub enum SpaceName {
    Register,
    Unique,
    Ram,
    Constant,
    Other(AddressSpaceName),
}

impl Display for SpaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut other_str;
        let string = match self {
            SpaceName::Register => "Register",
            SpaceName::Ram => "Ram",
            SpaceName::Constant => "Constant",
            SpaceName::Unique => "Unique",
            SpaceName::Other(name) => {
                other_str = "Other(".to_owned();
                other_str.push_str(name.as_ref());
                other_str.push(')');
                &other_str
            }
        };

        write!(f, "{}", &string)
    }
}

impl SpaceName {
    /// Attempt to match string with [SpaceName] enum, returns None if no match found.
    pub fn try_from_space(space: &str) -> Option<Self> {
        match space {
            "register" => Some(SpaceName::Register),
            "ram" => Some(SpaceName::Ram),
            "const" => Some(SpaceName::Constant),
            "unique" => Some(SpaceName::Unique),
            _ => None,
        }
    }
}

impl From<&str> for SpaceName {
    fn from(value: &str) -> Self {
        // try to convert to enum, fallback to an a string [AddressSpaceName]
        Self::try_from_space(value).unwrap_or(SpaceName::Other(AddressSpaceName::Owned(
            value.to_owned().into_boxed_str(),
        )))
    }
}

/// String name of an address space not covered in [SpaceName].
///
/// In essence, this enum is an abstraction around the ownership of underlying string. Because many
/// p-codes (with many varnodes) will be generated and passed around, performance around their data
/// structures should be considered. Having each varnode require a string allocation is not
/// efficient. An owned [Arc] with the string is more reasonable but is dependant on [Arc]
/// specifically. This enum allows for either solution in addition to future solutions that may be
/// better.
///
/// Get the string using its as_ref() function.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum AddressSpaceName {
    Owned(Box<str>),
    ReferenceCounted(Arc<str>),
}

impl AsRef<str> for AddressSpaceName {
    fn as_ref(&self) -> &str {
        match self {
            AddressSpaceName::ReferenceCounted(v) => v.as_ref(),
            AddressSpaceName::Owned(v) => v.as_ref(),
        }
    }
}

impl Display for AddressSpaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.as_ref(), f)
    }
}

impl PartialOrd for AddressSpaceName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.as_ref().cmp(other.as_ref()))
    }
}

impl Ord for AddressSpaceName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

#[derive(Debug)]
pub struct SpaceInfo {
    /// Number of bytes per address.
    ///
    /// This is usually 1. Only affects pointer arithmetic (Load/Store) because varnodes are
    /// represented as offsets.
    ///
    /// ## Offset vs Address
    /// Offset is an offset in bytes into the memory store. Address (as in load/store) is determined by
    /// the address space's word size.
    pub word_size: u64,
    /// Number of bytes in an address.
    ///
    /// Theoretical total space size is `2^address_size`
    pub address_size: u64,
    /// Endianness of this space, usually matches the processor endianness.
    pub endian: ArchEndian,
    /// Unique ID of space.
    pub id: SpaceId,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SpaceId {
    Integer(u64),
}

impl From<u64> for SpaceId {
    fn from(value: u64) -> Self {
        Self::Integer(value)
    }
}
