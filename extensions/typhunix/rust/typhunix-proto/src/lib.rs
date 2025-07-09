// SPDX-License-Identifier: BSD-2-Clause
//! Typhunix protocol and library

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fs::File, io::Write, num::ParseIntError};
use styx_emulator::grpc::typhunix_interop::symbolic::{
    DataType, Function, FunctionParameter, Program, Symbol,
};
use styx_emulator::grpc::typhunix_interop::ProgramRef as _;

pub mod cache;
pub mod grpc_async_client;
pub mod grpc_sync_client;
pub mod symboldb;
pub mod test_utils;

pub type GrpcEndpoint = tonic::transport::Endpoint;
pub type ProgKeyType = (String, String);

pub trait ProgramRef: Send + Sync + 'static {
    fn get_program_key(&self) -> ProgKeyType;

    fn get_source_id(&self) -> String {
        self.get_program_key().0
    }

    fn get_program_name(&self) -> String {
        self.get_program_key().1
    }
}

pub trait Validator: Send + Sync + 'static {
    fn is_valid(&self) -> bool;
}

#[derive(Clone)]
pub struct DataTypeC {
    pub inner: DataType,
}

impl From<DataType> for DataTypeC {
    fn from(d: DataType) -> Self {
        DataTypeC { inner: d }
    }
}

impl std::hash::Hash for DataTypeC {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.id.hash(state);
        self.inner.name.hash(state);
    }
}

impl std::cmp::PartialEq for DataTypeC {
    fn eq(&self, other: &DataTypeC) -> bool {
        self.inner == other.inner
    }
}

impl std::cmp::Eq for DataTypeC {}

#[derive(Clone)]
pub struct ProgramC {
    pub inner: Program,
}

impl From<Program> for ProgramC {
    fn from(d: Program) -> Self {
        ProgramC { inner: d }
    }
}

impl std::hash::Hash for ProgramC {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.get_source_id().hash(state);
        self.inner.get_program_name().hash(state);
    }
}

impl std::cmp::PartialEq for ProgramC {
    fn eq(&self, other: &ProgramC) -> bool {
        self.inner == other.inner
    }
}

impl std::cmp::Eq for ProgramC {}

/// format an address "0x00000000", zero-padded to 8 digs, with "0x" prefix
#[inline]
pub fn fmt_address<T>(n: T) -> String
where
    T: std::fmt::LowerHex,
{
    format!("{:#010x}", n)
}

/// Convert the hex string "0x00000000" to u64
pub fn address_to_u64(addr: &str) -> Result<u64, ParseIntError> {
    let buf = String::from(addr);
    u64::from_str_radix(buf.trim_start_matches("0x"), 16)
}

/// Convert the hex string "-0x00000000" to i64
pub fn address_to_i64(addr: &str) -> Result<i64, ParseIntError> {
    let buf = String::from(addr);
    let is_neg = buf.starts_with('-');
    let mut raw = String::from(buf.trim_start_matches(if is_neg { "-0x" } else { "0x" }));
    if is_neg {
        raw.insert(0, '-');
    }
    i64::from_str_radix(raw.as_str(), 16)
}

/// JSON-serialize address fields as "0x00000000"
pub fn i64_addr_ser_hex_str8<S>(addr: &i64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(fmt_address(addr).as_str())
}

/// JSON-serialize address fields as "0x00000000"
pub fn u64_addr_ser_hex_str8<S>(addr: &u64, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(fmt_address(addr).as_str())
}

/// JSON-deserialize address fields "0x00000000" as i64 base 10
pub fn i64_addr_deser_hex_str8<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    address_to_i64(String::deserialize(deserializer)?.as_str()).map_err(serde::de::Error::custom)
}

/// JSON-deserialize address fields "0x00000000" as u64 base 10
pub fn u64_addr_deser_hex_str8<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    address_to_u64(String::deserialize(deserializer)?.as_str()).map_err(serde::de::Error::custom)
}

/// write symbols/datatypes to a file
/// Note: address fields are i64, but serialized as 0x00000000 strings
/// See: [`crate::i64_addr_ser_hex_str8`], [`crate::u64_addr_ser_hex_str8`]
pub fn serialize_to_file<T>(items: &[T], filename: String) -> Result<(), Box<dyn std::error::Error>>
where
    T: Serialize,
{
    let mut file = File::create(filename.as_str())?;
    for item in vec_to_json_strings(items)?.iter() {
        file.write_all(item.as_bytes())?;
    }
    Ok(())
}

/// given the vec of items, serialize as json to a vec of Strings
pub fn vec_to_json_strings<T>(items: &[T]) -> Result<Vec<String>, Box<dyn std::error::Error>>
where
    T: Serialize,
{
    let mut result: Vec<String> = Vec::new();
    for item in items.iter() {
        result.push(serde_json::to_value(item).unwrap().to_string());
    }
    Ok(result)
}

pub trait HasFunctions: Send + Sync + 'static {
    fn functions(&self) -> Vec<Function>;
}

pub trait AddrUtils: Send + Sync + 'static {
    fn addr_start(&self) -> u32;
    fn addr_end(&self) -> u32;
    fn contains(&self, addr: u32) -> bool;
}

pub trait SymbolUtils: Send + Sync + 'static {
    fn name(&self) -> String;
    fn short_display(&self) -> String;
}

pub trait FuncUtils: Send + Sync + 'static {
    fn symbol(&self) -> &Symbol;
    fn parameters(&self) -> Vec<FunctionParameter>;
}

pub trait Signature: Send + Sync + 'static {
    fn signature(&self) -> String;
}

pub trait AddrIn: Send + Sync + 'static {
    fn contains(&self, addr: u64) -> bool;
}

#[cfg(test)]
mod tests {
    use styx_emulator::grpc::typhunix_interop::symbolic::{symbol::SymbolType, ProgramIdentifier};
    use styx_emulator::grpc::typhunix_interop::Validator as _;

    use super::*;
    use std::collections::HashSet;
    use test_utils::random_program_identifier;

    #[test]
    fn test_data_type_wrapper() {
        let dt = DataType {
            pid: Some(random_program_identifier()),
            id: 12345,
            name: "foo".to_string(),
            ..Default::default()
        };
        assert!(dt.is_valid());
        let dt_cloned = dt.clone();
        let d = DataTypeC { inner: dt };
        assert!(d.inner.is_valid());
        let mut hs = HashSet::new();
        hs.insert(d.to_owned());
        assert!(hs.contains(&d));

        let d2 = DataTypeC::from(dt_cloned);
        // this is valid, but already in the map
        assert!(d2.inner.is_valid());
        assert!(hs.contains(&d2));
    }

    #[test]
    fn test_fmt_symbol() {
        let s = Symbol {
            name: "name".to_string(),
            id: 22,
            namespace: "Global".to_string(),
            pid: Some(ProgramIdentifier {
                source_id: "3524900975211717990".to_string(),
                name: "xyz.bin".to_string(),
            }),
            address: 0xdead,
            datatype_name: "dtname".to_string(),
            r#type: i32::from(SymbolType::SymbolLabel),
            ..Default::default()
        };
        let sstr = format!("{}", s);
        println!("{}", sstr);
    }

    #[test]
    fn test_hex_fmts() {
        assert_eq!(fmt_address(0x0), "0x00000000");
        assert_eq!(fmt_address(0x1), "0x00000001");
        assert_eq!(fmt_address(0xffff), "0x0000ffff");
        assert_eq!(fmt_address(0xFFFFFFFF_u64), "0xffffffff");
    }

    #[test]
    fn test_hex_str_to_num() {
        // test hex address to u64
        assert_eq!(address_to_u64("0x00000000").unwrap(), 0_u64);
        assert_eq!(address_to_u64("0x0").unwrap(), 0_u64);
        assert_eq!(address_to_u64("0xf").unwrap(), 15_u64);
        assert_eq!(address_to_u64("0x01").unwrap(), 1_u64);
        assert_eq!(address_to_u64("0xffff").unwrap(), 0xffff_u64);
        assert_eq!(address_to_u64("0xFFFFFFFF").unwrap(), 0xFFFFFFFF_u64);
        // text hex address to i64
        assert_eq!(address_to_i64("0xf").unwrap(), 15_i64);
        assert_eq!(address_to_i64("-0xf").unwrap(), -15_i64);
    }
}
