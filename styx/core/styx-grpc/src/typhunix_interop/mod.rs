// SPDX-License-Identifier: BSD-2-Clause
//! All services relating to `styx_machines`

pub use super::symbolic;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fs::File, io::Write, num::ParseIntError};

tonic::include_proto!("typhunix_interop");
use symbolic::{Function, FunctionParameter, Symbol};

pub type GrpcEndpoint = tonic::transport::Endpoint;
pub type ProgKeyType = (String, String);
pub mod symbolic_impl;

// pub mod cache;
// pub mod grpc_async_client;
// pub mod grpc_sync_client;
pub mod json_util;
// pub mod symboldb;
// pub mod test_utils;

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
