// SPDX-License-Identifier: BSD-2-Clause
//! json utilities for typhunix GRPC messages

use futures_lite::io::AsyncWriteExt;
use log::warn;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use super::ConnectMessage;
use crate::symbolic::{DataType, Symbol};

/// Deserialize the ConnectMessage from the file path
#[inline]
pub async fn connect_msg_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<ConnectMessage, Box<dyn Error>> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

/// Deserialize the symbol array from the file
#[inline]
pub async fn symbols_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<Symbol>, Box<dyn Error>> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

/// Deserialize the data type array from the file
#[inline]
pub async fn data_types_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<DataType>, Box<dyn Error>> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

/// write symbols/datatypes to a file - truncates if it exists
/// Note: address fields are i64, but serialized as 0x00000000 strings
/// See: [`crate::i64_addr_ser_hex_str8`], [`crate::u64_addr_ser_hex_str8`]
pub async fn dump_to_file<'de, T>(items: &Vec<T>, filename: String) -> Result<(), Box<dyn Error>>
where
    T: Serialize,
{
    let mut file = async_fs::File::create(filename.as_str()).await?;
    file.write_all(serde_json::to_value(items).unwrap().to_string().as_bytes())
        .await?;
    eprintln!("DUMPED: {}", filename.as_str());
    Ok(())
}

/// Serialize a [ConnectMessage] to json and write to the file.
/// Overwrites the file if it exists.
pub async fn dump_connect_message<P: AsRef<Path>>(
    path: P,
    msg: &ConnectMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    // truncates if it exists
    let mut file = async_fs::File::create(path).await?;
    match serde_json::to_string_pretty(msg) {
        Ok(s) => {
            let b = s.as_bytes();
            println!("nbytes={}", b.len());
        }
        Err(e) => {
            warn!("failed to serialize ConnectMesssage: {}", e);
        }
    }
    file.write_all(
        serde_json::to_string_pretty(msg)
            .unwrap()
            .to_string()
            .as_bytes(),
    )
    .await?;
    file.flush().await?;
    Ok(())
}
