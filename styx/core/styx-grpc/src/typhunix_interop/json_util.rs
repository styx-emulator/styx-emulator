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
pub async fn dump_to_file<T>(items: &Vec<T>, filename: String) -> Result<(), Box<dyn Error>>
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
            warn!("failed to serialize ConnectMesssage: {e}");
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
