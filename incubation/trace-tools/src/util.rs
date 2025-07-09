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
//! Common utils used across trace execution analysis tools

use std::{fs::OpenOptions, io::Write, path::Path};
use styx_core::grpc::typhunix_interop::symbolic::ProgramIdentifier;
use tracing::debug;

/// Text based I/O utilities for writing to `stderr`, `stdout`, and/or files
pub mod io {
    use styx_core::tracebus::{BinaryTraceEventType, Traceable, TraceableItem};

    /// Output formats for the raw trace events
    #[derive(PartialEq, Eq, Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
    pub enum OutputFormat {
        /// text is Debug output: {:?}
        TEXT = 1,
        #[default]
        /// jsonl format - a line per event
        JSONL = 2,
        /// raw is binary
        RAW = 3,
    }

    impl From<String> for OutputFormat {
        fn from(s: String) -> Self {
            OutputFormat::from(s.as_str())
        }
    }

    impl From<Option<String>> for OutputFormat {
        fn from(s: Option<String>) -> Self {
            match s {
                Some(s) => OutputFormat::from(s.as_str()),
                _ => OutputFormat::JSONL,
            }
        }
    }

    impl From<&str> for OutputFormat {
        fn from(r: &str) -> Self {
            match r {
                "jsonl" => OutputFormat::JSONL,
                "text" => OutputFormat::TEXT,
                "raw" => OutputFormat::RAW,
                // sane
                _ => OutputFormat::JSONL,
            }
        }
    }

    /// Variants that can be returned by [writable](fn@writable)
    pub enum ReturnType {
        /// binary data - use for file-based output
        Binary(BinaryTraceEventType),
        /// JSON string
        Json(String),
        /// text string
        Text(String),
    }

    /// Return the item in the specified `OutputFormat`
    pub fn writable(item: TraceableItem, fmt: OutputFormat) -> ReturnType {
        match fmt {
            OutputFormat::JSONL => ReturnType::Json(item.json()),
            OutputFormat::TEXT => ReturnType::Text(item.text()),
            OutputFormat::RAW => ReturnType::Binary(*item.binary()),
        }
    }
}

#[derive(Clone)]
pub enum OutDst<'a> {
    File(&'a str),
    FileAppend(&'a str),
    StdErr,
    StdOut,
}

/// Truncate an existing file
pub fn truncate(path: &str) {
    let _ = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
}

/// Return dyn [Write] impl based on the input
pub fn output_dst(out: OutDst) -> Result<Box<dyn Write>, std::io::Error> {
    match out {
        OutDst::StdOut => Ok(Box::new(std::io::stdout()) as Box<dyn Write>),
        OutDst::StdErr => Ok(Box::new(std::io::stderr()) as Box<dyn Write>),
        OutDst::File(in_path_str) => Ok(Box::new(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(in_path_str)?,
        ) as Box<dyn Write>),
        OutDst::FileAppend(in_path_str) => match Path::new(in_path_str).exists() {
            true => {
                Ok(Box::new(OpenOptions::new().append(true).open(in_path_str)?) as Box<dyn Write>)
            }
            false => Ok(Box::new(OpenOptions::new().open(in_path_str)?) as Box<dyn Write>),
        },
    }
}

/// Get the Ghidra ProgramIdentifer from the environment
pub fn ghidra_program_id_from_env() -> Option<ProgramIdentifier> {
    if let Ok(v) = std::env::var("GHIDRA_SOURCE_PROJECT_ID") {
        let parts = v.split(',').collect::<Vec<&str>>();
        if parts.len() >= 2 {
            let pid = ProgramIdentifier::from((parts[0], parts[1]));
            debug!(
                "Using program symbols from GHIDRA_SOURCE_PROJECT_ID: {}",
                pid
            );
            Some(pid)
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_truncate_not_exist() {
        // file does not exist
        let filename = format!("/tmp/{}", uuid::Uuid::new_v4());
        assert!(!Path::new(&filename).exists());
        // truncate will create 0-byte file
        truncate(&filename);
        assert!(std::fs::metadata(filename.clone()).unwrap().len() == 0);
        // cleanup
        std::fs::remove_file(filename.clone()).unwrap();
        assert!(!Path::new(&filename).exists());
    }

    #[test]
    fn test_truncate_exists() {
        // file exists with data - it gets truncated
        let filename = format!("/tmp/{}", uuid::Uuid::new_v4());
        assert!(!Path::new(&filename).exists());
        {
            // create the file, put some data in it
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(filename.clone())
                .unwrap();
            file.write_all("hello world".as_bytes()).unwrap();
            drop(file);
        }
        // file exists with data
        assert!(std::fs::metadata(filename.clone()).unwrap().len() > 0);
        // truncate makes 0-byte file
        truncate(&filename);
        assert!(std::fs::metadata(filename.clone()).unwrap().len() == 0);
        // cleanup
        std::fs::remove_file(filename.clone()).unwrap();
        assert!(!Path::new(&filename).exists());
    }
}
