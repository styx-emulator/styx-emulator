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
//! build tool for [styx_grpc](crate)

use std::collections::HashSet;
use std::path::PathBuf;

/// Serialize <i64>.address as String::"0x00000000"
const I64_ADDR_SERIALIZE_AS_HEX_STR: &str =
    r#"#[serde(serialize_with = "crate::i64_addr_ser_hex_str8")]"#;
/// Serialize <u64>.address as String::"0x00000000"
const U64_ADDR_SERIALIZE_AS_HEX_STR: &str =
    r#"#[serde(serialize_with = "crate::u64_addr_ser_hex_str8")]"#;

/// Derialize <i64>.address String::"0x0000000f" to `i64` 15 (base 10)
const I64_ADDR_DESERIALIZE_AS_I64: &str =
    r#"#[serde(deserialize_with = "crate::i64_addr_deser_hex_str8")]"#;

/// Derialize <u64>.address String::"0x0000000f" to `u64` 15 (base 10)
const U64_ADDR_DESERIALIZE_AS_U64: &str =
    r#"#[serde(deserialize_with = "crate::u64_addr_deser_hex_str8")]"#;

/// Derive Serialize
const DERIVE_SER: &str = "#[derive(serde::Serialize)]";
/// Derive Serialize
const DERIVE_DESER: &str = "#[derive(serde::Deserialize)]";

/// Derive TyphunixPyo3
const DERIVE_TYPHUNIX_PYO3: &str = r#"
    #[cfg_attr(feature = "pyo3_bindings", derive(typhunix_macros::TyphunixPyo3))]
    "#;
/// Derive pyo3 pyclass
const DERIVE_PYO3_PYCLASS_STRUCT: &str = r#"
    #[cfg_attr(feature = "pyo3_bindings", pyo3::prelude::pyclass(get_all))]
    "#;

/// Derive pyo3 pyclass for enums
const DERIVE_PYO3_PYCLASS_ENUM: &str = r#"
    #[cfg_attr(feature = "pyo3_bindings", pyo3::prelude::pyclass(get_all, eq, eq_int))]
    "#;

/// find/return all files that match the glob pattern, and a
/// unique list of directories to watch for changes
fn find_protos2(globs: &[&str]) -> (Vec<String>, Vec<String>) {
    let mut pbufs: Vec<PathBuf> = vec![];
    let mut dirs: HashSet<String> = HashSet::new();
    let mut files: HashSet<String> = HashSet::new();
    for gp in globs {
        for pbuf in glob::glob(gp).unwrap() {
            pbufs.push(pbuf.unwrap());
        }
    }
    for pb in pbufs.iter() {
        let file_name = pb.file_name().unwrap().to_str().unwrap();
        let dirname = pb.parent().unwrap();
        files.insert(file_name.to_string());
        dirs.insert(dirname.to_str().unwrap().to_string());
    }
    (
        files.iter().cloned().collect::<Vec<String>>(),
        dirs.iter().cloned().collect::<Vec<String>>(),
    )
}

fn main() {
    // Get a list of all proto files and a unique set of directories where
    // the proto files reside.
    let (proto_files, proto_dirs) = find_protos2(&["../../idl/proto/**/*.proto"]);

    let hash_items = &[
        ".emulation_registry.SupportedConfig",
        ".emulation_registry.Config",
        ".emulation_registry.ArchIdentity",
        ".emulation_registry.EndianIdentity",
        ".emulation_registry.VariantIdentity",
        ".emulation_registry.BackendIdentity",
        ".emulation_registry.LoaderIdentity",
    ];

    // here we don't specify an out directory intentionally,
    // this allows easier namespacing of the generated gRPC
    // definitions (see `lib.rs` for the implementation)
    let mut builder = tonic_build::configure()
        .build_client(true)
        .build_server(true)
        // emit_rerun_if_changed seems to be on by default now, and it is
        // re-running every time - set to false until it works
        .emit_rerun_if_changed(false);

    builder = builder
        // Derive pyo3 for items in symbolic
        .type_attribute(".symbolic", DERIVE_TYPHUNIX_PYO3)
        .message_attribute(".symbolic", DERIVE_PYO3_PYCLASS_STRUCT)
        .enum_attribute(".symbolic", DERIVE_PYO3_PYCLASS_ENUM)
        // Derive serde SeDe for all items, including google protobufbuilt-in types
        .type_attribute(".", DERIVE_SER)
        .type_attribute(".", DERIVE_DESER)
        // to get google built-in types plus serde, need the following two lines
        .extern_path(".google.protobuf", "::prost_wkt_types")
        .compile_well_known_types(true)
        // Args: derive clap helpers for using any item in args as clas cli args
        .type_attribute(".args", "#[styx_macros_args::styx_args]")
        // Field Attributes
        .field_attribute("Symbol.address", I64_ADDR_SERIALIZE_AS_HEX_STR)
        .field_attribute("Symbol.address", I64_ADDR_DESERIALIZE_AS_I64)
        .field_attribute("Segment.address", I64_ADDR_SERIALIZE_AS_HEX_STR)
        .field_attribute("Segment.address", I64_ADDR_DESERIALIZE_AS_I64)
        .field_attribute("BasicBlock.address", U64_ADDR_SERIALIZE_AS_HEX_STR)
        .field_attribute("BasicBlock.address", U64_ADDR_DESERIALIZE_AS_U64)
        .field_attribute("FunctionSymbol.last_insn", I64_ADDR_SERIALIZE_AS_HEX_STR)
        .field_attribute("FunctionSymbol.last_insn", I64_ADDR_DESERIALIZE_AS_I64)
        .build_client(true)
        .build_server(true)
        // emit_rerun_if_changed seems to be on by default now, and it is
        // re-running every time - set to false until it works
        .emit_rerun_if_changed(false);

    // derive for Hash
    for item in hash_items.iter() {
        builder = builder.type_attribute(item, "#[derive(Eq, Hash)]");
    }

    // compile and panic if it fails
    builder
        .compile_protos(&proto_files, &proto_dirs)
        .unwrap_or_else(|e| panic!("protobuf compile error: {}", e));

    // emit directory names where we found proto files - this seems to work well
    // for new files, deleted files, changed files.
    for dir in proto_dirs.iter() {
        println!("cargo:rerun-if-changed={}", dir);
    }
}
