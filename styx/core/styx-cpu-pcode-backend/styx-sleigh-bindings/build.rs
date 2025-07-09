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
use std::path::Path;

use glob::glob;

const SOURCE_FILES: &[&str] = &[
    "space.cc",
    "float.cc",
    "address.cc",
    "pcoderaw.cc",
    "translate.cc",
    "opcodes.cc",
    "globalcontext.cc",
    "capability.cc",
    "architecture.cc",
    "options.cc",
    "graph.cc",
    "cover.cc",
    "block.cc",
    "cast.cc",
    "typeop.cc",
    "database.cc",
    "cpool.cc",
    "comment.cc",
    "action.cc",
    "loadimage.cc",
    "varnode.cc",
    "op.cc",
    "type.cc",
    "variable.cc",
    "varmap.cc",
    "emulate.cc",
    "emulateutil.cc",
    "flow.cc",
    "userop.cc",
    "pcodeinject.cc",
    "prefersplit.cc",
    "double.cc",
    "condexe.cc",
    "override.cc",
    "dynamic.cc",
    "crc32.cc",
    "prettyprint.cc",
    "printlanguage.cc",
    "memstate.cc",
    "opbehavior.cc",
    "paramid.cc",
    "transform.cc",
    "stringmanage.cc",
    "loadimage_ghidra.cc",
    "inject_sleigh.cc",
    "sleigh_arch.cc",
    "sleigh.cc",
    "filemanage.cc",
    "semantics.cc",
    "slghsymbol.cc",
    "context.cc",
    "sleighbase.cc",
    "slghpatexpress.cc",
    "slghpattern.cc",
    "pcodecompile.cc",
    "xml.cc",
    "marshal.cc",
    "slaformat.cc",
    "compression.cc",
    "slgh_compile.cc",
    "slghparse.cc",
    "slghscan.cc",
];

fn main() {
    cxx_build::bridge("src/lib.rs")
        .flag_if_supported("-std=c++14") // Ghidra uses c++11, but we need c++14 for make_unique
        .include("sleigh/")
        .include("bridge/")
        .include("zlib/")
        .define("LOCAL_ZLIB", None) // these defines are used in the ghidra build system
        .define("NO_GZIP", None)
        .files(
            glob("zlib/*.c")
                .unwrap()
                .map(|zlib_file_result| zlib_file_result.unwrap()),
        )
        .files(
            SOURCE_FILES
                .iter()
                .map(|source_file_name| Path::new("sleigh").join(source_file_name)),
        )
        .file("bridge/bridge.cc")
        .warnings(false)
        .compile("sleigh");

    println!("cargo:rerun-if-changed=sleigh/");
    println!("cargo:rerun-if-changed=bridge/");
    println!("cargo:rerun-if-changed=zlib/");
    println!("cargo:rerun-if-changed=src/lib.rs");
}
