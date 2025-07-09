// SPDX-License-Identifier: BSD-2-Clause
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
