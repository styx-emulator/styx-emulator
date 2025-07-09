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

use cxx::let_cxx_string;
use styx_sleigh_bindings::ffi;

/// Compile a `slaspec` to a `sla`.
///
/// The `infile` should be a `.slaspec` file. The `outfile` should be a `.sla`.
/// A nonzero return indicates an error.
///
/// Refer to `SleighCompile.run_compilation()` in the ghidra sources for exact
/// details.
pub fn compile(infile: impl AsRef<Path>, outfile: impl AsRef<Path>) -> Result<(), CompileError> {
    let infile = infile.as_ref();
    let outfile = outfile.as_ref();
    // check input file exists and is file
    check_infile(infile)?;
    check_outfile(outfile)?;

    let_cxx_string!(infile_cxxstring = infile.as_os_str().as_encoded_bytes());
    let_cxx_string!(outfile_cxxstring = outfile.as_os_str().as_encoded_bytes());

    let mut compiler = ffi::new_sleigh_compile();
    let result = compiler
        .as_mut()
        .unwrap()
        .run_compilation(&infile_cxxstring, &outfile_cxxstring);

    // run_compilation() only returns 0 for success and 2 for failure with no error introspection
    match result {
        0 => Ok(()),
        _ => Err(CompileError::UnknownError),
    }
}

fn check_infile(infile: &Path) -> Result<(), CompileError> {
    let input_meta = std::fs::metadata(infile).map_err(|_| CompileError::CantOpenInputFile)?;
    if !input_meta.is_file() {
        return Err(CompileError::CantOpenInputFile);
    }

    Ok(())
}

fn check_outfile(outfile: &Path) -> Result<(), CompileError> {
    std::fs::metadata(outfile.parent().ok_or(CompileError::CantCreateOutputFile)?)
        .map_err(|_| CompileError::CantCreateOutputFile)?;

    Ok(())
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CompileError {
    #[error("can't create output file")]
    CantCreateOutputFile,
    #[error("can't open input file")]
    CantOpenInputFile,
    #[error("unknown error during sla compilation")]
    UnknownError,
}

#[cfg(test)]
mod tests {
    use std::env::temp_dir;
    use styx_util::bytes_to_tmp_file;

    use super::*;

    #[test]
    fn test_no_input_file() {
        let temp_file = bytes_to_tmp_file(&[]);
        let temp_dir = temp_dir();
        let temp_file_path = temp_file.path().to_owned();
        drop(temp_file); // remove temp file, file no longer available

        let result = compile(&temp_file_path, temp_dir.join("out.sla"));
        assert_eq!(result, Err(CompileError::CantOpenInputFile));
    }

    #[test]
    fn test_no_output_directory() {
        let temp_file = bytes_to_tmp_file(&[]);

        let result = compile(&temp_file, "/directory-that-does-not-exist/out.sla");
        assert_eq!(result, Err(CompileError::CantCreateOutputFile));
    }
}
