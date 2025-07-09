// SPDX-License-Identifier: BSD-2-Clause
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
