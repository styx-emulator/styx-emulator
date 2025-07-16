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
use std::error::Error;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;
use styx_core::util::resolve_path;

fn main() {
    println!("Cargo:rerun-if-changed=bin/");

    let binaries = &["proc", "hackme"];

    for bin in binaries {
        let bin_path = resolve_path(&format!(
            "data/test-binaries/arm/kinetis_21/bin/interrupt_{bin}/interrupt_{bin}_debug.bin"
        ));
        let elf_path = resolve_path(&format!(
            "data/test-binaries/arm/kinetis_21/bin/interrupt_{bin}/interrupt_{bin}_debug.elf"
        ));

        for fpath in &[bin_path, elf_path] {
            let filename_pathbuf = PathBuf::from(fpath);
            let filename = format!(
                "./bin/{}",
                filename_pathbuf.file_name().unwrap().to_str().unwrap()
            );
            let link_path = &fpath;

            println!("Cargo:rerun-if-changed={fpath}");
            remove_file(&filename).unwrap_or_else(|_| panic!("Failed to remove: {filename}"));
            exec(
                Command::new("ln").arg("-s").arg(link_path).arg(&filename),
                || format!("unable to link {fpath:?}"),
            );
        }
    }
}

fn remove_file(fpath: &str) -> Result<(), Box<dyn Error>> {
    match std::fs::remove_file(fpath) {
        Ok(_) => Ok(()),
        Err(err) => {
            if err.kind() == ErrorKind::NotFound {
                Ok(())
            } else {
                Err(Box::new(err) as Box<dyn Error>)
            }
        }
    }
}

fn exec(command: &mut Command, msg: impl FnOnce() -> String) {
    match command.output() {
        Ok(output) if output.status.success() => (),
        Ok(output) => panic!(
            "(exited w/ {}): {}\n{}",
            output.status,
            msg(),
            String::from_utf8(output.stderr).unwrap()
        ),
        Err(e) => panic!("(error {e}): {}", msg()),
    };
}
