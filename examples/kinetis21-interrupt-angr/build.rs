// SPDX-License-Identifier: BSD-2-Clause
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
                || format!("unable to link {:?}", fpath),
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
