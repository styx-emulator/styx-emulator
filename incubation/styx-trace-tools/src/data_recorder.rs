// SPDX-License-Identifier: BSD-2-Clause
//! (temporary) with utilities for saving various trace execution artifacts
//!
//! This should get replaced with a database

use crate::emu_observer::EmulationObserver;
use crate::util::{output_dst, truncate, OutDst};
use crate::variable::Variable;
use std::path::Path;
use styx_core::grpc::typhunix_interop::Signature;

const VARIABLES_JSON: &str = "variables.json";
const MEMORY: &str = "memory.bin";
const CALLSTACK: &str = "callstack.txt";
const OVERFLOW_ERRORS_JSON: &str = "overflow_errors.json";

pub struct DataRecorder {
    pub directory_root_path: String,
}

impl DataRecorder {
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let directory_root_path = String::from(path.as_ref().to_str().unwrap());
        std::fs::create_dir_all(path)?;
        let data_recorder = Self {
            directory_root_path,
        };
        data_recorder.init();
        Ok(data_recorder)
    }

    pub fn init(&self) {
        for p in &[VARIABLES_JSON, CALLSTACK, OVERFLOW_ERRORS_JSON, MEMORY] {
            truncate(&self.path_for(p));
        }
    }

    pub fn path_for(&self, basename: &str) -> String {
        format!("{}/{}", self.directory_root_path, basename)
    }

    // write overflow errors to a file or stdout
    pub fn dump_overflow_errors(
        &self,
        _: &EmulationObserver,
        _: OutDst,
    ) -> Result<(), std::io::Error> {
        // let mut out_dst = output_dst(dst)?;
        // log::info!("Dump overflow errors ... ");
        // let mut hm: HashMap<String, serde_json::value::Value> = HashMap::new();
        // let vars = emu.variables.lock().unwrap();
        // vars.values().for_each(|v| if v.overflow_count > 0 {});

        // emu.variables
        //     .lock()
        //     .unwrap()
        //     .values()
        //     .cloned()
        //     .collect::<Vec<Variable>>()
        //     .iter()
        //     .for_each(|sc| {
        //         if sc.overflow_count > 0 {
        //             let k = format!(
        //                 "{}_{}_{}",
        //                 sc.datatype.r#type(),
        //                 sc.datatype.name,
        //                 sc.symbol.name()
        //             );

        //             let _ = hm.insert(
        //                 k,
        //                 serde_json::json!({
        //                     "symbol": sc.symbol,
        //                     "datatype": sc.datatype,
        //                     "total_overflows": sc.overflow_count,
        //                     "errors": sc.mem_overflow_errors.clone()}
        //                 ),
        //             );
        //         }
        //     });

        // let msg = json!({
        //     "overflow_errors": hm,
        // });

        // Ok(writeln!(out_dst, "{}", msg)?)
        Ok(())
    }

    // write callstack errors to a file or stdout
    fn dump_callstack(&self, emu: &EmulationObserver) -> Result<(), std::io::Error> {
        let csfile = self.path_for(CALLSTACK);
        let dst = OutDst::File(&csfile);
        self.dump_overflow_errors(emu, OutDst::File(&self.path_for(OVERFLOW_ERRORS_JSON)))
            .unwrap_or_else(|e| {
                eprintln!("{e}");
            });

        let mut out_dst = output_dst(dst)?;
        let mut i = 0;
        writeln!(out_dst, "\nStack:")?;
        while let Some(func) = emu.fun_stack.pop() {
            writeln!(out_dst, " => {:05}:  {}", i, func.signature())?;
            i += 1;
        }

        Ok(())
    }

    pub fn finalize(
        &self,
        emu: &EmulationObserver,
        dump_vars: bool,
        dump_overflows: bool,
        dump_callstack: bool,
        dump_memory: bool,
    ) {
        if dump_memory {
            emu.memory.read().unwrap().dump(&self.path_for(MEMORY));
        }

        if dump_vars {
            // for sc in emu.variables.lock().unwrap().values() {
            //     sc.pprint(OutDst::FileAppend(&self.path_for(SYMBOL_VALUES)))
            //         .unwrap_or_else(|e| {
            //             eprintln!("Error: with symbol_values.txt: {e}");
            //         });
            // }
            let mut out = output_dst(OutDst::File(&self.path_for(VARIABLES_JSON))).unwrap();
            writeln!(out, "[").unwrap();
            let vars = emu.variables.read().unwrap();
            let len = vars.len();

            let _ = vars
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let json_str = v.json();
                    if i < (len - 1) {
                        writeln!(out, "{json_str},").unwrap();
                    } else {
                        writeln!(out, "{json_str}]").unwrap();
                    }
                })
                .collect::<Vec<()>>();
        }
        if dump_callstack {
            self.dump_callstack(emu).unwrap();
        }
        if dump_overflows {
            self.dump_overflow_errors(emu, OutDst::File(&self.path_for(OVERFLOW_ERRORS_JSON)))
                .unwrap_or_else(|e| {
                    eprintln!("dump_overflow_erros failed{e}");
                });
        }
    }
}

use std::error::Error;
use std::fs::File;
use std::io::BufReader;

/// Deserialize the ConnectMessage from the file path
#[inline]
pub async fn get_variables<P: AsRef<Path>>(path: P) -> Result<Vec<Variable>, Box<dyn Error>> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}
