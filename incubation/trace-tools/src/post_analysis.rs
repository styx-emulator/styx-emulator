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
//! post_analysis - analyze artifacts from a styx trace session

use crate::compact_repr;
use crate::data_recorder::get_variables;
use crate::util::{output_dst, OutDst};
use std::{fs::File, io::Read};
use styx_core::grpc::typhunix_interop::AddrUtils;
use styx_core::sync::sync::atomic::Ordering::SeqCst;
use tracing::{debug, warn};

pub async fn post_analysis(dir: &str) -> Result<(), std::io::Error> {
    debug!("ptrace: post analysis, dir={}", dir);
    let memfilename = format!("{dir}/memory.bin");
    let mut mem_buffer: Vec<u8> = Vec::new();

    // From vars file
    {
        let path = format!("{dir}/post_analysis_from_vars.txt");
        let dst = OutDst::File(&path);
        let mut out = output_dst(dst)?;
        let vars = get_variables(format!("{dir}/variables.json"))
            .await
            .unwrap();
        for var in vars.iter() {
            // let num_writes = var.num_writes.fetch_add(0, SeqCst);
            // println!("{:?} {}", var.datatype.r#type(), num_writes,);

            // if num_writes > 0 {
            //     if let Err(e) = var.pprint(OutDst::StdOut) {
            //         eprintln!("Error: {e}");
            //         std::process::exit(1);
            //     }
            // }
            let (s_repr, b_repr, a_repr) = var.to_c_repr();
            if let Some(cstruct) = s_repr {
                let sym_start = var.symbol.addr_start() as usize;
                let sym_end = var.symbol.addr_end() as usize;
                let sym_size = sym_end - sym_start;

                writeln!(
                    out,
                    "\nstruct {} {}  [struct bounds: [{}..{}] {}, [mem: {}]",
                    cstruct,
                    compact_repr(&var.mem, 0, var.mem.len()),
                    sym_start,
                    sym_end,
                    sym_size,
                    var.mem.len(),
                )
                .unwrap();
                let (x, y) = (cstruct.members.len(), var.datatype.children.len());
                assert_eq!(x, y);
                let (x, y) = (sym_size, var.mem.len());
                assert_eq!(x, y);

                for (i, member) in cstruct.members.iter().enumerate() {
                    let dt = var.datatype.children.get(i).unwrap();
                    let beg_mbr_mem = dt.offset as usize;
                    let mut end_mbr_mem = beg_mbr_mem + dt.size as usize;
                    if end_mbr_mem > var.mem.len() {
                        warn!("overflow: [{}..{}]", beg_mbr_mem, end_mbr_mem);
                        end_mbr_mem = var.mem.len();
                    }
                    if end_mbr_mem <= beg_mbr_mem {
                        warn!("Odd member: [{}..{}]", beg_mbr_mem, end_mbr_mem);
                        continue;
                    }
                    let mem_slice = &var.mem[beg_mbr_mem..end_mbr_mem];
                    let cr = compact_repr(mem_slice, 0, mem_slice.len());
                    if let Some(ref cvar_repr) = member.var {
                        writeln!(
                            out,
                            "    {} ==> {}  (( {} ))",
                            cvar_repr, member.repr_val, cr
                        )
                        .unwrap();
                    }
                }
            } else if let Some(cbasic) = b_repr {
                let sym_start = var.symbol.addr_start() as usize;
                let sym_end = var.symbol.addr_end() as usize;
                let sym_size = sym_end - sym_start;

                writeln!(
                    out,
                    "\nbasic {} {}  [BASIC bounds: [{}..{}] {}, [mem: {}]",
                    cbasic,
                    compact_repr(&var.mem, 0, var.mem.len()),
                    sym_start,
                    sym_end,
                    sym_size,
                    var.mem.len(),
                )
                .unwrap();
                if let Some(ref cvar_repr) = cbasic.var {
                    // println!("    {} ==> {}  (( {} ))", cvar_repr, member.repr_val, cr);
                    writeln!(
                        out,
                        "    {} ==> {}",
                        cvar_repr,
                        compact_repr(&var.mem, 0, var.mem.len())
                    )
                    .unwrap();
                }
            } else if let Some(carray) = a_repr {
                writeln!(out, "{carray:?}").unwrap();
            } else {
                eprintln!("Error: unhandled var");
                std::process::exit(1);
            }
        }
    }
    // from memory dump
    let path = format!("{dir}/post_analysis_from_mem.txt");
    let dst = OutDst::File(&path);
    let mut out = output_dst(dst)?;

    {
        let (_, vars) = {
            let (r1, r2) = futures::join!(
                read_mem(&memfilename, &mut mem_buffer),
                get_variables(format!("{dir}/variables.json"))
            );
            (r1.unwrap(), r2.unwrap())
        };

        writeln!(
            out,
            "Memory: {}, Symbolic variables: {}",
            mem_buffer.len(),
            vars.len()
        )
        .unwrap();

        for var in vars.iter() {
            let num_writes = var.num_writes.fetch_add(0, SeqCst);
            if num_writes > 0 {
                writeln!(out, "==> {}", var.symbol).unwrap();
                writeln!(out, "    {} ", var.datatype).unwrap();
                writeln!(out, "    num_writes: {num_writes}").unwrap();
                writeln!(out, "    {:?}", compact_repr(&var.mem, 0, var.mem.len())).unwrap();
                writeln!(out, "    -").unwrap();
                let (start, end) = (
                    var.symbol.addr_start() as usize,
                    var.symbol.addr_end() as usize,
                );
                writeln!(out, "    {:?}\n", compact_repr(&mem_buffer, start, end)).unwrap();
                var.pprint(&mut out).unwrap();
            }
        }
    }
    Ok(())
}

async fn read_mem(memfilename: &str, mem_buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
    let mut file = File::open(memfilename).unwrap();
    let filesize = std::fs::metadata(memfilename)?.len();
    print!("Reading memory ({filesize} bytes) ... ");
    let n = file.read_to_end(mem_buffer)?;
    assert_eq!(n, filesize as usize);
    Ok(())
}
