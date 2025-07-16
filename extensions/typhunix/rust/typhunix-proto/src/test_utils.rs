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
//! utilities for generating test data

use styx_emulator::grpc::typhunix_interop::{
    symbolic::{symbol::SymbolType, Program, ProgramIdentifier, Symbol},
    ProgramRef,
};

use rand::Rng;

pub fn new_program(program_id: &str, name: &str) -> Program {
    Program {
        pid: Some(ProgramIdentifier {
            source_id: program_id.to_owned(),
            name: name.to_owned(),
        }),
        ..Default::default()
    }
}

pub fn random_program() -> Program {
    let mut rng = rand::thread_rng();
    let pgm_str = format!("{}", rng.gen_range(0..3));
    let pid = format!("pid:{pgm_str:0>8} ");
    let pname = format!("pname:{pgm_str}");
    Program {
        pid: Some(ProgramIdentifier {
            source_id: pid,
            name: pname,
        }),
        ..Default::default()
    }
}

pub fn random_program_identifier() -> ProgramIdentifier {
    let p = random_program();
    ProgramIdentifier {
        source_id: p.get_source_id(),
        name: p.get_program_name(),
    }
}

pub fn random_symbol_no_program() -> Symbol {
    let mut rng = rand::thread_rng();
    let symbol_name = format!("SYM_{:0>4}", rng.gen_range(5..10000));

    Symbol {
        name: symbol_name,
        datatype_name: "ushort".to_string(),
        address: rng.gen_range(0xf..0xff),
        id: rng.gen_range(0xff..0xffff),
        namespace: "Global".to_string(),
        r#type: SymbolType::SymbolLabel.into(),
        ..Default::default()
    }
}

pub fn random_symbol_with_program() -> Symbol {
    let mut rng = rand::thread_rng();
    let symbol_name = format!("SYM_{:0>4}", rng.gen_range(5..10000));

    Symbol {
        name: symbol_name,
        datatype_name: "ushort".to_string(),
        address: rng.gen_range(0xf..0xff),
        id: rng.gen_range(0xff..0xffff),
        namespace: "Global".to_string(),
        r#type: SymbolType::SymbolLabel.into(),
        pid: Some(random_program_identifier()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_random_symbol() {
        assert!(random_symbol_no_program().pid.is_none());
        assert!(random_symbol_with_program().pid.is_some());
    }
}
