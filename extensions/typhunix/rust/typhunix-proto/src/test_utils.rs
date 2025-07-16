// SPDX-License-Identifier: BSD-2-Clause
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
