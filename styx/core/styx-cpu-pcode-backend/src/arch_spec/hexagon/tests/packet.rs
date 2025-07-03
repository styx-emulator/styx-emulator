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
use log::info;

use crate::arch_spec::hexagon::tests::*;

// can you mix a duplex instruction with some other stuff in a packet?
// (yes, this is tested somewhere here)
#[test]
fn test_packet_instructions() {
    // Packet instructions are interesting, as they are reordered to reflect the
    // appropriate slots and such.
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        "{ R1 = add(R0, #32); R2 = mpyi(R3, R4); R3 = add(R5, #10); }; ",
        None,
    );
    let r0 = 71;
    let r5 = 41272;
    let mult_opts = (92, 7);

    // truncate
    let initial_isa_pc = get_isa_pc(&mut cpu);
    trace!("initial isa pc is {}", initial_isa_pc);
    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R3, mult_opts.0)
        .unwrap();
    cpu.write_register(HexagonRegister::R4, mult_opts.1)
        .unwrap();
    cpu.write_register(HexagonRegister::R5, r5).unwrap();

    // Packet is 3 insns long, let's get the PC in the middle
    // and ensure it's not moving within a packet.
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    // truncate
    let mid_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(mid_isa_pc, initial_isa_pc);

    // let's now finish up. The no op is because styx internally only
    // sets the pc manager's isa pc at the start of the next instruction.
    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();

    // This *should* be the ISA PC
    let end_isa_pc = get_isa_pc(&mut cpu);

    assert_eq!(r1, r0 + 32);
    assert_eq!(r2, mult_opts.0 * mult_opts.1);
    assert_eq!(r3, r5 + 10);

    trace!("initial pc is {}, new pc is {}", initial_isa_pc, end_isa_pc);

    // TODO: test pc increment at end of packet
    assert_eq!(end_isa_pc - initial_isa_pc, 12);
}

struct PacketTestMetadata {
    no_regs: usize,
    asm: String,
    verify_fn: Box<dyn Fn(u32, u32, Vec<u32>)>,
    expected_length: usize,
    no_insns_to_exec: u64,
}

// TODO: want to also be able to check context options here, to make sure pktstart is set correctly
#[test]
fn test_all_packet_adjacent() {
    styx_util::logging::init_logging();
    // there are 7 types of packet combos (for now)
    // 1, 2, 3, 4 (sized, no duplex)
    // D, ID, IID (DD doesn't happen, the rest don't happen bc duplex must be slots 0 and 1, according to manual)
    //
    // what we will do:
    // { set } { P1 } { P2 }
    // { P1 } { P2 }
    //
    // at every insn, check the pkt start at the backend to make sure it's consistent with what we expect
    // we also make sure the results of the packets are what we expect.
    //
    // the extra set is to see if edge cases where we are handling the first packet given to the helper works properly.
    //
    // and check the backend to see if the pkt start is set correctly for
    // all combinations

    // tuples are: no of regs, asm, verify, and expected length in bytes, and no insns to exec
    // TODO: structify

    let init_pc = 0x1000u64;
    let ks = Keystone::new(
        keystone_engine::Arch::HEXAGON,
        keystone_engine::Mode::LITTLE_ENDIAN,
    )
    .expect("Could not initialize Keystone engine");
    let insns = vec![
        // packet IID
        PacketTestMetadata {
            no_regs: 4,
            asm: "{ %0 = add(r20, #299); %1 = mpyi(r21, r20); %2 = #10; %3 = #21;  }".to_owned(),
            verify_fn: Box::new(|r20: u32, r21: u32, regvec: Vec<u32>| {
                assert_eq!(regvec[0], r20 + 299);
                assert_eq!(regvec[1], r21 * r20);
                assert_eq!(regvec[2], 10);
                assert_eq!(regvec[3], 21);
            }) as Box<dyn Fn(u32, u32, Vec<u32>)>,
            expected_length: 12,
            no_insns_to_exec: 4,
        },
        // packet ID
        PacketTestMetadata {
            no_regs: 3,
            asm: "{ %0 = add(r20, #299); %1 = #10; %2 = #21; }".to_owned(),
            verify_fn: Box::new(|r20: u32, _r21: u32, regvec: Vec<u32>| {
                assert_eq!(regvec[0], r20 + 299);
                assert_eq!(regvec[1], 10);
                assert_eq!(regvec[2], 21);
            }),
            expected_length: 8,
            no_insns_to_exec: 3,
        },
        // packet D
        PacketTestMetadata {
            no_regs: 2,
            // NOTE: keystone had difficulties assembling stuff like {R4 = R21; R5 = R20}. It would turn this into
            // {R4 = R5; R5 = R4}, for some reason.
            asm: "{ %0 = #8; %1 = #14 }".to_owned(),
            verify_fn: Box::new(|_r20: u32, _r21: u32, regvec: Vec<u32>| {
                assert_eq!(regvec[0], 8);
                assert_eq!(regvec[1], 14);
            }),
            expected_length: 4,
            no_insns_to_exec: 2,
        },
        // length 1, no duplex
        PacketTestMetadata {
            no_regs: 1,
            asm: "{ %0 = #1552 }".to_owned(),
            verify_fn: Box::new(|_r20: u32, _r21: u32, regvec: Vec<u32>| {
                assert_eq!(regvec[0], 1552);
            }),
            expected_length: 4,
            no_insns_to_exec: 1,
        },
        // length 2, no duplex
        PacketTestMetadata {
            no_regs: 2,
            asm: "{ %0 = #199; %1 = or(r20, r21) }".to_owned(),
            verify_fn: Box::new(|r20: u32, r21: u32, regvec: Vec<u32>| {
                assert_eq!(regvec[0], 199);
                assert_eq!(regvec[1], r20 | r21);
            }),
            expected_length: 8,
            no_insns_to_exec: 2,
        },
        // length 3, no duplex
        PacketTestMetadata {
            no_regs: 3,
            asm: "{ %0 = add(r20, #3993); %1 = and(r21, #90); %2 = mpyi(r21, r20) }".to_owned(),
            verify_fn: Box::new(|r20: u32, r21: u32, regvec: Vec<u32>| {
                assert_eq!(regvec[0], r20 + 3993);
                assert_eq!(regvec[1], r21 & 90);
                assert_eq!(regvec[2], r21 * r20);
            }),
            expected_length: 12,
            no_insns_to_exec: 3,
        },
        // length 4, no duplex
        PacketTestMetadata {
            no_regs: 4,
            asm: "{ %0 = #2; %1 = and(r20, r21); %2 = add(r21, r20); %3 = mpyi(r21, r20) }"
                .to_owned(),
            verify_fn: Box::new(|r20: u32, r21: u32, regvec: Vec<u32>| {
                assert_eq!(regvec[0], 2);
                assert_eq!(regvec[1], r20 & r21);
                assert_eq!(regvec[2], r21 + r20);
                assert_eq!(regvec[3], r21 * r20);
            }),
            expected_length: 16,
            no_insns_to_exec: 4,
        },
    ];
    let mut tot_assembled = 0;

    // try every possible combo
    for i in 0..insns.len() {
        for j in 0..insns.len() {
            let ins0 = &insns[i];
            let ins1 = &insns[j];

            let mut reg_cnt = 0;
            let mut asm0 = ins0.asm.to_owned();
            let mut ins0regs = vec![];

            for k in 0..ins0.no_regs {
                let reg = format!("R{}", k);
                asm0 = asm0.replace(&format!("%{}", k), &reg);
                ins0regs
                    .push(HexagonRegister::from_name(&reg).expect("failed to get reg from str"));
                reg_cnt += 1;
            }

            let reg_cnt_base = reg_cnt;
            let mut asm1 = ins1.asm.to_owned();
            let mut ins1regs = vec![];

            for k in reg_cnt_base..(reg_cnt_base + ins1.no_regs) {
                let reg = format!("R{}", k);
                asm1 = asm1.replace(&format!("%{}", k - reg_cnt_base), &reg);
                ins1regs
                    .push(HexagonRegister::from_name(&reg).expect("failed to get reg from str"));
                reg_cnt += 1;
            }

            let asm_plain = asm0.clone() + ";" + &asm1;
            let asm_with_sets = "{ r23 = #123; r22 = #443; };".to_owned() + &asm0 + ";" + &asm1;

            for (asm_phase, asm) in [asm_plain, asm_with_sets].into_iter().enumerate() {
                info!("assembling {}", asm);

                let has_sets = asm_phase == 1;
                let code0 = ks.asm(asm0.clone(), init_pc).expect("Could not assemble");
                let code1 = ks.asm(asm1.clone(), init_pc).expect("Could not assemble");
                let code = ks.asm(asm, init_pc).expect("Could not assemble");
                trace!("bytes {:x?}", code.bytes);

                assert_eq!(code0.bytes.len(), ins0.expected_length);
                assert_eq!(code1.bytes.len(), ins1.expected_length);

                if has_sets {
                    assert_eq!(
                        code.bytes.len(),
                        ins0.expected_length + ins1.expected_length + 8
                    );
                }

                // NOTE: this is inefficient, but properly resets the state
                let (mut cpu, mut mmu, mut ev) = setup_cpu(init_pc, code.bytes);

                cpu.write_register(HexagonRegister::R20, 32u32).unwrap();
                cpu.write_register(HexagonRegister::R21, 991u32).unwrap();

                let mut expected_pkt_start = init_pc;
                if has_sets {
                    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
                    assert_eq!(TargetExitReason::InstructionCountComplete, exit.exit_reason);
                    let pkt_start = cpu
                        .shared_state
                        .get(&crate::SharedStateKey::HexagonPktStart)
                        .unwrap();
                    // ok to truncate here
                    assert_eq!(*pkt_start as u64, expected_pkt_start);

                    // again
                    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
                    assert_eq!(TargetExitReason::InstructionCountComplete, exit.exit_reason);
                    let pkt_start = cpu
                        .shared_state
                        .get(&crate::SharedStateKey::HexagonPktStart)
                        .unwrap();

                    // two sets
                    expected_pkt_start += 8;
                    assert_eq!(*pkt_start as u64, expected_pkt_start);

                    let r22 = cpu.read_register::<u32>(HexagonRegister::R22).unwrap();
                    let r23 = cpu.read_register::<u32>(HexagonRegister::R23).unwrap();

                    assert_eq!(r22, 443);
                    assert_eq!(r23, 123);
                }

                for ins in [ins0, ins1] {
                    // go ahead and run the first insn, then verify pkt start, then check that shared state is set right
                    if ins.no_insns_to_exec > 1 {
                        for k in 0..(ins.no_insns_to_exec - 1) {
                            trace!("k is {}", k);
                            let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
                            assert_eq!(
                                TargetExitReason::InstructionCountComplete,
                                exit.exit_reason
                            );
                            let pkt_start = cpu
                                .shared_state
                                .get(&crate::SharedStateKey::HexagonPktStart)
                                .unwrap();
                            // ok to truncate here
                            assert_eq!(*pkt_start as u64, expected_pkt_start);
                        }
                    }

                    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
                    assert_eq!(TargetExitReason::InstructionCountComplete, exit.exit_reason);
                    let pkt_start = cpu
                        .shared_state
                        .get(&crate::SharedStateKey::HexagonPktStart)
                        .unwrap();

                    expected_pkt_start += ins.expected_length as u64;
                    trace!(
                        "asserting that {} == {}",
                        *pkt_start as u64,
                        expected_pkt_start
                    );
                    assert_eq!(*pkt_start as u64, expected_pkt_start);

                    trace!("pkt finished successfully");
                }

                let r20 = cpu.read_register::<u32>(HexagonRegister::R20).unwrap();
                let r21 = cpu.read_register::<u32>(HexagonRegister::R21).unwrap();

                let ins0regs = ins0regs
                    .clone()
                    .into_iter()
                    .map(|reg| cpu.read_register::<u32>(reg).unwrap())
                    .collect();
                let ins1regs = ins1regs
                    .clone()
                    .into_iter()
                    .map(|reg| {
                        trace!("reading register {:?}", reg);
                        cpu.read_register::<u32>(reg).unwrap()
                    })
                    .collect();

                (ins0.verify_fn)(r20, r21, ins0regs);
                (ins1.verify_fn)(r20, r21, ins1regs);

                tot_assembled += 1;
            }
        }
    }

    info!(
        "assembled {}, there were {} standalone packets",
        tot_assembled,
        insns.len()
    );
    // times two for the "set" instructions
    assert_eq!(tot_assembled, insns.len() * insns.len() * 2);
}
