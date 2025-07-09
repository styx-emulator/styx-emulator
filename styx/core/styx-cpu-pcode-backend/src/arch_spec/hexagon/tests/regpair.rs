use crate::arch_spec::hexagon::regpairs::REGPAIR_MAP;
use crate::arch_spec::hexagon::tests::*;

#[test]
fn verify_regpairs() {
    // make sure the mapping is acceptable by going through
    // the styx sla mapping and making sure they both align
    // TODO: not clear how to do this, but maybe make sure that every
    // regpair is mapped?? this may not be what we want if there are regpairs
    // we intentionally haven't implemented yet.
    styx_util::logging::init_logging();
    let re = Regex::new(r"[A-Z]*\d*").unwrap();
    for (k, v) in REGPAIR_MAP.iter() {
        let regpair_str = hexagon_reg_to_str(&k);
        let reglo_str = hexagon_reg_to_str(&v.1);
        let reghi_str = hexagon_reg_to_str(&v.0);

        let regs: Vec<&str> = re.find_iter(&regpair_str).map(|m| m.as_str()).collect();
        trace!(
            "regs for {} are {:?} and hi {} lo {}",
            regpair_str,
            regs,
            reghi_str,
            reglo_str
        );
        // check these regs aginst the values, make sure the first value in regs
        // aligns with the hi in the map and second aligns with lo in the map
        assert_eq!(reghi_str, regs[0].into());
        assert_eq!(reglo_str, regs[1].into());
    }
}

#[test]
fn test_all_regpairs() {
    styx_util::logging::init_logging();
    // we're not going to run anything, just write and read stuff from and to registers
    let (mut cpu, _mmu, _ev) = setup_cpu(0, vec![]);

    let re = Regex::new(r"[A-Z]*\d*").unwrap();

    for (k, v) in REGPAIR_MAP.iter() {
        // since the registers are named consistently in ghidra, we can extract out the register pair name used
        // by keystone/llvm

        let regpair_str = hexagon_reg_to_str(&k);
        let regs: Vec<&str> = re.find_iter(&regpair_str).map(|m| m.as_str()).collect();

        let keystone_regpair_str = regs[0].to_owned() + ":" + &regs[1][1..];
        trace!(
            "calling test_regpair_helper on {} {:?} {:?} {:?}",
            keystone_regpair_str,
            k,
            v.0,
            v.1
        );
        test_regpair_helper(&mut cpu, *k, v.0, v.1);
    }
}

fn test_regpair_helper(
    cpu: &mut PcodeBackend,
    hex_regpair: HexagonRegister,
    hex_hi_reg: HexagonRegister,
    hex_lo_reg: HexagonRegister,
) {
    const LO: u64 = 0x29884433;
    // pretty sure this has to be a byte unless you want to copy from another
    // register
    const HI: u64 = 100;
    /*let assembly = format!("{{ {} = combine(#{}, #{}) }}", regpair_str, HI, LO);
    trace!("assembling {}", assembly);
    let (mut cpu, mut mmu, mut ev) = setup_asm(&assembly, None);

    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);*/

    cpu.write_register(hex_regpair, (HI << 32) | LO).unwrap();

    let reg_lo = cpu.read_register::<u32>(hex_lo_reg).unwrap();
    let reg_hi = cpu.read_register::<u32>(hex_hi_reg).unwrap();

    let reg_pair = cpu.read_register::<u64>(hex_regpair).unwrap();

    assert_eq!(reg_lo, LO as u32);
    assert_eq!(reg_hi, HI as u32);
    assert_eq!(reg_pair, (HI << 32) | LO);
}
