use crate::{arch_spec::ArchPcManager, PcodeBackend};

#[derive(Debug, Default)]
pub struct StandardPcManager {
    isa_pc: u64,
    internal_pc: u64,
}

// TODO: we need to have this advance the PC
// at the end of every packet
impl ArchPcManager for StandardPcManager {
    fn isa_pc(&self) -> u64 {
        self.isa_pc
    }

    fn set_isa_pc(&mut self, value: u64, backend: &mut PcodeBackend) {
        self.isa_pc = value
    }
}
