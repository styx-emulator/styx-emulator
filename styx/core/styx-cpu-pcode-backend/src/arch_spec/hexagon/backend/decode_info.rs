use log::trace;

#[derive(Copy, Clone, Debug)]
pub enum DuplexInsClass {
    A = 1,
    L1 = 2,
    L2 = 3,
    S1 = 4,
    S2 = 5,
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum PktLoopParseBits {
    Duplex = 0,
    NotEndOfPacket1 = 1,
    NotEndOfPacket2 = 2,
    EndOfPacket = 3,
    Other,
}

impl From<u8> for PktLoopParseBits {
    fn from(value: u8) -> Self {
        trace!("pkt loop parse bits from {}", value);
        match value {
            0 => Self::Duplex,
            1 => Self::NotEndOfPacket1,
            2 => Self::NotEndOfPacket2,
            3 => Self::EndOfPacket,
            _ => Self::Other,
        }
    }
}

impl PktLoopParseBits {
    pub fn new_from_insn(insn_data: u32) -> Self {
        (((insn_data >> 14) & 0b11) as u8).into()
    }
}
