// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    protogrp_cctrl: ProtogrpCctrl,
    protogrp_csts: ProtogrpCsts,
    protogrp_cerc: ProtogrpCerc,
    protogrp_cbt: ProtogrpCbt,
    protogrp_cir: ProtogrpCir,
    protogrp_ctr: ProtogrpCtr,
    protogrp_cfr: ProtogrpCfr,
    _reserved7: [u8; 0x04],
    protogrp_crr: ProtogrpCrr,
    protogrp_hws: ProtogrpHws,
    _reserved9: [u8; 0x5c],
    msghandgrp_motrx: MsghandgrpMotrx,
    msghandgrp_motra: MsghandgrpMotra,
    msghandgrp_motrb: MsghandgrpMotrb,
    msghandgrp_motrc: MsghandgrpMotrc,
    msghandgrp_motrd: MsghandgrpMotrd,
    msghandgrp_mondx: MsghandgrpMondx,
    msghandgrp_monda: MsghandgrpMonda,
    msghandgrp_mondb: MsghandgrpMondb,
    msghandgrp_mondc: MsghandgrpMondc,
    msghandgrp_mondd: MsghandgrpMondd,
    msghandgrp_moipx: MsghandgrpMoipx,
    msghandgrp_moipa: MsghandgrpMoipa,
    msghandgrp_moipb: MsghandgrpMoipb,
    msghandgrp_moipc: MsghandgrpMoipc,
    msghandgrp_moipd: MsghandgrpMoipd,
    msghandgrp_movalx: MsghandgrpMovalx,
    msghandgrp_movala: MsghandgrpMovala,
    msghandgrp_movalb: MsghandgrpMovalb,
    msghandgrp_movalc: MsghandgrpMovalc,
    msghandgrp_movald: MsghandgrpMovald,
    _reserved29: [u8; 0x2c],
    msgifgrp_if1cmr: MsgifgrpIf1cmr,
    msgifgrp_if1msk: MsgifgrpIf1msk,
    msgifgrp_if1arb: MsgifgrpIf1arb,
    msgifgrp_if1mctr: MsgifgrpIf1mctr,
    msgifgrp_if1da: MsgifgrpIf1da,
    msgifgrp_if1db: MsgifgrpIf1db,
    _reserved35: [u8; 0x08],
    msgifgrp_if2cmr: MsgifgrpIf2cmr,
    msgifgrp_if2msk: MsgifgrpIf2msk,
    msgifgrp_if2arb: MsgifgrpIf2arb,
    msgifgrp_if2mctr: MsgifgrpIf2mctr,
    msgifgrp_if2da: MsgifgrpIf2da,
    msgifgrp_if2db: MsgifgrpIf2db,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Control Register"]
    #[inline(always)]
    pub const fn protogrp_cctrl(&self) -> &ProtogrpCctrl {
        &self.protogrp_cctrl
    }
    #[doc = "0x04 - Status Register"]
    #[inline(always)]
    pub const fn protogrp_csts(&self) -> &ProtogrpCsts {
        &self.protogrp_csts
    }
    #[doc = "0x08 - Error Counter Register"]
    #[inline(always)]
    pub const fn protogrp_cerc(&self) -> &ProtogrpCerc {
        &self.protogrp_cerc
    }
    #[doc = "0x0c - This register is only writable if bits CCTRL.CCE and CCTRL.Init are set. The CAN bit time may be programed in the range of \\[4 .. 25\\]
time quanta. The CAN time quantum may be programmed in the range of \\[1 .. 1024\\]
CAN_CLK periods. For details see Application Note 001 \"Configuration of Bit Timing\". The actual interpretation by the hardware of this value is such that one more than the value programmed here is used. TSeg1 is the sum of Prop_Seg and Phase_Seg1. TSeg2 is Phase_Seg2. Therefore the length of the bit time is (programmed values) \\[TSeg1 + TSeg2 + 3\\]
tq or (functional values) \\[Sync_Seg + Prop_Seg + Phase_Seg1 + Phase_Seg2\\]
tq."]
    #[inline(always)]
    pub const fn protogrp_cbt(&self) -> &ProtogrpCbt {
        &self.protogrp_cbt
    }
    #[doc = "0x10 - If several interrupts are pending, the CAN Interrupt Register will point to the pending interrupt with the highest priority, disregarding their chronological order. An interrupt remains pending until the CPU has cleared it. If IntID is different from 0x00 and CCTRL.MIL is set, the interrupt port CAN_INT_MO is active. The interrupt port remains active until IntID is back to value 0x00 (the cause of the interrupt is reset) or until CCTRL.MIL is reset. If CCTRL.ILE is set and CCTRL.MIL is reseted the Message Object interrupts will be routed to interrupt port CAN_INT_STATUS. The interrupt port remains active until IntID is back to value 0x00 (the cause of the interrupt is reset) or until CCTRL.MIL is set or CCTRL.ILE is reset. The Message Object's interrupt priority decreases with increasing message number. A message interrupt is cleared by clearing the Message Object's IntPnd bit."]
    #[inline(always)]
    pub const fn protogrp_cir(&self) -> &ProtogrpCir {
        &self.protogrp_cir
    }
    #[doc = "0x14 - The Test Mode is entered by setting bit CCTRL.Test to one. In Test Mode the bits EXL, Tx1, Tx0, LBack and Silent in the Test Register are writable. Bit Rx monitors the state of pin CAN_RXD and therefore is only readable. All Test Register functions are disabled when bit Test is reset to zero. Loop Back Mode and CAN_TXD Control Mode are hardware test modes, not to be used by application programs. Note: This register is only writable if bit CCTRL.Test is set."]
    #[inline(always)]
    pub const fn protogrp_ctr(&self) -> &ProtogrpCtr {
        &self.protogrp_ctr
    }
    #[doc = "0x18 - The Function Register controls the features RAM_Initialisation and Power_Down also by application register. The CAN module can be prepared for Power_Down by setting the port CAN_CLKSTOP_REQ to one or writing to CFR.ClkStReq a one. The power down state is left by setting port CAN_CLKSTOP_REQ to zero or writing to CFR.ClkStReq a zero, acknowledged by CAN_CLKSTOP_ACK is going to zero as well as CFR.ClkStAck. The CCTRL.Init bit is left one and has to be written by the application to re-enable CAN transfers. Note: It's recommended to use either the ports CAN_CLKSTOP_REQ and CAN_CLKSTOP_ACK or the CCTRL.ClkStReq and CFR.ClkStAck. The application CFR.ClkStReq showsalso the actual status of the portCAN_CLKSTOP_REQ."]
    #[inline(always)]
    pub const fn protogrp_cfr(&self) -> &ProtogrpCfr {
        &self.protogrp_cfr
    }
    #[doc = "0x20 - Core Release Register"]
    #[inline(always)]
    pub const fn protogrp_crr(&self) -> &ProtogrpCrr {
        &self.protogrp_crr
    }
    #[doc = "0x24 - Hardware Configuration Status Register"]
    #[inline(always)]
    pub const fn protogrp_hws(&self) -> &ProtogrpHws {
        &self.protogrp_hws
    }
    #[doc = "0x84 - Reading this register allows the CPU to quickly detect if any of the transmission request bits in each of the MOTRA, MOTRB, MOTRC, and MOTRD Transmission Request Registers are set."]
    #[inline(always)]
    pub const fn msghandgrp_motrx(&self) -> &MsghandgrpMotrx {
        &self.msghandgrp_motrx
    }
    #[doc = "0x88 - Transmission request bits for Message Objects 1 to 32. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission."]
    #[inline(always)]
    pub const fn msghandgrp_motra(&self) -> &MsghandgrpMotra {
        &self.msghandgrp_motra
    }
    #[doc = "0x8c - Transmission request bits for Message Objects 33 to 64. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission."]
    #[inline(always)]
    pub const fn msghandgrp_motrb(&self) -> &MsghandgrpMotrb {
        &self.msghandgrp_motrb
    }
    #[doc = "0x90 - Transmission request bits for Message Objects 65 to 96. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission."]
    #[inline(always)]
    pub const fn msghandgrp_motrc(&self) -> &MsghandgrpMotrc {
        &self.msghandgrp_motrc
    }
    #[doc = "0x94 - Transmission request bits for Message Objects 97 to 128. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission."]
    #[inline(always)]
    pub const fn msghandgrp_motrd(&self) -> &MsghandgrpMotrd {
        &self.msghandgrp_motrd
    }
    #[doc = "0x98 - Reading this register allows the CPU to quickly detect if any of the new data bits in each of the MONDA, MONDB, MONDC, and MONDD New Data Registers are set."]
    #[inline(always)]
    pub const fn msghandgrp_mondx(&self) -> &MsghandgrpMondx {
        &self.msghandgrp_mondx
    }
    #[doc = "0x9c - New data bits for Message Objects 1 to 32. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission."]
    #[inline(always)]
    pub const fn msghandgrp_monda(&self) -> &MsghandgrpMonda {
        &self.msghandgrp_monda
    }
    #[doc = "0xa0 - New data bits for Message Objects 33 to 64. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission."]
    #[inline(always)]
    pub const fn msghandgrp_mondb(&self) -> &MsghandgrpMondb {
        &self.msghandgrp_mondb
    }
    #[doc = "0xa4 - New data bits for Message Objects 65 to 96. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission."]
    #[inline(always)]
    pub const fn msghandgrp_mondc(&self) -> &MsghandgrpMondc {
        &self.msghandgrp_mondc
    }
    #[doc = "0xa8 - New data bits for Message Objects 97 to 128. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission."]
    #[inline(always)]
    pub const fn msghandgrp_mondd(&self) -> &MsghandgrpMondd {
        &self.msghandgrp_mondd
    }
    #[doc = "0xac - Reading this register allows the CPU to quickly detect if any of the interrupt pending bits in each of the MOIPA, MOIPB, MOIPC, and MOIPD Interrupt Pending Registers are set."]
    #[inline(always)]
    pub const fn msghandgrp_moipx(&self) -> &MsghandgrpMoipx {
        &self.msghandgrp_moipx
    }
    #[doc = "0xb0 - Interrupt pending bits for Message Objects 1 to 32. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register."]
    #[inline(always)]
    pub const fn msghandgrp_moipa(&self) -> &MsghandgrpMoipa {
        &self.msghandgrp_moipa
    }
    #[doc = "0xb4 - Interrupt pending bits for Message Objects 33 to 64. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register."]
    #[inline(always)]
    pub const fn msghandgrp_moipb(&self) -> &MsghandgrpMoipb {
        &self.msghandgrp_moipb
    }
    #[doc = "0xb8 - Interrupt pending bits for Message Objects 65 to 96. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register."]
    #[inline(always)]
    pub const fn msghandgrp_moipc(&self) -> &MsghandgrpMoipc {
        &self.msghandgrp_moipc
    }
    #[doc = "0xbc - Interrupt pending bits for Message Objects 97 to 128. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register."]
    #[inline(always)]
    pub const fn msghandgrp_moipd(&self) -> &MsghandgrpMoipd {
        &self.msghandgrp_moipd
    }
    #[doc = "0xc0 - Reading this register allows the CPU to quickly detect if any of the message valid bits in each of the MOVALA, MOVALB, MOVALC, and MOVALD Message Valid Registers are set."]
    #[inline(always)]
    pub const fn msghandgrp_movalx(&self) -> &MsghandgrpMovalx {
        &self.msghandgrp_movalx
    }
    #[doc = "0xc4 - Message valid bits for Message Objects 1 to 32. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers."]
    #[inline(always)]
    pub const fn msghandgrp_movala(&self) -> &MsghandgrpMovala {
        &self.msghandgrp_movala
    }
    #[doc = "0xc8 - Message valid bits for Message Objects 33 to 64. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers."]
    #[inline(always)]
    pub const fn msghandgrp_movalb(&self) -> &MsghandgrpMovalb {
        &self.msghandgrp_movalb
    }
    #[doc = "0xcc - Message valid bits for Message Objects 65 to 96. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers."]
    #[inline(always)]
    pub const fn msghandgrp_movalc(&self) -> &MsghandgrpMovalc {
        &self.msghandgrp_movalc
    }
    #[doc = "0xd0 - Message valid bits for Message Objects 97 to 128. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers."]
    #[inline(always)]
    pub const fn msghandgrp_movald(&self) -> &MsghandgrpMovald {
        &self.msghandgrp_movald
    }
    #[doc = "0x100 - The control bits of the IF1/2 Command Register specify the transfer direction and select which portions of the Message Object should be transferred. A message transfer is started as soon as the CPU has written the message number to the low byte of the Command Request Register and IFxCMR.AutoInc is zero. With this write operation, the IFxCMR.Busy bit is automatically set to 1 to notify the CPU that a transfer is in progress. After a wait time of 2 to 8 HOST_CLK periods, the transfer between theInterface Register and the Message RAM has been completed and the IFxCMR.Busy bit is cleared to 0. The upper limit of the wait time occurs when the message transfer coincides with a CAN message transmission, acceptance filtering, or message storage. If the CPU writes to both Command Registers consecutively (requests a second transfer while another transfer is already in progress), the second transfer starts when the first one is completed. Note: While Busy bit of IF1/2 Command Register is one, IF1/2 Register Set is write protected."]
    #[inline(always)]
    pub const fn msgifgrp_if1cmr(&self) -> &MsgifgrpIf1cmr {
        &self.msgifgrp_if1cmr
    }
    #[doc = "0x104 - The Message Object Mask Bits together with the arbitration bits are used for acceptance filtering of incoming messages. Note: While IFxCMR.Busy bit is one, the IF1/2 Register Set is write protected."]
    #[inline(always)]
    pub const fn msgifgrp_if1msk(&self) -> &MsgifgrpIf1msk {
        &self.msgifgrp_if1msk
    }
    #[doc = "0x108 - The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number."]
    #[inline(always)]
    pub const fn msgifgrp_if1arb(&self) -> &MsgifgrpIf1arb {
        &self.msgifgrp_if1arb
    }
    #[doc = "0x10c - The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number."]
    #[inline(always)]
    pub const fn msgifgrp_if1mctr(&self) -> &MsgifgrpIf1mctr {
        &self.msgifgrp_if1mctr
    }
    #[doc = "0x110 - The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first."]
    #[inline(always)]
    pub const fn msgifgrp_if1da(&self) -> &MsgifgrpIf1da {
        &self.msgifgrp_if1da
    }
    #[doc = "0x114 - The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first."]
    #[inline(always)]
    pub const fn msgifgrp_if1db(&self) -> &MsgifgrpIf1db {
        &self.msgifgrp_if1db
    }
    #[doc = "0x120 - The control bits of the IF1/2 Command Register specify the transfer direction and select which portions of the Message Object should be transferred. A message transfer is started as soon as the CPU has written the message number to the low byte of the Command Request Register and IFxCMR.AutoInc is zero. With this write operation, the IFxCMR.Busy bit is automatically set to 1 to notify the CPU that a transfer is in progress. After a wait time of 2 to 8 HOST_CLK periods, the transfer between theInterface Register and the Message RAM has been completed and the IFxCMR.Busy bit is cleared to 0. The upper limit of the wait time occurs when the message transfer coincides with a CAN message transmission, acceptance filtering, or message storage. If the CPU writes to both Command Registers consecutively (requests a second transfer while another transfer is already in progress), the second transfer starts when the first one is completed. Note: While Busy bit of IF1/2 Command Register is one, IF1/2 Register Set is write protected."]
    #[inline(always)]
    pub const fn msgifgrp_if2cmr(&self) -> &MsgifgrpIf2cmr {
        &self.msgifgrp_if2cmr
    }
    #[doc = "0x124 - The Message Object Mask Bits together with the arbitration bits are used for acceptance filtering of incoming messages. Note: While IFxCMR.Busy bit is one, the IF1/2 Register Set is write protected."]
    #[inline(always)]
    pub const fn msgifgrp_if2msk(&self) -> &MsgifgrpIf2msk {
        &self.msgifgrp_if2msk
    }
    #[doc = "0x128 - The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number."]
    #[inline(always)]
    pub const fn msgifgrp_if2arb(&self) -> &MsgifgrpIf2arb {
        &self.msgifgrp_if2arb
    }
    #[doc = "0x12c - The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number."]
    #[inline(always)]
    pub const fn msgifgrp_if2mctr(&self) -> &MsgifgrpIf2mctr {
        &self.msgifgrp_if2mctr
    }
    #[doc = "0x130 - The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first."]
    #[inline(always)]
    pub const fn msgifgrp_if2da(&self) -> &MsgifgrpIf2da {
        &self.msgifgrp_if2da
    }
    #[doc = "0x134 - The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first."]
    #[inline(always)]
    pub const fn msgifgrp_if2db(&self) -> &MsgifgrpIf2db {
        &self.msgifgrp_if2db
    }
}
#[doc = "protogrp_CCTRL (rw) register accessor: Control Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cctrl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`protogrp_cctrl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_cctrl`]
module"]
#[doc(alias = "protogrp_CCTRL")]
pub type ProtogrpCctrl = crate::Reg<protogrp_cctrl::ProtogrpCctrlSpec>;
#[doc = "Control Register"]
pub mod protogrp_cctrl;
#[doc = "protogrp_CSTS (r) register accessor: Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_csts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_csts`]
module"]
#[doc(alias = "protogrp_CSTS")]
pub type ProtogrpCsts = crate::Reg<protogrp_csts::ProtogrpCstsSpec>;
#[doc = "Status Register"]
pub mod protogrp_csts;
#[doc = "protogrp_CERC (r) register accessor: Error Counter Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cerc::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_cerc`]
module"]
#[doc(alias = "protogrp_CERC")]
pub type ProtogrpCerc = crate::Reg<protogrp_cerc::ProtogrpCercSpec>;
#[doc = "Error Counter Register"]
pub mod protogrp_cerc;
#[doc = "protogrp_CBT (rw) register accessor: This register is only writable if bits CCTRL.CCE and CCTRL.Init are set. The CAN bit time may be programed in the range of \\[4 .. 25\\]
time quanta. The CAN time quantum may be programmed in the range of \\[1 .. 1024\\]
CAN_CLK periods. For details see Application Note 001 \"Configuration of Bit Timing\". The actual interpretation by the hardware of this value is such that one more than the value programmed here is used. TSeg1 is the sum of Prop_Seg and Phase_Seg1. TSeg2 is Phase_Seg2. Therefore the length of the bit time is (programmed values) \\[TSeg1 + TSeg2 + 3\\]
tq or (functional values) \\[Sync_Seg + Prop_Seg + Phase_Seg1 + Phase_Seg2\\]
tq.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cbt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`protogrp_cbt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_cbt`]
module"]
#[doc(alias = "protogrp_CBT")]
pub type ProtogrpCbt = crate::Reg<protogrp_cbt::ProtogrpCbtSpec>;
#[doc = "This register is only writable if bits CCTRL.CCE and CCTRL.Init are set. The CAN bit time may be programed in the range of \\[4 .. 25\\]
time quanta. The CAN time quantum may be programmed in the range of \\[1 .. 1024\\]
CAN_CLK periods. For details see Application Note 001 \"Configuration of Bit Timing\". The actual interpretation by the hardware of this value is such that one more than the value programmed here is used. TSeg1 is the sum of Prop_Seg and Phase_Seg1. TSeg2 is Phase_Seg2. Therefore the length of the bit time is (programmed values) \\[TSeg1 + TSeg2 + 3\\]
tq or (functional values) \\[Sync_Seg + Prop_Seg + Phase_Seg1 + Phase_Seg2\\]
tq."]
pub mod protogrp_cbt;
#[doc = "protogrp_CIR (r) register accessor: If several interrupts are pending, the CAN Interrupt Register will point to the pending interrupt with the highest priority, disregarding their chronological order. An interrupt remains pending until the CPU has cleared it. If IntID is different from 0x00 and CCTRL.MIL is set, the interrupt port CAN_INT_MO is active. The interrupt port remains active until IntID is back to value 0x00 (the cause of the interrupt is reset) or until CCTRL.MIL is reset. If CCTRL.ILE is set and CCTRL.MIL is reseted the Message Object interrupts will be routed to interrupt port CAN_INT_STATUS. The interrupt port remains active until IntID is back to value 0x00 (the cause of the interrupt is reset) or until CCTRL.MIL is set or CCTRL.ILE is reset. The Message Object's interrupt priority decreases with increasing message number. A message interrupt is cleared by clearing the Message Object's IntPnd bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cir::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_cir`]
module"]
#[doc(alias = "protogrp_CIR")]
pub type ProtogrpCir = crate::Reg<protogrp_cir::ProtogrpCirSpec>;
#[doc = "If several interrupts are pending, the CAN Interrupt Register will point to the pending interrupt with the highest priority, disregarding their chronological order. An interrupt remains pending until the CPU has cleared it. If IntID is different from 0x00 and CCTRL.MIL is set, the interrupt port CAN_INT_MO is active. The interrupt port remains active until IntID is back to value 0x00 (the cause of the interrupt is reset) or until CCTRL.MIL is reset. If CCTRL.ILE is set and CCTRL.MIL is reseted the Message Object interrupts will be routed to interrupt port CAN_INT_STATUS. The interrupt port remains active until IntID is back to value 0x00 (the cause of the interrupt is reset) or until CCTRL.MIL is set or CCTRL.ILE is reset. The Message Object's interrupt priority decreases with increasing message number. A message interrupt is cleared by clearing the Message Object's IntPnd bit."]
pub mod protogrp_cir;
#[doc = "protogrp_CTR (rw) register accessor: The Test Mode is entered by setting bit CCTRL.Test to one. In Test Mode the bits EXL, Tx1, Tx0, LBack and Silent in the Test Register are writable. Bit Rx monitors the state of pin CAN_RXD and therefore is only readable. All Test Register functions are disabled when bit Test is reset to zero. Loop Back Mode and CAN_TXD Control Mode are hardware test modes, not to be used by application programs. Note: This register is only writable if bit CCTRL.Test is set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_ctr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`protogrp_ctr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_ctr`]
module"]
#[doc(alias = "protogrp_CTR")]
pub type ProtogrpCtr = crate::Reg<protogrp_ctr::ProtogrpCtrSpec>;
#[doc = "The Test Mode is entered by setting bit CCTRL.Test to one. In Test Mode the bits EXL, Tx1, Tx0, LBack and Silent in the Test Register are writable. Bit Rx monitors the state of pin CAN_RXD and therefore is only readable. All Test Register functions are disabled when bit Test is reset to zero. Loop Back Mode and CAN_TXD Control Mode are hardware test modes, not to be used by application programs. Note: This register is only writable if bit CCTRL.Test is set."]
pub mod protogrp_ctr;
#[doc = "protogrp_CFR (rw) register accessor: The Function Register controls the features RAM_Initialisation and Power_Down also by application register. The CAN module can be prepared for Power_Down by setting the port CAN_CLKSTOP_REQ to one or writing to CFR.ClkStReq a one. The power down state is left by setting port CAN_CLKSTOP_REQ to zero or writing to CFR.ClkStReq a zero, acknowledged by CAN_CLKSTOP_ACK is going to zero as well as CFR.ClkStAck. The CCTRL.Init bit is left one and has to be written by the application to re-enable CAN transfers. Note: It's recommended to use either the ports CAN_CLKSTOP_REQ and CAN_CLKSTOP_ACK or the CCTRL.ClkStReq and CFR.ClkStAck. The application CFR.ClkStReq showsalso the actual status of the portCAN_CLKSTOP_REQ.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_cfr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`protogrp_cfr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_cfr`]
module"]
#[doc(alias = "protogrp_CFR")]
pub type ProtogrpCfr = crate::Reg<protogrp_cfr::ProtogrpCfrSpec>;
#[doc = "The Function Register controls the features RAM_Initialisation and Power_Down also by application register. The CAN module can be prepared for Power_Down by setting the port CAN_CLKSTOP_REQ to one or writing to CFR.ClkStReq a one. The power down state is left by setting port CAN_CLKSTOP_REQ to zero or writing to CFR.ClkStReq a zero, acknowledged by CAN_CLKSTOP_ACK is going to zero as well as CFR.ClkStAck. The CCTRL.Init bit is left one and has to be written by the application to re-enable CAN transfers. Note: It's recommended to use either the ports CAN_CLKSTOP_REQ and CAN_CLKSTOP_ACK or the CCTRL.ClkStReq and CFR.ClkStAck. The application CFR.ClkStReq showsalso the actual status of the portCAN_CLKSTOP_REQ."]
pub mod protogrp_cfr;
#[doc = "protogrp_CRR (r) register accessor: Core Release Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_crr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_crr`]
module"]
#[doc(alias = "protogrp_CRR")]
pub type ProtogrpCrr = crate::Reg<protogrp_crr::ProtogrpCrrSpec>;
#[doc = "Core Release Register"]
pub mod protogrp_crr;
#[doc = "protogrp_HWS (r) register accessor: Hardware Configuration Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`protogrp_hws::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@protogrp_hws`]
module"]
#[doc(alias = "protogrp_HWS")]
pub type ProtogrpHws = crate::Reg<protogrp_hws::ProtogrpHwsSpec>;
#[doc = "Hardware Configuration Status Register"]
pub mod protogrp_hws;
#[doc = "msghandgrp_MOTRX (r) register accessor: Reading this register allows the CPU to quickly detect if any of the transmission request bits in each of the MOTRA, MOTRB, MOTRC, and MOTRD Transmission Request Registers are set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_motrx::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_motrx`]
module"]
#[doc(alias = "msghandgrp_MOTRX")]
pub type MsghandgrpMotrx = crate::Reg<msghandgrp_motrx::MsghandgrpMotrxSpec>;
#[doc = "Reading this register allows the CPU to quickly detect if any of the transmission request bits in each of the MOTRA, MOTRB, MOTRC, and MOTRD Transmission Request Registers are set."]
pub mod msghandgrp_motrx;
#[doc = "msghandgrp_MOTRA (r) register accessor: Transmission request bits for Message Objects 1 to 32. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_motra::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_motra`]
module"]
#[doc(alias = "msghandgrp_MOTRA")]
pub type MsghandgrpMotra = crate::Reg<msghandgrp_motra::MsghandgrpMotraSpec>;
#[doc = "Transmission request bits for Message Objects 1 to 32. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission."]
pub mod msghandgrp_motra;
#[doc = "msghandgrp_MOTRB (r) register accessor: Transmission request bits for Message Objects 33 to 64. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_motrb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_motrb`]
module"]
#[doc(alias = "msghandgrp_MOTRB")]
pub type MsghandgrpMotrb = crate::Reg<msghandgrp_motrb::MsghandgrpMotrbSpec>;
#[doc = "Transmission request bits for Message Objects 33 to 64. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission."]
pub mod msghandgrp_motrb;
#[doc = "msghandgrp_MOTRC (r) register accessor: Transmission request bits for Message Objects 65 to 96. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_motrc::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_motrc`]
module"]
#[doc(alias = "msghandgrp_MOTRC")]
pub type MsghandgrpMotrc = crate::Reg<msghandgrp_motrc::MsghandgrpMotrcSpec>;
#[doc = "Transmission request bits for Message Objects 65 to 96. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission."]
pub mod msghandgrp_motrc;
#[doc = "msghandgrp_MOTRD (r) register accessor: Transmission request bits for Message Objects 97 to 128. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_motrd::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_motrd`]
module"]
#[doc(alias = "msghandgrp_MOTRD")]
pub type MsghandgrpMotrd = crate::Reg<msghandgrp_motrd::MsghandgrpMotrdSpec>;
#[doc = "Transmission request bits for Message Objects 97 to 128. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission."]
pub mod msghandgrp_motrd;
#[doc = "msghandgrp_MONDX (r) register accessor: Reading this register allows the CPU to quickly detect if any of the new data bits in each of the MONDA, MONDB, MONDC, and MONDD New Data Registers are set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_mondx::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_mondx`]
module"]
#[doc(alias = "msghandgrp_MONDX")]
pub type MsghandgrpMondx = crate::Reg<msghandgrp_mondx::MsghandgrpMondxSpec>;
#[doc = "Reading this register allows the CPU to quickly detect if any of the new data bits in each of the MONDA, MONDB, MONDC, and MONDD New Data Registers are set."]
pub mod msghandgrp_mondx;
#[doc = "msghandgrp_MONDA (r) register accessor: New data bits for Message Objects 1 to 32. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_monda::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_monda`]
module"]
#[doc(alias = "msghandgrp_MONDA")]
pub type MsghandgrpMonda = crate::Reg<msghandgrp_monda::MsghandgrpMondaSpec>;
#[doc = "New data bits for Message Objects 1 to 32. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission."]
pub mod msghandgrp_monda;
#[doc = "msghandgrp_MONDB (r) register accessor: New data bits for Message Objects 33 to 64. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_mondb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_mondb`]
module"]
#[doc(alias = "msghandgrp_MONDB")]
pub type MsghandgrpMondb = crate::Reg<msghandgrp_mondb::MsghandgrpMondbSpec>;
#[doc = "New data bits for Message Objects 33 to 64. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission."]
pub mod msghandgrp_mondb;
#[doc = "msghandgrp_MONDC (r) register accessor: New data bits for Message Objects 65 to 96. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_mondc::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_mondc`]
module"]
#[doc(alias = "msghandgrp_MONDC")]
pub type MsghandgrpMondc = crate::Reg<msghandgrp_mondc::MsghandgrpMondcSpec>;
#[doc = "New data bits for Message Objects 65 to 96. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission."]
pub mod msghandgrp_mondc;
#[doc = "msghandgrp_MONDD (r) register accessor: New data bits for Message Objects 97 to 128. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_mondd::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_mondd`]
module"]
#[doc(alias = "msghandgrp_MONDD")]
pub type MsghandgrpMondd = crate::Reg<msghandgrp_mondd::MsghandgrpMonddSpec>;
#[doc = "New data bits for Message Objects 97 to 128. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission."]
pub mod msghandgrp_mondd;
#[doc = "msghandgrp_MOIPX (r) register accessor: Reading this register allows the CPU to quickly detect if any of the interrupt pending bits in each of the MOIPA, MOIPB, MOIPC, and MOIPD Interrupt Pending Registers are set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_moipx::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_moipx`]
module"]
#[doc(alias = "msghandgrp_MOIPX")]
pub type MsghandgrpMoipx = crate::Reg<msghandgrp_moipx::MsghandgrpMoipxSpec>;
#[doc = "Reading this register allows the CPU to quickly detect if any of the interrupt pending bits in each of the MOIPA, MOIPB, MOIPC, and MOIPD Interrupt Pending Registers are set."]
pub mod msghandgrp_moipx;
#[doc = "msghandgrp_MOIPA (r) register accessor: Interrupt pending bits for Message Objects 1 to 32. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_moipa::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_moipa`]
module"]
#[doc(alias = "msghandgrp_MOIPA")]
pub type MsghandgrpMoipa = crate::Reg<msghandgrp_moipa::MsghandgrpMoipaSpec>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register."]
pub mod msghandgrp_moipa;
#[doc = "msghandgrp_MOIPB (r) register accessor: Interrupt pending bits for Message Objects 33 to 64. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_moipb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_moipb`]
module"]
#[doc(alias = "msghandgrp_MOIPB")]
pub type MsghandgrpMoipb = crate::Reg<msghandgrp_moipb::MsghandgrpMoipbSpec>;
#[doc = "Interrupt pending bits for Message Objects 33 to 64. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register."]
pub mod msghandgrp_moipb;
#[doc = "msghandgrp_MOIPC (r) register accessor: Interrupt pending bits for Message Objects 65 to 96. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_moipc::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_moipc`]
module"]
#[doc(alias = "msghandgrp_MOIPC")]
pub type MsghandgrpMoipc = crate::Reg<msghandgrp_moipc::MsghandgrpMoipcSpec>;
#[doc = "Interrupt pending bits for Message Objects 65 to 96. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register."]
pub mod msghandgrp_moipc;
#[doc = "msghandgrp_MOIPD (r) register accessor: Interrupt pending bits for Message Objects 97 to 128. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_moipd::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_moipd`]
module"]
#[doc(alias = "msghandgrp_MOIPD")]
pub type MsghandgrpMoipd = crate::Reg<msghandgrp_moipd::MsghandgrpMoipdSpec>;
#[doc = "Interrupt pending bits for Message Objects 97 to 128. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register."]
pub mod msghandgrp_moipd;
#[doc = "msghandgrp_MOVALX (r) register accessor: Reading this register allows the CPU to quickly detect if any of the message valid bits in each of the MOVALA, MOVALB, MOVALC, and MOVALD Message Valid Registers are set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_movalx::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_movalx`]
module"]
#[doc(alias = "msghandgrp_MOVALX")]
pub type MsghandgrpMovalx = crate::Reg<msghandgrp_movalx::MsghandgrpMovalxSpec>;
#[doc = "Reading this register allows the CPU to quickly detect if any of the message valid bits in each of the MOVALA, MOVALB, MOVALC, and MOVALD Message Valid Registers are set."]
pub mod msghandgrp_movalx;
#[doc = "msghandgrp_MOVALA (r) register accessor: Message valid bits for Message Objects 1 to 32. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_movala::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_movala`]
module"]
#[doc(alias = "msghandgrp_MOVALA")]
pub type MsghandgrpMovala = crate::Reg<msghandgrp_movala::MsghandgrpMovalaSpec>;
#[doc = "Message valid bits for Message Objects 1 to 32. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers."]
pub mod msghandgrp_movala;
#[doc = "msghandgrp_MOVALB (r) register accessor: Message valid bits for Message Objects 33 to 64. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_movalb::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_movalb`]
module"]
#[doc(alias = "msghandgrp_MOVALB")]
pub type MsghandgrpMovalb = crate::Reg<msghandgrp_movalb::MsghandgrpMovalbSpec>;
#[doc = "Message valid bits for Message Objects 33 to 64. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers."]
pub mod msghandgrp_movalb;
#[doc = "msghandgrp_MOVALC (r) register accessor: Message valid bits for Message Objects 65 to 96. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_movalc::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_movalc`]
module"]
#[doc(alias = "msghandgrp_MOVALC")]
pub type MsghandgrpMovalc = crate::Reg<msghandgrp_movalc::MsghandgrpMovalcSpec>;
#[doc = "Message valid bits for Message Objects 65 to 96. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers."]
pub mod msghandgrp_movalc;
#[doc = "msghandgrp_MOVALD (r) register accessor: Message valid bits for Message Objects 97 to 128. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_movald::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msghandgrp_movald`]
module"]
#[doc(alias = "msghandgrp_MOVALD")]
pub type MsghandgrpMovald = crate::Reg<msghandgrp_movald::MsghandgrpMovaldSpec>;
#[doc = "Message valid bits for Message Objects 97 to 128. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers."]
pub mod msghandgrp_movald;
#[doc = "msgifgrp_IF1CMR (rw) register accessor: The control bits of the IF1/2 Command Register specify the transfer direction and select which portions of the Message Object should be transferred. A message transfer is started as soon as the CPU has written the message number to the low byte of the Command Request Register and IFxCMR.AutoInc is zero. With this write operation, the IFxCMR.Busy bit is automatically set to 1 to notify the CPU that a transfer is in progress. After a wait time of 2 to 8 HOST_CLK periods, the transfer between theInterface Register and the Message RAM has been completed and the IFxCMR.Busy bit is cleared to 0. The upper limit of the wait time occurs when the message transfer coincides with a CAN message transmission, acceptance filtering, or message storage. If the CPU writes to both Command Registers consecutively (requests a second transfer while another transfer is already in progress), the second transfer starts when the first one is completed. Note: While Busy bit of IF1/2 Command Register is one, IF1/2 Register Set is write protected.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if1cmr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if1cmr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if1cmr`]
module"]
#[doc(alias = "msgifgrp_IF1CMR")]
pub type MsgifgrpIf1cmr = crate::Reg<msgifgrp_if1cmr::MsgifgrpIf1cmrSpec>;
#[doc = "The control bits of the IF1/2 Command Register specify the transfer direction and select which portions of the Message Object should be transferred. A message transfer is started as soon as the CPU has written the message number to the low byte of the Command Request Register and IFxCMR.AutoInc is zero. With this write operation, the IFxCMR.Busy bit is automatically set to 1 to notify the CPU that a transfer is in progress. After a wait time of 2 to 8 HOST_CLK periods, the transfer between theInterface Register and the Message RAM has been completed and the IFxCMR.Busy bit is cleared to 0. The upper limit of the wait time occurs when the message transfer coincides with a CAN message transmission, acceptance filtering, or message storage. If the CPU writes to both Command Registers consecutively (requests a second transfer while another transfer is already in progress), the second transfer starts when the first one is completed. Note: While Busy bit of IF1/2 Command Register is one, IF1/2 Register Set is write protected."]
pub mod msgifgrp_if1cmr;
#[doc = "msgifgrp_IF1MSK (rw) register accessor: The Message Object Mask Bits together with the arbitration bits are used for acceptance filtering of incoming messages. Note: While IFxCMR.Busy bit is one, the IF1/2 Register Set is write protected.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if1msk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if1msk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if1msk`]
module"]
#[doc(alias = "msgifgrp_IF1MSK")]
pub type MsgifgrpIf1msk = crate::Reg<msgifgrp_if1msk::MsgifgrpIf1mskSpec>;
#[doc = "The Message Object Mask Bits together with the arbitration bits are used for acceptance filtering of incoming messages. Note: While IFxCMR.Busy bit is one, the IF1/2 Register Set is write protected."]
pub mod msgifgrp_if1msk;
#[doc = "msgifgrp_IF1ARB (rw) register accessor: The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if1arb::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if1arb::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if1arb`]
module"]
#[doc(alias = "msgifgrp_IF1ARB")]
pub type MsgifgrpIf1arb = crate::Reg<msgifgrp_if1arb::MsgifgrpIf1arbSpec>;
#[doc = "The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number."]
pub mod msgifgrp_if1arb;
#[doc = "msgifgrp_IF1MCTR (rw) register accessor: The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if1mctr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if1mctr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if1mctr`]
module"]
#[doc(alias = "msgifgrp_IF1MCTR")]
pub type MsgifgrpIf1mctr = crate::Reg<msgifgrp_if1mctr::MsgifgrpIf1mctrSpec>;
#[doc = "The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number."]
pub mod msgifgrp_if1mctr;
#[doc = "msgifgrp_IF1DA (rw) register accessor: The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if1da::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if1da::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if1da`]
module"]
#[doc(alias = "msgifgrp_IF1DA")]
pub type MsgifgrpIf1da = crate::Reg<msgifgrp_if1da::MsgifgrpIf1daSpec>;
#[doc = "The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first."]
pub mod msgifgrp_if1da;
#[doc = "msgifgrp_IF1DB (rw) register accessor: The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if1db::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if1db::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if1db`]
module"]
#[doc(alias = "msgifgrp_IF1DB")]
pub type MsgifgrpIf1db = crate::Reg<msgifgrp_if1db::MsgifgrpIf1dbSpec>;
#[doc = "The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first."]
pub mod msgifgrp_if1db;
#[doc = "msgifgrp_IF2CMR (rw) register accessor: The control bits of the IF1/2 Command Register specify the transfer direction and select which portions of the Message Object should be transferred. A message transfer is started as soon as the CPU has written the message number to the low byte of the Command Request Register and IFxCMR.AutoInc is zero. With this write operation, the IFxCMR.Busy bit is automatically set to 1 to notify the CPU that a transfer is in progress. After a wait time of 2 to 8 HOST_CLK periods, the transfer between theInterface Register and the Message RAM has been completed and the IFxCMR.Busy bit is cleared to 0. The upper limit of the wait time occurs when the message transfer coincides with a CAN message transmission, acceptance filtering, or message storage. If the CPU writes to both Command Registers consecutively (requests a second transfer while another transfer is already in progress), the second transfer starts when the first one is completed. Note: While Busy bit of IF1/2 Command Register is one, IF1/2 Register Set is write protected.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2cmr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2cmr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if2cmr`]
module"]
#[doc(alias = "msgifgrp_IF2CMR")]
pub type MsgifgrpIf2cmr = crate::Reg<msgifgrp_if2cmr::MsgifgrpIf2cmrSpec>;
#[doc = "The control bits of the IF1/2 Command Register specify the transfer direction and select which portions of the Message Object should be transferred. A message transfer is started as soon as the CPU has written the message number to the low byte of the Command Request Register and IFxCMR.AutoInc is zero. With this write operation, the IFxCMR.Busy bit is automatically set to 1 to notify the CPU that a transfer is in progress. After a wait time of 2 to 8 HOST_CLK periods, the transfer between theInterface Register and the Message RAM has been completed and the IFxCMR.Busy bit is cleared to 0. The upper limit of the wait time occurs when the message transfer coincides with a CAN message transmission, acceptance filtering, or message storage. If the CPU writes to both Command Registers consecutively (requests a second transfer while another transfer is already in progress), the second transfer starts when the first one is completed. Note: While Busy bit of IF1/2 Command Register is one, IF1/2 Register Set is write protected."]
pub mod msgifgrp_if2cmr;
#[doc = "msgifgrp_IF2MSK (rw) register accessor: The Message Object Mask Bits together with the arbitration bits are used for acceptance filtering of incoming messages. Note: While IFxCMR.Busy bit is one, the IF1/2 Register Set is write protected.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2msk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2msk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if2msk`]
module"]
#[doc(alias = "msgifgrp_IF2MSK")]
pub type MsgifgrpIf2msk = crate::Reg<msgifgrp_if2msk::MsgifgrpIf2mskSpec>;
#[doc = "The Message Object Mask Bits together with the arbitration bits are used for acceptance filtering of incoming messages. Note: While IFxCMR.Busy bit is one, the IF1/2 Register Set is write protected."]
pub mod msgifgrp_if2msk;
#[doc = "msgifgrp_IF2ARB (rw) register accessor: The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2arb::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2arb::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if2arb`]
module"]
#[doc(alias = "msgifgrp_IF2ARB")]
pub type MsgifgrpIf2arb = crate::Reg<msgifgrp_if2arb::MsgifgrpIf2arbSpec>;
#[doc = "The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number."]
pub mod msgifgrp_if2arb;
#[doc = "msgifgrp_IF2MCTR (rw) register accessor: The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2mctr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2mctr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if2mctr`]
module"]
#[doc(alias = "msgifgrp_IF2MCTR")]
pub type MsgifgrpIf2mctr = crate::Reg<msgifgrp_if2mctr::MsgifgrpIf2mctrSpec>;
#[doc = "The Arbitration Registers ID28-0, Xtd, and Dir are used to define the identifier and type of outgoing messages and are used (together with the mask registers Msk28-0, MXtd, and MDir) for acceptance filtering of incoming messages. A received message is stored into the valid Message Object with matching identifier and Direction=receive (Data Frame) or Direction=transmit (Remote Frame). Extended frames can be stored only in Message Objects with Xtd = one, standard frames in Message Objects with Xtd = zero. If a received message (Data Frame or Remote Frame) matches with more than one valid Message Object, it is stored into that with the lowest message number."]
pub mod msgifgrp_if2mctr;
#[doc = "msgifgrp_IF2DA (rw) register accessor: The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2da::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2da::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if2da`]
module"]
#[doc(alias = "msgifgrp_IF2DA")]
pub type MsgifgrpIf2da = crate::Reg<msgifgrp_if2da::MsgifgrpIf2daSpec>;
#[doc = "The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first."]
pub mod msgifgrp_if2da;
#[doc = "msgifgrp_IF2DB (rw) register accessor: The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msgifgrp_if2db::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`msgifgrp_if2db::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@msgifgrp_if2db`]
module"]
#[doc(alias = "msgifgrp_IF2DB")]
pub type MsgifgrpIf2db = crate::Reg<msgifgrp_if2db::MsgifgrpIf2dbSpec>;
#[doc = "The data bytes of CAN messages are stored in the IF1/2 registers in the following order. In a CAN Data Frame, Data(0) is the first, Data(7) is the last byte to be transmitted or received. In CAN's serial bit stream, the MSB of each byte will be transmitted first."]
pub mod msgifgrp_if2db;
