// SPDX-License-Identifier: BSD-2-Clause
use bilge::prelude::*;
use getset::Getters;

/// UARTx_BDH register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1373
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct BDH {
    /// UART Baud Rate bits, upper 5 bits
    pub sbr: u5,
    /// zero: always zero. Read Only.
    pub zero: u1,
    /// RxD Input Active Edge Interrupt Enable
    /// Enables receive input active edge (`RXEDGIF`) to generate interrupts
    /// 0: Hardware interrupts from `RXEDGIF` disabled using polling
    /// 1: RXEDGIF interrupt request enabled
    pub rxedgie: bool,
    /// LIN Break Detect Interrupt Enable
    /// Enabled the LIN break detect flag, (`LBKDIF`) to generate interrupts
    /// based on the state of `LBKDDMAS`
    /// 0: LBKDIF interrupt requests disabled
    /// 1: LBKDIF interrupt requests enabled
    pub lbkdie: bool,
}

/// UARTx_BDL register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1374
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct BDL {
    /// UART Baud Rate bits, lower 6 bits
    pub sbr: u8,
}

/// UARTx_C1 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1375
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct C1 {
    /// Parity Type
    /// 0: Even parity
    /// 1: Odd parity
    pub pt: u1,
    /// Parity Enable
    /// 0: parity disabled
    /// 1: parity enabled
    pub pe: bool,
    /// Idle Line Type Select
    /// Determines when receiver counts logic 1s as idle character bits.
    /// 0: Idle character bit count starts after start bit
    /// 1: Idle character bit count starts after stop bit
    pub ilt: u1,
    /// Receiver Wakeup Method Select
    /// Determines which condition wakes the UART
    /// 0: Idle line wakeup
    /// 1: Address Mark wakeup
    pub wake: u1,
    /// 9 bit or 8 bit Mode Select
    /// This field must be set in `C7816` mode
    /// 0: Normal -- start + 8 data bits (LSB/MSB determined by MSBF) + stop
    /// 1: Use -- start + 9 data bits (LSB/MSB determined by MSBF) + stop
    pub m: u1,
    /// Receiver Source Select
    /// This field has no meaning if LOOPS is not set
    /// 0: Selects internal loop back mode
    /// 1: Single wire UART mode where receiver input is connected to tx pin input
    pub rsrc: u1,
    /// UART stops in Wait Mode
    /// 0: UART clock continues to run in Wait mode
    /// 1: UART clock freezes while CPU is in Wait mode
    pub uartswai: u1,
    /// Loop Mode Select
    /// Enable loopback mode on the uart, disconnects external RxD pin
    /// 0: Normal operation
    /// 1: tx is internally connected to rx pin, input determined by `RSRC`
    pub loops: u1,
}

/// UARTx_C2 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1376
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct C2 {
    pub sbk: u1,
    pub rwu: u1,
    pub re: bool,
    pub te: bool,
    pub ilie: bool,
    pub rie: bool,
    pub tcie: bool,
    pub tie: bool,
}

/// UARTx_S1 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1378
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct S1 {
    pub pf: u1,
    pub fe: u1,
    pub nf: u1,
    pub or: u1,
    pub edle: u1,
    pub rdrf: u1,
    pub tc: u1,
    pub tdre: u1,
}

/// UARTx_S2 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1381
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct S2 {
    pub raf: u1,
    pub lbkde: u1,
    pub brk13: u1,
    pub rwuid: u1,
    pub rxinv: u1,
    pub msbf: u1,
    pub rxedgit: u1,
    pub lbkdif: u1,
}
/// UARTx_C3 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1381
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct C3 {
    pub peie: u1,
    pub feie: u1,
    pub neie: u1,
    pub orie: u1,
    pub txinv: u1,
    pub txdir: u1,
    pub t8: u1,
    pub r8: u1,
}

/// UARTx_D register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1384
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct D {
    pub rt: u8,
}

/// UARTx_MA1 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1385
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct MA1 {
    pub ma: u8,
}

/// UARTx_MA2 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1386
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct MA2 {
    pub ma: u8,
}

/// UARTx_C4 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1386
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct C4 {
    pub bfra: u5,
    pub m10: u1,
    pub maen2: u1,
    pub maen1: u1,
}

/// UARTx_C5 register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1387
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct C5 {
    pub reserved_0: u5,
    pub rdmas: u1,
    pub reserved_1: u1,
    pub tdmas: u1,
}

/// UARTx_ED register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1388
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct ED {
    pub reserved: u6,
    pub paritye: u1,
    pub noisy: u1,
}

/// UARTx_MODEM register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1389
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct MODEM {
    pub txctse: u1,
    pub txrtse: u1,
    pub txrtspol: u1,
    pub rxrtse: u1,
    pub reserved_0: u4,
}

/// UARTx_IR register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1390
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct IR {
    pub tnp: u2,
    pub iren: u1,
    pub reserved: u5,
}

/// UARTx_PFIFO register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1391
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct PFIFO {
    pub rxfifosize: u3,
    pub rxfe: u1,
    pub txfifosize: u3,
    pub tsfe: u1,
}

/// UARTx_CFIFO register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1392
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct CFIFO {
    pub rxufe: u1,
    pub txofe: u1,
    pub rxofe: u1,
    pub reserved: u3,
    pub rxflush: u1,
    pub txflush: u1,
}

/// UARTx_SFIFO register field.
///
/// K21 Sub-Family Reference Manual, Rev 4, November 2014 pg. 1393
#[bitsize(8)]
#[derive(DebugBits, Default, FromBits, Clone)]
pub struct SFIFO {
    pub rxuf: u1,
    pub txof: u1,
    pub rxof: u1,
    pub reserved: u3,
    pub rxempt: u1,
    pub txempt: u1,
}

/// Inner Uart struct, thinly wraps HAL in a bunch of conveinence
/// wrappers.
#[allow(dead_code)]
#[derive(Default, Getters, Debug)]
#[getset(get = "pub")]
pub struct UartHalLayer {
    pub(crate) bdh: BDH,
    pub(crate) bdl: BDL,
    pub(crate) c1: C1,
    pub(crate) c2: C2,
    pub(crate) s1: S1,
    pub(crate) s2: S2,
    pub(crate) c3: C3,
    pub(crate) d: D,
    pub(crate) ma1: MA1,
    pub(crate) ma2: MA2,
    pub(crate) c4: C4,
    pub(crate) c5: C5,
    pub(crate) ed: ED,
    pub(crate) modem: MODEM,
    pub(crate) ir: IR,
    pub(crate) pfifo: PFIFO,
    pub(crate) cfifo: CFIFO,
    pub(crate) sfifo: SFIFO,
}

impl UartHalLayer {
    #[allow(dead_code)]
    pub fn from_bytes(data: &[u8; 18]) -> Self {
        UartHalLayer {
            bdh: BDH::from(data[0]),
            bdl: BDL::from(data[1]),
            c1: C1::from(data[2]),
            c2: C2::from(data[3]),
            s1: S1::from(data[4]),
            s2: S2::from(data[5]),
            c3: C3::from(data[6]),
            d: D::from(data[7]),
            ma1: MA1::from(data[8]),
            ma2: MA2::from(data[9]),
            c4: C4::from(data[10]),
            c5: C5::from(data[11]),
            ed: ED::from(data[12]),
            modem: MODEM::from(data[13]),
            ir: IR::from(data[14]),
            pfifo: PFIFO::from(data[15]),
            cfifo: CFIFO::from(data[16]),
            sfifo: SFIFO::from(data[17]),
        }
    }
}
