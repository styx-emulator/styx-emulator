// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `irqstat` reader"]
pub type R = crate::R<IrqstatSpec>;
#[doc = "Register `irqstat` writer"]
pub type W = crate::W<IrqstatSpec>;
#[doc = "An underflow is detected when an attempt to transfer data is made when the transmit FIFO is empty. This may occur when the AHB write data is being supplied too slowly to keep up with the requested write operation. This bit is reset only by a system reset and cleared only when the register is read.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Underflowdet {
    #[doc = "1: `1`"]
    Underflow = 1,
    #[doc = "0: `0`"]
    Nounderflow = 0,
}
impl From<Underflowdet> for bool {
    #[inline(always)]
    fn from(variant: Underflowdet) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `underflowdet` reader - An underflow is detected when an attempt to transfer data is made when the transmit FIFO is empty. This may occur when the AHB write data is being supplied too slowly to keep up with the requested write operation. This bit is reset only by a system reset and cleared only when the register is read."]
pub type UnderflowdetR = crate::BitReader<Underflowdet>;
impl UnderflowdetR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Underflowdet {
        match self.bits {
            true => Underflowdet::Underflow,
            false => Underflowdet::Nounderflow,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_underflow(&self) -> bool {
        *self == Underflowdet::Underflow
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nounderflow(&self) -> bool {
        *self == Underflowdet::Nounderflow
    }
}
#[doc = "Field `underflowdet` writer - An underflow is detected when an attempt to transfer data is made when the transmit FIFO is empty. This may occur when the AHB write data is being supplied too slowly to keep up with the requested write operation. This bit is reset only by a system reset and cleared only when the register is read."]
pub type UnderflowdetW<'a, REG> = crate::BitWriter1C<'a, REG, Underflowdet>;
impl<'a, REG> UnderflowdetW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn underflow(self) -> &'a mut crate::W<REG> {
        self.variant(Underflowdet::Underflow)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nounderflow(self) -> &'a mut crate::W<REG> {
        self.variant(Underflowdet::Nounderflow)
    }
}
#[doc = "Controller has completed last triggered indirect operation\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indopdone {
    #[doc = "1: `1`"]
    Indirectop = 1,
    #[doc = "0: `0`"]
    Noindirectop = 0,
}
impl From<Indopdone> for bool {
    #[inline(always)]
    fn from(variant: Indopdone) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indopdone` reader - Controller has completed last triggered indirect operation"]
pub type IndopdoneR = crate::BitReader<Indopdone>;
impl IndopdoneR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indopdone {
        match self.bits {
            true => Indopdone::Indirectop,
            false => Indopdone::Noindirectop,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_indirectop(&self) -> bool {
        *self == Indopdone::Indirectop
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noindirectop(&self) -> bool {
        *self == Indopdone::Noindirectop
    }
}
#[doc = "Field `indopdone` writer - Controller has completed last triggered indirect operation"]
pub type IndopdoneW<'a, REG> = crate::BitWriter1C<'a, REG, Indopdone>;
impl<'a, REG> IndopdoneW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn indirectop(self) -> &'a mut crate::W<REG> {
        self.variant(Indopdone::Indirectop)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noindirectop(self) -> &'a mut crate::W<REG> {
        self.variant(Indopdone::Noindirectop)
    }
}
#[doc = "Indirect operation was requested but could not be accepted. Two indirect operations already in storage.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indrdreject {
    #[doc = "1: `1`"]
    Indirectreq = 1,
    #[doc = "0: `0`"]
    Noindirectreq = 0,
}
impl From<Indrdreject> for bool {
    #[inline(always)]
    fn from(variant: Indrdreject) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indrdreject` reader - Indirect operation was requested but could not be accepted. Two indirect operations already in storage."]
pub type IndrdrejectR = crate::BitReader<Indrdreject>;
impl IndrdrejectR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indrdreject {
        match self.bits {
            true => Indrdreject::Indirectreq,
            false => Indrdreject::Noindirectreq,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_indirectreq(&self) -> bool {
        *self == Indrdreject::Indirectreq
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noindirectreq(&self) -> bool {
        *self == Indrdreject::Noindirectreq
    }
}
#[doc = "Field `indrdreject` writer - Indirect operation was requested but could not be accepted. Two indirect operations already in storage."]
pub type IndrdrejectW<'a, REG> = crate::BitWriter1C<'a, REG, Indrdreject>;
impl<'a, REG> IndrdrejectW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn indirectreq(self) -> &'a mut crate::W<REG> {
        self.variant(Indrdreject::Indirectreq)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noindirectreq(self) -> &'a mut crate::W<REG> {
        self.variant(Indrdreject::Noindirectreq)
    }
}
#[doc = "Write to protected area was attempted and rejected.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protwrattempt {
    #[doc = "1: `1`"]
    Writeprot = 1,
    #[doc = "0: `0`"]
    Nowriteprot = 0,
}
impl From<Protwrattempt> for bool {
    #[inline(always)]
    fn from(variant: Protwrattempt) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `protwrattempt` reader - Write to protected area was attempted and rejected."]
pub type ProtwrattemptR = crate::BitReader<Protwrattempt>;
impl ProtwrattemptR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Protwrattempt {
        match self.bits {
            true => Protwrattempt::Writeprot,
            false => Protwrattempt::Nowriteprot,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_writeprot(&self) -> bool {
        *self == Protwrattempt::Writeprot
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nowriteprot(&self) -> bool {
        *self == Protwrattempt::Nowriteprot
    }
}
#[doc = "Field `protwrattempt` writer - Write to protected area was attempted and rejected."]
pub type ProtwrattemptW<'a, REG> = crate::BitWriter1C<'a, REG, Protwrattempt>;
impl<'a, REG> ProtwrattemptW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn writeprot(self) -> &'a mut crate::W<REG> {
        self.variant(Protwrattempt::Writeprot)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nowriteprot(self) -> &'a mut crate::W<REG> {
        self.variant(Protwrattempt::Nowriteprot)
    }
}
#[doc = "Illegal AHB access has been detected. AHB wrapping bursts and the use of SPLIT/RETRY accesses will cause this error interrupt to trigger.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Illegalacc {
    #[doc = "1: `1`"]
    Illegalahb = 1,
    #[doc = "0: `0`"]
    Noillegalahb = 0,
}
impl From<Illegalacc> for bool {
    #[inline(always)]
    fn from(variant: Illegalacc) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `illegalacc` reader - Illegal AHB access has been detected. AHB wrapping bursts and the use of SPLIT/RETRY accesses will cause this error interrupt to trigger."]
pub type IllegalaccR = crate::BitReader<Illegalacc>;
impl IllegalaccR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Illegalacc {
        match self.bits {
            true => Illegalacc::Illegalahb,
            false => Illegalacc::Noillegalahb,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_illegalahb(&self) -> bool {
        *self == Illegalacc::Illegalahb
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noillegalahb(&self) -> bool {
        *self == Illegalacc::Noillegalahb
    }
}
#[doc = "Field `illegalacc` writer - Illegal AHB access has been detected. AHB wrapping bursts and the use of SPLIT/RETRY accesses will cause this error interrupt to trigger."]
pub type IllegalaccW<'a, REG> = crate::BitWriter1C<'a, REG, Illegalacc>;
impl<'a, REG> IllegalaccW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn illegalahb(self) -> &'a mut crate::W<REG> {
        self.variant(Illegalacc::Illegalahb)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noillegalahb(self) -> &'a mut crate::W<REG> {
        self.variant(Illegalacc::Noillegalahb)
    }
}
#[doc = "Indirect Transfer Watermark Level Reached\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indxfrlvl {
    #[doc = "1: `1`"]
    Waterlevl = 1,
    #[doc = "0: `0`"]
    Nowaterlvl = 0,
}
impl From<Indxfrlvl> for bool {
    #[inline(always)]
    fn from(variant: Indxfrlvl) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indxfrlvl` reader - Indirect Transfer Watermark Level Reached"]
pub type IndxfrlvlR = crate::BitReader<Indxfrlvl>;
impl IndxfrlvlR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indxfrlvl {
        match self.bits {
            true => Indxfrlvl::Waterlevl,
            false => Indxfrlvl::Nowaterlvl,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_waterlevl(&self) -> bool {
        *self == Indxfrlvl::Waterlevl
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_nowaterlvl(&self) -> bool {
        *self == Indxfrlvl::Nowaterlvl
    }
}
#[doc = "Field `indxfrlvl` writer - Indirect Transfer Watermark Level Reached"]
pub type IndxfrlvlW<'a, REG> = crate::BitWriter1C<'a, REG, Indxfrlvl>;
impl<'a, REG> IndxfrlvlW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn waterlevl(self) -> &'a mut crate::W<REG> {
        self.variant(Indxfrlvl::Waterlevl)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn nowaterlvl(self) -> &'a mut crate::W<REG> {
        self.variant(Indxfrlvl::Nowaterlvl)
    }
}
#[doc = "This should only occur in Legacy SPI mode. Set if an attempt is made to push the RX FIFO when it is full. This bit is reset only by a system reset and cleared only when this register is read. If a new push to the RX FIFO occurs coincident with a register read this flag will remain set. 0 : no overflow has been detected. 1 : an overflow has occurred.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxover {
    #[doc = "1: `1`"]
    Rcvover = 1,
    #[doc = "0: `0`"]
    Norcvover = 0,
}
impl From<Rxover> for bool {
    #[inline(always)]
    fn from(variant: Rxover) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxover` reader - This should only occur in Legacy SPI mode. Set if an attempt is made to push the RX FIFO when it is full. This bit is reset only by a system reset and cleared only when this register is read. If a new push to the RX FIFO occurs coincident with a register read this flag will remain set. 0 : no overflow has been detected. 1 : an overflow has occurred."]
pub type RxoverR = crate::BitReader<Rxover>;
impl RxoverR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxover {
        match self.bits {
            true => Rxover::Rcvover,
            false => Rxover::Norcvover,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rcvover(&self) -> bool {
        *self == Rxover::Rcvover
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_norcvover(&self) -> bool {
        *self == Rxover::Norcvover
    }
}
#[doc = "Field `rxover` writer - This should only occur in Legacy SPI mode. Set if an attempt is made to push the RX FIFO when it is full. This bit is reset only by a system reset and cleared only when this register is read. If a new push to the RX FIFO occurs coincident with a register read this flag will remain set. 0 : no overflow has been detected. 1 : an overflow has occurred."]
pub type RxoverW<'a, REG> = crate::BitWriter1C<'a, REG, Rxover>;
impl<'a, REG> RxoverW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn rcvover(self) -> &'a mut crate::W<REG> {
        self.variant(Rxover::Rcvover)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn norcvover(self) -> &'a mut crate::W<REG> {
        self.variant(Rxover::Norcvover)
    }
}
#[doc = "Indicates the number of entries in the transmit FIFO with respect to the threshold specified in the TXTHRESH register. Only relevant in SPI legacy mode.\n\nValue on reset: 1"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txthreshcmp {
    #[doc = "0: `0`"]
    Gt = 0,
    #[doc = "1: `1`"]
    Le = 1,
}
impl From<Txthreshcmp> for bool {
    #[inline(always)]
    fn from(variant: Txthreshcmp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txthreshcmp` reader - Indicates the number of entries in the transmit FIFO with respect to the threshold specified in the TXTHRESH register. Only relevant in SPI legacy mode."]
pub type TxthreshcmpR = crate::BitReader<Txthreshcmp>;
impl TxthreshcmpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txthreshcmp {
        match self.bits {
            false => Txthreshcmp::Gt,
            true => Txthreshcmp::Le,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_gt(&self) -> bool {
        *self == Txthreshcmp::Gt
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_le(&self) -> bool {
        *self == Txthreshcmp::Le
    }
}
#[doc = "Field `txthreshcmp` writer - Indicates the number of entries in the transmit FIFO with respect to the threshold specified in the TXTHRESH register. Only relevant in SPI legacy mode."]
pub type TxthreshcmpW<'a, REG> = crate::BitWriter1C<'a, REG, Txthreshcmp>;
impl<'a, REG> TxthreshcmpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn gt(self) -> &'a mut crate::W<REG> {
        self.variant(Txthreshcmp::Gt)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn le(self) -> &'a mut crate::W<REG> {
        self.variant(Txthreshcmp::Le)
    }
}
#[doc = "Indicates that the transmit FIFO is full or not. Only relevant in SPI legacy mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txfull {
    #[doc = "0: `0`"]
    Notfull = 0,
    #[doc = "1: `1`"]
    Full = 1,
}
impl From<Txfull> for bool {
    #[inline(always)]
    fn from(variant: Txfull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txfull` reader - Indicates that the transmit FIFO is full or not. Only relevant in SPI legacy mode."]
pub type TxfullR = crate::BitReader<Txfull>;
impl TxfullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txfull {
        match self.bits {
            false => Txfull::Notfull,
            true => Txfull::Full,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notfull(&self) -> bool {
        *self == Txfull::Notfull
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Txfull::Full
    }
}
#[doc = "Field `txfull` writer - Indicates that the transmit FIFO is full or not. Only relevant in SPI legacy mode."]
pub type TxfullW<'a, REG> = crate::BitWriter1C<'a, REG, Txfull>;
impl<'a, REG> TxfullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notfull(self) -> &'a mut crate::W<REG> {
        self.variant(Txfull::Notfull)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn full(self) -> &'a mut crate::W<REG> {
        self.variant(Txfull::Full)
    }
}
#[doc = "Indicates the number of entries in the receive FIFO with respect to the threshold specified in the RXTHRESH register. Only relevant in SPI legacy mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxthreshcmp {
    #[doc = "0: `0`"]
    Le = 0,
    #[doc = "1: `1`"]
    Gt = 1,
}
impl From<Rxthreshcmp> for bool {
    #[inline(always)]
    fn from(variant: Rxthreshcmp) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxthreshcmp` reader - Indicates the number of entries in the receive FIFO with respect to the threshold specified in the RXTHRESH register. Only relevant in SPI legacy mode."]
pub type RxthreshcmpR = crate::BitReader<Rxthreshcmp>;
impl RxthreshcmpR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxthreshcmp {
        match self.bits {
            false => Rxthreshcmp::Le,
            true => Rxthreshcmp::Gt,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_le(&self) -> bool {
        *self == Rxthreshcmp::Le
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_gt(&self) -> bool {
        *self == Rxthreshcmp::Gt
    }
}
#[doc = "Field `rxthreshcmp` writer - Indicates the number of entries in the receive FIFO with respect to the threshold specified in the RXTHRESH register. Only relevant in SPI legacy mode."]
pub type RxthreshcmpW<'a, REG> = crate::BitWriter1C<'a, REG, Rxthreshcmp>;
impl<'a, REG> RxthreshcmpW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn le(self) -> &'a mut crate::W<REG> {
        self.variant(Rxthreshcmp::Le)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn gt(self) -> &'a mut crate::W<REG> {
        self.variant(Rxthreshcmp::Gt)
    }
}
#[doc = "Indicates that the receive FIFO is full or not. Only relevant in SPI legacy mode.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfull {
    #[doc = "0: `0`"]
    Notfull = 0,
    #[doc = "1: `1`"]
    Full = 1,
}
impl From<Rxfull> for bool {
    #[inline(always)]
    fn from(variant: Rxfull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfull` reader - Indicates that the receive FIFO is full or not. Only relevant in SPI legacy mode."]
pub type RxfullR = crate::BitReader<Rxfull>;
impl RxfullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfull {
        match self.bits {
            false => Rxfull::Notfull,
            true => Rxfull::Full,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_notfull(&self) -> bool {
        *self == Rxfull::Notfull
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        *self == Rxfull::Full
    }
}
#[doc = "Field `rxfull` writer - Indicates that the receive FIFO is full or not. Only relevant in SPI legacy mode."]
pub type RxfullW<'a, REG> = crate::BitWriter1C<'a, REG, Rxfull>;
impl<'a, REG> RxfullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn notfull(self) -> &'a mut crate::W<REG> {
        self.variant(Rxfull::Notfull)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn full(self) -> &'a mut crate::W<REG> {
        self.variant(Rxfull::Full)
    }
}
#[doc = "Indirect Read Partition of SRAM is full and unable to immediately complete indirect operation\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indsramfull {
    #[doc = "1: `1`"]
    Rdpartfull = 1,
    #[doc = "0: `0`"]
    Rdpartnotfull = 0,
}
impl From<Indsramfull> for bool {
    #[inline(always)]
    fn from(variant: Indsramfull) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `indsramfull` reader - Indirect Read Partition of SRAM is full and unable to immediately complete indirect operation"]
pub type IndsramfullR = crate::BitReader<Indsramfull>;
impl IndsramfullR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Indsramfull {
        match self.bits {
            true => Indsramfull::Rdpartfull,
            false => Indsramfull::Rdpartnotfull,
        }
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_rdpartfull(&self) -> bool {
        *self == Indsramfull::Rdpartfull
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_rdpartnotfull(&self) -> bool {
        *self == Indsramfull::Rdpartnotfull
    }
}
#[doc = "Field `indsramfull` writer - Indirect Read Partition of SRAM is full and unable to immediately complete indirect operation"]
pub type IndsramfullW<'a, REG> = crate::BitWriter1C<'a, REG, Indsramfull>;
impl<'a, REG> IndsramfullW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
{
    #[doc = "`1`"]
    #[inline(always)]
    pub fn rdpartfull(self) -> &'a mut crate::W<REG> {
        self.variant(Indsramfull::Rdpartfull)
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn rdpartnotfull(self) -> &'a mut crate::W<REG> {
        self.variant(Indsramfull::Rdpartnotfull)
    }
}
impl R {
    #[doc = "Bit 1 - An underflow is detected when an attempt to transfer data is made when the transmit FIFO is empty. This may occur when the AHB write data is being supplied too slowly to keep up with the requested write operation. This bit is reset only by a system reset and cleared only when the register is read."]
    #[inline(always)]
    pub fn underflowdet(&self) -> UnderflowdetR {
        UnderflowdetR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Controller has completed last triggered indirect operation"]
    #[inline(always)]
    pub fn indopdone(&self) -> IndopdoneR {
        IndopdoneR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Indirect operation was requested but could not be accepted. Two indirect operations already in storage."]
    #[inline(always)]
    pub fn indrdreject(&self) -> IndrdrejectR {
        IndrdrejectR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Write to protected area was attempted and rejected."]
    #[inline(always)]
    pub fn protwrattempt(&self) -> ProtwrattemptR {
        ProtwrattemptR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Illegal AHB access has been detected. AHB wrapping bursts and the use of SPLIT/RETRY accesses will cause this error interrupt to trigger."]
    #[inline(always)]
    pub fn illegalacc(&self) -> IllegalaccR {
        IllegalaccR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Indirect Transfer Watermark Level Reached"]
    #[inline(always)]
    pub fn indxfrlvl(&self) -> IndxfrlvlR {
        IndxfrlvlR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - This should only occur in Legacy SPI mode. Set if an attempt is made to push the RX FIFO when it is full. This bit is reset only by a system reset and cleared only when this register is read. If a new push to the RX FIFO occurs coincident with a register read this flag will remain set. 0 : no overflow has been detected. 1 : an overflow has occurred."]
    #[inline(always)]
    pub fn rxover(&self) -> RxoverR {
        RxoverR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Indicates the number of entries in the transmit FIFO with respect to the threshold specified in the TXTHRESH register. Only relevant in SPI legacy mode."]
    #[inline(always)]
    pub fn txthreshcmp(&self) -> TxthreshcmpR {
        TxthreshcmpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Indicates that the transmit FIFO is full or not. Only relevant in SPI legacy mode."]
    #[inline(always)]
    pub fn txfull(&self) -> TxfullR {
        TxfullR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Indicates the number of entries in the receive FIFO with respect to the threshold specified in the RXTHRESH register. Only relevant in SPI legacy mode."]
    #[inline(always)]
    pub fn rxthreshcmp(&self) -> RxthreshcmpR {
        RxthreshcmpR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Indicates that the receive FIFO is full or not. Only relevant in SPI legacy mode."]
    #[inline(always)]
    pub fn rxfull(&self) -> RxfullR {
        RxfullR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Indirect Read Partition of SRAM is full and unable to immediately complete indirect operation"]
    #[inline(always)]
    pub fn indsramfull(&self) -> IndsramfullR {
        IndsramfullR::new(((self.bits >> 12) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - An underflow is detected when an attempt to transfer data is made when the transmit FIFO is empty. This may occur when the AHB write data is being supplied too slowly to keep up with the requested write operation. This bit is reset only by a system reset and cleared only when the register is read."]
    #[inline(always)]
    #[must_use]
    pub fn underflowdet(&mut self) -> UnderflowdetW<IrqstatSpec> {
        UnderflowdetW::new(self, 1)
    }
    #[doc = "Bit 2 - Controller has completed last triggered indirect operation"]
    #[inline(always)]
    #[must_use]
    pub fn indopdone(&mut self) -> IndopdoneW<IrqstatSpec> {
        IndopdoneW::new(self, 2)
    }
    #[doc = "Bit 3 - Indirect operation was requested but could not be accepted. Two indirect operations already in storage."]
    #[inline(always)]
    #[must_use]
    pub fn indrdreject(&mut self) -> IndrdrejectW<IrqstatSpec> {
        IndrdrejectW::new(self, 3)
    }
    #[doc = "Bit 4 - Write to protected area was attempted and rejected."]
    #[inline(always)]
    #[must_use]
    pub fn protwrattempt(&mut self) -> ProtwrattemptW<IrqstatSpec> {
        ProtwrattemptW::new(self, 4)
    }
    #[doc = "Bit 5 - Illegal AHB access has been detected. AHB wrapping bursts and the use of SPLIT/RETRY accesses will cause this error interrupt to trigger."]
    #[inline(always)]
    #[must_use]
    pub fn illegalacc(&mut self) -> IllegalaccW<IrqstatSpec> {
        IllegalaccW::new(self, 5)
    }
    #[doc = "Bit 6 - Indirect Transfer Watermark Level Reached"]
    #[inline(always)]
    #[must_use]
    pub fn indxfrlvl(&mut self) -> IndxfrlvlW<IrqstatSpec> {
        IndxfrlvlW::new(self, 6)
    }
    #[doc = "Bit 7 - This should only occur in Legacy SPI mode. Set if an attempt is made to push the RX FIFO when it is full. This bit is reset only by a system reset and cleared only when this register is read. If a new push to the RX FIFO occurs coincident with a register read this flag will remain set. 0 : no overflow has been detected. 1 : an overflow has occurred."]
    #[inline(always)]
    #[must_use]
    pub fn rxover(&mut self) -> RxoverW<IrqstatSpec> {
        RxoverW::new(self, 7)
    }
    #[doc = "Bit 8 - Indicates the number of entries in the transmit FIFO with respect to the threshold specified in the TXTHRESH register. Only relevant in SPI legacy mode."]
    #[inline(always)]
    #[must_use]
    pub fn txthreshcmp(&mut self) -> TxthreshcmpW<IrqstatSpec> {
        TxthreshcmpW::new(self, 8)
    }
    #[doc = "Bit 9 - Indicates that the transmit FIFO is full or not. Only relevant in SPI legacy mode."]
    #[inline(always)]
    #[must_use]
    pub fn txfull(&mut self) -> TxfullW<IrqstatSpec> {
        TxfullW::new(self, 9)
    }
    #[doc = "Bit 10 - Indicates the number of entries in the receive FIFO with respect to the threshold specified in the RXTHRESH register. Only relevant in SPI legacy mode."]
    #[inline(always)]
    #[must_use]
    pub fn rxthreshcmp(&mut self) -> RxthreshcmpW<IrqstatSpec> {
        RxthreshcmpW::new(self, 10)
    }
    #[doc = "Bit 11 - Indicates that the receive FIFO is full or not. Only relevant in SPI legacy mode."]
    #[inline(always)]
    #[must_use]
    pub fn rxfull(&mut self) -> RxfullW<IrqstatSpec> {
        RxfullW::new(self, 11)
    }
    #[doc = "Bit 12 - Indirect Read Partition of SRAM is full and unable to immediately complete indirect operation"]
    #[inline(always)]
    #[must_use]
    pub fn indsramfull(&mut self) -> IndsramfullW<IrqstatSpec> {
        IndsramfullW::new(self, 12)
    }
}
#[doc = "The status fields in this register are set when the described event occurs and the interrupt is enabled in the mask register. When any of these bit fields are set, the interrupt output is asserted high. The fields are each cleared by writing a 1 to the field. Note that bit fields 7 thru 11 are only valid when legacy SPI mode is active.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`irqstat::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`irqstat::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IrqstatSpec;
impl crate::RegisterSpec for IrqstatSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`irqstat::R`](R) reader structure"]
impl crate::Readable for IrqstatSpec {}
#[doc = "`write(|w| ..)` method takes [`irqstat::W`](W) writer structure"]
impl crate::Writable for IrqstatSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x1ffe;
}
#[doc = "`reset()` method sets irqstat to value 0x0100"]
impl crate::Resettable for IrqstatSpec {
    const RESET_VALUE: u32 = 0x0100;
}
