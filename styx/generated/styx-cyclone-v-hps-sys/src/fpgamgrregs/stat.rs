// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `stat` reader"]
pub type R = crate::R<StatSpec>;
#[doc = "Register `stat` writer"]
pub type W = crate::W<StatSpec>;
#[doc = "Reports FPGA state\n\nValue on reset: 5"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    #[doc = "0: `0`"]
    Fpgaoff = 0,
    #[doc = "1: `1`"]
    ResetPhase = 1,
    #[doc = "2: `10`"]
    CfgPhase = 2,
    #[doc = "3: `11`"]
    InitPhase = 3,
    #[doc = "4: `100`"]
    UserMode = 4,
    #[doc = "5: `101`"]
    Unknown = 5,
}
impl From<Mode> for u8 {
    #[inline(always)]
    fn from(variant: Mode) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Mode {
    type Ux = u8;
}
#[doc = "Field `mode` reader - Reports FPGA state"]
pub type ModeR = crate::FieldReader<Mode>;
impl ModeR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Mode> {
        match self.bits {
            0 => Some(Mode::Fpgaoff),
            1 => Some(Mode::ResetPhase),
            2 => Some(Mode::CfgPhase),
            3 => Some(Mode::InitPhase),
            4 => Some(Mode::UserMode),
            5 => Some(Mode::Unknown),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_fpgaoff(&self) -> bool {
        *self == Mode::Fpgaoff
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_reset_phase(&self) -> bool {
        *self == Mode::ResetPhase
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_cfg_phase(&self) -> bool {
        *self == Mode::CfgPhase
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_init_phase(&self) -> bool {
        *self == Mode::InitPhase
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_user_mode(&self) -> bool {
        *self == Mode::UserMode
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_unknown(&self) -> bool {
        *self == Mode::Unknown
    }
}
#[doc = "Field `mode` writer - Reports FPGA state"]
pub type ModeW<'a, REG> = crate::FieldWriter<'a, REG, 3, Mode>;
impl<'a, REG> ModeW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn fpgaoff(self) -> &'a mut crate::W<REG> {
        self.variant(Mode::Fpgaoff)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn reset_phase(self) -> &'a mut crate::W<REG> {
        self.variant(Mode::ResetPhase)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn cfg_phase(self) -> &'a mut crate::W<REG> {
        self.variant(Mode::CfgPhase)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn init_phase(self) -> &'a mut crate::W<REG> {
        self.variant(Mode::InitPhase)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn user_mode(self) -> &'a mut crate::W<REG> {
        self.variant(Mode::UserMode)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn unknown(self) -> &'a mut crate::W<REG> {
        self.variant(Mode::Unknown)
    }
}
#[doc = "This read-only field allows software to observe the MSEL inputs from the device pins. The MSEL pins define the FPGA configuration mode.\n\nValue on reset: 8"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Msel {
    #[doc = "0: `0`"]
    Pp16FastNoaesNodc = 0,
    #[doc = "1: `1`"]
    Pp16FastAesNodc = 1,
    #[doc = "2: `10`"]
    Pp16FastAesoptDc = 2,
    #[doc = "3: `11`"]
    Rsvd3 = 3,
    #[doc = "4: `100`"]
    Pp16SlowNoaesNodc = 4,
    #[doc = "5: `101`"]
    Pp16SlowAesNodc = 5,
    #[doc = "6: `110`"]
    Pp16SlowAesoptDc = 6,
    #[doc = "7: `111`"]
    Rsvd7 = 7,
    #[doc = "8: `1000`"]
    Pp32FastNoaesNodc = 8,
    #[doc = "9: `1001`"]
    Pp32FastAesNodc = 9,
    #[doc = "10: `1010`"]
    Pp32FastAesoptDc = 10,
    #[doc = "11: `1011`"]
    Rsvd11 = 11,
    #[doc = "12: `1100`"]
    Pp32SlowNoaesNodc = 12,
    #[doc = "13: `1101`"]
    Pp32SlowAesNodc = 13,
    #[doc = "14: `1110`"]
    Pp32SlowAesoptDc = 14,
    #[doc = "15: `1111`"]
    Rsvd15 = 15,
    #[doc = "16: `10000`"]
    Rsvd16 = 16,
    #[doc = "17: `10001`"]
    Rsvd17 = 17,
    #[doc = "18: `10010`"]
    Rsvd18 = 18,
    #[doc = "19: `10011`"]
    Rsvd19 = 19,
    #[doc = "20: `10100`"]
    Rsvd20 = 20,
    #[doc = "21: `10101`"]
    Rsvd21 = 21,
    #[doc = "22: `10110`"]
    Rsvd22 = 22,
    #[doc = "23: `10111`"]
    Rsvd23 = 23,
    #[doc = "24: `11000`"]
    Rsvd24 = 24,
    #[doc = "25: `11001`"]
    Rsvd25 = 25,
    #[doc = "26: `11010`"]
    Rsvd26 = 26,
    #[doc = "27: `11011`"]
    Rsvd27 = 27,
    #[doc = "28: `11100`"]
    Rsvd28 = 28,
    #[doc = "29: `11101`"]
    Rsvd29 = 29,
    #[doc = "30: `11110`"]
    Rsvd30 = 30,
    #[doc = "31: `11111`"]
    Rsvd31 = 31,
}
impl From<Msel> for u8 {
    #[inline(always)]
    fn from(variant: Msel) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Msel {
    type Ux = u8;
}
#[doc = "Field `msel` reader - This read-only field allows software to observe the MSEL inputs from the device pins. The MSEL pins define the FPGA configuration mode."]
pub type MselR = crate::FieldReader<Msel>;
impl MselR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Msel {
        match self.bits {
            0 => Msel::Pp16FastNoaesNodc,
            1 => Msel::Pp16FastAesNodc,
            2 => Msel::Pp16FastAesoptDc,
            3 => Msel::Rsvd3,
            4 => Msel::Pp16SlowNoaesNodc,
            5 => Msel::Pp16SlowAesNodc,
            6 => Msel::Pp16SlowAesoptDc,
            7 => Msel::Rsvd7,
            8 => Msel::Pp32FastNoaesNodc,
            9 => Msel::Pp32FastAesNodc,
            10 => Msel::Pp32FastAesoptDc,
            11 => Msel::Rsvd11,
            12 => Msel::Pp32SlowNoaesNodc,
            13 => Msel::Pp32SlowAesNodc,
            14 => Msel::Pp32SlowAesoptDc,
            15 => Msel::Rsvd15,
            16 => Msel::Rsvd16,
            17 => Msel::Rsvd17,
            18 => Msel::Rsvd18,
            19 => Msel::Rsvd19,
            20 => Msel::Rsvd20,
            21 => Msel::Rsvd21,
            22 => Msel::Rsvd22,
            23 => Msel::Rsvd23,
            24 => Msel::Rsvd24,
            25 => Msel::Rsvd25,
            26 => Msel::Rsvd26,
            27 => Msel::Rsvd27,
            28 => Msel::Rsvd28,
            29 => Msel::Rsvd29,
            30 => Msel::Rsvd30,
            31 => Msel::Rsvd31,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_pp16_fast_noaes_nodc(&self) -> bool {
        *self == Msel::Pp16FastNoaesNodc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pp16_fast_aes_nodc(&self) -> bool {
        *self == Msel::Pp16FastAesNodc
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_pp16_fast_aesopt_dc(&self) -> bool {
        *self == Msel::Pp16FastAesoptDc
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_rsvd3(&self) -> bool {
        *self == Msel::Rsvd3
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_pp16_slow_noaes_nodc(&self) -> bool {
        *self == Msel::Pp16SlowNoaesNodc
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_pp16_slow_aes_nodc(&self) -> bool {
        *self == Msel::Pp16SlowAesNodc
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_pp16_slow_aesopt_dc(&self) -> bool {
        *self == Msel::Pp16SlowAesoptDc
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_rsvd7(&self) -> bool {
        *self == Msel::Rsvd7
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_pp32_fast_noaes_nodc(&self) -> bool {
        *self == Msel::Pp32FastNoaesNodc
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_pp32_fast_aes_nodc(&self) -> bool {
        *self == Msel::Pp32FastAesNodc
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_pp32_fast_aesopt_dc(&self) -> bool {
        *self == Msel::Pp32FastAesoptDc
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_rsvd11(&self) -> bool {
        *self == Msel::Rsvd11
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_pp32_slow_noaes_nodc(&self) -> bool {
        *self == Msel::Pp32SlowNoaesNodc
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_pp32_slow_aes_nodc(&self) -> bool {
        *self == Msel::Pp32SlowAesNodc
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_pp32_slow_aesopt_dc(&self) -> bool {
        *self == Msel::Pp32SlowAesoptDc
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_rsvd15(&self) -> bool {
        *self == Msel::Rsvd15
    }
    #[doc = "`10000`"]
    #[inline(always)]
    pub fn is_rsvd16(&self) -> bool {
        *self == Msel::Rsvd16
    }
    #[doc = "`10001`"]
    #[inline(always)]
    pub fn is_rsvd17(&self) -> bool {
        *self == Msel::Rsvd17
    }
    #[doc = "`10010`"]
    #[inline(always)]
    pub fn is_rsvd18(&self) -> bool {
        *self == Msel::Rsvd18
    }
    #[doc = "`10011`"]
    #[inline(always)]
    pub fn is_rsvd19(&self) -> bool {
        *self == Msel::Rsvd19
    }
    #[doc = "`10100`"]
    #[inline(always)]
    pub fn is_rsvd20(&self) -> bool {
        *self == Msel::Rsvd20
    }
    #[doc = "`10101`"]
    #[inline(always)]
    pub fn is_rsvd21(&self) -> bool {
        *self == Msel::Rsvd21
    }
    #[doc = "`10110`"]
    #[inline(always)]
    pub fn is_rsvd22(&self) -> bool {
        *self == Msel::Rsvd22
    }
    #[doc = "`10111`"]
    #[inline(always)]
    pub fn is_rsvd23(&self) -> bool {
        *self == Msel::Rsvd23
    }
    #[doc = "`11000`"]
    #[inline(always)]
    pub fn is_rsvd24(&self) -> bool {
        *self == Msel::Rsvd24
    }
    #[doc = "`11001`"]
    #[inline(always)]
    pub fn is_rsvd25(&self) -> bool {
        *self == Msel::Rsvd25
    }
    #[doc = "`11010`"]
    #[inline(always)]
    pub fn is_rsvd26(&self) -> bool {
        *self == Msel::Rsvd26
    }
    #[doc = "`11011`"]
    #[inline(always)]
    pub fn is_rsvd27(&self) -> bool {
        *self == Msel::Rsvd27
    }
    #[doc = "`11100`"]
    #[inline(always)]
    pub fn is_rsvd28(&self) -> bool {
        *self == Msel::Rsvd28
    }
    #[doc = "`11101`"]
    #[inline(always)]
    pub fn is_rsvd29(&self) -> bool {
        *self == Msel::Rsvd29
    }
    #[doc = "`11110`"]
    #[inline(always)]
    pub fn is_rsvd30(&self) -> bool {
        *self == Msel::Rsvd30
    }
    #[doc = "`11111`"]
    #[inline(always)]
    pub fn is_rsvd31(&self) -> bool {
        *self == Msel::Rsvd31
    }
}
#[doc = "Field `msel` writer - This read-only field allows software to observe the MSEL inputs from the device pins. The MSEL pins define the FPGA configuration mode."]
pub type MselW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:2 - Reports FPGA state"]
    #[inline(always)]
    pub fn mode(&self) -> ModeR {
        ModeR::new((self.bits & 7) as u8)
    }
    #[doc = "Bits 3:7 - This read-only field allows software to observe the MSEL inputs from the device pins. The MSEL pins define the FPGA configuration mode."]
    #[inline(always)]
    pub fn msel(&self) -> MselR {
        MselR::new(((self.bits >> 3) & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - Reports FPGA state"]
    #[inline(always)]
    #[must_use]
    pub fn mode(&mut self) -> ModeW<StatSpec> {
        ModeW::new(self, 0)
    }
    #[doc = "Bits 3:7 - This read-only field allows software to observe the MSEL inputs from the device pins. The MSEL pins define the FPGA configuration mode."]
    #[inline(always)]
    #[must_use]
    pub fn msel(&mut self) -> MselW<StatSpec> {
        MselW::new(self, 3)
    }
}
#[doc = "Provides status fields for software for the FPGA Manager. The Mode field tells software what configuration phase the FPGA currently is in. For regular configuration through the PINs or through the HPS, these states map directly to customer configuration documentation. For Configuration Via PCI Express (CVP), the IOCSR configuration is done through the PINS or through HPS. Then the complete configuration is done through the PCI Express Bus. When CVP is being done, InitPhase indicates only IOCSR configuration has completed. CVP_CONF_DONE is available in the CB Monitor for observation by software. The MSEL field provides a read only register for software to read the MSEL value driven from the external pins.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`stat::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`stat::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatSpec;
impl crate::RegisterSpec for StatSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`stat::R`](R) reader structure"]
impl crate::Readable for StatSpec {}
#[doc = "`write(|w| ..)` method takes [`stat::W`](W) writer structure"]
impl crate::Writable for StatSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets stat to value 0x45"]
impl crate::Resettable for StatSpec {
    const RESET_VALUE: u32 = 0x45;
}
