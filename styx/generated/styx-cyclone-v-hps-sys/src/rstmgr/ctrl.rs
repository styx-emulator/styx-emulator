// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrl` reader"]
pub type R = crate::R<CtrlSpec>;
#[doc = "Register `ctrl` writer"]
pub type W = crate::W<CtrlSpec>;
#[doc = "Field `swcoldrstreq` reader - This is a one-shot bit written by software to 1 to trigger a cold reset. It always reads the value 0."]
pub type SwcoldrstreqR = crate::BitReader;
#[doc = "Field `swcoldrstreq` writer - This is a one-shot bit written by software to 1 to trigger a cold reset. It always reads the value 0."]
pub type SwcoldrstreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `swwarmrstreq` reader - This is a one-shot bit written by software to 1 to trigger a hardware sequenced warm reset. It always reads the value 0."]
pub type SwwarmrstreqR = crate::BitReader;
#[doc = "Field `swwarmrstreq` writer - This is a one-shot bit written by software to 1 to trigger a hardware sequenced warm reset. It always reads the value 0."]
pub type SwwarmrstreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdrselfrefen` reader - This field controls whether the contents of SDRAM devices survive a hardware sequenced warm reset. If set to 1, the Reset Manager makes a request to the SDRAM Controller Subsystem to put the SDRAM devices into self-refresh mode before asserting warm reset signals. However, if SDRAM is already in warm reset, Handshake with SDRAM is not performed."]
pub type SdrselfrefenR = crate::BitReader;
#[doc = "Field `sdrselfrefen` writer - This field controls whether the contents of SDRAM devices survive a hardware sequenced warm reset. If set to 1, the Reset Manager makes a request to the SDRAM Controller Subsystem to put the SDRAM devices into self-refresh mode before asserting warm reset signals. However, if SDRAM is already in warm reset, Handshake with SDRAM is not performed."]
pub type SdrselfrefenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdrselfrefreq` reader - Software writes this field 1 to request to the SDRAM Controller Subsystem that it puts the SDRAM devices into self-refresh mode. This is done to preserve SDRAM contents across a software warm reset. Software waits for the SDRSELFREFACK to be 1 and then writes this field to 0. Note that it is possible for the SDRAM Controller Subsystem to never assert SDRSELFREFACK so software should timeout if SDRSELFREFACK is never asserted."]
pub type SdrselfrefreqR = crate::BitReader;
#[doc = "Field `sdrselfrefreq` writer - Software writes this field 1 to request to the SDRAM Controller Subsystem that it puts the SDRAM devices into self-refresh mode. This is done to preserve SDRAM contents across a software warm reset. Software waits for the SDRSELFREFACK to be 1 and then writes this field to 0. Note that it is possible for the SDRAM Controller Subsystem to never assert SDRSELFREFACK so software should timeout if SDRSELFREFACK is never asserted."]
pub type SdrselfrefreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `sdrselfreqack` reader - This is the acknowlege for a SDRAM self-refresh mode request initiated by the SDRSELFREFREQ field. A 1 indicates that the SDRAM Controller Subsystem has put the SDRAM devices into self-refresh mode."]
pub type SdrselfreqackR = crate::BitReader;
#[doc = "Field `sdrselfreqack` writer - This is the acknowlege for a SDRAM self-refresh mode request initiated by the SDRSELFREFREQ field. A 1 indicates that the SDRAM Controller Subsystem has put the SDRAM devices into self-refresh mode."]
pub type SdrselfreqackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpgamgrhsen` reader - Enables a handshake between the Reset Manager and FPGA Manager before a warm reset. The handshake is used to warn the FPGA Manager that a warm reset it coming so it can prepare for it. When the FPGA Manager receives a warm reset handshake, the FPGA Manager drives its output clock to a quiescent state to avoid glitches. If set to 1, the Manager makes a request to the FPGA Managerbefore asserting warm reset signals. However if the FPGA Manager is already in warm reset, the handshake is skipped. If set to 0, the handshake is skipped."]
pub type FpgamgrhsenR = crate::BitReader;
#[doc = "Field `fpgamgrhsen` writer - Enables a handshake between the Reset Manager and FPGA Manager before a warm reset. The handshake is used to warn the FPGA Manager that a warm reset it coming so it can prepare for it. When the FPGA Manager receives a warm reset handshake, the FPGA Manager drives its output clock to a quiescent state to avoid glitches. If set to 1, the Manager makes a request to the FPGA Managerbefore asserting warm reset signals. However if the FPGA Manager is already in warm reset, the handshake is skipped. If set to 0, the handshake is skipped."]
pub type FpgamgrhsenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpgamgrhsreq` reader - Software writes this field 1 to request to the FPGA Manager to idle its output clock. Software waits for the FPGAMGRHSACK to be 1 and then writes this field to 0. Note that it is possible for the FPGA Manager to never assert FPGAMGRHSACK so software should timeout in this case."]
pub type FpgamgrhsreqR = crate::BitReader;
#[doc = "Field `fpgamgrhsreq` writer - Software writes this field 1 to request to the FPGA Manager to idle its output clock. Software waits for the FPGAMGRHSACK to be 1 and then writes this field to 0. Note that it is possible for the FPGA Manager to never assert FPGAMGRHSACK so software should timeout in this case."]
pub type FpgamgrhsreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpgamgrhsack` reader - This is the acknowlege (high active) that the FPGA manager has successfully idled its output clock."]
pub type FpgamgrhsackR = crate::BitReader;
#[doc = "Field `fpgamgrhsack` writer - This is the acknowlege (high active) that the FPGA manager has successfully idled its output clock."]
pub type FpgamgrhsackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `scanmgrhsen` reader - Enables a handshake between the Reset Manager and Scan Manager before a warm reset. The handshake is used to warn the Scan Manager that a warm reset it coming so it can prepare for it. When the Scan Manager receives a warm reset handshake, the Scan Manager drives its output clocks to a quiescent state to avoid glitches. If set to 1, the Reset Manager makes a request to the Scan Managerbefore asserting warm reset signals. However if the Scan Manager is already in warm reset, the handshake is skipped. If set to 0, the handshake is skipped."]
pub type ScanmgrhsenR = crate::BitReader;
#[doc = "Field `scanmgrhsen` writer - Enables a handshake between the Reset Manager and Scan Manager before a warm reset. The handshake is used to warn the Scan Manager that a warm reset it coming so it can prepare for it. When the Scan Manager receives a warm reset handshake, the Scan Manager drives its output clocks to a quiescent state to avoid glitches. If set to 1, the Reset Manager makes a request to the Scan Managerbefore asserting warm reset signals. However if the Scan Manager is already in warm reset, the handshake is skipped. If set to 0, the handshake is skipped."]
pub type ScanmgrhsenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `scanmgrhsreq` reader - Software writes this field 1 to request to the SCAN manager to idle its output clocks. Software waits for the SCANMGRHSACK to be 1 and then writes this field to 0. Note that it is possible for the Scan Manager to never assert SCANMGRHSACK (e.g. its input clock is disabled) so software should timeout in this case."]
pub type ScanmgrhsreqR = crate::BitReader;
#[doc = "Field `scanmgrhsreq` writer - Software writes this field 1 to request to the SCAN manager to idle its output clocks. Software waits for the SCANMGRHSACK to be 1 and then writes this field to 0. Note that it is possible for the Scan Manager to never assert SCANMGRHSACK (e.g. its input clock is disabled) so software should timeout in this case."]
pub type ScanmgrhsreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `scanmgrhsack` reader - This is the acknowlege (high active) that the SCAN manager has successfully idled its output clocks."]
pub type ScanmgrhsackR = crate::BitReader;
#[doc = "Field `scanmgrhsack` writer - This is the acknowlege (high active) that the SCAN manager has successfully idled its output clocks."]
pub type ScanmgrhsackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpgahsen` reader - This field controls whether to perform handshake with FPGA before asserting warm reset. If set to 1, the Reset Manager makes a request to the FPGAbefore asserting warm reset signals. However if FPGA is already in warm reset state, the handshake is not performed. If set to 0, the handshake is not performed"]
pub type FpgahsenR = crate::BitReader;
#[doc = "Field `fpgahsen` writer - This field controls whether to perform handshake with FPGA before asserting warm reset. If set to 1, the Reset Manager makes a request to the FPGAbefore asserting warm reset signals. However if FPGA is already in warm reset state, the handshake is not performed. If set to 0, the handshake is not performed"]
pub type FpgahsenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpgahsreq` reader - Software writes this field 1 to initiate handshake request to FPGA . Software waits for the FPGAHSACK to be active and then writes this field to 0. Note that it is possible for the FPGA to never assert FPGAHSACK so software should timeout in this case."]
pub type FpgahsreqR = crate::BitReader;
#[doc = "Field `fpgahsreq` writer - Software writes this field 1 to initiate handshake request to FPGA . Software waits for the FPGAHSACK to be active and then writes this field to 0. Note that it is possible for the FPGA to never assert FPGAHSACK so software should timeout in this case."]
pub type FpgahsreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `fpgahsack` reader - This is the acknowlege (high active) that the FPGA handshake acknowledge has been received by Reset Manager."]
pub type FpgahsackR = crate::BitReader;
#[doc = "Field `fpgahsack` writer - This is the acknowlege (high active) that the FPGA handshake acknowledge has been received by Reset Manager."]
pub type FpgahsackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `etrstallen` reader - This field controls whether the ETR is requested to idle its AXI master interface (i.e. finish outstanding transactions and not initiate any more) to the L3 Interconnect before a warm or debug reset. If set to 1, the Reset Manager makes a request to the ETR to stall its AXI master and waits for it to finish any outstanding AXI transactions before a warm reset of the L3 Interconnect or a debug reset of the ETR. This stalling is required because the debug logic (including the ETR) is reset on a debug reset and the ETR AXI master is connected to the L3 Interconnect which is reset on a warm reset and these resets can happen independently."]
pub type EtrstallenR = crate::BitReader;
#[doc = "Field `etrstallen` writer - This field controls whether the ETR is requested to idle its AXI master interface (i.e. finish outstanding transactions and not initiate any more) to the L3 Interconnect before a warm or debug reset. If set to 1, the Reset Manager makes a request to the ETR to stall its AXI master and waits for it to finish any outstanding AXI transactions before a warm reset of the L3 Interconnect or a debug reset of the ETR. This stalling is required because the debug logic (including the ETR) is reset on a debug reset and the ETR AXI master is connected to the L3 Interconnect which is reset on a warm reset and these resets can happen independently."]
pub type EtrstallenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `etrstallreq` reader - Software writes this field 1 to request to the ETR that it stalls its AXI master to the L3 Interconnect. Software waits for the ETRSTALLACK to be 1 and then writes this field to 0. Note that it is possible for the ETR to never assert ETRSTALLACK so software should timeout if ETRSTALLACK is never asserted."]
pub type EtrstallreqR = crate::BitReader;
#[doc = "Field `etrstallreq` writer - Software writes this field 1 to request to the ETR that it stalls its AXI master to the L3 Interconnect. Software waits for the ETRSTALLACK to be 1 and then writes this field to 0. Note that it is possible for the ETR to never assert ETRSTALLACK so software should timeout if ETRSTALLACK is never asserted."]
pub type EtrstallreqW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `etrstallack` reader - This is the acknowlege for a ETR AXI master stall initiated by the ETRSTALLREQ field. A 1 indicates that the ETR has stalled its AXI master"]
pub type EtrstallackR = crate::BitReader;
#[doc = "Field `etrstallack` writer - This is the acknowlege for a ETR AXI master stall initiated by the ETRSTALLREQ field. A 1 indicates that the ETR has stalled its AXI master"]
pub type EtrstallackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `etrstallwarmrst` reader - If a warm reset occurs and ETRSTALLEN is 1, hardware sets this bit to 1 to indicate that the stall of the ETR AXI master is pending. Hardware leaves the ETR stalled until software clears this field by writing it with 1. Software must only clear this field when it is ready to have the ETR AXI master start making AXI requests to write trace data."]
pub type EtrstallwarmrstR = crate::BitReader;
#[doc = "Field `etrstallwarmrst` writer - If a warm reset occurs and ETRSTALLEN is 1, hardware sets this bit to 1 to indicate that the stall of the ETR AXI master is pending. Hardware leaves the ETR stalled until software clears this field by writing it with 1. Software must only clear this field when it is ready to have the ETR AXI master start making AXI requests to write trace data."]
pub type EtrstallwarmrstW<'a, REG> = crate::BitWriter1C<'a, REG>;
impl R {
    #[doc = "Bit 0 - This is a one-shot bit written by software to 1 to trigger a cold reset. It always reads the value 0."]
    #[inline(always)]
    pub fn swcoldrstreq(&self) -> SwcoldrstreqR {
        SwcoldrstreqR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This is a one-shot bit written by software to 1 to trigger a hardware sequenced warm reset. It always reads the value 0."]
    #[inline(always)]
    pub fn swwarmrstreq(&self) -> SwwarmrstreqR {
        SwwarmrstreqR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 4 - This field controls whether the contents of SDRAM devices survive a hardware sequenced warm reset. If set to 1, the Reset Manager makes a request to the SDRAM Controller Subsystem to put the SDRAM devices into self-refresh mode before asserting warm reset signals. However, if SDRAM is already in warm reset, Handshake with SDRAM is not performed."]
    #[inline(always)]
    pub fn sdrselfrefen(&self) -> SdrselfrefenR {
        SdrselfrefenR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Software writes this field 1 to request to the SDRAM Controller Subsystem that it puts the SDRAM devices into self-refresh mode. This is done to preserve SDRAM contents across a software warm reset. Software waits for the SDRSELFREFACK to be 1 and then writes this field to 0. Note that it is possible for the SDRAM Controller Subsystem to never assert SDRSELFREFACK so software should timeout if SDRSELFREFACK is never asserted."]
    #[inline(always)]
    pub fn sdrselfrefreq(&self) -> SdrselfrefreqR {
        SdrselfrefreqR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - This is the acknowlege for a SDRAM self-refresh mode request initiated by the SDRSELFREFREQ field. A 1 indicates that the SDRAM Controller Subsystem has put the SDRAM devices into self-refresh mode."]
    #[inline(always)]
    pub fn sdrselfreqack(&self) -> SdrselfreqackR {
        SdrselfreqackR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - Enables a handshake between the Reset Manager and FPGA Manager before a warm reset. The handshake is used to warn the FPGA Manager that a warm reset it coming so it can prepare for it. When the FPGA Manager receives a warm reset handshake, the FPGA Manager drives its output clock to a quiescent state to avoid glitches. If set to 1, the Manager makes a request to the FPGA Managerbefore asserting warm reset signals. However if the FPGA Manager is already in warm reset, the handshake is skipped. If set to 0, the handshake is skipped."]
    #[inline(always)]
    pub fn fpgamgrhsen(&self) -> FpgamgrhsenR {
        FpgamgrhsenR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Software writes this field 1 to request to the FPGA Manager to idle its output clock. Software waits for the FPGAMGRHSACK to be 1 and then writes this field to 0. Note that it is possible for the FPGA Manager to never assert FPGAMGRHSACK so software should timeout in this case."]
    #[inline(always)]
    pub fn fpgamgrhsreq(&self) -> FpgamgrhsreqR {
        FpgamgrhsreqR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - This is the acknowlege (high active) that the FPGA manager has successfully idled its output clock."]
    #[inline(always)]
    pub fn fpgamgrhsack(&self) -> FpgamgrhsackR {
        FpgamgrhsackR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 12 - Enables a handshake between the Reset Manager and Scan Manager before a warm reset. The handshake is used to warn the Scan Manager that a warm reset it coming so it can prepare for it. When the Scan Manager receives a warm reset handshake, the Scan Manager drives its output clocks to a quiescent state to avoid glitches. If set to 1, the Reset Manager makes a request to the Scan Managerbefore asserting warm reset signals. However if the Scan Manager is already in warm reset, the handshake is skipped. If set to 0, the handshake is skipped."]
    #[inline(always)]
    pub fn scanmgrhsen(&self) -> ScanmgrhsenR {
        ScanmgrhsenR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Software writes this field 1 to request to the SCAN manager to idle its output clocks. Software waits for the SCANMGRHSACK to be 1 and then writes this field to 0. Note that it is possible for the Scan Manager to never assert SCANMGRHSACK (e.g. its input clock is disabled) so software should timeout in this case."]
    #[inline(always)]
    pub fn scanmgrhsreq(&self) -> ScanmgrhsreqR {
        ScanmgrhsreqR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - This is the acknowlege (high active) that the SCAN manager has successfully idled its output clocks."]
    #[inline(always)]
    pub fn scanmgrhsack(&self) -> ScanmgrhsackR {
        ScanmgrhsackR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 16 - This field controls whether to perform handshake with FPGA before asserting warm reset. If set to 1, the Reset Manager makes a request to the FPGAbefore asserting warm reset signals. However if FPGA is already in warm reset state, the handshake is not performed. If set to 0, the handshake is not performed"]
    #[inline(always)]
    pub fn fpgahsen(&self) -> FpgahsenR {
        FpgahsenR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Software writes this field 1 to initiate handshake request to FPGA . Software waits for the FPGAHSACK to be active and then writes this field to 0. Note that it is possible for the FPGA to never assert FPGAHSACK so software should timeout in this case."]
    #[inline(always)]
    pub fn fpgahsreq(&self) -> FpgahsreqR {
        FpgahsreqR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - This is the acknowlege (high active) that the FPGA handshake acknowledge has been received by Reset Manager."]
    #[inline(always)]
    pub fn fpgahsack(&self) -> FpgahsackR {
        FpgahsackR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 20 - This field controls whether the ETR is requested to idle its AXI master interface (i.e. finish outstanding transactions and not initiate any more) to the L3 Interconnect before a warm or debug reset. If set to 1, the Reset Manager makes a request to the ETR to stall its AXI master and waits for it to finish any outstanding AXI transactions before a warm reset of the L3 Interconnect or a debug reset of the ETR. This stalling is required because the debug logic (including the ETR) is reset on a debug reset and the ETR AXI master is connected to the L3 Interconnect which is reset on a warm reset and these resets can happen independently."]
    #[inline(always)]
    pub fn etrstallen(&self) -> EtrstallenR {
        EtrstallenR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Software writes this field 1 to request to the ETR that it stalls its AXI master to the L3 Interconnect. Software waits for the ETRSTALLACK to be 1 and then writes this field to 0. Note that it is possible for the ETR to never assert ETRSTALLACK so software should timeout if ETRSTALLACK is never asserted."]
    #[inline(always)]
    pub fn etrstallreq(&self) -> EtrstallreqR {
        EtrstallreqR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - This is the acknowlege for a ETR AXI master stall initiated by the ETRSTALLREQ field. A 1 indicates that the ETR has stalled its AXI master"]
    #[inline(always)]
    pub fn etrstallack(&self) -> EtrstallackR {
        EtrstallackR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - If a warm reset occurs and ETRSTALLEN is 1, hardware sets this bit to 1 to indicate that the stall of the ETR AXI master is pending. Hardware leaves the ETR stalled until software clears this field by writing it with 1. Software must only clear this field when it is ready to have the ETR AXI master start making AXI requests to write trace data."]
    #[inline(always)]
    pub fn etrstallwarmrst(&self) -> EtrstallwarmrstR {
        EtrstallwarmrstR::new(((self.bits >> 23) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This is a one-shot bit written by software to 1 to trigger a cold reset. It always reads the value 0."]
    #[inline(always)]
    #[must_use]
    pub fn swcoldrstreq(&mut self) -> SwcoldrstreqW<CtrlSpec> {
        SwcoldrstreqW::new(self, 0)
    }
    #[doc = "Bit 1 - This is a one-shot bit written by software to 1 to trigger a hardware sequenced warm reset. It always reads the value 0."]
    #[inline(always)]
    #[must_use]
    pub fn swwarmrstreq(&mut self) -> SwwarmrstreqW<CtrlSpec> {
        SwwarmrstreqW::new(self, 1)
    }
    #[doc = "Bit 4 - This field controls whether the contents of SDRAM devices survive a hardware sequenced warm reset. If set to 1, the Reset Manager makes a request to the SDRAM Controller Subsystem to put the SDRAM devices into self-refresh mode before asserting warm reset signals. However, if SDRAM is already in warm reset, Handshake with SDRAM is not performed."]
    #[inline(always)]
    #[must_use]
    pub fn sdrselfrefen(&mut self) -> SdrselfrefenW<CtrlSpec> {
        SdrselfrefenW::new(self, 4)
    }
    #[doc = "Bit 5 - Software writes this field 1 to request to the SDRAM Controller Subsystem that it puts the SDRAM devices into self-refresh mode. This is done to preserve SDRAM contents across a software warm reset. Software waits for the SDRSELFREFACK to be 1 and then writes this field to 0. Note that it is possible for the SDRAM Controller Subsystem to never assert SDRSELFREFACK so software should timeout if SDRSELFREFACK is never asserted."]
    #[inline(always)]
    #[must_use]
    pub fn sdrselfrefreq(&mut self) -> SdrselfrefreqW<CtrlSpec> {
        SdrselfrefreqW::new(self, 5)
    }
    #[doc = "Bit 6 - This is the acknowlege for a SDRAM self-refresh mode request initiated by the SDRSELFREFREQ field. A 1 indicates that the SDRAM Controller Subsystem has put the SDRAM devices into self-refresh mode."]
    #[inline(always)]
    #[must_use]
    pub fn sdrselfreqack(&mut self) -> SdrselfreqackW<CtrlSpec> {
        SdrselfreqackW::new(self, 6)
    }
    #[doc = "Bit 8 - Enables a handshake between the Reset Manager and FPGA Manager before a warm reset. The handshake is used to warn the FPGA Manager that a warm reset it coming so it can prepare for it. When the FPGA Manager receives a warm reset handshake, the FPGA Manager drives its output clock to a quiescent state to avoid glitches. If set to 1, the Manager makes a request to the FPGA Managerbefore asserting warm reset signals. However if the FPGA Manager is already in warm reset, the handshake is skipped. If set to 0, the handshake is skipped."]
    #[inline(always)]
    #[must_use]
    pub fn fpgamgrhsen(&mut self) -> FpgamgrhsenW<CtrlSpec> {
        FpgamgrhsenW::new(self, 8)
    }
    #[doc = "Bit 9 - Software writes this field 1 to request to the FPGA Manager to idle its output clock. Software waits for the FPGAMGRHSACK to be 1 and then writes this field to 0. Note that it is possible for the FPGA Manager to never assert FPGAMGRHSACK so software should timeout in this case."]
    #[inline(always)]
    #[must_use]
    pub fn fpgamgrhsreq(&mut self) -> FpgamgrhsreqW<CtrlSpec> {
        FpgamgrhsreqW::new(self, 9)
    }
    #[doc = "Bit 10 - This is the acknowlege (high active) that the FPGA manager has successfully idled its output clock."]
    #[inline(always)]
    #[must_use]
    pub fn fpgamgrhsack(&mut self) -> FpgamgrhsackW<CtrlSpec> {
        FpgamgrhsackW::new(self, 10)
    }
    #[doc = "Bit 12 - Enables a handshake between the Reset Manager and Scan Manager before a warm reset. The handshake is used to warn the Scan Manager that a warm reset it coming so it can prepare for it. When the Scan Manager receives a warm reset handshake, the Scan Manager drives its output clocks to a quiescent state to avoid glitches. If set to 1, the Reset Manager makes a request to the Scan Managerbefore asserting warm reset signals. However if the Scan Manager is already in warm reset, the handshake is skipped. If set to 0, the handshake is skipped."]
    #[inline(always)]
    #[must_use]
    pub fn scanmgrhsen(&mut self) -> ScanmgrhsenW<CtrlSpec> {
        ScanmgrhsenW::new(self, 12)
    }
    #[doc = "Bit 13 - Software writes this field 1 to request to the SCAN manager to idle its output clocks. Software waits for the SCANMGRHSACK to be 1 and then writes this field to 0. Note that it is possible for the Scan Manager to never assert SCANMGRHSACK (e.g. its input clock is disabled) so software should timeout in this case."]
    #[inline(always)]
    #[must_use]
    pub fn scanmgrhsreq(&mut self) -> ScanmgrhsreqW<CtrlSpec> {
        ScanmgrhsreqW::new(self, 13)
    }
    #[doc = "Bit 14 - This is the acknowlege (high active) that the SCAN manager has successfully idled its output clocks."]
    #[inline(always)]
    #[must_use]
    pub fn scanmgrhsack(&mut self) -> ScanmgrhsackW<CtrlSpec> {
        ScanmgrhsackW::new(self, 14)
    }
    #[doc = "Bit 16 - This field controls whether to perform handshake with FPGA before asserting warm reset. If set to 1, the Reset Manager makes a request to the FPGAbefore asserting warm reset signals. However if FPGA is already in warm reset state, the handshake is not performed. If set to 0, the handshake is not performed"]
    #[inline(always)]
    #[must_use]
    pub fn fpgahsen(&mut self) -> FpgahsenW<CtrlSpec> {
        FpgahsenW::new(self, 16)
    }
    #[doc = "Bit 17 - Software writes this field 1 to initiate handshake request to FPGA . Software waits for the FPGAHSACK to be active and then writes this field to 0. Note that it is possible for the FPGA to never assert FPGAHSACK so software should timeout in this case."]
    #[inline(always)]
    #[must_use]
    pub fn fpgahsreq(&mut self) -> FpgahsreqW<CtrlSpec> {
        FpgahsreqW::new(self, 17)
    }
    #[doc = "Bit 18 - This is the acknowlege (high active) that the FPGA handshake acknowledge has been received by Reset Manager."]
    #[inline(always)]
    #[must_use]
    pub fn fpgahsack(&mut self) -> FpgahsackW<CtrlSpec> {
        FpgahsackW::new(self, 18)
    }
    #[doc = "Bit 20 - This field controls whether the ETR is requested to idle its AXI master interface (i.e. finish outstanding transactions and not initiate any more) to the L3 Interconnect before a warm or debug reset. If set to 1, the Reset Manager makes a request to the ETR to stall its AXI master and waits for it to finish any outstanding AXI transactions before a warm reset of the L3 Interconnect or a debug reset of the ETR. This stalling is required because the debug logic (including the ETR) is reset on a debug reset and the ETR AXI master is connected to the L3 Interconnect which is reset on a warm reset and these resets can happen independently."]
    #[inline(always)]
    #[must_use]
    pub fn etrstallen(&mut self) -> EtrstallenW<CtrlSpec> {
        EtrstallenW::new(self, 20)
    }
    #[doc = "Bit 21 - Software writes this field 1 to request to the ETR that it stalls its AXI master to the L3 Interconnect. Software waits for the ETRSTALLACK to be 1 and then writes this field to 0. Note that it is possible for the ETR to never assert ETRSTALLACK so software should timeout if ETRSTALLACK is never asserted."]
    #[inline(always)]
    #[must_use]
    pub fn etrstallreq(&mut self) -> EtrstallreqW<CtrlSpec> {
        EtrstallreqW::new(self, 21)
    }
    #[doc = "Bit 22 - This is the acknowlege for a ETR AXI master stall initiated by the ETRSTALLREQ field. A 1 indicates that the ETR has stalled its AXI master"]
    #[inline(always)]
    #[must_use]
    pub fn etrstallack(&mut self) -> EtrstallackW<CtrlSpec> {
        EtrstallackW::new(self, 22)
    }
    #[doc = "Bit 23 - If a warm reset occurs and ETRSTALLEN is 1, hardware sets this bit to 1 to indicate that the stall of the ETR AXI master is pending. Hardware leaves the ETR stalled until software clears this field by writing it with 1. Software must only clear this field when it is ready to have the ETR AXI master start making AXI requests to write trace data."]
    #[inline(always)]
    #[must_use]
    pub fn etrstallwarmrst(&mut self) -> EtrstallwarmrstW<CtrlSpec> {
        EtrstallwarmrstW::new(self, 23)
    }
}
#[doc = "The CTRL register is used by software to control reset behavior.It includes fields for software to initiate the cold and warm reset, enable hardware handshake with other modules before warm reset, and perform software handshake. The software handshake sequence must match the hardware sequence. Software mustde-assert the handshake request after asserting warm reset and before de-assert the warm reset. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrl::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrl::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlSpec;
impl crate::RegisterSpec for CtrlSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`ctrl::R`](R) reader structure"]
impl crate::Readable for CtrlSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrl::W`](W) writer structure"]
impl crate::Writable for CtrlSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x0080_0000;
}
#[doc = "`reset()` method sets ctrl to value 0x0010_0000"]
impl crate::Resettable for CtrlSpec {
    const RESET_VALUE: u32 = 0x0010_0000;
}
