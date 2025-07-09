// SPDX-License-Identifier: BSD-2-Clause
use enum_map::{Enum, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use styx_core::prelude::*;
use tracing::{debug, trace};

use super::Event;

/// Single peripheral with methods to get peripheral information.
#[derive(Clone, Copy, PartialEq, Eq, Debug, IntoPrimitive, TryFromPrimitive, Enum)]
#[repr(u8)]
pub enum PeripheralId {
    PLLWakeup,
    DMAError,
    DMAR0BlockInterrupt,
    DMAR1BlockInterrupt,
    DMAR0OverflowError,
    DMAR1OverflowError,
    PPIError,
    EthernetMACStatus,

    SPORT0Status,
    SPORT1Status,
    PTPErrorInterrupt,
    Reserved11,
    UART0Status,
    UART1Status,
    RealTimeClock,
    /// PPI
    DMA0,

    /// SPORT0 RX
    DMA3,
    /// SPORT0 TX/RSI
    DMA4,
    ///SPORT1 RX/SPI1 RX or TX
    DMA5,
    /// SPORT1 TX
    DMA6,
    Twi,
    /// SPI0 RX or TX
    DMA7,
    /// UART0 RX
    DMA8,
    /// UART0 TX
    DMA9,

    /// UART1 RX
    DMA10,
    /// UART1 TX
    DMA11,
    OTPMemory,
    GPCounter,
    /// Ethernet MAC Rx
    DMA1,
    PortHInterruptA,
    /// Ethernet MAC TX
    DMA2,
    PortHInterruptB,

    TIMER0,
    TIMER1,
    TIMER2,
    TIMER3,
    TIMER4,
    TIMER5,
    TIMER6,
    TIMER7,

    PortGInterruptA,
    PortGInterruptB,
    MDMA0,
    MDMA1,
    WatchdogTimer,
    PortFInterruptA,
    PortFInterruptB,

    Spi0Status,
    Spi1Status,
    Reserved49,
    Reserved50,
    RsiInterrupt0,
    RsiInterrupt1,
    PWMTrip,
    PWMSync,
    PTPStatus,

    Reserved56,
    Reserved57,
    Reserved58,
    Reserved59,
    Reserved60,
    Reserved61,
    Reserved62,
    Reserved63,
}

/// The `x` in `SIC_IMASKx`, `SIC_ISRx`, and `SIC_IWRx`. Each [PeripheralId] maps through one of
/// these.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RoutingBank {
    One,
    Zero,
}
impl From<PeripheralId> for RoutingBank {
    fn from(value: PeripheralId) -> Self {
        if u8::from(value) < 32 {
            Self::Zero
        } else {
            Self::One
        }
    }
}
impl RoutingBank {
    fn mask_register(self) -> u64 {
        match self {
            RoutingBank::Zero => super::sys::SIC_IMASK0,
            RoutingBank::One => super::sys::SIC_IMASK1,
        }
        .into()
    }

    fn status_register(self) -> u64 {
        match self {
            RoutingBank::Zero => super::sys::SIC_ISR0,
            RoutingBank::One => super::sys::SIC_ISR1,
        }
        .into()
    }

    fn wakeup_enabled_register(self) -> u64 {
        match self {
            RoutingBank::Zero => super::sys::SIC_IWR0,
            RoutingBank::One => super::sys::SIC_IWR1,
        }
        .into()
    }
}

/// The `x` in `SIC_IARx`.
#[derive(Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum AssignmentBank {
    Zero,
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
}

impl PeripheralId {
    const PERIPHERALS_PER_ASSIGNMENT_REGISTER: u8 = 8;
    const PERIPHERALS_PER_BANK_REGISTER: u8 = 32;

    /// [RoutingBank::Zero] for SIC_{ISR,IWR,IMASK}0, [RoutingBank::One] for SIC_{ISR,IWR,IMASK}1
    ///
    /// First 32 are [RoutingBank::Zero], last 32 are [RoutingBank::One]
    fn routing_bank(self) -> RoutingBank {
        RoutingBank::from(self)
    }

    /// Get assignment bank of peripheral.
    fn assignment_bank(self) -> AssignmentBank {
        let assignment_number = self.index() / Self::PERIPHERALS_PER_ASSIGNMENT_REGISTER;

        AssignmentBank::try_from(assignment_number).expect("assignment bank parsing incorrect")
    }

    /// Peripheral Id Number, 0-63.
    fn index(self) -> u8 {
        u8::from(self)
    }

    /// Bit offset for routing bank registers (`SIC_IMASKx`, `SIC_ISRx`, and `SIC_IWRx`)
    fn bank_bit_offset(self) -> u8 {
        self.index() % Self::PERIPHERALS_PER_BANK_REGISTER
    }

    /// Is bit set in this bank registers?
    ///
    /// Must be a bank register (e.g. `SIC_IMASKx`, `SIC_ISRx`, and `SIC_IWRx`).
    fn is_set_bank(self, register_value: u32) -> bool {
        (register_value & (1 << self.bank_bit_offset())) > 0
    }

    #[allow(dead_code)]
    fn mask_register(self) -> u64 {
        self.routing_bank().mask_register()
    }

    #[allow(dead_code)]
    fn status_register(self) -> u64 {
        self.routing_bank().status_register()
    }

    #[allow(dead_code)]
    fn wakeup_enabled_register(self) -> u64 {
        self.routing_bank().wakeup_enabled_register()
    }

    #[allow(dead_code)]
    fn assignment_register(self) -> u64 {
        // 8 registers contained in each register
        // 32 bits, 4 bits per peripheral

        let base_register = super::sys::SIC_IAR0;
        let register_bytes = 4;

        let register_number = self.index() / Self::PERIPHERALS_PER_ASSIGNMENT_REGISTER;

        (base_register + (register_number * register_bytes) as u32).into()
    }

    /// Gets the [Event] that the peripheral refers to given the assignment register.
    ///
    /// Note that this returns [None] if the assignment register is not a valid event (i.e. > 8).
    ///
    /// Mapping is defined in the blackfin hardware reference 5-11.
    fn assigned_event(self, assignment_register: u32) -> Option<Event> {
        // 0-8 peripheral in assignment register
        let index_in_register = self.index() % Self::PERIPHERALS_PER_ASSIGNMENT_REGISTER;
        // 4 bits per assignment in register
        let per_peripheral_bits = 4;

        // start of assignment mask
        let mask_offset = index_in_register * per_peripheral_bits;

        // 4 bits per peripheral
        let assignment_value = (assignment_register >> mask_offset) & 0xF;
        // + IVG7 is because assignments start at IVG7
        // 0 -> IVG7
        // 1 -> IVG8, etc
        // invalid values are mapped to None
        Event::try_from(assignment_value as u8 + Event::Interrupt7.event_number()).ok()
    }

    /// Default value in SIC_IARx.
    fn default_assignment(self) -> Event {
        match self {
            PeripheralId::PLLWakeup
            | PeripheralId::DMAError
            | PeripheralId::DMAR0BlockInterrupt
            | PeripheralId::DMAR1BlockInterrupt
            | PeripheralId::DMAR0OverflowError
            | PeripheralId::DMAR1OverflowError
            | PeripheralId::PPIError
            | PeripheralId::EthernetMACStatus
            | PeripheralId::SPORT0Status
            | PeripheralId::SPORT1Status
            | PeripheralId::PTPErrorInterrupt
            | PeripheralId::Reserved11
            | PeripheralId::UART0Status
            | PeripheralId::UART1Status => Event::Interrupt7,
            PeripheralId::RealTimeClock | PeripheralId::DMA0 => Event::Interrupt8,
            PeripheralId::DMA3 | PeripheralId::DMA4 | PeripheralId::DMA5 | PeripheralId::DMA6 => {
                Event::Interrupt9
            }
            PeripheralId::Twi
            | PeripheralId::DMA7
            | PeripheralId::DMA8
            | PeripheralId::DMA9
            | PeripheralId::DMA10
            | PeripheralId::DMA11 => Event::Interrupt10,
            PeripheralId::OTPMemory
            | PeripheralId::GPCounter
            | PeripheralId::DMA1
            | PeripheralId::PortHInterruptA
            | PeripheralId::DMA2
            | PeripheralId::PortHInterruptB => Event::Interrupt11,
            PeripheralId::TIMER0
            | PeripheralId::TIMER1
            | PeripheralId::TIMER2
            | PeripheralId::TIMER3
            | PeripheralId::TIMER4
            | PeripheralId::TIMER5
            | PeripheralId::TIMER6
            | PeripheralId::TIMER7
            | PeripheralId::PortGInterruptA
            | PeripheralId::PortGInterruptB => Event::Interrupt12,
            PeripheralId::MDMA0
            | PeripheralId::MDMA1
            | PeripheralId::WatchdogTimer
            | PeripheralId::PortFInterruptA
            | PeripheralId::PortFInterruptB => Event::Interrupt13,
            PeripheralId::Spi0Status
            | PeripheralId::Spi1Status
            | PeripheralId::Reserved49
            | PeripheralId::Reserved50 => Event::Interrupt7,
            PeripheralId::RsiInterrupt0
            | PeripheralId::RsiInterrupt1
            | PeripheralId::PWMSync
            | PeripheralId::PWMTrip
            | PeripheralId::PTPStatus => Event::Interrupt10,

            PeripheralId::Reserved56
            | PeripheralId::Reserved57
            | PeripheralId::Reserved58
            | PeripheralId::Reserved59
            | PeripheralId::Reserved60 => Event::Interrupt12,
            PeripheralId::Reserved61 | PeripheralId::Reserved62 | PeripheralId::Reserved63 => {
                Event::Interrupt13
            }
        }
    }
}

#[derive(Debug)]
pub struct SystemInterruptState {
    peripheral: PeripheralId,
    /// Does this trigger core interrupt? Controlled in `SIC_IMASK`.
    enabled: bool,

    /// Status bit indicating if source has been triggered, bit in `SIC_ISR`.
    ///
    /// E.g. if a timer has triggered, this is set until the timer core interrupt handler clears the
    /// timer status, which will clear the system interrupt status.
    status: bool,

    /// Wakeup enabled. Represents `SIC_IWR`.
    wakeup: bool,

    /// Current assigned [Event] mapping, [None] if invalid mapping. Represents `SIC_IAR`.
    assignment: Option<Event>,
}

impl SystemInterruptState {
    /// Default reset configuration.
    fn default_from_peripheral(peripheral: PeripheralId) -> Self {
        Self {
            peripheral,
            enabled: false,
            status: false,
            wakeup: true,
            assignment: Some(peripheral.default_assignment()),
        }
    }

    /// Latches a system interrupt, enabling the status and returns its [Event] if enabled.
    fn latch(&mut self) -> Option<Event> {
        self.status = true;
        self.enabled
            .then(|| self.assignment.expect("invalid assignment"))
    }

    fn unlatch(&mut self) {
        self.status = false;
    }

    fn set_from_mask(&mut self, mask_register: u32) {
        let peripheral = self.peripheral;
        let enabled = peripheral.is_set_bank(mask_register);
        let prev_enabled = self.enabled;
        self.enabled = enabled;
        if enabled != prev_enabled {
            debug!("{peripheral:?} mask: {prev_enabled} -> {enabled}");
        }
    }

    fn set_from_wakeup(&mut self, wakeup: u32) {
        let peripheral = self.peripheral;
        let wakeup_enabled = peripheral.is_set_bank(wakeup);
        let prev_wakeup_enabled = self.wakeup;
        self.wakeup = wakeup_enabled;
        if wakeup_enabled != prev_wakeup_enabled {
            debug!("{peripheral:?} wakeup: {prev_wakeup_enabled} -> {wakeup_enabled}");
        }
    }

    fn set_from_assignment(&mut self, assignment: u32) {
        let peripheral = self.peripheral;
        let new_assignment = peripheral.assigned_event(assignment);
        let prev_assignment = self.assignment;
        self.assignment = new_assignment;
        if prev_assignment != new_assignment {
            debug!("{peripheral:?} assignment: {prev_assignment:?} -> {new_assignment:?}");
        }
    }
}

/// Source-of-truth manager for events.
pub struct PeripheralsContainer {
    /// A mapping of event types to mutex-protected event states. Maybe make the whole container Mutex'd?
    interrupts: EnumMap<PeripheralId, SystemInterruptState>,
}

impl PeripheralsContainer {
    pub fn new() -> Self {
        let interrupts = EnumMap::from_fn(|peripheral_id| {
            SystemInterruptState::default_from_peripheral(peripheral_id)
        });
        Self { interrupts }
    }

    /// Iterate over peripherals that are in single [RoutingBank].
    fn bank_iter(
        &self,
        bank: RoutingBank,
    ) -> impl Iterator<Item = (PeripheralId, &SystemInterruptState)> {
        self.interrupts
            .iter()
            .filter(move |(i, _)| i.routing_bank() == bank)
    }
    /// Iterate over peripherals that are in single [RoutingBank] but it's mutable.
    fn bank_iter_mut(
        &mut self,
        bank: RoutingBank,
    ) -> impl Iterator<Item = (PeripheralId, &mut SystemInterruptState)> {
        self.interrupts
            .iter_mut()
            .filter(move |(i, _)| i.routing_bank() == bank)
    }

    /// Iterate over peripherals that are in single [AssignmentBank], mutable.
    fn assignment_iter_mut(
        &mut self,
        bank: AssignmentBank,
    ) -> impl Iterator<Item = (PeripheralId, &mut SystemInterruptState)> {
        self.interrupts
            .iter_mut()
            .filter(move |(i, _)| i.assignment_bank() == bank)
    }

    /// Generates the status register value for a [RoutingBank].
    fn calculate_status_register(&self, bank: RoutingBank) -> u32 {
        let mut isr = 0u32;
        for (id, state) in self.bank_iter(bank) {
            isr |= (state.status as u32) << id.bank_bit_offset();
        }
        isr
    }

    /// Writes the status register value for a [RoutingBank].
    fn write_status_register(&self, mmu: &mut Mmu, bank: RoutingBank) {
        mmu.data()
            .write(bank.status_register())
            .le()
            .u32(self.calculate_status_register(bank))
            .unwrap()
    }

    pub fn set_masks(&mut self, routing_bank: RoutingBank, mask: u32) {
        for (_id, state) in self.bank_iter_mut(routing_bank) {
            state.set_from_mask(mask);
        }
    }

    pub fn set_wakeup(&mut self, routing_bank: RoutingBank, wakeup: u32) {
        for (_id, state) in self.bank_iter_mut(routing_bank) {
            state.set_from_wakeup(wakeup);
        }
    }

    pub fn set_assignment(&mut self, bank: AssignmentBank, assignment: u32) {
        for (_id, state) in self.assignment_iter_mut(bank) {
            state.set_from_assignment(assignment);
        }
    }

    /// Latch a peripheral interrupt, should be called from a peripheral (e.g. timer, uart, etc.)
    pub fn latch_peripheral(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut dyn EventControllerImpl,
        peripheral: impl Into<PeripheralId>,
    ) {
        let id: PeripheralId = peripheral.into();
        let event = self.interrupts[id].latch();

        self.write_status_register(mmu, id.routing_bank());

        // Latch core interrupt if peripheral interrupt is enabled
        if let Some(event) = event {
            trace!("peripheral {id:?} latched core interrupt {event:?}");
            ev.latch(event.into()).unwrap()
        } else {
            trace!("peripheral {id:?} latched but was not enabled");
        }
    }

    /// Removes status bit from peripheral
    pub fn unlatch_peripheral(&mut self, peripheral: impl Into<PeripheralId>) {
        let id: PeripheralId = peripheral.into();
        self.interrupts[id].unlatch()
    }
}

/// Clonable newtype handle for the system interrupt controller to allow easy peripheral
/// latching/unlatching.
///
/// Should be used by peripherals.
#[derive(Clone)]
pub(crate) struct SicHandle {
    internal: Arc<Mutex<PeripheralsContainer>>,
}

impl SicHandle {
    pub(crate) fn new(internal: &Arc<Mutex<PeripheralsContainer>>) -> Self {
        Self {
            internal: internal.clone(),
        }
    }

    /// Latch a peripheral interrupt.
    pub(crate) fn latch_peripheral(
        &self,
        mmu: &mut Mmu,
        ev: &mut dyn EventControllerImpl,
        peripheral: impl Into<PeripheralId>,
    ) {
        self.internal
            .lock()
            .unwrap()
            .latch_peripheral(mmu, ev, peripheral)
    }

    /// Removes status bit from peripheral, should be executed when the interrupt handler "handles"
    /// the interrupt.
    pub(crate) fn unlatch_peripheral(&self, peripheral: impl Into<PeripheralId>) {
        self.internal.lock().unwrap().unlatch_peripheral(peripheral)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_status_bank() {
        let mut test = PeripheralsContainer::new();

        test.interrupts[PeripheralId::TIMER0].status = true;

        let bank0_isr = test.calculate_status_register(RoutingBank::Zero);
        assert_eq!(bank0_isr, 0);

        let bank1_isr = test.calculate_status_register(RoutingBank::One);
        assert_eq!(bank1_isr, 1);
    }

    #[test]
    fn test_peripheral_id_bank_offset() {
        assert_eq!(PeripheralId::TIMER0.bank_bit_offset(), 0);
        assert_eq!(PeripheralId::Spi0Status.bank_bit_offset(), 15);
        assert_eq!(PeripheralId::UART0Status.bank_bit_offset(), 12);
        assert_eq!(PeripheralId::PortHInterruptB.bank_bit_offset(), 31);
    }

    #[test]
    fn test_peripheral_assigned_event() {
        // TIMER0 is bottom bits, [0..4]
        let timer0 = PeripheralId::TIMER0;
        assert_eq!(timer0.assigned_event(0x0), Some(Event::Interrupt7));
        assert_eq!(timer0.assigned_event(0xFFF0), Some(Event::Interrupt7));
        assert_eq!(timer0.assigned_event(0x1), Some(Event::Interrupt8));
        assert_eq!(timer0.assigned_event(0x8), Some(Event::Interrupt15));
        assert_eq!(timer0.assigned_event(0x9), None);
        assert_eq!(timer0.assigned_event(0xF), None);
        assert_eq!(timer0.assigned_event(0xFFFFF), None);

        // TIMER1 is [4..8]
        let timer1 = PeripheralId::TIMER1;
        assert_eq!(timer1.assigned_event(0x0), Some(Event::Interrupt7));
        assert_eq!(timer1.assigned_event(0xF), Some(Event::Interrupt7));
        assert_eq!(timer1.assigned_event(0x1F), Some(Event::Interrupt8));
        assert_eq!(timer1.assigned_event(0x8F), Some(Event::Interrupt15));
        assert_eq!(timer1.assigned_event(0xFF), None);
    }
}
