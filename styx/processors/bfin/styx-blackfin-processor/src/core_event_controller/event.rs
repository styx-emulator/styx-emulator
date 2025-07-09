// SPDX-License-Identifier: BSD-2-Clause
use styx_core::{event_controller::ActivateIRQnError, prelude::*};

use enum_map::Enum;
use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Variant representation is the event's event number.
///
/// Ordering of [Event]s is determined by priority level, which is inverse to the event number. For
/// example, [Event::Emulation] > [Event::Reset].
#[derive(Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive, Enum, Debug)]
#[repr(u8)]
pub enum Event {
    /// EMU
    Emulation = 0,
    /// Reset
    Reset = 1,
    /// NMI
    Nmi = 2,
    /// EVX
    Exception = 3,
    /// IVHW
    HardwareError = 5,
    /// IVTMR
    CoreTimer = 6,
    /// IVG7
    Interrupt7 = 7,
    /// IVG8
    Interrupt8 = 8,
    /// IVG9
    Interrupt9 = 9,
    /// IVG10
    Interrupt10 = 10,
    /// IVG11
    Interrupt11 = 11,
    /// IVG12
    Interrupt12 = 12,
    /// IVG13
    Interrupt13 = 13,
    /// IVG14
    Interrupt14 = 14,
    /// IVG15
    Interrupt15 = 15,
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u8::from(*self).cmp(&u8::from(*other)).reverse()
    }
}

impl Event {
    pub fn from_event_irqn_expect(value: ExceptionNumber) -> Result<Self, ActivateIRQnError> {
        Self::try_from(value).map_err(|_| ActivateIRQnError::InvalidIRQn(value))
    }

    pub fn event_number(self) -> u8 {
        self.into()
    }

    /// Event vector table address for event. Holds the address of the event handler routine.
    pub fn evt_address(self) -> u64 {
        (super::sys::EVT0 + (self.event_number() as u32 * 4)) as u64
    }

    /// Bit location of this event in core event controller registers (IMASK, IPEND, and ILAT).
    fn mask_bit(self) -> u8 {
        self.event_number()
    }

    /// Can this [Event] be masked in the IMASK register?
    pub fn is_maskable(self) -> bool {
        // events 0, 1, 2, and 3 are not maskable
        match self {
            Event::Emulation | Event::Reset | Event::Nmi | Event::Exception => false,
            Event::HardwareError
            | Event::CoreTimer
            | Event::Interrupt7
            | Event::Interrupt8
            | Event::Interrupt9
            | Event::Interrupt10
            | Event::Interrupt11
            | Event::Interrupt12
            | Event::Interrupt13
            | Event::Interrupt14
            | Event::Interrupt15 => true,
        }
    }

    /// Is this event always enabled? If always enabled then it is not maskable.
    pub fn always_enabled(self) -> bool {
        !self.is_maskable()
    }

    /// Is this event latchable from RAISE instruction.
    pub fn is_raise_latchable(self) -> bool {
        match self {
            Event::Emulation | Event::Exception => false,
            Event::Reset
            | Event::Nmi
            | Event::HardwareError
            | Event::CoreTimer
            | Event::Interrupt7
            | Event::Interrupt8
            | Event::Interrupt9
            | Event::Interrupt10
            | Event::Interrupt11
            | Event::Interrupt12
            | Event::Interrupt13
            | Event::Interrupt14
            | Event::Interrupt15 => true,
        }
    }

    /// Returns whether a mask is set for the given event.
    ///
    /// This function takes a 16-bit mask register and checks if the bit corresponding to this event
    /// is set. It returns `true` if the bit is set, and `false` otherwise.
    pub fn is_set_u16(self, mask_register: u16) -> bool {
        (mask_register & (1 << self.mask_bit())) > 0
    }
}

impl TryFrom<ExceptionNumber> for Event {
    type Error = ();

    fn try_from(value: ExceptionNumber) -> Result<Self, Self::Error> {
        Self::try_from(u8::try_from(value).map_err(|_| ())?).map_err(|_| ())
    }
}

impl From<Event> for ExceptionNumber {
    fn from(value: Event) -> Self {
        value.event_number() as i32
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use test_case::test_case;

    use super::*;

    #[test_case(Event::CoreTimer, Event::HardwareError, Ordering::Less; "core timer is less priority than hardware error")]
    #[test_case(Event::Interrupt7, Event::Interrupt8, Ordering::Greater; "interrupt 7 is higher priority than interrupt 8")]
    #[test_case(Event::Emulation, Event::Interrupt15, Ordering::Greater; "emulation higher priority than interrupt 15")]
    #[test_case(Event::Reset, Event::Reset, Ordering::Equal; "reset is the same priority as reset")]
    fn test_ordering(a: Event, b: Event, answer: Ordering) {
        assert_eq!(answer, a.cmp(&b));
    }

    #[test_case(Event::Reset, 1; "reset irqn")]
    #[test_case(Event::Interrupt11, 11; "interrupt 11")]
    #[test_case(Event::Exception, 3; "Exception")]
    #[test_case(Event::HardwareError, 5; "hardware error")]
    fn test_from_event_irqn(event: Event, irqn: ExceptionNumber) {
        let actual_event = Event::from_event_irqn_expect(irqn).unwrap();
        assert_eq!(actual_event, event);

        let actual_irqn = ExceptionNumber::from(actual_event);
        assert_eq!(actual_irqn, irqn);
    }
}
