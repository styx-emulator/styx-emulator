// SPDX-License-Identifier: BSD-2-Clause
use styx_core::prelude::*;

use enum_map::EnumMap;
use tracing::debug;

use super::Event;

/// Runtime state for an [Event]. Always interfaced through [EventsContainer].
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct EventState {
    /// [Event] that this state is holding for. Used to check [Event::always_enabled()] status.
    event: Event,
    /// Is this event written to be enabled in the mask register? Note: use [EventState::enabled()]
    /// to check if enabled, including if always enabled (e.g. emu, reset, etc.)
    written_enabled: bool,
    /// Is this event pending? Pending is set when interrupt is serviced.
    pending: bool,
    /// Is this event latched? Latched events will be serviced in the future. An event will stay
    /// latched but not serviced if it is not enabled.
    latched: bool,
}

impl EventState {
    /// Is this event enabled?
    pub fn enabled(&self) -> bool {
        self.event.always_enabled() || self.written_enabled
    }

    /// Sets the pending to true and removes the latch.
    pub fn set_pending(&mut self) {
        self.pending = true;
        self.latched = false;
    }

    /// Clears the pending to false.
    pub fn clear_pending(&mut self) {
        self.pending = false;
    }
}

/// Source-of-truth manager for events.
///
/// TODO
/// - Writing state to IMASK, IPEND, and ILAT.
#[derive(Debug)]
pub struct EventsContainer {
    /// A mapping of event types to mutex-protected event states. Maybe make the whole container Mutex'd?
    exceptions: EnumMap<Event, Mutex<EventState>>,
}

impl Default for EventsContainer {
    fn default() -> Self {
        let exceptions = EnumMap::from_fn(|event| {
            Mutex::new(EventState {
                event,
                written_enabled: false,
                pending: false,
                latched: false,
            })
        });
        Self { exceptions }
    }
}

#[derive(Debug)]
pub enum LatchError {
    /// Event is already latched.
    AlreadyLatched,
    /// Event is set to pending and cannot be latched.
    Pending,
}
impl EventsContainer {
    fn find<P>(&self, mut predicate: P) -> Option<Event>
    where
        P: FnMut(&EventState) -> bool,
    {
        self.exceptions
            .iter()
            .find(|(_, exception)| predicate(&exception.lock().unwrap()))
            .map(|(event, _)| event)
    }

    /// Latches event, returning Err if already latched or if pending.
    ///
    /// Does not check mask.
    pub fn latch(&self, event: Event) -> Result<(), LatchError> {
        let mut exception = self.exceptions[event].lock().unwrap();

        if exception.latched {
            Err(LatchError::AlreadyLatched)
        } else if exception.pending {
            Err(LatchError::Pending)
        } else {
            exception.latched = true;
            Ok(())
        }
    }

    /// Returns the highest priority event that is pending, indicating an active interrupt.
    ///
    /// Iterates over all events in the system and checks if each event's state is set to `pending`.
    /// If at least one event is found with this state, returns the corresponding event; otherwise,
    /// returns `None`.
    pub fn active_interrupt(&self) -> Option<Event> {
        for (event, exception) in self.exceptions.iter() {
            if exception.lock().unwrap().pending {
                return Some(event);
            }
        }

        None
    }

    /// Returns the highest priority event that is both latched and enabled.
    ///
    /// This method iterates over all events, checking if each event's state is both latched
    /// (`latched` field) and enabled (`enabled` method).
    ///
    /// If no such event is found, an `Option<Event>` with a value of `None` will be returned.
    /// Otherwise, the highest priority matching event will be returned.
    pub fn first_latched_and_enabled(&self) -> Option<Event> {
        self.find(|exception| exception.latched && exception.enabled())
    }

    /// Sets the pending state of an event.
    ///
    /// This method sets the `pending` field of the given `EventState` to `true`, and also clears
    /// the `latched` flag.
    pub fn set_pending(&self, event: Event) {
        self.exceptions[event].lock().unwrap().set_pending()
    }

    pub fn clear_pending(&self, event: Event) {
        self.exceptions[event].lock().unwrap().clear_pending()
    }

    /// Sets the written-enabled state for all events based on the provided mask.
    ///
    /// This function iterates over all events and sets their `written_enabled` field to true if the
    /// corresponding bit is set in the mask, and false otherwise.
    pub fn set_masks(&self, mask: u16) {
        for (event, exception) in self.exceptions.iter() {
            let enabled = event.is_set_u16(mask);
            let mut exception = exception.lock().unwrap();
            let was_enabled = exception.written_enabled;
            exception.written_enabled = enabled;

            if was_enabled != enabled {
                debug!("{event:?} mask: {was_enabled} -> {enabled}");
            }
        }
    }

    /// Performs latch bit clearing as described in the ILAT documentation.
    ///
    /// Writes to ILAT are used to clear bits only (in Supervisor mode). To clear bit N from ILAT,
    /// first make sure that `IMASK[N] == 0`, and then write `ILAT[N] = 1`. This write
    /// functionality to ILAT is provided for cases where latched interrupt requests need to be
    /// cleared (cancelled) instead of serviced.
    pub fn clear_latches(&self, set_latched: u16) {
        for (event, exception) in self.exceptions.iter() {
            let mut exception = exception.lock().unwrap();
            let set_latched = event.is_set_u16(set_latched);
            if set_latched && !exception.enabled() {
                exception.latched = false;
            }
        }
    }
}
