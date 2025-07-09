// SPDX-License-Identifier: BSD-2-Clause
use derive_more::Display;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcessorStateError {
    #[error("Processor is already in state: `{0}`")]
    DuplicateProcessorState(ProcessorState),
    #[error("Not allowed to move from Processor state: `{0}` to `{1}`")]
    IllegalTransition(ProcessorState, ProcessorState),
}

/// Represents the operating state of a `Processor`
///
/// Note that [`ProcessorState::Paused`] is the only state that is
/// allowed to transition to itself
///
/// # Valid Transitions
/// - `Uninitialized` -> `Initializing`
/// - `Initializing` -> `Initialized`
/// - `Initialized` -> `ShuttingDown` | `Running` | `Paused`
/// - `Paused` -> `ShuttingDown` | `Running` | `Paused`
/// - `Running` -> `Paused`
/// - `ShuttingDown` -> `Shutdown`
/// - `Shutdown` (None)
#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Display, PartialOrd, Ord)]
#[cfg_attr(serde, derive(serde::Serialize, serde::Deserialize))]
pub enum ProcessorState {
    #[default]
    /// Processor has not been initialized
    Uninitialized,
    /// Processor is currently being built
    Initializing,
    /// Processor has completed build phase
    Initialized,
    /// Processor has been paused
    Paused,
    /// Processor is currently executing
    Running,
    /// Processor is beginning shutdown process
    ShuttingDown,
    /// Processor has completed shutdown process
    Shutdown,
}

impl ProcessorState {
    fn valid_transition(&self, next_state: Self) -> Result<(), ProcessorStateError> {
        // all duplicate cases are taken care of
        // paused is explicitly ALLOWED to be self->self
        if *self == next_state && next_state != ProcessorState::Paused {
            return Err(ProcessorStateError::DuplicateProcessorState(next_state));
        }

        // find the allowed / disallowed transitions
        match *self {
            Self::Uninitialized => match next_state {
                Self::Initializing => Ok(()),
                _ => Err(ProcessorStateError::IllegalTransition(*self, next_state)),
            },
            Self::Initializing => match next_state {
                Self::Initialized => Ok(()),
                _ => Err(ProcessorStateError::IllegalTransition(*self, next_state)),
            },
            Self::Initialized => match next_state {
                Self::Paused | Self::Running | Self::ShuttingDown => Ok(()),
                _ => Err(ProcessorStateError::IllegalTransition(*self, next_state)),
            },
            Self::Paused => match next_state {
                // include Paused -> Paused
                Self::Paused | Self::Running | Self::ShuttingDown => Ok(()),
                _ => Err(ProcessorStateError::IllegalTransition(*self, next_state)),
            },
            Self::Running => match next_state {
                Self::Paused => Ok(()),
                _ => Err(ProcessorStateError::IllegalTransition(*self, next_state)),
            },
            Self::ShuttingDown => match next_state {
                Self::Shutdown => Ok(()),
                _ => Err(ProcessorStateError::IllegalTransition(*self, next_state)),
            },
            // shutdown cannot advance
            _ => Err(ProcessorStateError::IllegalTransition(*self, next_state)),
        }
    }

    pub fn advance_state(&mut self, next_state: Self) -> Result<(), ProcessorStateError> {
        self.valid_transition(next_state)?;

        // set self to new state
        *self = next_state;

        Ok(())
    }
}

#[cfg(test)]
mod processor_state_tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn test_default() {
        assert_eq!(ProcessorState::Uninitialized, ProcessorState::default());
    }

    #[test_case(ProcessorState::Uninitialized; "Uninitialized to Uninitialized")]
    #[test_case(ProcessorState::Initializing; "Initializing to Initializing")]
    #[test_case(ProcessorState::Initialized; "Initialized to Initialized")]
    #[test_case(ProcessorState::Running; "Running to Running")]
    #[test_case(ProcessorState::ShuttingDown; "ShuttingDown to ShuttingDown")]
    #[test_case(ProcessorState::Shutdown; "Shutdown to Shutdown")]
    fn test_illegal_duplicate_states(mut state: ProcessorState) {
        assert!(state.advance_state(state).is_err());
    }

    #[test_case(ProcessorState::Paused; "Paused to Paused")]
    fn test_legal_duplicate_states(mut state: ProcessorState) {
        assert!(state.advance_state(state).is_ok());
    }

    #[test_case(ProcessorState::Uninitialized, ProcessorState::Initializing; "Uninitialized to Initializing")]
    #[test_case(ProcessorState::Initializing, ProcessorState::Initialized; "Initializing to Initialized")]
    #[test_case(ProcessorState::Initialized, ProcessorState::ShuttingDown; "Initialized to ShuttingDown")]
    #[test_case(ProcessorState::Initialized, ProcessorState::Running; "Initialized to Running")]
    #[test_case(ProcessorState::Initialized, ProcessorState::Paused; "Initialized to Pausing")]
    #[test_case(ProcessorState::Paused, ProcessorState::ShuttingDown; "Paused to ShuttingDown")]
    #[test_case(ProcessorState::Paused, ProcessorState::Running; "Paused to Running")]
    #[test_case(ProcessorState::Paused, ProcessorState::Paused; "Paused to Paused")]
    #[test_case(ProcessorState::Running, ProcessorState::Paused; "Running to Paused")]
    #[test_case(ProcessorState::ShuttingDown, ProcessorState::Shutdown; "ShuttingDown to Shutdown")]
    fn test_legal_state_transitions(mut initial: ProcessorState, next: ProcessorState) {
        assert!(initial.advance_state(next).is_ok());
    }

    #[test_case(ProcessorState::Uninitialized, ProcessorState::Initialized; "Uninitialized to Initialized")]
    #[test_case(ProcessorState::Uninitialized, ProcessorState::Paused; "Uninitialized to Paused")]
    #[test_case(ProcessorState::Uninitialized, ProcessorState::Running; "Uninitialized to Running")]
    #[test_case(ProcessorState::Uninitialized, ProcessorState::ShuttingDown; "Uninitialized to ShuttingDown")]
    #[test_case(ProcessorState::Uninitialized, ProcessorState::Shutdown; "Uninitialized to Shutdown")]
    #[test_case(ProcessorState::Initializing, ProcessorState::Initializing; "Initializing to Initializing")]
    #[test_case(ProcessorState::Initializing, ProcessorState::Paused; "Initializing to Paused")]
    #[test_case(ProcessorState::Initializing, ProcessorState::Running; "Initializing to Running")]
    #[test_case(ProcessorState::Initializing, ProcessorState::ShuttingDown; "Initializing to ShuttingDown")]
    #[test_case(ProcessorState::Initializing, ProcessorState::Shutdown; "Initializing to Shutdown")]
    #[test_case(ProcessorState::Initialized, ProcessorState::Initializing; "Initialized to Initializing")]
    #[test_case(ProcessorState::Initialized, ProcessorState::Initialized; "Initialized to Initialized")]
    #[test_case(ProcessorState::Initialized, ProcessorState::Shutdown; "Initialized to Shutdown")]
    #[test_case(ProcessorState::Paused, ProcessorState::Initializing; "Paused to Initializing")]
    #[test_case(ProcessorState::Paused, ProcessorState::Shutdown; "Paused to Shutdown")]
    #[test_case(ProcessorState::Running, ProcessorState::Initializing; "Running to Initializing")]
    #[test_case(ProcessorState::Running, ProcessorState::Initialized; "Running to Initialized")]
    #[test_case(ProcessorState::Running, ProcessorState::ShuttingDown; "Running to ShuttingDown")]
    #[test_case(ProcessorState::Running, ProcessorState::Shutdown; "Running to Shutdown")]
    #[test_case(ProcessorState::ShuttingDown, ProcessorState::Initializing; "ShuttingDown to Initializing")]
    #[test_case(ProcessorState::ShuttingDown, ProcessorState::Initialized; "ShuttingDown to Initialized")]
    #[test_case(ProcessorState::ShuttingDown, ProcessorState::Paused; "ShuttingDown to Paused")]
    #[test_case(ProcessorState::ShuttingDown, ProcessorState::Running; "ShuttingDown to Running")]
    fn test_illegal_state_transitions(mut initial: ProcessorState, next: ProcessorState) {
        assert!(initial.advance_state(next).is_err());
    }
}
