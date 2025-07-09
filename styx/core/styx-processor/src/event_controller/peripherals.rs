// SPDX-License-Identifier: BSD-2-Clause
use std::any::type_name;

use rustc_hash::FxHashMap;
use styx_errors::{
    anyhow::{anyhow, Context},
    UnknownError,
};

use super::{ExceptionNumber, Peripheral};

#[derive(Default)]
/// A container for holding Peripherals.
///
/// Provides useful methods and data structures for getting and inserting.
///
/// Note:
///
/// Don't reorder the internal peripherals array without also updating the
/// hashmap, otherwise some functionality will break.
pub struct Peripherals {
    pub peripherals: Vec<Box<dyn Peripheral>>,
    /// a mapping from exception numbers to indices in the peripherals vec.
    /// allows for fast lookups of peripheral by exception number
    index_map: FxHashMap<ExceptionNumber, usize>,
}

impl Peripherals {
    /// Returns the first peripheral that matches the passed in generic type T.
    ///
    /// Returns None if no peripheral matched.
    pub fn get<T: Peripheral + 'static>(&mut self) -> Option<&mut T> {
        self.peripherals
            .iter_mut()
            .find_map(|p| p.as_any_mut().downcast_mut::<T>())
    }

    /// Performs the same functionality as `Peripherals::get::<T>()` but wraps any errors with additional context.
    pub fn get_expect<T: Peripheral + 'static>(&mut self) -> Result<&mut T, UnknownError> {
        self.get::<T>()
            .with_context(|| format!("could not find expected peripheral {:?}", type_name::<T>()))
    }

    /// Search for and return a peripheral with a matching exception number.
    ///
    /// Returns an error if no matching peripherals were found.
    pub fn get_peripheral_by_exception(
        &mut self,
        exn: ExceptionNumber,
    ) -> Result<&mut Box<dyn Peripheral>, UnknownError> {
        if let Some(i) = self.index_map.get(&exn) {
            Ok(&mut self.peripherals[*i])
        } else {
            Err(anyhow!(
                "exception number does not belong to any peripheral: {:}",
                exn
            ))
        }
    }

    /// Add a new peripheral.
    ///
    /// Peripheral names must be unique and exception numbers must map to a single peripheral.
    /// This will return an error if another peripheral with the same name already exists
    /// or if duplicate exception numbers are encountered.
    pub fn insert_peripheral(
        &mut self,
        peripheral: Box<dyn Peripheral>,
    ) -> Result<(), UnknownError> {
        // check for peripherals with the same name
        for existing_peripheral in &self.peripherals {
            if existing_peripheral.name() == peripheral.name() {
                return Err(anyhow!(
                    "duplicate peripheral: {:?}",
                    existing_peripheral.name()
                ));
            }
        }

        let index = self.peripherals.len();
        // create a mapping between exceptions and peripheral
        for exn in peripheral.irqs() {
            if let Some(i) = self.index_map.insert(exn, index) {
                return Err(anyhow!(
                    "multiple peripherals with the same exception number: {:?}, {:?}",
                    peripheral.name(),
                    self.peripherals[i].name()
                ));
            }
        }

        // add peripheral to list
        self.peripherals.push(peripheral);

        Ok(())
    }
}
