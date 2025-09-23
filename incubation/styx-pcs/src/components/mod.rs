// SPDX-License-Identifier: BSD-2-Clause
//! Generic compiletime pluggable functionality for derserialization.
//!
//! Components allow users to provide custom implementations (components) of a system
//! that can be iterated and referenced by id by styx.
//! In addition, the components are easily registered just by adding a crate with components you want to use.
//!
use std::collections::{hash_map::Entry, HashMap};

use inventory::Collect;
use styx_core::{errors::UnknownError, prelude::log};
use thiserror::Error;

/// Derserializable configs for Components.
mod config;
pub use config::*;

mod macros;

/// Storage of components.
///
/// See the module level documentation for more information.
#[derive(Debug)]
pub struct ComponentStore<T> {
    // ids are Strings which introduce extra allocations but this shouldn't be perf critical code.
    // we can switch to Cow or &'static str later at the cost of a worse api/code
    /// Stores id -> item (`T`) mappings.
    store: HashMap<String, T>,
}
impl<T> Default for ComponentStore<T> {
    fn default() -> Self {
        Self {
            store: HashMap::new(),
        }
    }
}

#[derive(Error, Debug)]
#[error("id \"{0}\" not found")]
pub struct IdNotFound(String);

#[derive(Error, Debug)]
pub(crate) enum GenerateError {
    #[error("id not found while getting generator")]
    IdNotFound(#[from] IdNotFound),
    #[error(transparent)]
    Other(#[from] UnknownError),
}

#[derive(Error, Debug)]
#[error("duplicate id \"{0}\" found")]
pub struct DuplicateId(String);

impl<T> ComponentStore<T> {
    fn empty() -> Self {
        Self::default()
    }

    pub fn get(&self, id: impl AsRef<str>) -> Result<&T, IdNotFound> {
        self.store
            .get(id.as_ref())
            .ok_or_else(|| IdNotFound(id.as_ref().to_owned()))
    }

    /// Checked add, errors if impl already exists.
    pub fn add(&mut self, id: impl Into<String>, generator: T) -> Result<(), DuplicateId> {
        let id: String = id.into();
        // for the duplicate id error in the else branch
        let id2 = id.clone();
        if let Entry::Vacant(e) = self.store.entry(id) {
            e.insert(generator);
            Ok(())
        } else {
            Err(DuplicateId(id2))
        }
    }

    /// List all ids in the store.
    ///
    /// Currently just used for testing but should be used for monitoring/logging later.
    #[cfg(test)]
    pub fn list(&self) -> impl Iterator<Item = &str> {
        self.store.keys().map(|i| i.as_str())
    }
}

// ComponentStore where the item can be collected by inventory.
impl<T> ComponentStore<T>
where
    Component<T>: Collect,
    T: Clone,
{
    /// Add collected items to the store.
    pub fn populate(&mut self) -> Result<(), DuplicateId> {
        let items = inventory::iter::<Component<T>>();
        for item in items {
            log::trace!(
                "registered \"{}\" provided by {}",
                item.id,
                item.module_path
            );
            self.add(item.id, item.item.clone())?;
        }
        Ok(())
    }

    /// Create a new [`ComponentStore`] with items populated by inventory.
    ///
    /// See [`ComponentStore::populate()`] to add items an existing store.
    ///
    /// This will error if there are multiple components that register with the same id.
    pub fn populated() -> Result<Self, DuplicateId> {
        let mut new = Self::empty();
        new.populate()?;
        Ok(new)
    }
}
/// Compile time component for registration.
///
/// If you just want to register a component, see the module level documentation for
/// [`crate::components`].
///
/// This is used internally by the component registration macros and stores module/file information
/// to log for debug purposes.
pub struct Component<T> {
    pub id: &'static str,
    pub item: T,
    #[allow(unused)]
    pub file: &'static str,
    #[allow(unused)]
    pub line: u32,
    pub module_path: &'static str,
}
