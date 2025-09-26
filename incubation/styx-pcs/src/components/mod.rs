use std::{
    borrow::Cow,
    collections::{hash_map::Entry, HashMap},
};

use inventory::Collect;
use styx_core::{errors::UnknownError, prelude::log};
use thiserror::Error;

/// Derserializable configs.
pub mod config;

#[derive(Debug)]
pub struct ComponentStore<T> {
    /// Stores id -> [`ComponentGenerator`] mappings.
    store: HashMap<Cow<'static, str>, T>,
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
pub(crate) struct IdNotFound(String);

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
    pub fn add(
        &mut self,
        id: impl Into<Cow<'static, str>>,
        generator: T,
    ) -> Result<(), DuplicateId> {
        let id: Cow<'static, str> = id.into();
        // for the duplicate id error in the else branch
        let id2 = id.clone();
        if let Entry::Vacant(e) = self.store.entry(id) {
            e.insert(generator);
            Ok(())
        } else {
            Err(DuplicateId(id2.into_owned()))
        }
    }

    pub fn list(&self) -> impl Iterator<Item = Cow<'static, str>> + use<'_, T> {
        self.store.keys().cloned()
    }
}

impl<T> ComponentStore<T>
where
    Component<T>: Collect,
    T: Clone,
{
    fn populate(&mut self) -> Result<(), DuplicateId> {
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
    pub file: &'static str,
    pub line: u32,
    pub module_path: &'static str,
}
