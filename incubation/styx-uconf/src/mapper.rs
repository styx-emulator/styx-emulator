// SPDX-License-Identifier: BSD-2-Clause
use std::{
    borrow::Cow,
    collections::{hash_map::Entry, HashMap},
};

use styx_core::{
    core::builder::ProcessorImpl,
    errors::UnknownError,
    prelude::{log::trace, ExecutorImpl, UninitPlugin},
};
use thiserror::Error;

use crate::{
    components::{Component, ComponentType},
    ComponentConfig, ComponentReference,
};

pub type ComponentGenerator<T> = fn(Option<&ComponentConfig>) -> Result<T, UnknownError>;

#[derive(Debug)]
pub struct ComponentStore<T> {
    /// Stores id -> [`ComponentGenerator`] mappings.
    store: HashMap<Cow<'static, str>, ComponentGenerator<T>>,
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

impl<T> ComponentStore<T> {
    fn get(&self, id: impl AsRef<str>) -> Result<&ComponentGenerator<T>, IdNotFound> {
        self.store
            .get(id.as_ref())
            .ok_or_else(|| IdNotFound(id.as_ref().to_owned()))
    }

    /// Checked add, errors if impl already exists.
    pub fn add(
        &mut self,
        id: impl Into<Cow<'static, str>>,
        generator: ComponentGenerator<T>,
    ) -> Result<(), ComponentGenerator<T>> {
        let id: Cow<'static, str> = id.into();
        if let Entry::Vacant(e) = self.store.entry(id) {
            e.insert(generator);
            Ok(())
        } else {
            Err(generator)
        }
    }

    pub(crate) fn generate(
        &self,
        component_reference: impl ComponentReference,
    ) -> Result<T, GenerateError> {
        let id = component_reference.id();
        let config = component_reference.config();
        let generator = self.get(id)?;
        Ok(generator(config)?)
    }

    pub fn list(&self) -> impl Iterator<Item = Cow<'static, str>> + use<'_, T> {
        self.store.keys().cloned()
    }
}

/// Store all registered components that could be referenced when configuring a processor.
#[derive(Default)]
pub struct ProcessorComponentsStore {
    pub builders: ComponentStore<Box<dyn ProcessorImpl>>,
    pub plugins: ComponentStore<Box<dyn UninitPlugin>>,
    pub executors: ComponentStore<Box<dyn ExecutorImpl>>,
}

impl ProcessorComponentsStore {
    pub fn new() -> Self {
        // todo inventory stuff
        let mut me = Self::default();
        me.build_inventory().unwrap();
        me
    }

    pub fn build_inventory(&mut self) -> Result<(), UnknownError> {
        for component in inventory::iter::<Component> {
            let id = component.id;
            trace!(
                "registered {} \"{}\" provided by {}",
                component.generator,
                component.id,
                component.module_path
            );
            match component.generator {
                ComponentType::Processor(generator) => self.builders.add(id, generator).unwrap(),
                ComponentType::Executor(generator) => self.executors.add(id, generator).unwrap(),
                ComponentType::Plugin(generator) => self.plugins.add(id, generator).unwrap(),
            }
        }
        Ok(())
    }
}
