// SPDX-License-Identifier: BSD-2-Clause
//! Read-only, processor-global configuration values.
//!
//! The config system provides a type-keyed store of [`ProcessorConfig`]
//! values that are set during processor construction and shared
//! read-only across subsystems at runtime. Each config type is
//! registered at most once; its concrete [`TypeId`] serves as the
//! lookup key, so different subsystems can retrieve the values they
//! care about without coupling to one another.
//!
//! See [`core_configs`] for the built-in config types supplied by the
//! processor builder.

pub mod core_configs;

use std::{any::TypeId, collections::HashMap};

use as_any::{AsAny, Downcast};

/// Marker trait for types that can be stored in a [`Config`] map.
///
/// Implementors must be `Send + Sync + 'static` so the config map can
/// be shared safely across threads. The [`AsAny`] super-trait enables
/// type-safe downcasting at retrieval time.
pub trait ProcessorConfig: Send + Sync + AsAny + 'static {}

/// Type-erased key derived from a concrete config type's [`TypeId`].
#[derive(Hash, Clone, Copy, PartialEq, Eq)]
struct ConfigId(TypeId);

impl ConfigId {
    /// Creates a key for the config type `T`.
    fn new<T: 'static>() -> Self {
        Self(TypeId::of::<T>())
    }
}

/// A type-keyed, heterogeneous map of [`ProcessorConfig`] values.
///
/// Each concrete config type may appear at most once. Values are
/// inserted during processor construction and read (but never mutated)
/// by subsystems at runtime.
///
/// Users building processors should use [`ProcessorBuilder::config()`](super::ProcessorBuilder::config) and
/// [`ProcessorBuilder::modify_config_or_default()`](super::ProcessorBuilder::modify_config_or_default) to add [`ProcessorConfig`]s
/// to their processor.
///
/// Builders of processors components that received a `&Config` can use
/// [`Config::get()`] and [`Config::get_or_default()`] to retrieve configuration
/// values.
///
/// # Examples
///
/// ```
/// use styx_processor::processor::{Config, ProcessorConfig};
///
/// #[derive(Default, Clone, Copy)]
/// struct MyConfig { stride: u64 }
/// impl ProcessorConfig for MyConfig {}
///
/// // An empty config returns `None` for unregistered types.
/// let config = Config::default();
/// assert!(config.get::<MyConfig>().is_none());
///
/// // `get_or_default` falls back to `Default::default()`.
/// assert_eq!(config.get_or_default::<MyConfig>().stride, 0);
/// ```
#[derive(Default)]
pub struct Config {
    configs: HashMap<ConfigId, Box<dyn ProcessorConfig>>,
}

impl Config {
    /// Registers or overwrites the config  `C`.
    ///
    /// `None` is returned if the new config value is registered,
    /// otherwise, the old config value is returned.
    ///
    /// Styx users use [`super::builder::ProcessorBuilder::register_config()`].
    pub(crate) fn register_config<C: ProcessorConfig>(&mut self, config: C) -> Option<C> {
        let config = Box::new(config);
        let config_id = ConfigId::new::<C>();
        let old = self.configs.insert(config_id, config)?;
        let raw = Box::into_raw(old);
        // SAFETY: we know that value is the type that the key refers to.
        Some(*unsafe { Box::from_raw(raw as *mut C) })
    }

    /// Applies `f` to the existing config of type `C`, inserting a
    /// default value first if none is present.
    ///
    /// Styx users use [`super::builder::ProcessorBuilder::modify_config_or_default()`].
    pub(crate) fn modify_config_or_default<C: ProcessorConfig + Default>(
        &mut self,
        f: impl FnOnce(&mut C),
    ) {
        let config_id = ConfigId::new::<C>();
        self.configs
            .entry(config_id)
            .and_modify(move |config_item| {
                let config_downcast = config_item.as_mut().downcast_mut::<C>().expect("no");
                f(config_downcast);
            })
            .or_insert(Box::new(C::default()));
    }

    /// Returns a reference to the config of type `C`, or `None` if it
    /// has not been registered.
    ///
    /// # Examples
    ///
    /// ```
    /// use styx_processor::processor::{Config, ProcessorConfig};
    ///
    /// struct MyConfig { stride: u64 }
    /// impl ProcessorConfig for MyConfig {}
    ///
    /// let config = Config::default();
    ///
    /// // Not registered, so `get` returns `None`.
    /// assert!(config.get::<MyConfig>().is_none());
    /// ```
    pub fn get<C: ProcessorConfig>(&self) -> Option<&C> {
        let config_id = ConfigId::new::<C>();
        let config = self.configs.get(&config_id)?;
        Some(config.as_ref().downcast_ref::<C>().unwrap())
    }

    /// Returns the config of type `C`, falling back to
    /// [`Default::default`] when the entry is absent.
    ///
    /// # Examples
    ///
    /// ```
    /// use styx_processor::processor::{Config, ProcessorConfig};
    ///
    /// #[derive(Default, Clone, Copy)]
    /// struct MyConfig { stride: u64 }
    /// impl ProcessorConfig for MyConfig {}
    ///
    /// let config = Config::default();
    ///
    /// // Falls back to `MyConfig::default()` since nothing was registered.
    /// let my_config = config.get_or_default::<MyConfig>();
    /// assert_eq!(my_config.stride, 0);
    /// ```
    pub fn get_or_default<C: ProcessorConfig + Default + Copy>(&self) -> C {
        self.get().copied().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct ExampleConfig {
            cfg_string: String,
            cfg_u32: u32,
        }
        impl ProcessorConfig for ExampleConfig {}

        let mut config = Config::default();
        let orig_example = ExampleConfig {
            cfg_string: "hello".to_owned(),
            cfg_u32: 0x1337,
        };
        config.register_config(orig_example.clone());

        let get = config.get::<ExampleConfig>().unwrap();
        assert_eq!(&get.cfg_string, "hello");
        assert_eq!(get.cfg_u32, 0x1337);

        // make sure another add_config returns the old config
        let another_example = ExampleConfig {
            cfg_string: "goodbye".to_owned(),
            cfg_u32: 0xdeadbeef,
        };
        let after_add_example = config
            .register_config(another_example)
            .expect("should have old config");
        assert_eq!(
            after_add_example, orig_example,
            "returned config {after_add_example:?} not the same as expected {orig_example:?}"
        )
    }
}
