// SPDX-License-Identifier: BSD-2-Clause
//! Styx Unified Configuration
//!
//! Unified Configuration is declarative configuration of processors using a YAML specification.
//!
//! This crate allows for programmatic configuration parsing and realization but users can use the
//! `styx-uconf-cli` crate for easier use.
//!
//! ## Recommended Usage
//!
//! Use [`realize_unified()`] to take a yaml spec and turn it into a list of [`ProcessorBuilder`].
//!
//! ```
//! # use styx_uconf::realize_unified;
//! # use styx_core::prelude::*;
//! let yaml = r#"
//! version: 1
//! processors:
//! - name: Test Processor
//!   ## you would use something like ppc_4xx
//!   processor: dummy
//!   port: 0
//! "#;
//!
//! let mut builder: Vec<ProcessorBuilder<'static>> = realize_unified(yaml).unwrap();
//! let processor = builder.pop().unwrap().build().unwrap();
//! // we can now use our processor!
//! // processor.start(Forever).unwrap();
//! ```
//!
//! ## Piecemeal Usage
//!
//! Alternatively, you can construct the processor builder using the config and components store
//! separately. This gives more control over the process allowing you do derive the
//! [`ProcessorConfig`] from a separate source (storage, other serde target, cli) and add custom
//! components to the [`ProcessorComponentsStore`] from other sources.
//!
//! The two main parts of uconf are the [`ProcessorConfig`] and [`ProcessorComponentsStore`]. The
//! [`ProcessorConfig`] is the Yaml declaration given by the user to define the processor. It can be
//! stored, serialized, deserialized, and exists has an independent file of Styx. The
//! [`ProcessorComponentsStore`] on the other hand contains all of the Styx specific glue needed to
//! transform the configuration into a functional processor. Namely, it allows for crates external
//! to Styx to register its implementations like processor builders, executors, and plugins.
//!
//! ```
//! # use styx_uconf::{realize_unified_config, ProcessorComponentsStore, UnifiedConfig};
//! # use styx_core::prelude::*;
//! let yaml = r#"
//! version: 1
//! processors:
//! - name: Test Processor
//!   ## you would use something like ppc_4xx
//!   processor: dummy
//!   port: 0
//! "#;
//!
//! let config: UnifiedConfig = serde_yaml::from_str(yaml).unwrap();
//! let components = ProcessorComponentsStore::new();
//! // add registered components, modify config here
//! let mut builder = realize_unified_config(&config, &components).unwrap();
//! let processor = builder.pop().unwrap().build().unwrap();
//! // we can now use our processor!
//! // processor.start(Forever).unwrap();
//! ```
//!
//! ## Registering Components
//!
//! The recommended way to register components is with the [`register_component`] and
//! [`register_component_config`] macros.
//!
//! ```
//! # use styx_core::prelude::*;
//! # use styx_uconf::{register_component, register_component_config, realize_unified};
//! # // impl plugin stuff for SuperAwesome, you can ignore.
//! # impl UninitPlugin for SuperAwesomePlugin {
//! #     fn init(self: Box<Self>, proc: &mut BuildingProcessor) -> Result<Box<dyn Plugin>, UnknownError> {
//! #          Ok(self)
//! #     }
//! # }
//! # impl Plugin for SuperAwesomePlugin {
//! #     fn name(&self) -> &str { "super awesome plugin" }
//! # }
//! # impl UninitPlugin for SuperComplexPlugin {
//! #     fn init(self: Box<Self>, proc: &mut BuildingProcessor) -> Result<Box<dyn Plugin>, UnknownError> {
//! #          Ok(self)
//! #     }
//! # }
//! # impl Plugin for SuperComplexPlugin {
//! #     fn name(&self) -> &str { "super complex plugin" }
//! # }
//! // Say I have a plugin component with no configuration: SuperAwesomePlugin
//! struct SuperAwesomePlugin;
//! register_component!(register plugin: id = super_awesome, component = SuperAwesomePlugin);
//!
//! // Or SuperComplexPlugin which has a configuration that should be able to be specified
//! #[derive(serde::Deserialize, Default)]
//! struct SuperComplexPlugin {
//!     critical_option: bool,
//! }
//! register_component_config!(register plugin: id = super_complex, component = SuperComplexPlugin);
//!
//! // Then...
//! let processor_config = r#"
//! version: 1
//! processors:
//! - name: Test Processor
//!   processor: dummy
//!   plugins:
//!   - super_awesome
//!   - id: super_complex
//!     config:
//!       critical_option: true
//! "#;
//!
//! let builder: Vec<ProcessorBuilder<'static>> = realize_unified(processor_config).unwrap();
//! ```
//!
use std::borrow::Cow;
use std::fmt::Debug;

use serde::Deserialize;
use styx_core::{
    core::ExceptionBehavior,
    prelude::{log::debug, *},
};

pub mod components;
mod core_components;
mod mapper;

pub use mapper::ComponentGenerator;
pub use mapper::ProcessorComponentsStore;

// Ideally, `version` would be an enum with each variant being a newtype with that version config
// structure. This is theoretically possible, but serde_yaml errors with the following error:
// `processors[0].program[0]: untagged and internally tagged enums do not support enum input`
//
// Until we can fix that we may have do have a structure like we have here.
#[derive(Deserialize, Debug)]
pub struct UnifiedConfig {
    pub processors: Vec<ProcessorConfig>,
    pub version: u16,
}

#[derive(Deserialize, Debug)]
pub struct ProcessorConfig {
    pub name: Cow<'static, str>,
    pub processor: SerdeComponentReference,
    pub backend: Option<Backend>,
    pub executor: Option<SerdeComponentReference>,
    #[serde(default)]
    pub plugins: Vec<SerdeComponentReference>,
    pub port: Option<IPCPort>,
    pub exception_behavior: Option<ExceptionBehavior>,
    #[serde(default)]
    pub program: styx_core::loader::LoadRecords,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum SerdeComponentReference {
    Flat(Cow<'static, str>),
    Struct {
        id: Cow<'static, str>,
        config: Option<ComponentConfig>,
    },
}

impl Debug for SerdeComponentReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SerdeComponentReference with id {:?} and ", self.id())?;
        match self.config() {
            Some(config) => write!(f, "config: {config:?}"),
            None => write!(f, "no config"),
        }
    }
}

/// Contains an id and config references a arbitrary component.
pub trait ComponentReference {
    fn id(&self) -> &str;
    fn config(&self) -> Option<&ComponentConfig>;
}

impl<T: ComponentReference> ComponentReference for &T {
    fn id(&self) -> &str {
        (*self).id()
    }

    fn config(&self) -> Option<&ComponentConfig> {
        (*self).config()
    }
}

impl ComponentReference for SerdeComponentReference {
    fn id(&self) -> &str {
        match self {
            SerdeComponentReference::Flat(id) => id,
            SerdeComponentReference::Struct { id, config: _ } => id,
        }
    }

    fn config(&self) -> Option<&ComponentConfig> {
        match self {
            SerdeComponentReference::Flat(_) => None,
            SerdeComponentReference::Struct { id: _, config } => config.as_ref(),
        }
    }
}

/// Used in [`ComponentReference::config()`], just a yaml value.
#[derive(Deserialize, Debug)]
#[serde(transparent)]
pub struct ComponentConfig {
    pub config: serde_yaml::Value,
}

/// Combine a processor config with the registered components store.
///
/// Users should prefer [realize_unified()] or the styx-uconf-cli as they are simpler.
pub fn realize_processor_config(
    config: &ProcessorConfig,
    mapper: &ProcessorComponentsStore,
) -> Result<ProcessorBuilder<'static>, UnknownError> {
    let mut proc_builder = ProcessorBuilder::default();

    // processor impl builder
    log_component_configured_yaml("builder", &config.processor);
    let builder = mapper
        .builders
        .generate(&config.processor)
        .with_context(|| {
            format!(
                "could not resolve processor impl plugin from reference {:?}",
                &config.processor
            )
        })?;
    proc_builder = proc_builder.with_builder_box(builder);

    // cpu backend
    if let Some(backend) = config.backend {
        log_component_configured_yaml("backend", backend);
        proc_builder = proc_builder.with_backend(backend);
    }

    // executor
    if let Some(executor) = &config.executor {
        log_component_configured_yaml("executor", executor);
        let executor = mapper
            .executors
            .generate(executor)
            .with_context(|| format!("could not resolve executor from reference {executor:?}"))?;
        proc_builder = proc_builder.with_executor_box(executor);
    }

    // plugins
    for plugin_reference in config.plugins.iter() {
        log_component_configured_yaml("plugin", plugin_reference);
        let plugin = mapper.plugins.generate(plugin_reference).with_context(|| {
            format!("could not resolve plugin from reference {plugin_reference:?}")
        })?;
        proc_builder = proc_builder.add_plugin_box(plugin);
    }

    // ipc port
    if let Some(port) = &config.port {
        log_component_configured_yaml("ipc port", port);
        proc_builder = proc_builder.with_ipc_port(*port);
    }

    // exception behavior
    if let Some(exception_behavior) = &config.exception_behavior {
        log_component_configured_yaml("exception behavior", exception_behavior);
        proc_builder = proc_builder.with_exception_behavior(*exception_behavior);
    }

    // loadable program
    if !config.program.is_empty() {
        // only load if nonempty, otherwise dummy processor will fail because it doesn't specify the
        // arch loader hint
        proc_builder = proc_builder
            .with_loader(ParameterizedLoader::with_records(config.program.clone()))
            .with_input_bytes(Cow::Owned(Vec::new()));
    }

    Ok(proc_builder)
}

/// helper log function
fn log_component_configured_yaml(component: &'static str, config_item: impl Debug) {
    debug!("yaml spec configured {component} as {config_item:?}");
}

/// Realize a [`ProcessorBuilder`] from a yaml processor config.
///
/// See the crate level documentation for more information.
pub fn realize_unified_config(
    config: &UnifiedConfig,
    mapper: &ProcessorComponentsStore,
) -> Result<Vec<ProcessorBuilder<'static>>, UnknownError> {
    config
        .processors
        .iter()
        .map(|proc_config| realize_processor_config(proc_config, mapper))
        .collect()
}

/// Realize a [`ProcessorBuilder`] list from a yaml unified config.
///
/// See the crate level documentation for more information.
pub fn realize_unified(
    config: impl AsRef<str>,
) -> Result<Vec<ProcessorBuilder<'static>>, UnknownError> {
    let unified_config: UnifiedConfig = serde_yaml::from_str(config.as_ref())?;
    let mapper = ProcessorComponentsStore::new();
    realize_unified_config(&unified_config, &mapper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_parse() {
        let yaml = r#"
        version: 1
        name: Test Processor
        processor: my_processor
        backend: Pcode
        executor:
            id: my_executor
            config:
                test: test2
        port: 1337
        program:
        - !FileElf
            # Base address for the file to be loaded.
            base: 0x10000
            # ELF file backing this region
            file: foo.elf
        - !FileRaw
            base: 0x80000
            file: bar.bin
            # Permissions for the allocated memory. Valid permissions are ReadOnly,
            # WriteOnly, ExecuteOnly, ReadWrite, ReadExecute and AllowAll.
            perms: !ReadWrite
        "#;

        let processor: ProcessorConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(&processor.processor.id(), &"my_processor");
    }

    #[test]
    fn test_unified() {
        let yaml = r#"
        version: 1
        processors:
        - name: Test Processor
          processor: my_processor
          backend: Pcode
          executor:
              id: my_executor
              config:
                  test: test2
          port: 1337
          program:
          - !FileElf
              # Base address for the file to be loaded.
              base: 0x10000
              # ELF file backing this region
              file: foo.elf
          - !FileRaw
              base: 0x80000
              file: bar.bin
              # Permissions for the allocated memory. Valid permissions are ReadOnly,
              # WriteOnly, ExecuteOnly, ReadWrite, ReadExecute and AllowAll.
              perms: !ReadWrite
        - name: Test Processor 2
          processor: my_processor2
          backend: Pcode
          executor:
              id: my_executor
              config:
                  test: test2
          port: 1337
          program:
          - !FileElf
              # Base address for the file to be loaded.
              base: 0x10000
              # ELF file backing this region
              file: foo.elf
          - !FileRaw
              base: 0x80000
              file: bar.bin
              # Permissions for the allocated memory. Valid permissions are ReadOnly,
              # WriteOnly, ExecuteOnly, ReadWrite, ReadExecute and AllowAll.
              perms: !ReadWrite
        "#;

        let processors: UnifiedConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(&processors.processors[0].processor.id(), &"my_processor");
        assert_eq!(&processors.processors[1].processor.id(), &"my_processor2");
    }
}
