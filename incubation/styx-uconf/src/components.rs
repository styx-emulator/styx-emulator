// SPDX-License-Identifier: BSD-2-Clause
//! Component registration.
//!
//!

use std::fmt::Display;
use styx_core::{core::builder::ProcessorImpl, prelude::*};

use crate::ComponentGenerator;

pub use inventory::submit as inventory_submit;
pub use serde_yaml::from_value;
pub use styx_core::prelude::log;
pub use styx_core::prelude::Context;
pub use styx_core::prelude::UnknownError;

/// Register a component with no configuration for use in the Styx Unified Configuration.
///
/// This macro can be called from anywhere and if the component code is linked then the uconf will
/// find it and add to the global list of available components.
///
/// Note that this will define a function with the name of passed `id`.
///
/// General usage as follows:
/// `styx_uconf::register_component!(register <class>: id = <unique_id>, component = <create_component_expr>);`
///
/// Class is one of the types found in [`crate::components::component_types`].
///
/// Usage example:
/// `styx_uconf::register_component!(register processor: id = ppc4xx, component = PowerPC405Builder::new());`
///
#[macro_export]
macro_rules! register_component {
    (register $class:ident: id = $id:ident, component = $thing:expr) => {
        fn $id(
            config: Option<&$crate::ComponentConfig>,
        ) -> Result<$crate::components::component_types::$class, $crate::components::UnknownError> {
            //
            if config.is_some() {
                $crate::components::log::warn!(
                    "config passed to component \"{}\" that takes no configuration",
                    stringify!($id)
                )
            }
            Ok(Box::new($thing))
        }

        $crate::components::inventory_submit! {
            $crate::$class!(stringify!($id), $id)
        }
    };
}

/// Register a component that is its own configuration for use in the Styx Unified Configuration.
///
/// This macro can be called from anywhere and if the component code is linked then the uconf will
/// find it and add to the global list of available components.
///
/// General usage as follows: `styx_uconf::register_component!(register <class>: id = <unique_id>,
/// component = <component_type>);`
///
/// Class is one of the types found in [`crate::components::component_types`].
///
/// The component must implement [`serde::Deserialize`] and [`Default::default`]. The component's
/// deserialization will serve as the `config`.
///
/// Usage example: `styx_uconf::register_component!(register processor: id = ppc4xx, component =
/// PowerPC405Builder::new());`
///
#[macro_export]
macro_rules! register_component_config {
    (register $class:ident: id = $id:ident, component = $config:ty) => {
        fn $id(
            config: Option<&$crate::ComponentConfig>,
        ) -> Result<$crate::components::component_types::$class, $crate::components::UnknownError> {
            use $crate::components::Context;
            let new_config = config
                .map(|c| {
                    $crate::components::from_value::<$config>(c.config.clone())
                        .with_context(|| "invalid config")
                })
                .transpose()?
                .unwrap_or_default();
            Ok(Box::new(new_config))
        }

        $crate::components::inventory_submit! {
            $crate::$class!(stringify!($id), $id)
        }
    };
}

#[macro_export]
macro_rules! register_component_config_fn {
    (register $class:ident: id = $id:ident, component_fn = $component_fn:ident, config = $config:ty) => {
        fn $id(
            config: Option<&$crate::ComponentConfig>,
        ) -> Result<$crate::components::component_types::$class, $crate::components::UnknownError> {
            use $crate::components::Context;
            let new_config = config
                .map(|c| {
                    $crate::components::from_value::<$config>(c.config.clone())
                        .with_context(|| "invalid config")
                })
                .transpose()?;
            let new_config = new_config.with_context(|| "config not passed")?;
            let component = $component_fn(new_config)?;
            Ok(component)
        }

        $crate::components::inventory_submit! {
            $crate::$class!(stringify!($id), $id)
        }
    };
}

pub mod component_types {
    //! Component types for use by [`register_component`] and [`register_component_config`]
    #![allow(non_camel_case_types)]

    use styx_core::{
        core::builder::ProcessorImpl,
        prelude::{ExecutorImpl, UninitPlugin},
    };

    pub type processor = Box<dyn ProcessorImpl>;
    pub type executor = Box<dyn ExecutorImpl>;
    pub type plugin = Box<dyn UninitPlugin>;
}

/// Compile time component for registration.
///
/// If you just want to register a component, see the module level documentation for
/// [`crate::components`].
///
/// This is used internally by the component registration macros and stores module/file information
/// to log for debug purposes.
pub struct Component {
    pub id: &'static str,
    pub generator: ComponentType,
    pub file: &'static str,
    pub line: u32,
    pub module_path: &'static str,
}

pub enum ComponentType {
    Processor(ComponentGenerator<Box<dyn ProcessorImpl>>),
    Executor(ComponentGenerator<Box<dyn ExecutorImpl>>),
    Plugin(ComponentGenerator<Box<dyn UninitPlugin>>),
}

impl Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let component_type = match self {
            ComponentType::Processor(_) => "processor",
            ComponentType::Executor(_) => "executor",
            ComponentType::Plugin(_) => "plugin",
        };
        write!(f, "{component_type}")
    }
}

/// See the module level documentation for [`crate::components`] to register components.
#[macro_export]
macro_rules! processor {
    ($id:expr, $generator:expr) => {
        $crate::components::Component {
            id: $id,
            generator: $crate::components::ComponentType::Processor($generator),
            file: file!(),
            line: line!(),
            module_path: module_path!(),
        }
    };
}

/// See the module level documentation for [`crate::components`] to register components.
#[macro_export]
macro_rules! executor {
    ($id:expr, $generator:expr) => {
        $crate::components::Component {
            id: $id,
            generator: $crate::components::ComponentType::Executor($generator),
            file: file!(),
            line: line!(),
            module_path: module_path!(),
        }
    };
}

/// See the module level documentation for [`crate::components`] to register components.
#[macro_export]
macro_rules! plugin {
    ($id:expr, $generator:expr) => {
        $crate::components::Component {
            id: $id,
            generator: $crate::components::ComponentType::Plugin($generator),
            file: file!(),
            line: line!(),
            module_path: module_path!(),
        }
    };
}

inventory::collect!(Component);
