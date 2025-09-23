use std::borrow::Cow;
use std::fmt::Debug;

use serde::Deserialize;

/// Semantic reference (i.e. not a Rust reference) to a Component.
///
/// Contains an id and optional config to an arbitrary component. See [`crate::components`] documentation for more information.
pub trait ComponentReference {
    fn id(&self) -> &str;
    fn config(&self) -> Option<&ComponentConfig>;
}

// convenience impl for refs
impl<T: ComponentReference> ComponentReference for &T {
    fn id(&self) -> &str {
        (*self).id()
    }

    fn config(&self) -> Option<&ComponentConfig> {
        (*self).config()
    }
}

/// Ergonomic component reference in configs (serde_yaml, etc).
#[derive(Deserialize, Clone)]
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

/// Used for [`ComponentReference::config()`], just a yaml value.
#[derive(Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct ComponentConfig {
    pub config: serde_yaml::Value,
}
