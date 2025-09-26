// SPDX-License-Identifier: BSD-2-Clause
pub mod core_configs;

use std::{any::TypeId, collections::HashMap};

use as_any::{AsAny, Downcast};

pub trait ProcessorConfig: Send + Sync + AsAny + 'static {}

#[derive(Hash, Clone, Copy, PartialEq, Eq)]
struct ConfigId(TypeId);

impl ConfigId {
    fn new<T: 'static>() -> Self {
        Self(TypeId::of::<T>())
    }
}

#[derive(Default)]
pub struct Config {
    configs: HashMap<ConfigId, Box<dyn ProcessorConfig>>,
}

impl Config {
    pub(crate) fn add_config<C: ProcessorConfig>(&mut self, config: C) {
        let config = Box::new(config);
        let config_id = ConfigId::new::<C>();
        self.configs.insert(config_id, config);
    }

    pub fn get_config<C: ProcessorConfig>(&self) -> Option<&C> {
        let config_id = ConfigId::new::<C>();
        let config = self.configs.get(&config_id)?;
        Some(config.as_ref().downcast_ref::<C>().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConfig {
        a: String,
        b: u32,
    }
    impl ProcessorConfig for TestConfig {}
    #[test]
    fn test_name() {
        let mut config = Config::default();
        config.add_config(TestConfig {
            a: "hello".to_owned(),
            b: 0x1337,
        });

        let get = config.get_config::<TestConfig>().unwrap();
        assert_eq!(&get.a, "hello");
        assert_eq!(get.b, 0x1337);
    }
}
