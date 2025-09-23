use std::collections::HashMap;

use bytes::Bytes;
use itertools::Itertools;
use styx_core::{
    errors::UnknownError,
    prelude::{anyhow, Context},
};
use tonic::transport::{Endpoint, Uri};

use crate::config::{ProcessorId, RemoteDevice};

#[derive(Clone, Default)]
pub struct Processors {
    processors: HashMap<ProcessorId, Processor>,
}

impl Processors {
    pub fn from_config<'a>(
        configs: impl IntoIterator<Item = &'a RemoteDevice> + Clone,
    ) -> Result<Self, UnknownError> {
        // collecting into a hashmap silently drops duplicates but we want error on
        // duplicate ids so let's check for duplicates first

        // iterator over duplicate processor ids
        let mut duplicates = configs
            .clone()
            .into_iter()
            .map(|d| &d.id)
            .duplicates()
            .peekable();
        if duplicates.peek().is_some() {
            let duplicates = duplicates.collect::<Vec<_>>();

            return Err(anyhow!(
                "duplicate processor ids found: {}",
                duplicates.iter().format(", ")
            ));
        }

        // now there are no duplicates, we are good to make the map
        let configs_tuple_result = configs
            .into_iter()
            .map(|c| Processor::parse(c.endpoint.clone()).map(|e| (c.id.clone(), e)));
        let processors = configs_tuple_result
            .collect::<Result<_, UnknownError>>()
            .context("could not parse remote device configs")?;
        Ok(Processors { processors })
    }
    pub fn get_processor(&self, id: &ProcessorId) -> Option<&Processor> {
        self.processors.get(id)
    }
}

#[derive(Clone)]
pub struct Processor {
    endpoint: Uri,
}
impl Processor {
    pub(crate) fn addr(&self) -> &Uri {
        &self.endpoint
    }

    fn parse<E: core::error::Error + Send + Sync + 'static>(
        endpoint_bytes: impl TryInto<Uri, Error = E>,
    ) -> Result<Self, UnknownError> {
        let endpoint = endpoint_bytes
            .try_into()
            .with_context(|| "could not parse uri")?;
        Ok(Processor { endpoint })
    }
}
