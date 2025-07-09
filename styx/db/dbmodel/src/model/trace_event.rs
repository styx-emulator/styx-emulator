// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use sea_orm::entity::prelude::*;
use sea_orm::Set;
use styx_core::tracebus::{Traceable, TraceableItem};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Default, Eq, serde::Serialize, serde::Deserialize,
)]
#[sea_orm(table_name = "trace_event")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    //BinaryTraceEventType
    pub event: Vec<u8>,
}

impl Model {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModel {
    pub fn new(item: TraceableItem) -> Self {
        Self {
            id: Set(Uuid::new_v4()),
            event: Set(Into::<Vec<u8>>::into(item.binary())),
        }
    }
}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::TryIntoModel;
    use styx_core::tracebus::{MemReadEvent, TRACE_EVENT_SIZE};
    #[allow(unused_imports)]
    use tracing::{debug, error, info, trace};
    pub type TestResult = Result<(), Box<dyn std::error::Error + 'static>>;

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_model_from_message() -> TestResult {
        styx_core::util::logging::init_logging();
        let event = MemReadEvent::new();
        let am = ActiveModel::new(event.into());
        let id = am.clone().id.unwrap();
        let event_bin = am.clone().event.unwrap();
        assert_eq!(event_bin.len(), TRACE_EVENT_SIZE);
        let model = am.try_into_model().unwrap();
        assert_eq!(model.id, id);
        assert_eq!(model.event, event_bin);
        Ok(())
    }
}
