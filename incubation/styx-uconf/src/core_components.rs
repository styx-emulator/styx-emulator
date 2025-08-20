// SPDX-License-Identifier: BSD-2-Clause
//! Component registrations for items in styx-core.

use styx_core::{core::builder::DummyProcessorBuilder, prelude::*};

use crate::register_component;

register_component!(register executor: id = default, component = DefaultExecutor);

register_component!(register processor: id = dummy, component = DummyProcessorBuilder);
