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
//! Encapsulates `emulation_registry.proto` messages, services, and supporting abstractions

use std::fmt::Display;

use crate::args::EmulationArgs;
use crate::utils::{EmuMetadata, Token};
use crate::Validator;
use styx_errors::styx_grpc::ApplicationError;

tonic::include_proto!("emulation_registry");

impl StartTraceExecutionRequest {
    /// Return clone of [EmulationArgs] from the request or an error
    pub fn args(&self) -> Result<EmulationArgs, ApplicationError> {
        if let Some(args) = &self.args {
            Ok(args.clone())
        } else {
            Err(ApplicationError::MissingRequiredArgs("args".into()))
        }
    }
}

pub trait Identifier {
    fn id(&self) -> u32;
    fn name(&self) -> String;
}
macro_rules! identifier {
    ($ty: ty) => {
        impl $ty {
            pub fn new(id: u32, name: &str) -> Self {
                Self {
                    id,
                    name: name.to_string(),
                }
            }
        }

        impl Identifier for $ty {
            fn id(&self) -> u32 {
                return self.id;
            }
            fn name(&self) -> String {
                return self.name.to_string();
            }
        }
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", &self.name, &self.id)
            }
        }
    };
}

identifier!(ArchIdentity);
identifier!(VariantIdentity);
identifier!(EndianIdentity);
identifier!(LoaderIdentity);
identifier!(BackendIdentity);

impl Validator for StartTraceExecutionRequest {
    fn is_valid(&self) -> bool {
        if let Some(args) = &self.args {
            args.is_valid()
        } else {
            false
        }
    }
}

impl StartTraceExecutionResponse {
    pub fn token(&self) -> Result<Token, ApplicationError> {
        if let Some(token) = &self.token {
            Ok(*token)
        } else {
            Err(ApplicationError::MissingRequiredArgs("token".into()))
        }
    }

    pub fn emu_metadata(&self) -> Result<EmuMetadata, ApplicationError> {
        if let Some(emu_metadata) = &self.emu_metadata {
            Ok(emu_metadata.clone())
        } else {
            Err(ApplicationError::MissingRequiredArgs("emu_metadata".into()))
        }
    }
}

pub fn ident_string<T>(label: &str, item: &Option<T>) -> String
where
    T: Display,
{
    let v = match item {
        Some(v) => v.to_string(),
        _ => "None".to_string(),
    };
    format!("{label}{v}")
}

impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let props = [
            ident_string("arch:    ", &self.arch_iden),
            ident_string("variant: ", &self.variant_iden),
            ident_string("endian:  ", &self.endian_iden),
            ident_string("loader:  ", &self.loader_iden),
            ident_string("backend: ", &self.backend_iden),
        ]
        .join("    \n");

        writeln!(f, "{props}")
    }
}
impl std::fmt::Display for SupportedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cfg_str = if let Some(ref config) = self.config {
            format!("{config}").to_string()
        } else {
            "".to_string()
        };

        writeln!(f, "{}({})\n{}", self.name, self.id, cfg_str)
    }
}
