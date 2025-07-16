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
//! logging / tracing utilities

use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry;
use tracing_subscriber::EnvFilter;

/// Initialize logging. Usefill for stand-alone executables that need basic logging.
/// The function is tolerant if logging has already been initialized.
/// # panics
/// if logging cannot be initialized
pub fn init_logging() {
    match tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_level(true)
                .with_target(true)
                .without_time()
                .compact()
                .with_filter(
                    EnvFilter::try_from_default_env()
                        .or_else(|_| EnvFilter::try_new("info"))
                        .unwrap(),
                ),
        )
        .try_init()
    {
        Ok(_) => (),
        Err(e) => {
            const ACCEPTABLE_ERRORS: &[&str; 1] =
                &["a global default trace dispatcher has already been set"];
            if !ACCEPTABLE_ERRORS
                .iter()
                .any(|error_msg| e.to_string().eq(*error_msg))
            {
                panic!("Cannot initialize logging: {e}");
            }
        }
    };
}

pub struct NonBlockingAppender;

impl std::io::Write for NonBlockingAppender {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buf_len = buf.len();
        println!("{buf:?}");
        Ok(buf_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Initialize the [Registry](tracing_subscriber::Registry) with a
/// file [RollingFileAppender](tracing_appender::rolling::RollingFileAppender)
/// that [never](tracing_appender::rolling::never) rolls over.
///
/// Use `dirname` and `filename` as inputs to [never](tracing_appender::rolling::never)
/// Parse the given trace directives.
pub fn init_file_logger(dirname: &str, filename: &str, directives: &str) {
    let log_file_filter = EnvFilter::builder().parse_lossy(directives);
    let file_appender = tracing_appender::rolling::never(dirname, filename);
    match registry()
        // console output
        .with(
            tracing_subscriber::fmt::layer()
                .with_level(true)
                .with_target(true)
                .without_time()
                .compact()
                .with_filter(
                    EnvFilter::try_from_default_env()
                        .or_else(|_| EnvFilter::try_new("error"))
                        .unwrap(),
                ),
        )
        // logfile output
        .with(
            fmt::layer()
                .with_line_number(true)
                .with_file(true)
                .with_ansi(false)
                .with_writer(file_appender)
                .with_filter(log_file_filter),
        )
        .try_init()
    {
        Ok(_) => (),
        Err(e) => {
            const ACCEPTABLE_ERRORS: &[&str; 1] =
                &["a global default trace dispatcher has already been set"];
            if !ACCEPTABLE_ERRORS
                .iter()
                .any(|error_msg| e.to_string().eq(*error_msg))
            {
                panic!("Cannot initialize logging: {e}");
            }
        }
    };
}

/// create a service log using [init_file_logger](fn@init_file_logger).
pub struct ServiceLog {
    name: String,
    dir: String,
    directives: Vec<String>,
    has_timestamp: bool,
}

impl ServiceLog {
    pub fn new(name: impl ToString) -> Self {
        Self {
            name: name.to_string(),
            dir: std::env::var("TRACE_WEBAPP_LOGDIR").unwrap_or("/tmp".to_string()),
            directives: ["debug", "tower=warn", "h2=warn", "hyper=warn"]
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<String>>(),
            has_timestamp: false,
        }
    }

    pub fn with_name(self, name: impl ToString) -> Self {
        Self {
            name: name.to_string(),
            ..self
        }
    }
    pub fn with_dir(self, dir: impl ToString) -> Self {
        Self {
            dir: dir.to_string(),
            ..self
        }
    }
    pub fn with_directives(self, directives: &[&str]) -> Self {
        Self {
            directives: directives.iter().map(|d| d.to_string()).collect(),
            ..self
        }
    }

    pub fn with_timestamp(self, has_timestamp: bool) -> Self {
        Self {
            has_timestamp,
            ..self
        }
    }

    /// Add the layer to the registry
    pub fn create(&self) {
        let mut idx = 0;
        let filename = if self.has_timestamp {
            loop {
                let filename = format!(
                    "{}-{}-{}.log",
                    self.name,
                    crate::dtutil::UtcDateTime::new()
                        .to_string()
                        .replace(':', ""),
                    idx
                );
                let full_path = format!("{}/{filename}", self.dir);
                if !std::path::Path::new(&full_path).exists() {
                    break filename;
                }
                idx += 1;
            }
        } else {
            format!("{}.log", self.name)
        };

        init_file_logger(&self.dir, &filename, &self.directives.join(","));
    }
}
