// SPDX-License-Identifier: BSD-2-Clause
//! App configuration

use confique::Config;
use serde_derive::Serialize;
use std::path::PathBuf;

#[derive(Config, Serialize)]
pub struct AppConfig {
    #[config(env = "TYPHUNIX_URL")]
    server_uri: Option<String>,

    #[config(env = "TYPHUNIX_HOME")]
    config_dir: Option<String>,

    #[config(nested)]
    pub log: LogConf,
}

#[derive(Config, Serialize)]
pub struct LogConf {
    #[config(default = "info")]
    pub level: String,

    #[config(default = true)]
    pub stdout: bool,

    /// log file path
    pub file: Option<PathBuf>,
}

fn _edit_example() {
    let mut value: serde_yaml::Value = serde_yaml::from_str(_TEST_EXAMPLE).unwrap();
    *value
        .get_mut("apps")
        .unwrap()
        .get_mut("datadog")
        .unwrap()
        .get_mut("version")
        .unwrap() = "1.38.8".into();
    serde_yaml::to_writer(std::io::stdout(), &value).unwrap();
}

/// The name of the environment variable for the typhunix server url
pub const TYPHUNIX_URL_ENV_NAME: &str = "TYPHUNIX_URL";

/// The default URL where the typhunix server is running, if one is not
/// provided by command-line option or environnt. See [TYPHUNIX_URL_ENV_NAME]
pub const DEFAULT_TYPHUNIX_URL: &str = "http://127.0.0.1:50051";

/// Returns the value of the environment variable, or if not set,
/// returns the provided defauilt value.
fn environ(name: String, default_value: &str) -> String {
    if let Ok(value) = std::env::var(name) {
        value
    } else {
        default_value.to_string()
    }
}

/// Return `(server, port)` tuple for the typhunix server and port
/// Return an error String this is not working out for whatever reason
pub fn server_host_port(default_url: &str) -> Result<(String, u16), String> {
    let url = environ(TYPHUNIX_URL_ENV_NAME.into(), default_url);
    match url::Url::parse(&url) {
        Ok(url) => {
            if let Some(port) = url.port() {
                if let Some(host) = url.host() {
                    return Ok((host.to_string(), port));
                }
            }
            Err("Cannot detarmine host and/or port".to_string())
        }
        Err(e) => Err(format!("{e}")),
    }
}

impl AppConfig {
    pub fn server_uri() -> String {
        let home = std::env::var("HOME").ok();

        let mut builder = AppConfig::builder().env();

        if home.is_some() {
            let file = format!("{}/typhunix-conf.yaml", home.unwrap());
            builder = builder.file(file);
        }

        match builder.load() {
            Ok(cfg) => {
                if let Some(server_uri) = cfg.server_uri {
                    server_uri
                } else {
                    DEFAULT_TYPHUNIX_URL.to_string()
                }
            }

            Err(e) => {
                eprintln!("{e}");
                DEFAULT_TYPHUNIX_URL.to_string()
            }
        }
    }

    pub fn config_dir() -> String {
        match std::env::var("TYPHUNIX_HOME") {
            Ok(v) => v,
            Err(_) => match std::env::var("HOME") {
                Ok(v) => format!("{v}/.typhunix"),
                Err(_) => ".typhunix".to_string(),
            },
        }
    }
}

const _TEST_EXAMPLE: &str = r#"
# Typhunix config
server: 127.0.0.1
port: 1234

# Log configuration
log:
  level: info
  stdout: true # Write to stdout?
  file: /tmp/file.log
"#;
