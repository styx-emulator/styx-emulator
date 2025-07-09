// SPDX-License-Identifier: BSD-2-Clause

//! Grpc error helpers

use thiserror::Error;
use tonic::Status;

/// End-to-end application errors, used by styx console apps and tui's
/// to return meaningful errors
/// to the uses of the end-to-end application.
#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("Error parsing arguments `{0}`")]
    ArgParseError(String),
    #[error("Unsupported Architecture Configuration: `{0}`")]
    ConfigNotSupported(String),
    #[error("Error calling service: `{0}`, error: `{1}`")]
    ConnectToServiceError(String, String),
    #[error("Database connection error to: `{0}`:  `{1}`")]
    DbConnectError(String, String),
    #[error("Database query error: `{0}`, `{1}`")]
    DbQueryError(&'static str, String),
    #[error("Feature not supported: `{0}`")]
    FeatureNotSupported(String),
    #[error("Error connecting to service: `{0}`")]
    GrpcConnectError(&'static str, String),
    #[error("Initialize emulation service failed `{0}`")]
    InitializeEmulationServiceFailed(String),
    #[error("The `{0}` parameters are not valid")]
    InvalidArgs(String),
    #[error("The `{0}` request did not pass the validator")]
    InvalidRequest(String),
    #[error("Expected data which is not present `{0}`")]
    MissingData(String),
    #[error("Missing required environment variable `{0}`: `{1}`")]
    MissingEnvironmentVar(String, std::env::VarError),
    #[error("Missing required field(s) `{0}`")]
    MissingRequiredArgs(String),
    #[error("An I/O error occurred during the operation. `{0}`")]
    StdIOError(String),
}

/// Get a value for the environement variable or return an [ApplicationError]
pub fn env_or_error(varname: &str) -> Result<String, ApplicationError> {
    match std::env::var(varname) {
        Ok(v) => Ok(v),
        Err(e) => Err(ApplicationError::MissingEnvironmentVar(varname.into(), e)),
    }
}

/// Convert an [`ApplicationError`] to a [`Status`]
impl From<ApplicationError> for Status {
    fn from(value: ApplicationError) -> Self {
        Status::new(tonic::Code::Unknown, format!("{:?}", value))
    }
}

impl From<std::io::Error> for ApplicationError {
    fn from(value: std::io::Error) -> Self {
        ApplicationError::StdIOError(value.to_string())
    }
}

impl From<tonic::transport::Error> for ApplicationError {
    fn from(value: tonic::transport::Error) -> Self {
        ApplicationError::InitializeEmulationServiceFailed(format!(
            "Could not start the service: {}",
            value
        ))
    }
}

/// Convert an [ApplicationError] to a [std::io::Error]
impl From<ApplicationError> for std::io::Error {
    fn from(value: ApplicationError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, value.to_string())
    }
}
