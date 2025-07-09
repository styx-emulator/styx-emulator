// SPDX-License-Identifier: BSD-2-Clause
use thiserror::Error;
use unicorn_engine::uc_error;

/// ffi [uc_error] wrapper, guaranteed to be an error variant i.e. will never be [uc_error::OK].
#[derive(Debug, Error)]
#[error("unicorn error of type `{0:?}`")]
pub struct UcErr(uc_error);

impl UcErr {
    pub fn from_unicorn(error: uc_error) -> Result<(), UcErr> {
        match error {
            uc_error::OK => Ok(()),
            other => Err(UcErr(other)),
        }
    }

    pub fn from_unicorn_trn<T>(error: uc_error, value: T) -> Result<T, UcErr> {
        match error {
            uc_error::OK => Ok(value),
            other => Err(UcErr(other)),
        }
    }

    pub fn from_unicorn_result<T>(error: Result<T, uc_error>) -> Result<T, UcErr> {
        if let Err(error_from_uc) = error {
            debug_assert_ne!(
                error_from_uc,
                uc_error::OK,
                "error variant of uc_error result is OK"
            );
        }
        error.map_err(UcErr)
    }
}
