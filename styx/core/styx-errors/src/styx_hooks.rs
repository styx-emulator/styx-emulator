// SPDX-License-Identifier: BSD-2-Clause
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StyxHookError {
    #[error("Hook add error.")]
    HookAddError,
    #[error("Failed to remove hook.")]
    HookRemoveError,
    #[error("HookToken is uninitialized, inner is null pointer.")]
    NullTokenError,
    #[error(
        "HookToken is incorrect type, tokens can only be used with the backend that gave them."
    )]
    WrongType,
}
