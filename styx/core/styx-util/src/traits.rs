// SPDX-License-Identifier: BSD-2-Clause
//! Common/useful traits

pub trait HasUrl {
    fn url(&self) -> String;
}
