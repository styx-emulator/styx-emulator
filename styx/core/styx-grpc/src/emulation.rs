// SPDX-License-Identifier: BSD-2-Clause
//! Encapsulates `emulation.proto` messages, services, and supporting abstractions

tonic::include_proto!("emulation");
impl StartSingleEmulationResponse {
    pub fn ok_or_warn(&self) -> bool {
        let result = self.response_status.clone();
        if let Some(result) = result {
            match result.result() {
                crate::utils::response_status::Result::Ok
                | crate::utils::response_status::Result::Warn => true,
                crate::utils::response_status::Result::Err => false,
            }
        } else {
            false
        }
    }
}
