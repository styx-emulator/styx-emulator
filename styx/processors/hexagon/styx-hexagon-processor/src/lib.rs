// SPDX-License-Identifier: BSD-2-Clause
//! # Styx-Processors

#[derive(serde::Deserialize)]
pub struct HexagonBuilder {
    pub variant: HexagonVariants,
}

impl Default for HexagonBuilder {
    fn default() -> Self {
        Self {
            variant: HexagonVariant::QDSP6V62,
        }
    }
}

impl ProcessorImpl for BlackfinBuilder {}
