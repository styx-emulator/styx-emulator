use super::*;
use styx_cpu_type::{arch::backends::ArchVariant, ArchEndian, Backend};

/// Architecture of processor.
pub struct ArchConfig(pub ArchVariant);
impl ProcessorConfig for ArchConfig {}

/// Architecture of processor.
pub struct ConfigEndian(pub ArchEndian);
impl ProcessorConfig for ConfigEndian {}

/// CPU backend preference.
pub struct ConfigBackend(pub Backend);
impl ProcessorConfig for ConfigBackend {}
