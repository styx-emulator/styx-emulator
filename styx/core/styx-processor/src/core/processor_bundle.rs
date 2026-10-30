// SPDX-License-Identifier: BSD-2-Clause
use std::any::Any;

use styx_cpu_type::Arch;
use styx_errors::UnknownError;
use thiserror::Error;

use crate::{
    event_controller::{EventDistributorImpl, Peripheral, SingleVcpuEventDistributor},
    loader::LoaderHints,
    memory::MemoryBackend,
};

use super::{builder::VcpuBundleBuilder, VcpuBundle, VcpuId};

/// Contains the uninitialized parts needed to create a
/// [`Processor`](crate::processor::Processor).
///
/// The [`Default`] implementation contains a single dummy vCPU and empty lists
/// for peripherals and loader hints.
///
/// Use [`ProcessorBundle::builder()`] to construct a non-trvial processor.
pub struct ProcessorBundle {
    /// Physical memory.
    pub memory: MemoryBackend,
    /// Uninitialized processor-level [EventDistributorImpl] implementation.
    pub event_distributor: Box<dyn EventDistributorImpl>,
    /// Per-vCPU bundles; at least one entry is required.
    pub vcpus: Vec<VcpuBundle>,
    /// List of peripherals that will be added and initialized.
    pub peripherals: Vec<Box<dyn Peripheral>>,
    pub loader_hints: LoaderHints,
}

impl Default for ProcessorBundle {
    fn default() -> Self {
        Self {
            memory: MemoryBackend::default(),
            event_distributor: Box::new(SingleVcpuEventDistributor::default()),
            vcpus: vec![VcpuBundle::default()],
            peripherals: Default::default(),
            loader_hints: Default::default(),
        }
    }
}

impl ProcessorBundle {
    /// Start building a [`ProcessorBundle`].
    ///
    /// See [`ProcessorBundleBuilder`] for the full API. Thisbuilder fills
    /// sensible defaults for every field except the vCPU, which must be
    /// configured explicitly via [`ProcessorBundleBuilder::with_vcpu()`] or
    /// [`ProcessorBundleBuilder::add_vcpu()`].
    ///
    /// # Example
    ///
    /// ```
    /// # use styx_processor::core::{ProcessorBundle};
    /// # use styx_processor::core::builder::{BuildProcessorImplArgs, ProcessorImpl};
    /// # use styx_processor::cpu::DummyBackend;
    /// # use styx_cpu_type::{Arch, Backend};
    /// # use styx_errors::UnknownError;
    /// struct MyProcessor;
    /// impl ProcessorImpl for MyProcessor {
    ///     fn build(&self, _args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
    ///         Ok(ProcessorBundle::builder()
    ///             .with_vcpu(|v| v.with_cpu(DummyBackend))
    ///             .with_arch_hint(Arch::Arm)
    ///             .build()?)
    ///     }
    /// }
    /// ```
    pub fn builder() -> ProcessorBundleBuilder {
        ProcessorBundleBuilder::default()
    }
}

/// Errors produced while finalizing a [`ProcessorBundleBuilder`].
#[derive(Debug, Error)]
pub enum ProcessorBundleBuilderError {
    #[error("at least one vCPU must be configured")]
    NoVcpus,
    #[error(transparent)]
    Unknown(#[from] UnknownError),
}

/// Build a [`ProcessorBundle`].
///
/// Starts with a [`MemoryBackend::new_flat()`], a [`SingleVcpuEventDistributor`],
/// empty peripheral and loader-hint collections, and no vCPUs.
pub struct ProcessorBundleBuilder {
    memory: MemoryBackend,
    event_distributor: Box<dyn EventDistributorImpl>,
    vcpus: Vec<VcpuBundle>,
    peripherals: Vec<Box<dyn Peripheral>>,
    loader_hints: LoaderHints,
}

impl Default for ProcessorBundleBuilder {
    fn default() -> Self {
        Self {
            memory: MemoryBackend::new_flat(),
            event_distributor: Box::new(SingleVcpuEventDistributor::default()),
            vcpus: Vec::new(),
            peripherals: Vec::new(),
            loader_hints: LoaderHints::new(),
        }
    }
}

impl ProcessorBundleBuilder {
    /// Equivalent to [`Self::default`] and [`ProcessorBundle::builder`].
    pub fn new() -> Self {
        Self::default()
    }

    // --- memory ---

    /// Replace the [`MemoryBackend`].
    pub fn with_memory(mut self, memory: MemoryBackend) -> Self {
        self.memory = memory;
        self
    }

    /// Mutate the current [`MemoryBackend`] in place via a closure.
    ///
    /// Most processors want to map regions during build. This lets you do it
    /// without moving ownership out of the builder. The closure may return an
    /// error which will be propagated.
    pub fn modify_memory(
        mut self,
        f: impl FnOnce(&mut MemoryBackend) -> Result<(), UnknownError>,
    ) -> Result<Self, UnknownError> {
        f(&mut self.memory)?;
        Ok(self)
    }

    // --- event distributor ---

    /// Replace the processor-level [`EventDistributorImpl`].
    pub fn with_event_distributor(
        mut self,
        event_controller: impl EventDistributorImpl + 'static,
    ) -> Self {
        self.event_distributor = Box::new(event_controller);
        self
    }

    /// See [`Self::with_event_distributor()`] but accepts an already-boxed impl.
    pub fn with_event_distributor_box(
        mut self,
        event_controller: Box<dyn EventDistributorImpl>,
    ) -> Self {
        self.event_distributor = event_controller;
        self
    }

    // --- vCPUs ---

    /// Append a vCPU configured by the given closure.
    ///
    /// This is the preferred way to add vCPUs. It starts from a default
    /// [`VcpuBundleBuilder`] (dummies for every field) and lets you override
    /// only what you need.
    ///
    /// ```
    /// # use styx_processor::core::ProcessorBundle;
    /// # use styx_processor::cpu::DummyBackend;
    /// let _bundle = ProcessorBundle::builder()
    ///     .with_vcpu(|v| v.with_cpu(DummyBackend))
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn with_vcpu(mut self, f: impl FnOnce(VcpuBundleBuilder) -> VcpuBundleBuilder) -> Self {
        self.vcpus.push(f(VcpuBundleBuilder::default()).build());
        self
    }

    /// Append a pre-built [`VcpuBundle`].
    ///
    /// Use this when you already have a bundle constructed elsewhere, prefer
    /// [`Self::with_vcpu`] otherwise.
    pub fn add_vcpu(mut self, vcpu: impl Into<VcpuBundle>) -> Self {
        self.vcpus.push(vcpu.into());
        self
    }

    /// Append `n` vCPUs configured by a single closure.
    ///
    /// This is the preferred way to add vCPUs. It starts from a default
    /// [`VcpuBundleBuilder`] (dummies for every field) and lets you override
    /// only what you need.
    ///
    /// ```
    /// # use styx_processor::core::ProcessorBundle;
    /// # use styx_processor::cpu::DummyBackend;
    /// let _bundle = ProcessorBundle::builder()
    ///     .with_vcpus(4, |_i, v| v.with_cpu(DummyBackend))
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn with_vcpus(
        mut self,
        n: VcpuId,
        mut f: impl FnMut(VcpuId, VcpuBundleBuilder) -> VcpuBundleBuilder,
    ) -> Self {
        for i in 0..n {
            self.vcpus.push(f(i, VcpuBundleBuilder::default()).build());
        }
        self
    }

    // --- peripherals ---

    /// Append a [`Peripheral`].
    pub fn add_peripheral(mut self, peripheral: impl Peripheral + 'static) -> Self {
        self.peripherals.push(Box::new(peripheral));
        self
    }

    /// See [`Self::add_peripheral`] but accepts an already-boxed peripheral.
    pub fn add_peripheral_box(mut self, peripheral: Box<dyn Peripheral>) -> Self {
        self.peripherals.push(peripheral);
        self
    }

    // --- loader hints ---

    /// Replace the [`LoaderHints`] map.
    pub fn with_loader_hints(mut self, hints: LoaderHints) -> Self {
        self.loader_hints = hints;
        self
    }

    /// Insert a single loader hint, converting the key and boxing the value.
    ///
    /// Avoids the `key.to_string().into_boxed_str()` + `Box::new(value)`
    /// boilerplate.
    pub fn add_loader_hint<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<Box<str>>,
        V: Any + 'static,
    {
        self.loader_hints.insert(key.into(), Box::new(value));
        self
    }

    /// Insert the ubiquitous `"arch"` loader hint. Shortcut for
    /// `add_loader_hint("arch", arch)`.
    pub fn with_arch_hint(self, arch: Arch) -> Self {
        self.add_loader_hint("arch", arch)
    }

    // --- terminal ---

    /// Finalize into a [`ProcessorBundle`].
    ///
    /// Can error if the supplied args are not correct. Currently the only way
    /// for this to happen is if no vcpus are provided.
    pub fn build(self) -> Result<ProcessorBundle, ProcessorBundleBuilderError> {
        if self.vcpus.is_empty() {
            return Err(ProcessorBundleBuilderError::NoVcpus);
        }
        Ok(ProcessorBundle {
            memory: self.memory,
            event_distributor: self.event_distributor,
            vcpus: self.vcpus,
            peripherals: self.peripherals,
            loader_hints: self.loader_hints,
        })
    }
}

#[cfg(test)]
mod tests {
    use as_any::AsAny;

    use crate::cpu::DummyBackend;

    use super::*;

    #[test]
    fn builder_requires_at_least_one_vcpu() {
        match ProcessorBundle::builder().build() {
            Err(ProcessorBundleBuilderError::NoVcpus) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("build() must reject empty vcpus"),
        }
    }

    #[test]
    fn with_vcpu_closure_appends_configured_bundle() {
        let bundle = ProcessorBundle::builder()
            .with_vcpu(|v| v.with_cpu(DummyBackend))
            .build()
            .expect("single-vcpu build should succeed");
        assert_eq!(bundle.vcpus.len(), 1);
    }

    #[test]
    fn add_vcpu_accepts_prebuilt_and_builder() {
        let bundle = ProcessorBundle::builder()
            .add_vcpu(VcpuBundle::default())
            .add_vcpu(VcpuBundle::builder().with_cpu(DummyBackend))
            .build()
            .expect("multi-vcpu build should succeed");
        assert_eq!(bundle.vcpus.len(), 2);
    }

    #[test]
    fn with_arch_hint_inserts_arch_key() {
        let bundle = ProcessorBundle::builder()
            .with_vcpu(|v| v.with_cpu(DummyBackend))
            .with_arch_hint(Arch::Arm)
            .build()
            .unwrap();
        let arch = bundle
            .loader_hints
            .get("arch")
            .expect("arch hint should be set")
            .downcast_ref::<Arch>()
            .expect("arch hint should be typed Arch");
        assert_eq!(*arch, Arch::Arm);
    }

    #[test]
    fn modify_memory_propagates_errors() {
        let result = ProcessorBundle::builder().modify_memory(|_| Err(UnknownError::msg("boom")));
        assert!(result.is_err());
    }

    #[test]
    fn add_peripheral_box_accepts_preboxed() {
        // Compilation-only check: ensure the signature accepts a trait object.
        fn _assert_add_peripheral_box(
            builder: ProcessorBundleBuilder,
            p: Box<dyn Peripheral>,
        ) -> ProcessorBundleBuilder {
            builder.add_peripheral_box(p)
        }
    }

    /// Asserts default values of the processor bundle.
    ///
    /// These can change, but this is a significant api change.
    /// If the defaults change and this test needs to be updated then
    /// be sure to check the processors that depend on these defaults.
    #[test]
    fn processor_bundle_defaults() {
        let bundle = ProcessorBundle::builder();

        // Memory backend configuration
        let memory_range = bundle.memory.valid_memory_range().von_neuman().unwrap();
        assert_eq!(memory_range.start, 0);
        assert_eq!(memory_range.end, u32::MAX as u64);

        // Event Distributor
        assert_eq!(
            bundle.event_distributor.as_ref().type_id(),
            SingleVcpuEventDistributor::default().as_any().type_id()
        );

        // vcpus
        assert_eq!(bundle.vcpus.len(), 0);
    }
}
