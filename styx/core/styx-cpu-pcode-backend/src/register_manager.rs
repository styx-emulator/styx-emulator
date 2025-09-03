// SPDX-License-Identifier: BSD-2-Clause
use super::memory::sized_value::SizedValue;
use crate::arch_spec::HexagonPcodeBackend;
use crate::memory::space_manager::{HasSpaceManager, SpaceManager};
use crate::pcode_gen::{GhidraPcodeGenerator, HasPcodeGenerator, RegisterTranslator};
use crate::PcodeBackend;
use log::trace;
use std::collections::HashMap;
use std::fmt::Debug;
use styx_cpu_type::arch::backends::ArchRegister;
use styx_errors::anyhow::Context;
use styx_errors::UnknownError;
use styx_processor::cpu::CpuBackend;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("failed to handle register")]
pub enum RegisterHandleError {
    #[error("cannot handle register {0}")]
    CannotHandleRegister(ArchRegister),
    #[allow(unused)]
    #[error(transparent)]
    Other(#[from] UnknownError),
    #[error("\
        register {register:?} has mismatched sizes with register handler: styx:{styx_size} vs register handler:{actual_size}\n\
        the simplest solution is to implement a register handler for {register:?} that returns the correct size\n\
        if this register already has a custom register handler then it returned the wrong size and must be fixed\n\
        alternatively, if this is a custom sla spec then modify the register definition to match the styx size of {styx_size} bytes")]
    ReadMismatchedSize {
        styx_size: usize,
        actual_size: usize,
        register: ArchRegister,
    },
    #[error("\
        register {register:?} has mismatched sizes with default register handler: styx:{styx_size} vs default handler:{actual_size}\n\
        the simplest solution is to implement a custom register handler for {register:?} that handles writes of the correct size\n\
        alternatively, if this is a custom sla spec then modify the register definition to match the styx size of {styx_size} bytes")]
    WriteMismatchedSize {
        styx_size: usize,
        actual_size: usize,
        register: ArchRegister,
    },
}

/// Convenience new type for a Arc'd [RegisterCallback].
#[derive(Debug)]
pub struct RegisterHandler<T: CpuBackend>(pub Box<dyn RegisterCallback<T>>);

impl<T: RegisterCallback<PcodeBackend> + 'static> From<T> for RegisterHandler<PcodeBackend> {
    fn from(value: T) -> Self {
        RegisterHandler(Box::new(value))
    }
}

impl<T: RegisterCallback<HexagonPcodeBackend> + 'static> From<T>
    for RegisterHandler<HexagonPcodeBackend>
{
    fn from(value: T) -> Self {
        RegisterHandler(Box::new(value))
    }
}

pub trait RegisterCallback<T: CpuBackend>: Debug + Send + Sync {
    /// Given a styx [ArchRegister], read the value with correct size.
    ///
    /// The default behavior for reading register is defined in [`default_register_read()`] and
    /// reads from the register space using the varnode given by the
    /// [PcodeBackend::pcode_generator]. Custom handler can read from the space memories by
    /// following the default register read code, or they can store values by other means.
    ///
    /// The [`RegisterManager::read_register()`] function will check the returned [`SizedValue`] and
    /// assert that the size ([`SizedValue::size`]) matches the expected size of `register`.
    /// Otherwise a fatal error will be propagated.
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError>;

    /// Given a styx [ArchRegister], read the value with correct size.
    ///
    /// The default behavior for reading register is defined in [`default_register_read()`] and
    /// reads from the register space using the varnode given by the
    /// [PcodeBackend::pcode_generator]. Custom handler can read from the space memories by
    /// following the default register read code, or they can store values by other means.
    ///
    /// The [`RegisterManager::read_register()`] function will check the returned [`SizedValue`] and
    /// assert that the size ([`SizedValue::size`]) matches the expected size of `register`.
    /// Otherwise a fatal error will be propagated.
    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError>;
}

/// Handler store for [RegisterManager]s that can read/write.
///
/// There is a fallback handler that is used when a specific handler has not be added for a queried
/// register.
///
/// Handles can be triggered but not added or deleted.
#[derive(Debug)]
pub(crate) struct RegisterManager<T: CpuBackend> {
    handlers: HashMap<ArchRegister, RegisterHandler<T>>,
}

impl<T: CpuBackend> Default for RegisterManager<T> {
    fn default() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }
}

pub(crate) trait HasRegisterManager {
    type InnerCpuBackend: CpuBackend;
    fn register_manager(&mut self) -> &mut RegisterManager<Self::InnerCpuBackend>;
}

impl HasRegisterManager for PcodeBackend {
    type InnerCpuBackend = PcodeBackend;
    fn register_manager(&mut self) -> &mut RegisterManager<Self::InnerCpuBackend> {
        &mut self.register_manager
    }
}

impl<T: CpuBackend> RegisterManager<T> {
    /// Used by the Styx api to read a register from the manager, fallible.
    ///
    /// First, the manager is searched for custom register handlers. The custom handler is used to
    /// read (see [`RegisterCallback::read()`] for pre/post conditions) the register.
    ///
    /// Otherwise the [`default_register_read()`] is used.
    ///
    /// In either case, the resulting [`SizedValue`] is checked for size consistency and will return
    /// a RegisterHandleError::ReadMismatchedSize otherwise.
    pub(crate) fn read_register(
        cpu: &mut dyn RegisterCallbackCpu<T>,
        register: ArchRegister,
    ) -> Result<SizedValue, RegisterHandleError> {
        // Try to handle with added handler
        let first_handler = cpu.register_manager().handlers.remove(&register);
        let res = match first_handler {
            Some(mut first_handler) => {
                let res = first_handler.0.read(register, cpu);
                cpu.register_manager()
                    .handlers
                    .insert(register, first_handler);
                res
            }
            None => {
                let (spc, gen) = cpu.borrow_space_gen();
                default_register_read(register, spc, gen)
            }
        };
        let res = res?;

        // ensure the read sized value matches the `register` size
        let styx_reg_size = register.register_value_enum().to_byte_size();
        let rtn_reg_size = res.size() as usize;
        if rtn_reg_size != styx_reg_size {
            Err(RegisterHandleError::ReadMismatchedSize {
                styx_size: styx_reg_size,
                actual_size: rtn_reg_size,
                register,
            })
        } else {
            Ok(res)
        }
    }

    /// Used by the Styx api to write a register to the manager, fallible.
    ///
    /// First, the manager is searched for custom register handlers. The custom handler is used to
    /// read (see [`RegisterCallback::write()`] for pre/post conditions) the register.
    ///
    /// Otherwise the [`default_register_write()`] is used.
    ///
    /// The resulting [`SizedValue`] is only checked for size consistency by the
    /// [`default_register_write()`]. Otherwise, it is the custom register handler's job to ensure
    /// the register is correctly stored.
    pub(crate) fn write_register(
        cpu: &mut dyn RegisterCallbackCpu<T>,
        register: ArchRegister,
        value: SizedValue,
    ) -> Result<(), RegisterHandleError> {
        trace!("Triggering write_register index {register}.",);

        // Try to handle with added handler
        let first_handler = cpu.register_manager().handlers.remove(&register);
        let first_result = match first_handler {
            Some(mut first_handler) => {
                let res = first_handler.0.write(register, value, cpu);
                cpu.register_manager()
                    .handlers
                    .insert(register, first_handler);
                res
            }
            None => Err(RegisterHandleError::CannotHandleRegister(register)),
        };

        // Try again with default handler
        match first_result {
            // Already handled! pass on value
            Ok(value) => Ok(value),
            // Not found... try again with default handler
            Err(err) => match err {
                RegisterHandleError::CannotHandleRegister(_) => {
                    let (spc, gen) = cpu.borrow_space_gen();
                    default_register_write(register, value, spc, gen)
                }
                _ => Err(err),
            },
        }
    }

    pub fn add_handler(
        &mut self,
        register: impl Into<ArchRegister>,
        callback: impl Into<RegisterHandler<T>>,
    ) -> Result<(), AddRegisterHandlerError> {
        let index = register.into();
        match self.handlers.get(&index) {
            Some(_) => return Err(AddRegisterHandlerError::RegisterAlreadyExists(index)),
            None => {
                let handler = callback.into();
                self.handlers.insert(index, handler);
            }
        };

        Ok(())
    }

    #[allow(unused)]
    pub fn registers(
        &self,
    ) -> std::collections::hash_map::Keys<'_, ArchRegister, RegisterHandler<T>> {
        self.handlers.keys()
    }
}

#[derive(Error, Debug)]
pub enum AddRegisterHandlerError {
    #[error("handler already exists for register {0}")]
    RegisterAlreadyExists(ArchRegister),
}

fn default_register_read(
    register: ArchRegister,
    space_manager: &mut SpaceManager,
    pcode_generator: &mut impl RegisterTranslator,
) -> Result<SizedValue, RegisterHandleError> {
    let varnode_result = pcode_generator.get_register(&register);
    match varnode_result {
        Some(varnode) => Ok(space_manager
            .read(varnode)
            .with_context(|| format!("error reading {register:?} @ {varnode:?} from space"))?),
        None => Err(RegisterHandleError::CannotHandleRegister(register)),
    }
}

fn default_register_write(
    register: ArchRegister,
    value: SizedValue,
    space_manager: &mut SpaceManager,
    pcode_generator: &mut impl RegisterTranslator,
) -> Result<(), RegisterHandleError> {
    let varnode = pcode_generator
        .get_register(&register)
        .ok_or(RegisterHandleError::CannotHandleRegister(register))?;

    let styx_reg_size = register.register_value_enum().to_byte_size();
    let rtn_reg_size = varnode.size as usize;
    if rtn_reg_size != styx_reg_size {
        Err(RegisterHandleError::WriteMismatchedSize {
            styx_size: styx_reg_size,
            actual_size: rtn_reg_size,
            register,
        })
    } else {
        space_manager
            .write(varnode, value)
            .with_context(|| format!("error writing {register:?} @ {varnode:?} to space"))?;
        Ok(())
    }
}

/// [RegisterCallback] to alias to an existing register. Passes read/writes to the mapped register.
#[derive(Debug)]
pub struct MappedRegister {
    upstream: ArchRegister,
}

impl MappedRegister {
    /// Reads and writes are passed to the `upstream` register.
    pub fn new(upstream: impl Into<ArchRegister>) -> Self {
        Self {
            upstream: upstream.into(),
        }
    }
}

pub(crate) trait RegisterCallbackCpu<T: CpuBackend>:
    CpuBackend
    + HasSpaceManager
    + HasPcodeGenerator<InnerCpuBackend = T>
    + HasRegisterManager<InnerCpuBackend = T>
{
    fn borrow_space_gen(&mut self) -> (&mut SpaceManager, &mut GhidraPcodeGenerator<T>);
}

impl RegisterCallbackCpu<PcodeBackend> for PcodeBackend {
    fn borrow_space_gen(&mut self) -> (&mut SpaceManager, &mut GhidraPcodeGenerator<PcodeBackend>) {
        (&mut self.space_manager, &mut self.pcode_generator)
    }
}

impl<T: CpuBackend> RegisterCallback<T> for MappedRegister {
    fn read(
        &mut self,
        _register: ArchRegister,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        RegisterManager::read_register(cpu, self.upstream)
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        {
            let register = self.upstream;
            trace!("Triggering write_register index {register}.",);

            // Try to handle with added handler
            let first_handler = cpu.register_manager().handlers.remove(&register);
            let first_result = match first_handler {
                Some(mut first_handler) => {
                    let res = first_handler.0.write(register, value, cpu);
                    cpu.register_manager()
                        .handlers
                        .insert(register, first_handler);
                    res
                }
                None => Err(RegisterHandleError::CannotHandleRegister(register)),
            };

            // Try again with default handler
            match first_result {
                // Already handled! pass on value
                Ok(value) => Ok(value),
                // Not found... try again with default handler
                Err(err) => match err {
                    RegisterHandleError::CannotHandleRegister(_) => {
                        let (spc, gen) = cpu.borrow_space_gen();
                        default_register_write(register, value, spc, gen)
                    }
                    _ => Err(err),
                },
            }
        }
    }
}

#[cfg(all(test, feature = "arch_arm"))]
mod tests {
    use super::*;

    use core::result::Result;

    use styx_cpu_type::{
        arch::arm::{ArmRegister, ArmVariants},
        Arch, ArchEndian,
    };
    use styx_pcode::pcode::{SpaceName, VarnodeData};

    /// RegisterTranslator for testing that returns varnodes with sepcified custom size.
    struct RegisterTranslatorCustomSize(VarnodeData);
    impl RegisterTranslatorCustomSize {
        pub fn new(size: u32) -> Self {
            RegisterTranslatorCustomSize(VarnodeData {
                space: SpaceName::Ram,
                offset: 0,
                size,
            })
        }
    }
    impl RegisterTranslator for RegisterTranslatorCustomSize {
        fn get_register(
            &self,
            _register: &ArchRegister,
        ) -> Option<&styx_pcode::pcode::VarnodeData> {
            Some(&self.0)
        }
    }

    /// RegisterCallback for testing that reads `0` with the specified size (self.0)
    #[derive(Debug)]
    struct RegisterCallbackCustomSize(u8);
    impl<T: CpuBackend> RegisterCallback<T> for RegisterCallbackCustomSize {
        fn read(
            &mut self,
            _register: ArchRegister,
            _cpu: &mut dyn RegisterCallbackCpu<T>,
        ) -> Result<SizedValue, RegisterHandleError> {
            Ok(SizedValue::from_u128(0, self.0))
        }

        fn write(
            &mut self,
            _register: ArchRegister,
            _value: SizedValue,
            _cpu: &mut dyn RegisterCallbackCpu<T>,
        ) -> Result<(), RegisterHandleError> {
            todo!("RegisterCallbackCustomSize only supports reads for testing")
        }
    }

    /// Tests a user register read when the sla spec/custom register handler reports an 8 byte size
    /// but the read operation by the user is 4 byte size. This tests the scenario where the styx
    /// register size is correct (4 bytes for R0) but the sla spec or custom register handler
    /// reports a larger sized value.
    #[test]
    fn test_register_read_mismatched_size_greater() -> Result<(), UnknownError> {
        let mut cpu = PcodeBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexM4,
            ArchEndian::LittleEndian,
        );
        let register: ArchRegister = ArmRegister::R0.into();
        cpu.register_manager
            .add_handler(ArmRegister::R0, RegisterCallbackCustomSize(8))?;

        let res = RegisterManager::read_register(&mut cpu, register);

        let res = dbg!(res);
        assert!(matches!(
            res,
            Err(RegisterHandleError::ReadMismatchedSize {
                styx_size: 4,
                actual_size: 8,
                register: _,
            })
        ));

        Ok(())
    }

    /// Tests a user register read when the sla spec/custom register handler reports an 1 byte size
    /// but the read operation by the user is 4 byte size. This tests the scenario where the styx
    /// register size is correct (4 bytes for R0) but the sla spec or custom register handler
    /// reports a lesser sized value.
    #[test]
    fn test_register_read_mismatched_size_lesser() -> Result<(), UnknownError> {
        let mut cpu = PcodeBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexM4,
            ArchEndian::LittleEndian,
        );
        let register: ArchRegister = ArmRegister::R0.into();
        cpu.register_manager
            .add_handler(ArmRegister::R0, RegisterCallbackCustomSize(1))?;

        let res = RegisterManager::read_register(&mut cpu, register);

        let res = dbg!(res);
        assert!(matches!(
            res,
            Err(RegisterHandleError::ReadMismatchedSize {
                styx_size: 4,
                actual_size: 1,
                register: _,
            })
        ));

        Ok(())
    }

    /// Tests a user register write when the sla spec reports an 8 byte size but the write operation
    /// by the user is 4 byte size. This tests the scenario where the styx register size is correct
    /// (4 bytes for R0) but the sla spec or custom register handler reports a greater sized value.
    #[test]
    fn test_register_write_mismatched_size_greater() -> Result<(), UnknownError> {
        let register: ArchRegister = ArmRegister::R0.into();
        let mut space_manager = SpaceManager::create_test_instance(4, ArchEndian::LittleEndian);

        // The written value is a u32
        let value = SizedValue::from_u128(0, 4);
        // but our register translator (i.e. our sla spec) will report that R0 should be 8 bytes
        let mut register_translator = RegisterTranslatorCustomSize::new(8);
        let res = default_register_write(
            register,
            value,
            &mut space_manager,
            &mut register_translator,
        );

        let res = dbg!(res);
        assert!(matches!(
            res,
            Err(RegisterHandleError::WriteMismatchedSize {
                styx_size: 4,
                actual_size: 8,
                register: _,
            })
        ));

        Ok(())
    }

    /// Tests a user register write when the sla spec reports an 1 byte size but the write operation
    /// by the user is 4 byte size. This tests the scenario where the styx register size is correct
    /// (4 bytes for R0) but the sla spec or custom register handler reports a lesser sized value.
    #[test]
    fn test_register_write_mismatched_size_lesser() -> Result<(), UnknownError> {
        let register: ArchRegister = ArmRegister::R0.into();
        let mut space_manager = SpaceManager::create_test_instance(4, ArchEndian::LittleEndian);

        // The written value is a u32
        let value = SizedValue::from_u128(0, 4);
        // but our register translator (i.e. our sla spec) will report that R0 should be 1 byte
        let mut register_translator = RegisterTranslatorCustomSize::new(1);
        let res = default_register_write(
            register,
            value,
            &mut space_manager,
            &mut register_translator,
        );

        let res = dbg!(res);
        assert!(matches!(
            res,
            Err(RegisterHandleError::WriteMismatchedSize {
                styx_size: 4,
                actual_size: 1,
                register: _,
            })
        ));

        Ok(())
    }
}
