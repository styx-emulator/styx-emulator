// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! Executable which launches a styx emulator

use clap::Parser;
use emulation_service::processor_factory::ProcessorFactory;
use styx_core::cpu::arch::arm::gdb_targets::{
    ArmCoreDescription, ArmMProfileDescription, Armv7emDescription,
};
use styx_core::cpu::arch::blackfin::gdb_targets::BlackfinDescription;
use styx_core::cpu::arch::ppc32::gdb_targets::Mpc8xxTargetDescription;
use styx_core::executor::DefaultExecutor;
use styx_core::grpc::args::Target;
use styx_core::prelude::Forever;
use styx_core::tracebus::STRACE_ENV_VAR;
use styx_core::util::logging::init_logging;
use styx_plugins::gdb::{GdbExecutor, GdbPluginParams};

/// Run a styx emulation
#[styx_macros_args::styx_app_args]
pub struct MyEmuArgs {
    /// Display args, but do not execute
    #[arg(short, long, default_value_t = false)]
    pub dry_run: bool,

    /// Debug with gdb
    #[arg(short, long, default_value_t = false)]
    gdb: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var(STRACE_ENV_VAR, "srb") };

    let args = MyEmuArgs::parse();
    println!("\nInput as yaml:");
    println!("{}---", serde_yaml::to_string(&args).unwrap());
    if args.dry_run {
        std::process::exit(0);
    }

    let mut proc_process = if args.gdb {
        let params = GdbPluginParams::tcp("0.0.0.0", 9999, true);

        match args.target {
            Target::CycloneV => ProcessorFactory::create_processor_no_svc(
                &args,
                GdbExecutor::<ArmCoreDescription>::new(params)?,
            )?,
            Target::Kinetis21 => ProcessorFactory::create_processor_no_svc(
                &args,
                GdbExecutor::<Armv7emDescription>::new(params)?,
            )?,
            Target::PowerQuicc => ProcessorFactory::create_processor_no_svc(
                &args,
                GdbExecutor::<Mpc8xxTargetDescription>::new(params)?,
            )?,

            Target::Stm32f107 => ProcessorFactory::create_processor_no_svc(
                &args,
                GdbExecutor::<ArmMProfileDescription>::new(params)?,
            )?,
            Target::Blackfin512 => ProcessorFactory::create_processor_no_svc(
                &args,
                GdbExecutor::<BlackfinDescription>::new(params)?,
            )?,
        }
    } else {
        ProcessorFactory::create_processor_no_svc(&args, DefaultExecutor)?
    };

    match proc_process.run(Forever) {
        Ok(_) => {
            eprintln!("processor exited OK");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("processor exited with error: {e}");
            std::process::exit(1);
        }
    }
}
