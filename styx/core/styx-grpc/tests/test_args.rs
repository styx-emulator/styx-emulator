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
#[cfg(test)]
mod tests {
    use clap::Parser;
    use styx_grpc::args::{
        EmuRunLimitsParser, HasEmulationOptArgs, HasTarget, Target, TracePluginArgsParser,
    };

    /// function for testing clap args help expected results
    /// this function Removes leading and trailing whitespace, and all blank lines
    #[allow(dead_code)]
    fn trim_all(s: &str) -> String {
        let lines = s
            .split('\n')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();
        let mut results: Vec<String> = vec![];
        for line in lines.iter() {
            let newline = line.replace('\n', "");
            if !newline.is_empty() {
                results.push(newline);
            }
        }
        results.join("\n")
    }

    const EXPECTED_HELP_MSG: &str = "BasicEmulationArg help";
    // ^^^ keep this constant consistant with BasicEmulationArgs doc string below
    #[styx_macros_args::styx_app_args]
    /// BasicEmulationArg help
    pub struct BasicEmulationArgs {}

    #[test]
    fn test_clap_emulation_args_help() {
        // run clap parse passing the --help flag, match on strings to make sure
        // the basic mechanisms are working
        let expected_help_strings = [
            EXPECTED_HELP_MSG,
            "--firmware-path",
            "--ipc-port",
            "--target",
            "Possible values:",
            "- kinetis21:   Kinetis21",
            "- power-quicc: PowerQuicc",
            "- stm32f107:   Stm32f107",
            "--trace-plugin-args",
            "--emu-run-limits",
            "--raw-loader-args",
        ];

        let args = BasicEmulationArgs::try_parse_from(["app_name", "--help"]);
        assert!(args.is_err());
        if let Err(e) = args {
            assert!(
                e.kind() == clap::error::ErrorKind::DisplayHelp,
                "expected help message"
            );
            let helpmsg = e.to_string();
            for s in expected_help_strings {
                assert!(helpmsg.contains(s));
            }

            log::debug!("{helpmsg}");
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_minimal_with_defaults() {
        let target_name = "kinetis21";
        let expected_target = Target::Kinetis21;
        let fwpath = "/tmp/test.bin";
        let args = BasicEmulationArgs::parse_from([
            "app_name",
            "--target",
            target_name,
            "--firmware-path",
            fwpath,
            "--ipc-port",
            "0",
        ]);
        let yaml = args.yaml();
        log::debug!("YAML from args: {yaml}");
        assert_eq!(args.firmware_path(), fwpath);
        assert_eq!(args.ipc_port(), Some(0));
        let t = Target::from_str_name(target_name);
        log::debug!("{t:?}");
        assert_eq!(args.target(), expected_target);
        assert!(args.trace_plugin_args.is_none());
        assert!(args.emu_run_limits.is_none());
        assert!(args.raw_loader_args.is_none());
    }

    #[test]
    fn test_minimal_with_trace_plugin_args() {
        let target_name = "kinetis21";
        let expected_target = Target::Kinetis21;
        let fwpath = "/tmp/test.bin";
        let args = BasicEmulationArgs::parse_from([
            "app_name",
            "--target",
            target_name,
            "--firmware-path",
            fwpath,
            "--ipc-port",
            "0",
        ]);
        assert_eq!(args.firmware_path(), fwpath);
        let t = Target::from_str_name(target_name);
        log::debug!("{t:?}");

        assert_eq!(args.target(), expected_target);

        assert_eq!(args.ipc_port(), Some(0));
        assert!(args.trace_plugin_args.is_none());
        assert!(args.emu_run_limits.is_none());
        assert!(args.raw_loader_args.is_none());
    }

    #[test]
    fn test_value_parser() {
        assert!(TracePluginArgsParser::try_parse_from(["--insn-event"]).is_ok());
        assert!(EmuRunLimitsParser::try_parse_from([
            "--emu-run-limits",
            "--emu-max-insn",
            "0",
            "--emu-seconds",
            "20",
        ])
        .is_ok());
    }
}
