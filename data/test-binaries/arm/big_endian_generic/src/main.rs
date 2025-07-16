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

// Test data build scripts that have been taken from the blackfin testdata
// HOW TO USE:
// OUT_DIR=name_of_file cargo run
// where name_of_file is a folder and the path to it from where the /src/ folder is.
//
// A dockerfile, makefile, and testutils.inc file must all be present in the working directory of the

use anyhow::Context;
use std::{
    env,
    io::Write,
    process::{Child, Command, Output, Stdio},
};
use thiserror::Error;

fn main() -> anyhow::Result<()> {
    build_tests()?;
    Ok(())
}

pub fn build_tests() -> anyhow::Result<()> {
    // we need to build the docker first
    // all dockers used with this program must act the same
    // put files in: /testdata/bin
    // move to a volume OR this file will manually extract into a folder

    // OUT_DIR is where the files will end up going - default "bin"
    let out_dir = env::var("OUT_DIR").unwrap_or("bin".to_string());

    //first step is to actually build it
    let image_name = build_image().with_context(|| "image building failed")?;

    //next run it
    let id: String = create_container(&image_name).with_context(|| "could not create container")?;

    // copy built files out and remove container
    let copy_result = copy_files(&id, &out_dir);
    remove_container(&id).with_context(|| "could not remove container")?; // remove container no matter success of copy
    copy_result.with_context(|| "could not copy files")?;

    Ok(())
}

fn build_image() -> anyhow::Result<String> {
    let mut cmd = docker_cmd();

    // rel path to your specific dockerfile
    let dockerfile = include_bytes!("../Dockerfile");

    let image_name = "be-arm-builder";

    cmd.args(["build", "--tag", image_name, "--file", "-", "."]);

    let mut child = cmd
        .spawn()
        .with_context(|| format!("could not run command: {cmd:?}"))?;
    let child_stdin = child
        .stdin
        .as_mut()
        .expect("docker command must be spawned with piped stdin");
    child_stdin
        .write_all(dockerfile)
        .with_context(|| "could not write dockerfile to stdin")?;

    child
        .finish()
        .with_context(|| "build image did not succeed")?;

    Ok(image_name.to_string())
}

/// Creates docker container and returns id.
///
/// Container is run with a `sleep 100` and is set to remove it self after completing so if the
/// container isn't removed by us it will be removed after the sleep has completed.
fn create_container(image_name: &str) -> anyhow::Result<String> {
    let mut cmd = docker_cmd();
    cmd.args(["run", "--rm", "--detach", image_name]);

    let child = cmd.spawn()?;
    let output = child.finish()?;
    let binding = String::from_utf8(output.stdout)?;
    let id = binding.trim();
    Ok(id.to_string())
}

/// Copies files from docker container to out dir.
fn copy_files(id: &str, out_dir: &str) -> anyhow::Result<()> {
    let mut cmd = docker_cmd();
    cmd.arg("cp")
        .arg(format!("{id}:/testdata/elf/"))
        .arg(out_dir);

    let child = cmd.spawn().unwrap();
    child.finish()?;

    Ok(())
}

/// `docker` command with stdio as piped.
/// Invokes with docker with `sudo` if environment variable
/// `STYX_DOCKER_SUDO_REQUIRED` == `yes`
fn docker_cmd() -> Command {
    let mut sudo_required = false;
    let mut cmd = match env::var("STYX_DOCKER_SUDO_REQUIRED") {
        Ok(s) => {
            if s == "yes" {
                sudo_required = true;
                Command::new("sudo")
            } else {
                Command::new("docker")
            }
        }
        _ => Command::new("docker"),
    };

    if sudo_required {
        cmd.arg("docker");
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    cmd
}

/// Kills docker container to remove it as soon as possible.
fn remove_container(id: &str) -> anyhow::Result<()> {
    let mut cmd = docker_cmd();
    cmd.args(["kill", id]);
    let child = cmd.spawn()?;

    child.finish()?;

    Ok(())
}

/// Helper trait to easily return error if exit status isn't success.
trait Finish {
    fn finish(self) -> anyhow::Result<Output>;
}
impl Finish for Child {
    fn finish(self) -> anyhow::Result<Output> {
        let output = self.wait_with_output()?;

        let status = output.status;
        if status.success() {
            Ok(output)
        } else {
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            Err(CommandError { stdout, stderr })?
        }
    }
}

#[derive(Error, Debug)]
#[error("Command errored with stdout: {} and stderr: {}", stdout, stderr)]
struct CommandError {
    stdout: String,
    stderr: String,
}
