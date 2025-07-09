//! Blackfin Tests Data build script
//!
//! In order of execution:
//! - docker build the test data container
//! - run the container
//! - copy binaries out of container to crate's
//!   [OUT_DIR](https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts)
//! - generate rust code to include test binaries
//!
//! # Building the Binaries
//!
//! The building of the binaries is done in the dockerfile in the `data/`` directory. The dockerfile
//! pulls sources from the binutils-gdb repo, replaces the makefile and testutils.inc, and builds
//! the binaries into `/testdata/bin/`.
//!
//! That image is ran and the binaries are copied out. The container is killed after the binaries
//! are copied. Additionally, the container is set to remove itself after 100 seconds so if the
//! build script exits unexpectedly then the container will still be cleaned up.
//!

fn main() -> anyhow::Result<()> {
    // build bintutils tests
    if cfg!(feature = "binutils-tests") && !cfg!(feature = "disable-blackfin-tests") {
        docker_build::build_binutils_tests()?;
    }

    Ok(())
}

#[cfg_attr(feature = "disable-blackfin-tests", allow(dead_code))] // we do not build when running clippy
mod docker_build {
    use std::{
        env, fs,
        io::Write,
        path::Path,
        process::{Child, Command, Output, Stdio},
    };

    use anyhow::Context;
    use heck::AsShoutySnakeCase;
    use quote::{format_ident, quote};
    use thiserror::Error;

    pub fn build_binutils_tests() -> anyhow::Result<()> {
        // build time directory for our compiled outputs
        let out_dir = env::var("OUT_DIR").with_context(|| "OUT_DIR not set")?;

        // build the docker image (which builds test binaries)
        let image_name = build_image().with_context(|| "could not build image")?;

        // create container to copy out of
        let id = create_container(&image_name).with_context(|| "could not create container")?;

        // copy built files out and remove container
        let copy_result = copy_files(&id, &out_dir);
        remove_container(&id).with_context(|| "could not remove container")?; // remove container no matter success of copy
        copy_result.with_context(|| "could not copy files")?;

        let bins = fs::read_dir(Path::new(&out_dir).join("bin"))
            .with_context(|| "could not read bin dir")?;

        let mut tokens = quote! {};
        for bin in bins {
            let file = bin.with_context(|| "could not read binary in bin dir")?;

            let filename = file.file_name().into_string().unwrap();
            let filename_sanitized = sanitize_test_filename(&filename);
            let test_data_identifier = format_ident!("TEST_{}", filename_sanitized);

            tokens.extend(quote! {
        pub const #test_data_identifier: TestData = TestData::new(include_bytes!(concat!(env!("OUT_DIR"), "/bin/", #filename)));
    })
        }

        let test_str = tokens.to_string();

        let out_file = Path::new(&out_dir).join("generated_binutils_binaries.rs");
        std::fs::write(out_file, test_str)
            .with_context(|| "could not write generated binutils rust code")?;

        Ok(())
    }

    /// Remove extension and dashes from file name and make SHOUTY_SNAKE_CASE.
    fn sanitize_test_filename(file_name: &str) -> String {
        let no_extension = file_name.split_once('.').unwrap().0;
        let no_dashes = no_extension.replace('-', "_");
        AsShoutySnakeCase(no_dashes).to_string()
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

    /// Builds docker image with binaries and return the image name.
    fn build_image() -> anyhow::Result<String> {
        let dockerfile = include_bytes!("data/blackfin-builder.Dockerfile");

        let image_name = "blackfin-builder";

        let mut cmd = docker_cmd();

        cmd.args(["build", "--tag", image_name, "--file", "-", "."]);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("could not run command: {:?}", cmd))?;
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
            .arg(format!("{id}:/testdata/bin/"))
            .arg(out_dir);

        let child = cmd.spawn().unwrap();
        child.finish()?;

        Ok(())
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
}
