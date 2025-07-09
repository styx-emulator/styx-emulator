// SPDX-License-Identifier: BSD-2-Clause
use pyo3_stub_gen::Result;
use styx_py_api::{stub_info, BetterGenerate};

fn main() -> Result<()> {
    let info = stub_info()?;
    println!("Generating new stub into: {:?}", info.python_root);
    info.custom_generate()?;

    Ok(())
}
