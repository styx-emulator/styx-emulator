// SPDX-License-Identifier: BSD-2-Clause
//! Python bindings for typhunix using pyo3

use pyo3::prelude::*;

use tonic::Request;

use typhunix_config::AppConfig;

use styx_emulator::grpc::typhunix_interop::symbolic::{
    data_type::MetaType, symbol::SymbolType, DataType, Program, ProgramFilter, ProgramIdentifier,
    Symbol,
};

use typhunix_proto::{grpc_sync_client::*, vec_to_json_strings};

#[pymodule]
fn pytyphunix(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(is_running, m)?)?;
    m.add_function(wrap_pyfunction!(pids, m)?)?;
    m.add_function(wrap_pyfunction!(symbols, m)?)?;
    m.add_function(wrap_pyfunction!(data_types, m)?)?;
    m.add_function(wrap_pyfunction!(symbols_json, m)?)?;
    m.add_function(wrap_pyfunction!(data_types_json, m)?)?;
    m.add_class::<DataType>()?;
    m.add_class::<Symbol>()?;
    m.add_class::<Program>()?;
    m.add_class::<ProgramIdentifier>()?;
    m.add_class::<MetaType>()?;
    m.add_class::<SymbolType>()?;
    Ok(())
}

/// is the server running at env::TYPHUNIX_URL
#[pyfunction]
fn is_running(_py: Python) -> PyResult<bool> {
    Ok(BlockingClient::connect(AppConfig::server_uri()).is_ok())
}

/// Get list of program identifiers from the server at env::TYPHUNIX_URL
#[pyfunction]
fn pids(_py: Python) -> PyResult<Vec<ProgramIdentifier>> {
    let mut result = Vec::new();
    for p in BlockingClient::connect(AppConfig::server_uri())
        .unwrap()
        .get_programs(Request::new(ProgramFilter::default()))
        .unwrap()
    {
        if let Some(pid) = p.pid {
            result.push(pid);
        }
    }
    Ok(result)
}

/// Get symbols from the typhunix server at env::TYPHUNIX_URL

#[pyfunction]
fn symbols(_py: Python, name: &str, source_id: &str) -> PyResult<Vec<Symbol>> {
    Ok(BlockingClient::connect(AppConfig::server_uri())
        .unwrap()
        .get_symbols(ProgramIdentifier::new(name, source_id).into())
        .unwrap())
}

/// Get data_types from the typhunix server at env::TYPHUNIX_URL

#[pyfunction]
fn data_types(_py: Python, name: &str, source_id: &str) -> PyResult<Vec<DataType>> {
    Ok(BlockingClient::connect(AppConfig::server_uri())
        .unwrap()
        .get_data_types(ProgramIdentifier::new(name, source_id).into())
        .unwrap())
}

/// Get symbols from the typhunix server at env::TYPHUNIX_URL

#[pyfunction]
fn symbols_json(_py: Python, name: &str, source_id: &str) -> PyResult<Vec<String>> {
    Ok(vec_to_json_strings(
        &BlockingClient::connect(AppConfig::server_uri())
            .unwrap()
            .get_symbols(ProgramIdentifier::new(name, source_id).into())
            .unwrap(),
    )
    .unwrap())
}

/// Get data types from the typhunix server at env::TYPHUNIX_URL

#[pyfunction]
fn data_types_json(_py: Python, name: &str, source_id: &str) -> PyResult<Vec<String>> {
    Ok(vec_to_json_strings(
        &BlockingClient::connect(AppConfig::server_uri())
            .unwrap()
            .get_data_types(ProgramIdentifier::new(name, source_id).into())
            .unwrap(),
    )
    .unwrap())
}
