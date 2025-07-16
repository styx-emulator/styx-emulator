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
//! GRPC async client and functions

use styx_emulator::grpc::typhunix_interop::symbolic::ProgramIdentifier;
use styx_emulator::grpc::typhunix_interop::{
    symbolic::{DataType, Program, ProgramFilter, Symbol},
    typhunix_client::TyphunixClient,
};
use tonic::{transport::Channel, IntoRequest};

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;
// Boxed because tonic::Status is LARGE
pub type GrpcStatus = tonic::Status;

pub struct AsyncClient {
    pub client: TyphunixClient<Channel>,
}

impl AsyncClient {
    /// Connect to the grpc service
    pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
    where
        D: TryInto<tonic::transport::Endpoint>,
        D::Error: Into<StdError>,
    {
        let client = TyphunixClient::connect(dst).await?;
        Ok(Self { client })
    }

    /// Get a stream to the `Program` endpoint
    pub async fn get_programs_stream(
        &mut self,
        request: impl IntoRequest<ProgramFilter>,
    ) -> Result<tonic::Response<tonic::codec::Streaming<Program>>, tonic::Status> {
        self.client.get_programs(request).await
    }

    /// get programs as a vec
    pub async fn get_programs_vec(
        &mut self,
        filter: ProgramFilter,
    ) -> Result<Vec<Program>, GrpcStatus> {
        get_programs(&mut self.client, filter).await
    }

    /// get programs as a vec
    pub async fn get_program_id_vec(&mut self) -> Result<Vec<ProgramIdentifier>, GrpcStatus> {
        get_programs_ids(&mut self.client).await
    }

    /// get symbols stream
    pub async fn get_symbols_stream(
        &mut self,
        request: impl IntoRequest<Program>,
    ) -> Result<tonic::Response<tonic::codec::Streaming<Symbol>>, GrpcStatus> {
        self.client.get_symbols(request).await
    }

    /// get symbols as vec
    pub async fn get_symbols_vec(&mut self, program: Program) -> Result<Vec<Symbol>, GrpcStatus> {
        get_symbols(&mut self.client, program).await
    }

    /// get data_types stream
    pub async fn get_data_types_stream(
        &mut self,
        request: impl IntoRequest<Program>,
    ) -> Result<tonic::Response<tonic::codec::Streaming<DataType>>, GrpcStatus> {
        self.client.get_data_types(request).await
    }

    /// get data_types as vec
    pub async fn get_data_types_vec(
        &mut self,
        program: Program,
    ) -> Result<Vec<DataType>, GrpcStatus> {
        get_data_types(&mut self.client, program).await
    }
}

/// get programs using the provided channel
pub async fn get_programs(
    client: &mut TyphunixClient<Channel>,
    filter: ProgramFilter,
) -> Result<Vec<Program>, GrpcStatus> {
    let mut stream = client
        .get_programs(tonic::Request::new(filter))
        .await?
        .into_inner();
    let mut programs: Vec<Program> = Vec::new();
    while let Some(program) = stream.message().await? {
        programs.push(program);
    }

    Ok(programs)
}

/// get programs using the provided channel
pub async fn get_programs_ids(
    client: &mut TyphunixClient<Channel>,
) -> Result<Vec<ProgramIdentifier>, GrpcStatus> {
    let mut stream = client
        .get_programs_identifiers(tonic::Request::new(ProgramFilter::default()))
        .await?
        .into_inner();
    let mut pids: Vec<ProgramIdentifier> = Vec::new();
    while let Some(pid) = stream.message().await? {
        pids.push(pid);
    }

    Ok(pids)
}

/// get data types using the provided channel
pub async fn get_data_types(
    client: &mut TyphunixClient<Channel>,
    program: Program,
) -> Result<Vec<DataType>, GrpcStatus> {
    let mut stream = client
        .get_data_types(tonic::Request::new(program))
        .await?
        .into_inner();
    let mut items: Vec<DataType> = Vec::new();
    while let Some(item) = stream.message().await? {
        items.push(item);
    }
    Ok(items)
}

/// get symbols using the provided channel
pub async fn get_symbols(
    client: &mut TyphunixClient<Channel>,
    program: Program,
) -> Result<Vec<Symbol>, GrpcStatus> {
    let mut stream = client
        .get_symbols(tonic::Request::new(program))
        .await?
        .into_inner();
    let mut items: Vec<Symbol> = Vec::new();
    while let Some(item) = stream.message().await? {
        items.push(item);
    }
    Ok(items)
}

/// Connect to `typhunix` grpc,  get a list of [Symbol] objects
/// ## Example
/// ```no_run
/// use typhunix_proto::grpc_async_client::symbols_vec;
/// use styx_emulator::grpc::typhunix_interop::symbolic::Program;
/// async fn example(program: Program) -> Result<(), Box<dyn std::error::Error>> {
///     for symbol in symbols_vec("http://localhost:50051", program).await? {
///         println!("{}", symbol);
///     }
///     Ok(())
/// }
/// ```
pub async fn symbols_vec<D>(dst: D, program: Program) -> Result<Vec<Symbol>, GrpcStatus>
where
    D: TryInto<tonic::transport::Endpoint>,
    D::Error: Into<StdError>,
{
    AsyncClient::connect(dst)
        .await
        .map_err(|e| tonic::Status::new(tonic::Code::Unknown, format!("connect failed: {e}")))?
        .get_symbols_vec(program)
        .await
}

/// Connect to `typhunix` grpc,  get a list of [DataType] objects
/// ## Example
/// ```no_run
/// use typhunix_proto::grpc_async_client::data_types_vec;
/// use styx_emulator::grpc::typhunix_interop::symbolic::Program;
/// async fn example(program: Program) -> Result<(), Box<dyn std::error::Error>> {
///     for datatype in data_types_vec("http://localhost:50051", program).await? {
///         println!("{}", datatype);
///     }
///     Ok(())
/// }
/// ```
pub async fn data_types_vec<D>(dst: D, program: Program) -> Result<Vec<DataType>, GrpcStatus>
where
    D: TryInto<tonic::transport::Endpoint>,
    D::Error: Into<StdError>,
{
    AsyncClient::connect(dst)
        .await
        .map_err(|e| tonic::Status::new(tonic::Code::Unknown, format!("connect failed: {e}")))?
        .get_data_types_vec(program)
        .await
}

/// Connect to `typhunix` grpc,  get a list of [Program] objects
/// ## Example
/// ```no_run
/// use typhunix_proto::grpc_async_client::programs_vec;
/// use styx_emulator::grpc::typhunix_interop::symbolic::ProgramFilter;
/// async fn example(filter: ProgramFilter) -> Result<(), Box<dyn std::error::Error>> {
///     for program in programs_vec("http://localhost:50051", filter).await? {
///         println!("{}", program);
///     }
///     Ok(())
/// }
/// ```
pub async fn programs_vec<D>(dst: D, filter: ProgramFilter) -> Result<Vec<Program>, GrpcStatus>
where
    D: TryInto<tonic::transport::Endpoint>,
    D::Error: Into<StdError>,
{
    AsyncClient::connect(dst)
        .await
        .map_err(|e| tonic::Status::new(tonic::Code::Unknown, format!("connect failed: {e}")))?
        .get_programs_vec(filter)
        .await
}

/// Connect to `typhunix` grpc,  get a list of [ProgramIdentifier] objects
/// ## Example
/// ```no_run
/// use typhunix_proto::grpc_async_client::programs_id_vec;
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     for pid in programs_id_vec("http://localhost:50051").await? {
///         println!("{}", pid);
///     }
///     Ok(())
/// }
/// ```
pub async fn programs_id_vec<D>(dst: D) -> Result<Vec<ProgramIdentifier>, GrpcStatus>
where
    D: TryInto<tonic::transport::Endpoint>,
    D::Error: Into<StdError>,
{
    AsyncClient::connect(dst)
        .await
        .map_err(|e| tonic::Status::new(tonic::Code::Unknown, format!("connect failed: {e}")))?
        .get_program_id_vec()
        .await
}
