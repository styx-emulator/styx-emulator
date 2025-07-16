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
use crate::{DbUrl, DbUtil, POSGRES_PORT};
use sea_orm::DatabaseConnection;
use std::net::IpAddr;
use std::{collections::HashMap, path::Path};
use styx_dbmigration::*;
use testcontainers_modules::testcontainers::TestcontainersError;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{
        core::{AccessMode, Mount, WaitFor},
        runners::AsyncRunner,
        ContainerAsync, ContainerRequest, GenericImage, ImageExt,
    },
};
use thiserror::Error;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::join;

#[derive(Error, Debug)]
pub enum TestNodeError {
    #[error(transparent)]
    IoErr(#[from] std::io::Error),
    #[error(transparent)]
    TestContainersErr(#[from] TestcontainersError),
}

#[async_trait::async_trait]
pub trait LogDump: Send + Sync {
    fn id(&self) -> String;
    async fn stdout_to_vec(&self) -> Result<Vec<u8>, TestNodeError>;
    async fn stderr_to_vec(&self) -> Result<Vec<u8>, TestNodeError>;
    async fn dump_stdout(&self) -> Result<(), TestNodeError> {
        Ok(File::create_new(format!("/tmp/{}-stdout.log", self.id()))
            .await?
            .write_all(&self.stdout_to_vec().await?)
            .await?)
    }

    async fn dump_stderr(&self) -> Result<(), TestNodeError> {
        Ok(File::create_new(format!("/tmp/{}-stderr.log", self.id()))
            .await?
            .write_all(&self.stderr_to_vec().await?)
            .await?)
    }

    async fn dump_logs(&self) -> Result<(), TestNodeError> {
        let (stdout_result, stderr_result) = join!(self.dump_stdout(), self.dump_stderr());
        stdout_result?;
        stderr_result?;
        Ok(())
    }
}

pub struct ServiceImage(ContainerRequest<GenericImage>);

impl ServiceImage {
    pub fn new(
        network_name: &str,
        service_name: &str,
        env_vars: Box<dyn Iterator<Item = (&String, &String)> + '_>,
        exposed_port: u16,
        wait_for_message: &str,
    ) -> Result<Self, Box<dyn std::error::Error + 'static>> {
        let image = {
            let source_path = {
                let mut from = styx_core::util::styx_root_pathbuf();
                from.push("target/debug");
                from.as_path().to_str().unwrap().to_string()
            };
            let svcbin = format!("{source_path}/{service_name}");
            {
                // make sure binary exists
                std::fs::File::open(Path::new(&svcbin)).inspect_err(|e| {
                    eprintln!("error: {svcbin}: {e:?}");
                })?;
            }

            let target_path = "/bins";
            let entry_point = format!("{target_path}/{service_name}");
            let mount =
                Mount::bind_mount(source_path, target_path).with_access_mode(AccessMode::ReadOnly);

            let mut image = ContainerRequest::from(
                GenericImage::new("python", "3.12-bookworm")
                    .with_entrypoint(&entry_point)
                    .with_exposed_port(exposed_port.into())
                    .with_wait_for(WaitFor::message_on_stderr(wait_for_message)),
            )
            .with_network(network_name)
            .with_container_name(format!("{network_name}-{service_name}"))
            .with_mount(mount);
            for env_var in env_vars {
                image = image.with_env_var(env_var.0, env_var.1);
            }
            image
        };

        Ok(Self(image))
    }
}

pub struct WorkspaceSvcNode {
    pub node: ContainerAsync<GenericImage>,
    pub url: String,
}
#[async_trait::async_trait]
impl LogDump for WorkspaceSvcNode {
    fn id(&self) -> String {
        self.node.id().to_string()
    }
    async fn stdout_to_vec(&self) -> Result<Vec<u8>, TestNodeError> {
        Ok(self.node.stdout_to_vec().await?)
    }
    async fn stderr_to_vec(&self) -> Result<Vec<u8>, TestNodeError> {
        Ok(self.node.stderr_to_vec().await?)
    }
}

impl WorkspaceSvcNode {
    pub async fn new(
        network_name: &str,
        dburl: &str,
    ) -> Result<Self, Box<dyn std::error::Error + 'static>> {
        let service_name = "workspace-svc";
        let env = [
            ("DATABASE_URL", dburl),
            ("NO_COLOR", &std::env::var("NO_COLOR").unwrap_or_default()),
            ("RUST_LOG", &std::env::var("RUST_LOG").unwrap_or_default()),
        ];

        let mut env_vars: HashMap<String, String> = HashMap::new();
        env.iter().for_each(|var| {
            let k = var.0.to_string();
            let v = var.1.to_string();
            env_vars.insert(k, v);
        });
        let image = ServiceImage::new(
            network_name,
            service_name,
            Box::new(env_vars.iter()),
            workspace_service::SERVICE_PORT,
            workspace_service::SERVICE_READY_MSG,
        )?;
        let node = image.0.start().await.unwrap();
        let host = node.get_host().await.unwrap().to_string();
        let port = node
            .get_host_port_ipv4(workspace_service::SERVICE_PORT)
            .await?;
        let url = format!("http://{host}:{port}");
        Ok(Self { node, url })
    }
}

pub struct TyphunixSvcNode {
    pub node: ContainerAsync<GenericImage>,
    pub url: String,
}

#[async_trait::async_trait]
impl LogDump for TyphunixSvcNode {
    fn id(&self) -> String {
        self.node.id().to_string()
    }
    async fn stdout_to_vec(&self) -> Result<Vec<u8>, TestNodeError> {
        Ok(self.node.stdout_to_vec().await?)
    }
    async fn stderr_to_vec(&self) -> Result<Vec<u8>, TestNodeError> {
        Ok(self.node.stderr_to_vec().await?)
    }
}

impl TyphunixSvcNode {
    pub async fn new(
        network_name: &str,
        dburl: &str,
    ) -> Result<Self, Box<dyn std::error::Error + 'static>> {
        let service_name = "typhunix-server";
        let env = [
            ("DATABASE_URL", dburl),
            ("NO_COLOR", &std::env::var("NO_COLOR").unwrap_or_default()),
            ("RUST_LOG", &std::env::var("RUST_LOG").unwrap_or_default()),
        ];
        let mut env_vars: HashMap<String, String> = HashMap::new();
        env.iter().for_each(|var| {
            let k = var.0.to_string();
            let v = var.1.to_string();
            env_vars.insert(k, v);
        });
        let image = ServiceImage::new(
            network_name,
            service_name,
            Box::new(env_vars.iter()),
            typhunix_server_bin::SERVICE_PORT,
            typhunix_server_bin::SERVICE_READY_MSG,
        )?;
        let node = image.0.start().await.unwrap();
        let host = node.get_host().await.unwrap().to_string();
        let port = node
            .get_host_port_ipv4(typhunix_server_bin::SERVICE_PORT)
            .await?;
        let url = format!("http://{host}:{port}");
        Ok(Self { node, url })
    }
}

pub struct PostgesNode {
    pub node: ContainerAsync<Postgres>,
    pub url: String,
    pub cnx: DatabaseConnection,
    pub ipv4: IpAddr,
    pub dbname: String,
    pub passwd: String,
    pub network_name: String,
}

impl PostgesNode {
    /// Create / start a container on the network named `network_name` with password
    /// set to `password`
    pub async fn new(network_name: &str) -> Result<Self, Box<dyn std::error::Error + 'static>> {
        let passwd = "styx";
        let dbname = "styxdb";
        let node = ContainerRequest::from(Postgres::default().with_password(passwd))
            .with_network(network_name)
            .with_container_name(format!("{network_name}-postgres"))
            .start()
            .await?;
        let host = node.get_host().await?.to_string();
        let port = node.get_host_port_ipv4(POSGRES_PORT).await?;
        let container_dburl_base =
            DbUrl::try_from(format!("postgres://postgres:{passwd}@{host}:{port}").as_str())?;
        let dburl = DbUrl::try_from(format!("{container_dburl_base}/{dbname}").as_str())?;
        let dbu = DbUtil::fresh(&dburl.to_string()).await?;
        let bridge_ip = node.get_bridge_ip_address().await?;

        Ok(Self {
            node,
            ipv4: bridge_ip,
            url: format!("postgres://postgres:styx@{bridge_ip}/styxdb"),
            cnx: dbu.connect().await?,
            dbname: dbname.to_string(),
            passwd: passwd.to_string(),
            network_name: network_name.to_string(),
        })
    }
}
