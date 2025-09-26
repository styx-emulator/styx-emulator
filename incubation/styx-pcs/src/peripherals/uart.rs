use serde::Deserialize;
use styx_core::{
    errors::UnknownError,
    grpc::io::uart::{
        bytes_message::Data::{self},
        uart_port_client::UartPortClient,
        BytesMessage, PortRequest, SubscribeRequest, TX_DIRECTION,
    },
    prelude::{anyhow, log::debug, Context},
};
use tokio::runtime::Handle;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::{
    components::Component,
    config::ProcessorId,
    peripherals::{peripheral_service_handle, PeripheralService, PeripheralServiceHandle},
    processor::Processors,
};

#[derive(Deserialize)]
enum UartDirection {
    From,
    To,
    Both,
}

#[derive(Deserialize)]
struct UartConfig {
    from: ProcessorConnection,
    to: ProcessorConnection,
    direction: UartDirection,
}

#[derive(Deserialize)]
struct ProcessorConnection {
    id: ProcessorId,
    port: String,
}

/// Uart specific processor with an endpoint, id, uart port, and Uart Client.
#[derive(Clone, Debug)]
struct ResolvedProcessor {
    id: String,
    port: String,
    connection: Uri,
    client: UartPortClient<Channel>,
}

async fn resolve_connection(
    connection: &ProcessorConnection,
    processors: &Processors,
) -> Result<ResolvedProcessor, UnknownError> {
    let proc = processors
        .get_processor(&connection.id)
        .ok_or(anyhow!("processor not found"))?;
    let endpoint = proc.addr().clone();
    println!("endpoint: {:?}", endpoint);
    let client = UartPortClient::connect(endpoint.clone())
        .await
        .with_context(|| "could not connect")?;
    Ok(ResolvedProcessor {
        id: connection.id.as_ref().to_owned(),
        port: connection.port.clone(),
        connection: proc.addr().clone(),
        client,
    })
}

const UART_BUILDER: PeripheralService = build_uart;

inventory::submit! {
    Component {
        id: "uart",
        item: UART_BUILDER,
        file: "file",
        line: 10,
        module_path: "fdjf"
    }
}

pub fn build_uart(
    config: Option<&serde_yaml::Value>,
    processors: &Processors,
    runtime: &Handle,
) -> Result<PeripheralServiceHandle, UnknownError> {
    let processors = processors.clone();
    let uart_config =
        serde_yaml::from_value::<UartConfig>(config.ok_or(anyhow!("missing config"))?.clone())
            .with_context(|| "bad config")?;
    runtime.spawn(async move { spawn_uart(&uart_config, &processors).await });

    let (_, handle) = peripheral_service_handle();
    Ok(handle)
}

async fn spawn_uart(config: &UartConfig, processors: &Processors) {
    let from = resolve_connection(&config.from, processors).await.unwrap();
    let to = resolve_connection(&config.to, processors).await.unwrap();
    debug!("from: {from:?}");
    debug!("to: {to:?}");
    {
        let from = from.clone();
        let to = to.clone();
        tokio::spawn(build_from(from.clone(), to.clone()));
        tokio::spawn(build_from(to.clone(), from.clone()));
    }
}

/// Spawn a thread that receives from From and sends to To
async fn build_from(from: ResolvedProcessor, to: ResolvedProcessor) {
    let mut from_client = from.client.clone();
    let mut to_client = to.client.clone();
    debug!("subscribing to the TX of {from:?}");
    let mut resp = from_client
        .subscribe(SubscribeRequest {
            direction: TX_DIRECTION,
            port: Some(PortRequest {
                port: from.port.clone(),
            }),
        })
        .await
        .with_context(|| format!("could not subscribe to uart {from:?}"))
        .unwrap()
        .into_inner();

    while let Some(recv) = resp.next().await {
        if let Err(e) = recv {
            println!("Server disconnected or other error occured: {e:?}");
            break;
        }

        // take from and send to to
        let msg: BytesMessage = recv.unwrap();
        debug!("got some data: {msg:?} from {} to {}", from.id, to.id);
        match msg.data.unwrap() {
            Data::TxData(recv_data) => {
                let new_data = Data::RxData(styx_core::grpc::io::uart::RxData {
                    data: recv_data.data,
                });
                let new_message = BytesMessage {
                    port: to.port.clone(),
                    data: Some(new_data),
                };
                to_client.receive(new_message).await.unwrap();
            }
            Data::RxData(_) => Err(anyhow!("got rx data on tx direction")).unwrap(),
        }
    }
}
