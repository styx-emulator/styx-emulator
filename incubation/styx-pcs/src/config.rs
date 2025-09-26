use derive_more::derive::Display;
use serde::Deserialize;

/// Top level PCS config, defined in RFC X03.
#[derive(Deserialize, Clone, Debug)]
pub struct PcsConfig {
    pub devices: DeviceList,
    pub connections: Vec<Connection>,
}

/// Single peripheral proxy.
///
/// Currently a transparent Component Reference.
#[derive(Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct Connection {
    pub component_ref: crate::components::config::SerdeComponentReference,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct DeviceList(Vec<Device>);

#[derive(Deserialize, Clone, Debug)]
pub enum Device {
    Remote(RemoteDevice),
    Spawn(SpawnDevice),
}

impl DeviceList {
    pub(crate) fn separate(self) -> (Vec<RemoteDevice>, Vec<SpawnDevice>) {
        let mut remote_devices = Vec::new();
        let mut spawn_devices = Vec::new();
        for device in self.0.into_iter() {
            match device {
                Device::Remote(remote_device) => remote_devices.push(remote_device),
                Device::Spawn(spawn_device) => spawn_devices.push(spawn_device),
            }
        }

        (remote_devices, spawn_devices)
    }
}

/// Define a gRPC server that we must connect to.
///
/// Usually this is a processor on localhost:<port> but the endpoint can be
/// remote or even a unix domain socket.
#[derive(Deserialize, Clone, Debug)]
pub struct RemoteDevice {
    pub id: ProcessorId,
    // gets parsed into a tonic Endpoint
    // could be a Uri but I think tonic has special parsing
    // for unix domain sockets that wouldn't be available if we parsed
    // into a Uri.
    pub endpoint: String,
}

#[derive(Deserialize, Clone, Hash, PartialEq, Eq, Debug, Display)]
#[serde(transparent)]
pub struct ProcessorId(String);
// processor id is pretty much a string
impl AsRef<str> for ProcessorId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A gRPC client that is to be spawned.
#[derive(Deserialize, Clone, Debug)]
pub struct SpawnDevice {
    component_ref: crate::components::config::SerdeComponentReference,
}
