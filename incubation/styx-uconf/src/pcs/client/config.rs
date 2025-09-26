use std::net::SocketAddr;

#[derive(serde::Deserialize)]
pub struct PcsClientConfiguration {
    connection: SocketAddr,
    channels: Vec<ChannelConfig>,
}

#[derive(serde::Deserialize)]
pub struct ChannelConfig {
    id: String,
    peripheral: Peripheral,
}

#[derive(serde::Deserialize)]
pub enum Peripheral {
    Uart { port: u32 },
    Spi { port: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let yaml = r#"
        connection: localhost:9999
        channels:
          - id: uart1
            peripheral: !Uart
              port: 1
        "#;

        serde_yaml::from_str::<PcsClientConfiguration>(yaml).unwrap();
    }
}
