use std::net::Ipv4Addr;

use anyhow::Context;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Settings {
    pub app_port: u16,
    pub app_ip: Ipv4Addr,
}

impl Settings {
    pub fn load_configuration() -> Result<Settings, anyhow::Error> {
        let config_file = std::env::var("APP_CONFIG_FILE")
            .expect("APP_CONFIG_FILE var is unset!");

        config::Config::builder()
            .add_source(config::File::new(
                &config_file,
                config::FileFormat::Yaml,
            ))
            .build()?
            .try_deserialize()
            .context("Failed to build config from local config file.")
    }
}
