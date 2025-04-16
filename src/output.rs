use crate::os_detector::OSInfo;
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    target: String,
    os_info: Option<OSInfo>,
    ports: Vec<PortInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortInfo {
    port: u16,
    service: String,
    protocol: String,
}

impl Output {
    pub fn new(target: String) -> Self {
        Self {
            target,
            os_info: None,
            ports: Vec::new(),
        }
    }

    pub fn set_os_info(&mut self, os_info: OSInfo) {
        self.os_info = Some(os_info);
    }

    pub fn add_port(&mut self, port: u16, service: String, protocol: String) {
        self.ports.push(PortInfo {
            port,
            service,
            protocol,
        });
    }

    pub fn print_console(&self) {
        println!("{} 扫描结果:", "[*]".blue());
        println!("目标: {}", self.target);

        if let Some(os_info) = &self.os_info {
            println!(
                "操作系统: {} (置信度: {:.2}%)",
                os_info.name,
                os_info.confidence * 100.0
            );
            if let Some(version) = &os_info.version {
                println!("版本: {}", version);
            }
            println!("特征:");
            for feature in &os_info.features {
                println!("  - {}", feature);
            }
        }

        println!("\n开放端口:");
        for port_info in &self.ports {
            println!(
                "  - {} ({}) - {}",
                port_info.port, port_info.protocol, port_info.service
            );
        }
    }

    pub fn save_json(&self, path: &PathBuf) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn save_csv(&self, path: &PathBuf) -> anyhow::Result<()> {
        let mut wtr = csv::Writer::from_path(path)?;

        // 写入操作系统信息
        if let Some(os_info) = &self.os_info {
            wtr.write_record(&[
                "OS",
                &os_info.name,
                &os_info.version.as_deref().unwrap_or("Unknown"),
                &format!("{:.2}", os_info.confidence * 100.0),
            ])?;
        }

        // 写入端口信息
        for port_info in &self.ports {
            wtr.write_record(&[
                "Port",
                &port_info.port.to_string(),
                &port_info.protocol,
                &port_info.service,
            ])?;
        }

        wtr.flush()?;
        Ok(())
    }
}
