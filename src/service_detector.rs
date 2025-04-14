use std::net::{IpAddr, TcpStream};
use std::time::Duration;
use anyhow::Result;
use crate::service_fingerprints::{ServiceFingerprintDB, ServiceFingerprint};

pub struct ServiceDetector {
    target: IpAddr,
    port: u16,
    timeout: Duration,
    fingerprint_db: ServiceFingerprintDB,
}

impl ServiceDetector {
    pub fn new(target: IpAddr, port: u16, timeout: Duration) -> Self {
        Self {
            target,
            port,
            timeout,
            fingerprint_db: ServiceFingerprintDB::new(),
        }
    }

    pub async fn detect(&self) -> Result<String> {
        // 并行执行所有检测方法
        let fingerprint_task = self.detect_via_fingerprint();
        let banner_task = self.detect_via_banner();
        let port = self.port; // 复制端口号

        // 等待所有任务完成，选择最可靠的结果
        let (fingerprint_result, banner_result) = tokio::join!(
            fingerprint_task,
            banner_task,
        );

        // 优先使用指纹识别结果
        if let Ok(Some(fingerprint)) = fingerprint_result {
            if fingerprint.weight > 0.8 {
                return Ok(format!("{} ({})", fingerprint.name, fingerprint.protocol));
            }
            return Ok(fingerprint.name);
        }

        // 其次使用banner识别结果
        if let Ok(service) = banner_result {
            if service != "Unknown" {
                return Ok(service);
            }
        }

        // 最后使用端口猜测结果
        Ok(self.guess_service_by_port())
    }

    async fn detect_via_fingerprint(&self) -> Result<Option<ServiceFingerprint>> {
        self.fingerprint_db.identify_service(
            &self.target.to_string(),
            self.port,
            self.timeout
        ).await
    }

    async fn detect_via_banner(&self) -> Result<String> {
        let socket = std::net::TcpStream::connect_timeout(
            &(self.target, self.port).into(),
            self.timeout,
        )?;
        self.read_banner(&socket)
    }

    fn read_banner(&self, _socket: &TcpStream) -> Result<String> {
        // 这里实现banner读取逻辑
        // 例如：HTTP、FTP、SSH等服务的banner识别
        Ok("Unknown".to_string())
    }

    fn guess_service_by_port(&self) -> String {
        match self.port {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            6379 => "Redis",
            8080 => "HTTP-Proxy",
            _ => "Unknown",
        }
        .to_string()
    }
} 