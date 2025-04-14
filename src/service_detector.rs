use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use anyhow::Result;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
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
        // 首先尝试使用指纹识别
        if let Ok(Some(fingerprint)) = self.detect_via_fingerprint().await {
            if fingerprint.weight > 0.8 {
                return Ok(format!("{} ({})", fingerprint.name, fingerprint.protocol));
            }
            return Ok(fingerprint.name);
        }

        // 如果指纹识别失败，尝试协议探测
        if let Ok(service) = self.detect_via_protocol().await {
            if service != "Unknown" {
                return Ok(service);
            }
        }

        // 最后使用端口猜测
        Ok(self.guess_service_by_port())
    }

    async fn detect_via_fingerprint(&self) -> Result<Option<ServiceFingerprint>> {
        self.fingerprint_db.identify_service(
            &self.target.to_string(),
            self.port,
            self.timeout
        ).await
    }

    async fn detect_via_protocol(&self) -> Result<String> {
        let addr = SocketAddr::new(self.target, self.port);
        match time::timeout(self.timeout, TokioTcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // 根据端口尝试不同的协议探测
                match self.port {
                    80 | 8080 | 443 => {
                        // HTTP/HTTPS探测
                        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
                        if let Ok(_) = stream.write_all(request).await {
                            let mut buffer = [0u8; 1024];
                            if let Ok(Ok(len)) = time::timeout(self.timeout, stream.read(&mut buffer)).await {
                                let response = String::from_utf8_lossy(&buffer[..len]);
                                if response.contains("HTTP/") {
                                    return Ok(if self.port == 443 { "HTTPS" } else { "HTTP" }.to_string());
                                }
                            }
                        }
                    }
                    22 => {
                        // SSH探测
                        let mut buffer = [0u8; 1024];
                        if let Ok(Ok(len)) = time::timeout(self.timeout, stream.read(&mut buffer)).await {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.contains("SSH-") {
                                return Ok("SSH".to_string());
                            }
                        }
                    }
                    25 => {
                        // SMTP探测
                        let mut buffer = [0u8; 1024];
                        if let Ok(Ok(len)) = time::timeout(self.timeout, stream.read(&mut buffer)).await {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.contains("220") {
                                return Ok("SMTP".to_string());
                            }
                        }
                    }
                    110 => {
                        // POP3探测
                        let mut buffer = [0u8; 1024];
                        if let Ok(Ok(len)) = time::timeout(self.timeout, stream.read(&mut buffer)).await {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.contains("+OK") {
                                return Ok("POP3".to_string());
                            }
                        }
                    }
                    143 => {
                        // IMAP探测
                        let mut buffer = [0u8; 1024];
                        if let Ok(Ok(len)) = time::timeout(self.timeout, stream.read(&mut buffer)).await {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.contains("* OK") {
                                return Ok("IMAP".to_string());
                            }
                        }
                    }
                    3306 => {
                        // MySQL探测
                        let mut buffer = [0u8; 1024];
                        if let Ok(Ok(len)) = time::timeout(self.timeout, stream.read(&mut buffer)).await {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.contains("mysql_native_password") {
                                return Ok("MySQL".to_string());
                            }
                        }
                    }
                    5432 => {
                        // PostgreSQL探测
                        let mut buffer = [0u8; 1024];
                        if let Ok(Ok(len)) = time::timeout(self.timeout, stream.read(&mut buffer)).await {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.contains("PostgreSQL") {
                                return Ok("PostgreSQL".to_string());
                            }
                        }
                    }
                    6379 => {
                        // Redis探测
                        let mut buffer = [0u8; 1024];
                        if let Ok(Ok(len)) = time::timeout(self.timeout, stream.read(&mut buffer)).await {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.contains("REDIS") {
                                return Ok("Redis".to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        Ok("Unknown".to_string())
    }

    fn guess_service_by_port(&self) -> String {
        // 从指纹库中获取端口对应的服务
        if let Some(fingerprints) = self.fingerprint_db.get_fingerprints_by_port(self.port) {
            if let Some(fingerprint) = fingerprints.first() {
                return fingerprint.name.clone();
            }
        }
        "Unknown".to_string()
    }
} 