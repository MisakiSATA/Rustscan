use std::net::IpAddr;
use std::time::Duration;
use anyhow::Result;
use crate::service_fingerprints::ServiceFingerprintDB;

pub struct ServiceDetector {
    timeout: Duration,
    fingerprint_db: ServiceFingerprintDB,
}

impl ServiceDetector {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            fingerprint_db: ServiceFingerprintDB::new(),
        }
    }

    pub async fn detect(&self, addr: IpAddr, port: u16) -> Result<Option<String>> {
        // 使用指纹数据库进行服务识别
        if let Ok(Some(fingerprint)) = self.fingerprint_db.identify_service(&addr.to_string(), port, self.timeout).await {
            return Ok(Some(fingerprint.name));
        }

        // 如果指纹识别失败，根据端口号进行基本服务识别
        let service = match port {
            80 | 443 => Some("HTTP"),
            22 => Some("SSH"),
            25 | 587 => Some("SMTP"),
            110 => Some("POP3"),
            143 => Some("IMAP"),
            3306 => Some("MySQL"),
            5432 => Some("PostgreSQL"),
            27017 => Some("MongoDB"),
            6379 => Some("Redis"),
            _ => None,
        };

        Ok(service.map(String::from))
    }
} 