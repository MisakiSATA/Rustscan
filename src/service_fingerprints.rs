use std::collections::HashMap;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use anyhow::Result;
use regex::Regex;
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone)]
pub struct ServiceFingerprint {
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub banner_pattern: Option<String>,
    pub response_pattern: Option<String>,
    pub weight: f32,
}

pub struct ServiceFingerprintDB {
    fingerprints: HashMap<u16, Vec<ServiceFingerprint>>,
}

impl ServiceFingerprintDB {
    pub fn new() -> Self {
        let mut fingerprints = HashMap::new();
        
        // Web 服务
        fingerprints.insert(80, vec![
            ServiceFingerprint {
                name: "HTTP".to_string(),
                protocol: "TCP".to_string(),
                port: 80,
                banner_pattern: Some(r"HTTP/\d\.\d".to_string()),
                response_pattern: None,
                weight: 1.0,
            }
        ]);
        
        fingerprints.insert(443, vec![
            ServiceFingerprint {
                name: "HTTPS".to_string(),
                protocol: "TCP".to_string(),
                port: 443,
                banner_pattern: None,
                response_pattern: None,
                weight: 1.0,
            }
        ]);

        // 数据库服务
        fingerprints.insert(3306, vec![
            ServiceFingerprint {
                name: "MySQL".to_string(),
                protocol: "TCP".to_string(),
                port: 3306,
                banner_pattern: Some(r"mysql_native_password".to_string()),
                response_pattern: None,
                weight: 0.9,
            }
        ]);

        fingerprints.insert(5432, vec![
            ServiceFingerprint {
                name: "PostgreSQL".to_string(),
                protocol: "TCP".to_string(),
                port: 5432,
                banner_pattern: Some(r"PostgreSQL".to_string()),
                response_pattern: None,
                weight: 0.9,
            }
        ]);

        // 远程管理服务
        fingerprints.insert(22, vec![
            ServiceFingerprint {
                name: "SSH".to_string(),
                protocol: "TCP".to_string(),
                port: 22,
                banner_pattern: Some(r"SSH-\d\.\d".to_string()),
                response_pattern: None,
                weight: 0.95,
            }
        ]);

        fingerprints.insert(3389, vec![
            ServiceFingerprint {
                name: "RDP".to_string(),
                protocol: "TCP".to_string(),
                port: 3389,
                banner_pattern: None,
                response_pattern: None,
                weight: 0.95,
            }
        ]);

        // 文件共享服务
        fingerprints.insert(445, vec![
            ServiceFingerprint {
                name: "SMB".to_string(),
                protocol: "TCP".to_string(),
                port: 445,
                banner_pattern: None,
                response_pattern: None,
                weight: 0.9,
            }
        ]);

        // 邮件服务
        fingerprints.insert(25, vec![
            ServiceFingerprint {
                name: "SMTP".to_string(),
                protocol: "TCP".to_string(),
                port: 25,
                banner_pattern: Some(r"220.*SMTP".to_string()),
                response_pattern: None,
                weight: 0.85,
            }
        ]);

        Self { fingerprints }
    }

    pub async fn identify_service(
        &self,
        target: &str,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<Option<ServiceFingerprint>> {
        if let Some(fingerprints) = self.fingerprints.get(&port) {
            let addr = format!("{}:{}", target, port);
            if let Ok(stream) = timeout(timeout_duration, TcpStream::connect(&addr)).await {
                if let Ok(mut stream) = stream {
                    let mut buffer = [0u8; 1024];
                    if let Ok(len) = stream.read(&mut buffer).await {
                        let response = String::from_utf8_lossy(&buffer[..len]);
                        
                        for fingerprint in fingerprints {
                            if let Some(pattern) = &fingerprint.banner_pattern {
                                if let Ok(re) = Regex::new(pattern) {
                                    if re.is_match(&response) {
                                        return Ok(Some(fingerprint.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_identification() {
        let db = ServiceFingerprintDB::new();
        let result = db.identify_service("127.0.0.1", 80, Duration::from_secs(1)).await;
        assert!(result.is_ok());
    }
} 