use std::collections::HashMap;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use anyhow::Result;
use regex::Regex;
use tokio::io::AsyncReadExt;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub banner_pattern: Option<String>,
    pub response_pattern: Option<String>,
    pub weight: f32,
    pub description: Option<String>,
    pub version_pattern: Option<String>,
    pub vendor: Option<String>,
    pub cpe: Option<String>, // Common Platform Enumeration
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FingerprintConfig {
    pub fingerprints: Vec<ServiceFingerprint>,
}

#[derive(Clone)]
pub struct ServiceFingerprintDB {
    fingerprints: HashMap<u16, Vec<ServiceFingerprint>>,
    compiled_patterns: HashMap<String, Regex>,
}

impl ServiceFingerprintDB {
    pub fn new() -> Self {
        let mut db = Self {
            fingerprints: HashMap::new(),
            compiled_patterns: HashMap::new(),
        };
        
        // 尝试从配置文件加载指纹
        if let Ok(config) = db.load_config("fingerprints.json") {
            db.initialize_from_config(config);
        } else {
            // 如果配置文件不存在，使用默认指纹
            db.initialize_default_fingerprints();
        }
        
        db
    }

    fn load_config<P: AsRef<Path>>(&self, path: P) -> Result<FingerprintConfig> {
        let content = fs::read_to_string(path)?;
        let config: FingerprintConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    fn initialize_from_config(&mut self, config: FingerprintConfig) {
        for fingerprint in config.fingerprints {
            self.add_fingerprint(fingerprint);
        }
    }

    fn add_fingerprint(&mut self, fingerprint: ServiceFingerprint) {
        let port = fingerprint.port;
        let entry = self.fingerprints.entry(port).or_insert_with(Vec::new);
        
        // 预编译正则表达式
        if let Some(pattern) = &fingerprint.banner_pattern {
            if let Ok(re) = Regex::new(pattern) {
                self.compiled_patterns.insert(pattern.clone(), re);
            }
        }
        if let Some(pattern) = &fingerprint.response_pattern {
            if let Ok(re) = Regex::new(pattern) {
                self.compiled_patterns.insert(pattern.clone(), re);
            }
        }
        
        entry.push(fingerprint);
    }

    fn initialize_default_fingerprints(&mut self) {
        // Web 服务
        self.add_fingerprint(ServiceFingerprint {
            name: "HTTP".to_string(),
            protocol: "TCP".to_string(),
            port: 80,
            banner_pattern: Some(r"HTTP/\d\.\d".to_string()),
            response_pattern: Some(r"Server: (.*)".to_string()),
            weight: 1.0,
            description: Some("Hypertext Transfer Protocol".to_string()),
            version_pattern: Some(r"HTTP/(\d\.\d)".to_string()),
            vendor: None,
            cpe: Some("cpe:/a:http:http_server".to_string()),
        });

        // 数据库服务
        self.add_fingerprint(ServiceFingerprint {
            name: "MySQL".to_string(),
            protocol: "TCP".to_string(),
            port: 3306,
            banner_pattern: Some(r"mysql_native_password".to_string()),
            response_pattern: Some(r"(\d+\.\d+\.\d+)-MySQL".to_string()),
            weight: 0.9,
            description: Some("MySQL Database Server".to_string()),
            version_pattern: Some(r"(\d+\.\d+\.\d+)-MySQL".to_string()),
            vendor: Some("Oracle".to_string()),
            cpe: Some("cpe:/a:mysql:mysql".to_string()),
        });

        // 远程管理服务
        self.add_fingerprint(ServiceFingerprint {
            name: "SSH".to_string(),
            protocol: "TCP".to_string(),
            port: 22,
            banner_pattern: Some(r"SSH-\d\.\d".to_string()),
            response_pattern: None,
            weight: 0.95,
            description: Some("Secure Shell".to_string()),
            version_pattern: Some(r"SSH-(\d\.\d)".to_string()),
            vendor: None,
            cpe: Some("cpe:/a:openssh:openssh".to_string()),
        });
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
                            // 使用预编译的正则表达式
                            if let Some(pattern) = &fingerprint.banner_pattern {
                                if let Some(re) = self.compiled_patterns.get(pattern) {
                                    if re.is_match(&response) {
                                        return Ok(Some(fingerprint.clone()));
                                    }
                                }
                            }
                            
                            if let Some(pattern) = &fingerprint.response_pattern {
                                if let Some(re) = self.compiled_patterns.get(pattern) {
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

    pub fn get_fingerprints_by_port(&self, port: u16) -> Option<&Vec<ServiceFingerprint>> {
        self.fingerprints.get(&port)
    }

    pub fn get_all_fingerprints(&self) -> Vec<&ServiceFingerprint> {
        self.fingerprints.values().flatten().collect()
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