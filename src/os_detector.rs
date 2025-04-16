use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time;
use anyhow::Result;
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::str;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSInfo {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f32,
    pub features: Vec<String>,
}

pub struct OSDetector {
    target: IpAddr,
    timeout: Duration,
}

impl OSDetector {
    pub fn new(target: IpAddr) -> Self {
        Self {
            target,
            timeout: Duration::from_secs(2),
        }
    }

    pub async fn detect(&self) -> Result<OSInfo> {
        // 并行执行所有检测方法
        let (http_result, tcp_result, services_result) = tokio::join!(
            self.detect_via_http(),
            self.detect_via_tcp(),
            self.detect_via_services()
        );

        // 合并结果
        let mut all_features = Vec::new();
        let mut max_confidence = 0.0;
        let mut best_name = "Unknown".to_string();
        let mut best_version = None;

        for info in [http_result, tcp_result, services_result].iter().filter_map(|r| r.as_ref().ok()) {
            if info.confidence > max_confidence {
                max_confidence = info.confidence;
                best_name = info.name.clone();
                best_version = info.version.clone();
            }
            for feat in &info.features {
                if !all_features.contains(feat) {
                    all_features.push(feat.clone());
                }
            }
        }

        Ok(OSInfo {
            name: best_name,
            version: best_version,
            confidence: max_confidence,
            features: all_features,
        })
    }

    async fn detect_via_http(&self) -> Result<OSInfo> {
        let addr = SocketAddr::new(self.target, 80);
        if let Ok(stream) = time::timeout(self.timeout, TokioTcpStream::connect(&addr)).await {
            if let Ok(mut stream) = stream {
                let request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
                stream.write_all(request.as_bytes()).await?;
                
                let mut buffer = [0u8; 1024];
                if let Ok(len) = stream.read(&mut buffer).await {
                    let response = String::from_utf8_lossy(&buffer[..len]);
                    
                    // 分析 HTTP 响应头
                    if let Some(os_info) = self.analyze_http_headers(&response) {
                        return Ok(os_info);
                    }
                }
            }
        }
        
        Ok(OSInfo {
            name: "Unknown".to_string(),
            version: None,
            confidence: 0.0,
            features: vec![],
        })
    }

    fn analyze_http_headers(&self, response: &str) -> Option<OSInfo> {
        let server_pattern = Regex::new(r"Server: (.*)").unwrap();
        let x_powered_by_pattern = Regex::new(r"X-Powered-By: (.*)").unwrap();
        
        let mut features = Vec::new();
        let mut confidence = 0.0;
        let mut name = "Unknown".to_string();
        let mut version = None;

        if let Some(caps) = server_pattern.captures(response) {
            let server = caps.get(1).unwrap().as_str();
            features.push(format!("Server: {}", server));
            
            // 分析服务器类型
            if server.contains("Apache") {
                name = "Linux/Unix".to_string();
                confidence = 0.8;
                if let Some(ver) = self.extract_version(server) {
                    version = Some(ver);
                    confidence += 0.1;
                }
            } else if server.contains("Microsoft-IIS") {
                name = "Windows".to_string();
                confidence = 0.9;
                if let Some(ver) = self.extract_version(server) {
                    version = Some(ver);
                    confidence += 0.1;
                }
            } else if server.contains("nginx") {
                name = "Linux/Unix".to_string();
                confidence = 0.85;
                if let Some(ver) = self.extract_version(server) {
                    version = Some(ver);
                    confidence += 0.1;
                }
            }
        }

        if let Some(caps) = x_powered_by_pattern.captures(response) {
            let powered_by = caps.get(1).unwrap().as_str();
            features.push(format!("Powered by: {}", powered_by));
            
            if powered_by.contains("PHP") {
                confidence += 0.05;
            } else if powered_by.contains("ASP.NET") {
                confidence += 0.1;
            }
        }

        if confidence > 0.0 {
            Some(OSInfo {
                name,
                version,
                confidence,
                features,
            })
        } else {
            None
        }
    }

    async fn detect_via_tcp(&self) -> Result<OSInfo> {
        let mut features = Vec::new();
        let mut confidence = 0.0;
        let mut name = "Unknown".to_string();
        let version = None;

        // 并行测试常见端口
        let test_ports = vec![22, 23, 80, 443, 445, 3389];
        let mut tasks = Vec::new();

        for port in test_ports {
            let addr = SocketAddr::new(self.target, port);
            let timeout = self.timeout;
            tasks.push(tokio::spawn(async move {
                if let Ok(stream) = time::timeout(timeout, TokioTcpStream::connect(&addr)).await {
                    if let Ok(_stream) = stream {
                        let ttl = _stream.ttl().ok()?;
                        Some((port, ttl))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }));
        }

        // 收集结果
        for task in tasks {
            if let Ok(Some((port, ttl))) = task.await {
                features.push(format!("TTL: {} (port {})", ttl, port));
                
                // 根据 TTL 猜测操作系统
                match ttl {
                    64 => {
                        name = "Linux/Unix".to_string();
                        confidence = 0.7;
                    }
                    128 => {
                        name = "Windows".to_string();
                        confidence = 0.7;
                    }
                    255 => {
                        name = "Solaris/AIX".to_string();
                        confidence = 0.7;
                    }
                    _ => {}
                }
            }
        }

        Ok(OSInfo {
            name,
            version,
            confidence,
            features,
        })
    }

    async fn detect_via_services(&self) -> Result<OSInfo> {
        let mut features = Vec::new();
        let mut confidence = 0.0;
        let mut name = "Unknown".to_string();
        let version = None;

        // 并行测试常见服务
        let test_services = vec![
            (22, "SSH"),
            (445, "SMB"),
            (3389, "RDP"),
        ];

        let mut tasks = Vec::new();
        for (port, service) in test_services {
            let addr = SocketAddr::new(self.target, port);
            let timeout = self.timeout;
            tasks.push(tokio::spawn(async move {
                if let Ok(stream) = time::timeout(timeout, TokioTcpStream::connect(&addr)).await {
                    if let Ok(_stream) = stream {
                        Some((port, service))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }));
        }

        // 收集结果
        for task in tasks {
            if let Ok(Some((port, service))) = task.await {
                features.push(format!("Service: {} (port {})", service, port));
                
                match service {
                    "SSH" => {
                        name = "Linux/Unix".to_string();
                        confidence = 0.8;
                    }
                    "SMB" | "RDP" => {
                        name = "Windows".to_string();
                        confidence = 0.9;
                    }
                    _ => {}
                }
            }
        }

        Ok(OSInfo {
            name,
            version,
            confidence,
            features,
        })
    }

    fn extract_version(&self, text: &str) -> Option<String> {
        let version_pattern = Regex::new(r"\d+\.\d+(\.\d+)*").unwrap();
        version_pattern.find(text).map(|m| m.as_str().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_os_detection() {
        let detector = OSDetector::new("127.0.0.1".parse().unwrap());
        let result = detector.detect().await;
        assert!(result.is_ok());
    }
}