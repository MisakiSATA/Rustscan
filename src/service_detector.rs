use std::net::IpAddr;
use std::time::Duration;
use anyhow::Result;
use crate::service_fingerprints::ServiceFingerprintDB;
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::collections::HashMap;

#[derive(Clone)]
pub struct ServiceDetector {
    timeout: Duration,
    fingerprint_db: ServiceFingerprintDB,
    cache: Arc<tokio::sync::RwLock<HashMap<(IpAddr, u16), String>>>,
    semaphore: Arc<Semaphore>,
}

impl ServiceDetector {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            fingerprint_db: ServiceFingerprintDB::new(),
            cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(100)), // 限制并发数
        }
    }

    pub async fn detect(&self, addr: IpAddr, port: u16) -> Result<Option<String>> {
        // 检查缓存
        {
            let cache = self.cache.read().await;
            if let Some(service) = cache.get(&(addr, port)) {
                return Ok(Some(service.clone()));
            }
        }

        // 获取信号量许可
        let _permit = self.semaphore.acquire().await.unwrap();

        // 使用指纹数据库进行服务识别
        if let Ok(Some(fingerprint)) = self.fingerprint_db.identify_service(&addr.to_string(), port, self.timeout).await {
            let service = fingerprint.name.clone();
            // 更新缓存
            let mut cache = self.cache.write().await;
            cache.insert((addr, port), service.clone());
            return Ok(Some(service));
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

        if let Some(service) = service {
            let service = service.to_string();
            // 更新缓存
            let mut cache = self.cache.write().await;
            cache.insert((addr, port), service.clone());
            Ok(Some(service))
        } else {
            Ok(None)
        }
    }

    pub async fn detect_batch(&self, addr: IpAddr, ports: &[u16]) -> Result<Vec<(u16, Option<String>)>> {
        let mut tasks = Vec::new();
        
        for &port in ports {
            let detector = self.clone();
            let addr = addr;
            let task = tokio::spawn(async move {
                match detector.detect(addr, port).await {
                    Ok(service) => (port, service),
                    Err(_) => (port, None),
                }
            });
            tasks.push(task);
        }

        let results = futures::future::join_all(tasks).await;
        let mut detected_services = Vec::new();
        
        for result in results {
            if let Ok((port, service)) = result {
                detected_services.push((port, service));
            }
        }

        Ok(detected_services)
    }
} 