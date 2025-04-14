use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{Semaphore, Mutex};
use crate::progress::ScanProgress;
use crate::rate_controller::RateController;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::service_detector::ServiceDetector;

#[derive(Clone)]
pub struct Scanner {
    target: IpAddr,
    start_port: u16,
    end_port: u16,
    timeout: Duration,
    threads: usize,
    progress: Arc<ScanProgress>,
    rate_controller: Arc<Mutex<RateController>>,
    service_detector: Arc<ServiceDetector>,
}

#[derive(Clone, Debug)]
pub enum ScanType {
    Tcp,
    Udp,
}

impl Scanner {
    pub fn new(
        target: IpAddr,
        start_port: u16,
        end_port: u16,
        timeout: Duration,
        threads: usize,
        progress: Arc<ScanProgress>,
        rate_controller: Arc<Mutex<RateController>>,
        _scan_type: ScanType,
        service_detector: Arc<ServiceDetector>,
    ) -> Self {
        Self {
            target,
            start_port,
            end_port,
            timeout,
            threads,
            progress,
            rate_controller,
            service_detector,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let open_ports = self.run_tcp_scan().await?;
        self.progress.set_total_services(open_ports.len() as u64);
        
        for port in open_ports {
            if let Ok(Some(service)) = self.service_detector.detect(self.target, port).await {
                println!("端口 {}: {}", port, service);
                self.progress.increment_service_detect();
            }
        }
        
        self.progress.finish();
        Ok(())
    }

    pub async fn run_tcp_scan(&self) -> Result<Vec<u16>> {
        let mut open_ports = Vec::new();
        let semaphore = Arc::new(Semaphore::new(self.threads));
        let total_requests = Arc::new(AtomicU64::new(0));

        let mut tasks = Vec::new();
        
        for port in self.start_port..=self.end_port {
            let target = self.target;
            let timeout = self.timeout;
            let semaphore = semaphore.clone();
            let progress = self.progress.clone();
            let rate_controller = self.rate_controller.clone();
            let total_requests = total_requests.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let result = Self::scan_port(target, port, timeout, rate_controller, total_requests).await;
                progress.increment_port_scan();
                result
            }));
        }

        let results = futures::future::join_all(tasks).await;
        for result in results {
            if let Ok(Some(port)) = result {
                open_ports.push(port);
            }
        }

        open_ports.sort();
        Ok(open_ports)
    }

    async fn run_udp_scan(&self) -> Result<Vec<u16>> {
        let semaphore = Arc::new(Semaphore::new(self.threads));
        let mut open_ports = Vec::new();
        let mut tasks = Vec::new();

        // UDP扫描使用更小的批次大小
        const UDP_BATCH_SIZE: usize = 100;
        let total_ports = (self.end_port - self.start_port + 1) as usize;
        let num_batches = (total_ports + UDP_BATCH_SIZE - 1) / UDP_BATCH_SIZE;

        for batch in 0..num_batches {
            let batch_start = self.start_port + (batch * UDP_BATCH_SIZE) as u16;
            let batch_end = std::cmp::min(batch_start + UDP_BATCH_SIZE as u16, self.end_port + 1);
            
            let semaphore = semaphore.clone();
            let progress = self.progress.clone();
            let rate_controller = self.rate_controller.clone();
            let target = self.target;
            let timeout = self.timeout;

            let task = tokio::spawn(async move {
                let mut batch_ports = Vec::new();
                let _permit = semaphore.acquire().await.unwrap();

                for port in batch_start..batch_end {
                    if let Ok(true) = Self::scan_udp_port(target, port, timeout, rate_controller.clone()).await {
                        batch_ports.push(port);
                    }
                    progress.increment_port_scan();
                }

                batch_ports
            });

            tasks.push(task);
        }

        for task in tasks {
            if let Ok(ports) = task.await {
                open_ports.extend(ports);
            }
        }

        open_ports.sort();
        Ok(open_ports)
    }

    async fn scan_port(
        target: IpAddr,
        port: u16,
        timeout_duration: Duration,
        rate_controller: Arc<Mutex<RateController>>,
        total_requests: Arc<AtomicU64>,
    ) -> Option<u16> {
        let addr = SocketAddr::new(target, port);
        
        // 在获取锁之前增加请求计数
        total_requests.fetch_add(1, Ordering::Relaxed);
        
        // 使用非阻塞连接
        match time::timeout(timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => {
                // 连接成功，调整速率
                let mut controller = rate_controller.lock().await;
                controller.adjust_rate(true, Duration::from_millis(0));
                Some(port)
            }
            Ok(Err(_)) => {
                // 连接失败，调整速率
                let mut controller = rate_controller.lock().await;
                controller.adjust_rate(false, Duration::from_millis(0));
                None
            }
            Err(_) => None,
        }
    }

    async fn scan_udp_port(
        target: IpAddr,
        port: u16,
        timeout: Duration,
        rate_controller: Arc<Mutex<RateController>>,
    ) -> Result<bool> {
        let mut rate_controller = rate_controller.lock().await;
        rate_controller.wait().await;
        let addr = SocketAddr::new(target, port);
        
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(timeout))?;
        
        let _ = socket.send_to(&[], addr);
        
        let mut buf = [0u8; 1024];
        match socket.recv_from(&mut buf) {
            Ok(_) => {
                rate_controller.increment_requests();
                rate_controller.adjust_rate(true, Duration::from_millis(0));
                Ok(true)
            }
            Err(e) => {
                rate_controller.increment_requests();
                if e.kind() == std::io::ErrorKind::WouldBlock || 
                   e.kind() == std::io::ErrorKind::TimedOut {
                    rate_controller.adjust_rate(true, Duration::from_millis(0));
                    Ok(true)
                } else {
                    rate_controller.adjust_rate(false, Duration::from_millis(0));
                    Ok(false)
                }
            }
        }
    }
}