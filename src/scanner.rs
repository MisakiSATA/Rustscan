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
use std::collections::HashMap;
use tokio::net::TcpSocket;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use futures::stream::{FuturesUnordered, StreamExt};

// 连接池结构
struct ConnectionPool {
    connections: HashMap<u16, TcpStream>,
    last_used: HashMap<u16, Instant>,
    max_idle_time: Duration,
}

impl ConnectionPool {
    fn new(max_idle_time: Duration) -> Self {
        Self {
            connections: HashMap::new(),
            last_used: HashMap::new(),
            max_idle_time,
        }
    }

    async fn get_connection(&mut self, addr: SocketAddr) -> Result<Option<TcpStream>> {
        let port = addr.port();
        
        // 清理过期连接
        self.cleanup_expired();
        
        // 检查是否有可用的连接
        if let Some(stream) = self.connections.remove(&port) {
            self.last_used.remove(&port);
            return Ok(Some(stream));
        }
        
        Ok(None)
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let expired_ports: Vec<u16> = self.last_used
            .iter()
            .filter(|(_, &last_used)| now.duration_since(last_used) > self.max_idle_time)
            .map(|(&port, _)| port)
            .collect();
            
        for port in expired_ports {
            self.connections.remove(&port);
            self.last_used.remove(&port);
        }
    }
}

#[derive(Clone, Debug)]
pub enum ScanType {
    Tcp,
    Udp,
}

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
    connection_pool: Arc<Mutex<ConnectionPool>>,
    batch_size: usize,
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
            connection_pool: Arc::new(Mutex::new(ConnectionPool::new(Duration::from_secs(30)))),
            batch_size: 100, // 默认批处理大小
        }
    }

    pub async fn run(&self) -> Result<Vec<(u16, String)>> {
        let open_ports = self.run_tcp_scan().await?;
        self.progress.set_total_services(open_ports.len() as u64);

        // 批量并发服务识别
        let batch_size = 20;
        let mut port_chunks = open_ports.chunks(batch_size);
        let mut tasks = FuturesUnordered::new();

        while let Some(chunk) = port_chunks.next() {
            let ports = chunk.to_vec();
            let target = self.target;
            let service_detector = self.service_detector.clone();
            let progress = self.progress.clone();

            tasks.push(tokio::spawn(async move {
                let mut results = Vec::with_capacity(ports.len());
                let mut futs = FuturesUnordered::new();
                for &port in &ports {
                    let service_detector = service_detector.clone();
                    futs.push(async move {
                        let res = service_detector.detect(target, port).await;
                        (port, res)
                    });
                }
                while let Some((port, res)) = futs.next().await {
                    if let Ok(Some(service)) = res {
                        results.push((port, service));
                    }
                    progress.increment_service_detect();
                }
                results
            }));
        }

        let mut all_results = Vec::new();
        while let Some(result) = tasks.next().await {
            if let Ok(services) = result {
                for (port, service) in services {
                    all_results.push((port, service));
                }
            }
        }

        Ok(all_results)
    }

    pub async fn run_tcp_scan(&self) -> Result<Vec<u16>> {
        let semaphore = Arc::new(Semaphore::new(self.threads));
        let total_requests = Arc::new(AtomicU64::new(0));
        let open_ports_mutex = Arc::new(Mutex::new(Vec::<u16>::new()));

        let total_ports = (self.end_port as u32).saturating_sub(self.start_port as u32).saturating_add(1) as usize;
        let batch_size = 2000; // 更大批次提升效率
        let num_batches = (total_ports + batch_size - 1) / batch_size;

        let mut tasks = FuturesUnordered::new();

        for batch in 0..num_batches {
            let batch_start = self.start_port.saturating_add((batch * batch_size) as u16);
            let batch_end = std::cmp::min(
                batch_start.saturating_add(batch_size as u16),
                self.end_port.saturating_add(1)
            );

            let target = self.target;
            let timeout = self.timeout;
            let semaphore = semaphore.clone();
            let progress = self.progress.clone();
            let rate_controller = self.rate_controller.clone();
            let total_requests = total_requests.clone();
            let open_ports = open_ports_mutex.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let mut batch_ports = Vec::with_capacity((batch_end - batch_start) as usize);

                let mut futs = FuturesUnordered::new();
                for port in batch_start..batch_end {
                    let target = target;
                    let timeout = timeout;
                    let rate_controller = rate_controller.clone();
                    let total_requests = total_requests.clone();
                    futs.push(Self::scan_port(target, port, timeout, rate_controller, total_requests));
                }
                let mut idx = 0;
                while let Some(result) = futs.next().await {
                    if result.is_some() {
                        batch_ports.push(batch_start.saturating_add(idx as u16));
                    }
                    progress.increment_port_scan();
                    idx += 1;
                }

                let mut open_ports = open_ports.lock().await;
                open_ports.extend(batch_ports);
            }));
        }

        while let Some(_res) = tasks.next().await {}

        let open_ports = open_ports_mutex.lock().await;
        let mut result = open_ports.clone();
        result.sort();
        Ok(result)
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
        
        match time::timeout(timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(_stream)) => {
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