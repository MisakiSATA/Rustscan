use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Semaphore;
use crate::progress::ScanProgress;
use crate::rate_controller::RateController;
use std::collections::VecDeque;

#[derive(Clone)]
pub struct Scanner {
    target: IpAddr,
    start_port: u16,
    end_port: u16,
    timeout: Duration,
    threads: usize,
    progress: Arc<ScanProgress>,
    rate_controller: Arc<RateController>,
    scan_type: ScanType,
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
        scan_type: ScanType,
    ) -> Self {
        let rate_controller = Arc::new(RateController::new(
            threads as u64,
            (threads / 10).max(1) as u64
        ));
        Self {
            target,
            start_port,
            end_port,
            timeout,
            threads,
            progress,
            rate_controller,
            scan_type,
        }
    }

    pub async fn run(&self) -> Result<Vec<u16>> {
        println!("当前扫描速率: {} 请求/秒", self.rate_controller.get_current_rate());
        println!("每秒实际请求数: {} 请求/秒", self.rate_controller.get_requests_per_second());
        println!("总请求数: {}", self.rate_controller.get_total_requests());
        
        match self.scan_type {
            ScanType::Tcp => self.run_tcp_scan().await,
            ScanType::Udp => self.run_udp_scan().await,
        }
    }

    async fn run_tcp_scan(&self) -> Result<Vec<u16>> {
        let semaphore = Arc::new(Semaphore::new(self.threads));
        let mut open_ports = Vec::new();
        let mut tasks = Vec::new();

        // 将端口范围分成多个批次
        let total_ports = (self.end_port as u32 - self.start_port as u32 + 1) as usize;
        let batch_size = (total_ports + self.threads - 1) / self.threads;
        let num_batches = (total_ports + batch_size - 1) / batch_size;

        for batch in 0..num_batches {
            let batch_start = self.start_port as u32 + (batch * batch_size) as u32;
            let batch_end = std::cmp::min(batch_start + batch_size as u32, self.end_port as u32 + 1);
            
            let semaphore = semaphore.clone();
            let progress = self.progress.clone();
            let rate_controller = self.rate_controller.clone();
            let target = self.target;
            let timeout = self.timeout;

            let task = tokio::spawn(async move {
                let mut batch_ports = Vec::new();
                let _permit = semaphore.acquire().await.unwrap();

                // 使用工作窃取队列来管理端口扫描任务
                let mut port_queue = VecDeque::new();
                for port in batch_start..batch_end {
                    port_queue.push_back(port as u16);
                }

                while let Some(port) = port_queue.pop_front() {
                    if let Ok(true) = Self::scan_port(target, port, timeout, &rate_controller).await {
                        batch_ports.push(port);
                    }
                    progress.increment_port_scan();
                }

                batch_ports
            });

            tasks.push(task);
        }

        // 收集所有开放端口
        for task in tasks {
            if let Ok(ports) = task.await {
                open_ports.extend(ports);
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
                    if let Ok(true) = Self::scan_udp_port(target, port, timeout, &rate_controller).await {
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
        timeout: Duration,
        rate_controller: &RateController,
    ) -> Result<bool> {
        rate_controller.wait().await;
        let addr = SocketAddr::new(target, port);
        
        match time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => {
                rate_controller.increment_requests();
                rate_controller.adjust_rate(true, Duration::from_millis(0));
                Ok(true)
            }
            Ok(Err(_)) => {
                rate_controller.increment_requests();
                rate_controller.adjust_rate(false, Duration::from_millis(0));
                Ok(false)
            }
            Err(_) => Ok(false),
        }
    }

    async fn scan_udp_port(
        target: IpAddr,
        port: u16,
        timeout: Duration,
        rate_controller: &RateController,
    ) -> Result<bool> {
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
                if e.kind() == std::io::ErrorKind::WouldBlock || 
                   e.kind() == std::io::ErrorKind::TimedOut {
                    rate_controller.increment_requests();
                    rate_controller.adjust_rate(true, Duration::from_millis(0));
                    Ok(true)
                } else {
                    rate_controller.increment_requests();
                    rate_controller.adjust_rate(false, Duration::from_millis(0));
                    Ok(false)
                }
            }
        }
    }
}