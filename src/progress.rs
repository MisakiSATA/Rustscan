use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub struct ScanProgress {
    multi_progress: MultiProgress,
    port_scan_bar: ProgressBar,
    service_detect_bar: ProgressBar,
    os_detect_bar: ProgressBar,
    ip_scan_bar: ProgressBar,
    total_ports: u64,
    scanned_ports: AtomicU64,
    total_services: AtomicU64,
    detected_services: AtomicU64,
    os_detected: AtomicU64,
    alive_ips: Mutex<HashSet<IpAddr>>,
    total_ips: u64,
    scanned_ips: AtomicU64,
}

impl ScanProgress {
    pub fn new(total_ports: u64, total_ips: u64) -> Self {
        let multi_progress = MultiProgress::new();

        let port_scan_bar = multi_progress.add(ProgressBar::new(total_ports));
        port_scan_bar.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} 端口扫描 [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}",
                )
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let service_detect_bar = multi_progress.add(ProgressBar::new(0));
        service_detect_bar.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.yellow} 服务识别 [{bar:40.yellow/blue}] {pos}/{len} ({eta}) {msg}",
                )
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let os_detect_bar = multi_progress.add(ProgressBar::new(1));
        os_detect_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.magenta} 操作系统识别 [{bar:40.magenta/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let ip_scan_bar = multi_progress.add(ProgressBar::new(total_ips));
        ip_scan_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} IP扫描 [{bar:40.green/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        Self {
            multi_progress,
            port_scan_bar,
            service_detect_bar,
            os_detect_bar,
            ip_scan_bar,
            total_ports,
            scanned_ports: AtomicU64::new(0),
            total_services: AtomicU64::new(0),
            detected_services: AtomicU64::new(0),
            os_detected: AtomicU64::new(0),
            alive_ips: Mutex::new(HashSet::new()),
            total_ips,
            scanned_ips: AtomicU64::new(0),
        }
    }

    pub fn increment_port_scan(&self) {
        let scanned = self.scanned_ports.fetch_add(1, Ordering::Relaxed) + 1;
        self.port_scan_bar.inc(1);
        if scanned == self.total_ports {
            self.port_scan_bar.finish_with_message("完成");
        }
    }

    pub fn add_alive_ip(&self, ip: IpAddr) {
        let mut alive_ips = self.alive_ips.lock().unwrap();
        if alive_ips.insert(ip) {
            self.ip_scan_bar.set_message(format!("存活IP: {}", ip));
        }
    }

    pub fn increment_ip_scan(&self) {
        let scanned = self.scanned_ips.fetch_add(1, Ordering::Relaxed);
        self.ip_scan_bar.inc(1);

        if scanned + 1 == self.total_ips {
            self.ip_scan_bar.finish_with_message("完成");
        }
    }

    pub fn set_total_services(&self, total: u64) {
        self.total_services.store(total, Ordering::Relaxed);
        self.service_detect_bar.set_length(total);
    }

    pub fn increment_service_detect(&self) {
        let detected = self.detected_services.fetch_add(1, Ordering::Relaxed) + 1;
        self.service_detect_bar.inc(1);

        if detected == self.total_services.load(Ordering::Relaxed) {
            self.service_detect_bar.finish_with_message("完成");
        }
    }

    pub fn set_os_detected(&self) {
        self.os_detected.store(1, Ordering::Relaxed);
        self.os_detect_bar.inc(1);
        self.os_detect_bar.finish_with_message("完成");
    }

    pub fn finish(&self) {
        let _ = self.multi_progress.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress() {
        let progress = ScanProgress::new(100, 100);
        assert_eq!(progress.total_ports, 100);
        assert_eq!(progress.scanned_ports.load(Ordering::Relaxed), 0);
    }
}
