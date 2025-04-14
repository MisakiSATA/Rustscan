use std::sync::atomic::{AtomicU64, Ordering};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

pub struct ScanProgress {
    multi_progress: MultiProgress,
    port_scan_bar: ProgressBar,
    service_detect_bar: ProgressBar,
    os_detect_bar: ProgressBar,
    total_ports: u64,
    scanned_ports: AtomicU64,
    total_services: AtomicU64,
    detected_services: AtomicU64,
    os_detected: AtomicU64,
}

impl ScanProgress {
    pub fn new(total_ports: u64) -> Self {
        let multi_progress = MultiProgress::new();
        
        let port_scan_bar = multi_progress.add(ProgressBar::new(total_ports));
        port_scan_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} 端口扫描 [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        let service_detect_bar = multi_progress.add(ProgressBar::new(0));
        service_detect_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} 服务识别 [{bar:40.yellow/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        let os_detect_bar = multi_progress.add(ProgressBar::new(1));
        os_detect_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} 操作系统识别 [{bar:40.magenta/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        Self {
            multi_progress,
            port_scan_bar,
            service_detect_bar,
            os_detect_bar,
            total_ports,
            scanned_ports: AtomicU64::new(0),
            total_services: AtomicU64::new(0),
            detected_services: AtomicU64::new(0),
            os_detected: AtomicU64::new(0),
        }
    }

    pub fn increment_port_scan(&self) {
        let scanned = self.scanned_ports.fetch_add(1, Ordering::Relaxed);
        self.port_scan_bar.inc(1);
        
        if scanned + 1 == self.total_ports {
            self.port_scan_bar.finish_with_message("端口扫描完成");
        }
    }

    pub fn set_total_services(&self, total: u64) {
        self.total_services.store(total, Ordering::Relaxed);
        self.service_detect_bar.set_length(total);
    }

    pub fn increment_service_detect(&self) {
        let detected = self.detected_services.fetch_add(1, Ordering::Relaxed);
        self.service_detect_bar.inc(1);
        
        if detected + 1 == self.total_services.load(Ordering::Relaxed) {
            self.service_detect_bar.finish_with_message("服务识别完成");
        }
    }

    pub fn set_os_detected(&self) {
        self.os_detected.store(1, Ordering::Relaxed);
        self.os_detect_bar.inc(1);
        self.os_detect_bar.finish_with_message("操作系统识别完成");
    }

    pub fn finish(&self) {
        self.multi_progress.clear().unwrap();
        println!("\n扫描完成:");
        println!("- 已扫描端口: {}/{}", 
            self.scanned_ports.load(Ordering::Relaxed),
            self.total_ports
        );
        println!("- 已识别服务: {}/{}", 
            self.detected_services.load(Ordering::Relaxed),
            self.total_services.load(Ordering::Relaxed)
        );
        println!("- 操作系统识别: {}/1", 
            self.os_detected.load(Ordering::Relaxed)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress() {
        let progress = ScanProgress::new(100);
        assert_eq!(progress.total_ports, 100);
        assert_eq!(progress.scanned_ports.load(Ordering::Relaxed), 0);
    }
} 