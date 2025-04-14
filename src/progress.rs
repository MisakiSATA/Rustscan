use std::sync::atomic::{AtomicU64, Ordering};
use indicatif::{ProgressBar, ProgressStyle};

pub struct ScanProgress {
    total: u64,
    scanned: AtomicU64,
    progress_bar: ProgressBar,
}

impl ScanProgress {
    pub fn new(total: u64) -> Self {
        let progress_bar = ProgressBar::new(total);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        Self {
            total,
            scanned: AtomicU64::new(0),
            progress_bar,
        }
    }

    pub fn increment(&self) {
        let scanned = self.scanned.fetch_add(1, Ordering::Relaxed);
        self.progress_bar.inc(1);
        
        if scanned + 1 == self.total {
            self.finish();
        }
    }

    pub fn finish(&self) {
        println!("扫描完成: {}/{} 端口已扫描", 
            self.get_scanned(), 
            self.get_total()
        );
        self.progress_bar.finish();
    }

    pub fn get_total(&self) -> u64 {
        self.total
    }

    pub fn get_scanned(&self) -> u64 {
        self.scanned.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress() {
        let progress = ScanProgress::new(100);
        assert_eq!(progress.total, 100);
        assert_eq!(progress.scanned.load(Ordering::Relaxed), 0);
    }
} 