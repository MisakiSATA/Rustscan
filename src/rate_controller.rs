use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::sleep;

pub struct RateController {
    start_time: Instant,
    total_requests: AtomicU64,
    current_rate: AtomicU64,
    max_rate: u64,
    min_rate: u64,
    target_rate: AtomicU64,
    last_adjustment: AtomicU64,
    adjustment_interval: Duration,
}

impl RateController {
    pub fn new(max_rate: u64, min_rate: u64) -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: AtomicU64::new(0),
            current_rate: AtomicU64::new(max_rate),
            max_rate,
            min_rate,
            target_rate: AtomicU64::new(max_rate),
            last_adjustment: AtomicU64::new(0),
            adjustment_interval: Duration::from_millis(100),
        }
    }

    pub async fn wait(&self) {
        let requests = self.total_requests.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let current_rate = requests as f64 / elapsed;

        if current_rate > self.current_rate.load(Ordering::Relaxed) as f64 {
            let delay = Duration::from_secs_f64(1.0 / self.current_rate.load(Ordering::Relaxed) as f64);
            sleep(delay).await;
        }
    }

    pub fn increment_requests(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn adjust_rate(&self, success_rate: f64, response_time: Duration) {
        let now = Instant::now();
        let last_adjustment = self.last_adjustment.load(Ordering::Relaxed);
        let elapsed = now.duration_since(Instant::now() - Duration::from_secs(last_adjustment as u64));
        
        if elapsed < self.adjustment_interval {
            return;
        }

        let current_rate = self.current_rate.load(Ordering::Relaxed);
        let mut new_target_rate = current_rate;

        if success_rate > 0.95 && response_time < Duration::from_millis(50) {
            new_target_rate = (current_rate as f64 * 1.2) as u64;
        } else if success_rate < 0.9 || response_time > Duration::from_millis(200) {
            new_target_rate = (current_rate as f64 * 0.9) as u64;
        }

        new_target_rate = new_target_rate.clamp(self.min_rate, self.max_rate);
        self.target_rate.store(new_target_rate, Ordering::Relaxed);
        self.current_rate.store(new_target_rate, Ordering::Relaxed);
        self.last_adjustment.store(now.elapsed().as_secs(), Ordering::Relaxed);
    }

    pub fn get_current_rate(&self) -> u64 {
        self.current_rate.load(Ordering::Relaxed)
    }

    pub fn get_total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_controller() {
        let controller = RateController::new(1000, 100);
        assert_eq!(controller.get_current_rate(), 1000);

        // 测试速率调整
        controller.adjust_rate(0.99, Duration::from_millis(50));
        assert!(controller.get_current_rate() > 1000);

        // 测试等待
        controller.increment_requests();
        controller.wait().await;
    }
} 