use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time;

pub struct RateController {
    start_time: Instant,
    total_requests: AtomicU64,
    current_rate: AtomicU64,
    max_rate: u64,
    min_rate: u64,
    last_adjustment: Instant,
    adjustment_interval: Duration,
    last_second_requests: AtomicU64,
    last_second_time: AtomicU64,
    last_request_time: AtomicU64,
}

impl RateController {
    pub fn new(max_rate: u64, min_rate: u64) -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: AtomicU64::new(0),
            current_rate: AtomicU64::new(max_rate),
            max_rate,
            min_rate,
            last_adjustment: Instant::now(),
            adjustment_interval: Duration::from_millis(100),
            last_second_requests: AtomicU64::new(0),
            last_second_time: AtomicU64::new(0),
            last_request_time: AtomicU64::new(0),
        }
    }

    pub async fn wait(&self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.start_time).as_secs();

        // 每秒重置请求计数
        if elapsed > self.last_second_time.load(Ordering::Relaxed) {
            self.last_second_requests.store(0, Ordering::Relaxed);
            self.last_second_time.store(elapsed, Ordering::Relaxed);
        }

        // 增加请求计数
        self.last_second_requests.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // 计算请求间隔
        let current_rate = self.current_rate.load(Ordering::Relaxed).max(1);
        let interval = Duration::from_secs_f64(1.0 / current_rate as f64);

        // 控制速率，避免自旋
        let last_request = self.last_request_time.load(Ordering::Relaxed);
        let now_ms = now.duration_since(self.start_time).as_millis() as u64;
        if now_ms > last_request {
            let next_time = last_request + interval.as_millis() as u64;
            if next_time > now_ms {
                time::sleep(Duration::from_millis(next_time - now_ms)).await;
            }
        }
        self.last_request_time.store(now_ms, Ordering::Relaxed);
    }

    pub fn increment_requests(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn adjust_rate(&mut self, success: bool, _response_time: Duration) {
        let now = Instant::now();
        if now.duration_since(self.last_adjustment) < self.adjustment_interval {
            return;
        }

        let current_rate = self.current_rate.load(Ordering::Relaxed);
        let new_rate = if success {
            // 如果成功，尝试增加速率，但增加幅度更小
            ((current_rate as f64 * 1.1) as u64).clamp(self.min_rate, self.max_rate)
        } else {
            // 如果失败，降低速率，但降低幅度更小
            ((current_rate as f64 * 0.9) as u64).clamp(self.min_rate, self.max_rate)
        };
        
        self.current_rate.store(new_rate, Ordering::Relaxed);
        self.last_adjustment = now;
    }

    pub fn get_current_rate(&self) -> u64 {
        self.current_rate.load(Ordering::Relaxed)
    }

    pub fn get_total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn get_requests_per_second(&self) -> u64 {
        self.last_second_requests.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_controller() {
        let mut controller = RateController::new(1000, 100);
        assert_eq!(controller.get_current_rate(), 1000);

        // 测试速率调整
        controller.adjust_rate(true, Duration::from_millis(50));
        assert!(controller.get_current_rate() > 1000);

        // 测试等待
        controller.increment_requests();
        controller.wait().await;
    }
}