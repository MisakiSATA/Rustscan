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
    success_count: AtomicU64,
    failure_count: AtomicU64,
    last_response_time: AtomicU64,
    last_second_requests: AtomicU64,
    last_second_time: AtomicU64,
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
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
            last_response_time: AtomicU64::new(0),
            last_second_requests: AtomicU64::new(0),
            last_second_time: AtomicU64::new(0),
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

        // 检查当前秒内的请求数是否超过限制
        let current_requests = self.last_second_requests.load(Ordering::Relaxed);
        if current_requests > self.current_rate.load(Ordering::Relaxed) {
            let delay = Duration::from_secs_f64(1.0 / self.current_rate.load(Ordering::Relaxed) as f64);
            sleep(delay).await;
        }
    }

    pub fn increment_requests(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn adjust_rate(&self, success: bool, response_time: Duration) {
        let now = Instant::now();
        let last_adjustment = self.last_adjustment.load(Ordering::Relaxed);
        let elapsed = now.duration_since(Instant::now() - Duration::from_secs(last_adjustment as u64));
        
        if elapsed < self.adjustment_interval {
            return;
        }

        // 更新成功/失败计数
        if success {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failure_count.fetch_add(1, Ordering::Relaxed);
        }

        // 更新响应时间
        self.last_response_time.store(response_time.as_millis() as u64, Ordering::Relaxed);

        // 计算成功率
        let total = self.success_count.load(Ordering::Relaxed) + self.failure_count.load(Ordering::Relaxed);
        let success_rate = if total > 0 {
            self.success_count.load(Ordering::Relaxed) as f64 / total as f64
        } else {
            1.0
        };

        let current_rate = self.current_rate.load(Ordering::Relaxed);
        let mut new_target_rate = current_rate;

        // 根据成功率和响应时间动态调整速率
        if success_rate > 0.95 && response_time < Duration::from_millis(50) {
            // 如果成功率高且响应时间短，增加速率
            new_target_rate = (current_rate as f64 * 1.2) as u64;
        } else if success_rate < 0.9 || response_time > Duration::from_millis(200) {
            // 如果成功率低或响应时间长，降低速率
            new_target_rate = (current_rate as f64 * 0.8) as u64;
        } else if success_rate > 0.8 && response_time < Duration::from_millis(100) {
            // 如果成功率适中且响应时间可接受，小幅增加速率
            new_target_rate = (current_rate as f64 * 1.1) as u64;
        }

        // 确保速率在允许范围内
        new_target_rate = new_target_rate.clamp(self.min_rate, self.max_rate);
        
        // 应用新的目标速率
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

    pub fn get_requests_per_second(&self) -> u64 {
        self.last_second_requests.load(Ordering::Relaxed)
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
        controller.adjust_rate(true, Duration::from_millis(50));
        assert!(controller.get_current_rate() > 1000);

        // 测试等待
        controller.increment_requests();
        controller.wait().await;
    }
} 