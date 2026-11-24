// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 背压与限流（SP-L2-03 / SP-L2-04 实现）。
//!
//! - 令牌桶限速器：洪流注入下不丢控、队列有界，触发限流时返回显式背压信号
//!   而非静默阻塞（SP-L2-03）；
//! - 审计通道独立配额：审计缓冲溢出时的降级是『标记事件丢失』而非静默丢弃
//!   （SP-L2-04），审计 sink 缓慢不得阻塞业务通道（防死锁环）。

use std::time::{Duration, Instant};

/// 背压信号（SP-L2-03：触发限流时调用方收到显式信号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backpressure {
    /// 允许通过（令牌已消耗）。
    Admitted,
    /// 触发限流被拒绝（调用方应排队、重试或降级，绝不静默阻塞）。
    Throttled {
        /// 距下一个令牌可用的预估等待时间。
        retry_after: Duration,
    },
}

impl Backpressure {
    /// 是否被限流。
    #[must_use]
    pub fn is_throttled(self) -> bool {
        matches!(self, Self::Throttled { .. })
    }
}

/// 令牌桶限速器。
///
/// 容量 capacity、匀速 `refill_per_sec` 补充； `acquire()` 原子语义由调用方保证
/// （单线程或外部锁），M2 的 loom 并发用例将验证并发包装的正确性。
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// 创建令牌桶（初始满桶）。
    #[must_use]
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: f64::from(capacity),
            tokens: f64::from(capacity),
            refill_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last_refill = now;
    }

    /// 尝试获取一个令牌；返回显式背压信号。
    pub fn acquire(&mut self) -> Backpressure {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Backpressure::Admitted
        } else {
            let deficit = 1.0 - self.tokens;
            let wait = if self.refill_per_sec > 0.0 {
                Duration::from_secs_f64(deficit / self.refill_per_sec)
            } else {
                Duration::MAX
            };
            Backpressure::Throttled { retry_after: wait }
        }
    }

    /// 当前可用令牌数（观测用）。
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens as u64
    }
}

/// 有界队列（SP-L2-03：队列必须有界，满了返回显式背压）。
#[derive(Debug)]
pub struct BoundedQueue<T> {
    cap: usize,
    items: std::collections::VecDeque<T>,
}

impl<T> BoundedQueue<T> {
    /// 创建容量为 cap 的有界队列。
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            items: std::collections::VecDeque::with_capacity(cap),
        }
    }

    /// 入队；满时返回 Err（显式背压，绝不无限堆积）。
    pub fn push(&mut self, item: T) -> Result<(), T> {
        if self.items.len() >= self.cap {
            return Err(item);
        }
        self.items.push_back(item);
        Ok(())
    }

    /// 出队。
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    /// 当前长度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 容量。
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap
    }
}

/// 审计通道溢出时的处置结果（SP-L2-04）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOverflow {
    /// 已入队。
    Enqueued,
    /// 缓冲已满：事件被标记为丢失（写入丢失计数并产生标记事件），
    /// 绝不静默丢弃。
    DroppedMarked,
}

/// 审计通道独立配额缓冲。
///
/// 独立于业务背压：业务通道被限流不影响审计入队；审计缓冲满时
/// 只影响审计自身（标记丢失），不反向阻塞业务（防死锁环）。
#[derive(Debug)]
pub struct AuditChannel<T> {
    queue: BoundedQueue<T>,
    dropped: u64,
}

impl<T> AuditChannel<T> {
    /// 创建审计通道（独立配额 cap）。
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            queue: BoundedQueue::new(cap),
            dropped: 0,
        }
    }

    /// 写入审计事件；溢出时计入丢失计数并返回 `DroppedMarked`。
    pub fn record(&mut self, event: T) -> AuditOverflow {
        match self.queue.push(event) {
            Ok(()) => AuditOverflow::Enqueued,
            Err(_event) => {
                self.dropped += 1;
                AuditOverflow::DroppedMarked
            }
        }
    }

    /// 取出下一条待写事件。
    pub fn take(&mut self) -> Option<T> {
        self.queue.pop()
    }

    /// 已标记丢失的事件数（溢出降级的可观测证据，必入审计报告）。
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// 当前积压量。
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_limits_burst() {
        let mut b = TokenBucket::new(3, 1000.0);
        assert_eq!(b.available(), 3, "初始应满桶 3 tokens");
        assert_eq!(b.acquire(), Backpressure::Admitted);
        assert_eq!(b.available(), 2);
        assert_eq!(b.acquire(), Backpressure::Admitted);
        assert_eq!(b.acquire(), Backpressure::Admitted);
        assert_eq!(b.available(), 0, "三次 acquire 后 tokens 应为 0");
        let bp = b.acquire();
        assert!(bp.is_throttled());
        if let Backpressure::Throttled { retry_after } = bp {
            assert!(retry_after > Duration::ZERO, "重试等待应 > 0");
        }
    }

    #[test]
    fn backpressure_is_throttled_both_sides() {
        assert!(!Backpressure::Admitted.is_throttled());
        assert!(Backpressure::Throttled {
            retry_after: Duration::from_secs(1)
        }
        .is_throttled());
    }

    #[test]
    fn token_bucket_zero_refill_stays_empty() {
        let mut b = TokenBucket::new(1, 0.0);
        assert_eq!(b.acquire(), Backpressure::Admitted);
        let bp = b.acquire();
        assert!(bp.is_throttled());
        if let Backpressure::Throttled { retry_after } = bp {
            assert_eq!(retry_after, Duration::MAX);
        }
    }

    #[test]
    fn token_bucket_refills() {
        let mut b = TokenBucket::new(1, 10_000.0);
        assert_eq!(b.acquire(), Backpressure::Admitted);
        assert!(b.acquire().is_throttled());
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(b.acquire(), Backpressure::Admitted);
    }

    #[test]
    fn bounded_queue_never_overflows() {
        let mut q = BoundedQueue::new(2);
        assert!(q.push(1).is_ok());
        assert!(q.push(2).is_ok());
        // 第 3 个被拒（队列有界，显式背压）
        assert_eq!(q.push(3), Err(3));
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop(), Some(1));
        assert!(q.push(3).is_ok());
        assert_eq!(q.len(), 2);
        assert!(!q.is_empty());
        assert_eq!(q.capacity(), 2);
        // 清空后 pop 返回 None
        q.pop();
        q.pop();
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
        assert_eq!(q.pop(), None, "空队列 pop 应返回 None");
    }

    #[test]
    fn bounded_queue_len_at_different_fills() {
        let mut q = BoundedQueue::<i32>::new(10);
        assert_eq!(q.len(), 0);
        q.push(1).unwrap();
        assert_eq!(q.len(), 1);
        q.push(2).unwrap();
        q.push(3).unwrap();
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn audit_channel_take_from_empty_returns_none() {
        let mut ch = AuditChannel::<&str>::new(2);
        assert_eq!(ch.take(), None);
        assert_eq!(ch.pending(), 0);
        assert_eq!(ch.dropped_count(), 0);
    }

    #[test]
    fn audit_channel_marks_dropped() {
        let mut ch = AuditChannel::new(2);
        assert_eq!(ch.record("e1"), AuditOverflow::Enqueued);
        assert_eq!(ch.record("e2"), AuditOverflow::Enqueued);
        // 溢出：标记丢失而非静默丢弃
        assert_eq!(ch.record("e3"), AuditOverflow::DroppedMarked);
        assert_eq!(ch.dropped_count(), 1);
        assert_eq!(ch.pending(), 2);
        assert_eq!(ch.take(), Some("e1"));
        // 腾出位置后可再入队
        assert_eq!(ch.record("e4"), AuditOverflow::Enqueued);
    }
}
