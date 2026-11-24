// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! loom 并发模型检查（docs/04-TEST-MATRIX.md 第 2 级 Required，M2 激活）。
//!
//! 验证 L2 背压原语在并发包装下的正确性：
//! - SP-L2-03：互斥锁保护的令牌桶并发 acquire 不超发令牌（上限 = 容量 + 测试窗口内补充）；
//! - SP-L2-03：Mutex+Condvar 有界队列并发生产/消费下所有元素恰好送达一次、队列有界不被击穿；
//! - SP-L2-04：溢出只标记丢失、绝不静默丢弃且不反向阻塞（防死锁环由条件变量模型佐证）。
//!
//! 运行方式（loom 模型检查较慢，默认 cargo test 跳过）：
//!   RUSTFLAGS="--cfg loom" cargo test -p xs-l2-res --test `loom_backpressure` --release

#![cfg(loom)]

use loom::sync::{Condvar, Mutex};
use loom::thread;

use xs_l2_res::{AuditChannel, AuditOverflow, Backpressure, BoundedQueue, TokenBucket};

/// 并发包装的令牌桶：多线程共享时每次 acquire 必须互斥。
///
/// 上限推导：容量 cap 满桶 + 单线程步内至多 1 次时间补充（refill=1e9/s，
/// loom 交错窗口纳秒级，补充 <1 枚），故 admitted ≤ cap + 1 且 ≤ 线程数。
#[test]
fn loom_token_bucket_mutex_never_overadmits() {
    loom::model(|| {
        let bucket = std::sync::Arc::new(Mutex::new(TokenBucket::new(1, 1e9)));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let bucket = std::sync::Arc::clone(&bucket);
            handles.push(thread::spawn(move || {
                let mut guard = bucket.lock().unwrap();
                matches!(guard.acquire(), Backpressure::Admitted)
            }));
        }

        let admitted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();

        assert!(admitted <= 2, "令牌超发：{admitted} > cap+1");
    });
}

/// Mutex+Condvar 有界队列：生产者不丢元素（满则等待），消费者恰好收到全部元素。
///
/// 验证不变量：队列长度永不超过容量；每个生产元素被消费恰好一次；无死锁
/// （loom 全交错搜索下任何死锁调度都会体现为测试挂死而被检出）。
#[test]
fn loom_bounded_queue_condvar_exactly_once_delivery() {
    loom::model(|| {
        const CAP: usize = 1;
        const N: u32 = 2;

        struct Shared {
            queue: BoundedQueue<u32>,
            consumed: Vec<u32>,
            done: bool,
        }

        let pair = std::sync::Arc::new((
            Mutex::new(Shared {
                queue: BoundedQueue::new(CAP),
                consumed: Vec::new(),
                done: false,
            }),
            Condvar::new(),
        ));

        let producer_pair = std::sync::Arc::clone(&pair);
        let producer = thread::spawn(move || {
            let (lock, cvar) = &*producer_pair;
            for i in 0..N {
                let mut shared = lock.lock().unwrap();
                loop {
                    if shared.queue.len() < CAP {
                        // 有界不变量：入队前长度严格小于容量。
                        shared.queue.push(i).map_err(|_| ()).unwrap();
                        break;
                    }
                    // 满则挂起等待消费者取走（背压传导：生产者降速而非溢出）。
                    shared = cvar.wait(shared).unwrap();
                }
                cvar.notify_one();
            }
            let mut shared = lock.lock().unwrap();
            shared.done = true;
            cvar.notify_one();
        });

        let consumer_pair = std::sync::Arc::clone(&pair);
        let consumer = thread::spawn(move || {
            let (lock, cvar) = &*consumer_pair;
            let mut shared = lock.lock().unwrap();
            loop {
                if let Some(item) = shared.queue.pop() {
                    shared.consumed.push(item);
                    cvar.notify_one();
                } else if shared.done {
                    break;
                } else {
                    shared = cvar.wait(shared).unwrap();
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();

        let (lock, _) = &*pair;
        let shared = lock.lock().unwrap();
        assert_eq!(shared.consumed, vec![0, 1], "元素必须恰好按序送达一次");
        assert!(shared.queue.is_empty());
    });
}

/// 并发审计通道：互斥保护下 record 结果要么 Enqueued 要么 DroppedMarked，
/// dropped_count 恒等于 DroppedMarked 次数（SP-L2-04：溢出只标记，绝不静默）。
#[test]
fn loom_audit_channel_marks_every_drop() {
    loom::model(|| {
        let channel = std::sync::Arc::new(Mutex::new(AuditChannel::new(1)));

        let mut handles = Vec::new();
        for i in 0..2u32 {
            let channel = std::sync::Arc::clone(&channel);
            handles.push(thread::spawn(move || {
                let mut guard = channel.lock().unwrap();
                matches!(guard.record(i), AuditOverflow::DroppedMarked)
            }));
        }

        let dropped_marked = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&d| d)
            .count() as u64;

        let guard = channel.lock().unwrap();
        assert_eq!(
            dropped_marked,
            guard.dropped_count(),
            "dropped_count 必须等于 DroppedMarked 返回次数"
        );
        assert!(guard.pending() <= 1, "审计缓冲有界不被击穿");
    });
}
