// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! `TSan` 数据竞争冒烟测试（docs/04-TEST-MATRIX.md 第 2 级 Required，M2 激活）。
//!
//! 在真实多线程调度下驱动 L2 背压原语的并发包装（std Mutex/Condvar），
//! 由 -Zsanitizer=thread 检测数据竞争；loom 负责全交错正确性，TSan 负责
//! 真实硬件内存模型下的竞争检出，两者互补（规约补充 1：TSan 先于 `ASan`）。
//!
//! 运行方式（nightly + 重建标准库）：
//!   RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test -p xs-l2-res \
//!     --test `tsan_smoke` --target x86_64-unknown-linux-gnu -Zbuild-std

use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use xs_l2_res::{AuditChannel, Backpressure, BoundedQueue, TokenBucket};

/// 多线程并发 acquire 互斥令牌桶：TSan 下不得报数据竞争。
#[test]
fn tsan_token_bucket_shared_mutex() {
    let bucket = Arc::new(Mutex::new(TokenBucket::new(4, 10_000.0)));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let bucket = Arc::clone(&bucket);
        handles.push(thread::spawn(move || {
            for _ in 0..8 {
                let mut guard = bucket.lock().unwrap();
                let _ = matches!(guard.acquire(), Backpressure::Admitted);
                drop(guard);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

/// 多线程并发写审计通道：record/take 交叉，TSan 下不得报数据竞争。
#[test]
fn tsan_audit_channel_shared_mutex() {
    let channel = Arc::new(Mutex::new(AuditChannel::new(8)));
    let mut handles = Vec::new();
    for t in 0..2u32 {
        let channel = Arc::clone(&channel);
        handles.push(thread::spawn(move || {
            for i in 0..16 {
                let mut guard = channel.lock().unwrap();
                let _ = guard.record(t * 100 + i);
                if i % 3 == 0 {
                    let _ = guard.take();
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let guard = channel.lock().unwrap();
    let _ = guard.dropped_count();
    let _ = guard.pending();
}

/// Mutex+Condvar 有界队列并发生产消费：TSan 下不得报数据竞争、不得死锁。
#[test]
fn tsan_bounded_queue_condvar_pipeline() {
    struct Shared {
        queue: BoundedQueue<u32>,
        done: bool,
    }
    let pair = Arc::new((
        Mutex::new(Shared {
            queue: BoundedQueue::new(2),
            done: false,
        }),
        Condvar::new(),
    ));

    let producer_pair = Arc::clone(&pair);
    let producer = thread::spawn(move || {
        let (lock, cvar) = &*producer_pair;
        for i in 0..16u32 {
            let mut shared = lock.lock().unwrap();
            while shared.queue.len() >= 2 {
                shared = cvar.wait(shared).unwrap();
            }
            let _ = shared.queue.push(i);
            cvar.notify_one();
        }
        let mut shared = lock.lock().unwrap();
        shared.done = true;
        cvar.notify_one();
    });

    let consumer_pair = Arc::clone(&pair);
    let consumer = thread::spawn(move || {
        let (lock, cvar) = &*consumer_pair;
        let mut got = 0u32;
        let mut shared = lock.lock().unwrap();
        loop {
            if shared.queue.pop().is_some() {
                got += 1;
                cvar.notify_one();
            } else if shared.done {
                break;
            } else {
                shared = cvar.wait(shared).unwrap();
            }
        }
        got
    });

    producer.join().unwrap();
    assert_eq!(consumer.join().unwrap(), 16);
}
