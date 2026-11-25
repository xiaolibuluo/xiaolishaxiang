// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! 审计日志：JSONL 格式异步落盘，记录沙箱生命周期事件。

use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::warn;

/// 审计事件类型。
#[derive(Debug, Clone, Copy, Serialize)]
pub enum AuditEventKind {
    Create,
    Run,
    Destroy,
}

impl AuditEventKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Run => "run",
            Self::Destroy => "destroy",
        }
    }
}

/// 单条审计记录（一行 JSONL）。
#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    ts: String,
    trace_id: &'a str,
    tenant_id: &'a str,
    sandbox_id: &'a str,
    event: &'a str,
    result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// 审计日志写入器：异步追加 JSONL，失败降级为 warn（不阻断请求）。
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<AuditInner>,
}

struct AuditInner {
    path: PathBuf,
    file: Mutex<Option<tokio::fs::File>>,
    enabled: bool,
}

impl AuditLog {
    /// 创建审计日志。打开文件失败时降级为 disabled（仅 warn，不 panic）。
    pub async fn new(path: PathBuf) -> Self {
        let file = match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
        {
            Ok(f) => {
                tracing::info!("审计日志已启用: {}", path.display());
                Some(f)
            }
            Err(e) => {
                warn!("审计日志打开失败（降级禁用）: {} err={e}", path.display());
                None
            }
        };
        Self {
            inner: Arc::new(AuditInner {
                path,
                file: Mutex::new(file),
                enabled: true,
            }),
        }
    }

    /// 记录一条审计事件。result 约定为 "ok" 或 "error"。
    pub async fn record(
        &self,
        kind: AuditEventKind,
        trace_id: &str,
        tenant_id: &str,
        sandbox_id: &str,
        result: &str,
        detail: Option<String>,
    ) {
        if !self.inner.enabled {
            return;
        }
        let record = AuditRecord {
            ts: now_iso8601(),
            trace_id,
            tenant_id,
            sandbox_id,
            event: kind.as_str(),
            result,
            detail,
        };
        let mut line = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(e) => {
                warn!("审计记录序列化失败: {e}");
                return;
            }
        };
        line.push('\n');

        let mut guard = self.inner.file.lock().await;
        if let Some(f) = guard.as_mut() {
            let write_result = f.write_all(line.as_bytes()).await;
            let flush_result = match write_result {
                Ok(()) => f.flush().await,
                Err(e) => Err(e),
            };
            if let Err(e) = flush_result {
                warn!(
                    "审计日志写入/落盘失败（后续禁用）: {} err={e}",
                    self.inner.path.display()
                );
                *guard = None;
            }
        }
    }
}

/// 当前时间的 ISO 8601（UTC）表示。
fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_iso8601(secs)
}

fn unix_to_iso8601(secs: u64) -> String {
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let (hours, minutes, seconds) = (time_secs / 3600, (time_secs % 3600) / 60, time_secs % 60);

    let mut year = 1970i64;
    let mut remaining = days as i64;
    loop {
        let yd = if is_leap(year) { 366 } else { 365 };
        if remaining < yd {
            break;
        }
        remaining -= yd;
        year += 1;
    }
    let mdays: [i64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u32;
    for &md in &mdays {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        remaining + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_epoch() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_known_date() {
        // 2024-02-29 12:00:00 UTC = 1709208000
        assert_eq!(unix_to_iso8601(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[tokio::test]
    async fn audit_write_and_disable_on_missing_dir() {
        let dir = std::env::temp_dir().join(format!("xs-audit-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");

        let log = AuditLog::new(path.clone()).await;
        log.record(
            AuditEventKind::Create,
            "trace-1",
            "tenant-a",
            "sandbox-1",
            "ok",
            Some("latency_us=123".into()),
        )
        .await;
        drop(log);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"event\":\"create\""));
        assert!(content.contains("\"trace_id\":\"trace-1\""));
        assert!(content.contains("\"sandbox_id\":\"sandbox-1\""));
        std::fs::remove_dir_all(&dir).ok();
    }
}
