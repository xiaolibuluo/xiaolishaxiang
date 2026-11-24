// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M2 Required 容错与崩溃测试（docs/04-TEST-MATRIX.md 第 2 级）。
//!
//! 容错：错误注入后按策略降级/显式失败（SP-G-01 fail-closed），不产生
//!       『看着隔离其实没隔离』的静默中间态；
//! 崩溃：沙箱内进程 panic/abort/段错误被限制在沙箱边界内，supervisor 正常回收
//!       且后续沙箱实例不受影响（边界不被击穿、可恢复）。

use std::path::PathBuf;
use std::sync::Mutex;

use xs_l1_sys::{DomainSpec, ExitStatus, L1Domain, SandboxCommand};

/// 本文件全部用例的互斥锁：用例各自在 `collect_inherited_fds` 后 spawn，并行线程间
/// 存在 fd 竞态窗口（release 模式回归实证 crash/exit 用例偶发失败），必须串行。
static SPAWN_TEST_LOCK: Mutex<()> = Mutex::new(());

/// 收集当前进程持有的 fd（fork 前调用；/proc 此时未被 landlock 限制）。
///
/// cargo test 运行器持有输出捕获管道等框架 fd（M2 排障实证 spawn 子进程继承
/// 18/28 后被白名单检出 126 退出——这正是 SP-L1-04 fail-closed 的正确行为）。
/// 真实 supervisor 依 docs/01 SP-L1-04 须在 fork 前收紧自身 fd 集；测试的合规
/// 形态是把框架 fd 纳入白名单。
fn collect_inherited_fds() -> Vec<i32> {
    std::fs::read_dir("/proc/self/fd")
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// 基于最小 spec 构造域，白名单覆盖框架继承 fd。
fn establish_with_inherited_fds(mut spec: DomainSpec) -> Option<L1Domain> {
    let inherited = collect_inherited_fds();
    spec.fd_whitelist.extend(inherited);
    L1Domain::establish(spec).ok().or_else(|| {
        eprintln!("not_applicable: 环境不足以建立 L1 域（effective=C）");
        None
    })
}

/// 探测环境可建立性；C 档按规约标记 `not_applicable`。
fn require_domain() -> Option<L1Domain> {
    establish_with_inherited_fds(DomainSpec::minimal())
}

/// 构造带 /bin /usr /lib /lib64 只读授权的域（使 /bin/sh 可加载执行；不授权 /etc）。
///
/// `DomainSpec` 字段公开，establish 前按需扩展授权集——与编排层 xs-api 的真实用法一致，
/// 不为测试在 supervisor 上开设后门接口。
fn require_domain_with_sh() -> Option<L1Domain> {
    let mut spec = DomainSpec::minimal();
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/bin"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/usr"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/lib"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/lib64"));
    establish_with_inherited_fds(spec)
}

/// 构造一个最小沙箱命令。
fn cmd(program: &str, args: &[&str]) -> SandboxCommand {
    SandboxCommand {
        program: PathBuf::from(program),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        env: vec![],
    }
}

// ------------------------------------------------------------------ 容错

/// 容错：exec 不存在的程序——隔离域建立成功但 execve 失败，
/// 子进程必须以退出码 127 显式失败（SP-G-01：禁止静默降级为未隔离执行）。
#[test]
fn fault_exec_missing_program_exits_127() {
    let _guard = SPAWN_TEST_LOCK.lock().unwrap();
    let Some(domain) = require_domain() else {
        return;
    };
    let pid = domain
        .spawn(&cmd("/nonexistent/xs-no-such-binary", &[]))
        .expect("spawn 本身应成功（失败发生在子进程 exec 阶段）");
    let status = domain.wait(pid).expect("wait 应成功");
    assert_eq!(
        status,
        ExitStatus::Exited(127),
        "exec 失败必须以 127 显式退出（与建立失败 126 区分）"
    );
}

/// 容错：沙箱内访问未授权路径——landlock 域在真实 spawn 的 /bin/sh 内生效，
/// 读取 /etc/hostname 必须失败（EACCES），sh 以非零码退出。
///
/// 注意：/bin/sh 自身需要在授权路径内才可 exec；最小域 grants 为空，
/// 故 /bin/sh 无法执行（exec 被 landlock 拦截前 execve 需读二进制——
/// landlock 不拦截 execve 本身，但 sh 启动后读 /etc/hostname 被拒）。
#[test]
fn fault_unauthorized_path_denied_in_real_sandbox() {
    let _guard = SPAWN_TEST_LOCK.lock().unwrap();
    let Some(domain) = require_domain_with_sh() else {
        return;
    };
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", "cat /etc/hostname"]))
        .expect("spawn 应成功");
    let status = domain.wait(pid).expect("wait 应成功");
    // sh 的 cat 被 landlock 拒绝（EACCES）→ sh 以非零码退出
    assert_ne!(
        status,
        ExitStatus::Exited(0),
        "SP-L1-01 失败：沙箱内未授权路径 /etc/hostname 竟可读取"
    );
}

// ------------------------------------------------------------------ 崩溃

/// 崩溃：沙箱内进程触发 SIGSEGV——supervisor 必须回收为 Signaled(SIGSEGV)，
/// 崩溃被限制在沙箱边界内，不波及 supervisor 自身。
#[test]
fn crash_segv_contained_and_reaped() {
    let _guard = SPAWN_TEST_LOCK.lock().unwrap();
    let Some(domain) = require_domain_with_sh() else {
        return;
    };
    // 向自身进程组发送 SIGSEGV 模拟段错误崩溃（kill -SEGV $$：进程组 0 = 自身，
    // 规避 $ 展开依赖——沙箱内 sh 初始化告警时 $ 展开可能受损）。
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", "kill -SEGV $$"]))
        .expect("spawn 应成功");
    let status = domain.wait(pid).expect("wait 应成功");
    assert_eq!(
        status,
        ExitStatus::Signaled(libc::SIGSEGV),
        "崩溃必须被回收为 Signaled(SIGSEGV)，不得表现为正常退出"
    );
}

/// 崩溃恢复：同一 domain 连续 spawn——先崩溃实例后正常实例，互不影响。
///
/// 验证崩溃不产生全局污染（supervisor 状态、后续实例的隔离域建立均正常）。
#[test]
fn crash_then_normal_spawn_recovers() {
    let _guard = SPAWN_TEST_LOCK.lock().unwrap();
    let Some(domain) = require_domain_with_sh() else {
        return;
    };
    // 实例 1：崩溃（SIGABRT，模拟 panic/abort 注入；kill -ABRT $$ = 自身进程组）
    let pid1 = domain
        .spawn(&cmd("/bin/sh", &["-c", "kill -ABRT $$"]))
        .expect("spawn 崩溃实例应成功");
    let st1 = domain.wait(pid1).expect("回收崩溃实例应成功");
    assert_eq!(st1, ExitStatus::Signaled(libc::SIGABRT));

    // 实例 2：正常命令——崩溃不得影响后续沙箱
    let pid2 = domain
        .spawn(&cmd("/bin/true", &[]))
        .expect("崩溃后 spawn 正常实例应成功");
    let st2 = domain.wait(pid2).expect("回收正常实例应成功");
    assert_eq!(
        st2,
        ExitStatus::Exited(0),
        "崩溃后后续沙箱实例必须正常工作（边界不被击穿、可恢复）"
    );
}

/// 容错：沙箱内程序非零退出码如实透传（不得被 supervisor 吞掉或改写）。
#[test]
fn fault_nonzero_exit_code_passthrough() {
    let _guard = SPAWN_TEST_LOCK.lock().unwrap();
    let Some(domain) = require_domain_with_sh() else {
        return;
    };
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", "exit 42"]))
        .expect("spawn 应成功");
    let status = domain.wait(pid).expect("wait 应成功");
    assert_eq!(
        status,
        ExitStatus::Exited(42),
        "沙箱退出码必须如实透传给 supervisor"
    );
}
