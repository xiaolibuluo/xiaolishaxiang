// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! seccomp BPF 过滤器构建与安装（SP-L1-03 的 Rust 实现）。
//!
//! 设计直接来自 M0 Spike 实测结论（spike/spike2.py，P2a/P2b/P3 全部通过）：
//! - allowlist 模式：未列出的 syscall 默认拒绝，禁止 denylist；
//! - `io_uring_setup/enter/register` 默认不在 allowlist（SP-L1-03）；
//! - 多线程安装必须带 TSYNC，否则 filter 只作用于安装线程（P2b 实测证实）；
//! - 安装被拒的错误码可能是 EPERM 或 EACCES（Ubuntu AppArmor，P2a 实测），两者都必须识别为『被拒绝』。
//!
//! 安装顺序契约（fail-closed）：必须先 `no_new_privs，再装` filter，最后 exec。

use xs_core::{XsError, XsResult};

/// BPF 指令操作码（与内核 seccomp BPF 子集一致）。
const BPF_LD: u16 = 0x20;
const BPF_JEQ: u16 = 0x15;
const BPF_RET: u16 = 0x06;

/// seccomp 返回值。
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// 拒绝时返回的 errno（EPERM，与 Spike 原型一致）。
const DENY_ERRNO: u32 = 1;

/// `x86_64` `架构标识（AUDIT_ARCH_X86_64`）。
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// seccomp 数据结构中 arch 字段的偏移（字节）。
const OFFSET_ARCH: u32 = 4;
/// seccomp 数据结构中 nr（syscall 号）字段的偏移（字节）。
const OFFSET_NR: u32 = 0;

/// `sock_filter` 单条 BPF 指令（与内核 struct `sock_filter` 布局一致）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SockFilter {
    const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// `sock_fprog：传递给内核的过滤器程序描述`。
#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const SockFilter,
}

/// seccomp allowlist 过滤器。
///
/// 只允许显式列出的 syscall `号；io_uring` 三件套默认被排除（SP-L1-03）。
#[derive(Debug, Clone)]
pub struct SeccompAllowlist {
    allowed: Vec<u32>,
}

impl SeccompAllowlist {
    /// 沙箱最小 allowlist：进程生命周期与隔离域内基本运转所需。
    ///
    /// 注意：明确不包含 `io_uring_setup(425)/io_uring_enter(426)/io_uring_register(427)`。
    #[must_use]
    pub fn sandbox_minimal() -> Self {
        let allowed = vec![
            libc::SYS_read as u32,
            libc::SYS_write as u32,
            libc::SYS_exit as u32,
            libc::SYS_exit_group as u32,
            libc::SYS_rt_sigreturn as u32,
            libc::SYS_rt_sigaction as u32,
            libc::SYS_rt_sigprocmask as u32,
            libc::SYS_brk as u32,
            libc::SYS_mmap as u32,
            libc::SYS_munmap as u32,
            libc::SYS_mprotect as u32,
            libc::SYS_close as u32,
            libc::SYS_fstat as u32,
            libc::SYS_getpid as u32,
            libc::SYS_gettid as u32,
            libc::SYS_sched_yield as u32,
            libc::SYS_nanosleep as u32,
            libc::SYS_clock_nanosleep as u32,
            // execve 必须在列：顺序契约在 exec 之前安装 filter（步骤 4），缺 execve
            // 则任何 spawn 都以 127 失败、契约永远无法到达 exec（M2 容错测试实证发现）。
            libc::SYS_execve as u32,
            // 动态链接程序自举最小集：ld-linux 加载共享库需 openat/pread64/newfstatat 等；
            // 缺以下任一项，动态链接程序 exec 后以 127 或崩溃退出（M2 容错测试实证）。
            // 路径面由 landlock 治理（SP-L1-01），seccomp 只管 syscall 号不碰路径。
            libc::SYS_openat as u32,
            libc::SYS_access as u32,
            libc::SYS_newfstatat as u32,
            libc::SYS_pread64 as u32,
            libc::SYS_close_range as u32,
            libc::SYS_set_tid_address as u32,
            libc::SYS_set_robust_list as u32,
            libc::SYS_rseq as u32,
            libc::SYS_prlimit64 as u32,
            libc::SYS_getrandom as u32,
            libc::SYS_readlink as u32,
            // 身份/进程查询与 TLS 初始化（strace -c 实证 /bin/sh 启动必需）：
            // 纯查询类 syscall 不涉及路径与提权（no_new_privs 已阻断提权路径）。
            libc::SYS_getppid as u32,
            libc::SYS_getuid as u32,
            libc::SYS_geteuid as u32,
            libc::SYS_getgid as u32,
            libc::SYS_getegid as u32,
            libc::SYS_arch_prctl as u32,
            // 信号发送（kill 为 sh 内建）：沙箱内进程自毁/崩溃注入必需；
            // 跨进程信号面由 PID namespace 边界约束（SP-L1-06）。
            libc::SYS_kill as u32,
            libc::SYS_tgkill as u32,
            // stdio fd 健全性查询（strace 实证，2026-11-25）：Ubuntu coreutils 经 libselinux
            // 启动期调用 fcntl(0/1/2, F_GETFD) 与 poll(stdin/out/err, events=0) 检查 fd 状态，
            // 被默认 ERRNO(EPERM) 拒绝后进程自触发 SIGABRT（/bin/echo hello 实测复现）。
            // 两者均为只读元数据操作，不碰路径与提权面（no_new_privs 已阻断提权）。
            libc::SYS_fcntl as u32,
            libc::SYS_poll as u32,
            // 当前工作目录查询（同批 strace 实证）：/bin/sh 启动期调用 getcwd()，
            // 缺失时打印 'getcwd() failed: Operation not permitted' 警告噪音（不影响功能）。
            // 纯只读返回内核已知 cwd 字符串，不触碰路径授权面（路径面归 landlock）。
            libc::SYS_getcwd as u32,
        ];
        Self { allowed }
    }

    /// 显式追加一个允许的 syscall 号（配置驱动的能力放行）。
    #[must_use]
    pub fn allow(mut self, nr: u32) -> Self {
        if !self.allowed.contains(&nr) {
            self.allowed.push(nr);
        }
        self
    }

    /// `io_uring` 三件套是否被排除（SP-L1-03 对抗用例的断言点）。
    #[must_use]
    pub fn io_uring_blocked(&self) -> bool {
        const IO_URING_SETUP: u32 = 425;
        const IO_URING_ENTER: u32 = 426;
        const IO_URING_REGISTER: u32 = 427;
        !self.allowed.contains(&IO_URING_SETUP)
            && !self.allowed.contains(&IO_URING_ENTER)
            && !self.allowed.contains(&IO_URING_REGISTER)
    }

    /// 构建 BPF 指令序列。
    ///
    /// 结构：架构校验 -> 逐条比对 allowlist（命中即 ALLOW）-> 默认 ERRNO(EPERM)。
    fn build_program(&self) -> Vec<SockFilter> {
        let mut prog = Vec::with_capacity(self.allowed.len() + 5);
        // 1. 加载 arch 字段并校验：非 x86_64 直接 KILL（架构错配不容忍）。
        prog.push(SockFilter::stmt(BPF_LD, OFFSET_ARCH));
        let nr_jumps = self.allowed.len() as u8;
        prog.push(SockFilter::jump(
            BPF_JEQ,
            AUDIT_ARCH_X86_64,
            0,
            // 架构不匹配时跳过：nr 加载(1) + allowlist 比对(N) + ERRNO(1) + ALLOW(1)，落到 KILL
            nr_jumps + 3,
        ));
        // 2. 加载 syscall 号。
        prog.push(SockFilter::stmt(BPF_LD, OFFSET_NR));
        // 3. allowlist 逐条比对：命中跳到最后一条 ALLOW。
        for (i, nr) in self.allowed.iter().enumerate() {
            let remaining = (self.allowed.len() - i - 1) as u8;
            // 相等则跳过剩余比对和 ERRNO，落到 ALLOW（remaining + 1 条之后）
            prog.push(SockFilter::jump(BPF_JEQ, *nr, remaining + 1, 0));
        }
        // 4. 默认拒绝：ERRNO(EPERM)。
        prog.push(SockFilter::stmt(BPF_RET, SECCOMP_RET_ERRNO | DENY_ERRNO));
        // 5. 允许。
        prog.push(SockFilter::stmt(BPF_RET, SECCOMP_RET_ALLOW));
        // 6. 架构错配的终点：KILL_PROCESS。
        prog.push(SockFilter::stmt(BPF_RET, SECCOMP_RET_KILL_PROCESS));
        prog
    }
}

/// 设置 `no_new_privs（seccomp` 安装的先决条件，SP-L1-03 顺序契约第一步）。
pub fn set_no_new_privs() -> XsResult<()> {
    // SAFETY（安全论证）：
    // - prctl(PR_SET_NO_NEW_PRIVS, 1) 只影响调用进程，设置后不可清除，无指针参数；
    // - 这是 seccomp 非特权安装的合法前置，语义来自 prctl(2)；
    // - 失败返回 -1 + errno，显式上报，绝不静默继续。
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(XsError::IsolatorSetupFailed {
            mechanism: "seccomp".to_string(),
            detail: format!("设置 no_new_privs 失败: {err}"),
        });
    }
    Ok(())
}

/// 多线程安装标志：TSYNC（P2b 实测证明无 TSYNC 时 filter 只作用于安装线程）。
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SYS_SECCOMP: libc::c_long = 317;

/// 安装 seccomp 过滤器（顺序契约第二步，必须在 exec 之前完成）。
///
/// tsync = true 时作用于全部线程（多线程必须，P2b）。
/// 安装被拒（EPERM 或 EACCES）时返回显式错误，绝不静默成功（P2a）。
pub fn install(list: &SeccompAllowlist, tsync: bool) -> XsResult<()> {
    let prog = list.build_program();
    let fprog = SockFprog {
        len: prog.len() as libc::c_ushort,
        filter: prog.as_ptr(),
    };
    let flags: u32 = if tsync { SECCOMP_FILTER_FLAG_TSYNC } else { 0 };
    // SAFETY（安全论证）：
    // - prog 在调用期间存活，fprog.filter 指向其有效内存，内核只读该缓冲区；
    // - len 与 prog 实际长度一致，不存在越界读取；
    // - syscall(317, SECCOMP_SET_MODE_FILTER, flags, &fprog) 语义来自 seccomp(2)；
    // - 必须在 no_new_privs 之后调用（顺序契约），该约束由 establish() 流程保证；
    // - 返回值 0 成功 / -1 + errno，EPERM 与 EACCES 都识别为『被拒绝』（P2a 实测）。
    let ret = unsafe { libc::syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, flags, &fprog) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        let raw = err.raw_os_error().unwrap_or(-1);
        // EPERM(1) 与 EACCES(13) 都是『被拒绝』，但原因不同，错误信息要可定位。
        let reason = match raw {
            libc::EPERM => "被拒绝(EPERM)：可能缺少 no_new_privs 或无 CAP_SYS_ADMIN",
            libc::EACCES => {
                "被拒绝(EACCES)：AppArmor 等 LSM 限制非特权 seccomp 安装（Ubuntu 常见）"
            }
            _ => "安装失败",
        };
        return Err(XsError::IsolatorSetupFailed {
            mechanism: "seccomp".to_string(),
            detail: format!("{reason}: {err} (errno={raw})"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_excludes_io_uring() {
        let list = SeccompAllowlist::sandbox_minimal();
        assert!(list.io_uring_blocked());
    }

    #[test]
    fn program_structure_sane() {
        let list = SeccompAllowlist::sandbox_minimal();
        let prog = list.build_program();
        // 长度 = 2(arch) + 1(nr load) + N(allowlist) + 1(errno) + 1(allow) + 1(kill)
        assert_eq!(prog.len(), list.allowed.len() + 6);
        // 倒数第三条是默认 ERRNO
        let errno_insn = prog[prog.len() - 3];
        assert_eq!(errno_insn.code, BPF_RET);
        assert_eq!(errno_insn.k, SECCOMP_RET_ERRNO | DENY_ERRNO);
        // 最后一条是 KILL_PROCESS
        assert_eq!(prog[prog.len() - 1].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn jump_targets_are_correct() {
        // 跳转目标校验（M1 调试中捕获的真实缺陷：arch 失败分支曾错落到 ALLOW）
        let list = SeccompAllowlist::sandbox_minimal();
        let prog = list.build_program();
        // 架构校验失败分支必须落到 KILL_PROCESS
        let arch_insn = prog[1];
        let arch_target = 1 + 1 + arch_insn.jf as usize;
        assert_eq!(prog[arch_target].k, SECCOMP_RET_KILL_PROCESS);
        // 每条 allowlist 命中必须落到 ALLOW
        for i in 0..list.allowed.len() {
            let idx = 3 + i;
            let target = idx + 1 + prog[idx].jt as usize;
            assert_eq!(
                prog[target].k, SECCOMP_RET_ALLOW,
                "allowlist[{i}] 跳转目标错误"
            );
        }
    }

    #[test]
    fn allow_adds_syscall() {
        let list = SeccompAllowlist::sandbox_minimal().allow(libc::SYS_getcwd as u32);
        assert!(list.allowed.contains(&(libc::SYS_getcwd as u32)));
        assert!(list.io_uring_blocked());
    }
}
