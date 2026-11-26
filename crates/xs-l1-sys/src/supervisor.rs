// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! L1 隔离域的 supervisor 侧进程模型（四级进程：supervisor → bootstrap → reaper → worker）。
//!
//! 进程模型（SP-L1-06 四级模型）：
//!   supervisor（可信，TCB 一部分）fork 出沙箱引导子进程（bootstrap）；
//!   bootstrap 执行 `prepare_bootstrap` 后二次 fork 出 sandbox（reaper）；
//!   reaper（PID ns 内 PID 1）再次 fork 出 worker（PID 2，非 init，可正常接收信号）；
//!   worker 执行 `prepare_sandbox`（seccomp+fd 白名单）后 exec 目标程序；
//!   reaper 通过 waitpid 回收 worker，信号转 128+sig 退出码；
//!   bootstrap 回溯 128+sig 并 raise(sig) 透传给 supervisor。
//!
//! D5 顺序约束：seccomp 安装在 worker 内完成（sandbox_minimal allowlist
//! 默认拒绝 clone/fork，二次 fork 必须先于过滤器安装）。
//!
//! 顺序契约完整链路（任一步失败即以非零码退出）：
//!   unshare namespaces -> `no_new_privs` -> landlock 域 ->
//!   二次 fork（PID ns 落地）-> PID 1 reaper fork worker ->
//!   seccomp filter(TSYNC) -> fd 白名单校验(SP-L1-04) -> exec。

use crate::domain::{prepare_bootstrap, prepare_sandbox, DomainSpec};
use xs_core::{XsError, XsResult};

/// 沙箱内要执行的命令。
#[derive(Debug, Clone)]
pub struct SandboxCommand {
    /// 可执行文件路径。
    pub program: std::path::PathBuf,
    /// 参数列表（不含 `argv[0]`）。
    pub args: Vec<String>,
    /// 环境变量（默认空 = 不继承 supervisor 环境，SP-L1 环境泄漏防护）。
    pub env: Vec<(String, String)>,
}

/// 已建立的 L1 隔离域（supervisor 侧句柄，对应一个沙箱子进程组）。
pub struct L1Domain {
    spec: DomainSpec,
}

impl L1Domain {
    /// 探测并建立域描述（不启动进程）。
    ///
    /// 探测在 supervisor `进程内完成（只读动作），min_assurance` 判定由上层完成。
    pub fn establish(spec: DomainSpec) -> XsResult<Self> {
        // 建立前探测：确认当前环境具备 L1 可建立性（只读，无副作用）
        let report = crate::domain::probe()?;
        // 本调用不直接判定等级（由 xs-api 编排层按 min_assurance 判定），
        // 但容器/被锁定环境直接 fail-closed（docs/02：C 档默认拒绝）。
        if report.effective == xs_core::AssuranceLevel::C {
            return Err(XsError::KernelFeatureMissing {
                feature: format!(
                    "L1 可建立性不足（effective=C）：容器内或 userns 不可用，kernel={}",
                    report.kernel
                ),
            });
        }
        Ok(Self { spec })
    }

    /// 在隔离域内启动命令，返回引导子进程 PID（bootstrap）。
    ///
    /// 四级进程模型：supervisor -> bootstrap -> reaper -> worker（SP-L1-06）。
    /// bootstrap 执行 prepare_bootstrap（unshare/no_new_privs/landlock），
    /// 二次 fork 出 reaper（PID ns 内 PID 1），reaper fork 出 worker（PID 2），
    /// worker 执行 prepare_sandbox（seccomp+fd 白名单）再 exec。
    /// 引导进程任一步失败以退出码 126 退出；exec 失败以退出码 127 退出。
    pub fn spawn(&self, cmd: &SandboxCommand) -> XsResult<u64> {
        // SAFETY（安全论证）：
        // - fork() 复制当前进程；返回值 0 为子进程、>0 为父进程中的子 PID、-1 失败。
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let err = std::io::Error::last_os_error();
            return Err(XsError::IsolatorSetupFailed {
                mechanism: "fork".to_string(),
                detail: format!("fork 失败: {err}"),
            });
        }
        if pid == 0 {
            // ── bootstrap 分支 ──
            // 阶段 A：prepare_bootstrap（unshare→no_new_privs→landlock）
            // 不装 seccomp——二次 fork 必须先于过滤器（allowlist 默认拒绝 clone）
            if let Err(e) = prepare_bootstrap(&self.spec) {
                eprintln!("[xs-l1] bootstrap 建立失败: {e}");
                // SAFETY：_exit 立即终止，不运行 atexit，避免污染父进程 IO 状态。
                unsafe { libc::_exit(126) };
            }

            // 阶段 B：二次 fork（SP-L1-06：CLONE_NEWPID 只对后代生效）
            // bootstrap 留在宿主 PID ns，reaper 进入新 PID ns（ns 内 PID=1）。
            let inner = unsafe { libc::fork() };
            if inner < 0 {
                eprintln!(
                    "[xs-l1] 二次 fork 失败（PID ns 落地）: {}",
                    std::io::Error::last_os_error()
                );
                // SAFETY：同上。
                unsafe { libc::_exit(125) };
            }
            if inner == 0 {
                // ── reaper 分支（PID ns 内 PID 1）──
                // PID 1（init）内核默认忽略致命信号，必须再 fork 一层：
                //   reaper（本进程，PID 1）：waitpid 回收 worker，信号→128+sig 退出码；
                //   worker（PID 2，非 init）：可正常接收信号，装 seccomp 后 exec。
                let worker = unsafe { libc::fork() };
                if worker < 0 {
                    eprintln!(
                        "[xs-l1] reaper fork 失败: {}",
                        std::io::Error::last_os_error()
                    );
                    // SAFETY：_exit 立即终止。
                    unsafe { libc::_exit(126) };
                }
                if worker == 0 {
                    // ── worker 分支（PID 2，非 init，可正常接收信号）──
                    // 阶段 C：prepare_sandbox（seccomp TSYNC + fd 白名单）
                    if let Err(e) = prepare_sandbox(&self.spec) {
                        eprintln!("[xs-l1] worker 建立失败: {e}");
                        // SAFETY：_exit 立即终止。
                        unsafe { libc::_exit(126) };
                    }
                    // 阶段 D：exec 目标程序（seccomp/landlock/no_new_privs 均随 fork 继承）
                    exec_command(cmd);
                    // exec 返回即失败
                    eprintln!("[xs-l1] exec 失败: {}", cmd.program.display());
                    // SAFETY：同上。
                    unsafe { libc::_exit(127) };
                }
                // ── reaper 分支（PID 1）──
                // 等待 worker 退出；worker 被信号杀时转译为 128+sig 退出码，
                // 由 bootstrap 层回溯为 raise(sig) 以正确传递崩溃语义。
                let mut wstatus: libc::c_int = 0;
                loop {
                    // SAFETY：waitpid(-1) 回收任意子进程（仅有 worker）；
                    // wstatus 为栈上有效变量。
                    let ret = unsafe { libc::waitpid(-1, &raw mut wstatus, 0) };
                    if ret == worker {
                        if libc::WIFEXITED(wstatus) {
                            // SAFETY：同上。
                            unsafe { libc::_exit(libc::WEXITSTATUS(wstatus)) };
                        } else if libc::WIFSIGNALED(wstatus) {
                            // 信号转译为退出码：128+sig（shell 惯例）
                            // SAFETY：同上。
                            unsafe { libc::_exit(128 + libc::WTERMSIG(wstatus)) };
                        }
                        // SAFETY：同上。
                        unsafe { libc::_exit(129) };
                    }
                    if ret < 0 {
                        // ECHILD：worker 已被他人回收，异常路径
                        // SAFETY：同上。
                        unsafe { libc::_exit(130) };
                    }
                    // 其他后代退出（防御分支，正常仅有 worker 一个子进程）
                }
            }
            // ── bootstrap 分支继续 ──
            // 等待 sandbox reaper 退出并透传退出码。
            // reaper 退出码策略：worker 正常退出→透传退出码；
            // worker 被信号杀→128+sig 退出码。bootstrap 直接将 reaper
            // 的退出码透传给 supervisor（含 128+sig 编码），由
            // ExitStatus::from_raw 逆向映射为 Signaled(sig)。
            let mut status: libc::c_int = 0;
            loop {
                // SAFETY：waitpid(-1) 回收任意子进程；status 为栈上有效变量。
                let ret = unsafe { libc::waitpid(-1, &raw mut status, 0) };
                if ret == inner {
                    if libc::WIFEXITED(status) {
                        // SAFETY：_exit 立即终止；退出码由 from_raw 逆向映射。
                        unsafe { libc::_exit(libc::WEXITSTATUS(status)) };
                    } else if libc::WIFSIGNALED(status) {
                        // reaper 自身被信号杀（非常规路径），转 128+sig
                        // SAFETY：同上。
                        unsafe { libc::_exit(128 + libc::WTERMSIG(status)) };
                    }
                    // SAFETY：同上。
                    unsafe { libc::_exit(129) };
                }
                if ret < 0 {
                    // ECHILD：无子进程可回收（reaper 已被他人回收，异常路径）
                    // SAFETY：同上。
                    unsafe { libc::_exit(130) };
                }
                // 其他后代退出（防御分支，正常流程 bootstrap 仅有 reaper 一个子进程）
            }
        }
        Ok(pid as u64)
    }

    /// 等待子进程退出并回收状态（SP-L1-06：僵尸进程必须回收）。
    ///
    /// 返回子进程退出码（正常退出）或被杀信号。
    pub fn wait(&self, pid: u64) -> XsResult<ExitStatus> {
        let mut status: libc::c_int = 0;
        // SAFETY（安全论证）：
        // - waitpid(pid, &mut status, 0) 阻塞等待指定子进程；status 为栈上有效变量；
        // - pid 来自本对象 spawn 的返回值，调用契约合法；
        // - 返回值 -1 + errno（如 ECHILD 表示非子进程）显式上报。
        let ret = unsafe { libc::waitpid(pid as libc::pid_t, &raw mut status, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(XsError::IsolatorSetupFailed {
                mechanism: "waitpid".to_string(),
                detail: format!("waitpid({pid}) 失败: {err}"),
            });
        }
        Ok(ExitStatus::from_raw(status))
    }

    /// 域配置（只读）。
    #[must_use]
    pub fn spec(&self) -> &DomainSpec {
        &self.spec
    }
}

/// 子进程退出状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// 正常退出及退出码。
    Exited(i32),
    /// 被信号杀死及信号号。
    Signaled(i32),
}

impl ExitStatus {
    fn from_raw(status: libc::c_int) -> Self {
        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);
            // 回溯 bootstrap 层的 128+sig 信号转译（shell 惯例）：
            // bootstrap 将 worker 被信号杀退化为 _exit(128+sig)；
            // 此处反向映射使 supervisor 感知为 Signaled(sig)，
            // 与沙箱内进程被信号杀死的行为等价。
            if (129..=254).contains(&code) {
                Self::Signaled(code - 128)
            } else {
                Self::Exited(code)
            }
        } else if libc::WIFSIGNALED(status) {
            Self::Signaled(libc::WTERMSIG(status))
        } else {
            Self::Exited(-1)
        }
    }

    /// 是否为成功退出（退出码 0）。
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::Exited(0))
    }
}

/// 在当前进程（子进程）上 exec 目标命令。
///
/// 返回即表示失败；成功时进程映像被替换，不再返回。
fn exec_command(cmd: &SandboxCommand) {
    let program = match std::ffi::CString::new(cmd.program.as_os_str().as_encoded_bytes()) {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut argv: Vec<std::ffi::CString> = Vec::with_capacity(cmd.args.len() + 1);
    argv.push(program.clone());
    for a in &cmd.args {
        match std::ffi::CString::new(a.as_str()) {
            Ok(s) => argv.push(s),
            Err(_) => return,
        }
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let mut env_storage: Vec<std::ffi::CString> = Vec::with_capacity(cmd.env.len());
    for (k, v) in &cmd.env {
        if let Ok(s) = std::ffi::CString::new(format!("{k}={v}")) {
            env_storage.push(s);
        }
    }
    let mut env_ptrs: Vec<*const libc::c_char> = env_storage.iter().map(|s| s.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());

    // SAFETY（安全论证）：
    // - program 与 argv/env 缓冲区在调用期间全部存活，指针数组以 NULL 结尾；
    // - execve 成功时不返回（进程映像被替换），失败返回 -1 由调用方处理；
    // - 这是 prepare_sandbox 完成后的最后一步（顺序契约终点），exec 之后
    //   landlock/seccomp 约束随进程映像继续生效。
    unsafe {
        libc::execve(program.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainSpec;

    #[test]
    fn establish_rejects_container_grade_c() {
        // 本机裸 VM 应成功；CI 容器内应为 KernelFeatureMissing（fail-closed 语义）。
        let spec = DomainSpec::minimal();
        match L1Domain::establish(spec) {
            Ok(d) => {
                let _ = d.spec();
            }
            Err(XsError::KernelFeatureMissing { .. }) => {}
            Err(other) => panic!("非预期错误类型: {other}"),
        }
    }

    #[test]
    fn exit_status_parsing() {
        // WIFEXITED/WEXITSTATUS 语义：退出码 42 的 raw status
        let raw = 42 << 8;
        let st = ExitStatus::from_raw(raw);
        assert_eq!(st, ExitStatus::Exited(42));
        assert!(!st.is_success());
        assert!(ExitStatus::Exited(0).is_success());
    }
}
