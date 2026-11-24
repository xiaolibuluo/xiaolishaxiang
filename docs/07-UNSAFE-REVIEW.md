<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# unsafe 审查清单（M3 Required 门禁）

依据 docs/04-TEST-MATRIX.md 第 2 级『unsafe 审查清单：人工核查每条 unsafe 的安全论证注释，全覆盖』。

## 审查范围约定

- **唯一豁免 crate**：`xs-l1-sys`（syscall / libc 交互层，lib.rs 第 7~8 行声明『每条 unsafe 块必须附安全论证注释（不变量、为什么安全、调用契约）』）。
- **其余全部 crate**（xs-core / xs-api / xs-l2-res / xs-l3-rt / xs-cli）：`#![forbid(unsafe_code)]` 编译期强制零 unsafe，无需逐条审查。
- **测试代码**：tests/ 中 unsafe（fork/waitpid/syscall 探测调用）属测试脚手架，不计入产品代码审查范围，但同样要求附注释。

## 审查方法

1. `grep -rn 'unsafe' crates/xs-l1-sys/src/` 全量枚举（基线：16 处 unsafe 块 / 0 个 unsafe fn / 0 个 unsafe impl）。
2. 逐条核对紧邻的 SAFETY 注释是否覆盖三要素：**不变量**（指针/fd/结构体有效性）、**为什么安全**（内核契约引用）、**调用契约**（返回值与错误路径）。
3. 每条结论：PASS（论证完整）/ GAP（论证缺失或不充分，需补齐）。
4. 新增 unsafe 时必须同步登记本清单，否则 Blocker 版权头/行数之外的 review 环节判 fail。

## 逐条审查记录（xs-l1-sys，16 处全部 PASS）

| # | 位置 | 调用 | 安全论证要点（不变量 / 为什么安全 / 调用契约） | 结论 |
|---|---|---|---|---|
| 1 | domain.rs:117 | `libc::fstat(fd, stat.as_mut_ptr())` | 不变量：fd 为本函数打开的合法描述符；stat 为 MaybeUninit<libc::stat> 栈空间，as_mut_ptr 指向可写且足够大的内存。为什么安全：fstat(2) 只向调用者提供的缓冲区写入定长结构体，不保留指针。契约：返回值 0/-1+errno，显式判定；成功后 assume_init 读取。 | PASS |
| 2 | landlock.rs:28 | `libc::syscall(SYS_LANDLOCK_CREATE_RULESET, ...)` | 不变量：attr 为栈上有效 RulesetAttr（repr(C)，与 ABI v1/v3 前缀兼容），按 size 传 8/16 字节，内核只读不越界。为什么安全：语义来自 landlock_create_ruleset(2)；flags=0 为创建而非查询。契约：成功返回 fd≥0，失败 -1+errno 显式上报（Err）。 | PASS |
| 3 | ruleset.rs:119 | `libc::close(self.fd)`（Drop） | 不变量：fd 由 create_ruleset 返回、结构独占持有、未被复制（无 Clone/Copy）。为什么安全：close(2) 对独占 fd 幂等语义由 RAII 保证只调一次。契约：Drop 中忽略返回值（fd 生命周期结束，无后续使用）。 | PASS |
| 4 | ruleset.rs:166 | `libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr, size, 0)` | 不变量：attr 栈上有效结构体；size 按 v1_only 传 8 或 16 字节，内核按 ABI 只读取对应字节。为什么安全：布局与 landlock_ruleset_attr 前缀兼容，语义来自 landlock_create_ruleset(2)。契约：fd≥0 成功 / -1+errno 显式上报。 | PASS |
| 5 | ruleset.rs:199 | `libc::open(c_path.as_ptr(), O_PATH\|O_CLOEXEC)` | 不变量：c_path 为 NUL 结尾 CString 且调用期间存活。为什么安全：O_PATH fd 仅作内核路径引用不支持读写（最小 fd 原则），O_CLOEXEC 防 exec 泄漏。契约：-1+errno 显式上报；成功 fd 随后被 close（见 #6）。 | PASS |
| 6 | ruleset.rs:215 | `libc::syscall(SYS_LANDLOCK_ADD_RULE, ruleset.fd, PATH_BENEATH, &rule, 0)` | 不变量：rule 栈上有效结构体内核只读；parent_fd 为有效 O_PATH fd；ruleset.fd 类型独占持有且未关闭。为什么安全：landlock_add_rule(2) 语义为向 ruleset 追加规则，无副作用外泄。契约：0 成功 / 非 0+errno 显式上报。 | PASS |
| 7 | ruleset.rs:225 | `libc::close(parent_fd)` | 不变量：parent_fd 使命（供内核拷贝路径引用）已结束，fd 独占无复制。为什么安全：紧随 add_rule 之后立即关闭，不存在 use-after-close 窗口。契约：忽略返回值（无论 add_rule 成败都必须归还 fd）。 | PASS |
| 8 | ruleset.rs:245 | `libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset.fd, 0)` | 不变量：ruleset.fd 有效且独占持有；flags=0。为什么安全：landlock_restrict_self(2) 只影响调用进程、只收紧不放宽（SP-L1-04 语义）。契约：调用顺序须在 no_new_privs 之后 exec 之前（文档头契约）；EPERM/EACCES 显式上报。 | PASS |
| 9 | filter.rs:191 | `libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` | 不变量：prctl(2) 无指针参数，无内存安全问题。为什么安全：PR_SET_NO_NEW_PRIVS 是 seccomp 安装的前置内核契约（无 TSYNC 时必需），语义来自 prctl(2)。契约：0 成功 / -1+errno 显式上报，绝不静默继续（SP-L1-03 反向用例要求）。 | PASS |
| 10 | filter.rs:224 | `libc::syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, flags, &fprog)` | 不变量：fprog 指向的 sock_fprog 及其 BPF 指令数组在调用期间有效（栈/堆引用持有），内核只读拷贝。为什么安全：seccomp(2) 语义；TSYNC 标志与 no_new_privs 前置由调用契约保证（反向用例覆盖缺失场景）。契约：0 成功 / -1+errno；EPERM 与 EACCES 都识别为被拒绝（P2a 实测）。 | PASS |
| 11 | namespace.rs:89 | `libc::unshare(bits)` | 不变量：bits 为合法 CLONE_NEW* 位掩码（由调用方常量构造），无指针参数。为什么安全：unshare(2) 只影响调用进程的命名空间成员关系。契约：0 成功 / -1+errno 显式上报，绝不静默成功（fail-closed）。 | PASS |
| 12 | supervisor.rs:66 | `libc::fork()` | 不变量：fork(2) 无参数。为什么安全：返回值区分父/子进程；子进程任何失败路径都以 _exit 结束、不运行 atexit 钩子，避免重复冲刷父进程缓冲区。契约：-1+errno 显式上报；子进程落入隔离建立路径。 | PASS |
| 13 | supervisor.rs:79 | `libc::_exit(126)` | 不变量：无。为什么安全：_exit(2) 立即终止、不运行 atexit，避免污染父进程 IO 状态（126 为 fail-closed 契约退出码）。契约：不返回。 | PASS |
| 14 | supervisor.rs:86 | `libc::_exit(127)` | 不变量：无。为什么安全：同 #13（127 为隔离建立失败契约退出码）。契约：不返回。 | PASS |
| 15 | supervisor.rs:100 | `libc::waitpid(pid, &mut status, 0)` | 不变量：pid 为本进程 fork 出的子进程；status 为栈上有效 c_int。为什么安全：waitpid(2) 只回收调用者的子进程，向调用者提供的缓冲区写入。契约：-1+errno（如 ECHILD）显式上报；status 仅在成功后经 WIFEXITED/WEXITSTATUS 解读。 | PASS |
| 16 | supervisor.rs:176 | `unsafe { ... }`（exec 路径块） | 不变量：exec 前隔离三件套（landlock/seccomp/no_new_privs）已按顺序生效；argv/envp 为 NUL 终止 CString 数组且调用期间存活。为什么安全：execve 语义为映像替换，landlock/seccomp 约束随新映像继续生效（内核保证）。契约：成功不返回；失败 -1+errno 落入 _exit(127) 路径。 | PASS |

## 审查结论

- **覆盖率**：16/16 产品代码 unsafe 块均附 SAFETY 论证注释（三要素齐备），**全覆盖 PASS，无 GAP**。
- **零 unsafe fn / unsafe impl**：全 crate 无 unsafe fn 声明与 unsafe trait 实现，FFI 边界全部收敛在 unsafe 块内联调用点。
- **forbid 防线**：其余 5 个 crate 由 `#![forbid(unsafe_code)]` 编译期兜底，clippy -D warnings 已在 Blocker 第 5 步验证。

## 维护规约

1. 新增/修改 unsafe 必须同步更新本清单并附三要素论证，否则 review 判 fail。
2. 本清单与 `grep -rn 'unsafe' crates/xs-l1-sys/src/` 的枚举结果必须一一对应；行号漂移时批量校正。
3. M3 实测基线（2026-11-24，内核 7.0.0-42 / Ubuntu 26.04.1）：16 处，全 PASS。
