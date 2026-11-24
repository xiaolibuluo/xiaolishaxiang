# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。
"""xiaolishaxiang M0 Spike: seccomp 顺序反向用例 / io_uring 阻断 / cgroup v2 委派探测。"""
import ctypes
import os
import struct
import sys
import threading
import time

libc = ctypes.CDLL(None, use_errno=True)

PR_SET_NO_NEW_PRIVS = 38
SYS_SECCOMP = 317
SYS_IO_URING_SETUP = 425
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_TSYNC = 1
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
AUDIT_ARCH_X86_64 = 0xC000003E
EPERM = 1


def stmt(code, k):
    return struct.pack("HBBI", code, 0, 0, k)


def jump(code, k, jt, jf):
    return struct.pack("HBBI", code, jt, jf, k)


def build_filter(deny_nr):
    ins = [
        stmt(0x20, 4),
        jump(0x15, AUDIT_ARCH_X86_64, 0, 4),
        stmt(0x20, 0),
        jump(0x15, deny_nr, 0, 1),
        stmt(0x06, SECCOMP_RET_ERRNO | EPERM),
        stmt(0x06, SECCOMP_RET_ALLOW),
        stmt(0x06, SECCOMP_RET_KILL_PROCESS),
    ]
    return b"".join(ins)


def install_filter(prog, flags=0):
    buf = ctypes.create_string_buffer(prog)

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(prog) // 8, ctypes.addressof(buf))
    ret = libc.syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, flags,
                       ctypes.byref(fprog))
    return ret, ctypes.get_errno()


def set_nnp():
    return libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


def probe_2a():
    """未设 no_new_privs 的非特权进程加载 seccomp 必须被 EPERM 拒绝。"""
    pid = os.fork()
    if pid == 0:
        try:
            os.setuid(65534)
            ret, err = install_filter(build_filter(9999))
            if ret == -1 and err == EPERM:
                print("P2a PASS: EPERM without nnp (uid=65534)")
            else:
                print(f"P2a FAIL: ret={ret} errno={err}")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)


def probe_2b():
    """多线程无 TSYNC：filter 只作用于安装线程；TSYNC 后作用于全部线程。"""
    results = {}

    def worker(tag):
        for _ in range(20):
            results[tag] = libc.syscall(39)
            time.sleep(0.01)

    pid = os.fork()
    if pid == 0:
        try:
            set_nnp()
            t = threading.Thread(target=worker, args=("other",), daemon=True)
            t.start()
            time.sleep(0.05)
            ret, err = install_filter(build_filter(39))
            if ret != 0:
                print(f"P2b FAIL: install ret={ret} errno={err}")
                os._exit(0)
            main_nr = libc.syscall(39)
            main_blocked = main_nr == -1 and ctypes.get_errno() == EPERM
            time.sleep(0.2)
            other_ok = results.get("other", -1) > 0
            if main_blocked and other_ok:
                print("P2b-part1 PASS: no TSYNC -> filter only on installing thread")
            else:
                print(f"P2b-part1 FAIL: main_blocked={main_blocked} other_ok={other_ok}")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)

    results2 = {}

    def worker2():
        time.sleep(0.1)
        nr = libc.syscall(39)
        results2["blocked"] = nr == -1 and ctypes.get_errno() == EPERM

    pid = os.fork()
    if pid == 0:
        try:
            set_nnp()
            t = threading.Thread(target=worker2, daemon=True)
            t.start()
            ret, err = install_filter(build_filter(39), SECCOMP_FILTER_FLAG_TSYNC)
            if ret != 0:
                print(f"P2b FAIL: TSYNC install ret={ret} errno={err}")
                os._exit(0)
            t.join()
            main_nr = libc.syscall(39)
            main_blocked = main_nr == -1 and ctypes.get_errno() == EPERM
            if main_blocked and results2.get("blocked"):
                print("P2b-part2 PASS: TSYNC -> all threads filtered")
            else:
                print(f"P2b-part2 FAIL: main={main_blocked} other={results2}")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)


def probe_3():
    """io_uring_setup 不在 allowlist 时必须被 EPERM 阻断且进程存活。"""
    pid = os.fork()
    if pid == 0:
        try:
            set_nnp()
            ret, err = install_filter(build_filter(SYS_IO_URING_SETUP))
            if ret != 0:
                print(f"P3 FAIL: install ret={ret} errno={err}")
                os._exit(0)
            nr = libc.syscall(SYS_IO_URING_SETUP, 8, None)
            if nr == -1 and ctypes.get_errno() == EPERM:
                print("P3 PASS: io_uring_setup blocked with EPERM, process alive")
            else:
                print(f"P3 FAIL: io_uring_setup ret={nr}")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)


def probe_4():
    """cgroup v2 真实委派：创建子组 -> enable 控制器 -> 写 memory.max -> 回读。"""
    base = "/sys/fs/cgroup"
    sub = os.path.join(base, "xs_spike")
    try:
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(base, "cgroup.subtree_control"), "w") as f:
            f.write("+memory +cpu")
        with open(os.path.join(sub, "memory.max"), "w") as f:
            f.write("134217728")
        with open(os.path.join(sub, "memory.max")) as f:
            got = f.read().strip()
        if got == "134217728":
            print("P4 PASS: cgroup v2 delegation real (subtree_control + memory.max readback)")
        else:
            print(f"P4 FAIL: readback={got}")
    except OSError as e:
        print(f"P4 FAIL: {e}")
    finally:
        try:
            os.rmdir(sub)
        except OSError:
            pass


if __name__ == "__main__":
    print(f"=== spike on kernel {os.uname().release} ===")
    probe_2a()
    probe_2b()
    probe_3()
    probe_4()
    print("=== spike done ===")
    sys.exit(0)
