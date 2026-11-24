# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。
"""M0 Spike 修复版：seccomp 顺序反向用例（P2a/P2b）与 io_uring 阻断（P3）。
子进程输出全部 flush，修复 fork 后 stdout 缓冲随 os._exit 丢失的问题。"""
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
TSYNC = 1
RET_ERRNO = 0x00050000
RET_ALLOW = 0x7FFF0000
RET_KILL = 0x80000000
ARCH = 0xC000003E
EPERM = 1


def stmt(c, k):
    return struct.pack("HBBI", c, 0, 0, k)


def jump(c, k, jt, jf):
    return struct.pack("HBBI", c, jt, jf, k)


def build(nr):
    return b"".join([
        stmt(0x20, 4),
        jump(0x15, ARCH, 0, 4),
        stmt(0x20, 0),
        jump(0x15, nr, 0, 1),
        stmt(0x06, RET_ERRNO | EPERM),
        stmt(0x06, RET_ALLOW),
        stmt(0x06, RET_KILL),
    ])


def install(prog, flags=0):
    buf = ctypes.create_string_buffer(prog)

    class F(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fp = F(len(prog) // 8, ctypes.addressof(buf))
    r = libc.syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, flags,
                     ctypes.byref(fp))
    return r, ctypes.get_errno()


def nnp():
    return libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


def p2a():
    pid = os.fork()
    if pid == 0:
        os.setuid(65534)
        r, e = install(build(9999))
        ok = r == -1 and e == EPERM
        print("P2a", "PASS" if ok else f"FAIL r={r} e={e}", flush=True)
        os._exit(0)
    os.waitpid(pid, 0)


def p2b():
    res = {}

    def worker():
        for _ in range(20):
            res["v"] = libc.syscall(39)
            time.sleep(0.01)

    pid = os.fork()
    if pid == 0:
        nnp()
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        time.sleep(0.05)
        r, e = install(build(39))
        if r != 0:
            print(f"P2b-1 FAIL install r={r} e={e}", flush=True)
            os._exit(0)
        nr = libc.syscall(39)
        mb = nr == -1 and ctypes.get_errno() == EPERM
        time.sleep(0.25)
        oth = res.get("v", -1) > 0
        print("P2b-1", "PASS" if (mb and oth) else
              f"FAIL main_blocked={mb} other_ok={oth}", flush=True)
        os._exit(0)
    os.waitpid(pid, 0)

    res2 = {}

    def worker2():
        time.sleep(0.1)
        nr = libc.syscall(39)
        res2["b"] = nr == -1 and ctypes.get_errno() == EPERM

    pid = os.fork()
    if pid == 0:
        nnp()
        t = threading.Thread(target=worker2, daemon=True)
        t.start()
        r, e = install(build(39), TSYNC)
        if r != 0:
            print(f"P2b-2 FAIL tsync install r={r} e={e}", flush=True)
            os._exit(0)
        t.join()
        nr = libc.syscall(39)
        mb = nr == -1 and ctypes.get_errno() == EPERM
        print("P2b-2", "PASS" if (mb and res2.get("b")) else
              f"FAIL main={mb} other={res2}", flush=True)
        os._exit(0)
    os.waitpid(pid, 0)


def p3():
    pid = os.fork()
    if pid == 0:
        nnp()
        r, e = install(build(SYS_IO_URING_SETUP))
        if r != 0:
            print(f"P3 FAIL install r={r} e={e}", flush=True)
            os._exit(0)
        nr = libc.syscall(SYS_IO_URING_SETUP, 8, None)
        e2 = ctypes.get_errno()
        ok = nr == -1 and e2 == EPERM
        print("P3", "PASS" if ok else f"FAIL nr={nr} e={e2}", flush=True)
        os._exit(0)
    os.waitpid(pid, 0)


print(f"=== spike2 kernel {os.uname().release} ===", flush=True)
p2a()
p2b()
p3()
print("=== done ===", flush=True)
sys.exit(0)
