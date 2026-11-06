#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
外部解锁通道的端到端测试（对应"后手启动无法解除控制"这条反馈）。

场景刻意做成"先有锁，再解锁"——也就是 CloudTrainer 晚于学生端启动的顺序：

  1. 编一个同名的假 HookLib.dll（导出 Lock，起一条 GetMessage 循环线程）；
  2. lockhost.exe 加载它 → 此时进程里有一条"锁线程"，和真机被锁住时同构；
  3. test_unlock.exe 调用**产品里真正使用的那段代码**
     （src/main/Unlock.cpp 的 QuitThreads），检查：
        * 能不能找到模块；
        * 能不能按"线程起始地址落在模块内"定位到锁线程；
        * 投递 WM_QUIT 之后线程是不是真的退出了。

另外跑一个反例：锁线程**没有消息队列**。这种情形下必须如实报告失败
（旧实现会静默返回 0，主程序以为没事发生，于是"后手启动无法解除控制"）。

**不会**触碰任何电子教室进程：host 是本仓库自带的空壳。
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import build as B

ROOT = B.ROOT
TESTS = os.path.join(ROOT, "tests")
OUT = os.path.join(B.BUILD, "tests")


def build_all(zig):
    os.makedirs(OUT, exist_ok=True)

    hooklib = os.path.join(OUT, "HookLib.dll")
    B.run([zig, "cc", "-target", "x86-windows-gnu", "-O1", "-shared",
           "-o", hooklib, os.path.join(TESTS, "fakehook", "hooklib.c"), "-static"])

    host = os.path.join(OUT, "lockhost.exe")
    B.run([zig, "cc", "-target", "x86-windows-gnu", "-O1",
           "-o", host, os.path.join(TESTS, "lockhost.c"), "-static"])

    tu = os.path.join(OUT, "test_unlock.exe")
    B.run([zig, "c++", "-target", "x86-windows-gnu", "-O1",
           "-DUNICODE", "-D_UNICODE",
           "-I", B.COMMON_SRC, "-I", B.MAIN_SRC,
           "-fno-exceptions", "-fno-rtti",
           "-o", tu,
           os.path.join(TESTS, "test_unlock.cpp"),
           os.path.join(B.MAIN_SRC, "Unlock.cpp"),
           "-static", "-luser32"])
    return host, tu


def run_one(host, tu, mode):
    pidfile = os.path.join(OUT, "lockhost.pid")
    if os.path.exists(pidfile):
        os.remove(pidfile)

    args = [host] + (["--noqueue"] if mode == "noqueue" else [])
    title = "锁线程有消息队列（正常情形）" if mode == "queue" else "锁线程没有消息队列（反例）"
    print("\n[场景] %s" % title)

    proc = subprocess.Popen(args, cwd=OUT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = None
    for _ in range(50):
        time.sleep(0.1)
        if os.path.exists(pidfile):
            pid = int(open(pidfile).read().strip() or 0)
            break
    if not pid:
        proc.kill()
        print("  [FAIL] lockhost 没写出 pid")
        return 3

    time.sleep(0.3)      # 让锁线程确实跑起来（模拟"锁已经生效"）
    print("  lockhost pid=%d，锁线程已在运行" % pid)

    rc = subprocess.call([tu, str(pid), mode], cwd=OUT)
    time.sleep(0.2)
    proc.kill()
    proc.wait()
    return rc


def main():
    zig = B.ensure_zig()
    host, tu = build_all(zig)

    rc1 = run_one(host, tu, "queue")
    rc2 = run_one(host, tu, "noqueue")

    ok = (rc1 == 0 and rc2 == 0)
    print("\n[结果] %s" % ("PASS —— 定位/退出/失败上报三条都符合预期"
                          if ok else "FAIL（queue=%d noqueue=%d）" % (rc1, rc2)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
