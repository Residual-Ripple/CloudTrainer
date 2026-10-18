#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
反射注入端到端测试。

做的事：
  1. 编译 tests/host.exe（一个空转的控制台程序）与 tests/test_inject.exe；
  2. 启动 host，拿到 pid；
  3. 让 test_inject 把 dist/CloudTrainerPayload.dll 反射映射进 host；
  4. 判据：注入返回成功 + host 里出现 CloudTrainer 的共享内存会话；
  5. 结束 host。

**不会** 触碰任何电子教室进程 —— host.exe 是本仓库自带的空壳程序。
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import build as B  # 复用工具链定位与命令执行

ROOT = B.ROOT
TESTS = os.path.join(ROOT, "tests")
OUT = os.path.join(B.BUILD, "tests")


def build_all(zig):
    os.makedirs(OUT, exist_ok=True)

    host = os.path.join(OUT, "host.exe")
    B.run([zig, "cc", "-target", "x86-windows-gnu", "-O1",
           "-o", host, os.path.join(TESTS, "host.c"), "-static"])

    ti = os.path.join(OUT, "test_inject.exe")
    B.run([zig, "c++", "-target", "x86-windows-gnu", "-O1",
           "-DUNICODE", "-D_UNICODE",
           "-I", B.COMMON_SRC, "-I", B.MAIN_SRC,
           "-fno-exceptions", "-fno-rtti",
           "-o", ti,
           os.path.join(TESTS, "test_inject.cpp"),
           os.path.join(B.MAIN_SRC, "Reflect.cpp"),
           "-static", "-luser32", "-lpsapi", "-ladvapi32"])
    return host, ti


def run_one(zig, host, ti, payload, occupy):
    pidfile = os.path.join(OUT, "host.pid")
    if os.path.exists(pidfile):
        os.remove(pidfile)

    args = [host] + (["--occupy"] if occupy else [])
    print("\n[场景] %s" % ("首选基址被占用（走重定位）" if occupy else "首选基址空闲"))
    proc = subprocess.Popen(args, cwd=OUT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = None
    for _ in range(50):
        time.sleep(0.1)
        if os.path.exists(pidfile):
            pid = int(open(pidfile).read().strip() or 0)
            break
    if not pid:
        proc.kill()
        print("  [FAIL] host 没写出 pid")
        return 3
    print("  host pid=%d" % pid)

    rc = subprocess.call([ti, str(pid), payload], cwd=OUT)
    time.sleep(0.3)
    proc.kill()
    proc.wait()
    return rc


def main():
    zig = B.ensure_zig()
    host, ti = build_all(zig)
    payload = B.PAYLOAD_OUT
    if not os.path.isfile(payload):
        print("找不到 %s，先跑一次 build.py" % payload)
        return 2

    rc1 = run_one(zig, host, ti, payload, occupy=False)
    rc2 = run_one(zig, host, ti, payload, occupy=True)

    ok = (rc1 == 0 and rc2 == 0)
    print("\n[结果] %s" % ("PASS —— 反射注入在两种基址场景下都可用"
                          if ok else "FAIL（preferred=%d relocated=%d）" % (rc1, rc2)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
