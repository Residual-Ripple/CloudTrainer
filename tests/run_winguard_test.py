#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
窗口守卫的端到端测试（对应"拖动时被立即移回左上角"这条反馈）。

做法：编一个假广播窗口，它的 WndProc 会像 MultiRender 那样把位置钉回 (0,0)，
然后：
  1. 先确认它真的会钉住（否则测试前提不成立）；
  2. 注入载荷，让 winguard 子类化它；
  3. 再从外部 SetWindowPos 到两个不同位置，看窗口能不能站住。

**不会** 触碰任何电子教室进程。
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

    host = os.path.join(OUT, "winguardhost.exe")
    B.run([zig, "cc", "-target", "x86-windows-gnu", "-O1",
           "-o", host, os.path.join(TESTS, "winguardhost.c"), "-static", "-luser32"])

    tw = os.path.join(OUT, "test_winguard.exe")
    B.run([zig, "c++", "-target", "x86-windows-gnu", "-O1",
           "-DUNICODE", "-D_UNICODE",
           "-I", B.COMMON_SRC, "-I", B.MAIN_SRC,
           "-fno-exceptions", "-fno-rtti",
           "-o", tw,
           os.path.join(TESTS, "test_winguard.cpp"),
           os.path.join(B.MAIN_SRC, "Reflect.cpp"),
           "-static", "-luser32", "-lpsapi", "-ladvapi32"])
    return host, tw


def main():
    zig = B.ensure_zig()
    host, tw = build_all(zig)
    payload = B.PAYLOAD_OUT
    if not os.path.isfile(payload):
        print("找不到 %s，先跑一次 build.py" % payload)
        return 2

    pidfile = os.path.join(OUT, "winguard.pid")
    if os.path.exists(pidfile):
        os.remove(pidfile)

    print("\n[场景] 假广播窗口把位置钉在 (0,0)，注入后从外部移动它")
    proc = subprocess.Popen([host], cwd=OUT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = hwnd = None
    for _ in range(60):
        time.sleep(0.1)
        if os.path.exists(pidfile):
            parts = open(pidfile).read().split()
            if len(parts) == 2:
                pid, hwnd = int(parts[0]), int(parts[1])
                break
    if not pid:
        proc.kill()
        print("  [FAIL] winguardhost 没写出 pid/hwnd")
        return 3
    print("  host pid=%d hwnd=0x%X" % (pid, hwnd))

    rc = subprocess.call([tw, str(pid), str(hwnd), payload], cwd=OUT)
    time.sleep(0.3)
    proc.kill()
    proc.wait()

    print("\n[结果] %s" % ("PASS —— 位置不再被拉回左上角" if rc == 0 else "FAIL（exit=%d）" % rc))
    return rc


if __name__ == "__main__":
    sys.exit(main())
