#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模拟 CloudTrainer 反射加载器的“导入表修复”过程，检查会不会踩到转发导出。

注入器用的算法是：
    1. 在当前进程 GetProcAddress 拿到函数地址；
    2. 找出**真正包含这个地址的模块**（kernel32!CreateFileW 实际在 kernelbase 里）；
    3. 用 (模块, RVA) 在目标进程重建 IAT。

这个脚本把 1、2 两步在本地跑一遍，确认：
    * 每个导入名都能解析；
    * 转发导出的比例（用来验证第 2 步不是多余的）；
    * 有没有解析不到的符号（那会让注入在目标进程里失败）。

只加载系统 DLL，不执行载荷代码，不接触任何控制程序。
"""
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.LoadLibraryW.restype = wt.HMODULE
k32.LoadLibraryW.argtypes = [wt.LPCWSTR]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [wt.HMODULE, ctypes.c_char_p]
k32.GetModuleHandleExW.restype = wt.BOOL
k32.GetModuleHandleExW.argtypes = [wt.DWORD, ctypes.c_void_p, ctypes.POINTER(wt.HMODULE)]
k32.GetModuleFileNameW.restype = wt.DWORD
k32.GetModuleFileNameW.argtypes = [wt.HMODULE, wt.LPWSTR, wt.DWORD]

GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x4
GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x2


class PE:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        self.e = struct.unpack_from("<I", d, 0x3C)[0]
        self.opt = self.e + 24
        self.nsec = struct.unpack_from("<H", d, self.e + 6)[0]
        self.optsize = struct.unpack_from("<H", d, self.e + 20)[0]
        self.sections = []
        s = self.opt + self.optsize
        for i in range(self.nsec):
            o = s + i * 40
            vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
            self.sections.append((vs, va, rs, ra))

    def rva2off(self, rva):
        for vs, va, rs, ra in self.sections:
            if va <= rva < va + max(vs, rs):
                return ra + (rva - va)
        return None

    def dirs(self, idx):
        return struct.unpack_from("<II", self.data, self.opt + 96 + idx * 8)

    def imports(self):
        rva, _ = self.dirs(1)
        if not rva:
            return
        off = self.rva2off(rva)
        i = 0
        while True:
            o = off + i * 20
            ilt, ts, fc, nm, iat = struct.unpack_from("<IIIII", self.data, o)
            if nm == 0:
                break
            no = self.rva2off(nm)
            dll = self.data[no:self.data.index(b"\0", no)].decode("latin1")
            t = self.rva2off(ilt or iat)
            j = 0
            names = []
            while True:
                v = struct.unpack_from("<I", self.data, t + 4 * j)[0]
                if v == 0:
                    break
                if v & 0x80000000:
                    names.append(("ord", v & 0xFFFF))
                else:
                    fo = self.rva2off(v) + 2
                    names.append(("name", self.data[fo:self.data.index(b"\0", fo)].decode("latin1")))
                j += 1
            yield dll, names
            i += 1


def module_of(addr):
    h = wt.HMODULE()
    if not k32.GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 ctypes.c_void_p(addr), ctypes.byref(h)):
        return None, None
    buf = ctypes.create_unicode_buffer(1024)
    k32.GetModuleFileNameW(h, buf, 1024)
    return h.value, os.path.basename(buf.value)


def check(path):
    print("=" * 74)
    print("检查 %s" % os.path.basename(path))
    pe = PE(path)
    total = 0
    forwarded = 0
    missing = []
    for dll, names in pe.imports():
        hmod = k32.LoadLibraryW(dll)
        if not hmod:
            missing.append("%s（整模块加载失败）" % dll)
            continue
        for kind, val in names:
            total += 1
            if kind == "ord":
                addr = k32.GetProcAddress(hmod, ctypes.cast(val, ctypes.c_char_p))
            else:
                addr = k32.GetProcAddress(hmod, val.encode("ascii"))
            if not addr:
                missing.append("%s!%s" % (dll, val))
                continue
            cont, cont_name = module_of(addr)
            if cont_name and cont_name.lower() != os.path.basename(dll).lower():
                forwarded += 1
    print("  导入符号总数 : %d" % total)
    print("  转发导出     : %d  %s" % (forwarded,
          "（所以注入器必须用“实际包含地址的模块”算 RVA）" if forwarded else ""))
    print("  解析失败     : %s" % ("无 ✔" if not missing else "、".join(missing[:10])))
    return not missing


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ok = True
    ok &= check(os.path.join(root, "dist", "CloudTrainerPayload.dll"))
    ok &= check(os.path.join(root, "dist", "CloudTrainer.exe"))
    print("=" * 74)
    print("结论：%s" % ("全部导入可解析 ✔" if ok else "存在无法解析的导入 ✘"))
    sys.exit(0 if ok else 1)
