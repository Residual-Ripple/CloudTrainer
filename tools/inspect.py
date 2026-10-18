#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudTrainer 产物静态检查（不执行任何二进制）

检查项：
  * PE 架构 / 子系统 / 入口点
  * 导入的 DLL 是否只有系统件（不能有 libstdc++ / libgcc 之类的运行库）
  * 是否存在 TLS 目录（手工映射不处理 TLS，必须为 0）
  * 是否存在重定位目录（决定能否在非首选基址映射）
  * 是否残留 mingw 的 pseudo-reloc 列表（会与手工重定位重复应用）
  * 主程序尾部是否正确附加了载荷
"""
import os
import struct
import sys

MAGIC_PAYLOAD = 0x4C504354


class PE:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        if d[:2] != b"MZ":
            raise SystemExit("%s 不是 PE" % path)
        self.e = struct.unpack_from("<I", d, 0x3C)[0]
        if d[self.e:self.e + 4] != b"PE\0\0":
            raise SystemExit("%s 缺少 PE 签名" % path)
        (self.machine, self.nsec, _, _, _, self.optsize,
         self.chars) = struct.unpack_from("<HHIIIHH", d, self.e + 4)
        self.opt = self.e + 24
        self.magic = struct.unpack_from("<H", d, self.opt)[0]
        self.entry = struct.unpack_from("<I", d, self.opt + 16)[0]
        self.imagebase = struct.unpack_from("<I", d, self.opt + 28)[0]
        self.subsystem = struct.unpack_from("<H", d, self.opt + 68)[0]
        self.dll_chars = struct.unpack_from("<H", d, self.e + 22)[0]
        self.sections = []
        s = self.opt + self.optsize
        for i in range(self.nsec):
            o = s + i * 40
            name = d[o:o + 8].rstrip(b"\0").decode("latin1")
            vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
            ch = struct.unpack_from("<I", d, o + 36)[0]
            self.sections.append((name, vs, va, rs, ra, ch))

    def dir(self, idx):
        return struct.unpack_from("<II", self.data, self.opt + 96 + idx * 8)

    def rva2off(self, rva):
        for name, vs, va, rs, ra, ch in self.sections:
            if va <= rva < va + max(vs, rs):
                return ra + (rva - va)
        return None

    def imports(self):
        rva, size = self.dir(1)
        out = []
        if not rva:
            return out
        off = self.rva2off(rva)
        i = 0
        while True:
            o = off + i * 20
            ilt, ts, fc, nm, iat = struct.unpack_from("<IIIII", self.data, o)
            if nm == 0:
                break
            no = self.rva2off(nm)
            dll = self.data[no:self.data.index(b"\0", no)].decode("latin1")
            out.append(dll)
            i += 1
        return out


def check(path, is_dll):
    print("=" * 72)
    print(path)
    p = PE(path)
    print("  machine      : 0x%04X %s" % (p.machine, "i386" if p.machine == 0x14C else "非 x86!"))
    print("  subsystem    : %d %s" % (p.subsystem, "GUI" if p.subsystem == 2 else ""))
    print("  image base   : 0x%08X" % p.imagebase)
    print("  entry RVA    : 0x%08X" % p.entry)
    print("  is dll       : %s" % ("yes" if p.dll_chars & 0x2000 else "no"))
    print("  size         : %d bytes" % len(p.data))

    reloc_rva, reloc_size = p.dir(5)
    tls_rva, tls_size = p.dir(9)
    print("  reloc dir    : rva=0x%08X size=%d %s" % (reloc_rva, reloc_size,
                                                     "OK" if reloc_rva else "缺失（只能按首选基址映射）"))
    print("  TLS dir      : rva=0x%08X size=%d %s" % (tls_rva, tls_size,
                                                     "存在（代码不用 __thread 则无害，见 README）" if tls_rva else "无 ✔"))

    print("  sections     :")
    for name, vs, va, rs, ra, ch in p.sections:
        flag = ""
        if ch & 0x20000000:
            flag += "X"
        if ch & 0x80000000:
            flag += "W"
        if ch & 0x40000000:
            flag += "R"
        print("      %-8s vs=0x%06X raw=%7d flags=%s" % (name, va, rs, flag))

    imps = p.imports()
    print("  imports (%d): %s" % (len(imps), ", ".join(imps)))
    bad = [i for i in imps if i.lower().startswith(("libstdc++", "libgcc", "libwinpthread"))]
    print("  运行库依赖   : %s" % ("无 ✔" if not bad else "⚠ " + ", ".join(bad)))

    # mingw pseudo-reloc 列表标记：段名 .rdata 中通常会有两个相邻指针；
    # 这里用更直接的办法——看有没有 __RUNTIME_PSEUDO_RELOC 字符串/符号残留
    marker = b"__RUNTIME_PSEUDO_RELOC_LIST__"
    print("  pseudo-reloc : %s" % ("存在符号名（需关注）" if marker in p.data else "无标记 ✔"))
    return p


def check_payload_footer(exe_path):
    d = open(exe_path, "rb").read()
    magic, size, crc, flags = struct.unpack_from("<IIII", d, len(d) - 16)
    import zlib
    body = d[len(d) - 16 - size:len(d) - 16]
    ok = magic == MAGIC_PAYLOAD and (zlib.crc32(body) & 0xFFFFFFFF) == crc
    print("=" * 72)
    print("尾部载荷：magic=%08X size=%d crc=%08X %s" % (magic, size, crc, "✔" if ok else "✘"))
    return ok


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dist = os.path.join(root, "dist")
    exe = os.path.join(dist, "CloudTrainer.exe")
    dll = os.path.join(dist, "CloudTrainerPayload.dll")
    check(dll, True)
    check(exe, False)
    check_payload_footer(exe)
