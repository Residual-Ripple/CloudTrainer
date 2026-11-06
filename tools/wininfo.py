#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
静态读出 MultiRender.exe 创建广播窗口时用的参数（只读，不运行）。

用 capstone 做线性反汇编，避免手工猜指令边界（上一版就是栽在这里，
把指令中间的 0x68 当成了 push）。

用法：
    python tools/wininfo.py [exe] [类名]
"""
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:
    print("需要 capstone：pip install capstone")
    sys.exit(2)

TARGET = sys.argv[1] if len(sys.argv) > 1 else r"F:\project\harness\Lenovo teaching system\MultiRender.exe"
WANT_CLS = sys.argv[2] if len(sys.argv) > 2 else "MultiRenderWindowClass"


class PE:
    def __init__(self, path):
        self.d = d = open(path, "rb").read()
        self.e = struct.unpack_from("<I", d, 0x3C)[0]
        self.machine = struct.unpack_from("<H", d, self.e + 4)[0]
        self.nsec = struct.unpack_from("<H", d, self.e + 6)[0]
        self.optsz = struct.unpack_from("<H", d, self.e + 20)[0]
        self.opt = self.e + 24
        self.imagebase = struct.unpack_from("<I", d, self.opt + 28)[0]
        self.sec = []
        o = self.opt + self.optsz
        for i in range(self.nsec):
            p = o + i * 40
            name = d[p:p + 8].rstrip(b"\0").decode("latin1")
            vs, va, rs, ra = struct.unpack_from("<IIII", d, p + 8)
            self.sec.append((name, va, max(vs, rs), ra))
        self.text = [s for s in self.sec if s[0] == ".text"][0]

    def r2o(self, rva):
        for name, va, sz, ra in self.sec:
            if va <= rva < va + sz:
                return ra + (rva - va)
        return None

    def find_str(self, s):
        out = []
        for enc in ("utf-16-le", "latin1"):
            b = s.encode(enc) + b"\0" * (2 if enc == "utf-16-le" else 1)
            i = 0
            while True:
                i = self.d.find(b, i)
                if i < 0:
                    break
                for name, va, sz, ra in self.sec:
                    if ra <= i < ra + sz:
                        out.append((enc, va + (i - ra)))
                i += 1
        return out

    def imports(self):
        irva = struct.unpack_from("<I", self.d, self.opt + 104)[0]
        out = {}
        if not irva:
            return out
        off = self.r2o(irva)
        i = 0
        while True:
            p = off + i * 20
            ilt, ts, fc, nm, iat = struct.unpack_from("<IIIII", self.d, p)
            if nm == 0 or i > 64:
                break
            no = self.r2o(nm)
            dll = self.d[no:self.d.index(b"\0", no)].decode("latin1")
            lst = []
            t = self.r2o(ilt or iat)
            j = 0
            while t:
                v = struct.unpack_from("<I", self.d, t + 4 * j)[0]
                if v == 0:
                    break
                if not (v & 0x80000000):
                    fo = self.r2o(v) + 2
                    lst.append((self.d[fo:self.d.index(b"\0", fo)].decode("latin1"), iat + 4 * j))
                j += 1
                if j > 4000:
                    break
            out[dll] = lst
            i += 1
        return out

    def disasm_text(self):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        name, va, sz, ra = self.text
        insns = list(md.disasm(self.d[ra:ra + sz], self.imagebase + va))
        return insns


STYLE = [
    (0x80000000, "WS_POPUP"), (0x40000000, "WS_CHILD"), (0x20000000, "WS_MINIMIZE"),
    (0x10000000, "WS_VISIBLE"), (0x08000000, "WS_DISABLED"), (0x04000000, "WS_CLIPSIBLINGS"),
    (0x02000000, "WS_CLIPCHILDREN"), (0x01000000, "WS_MAXIMIZE"), (0x00800000, "WS_BORDER"),
    (0x00400000, "WS_DLGFRAME"), (0x00200000, "WS_VSCROLL"), (0x00100000, "WS_HSCROLL"),
    (0x00080000, "WS_SYSMENU"), (0x00040000, "WS_THICKFRAME"), (0x00020000, "WS_MINIMIZEBOX"),
    (0x00010000, "WS_MAXIMIZEBOX"),
]
EXSTYLE = [
    (0x00000001, "WS_EX_DLGMODALFRAME"), (0x00000004, "WS_EX_NOPARENTNOTIFY"),
    (0x00000008, "WS_EX_TOPMOST"), (0x00000010, "WS_EX_ACCEPTFILES"),
    (0x00000020, "WS_EX_TRANSPARENT"), (0x00000040, "WS_EX_MDICHILD"),
    (0x00000080, "WS_EX_TOOLWINDOW"), (0x00000100, "WS_EX_WINDOWEDGE"),
    (0x00000200, "WS_EX_CLIENTEDGE"), (0x00000400, "WS_EX_CONTEXTHELP"),
    (0x00001000, "WS_EX_RIGHT"), (0x00010000, "WS_EX_CONTROLPARENT"),
    (0x00020000, "WS_EX_STATICEDGE"), (0x00040000, "WS_EX_APPWINDOW"),
    (0x00080000, "WS_EX_LAYERED"), (0x00100000, "WS_EX_NOINHERITLAYOUT"),
    (0x00400000, "WS_EX_NOREDIRECTIONBITMAP"), (0x02000000, "WS_EX_COMPOSITED"),
    (0x08000000, "WS_EX_NOACTIVATE"),
]


def decode(v, table):
    v &= 0xFFFFFFFF
    names, rest = [], v
    for bit, nm in table:
        if rest & bit:
            names.append(nm)
            rest &= ~bit
    if rest:
        names.append("0x%X" % rest)
    return " | ".join(names) if names else "0"


def main():
    pe = PE(TARGET)
    insns = pe.disasm_text()
    idx = {i.address: k for k, i in enumerate(insns)}

    print("文件      : %s" % os.path.basename(TARGET))
    print("镜像基址  : 0x%08X   .text 0x%X 字节  指令 %d 条" %
          (pe.imagebase, pe.text[2], len(insns)))

    strs = pe.find_str(WANT_CLS)
    print("\n类名字符串: %s" % ", ".join("RVA 0x%X (VA 0x%08X)" % (r, pe.imagebase + r) for e, r in strs))
    cls_vas = {pe.imagebase + r for e, r in strs}

    imps = {}
    for dll, lst in pe.imports().items():
        for nm, iat in lst:
            imps.setdefault(nm, (dll, iat))

    def call_target(ins):
        """如果是 call dword ptr [VA]，返回 VA"""
        if ins.mnemonic != "call":
            return None
        op = ins.op_str
        if "[" in op and "]" in op:
            try:
                return int(op[op.index("[") + 1:op.index("]")], 16)
            except ValueError:
                return None
        return None

    def args_before(k, maxn=14):
        """从第 k 条指令往前收 push 立即数（近的在前）"""
        out = []
        j = k - 1
        while j >= 0 and len(out) < maxn:
            ins = insns[j]
            if ins.address + ins.size != (insns[j + 1].address if j + 1 < len(insns) else -1):
                break
            m = ins.mnemonic
            if m == "push" and ins.op_str:
                try:
                    out.append(int(ins.op_str, 16))
                except ValueError:
                    out.append(None)
            elif m in ("ret", "retn") or m == "int3":
                break
            elif m == "call":
                break
            j -= 1
        return out

    print("\n== CreateWindowExW 调用 ==")
    want = imps.get("CreateWindowExW")
    if not want:
        print("  未导入")
    else:
        iat_va = pe.imagebase + want[1]
        names = ["dwExStyle", "lpClassName", "lpWindowName", "dwStyle",
                 "X", "Y", "nWidth", "nHeight", "hWndParent", "hMenu", "hInstance", "lpParam"]
        found = 0
        for k, ins in enumerate(insns):
            if call_target(ins) != iat_va:
                continue
            vals = args_before(k)
            if len(vals) < 12:
                continue
            if not any(v in cls_vas for v in vals[:12] if v):
                continue
            found += 1
            print("  VA 0x%08X" % ins.address)
            for n, v in enumerate(vals[:12]):
                if v is None:
                    continue
                lab = names[n]
                note = ""
                if lab == "dwExStyle":
                    note = "  => " + decode(v, EXSTYLE)
                elif lab == "dwStyle":
                    note = "  => " + decode(v, STYLE)
                elif lab == "lpClassName" and v in cls_vas:
                    note = "  => \"%s\"" % WANT_CLS
                print("      %-12s 0x%08X%s" % (lab, v, note))
            print()
        print("  命中 %d 处（引用了该窗口类）" % found)

    print("\n== 位置相关调用 ==")
    for api in ("SetWindowPos", "MoveWindow", "SetWindowPlacement", "SetWindowLongW"):
        w = imps.get(api)
        if not w:
            print("  %-18s 未导入" % api)
            continue
        iat_va = pe.imagebase + w[1]
        sites = [(k, ins) for k, ins in enumerate(insns) if call_target(ins) == iat_va]
        print("  %-18s %d 处" % (api, len(sites)))
        if api != "SetWindowPos":
            continue
        for k, ins in sites:
            vals = args_before(k, 8)
            if len(vals) < 7:
                continue
            # 参数：hwnd, after, X, Y, cx, cy, flags
            x, y = vals[2], vals[3]
            cx, cy, fl = vals[4], vals[5], vals[6]
            if x is None or y is None:
                continue
            def s32(v):
                return v - 0x100000000 if v and v & 0x80000000 else v
            # 只打印"看起来像常量"的（小整数）
            if all(v is not None and abs(s32(v)) < 100000 for v in (x, y, cx, cy)):
                print("      0x%08X  X=%-6d Y=%-6d cx=%-6d cy=%-6d flags=0x%X"
                      % (ins.address, s32(x), s32(y), s32(cx), s32(cy), (fl or 0) & 0xFFFFFFFF))


if __name__ == "__main__":
    main()
