#!/usr/bin/env python3
# =============================================================================
#  CloudTrainer 构建脚本
#  ---------------------------------------------------------------------------
#  本机没有 MSVC / CMake / MinGW，所以自带一个能产出 i686 PE 的工具链：
#      zig cc -target x86-windows-gnu
#  zig 自带 mingw-w64 头文件与静态库，可以直接交叉编译 32 位 Windows 程序。
#
#  用法：
#      python build.py             # 增量构建
#      python build.py --clean     # 清理后重建
#      python build.py --no-append # 只编译，不把 payload 附加到 exe
#
#  产物：
#      dist/CloudTrainer.exe            单文件（内含 payload）
#      dist/CloudTrainerPayload.dll     单独留档，便于排错
# =============================================================================
import os
import sys
import struct
import zlib
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(ROOT, "build")
DIST = os.path.join(ROOT, "dist")
TMP = os.path.join(BUILD, "tmp")
# 缓存放哪：如果仓库里带了 tools/zig，就把缓存放在它旁边 —— 这样清 build/ 不会把
# 编译好的 libc/libc++ 一起删掉（否则每次冷构建都要多花两分钟重新编译运行时）。
_TOOLS_ZIG = os.path.join(ROOT, "tools", "zig")
CACHE = (os.path.join(_TOOLS_ZIG, "cache") if os.path.isdir(_TOOLS_ZIG)
         else os.path.join(BUILD, "zigcache"))

SRC = os.path.join(ROOT, "src")
MAIN_SRC = os.path.join(SRC, "main")
PAYLOAD_SRC = os.path.join(SRC, "payload")
COMMON_SRC = os.path.join(SRC, "common")

PAYLOAD_OUT = os.path.join(DIST, "CloudTrainerPayload.dll")
EXE_OUT = os.path.join(DIST, "CloudTrainer.exe")

PAYLOAD_MAGIC = 0x4C504354  # 'CTPL'

CFLAGS = [
    "-target", "x86-windows-gnu",
    "-O2",
    "-DUNICODE", "-D_UNICODE",
    "-I", COMMON_SRC, "-I", MAIN_SRC,
    "-fno-asynchronous-unwind-tables",
    "-fno-exceptions",
    "-fno-rtti",
    "-Wall",
    "-Wno-unused-function",
    "-Wno-unused-variable",
    "-Wno-unused-but-set-variable",
    "-Wno-cast-function-type",
]

LDFLAGS_COMMON = [
    "-static",
    "-Wl,--gc-sections",
]

MAIN_LIBS = ["-luser32", "-lgdi32", "-lgdiplus", "-lshell32", "-ladvapi32", "-lole32",
             "-lcomctl32", "-lpsapi", "-lshlwapi", "-lversion"]

PAYLOAD_LIBS = ["-luser32", "-lpsapi", "-ladvapi32", "-lshell32"]


# -----------------------------------------------------------------------------
#  工具链定位
# -----------------------------------------------------------------------------
def find_zig():
    env = os.environ.get("ZIG")
    if env and os.path.isfile(env):
        return env
    candidates = [
        os.path.join(ROOT, "tools", "zig", "zig.exe"),
        os.path.join(BUILD, "zigpkg", "ziglang", "zig.exe"),          # 上次自动下载的解包位置
        os.path.join(ROOT, "..", ".ct-build", "zigpkg", "ziglang", "zig.exe"),
        os.path.join(ROOT, ".ct-build", "zigpkg", "ziglang", "zig.exe"),
    ]
    for c in candidates:
        c = os.path.abspath(c)
        if os.path.isfile(c):
            return c
    return None


def download_zig():
    """从 PyPI 镜像取 ziglang 轮子（内含完整 zig 发行版）并解包。"""
    urls = [
        "https://mirrors.aliyun.com/pypi/packages/e0/0c/66f4710aedf5544e15779ff9c6e770322986e15daf9299b1a4df0be19e09/ziglang-0.13.0-py3-none-win_amd64.whl",
        "https://pypi.org/packages/e0/0c/66f4710aedf5544e15779ff9c6e770322986e15daf9299b1a4df0be19e09/ziglang-0.13.0-py3-none-win_amd64.whl",
    ]
    os.makedirs(BUILD, exist_ok=True)
    whl = os.path.join(BUILD, "ziglang.whl")
    for u in urls:
        try:
            print("  下载 zig: %s" % u)
            with urllib.request.urlopen(u, timeout=120) as r, open(whl, "wb") as f:
                shutil.copyfileobj(r, f)
            break
        except Exception as e:
            print("  失败：%s" % e)
    else:
        return None
    dest = os.path.join(BUILD, "zigpkg")
    with zipfile.ZipFile(whl) as z:
        z.extractall(dest)
    p = os.path.join(dest, "ziglang", "zig.exe")
    return p if os.path.isfile(p) else None


def ensure_zig():
    z = find_zig()
    if z:
        print("[工具链] zig = %s" % z)
        return z
    print("[工具链] 未找到 zig，尝试自动获取 …")
    z = download_zig()
    if not z:
        print("无法获取 zig。请手动下载 https://ziglang.org/download/ 并把 zig.exe 放到 tools/zig/ 下，")
        print("或设置环境变量 ZIG 指向 zig.exe。")
        sys.exit(2)
    print("[工具链] zig = %s" % z)
    return z


# -----------------------------------------------------------------------------
#  编译
# -----------------------------------------------------------------------------
def run(cmd, cwd=None):
    print("  $ " + " ".join('"%s"' % c if " " in c else c for c in cmd[1:]))
    p = subprocess.run(cmd, cwd=cwd, env=make_env())
    if p.returncode != 0:
        print("\n[失败] 命令返回 %d" % p.returncode)
        sys.exit(p.returncode)


def make_env():
    env = dict(os.environ)
    for k in ("TMP", "TEMP", "TMPDIR"):
        env[k] = TMP
    env["ZIG_GLOBAL_CACHE_DIR"] = CACHE
    env["ZIG_LOCAL_CACHE_DIR"] = CACHE
    return env


def sources(path, ext):
    out = []
    for f in sorted(os.listdir(path)):
        if f.endswith(ext):
            out.append(os.path.join(path, f))
    return out


def build_payload(zig):
    srcs = sources(PAYLOAD_SRC, ".cpp") + sources(PAYLOAD_SRC, ".S")
    cmd = [zig, "c++"] + CFLAGS + [
        "-shared", "-o", PAYLOAD_OUT,
        # 不用 CRT 启动代码：载荷是手工映射的，没有加载器替我们跑 _CRT_INIT。
        # 这样也顺带消掉了 .tls 段（否则手工映射必须自己实现 TLS 分配）。
        "-nostartfiles",
        "-Wl,--entry,CtPayloadEntry",
    ] + srcs + LDFLAGS_COMMON + PAYLOAD_LIBS
    run(cmd)


def build_exe(zig):
    srcs = sources(MAIN_SRC, ".cpp")
    cmd = [zig, "c++"] + CFLAGS + [
        "-o", EXE_OUT,
        "-Wl,--subsystem,windows",
        "-Wl,--entry,WinMainCRTStartup",
    ] + srcs + LDFLAGS_COMMON + MAIN_LIBS
    run(cmd)


# -----------------------------------------------------------------------------
#  把 payload 附加到 exe 尾部
# -----------------------------------------------------------------------------
def append_payload():
    with open(PAYLOAD_OUT, "rb") as f:
        payload = f.read()
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    with open(EXE_OUT, "r+b") as f:
        f.seek(0, os.SEEK_END)
        f.write(payload)
        f.write(struct.pack("<IIII", PAYLOAD_MAGIC, len(payload), crc, 0))
    return len(payload), crc


def tidy_dist():
    """dist/ 只留发行物；pdb 与导入库搬到 build/obj/（不随发行版发布）。"""
    obj = os.path.join(BUILD, "obj")
    os.makedirs(obj, exist_ok=True)
    moved = []
    for f in os.listdir(DIST):
        low = f.lower()
        if low.endswith((".pdb", ".lib", ".exp", ".ilk", ".obj")):
            shutil.move(os.path.join(DIST, f), os.path.join(obj, f))
            moved.append(f)
    return moved


def verify():
    """构建后自检：PE 架构 / 子系统 / 尾部 footer。"""
    with open(EXE_OUT, "rb") as f:
        data = f.read()
    if data[:2] != b"MZ":
        raise SystemExit("产物不是 PE 文件")
    e = struct.unpack_from("<I", data, 0x3C)[0]
    machine, nsec, _ = struct.unpack_from("<HHI", data, e + 4)
    magic = struct.unpack_from("<H", data, e + 24)[0]
    subsys = struct.unpack_from("<H", data, e + 24 + 68)[0]

    magic_f, size, crc, _flags = struct.unpack_from("<IIII", data, len(data) - 16)
    ok_footer = magic_f == PAYLOAD_MAGIC
    body = data[len(data) - 16 - size: len(data) - 16] if ok_footer else b""
    ok_crc = ok_footer and (zlib.crc32(body) & 0xFFFFFFFF) == crc

    print("\n[产物自检]")
    print("  CloudTrainer.exe")
    print("    machine    = 0x%04X %s" % (machine, "(i386 ✔)" if machine == 0x014C else "(不是 x86 ✘)"))
    print("    optional   = 0x%04X %s" % (magic, "(PE32 ✔)" if magic == 0x010B else "(不是 PE32 ✘)"))
    print("    subsystem  = %d %s" % (subsys, "(GUI ✔)" if subsys == 2 else "(不是 GUI ✘)"))
    print("    size       = %d bytes" % len(data))
    print("    payload    = %d bytes, crc=%08X %s" % (size, crc, "✔" if ok_crc else "✘"))

    with open(PAYLOAD_OUT, "rb") as f:
        p = f.read()
    pe = struct.unpack_from("<I", p, 0x3C)[0]
    pm, _, _ = struct.unpack_from("<HHI", p, pe + 4)
    pch = struct.unpack_from("<H", p, pe + 22)[0]
    print("  CloudTrainerPayload.dll")
    print("    machine    = 0x%04X %s" % (pm, "(i386 ✔)" if pm == 0x014C else "(不是 x86 ✘)"))
    print("    dll        = %s" % ("✔" if pch & 0x2000 else "✘"))
    print("    size       = %d bytes" % len(p))

    if not (machine == 0x014C and magic == 0x010B and subsys == 2 and ok_crc):
        raise SystemExit("自检失败")


def main():
    args = sys.argv[1:]
    if "--clean" in args and os.path.isdir(BUILD):
        shutil.rmtree(BUILD, ignore_errors=True)
    if "--clean" in args and os.path.isdir(DIST):
        shutil.rmtree(DIST, ignore_errors=True)

    for d in (BUILD, DIST, TMP, CACHE):
        os.makedirs(d, exist_ok=True)

    zig = ensure_zig()
    print("[1/4] 编译载荷 CloudTrainerPayload.dll")
    build_payload(zig)
    print("[2/4] 编译主程序 CloudTrainer.exe")
    build_exe(zig)

    if "--no-append" not in args:
        print("[3/4] 把载荷追加到 exe 尾部")
        size, crc = append_payload()
        print("  payload=%d bytes crc=%08X" % (size, crc))
    else:
        print("[3/4] 跳过附加")

    moved = tidy_dist()
    if moved:
        print("  已把调试产物移到 build/obj/：%s" % ", ".join(moved))

    print("[4/4] 自检")
    verify()
    print("\n完成：%s" % EXE_OUT)


if __name__ == "__main__":
    main()
