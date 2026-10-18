# 构建说明

## 1. 为什么用 zig

开发机上没有 MSVC、没有 CMake、没有 MinGW，但需要一个能产出 **i686 PE** 的编译器：

- 目标 `Student.exe` 是 **x86**，载荷必须同位数，所以 64 位工具链不行；
- 单文件发行要求**静态 CRT**，不能依赖 `libgcc_s.dll` / `libstdc++-6.dll`。

zig 自带 mingw-w64 的头文件和静态库，一条命令就能交叉编译 32 位 Windows 程序：

```bash
zig c++ -target x86-windows-gnu ...
```

`build.py` 会按下面的顺序找 zig，都没有就去 PyPI 镜像下载（`ziglang` 轮子内含完整发行版）：

1. 环境变量 `ZIG`
2. `tools/zig/zig.exe` ← **本仓库当前就放了一份**
3. `build/zigpkg/ziglang/zig.exe`（上一次自动下载解包的位置）
4. `../.ct-build/zigpkg/ziglang/zig.exe`
5. `./.ct-build/zigpkg/ziglang/zig.exe`

`tools/zig/` 约 476 MB，已在 `.gitignore` 里排除，包含三部分：

| 路径 | 大小 | 作用 |
|---|---|---|
| `tools/zig/zig.exe` | ~200 MB | 编译器本体（clang + lld + 内嵌 mingw-w64 头与库） |
| `tools/zig/lib/` | ~120 MB | zig 标准库、libc/libc++ 源码、mingw 头文件 |
| `tools/zig/cache/` | ~150 MB | **编译产物缓存**（libc/libc++ 的 .o） |

`cache/` 放在这里而不是 `build/`，是因为它决定了构建是"秒级"还是"两分钟"：
zig 第一次为目标平台编译运行时需要 **1.5–2 分钟**，之后命中缓存只要 **4 秒**。
把它和 `build/` 一起删掉，就等于每次都要重新编译一遍运行时。

> 想省空间：删掉 `tools/zig/cache/` 能省 150 MB，代价是下次构建慢两分钟；
> 删掉整个 `tools/zig/` 能省 476 MB，`build.py` 会重新下载（80 MB，2–3 分钟）。

---

## 2. 两条编译命令

**载荷**（`dist/CloudTrainerPayload.dll`）：

```bash
zig c++ -target x86-windows-gnu -O2 -DUNICODE -D_UNICODE \
    -I src/common -I src/main \
    -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti \
    -shared -o dist/CloudTrainerPayload.dll \
    -nostartfiles -Wl,--entry,CtPayloadEntry \
    src/payload/dllmain.cpp src/payload/hooks.cpp src/payload/payload.cpp src/payload/call1.S \
    -static -Wl,--gc-sections \
    -luser32 -lpsapi -ladvapi32 -lshell32
```

三个关键参数：

| 参数 | 作用 |
|---|---|
| `-nostartfiles` | 不链 `dllcrt2.o`。载荷是被手工映射的，没有加载器替它跑 `_CRT_INIT` |
| `-Wl,--entry,CtPayloadEntry` | 入口直接指向自己的函数（`__stdcall`，单参数 `base`） |
| `-static` | 静态链接，产物不依赖任何 `libgcc/libstdc++/winpthread` DLL |

**主程序**（`dist/CloudTrainer.exe`）：

```bash
zig c++ -target x86-windows-gnu -O2 -DUNICODE -D_UNICODE \
    -I src/common -I src/main \
    -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti \
    -o dist/CloudTrainer.exe \
    -Wl,--subsystem,windows -Wl,--entry,WinMainCRTStartup \
    src/main/Core.cpp src/main/CtMain.cpp src/main/Guards.cpp \
    src/main/Inject.cpp src/main/Probe.cpp src/main/Ui.cpp \
    -static -Wl,--gc-sections \
    -luser32 -lgdi32 -lshell32 -ladvapi32 -lole32 -lcomctl32 -lpsapi -lshlwapi -lversion
```

---

## 3. 附加载荷

`build.py` 在编译完成后做一次追加：

```
[ exe 映像 ][ payload.dll 字节 ][ footer 16 字节 ]
footer = magic 'CTPL' | size(u32) | crc32(u32) | flags(u32)
```

运行时 `LoadEmbeddedPayload()` 读自身文件尾部，校验 magic + size + crc32 后把载荷读回内存。
这样发行物只有一个 exe，同时保留了"载荷是独立编译单元"的好处（可单独替换、可单独审计）。

> 为什么不用 `.rc` 资源：需要 `rc.exe`/`windres`，而这条工具链没有资源编译器。
> 尾部追加不依赖任何工具链，而且 CRC 能挡住截断/损坏。

---

## 4. 自检

```bash
python tools/inspect.py        # PE 结构：架构 / 子系统 / 节表 / TLS / 重定位 / 导入
python tools/check_imports.py  # 模拟加载器逐个解析导入，验证转发导出处理
```

`inspect.py` 关注三件事：

- `machine == 0x014C`（i386）且 `optional magic == 0x010B`（PE32）；
- 有没有 `libstdc++/libgcc/libwinpthread` 依赖；
- 载荷有没有 TLS 目录（有的话手工映射就得额外实现 TLS 分配，本项目刻意避开）。

`check_imports.py` 会打印**转发导出**的比例。当前产物：载荷 72 个导入符号里 42 个是转发导出
——这就是注入器必须用 `GetModuleHandleEx(FROM_ADDRESS)` 找"实际包含地址的模块"再算 RVA 的原因。

---

## 5. 换成 MSVC（可选）

如果你有 VS2022，等价配置是：

| 项 | 值 |
|---|---|
| 平台 | **Win32 / x86**（必须） |
| 字符集 | Unicode |
| 运行库 | **/MT**（静态） |
| 优化 | `/O2`，**关掉 `/GL`**（LTCG 会让静态 TLS 折叠，给手工映射添麻烦） |
| 载荷 | `Configuration Type = Dynamic Library`，入口 `/ENTRY:CtPayloadEntry`，**不要**链 CRT 启动（`/NODEFAULTLIB:libcmt` 视情况） |
| 主程序 | `SubSystem = Windows`，`/ENTRY:WinMainCRTStartup` |
| 链接 | `user32.lib gdi32.lib shell32.lib advapi32.lib ole32.lib comctl32.lib psapi.lib shlwapi.lib version.lib` |

需要注意两处和 GCC 的差异：

1. `src/payload/call1.S` 是 AT&T 语法，MSVC 要用 `ml` 写一份 Intel 语法的等价实现
   （逻辑就三行：存 ESP → push 参数 → call → 恢复 ESP）。
2. GCC 的 `__attribute__` / `#pragma pack` 用法两边都兼容，但 `_snwprintf` 在 MSVC 下会有
   弃用警告，换成 `_snwprintf_s` 即可。

本项目**只在 zig/clang 上验证过**。MSVC 路径没有实机跑过，仅作为移植参考。

---

## 6. 常见问题

**`zig: error: unable to make temporary file: Permission denied`**
zig 需要一个可写的临时目录。设置 `TMP` / `TEMP` / `TMPDIR` 指向构建目录即可（`build.py` 会自动设）。

**`Couldn't execute program 'zig.exe': 拒绝访问 (0x5)`**
zig 会 fork 自己来跑各个编译单元。如果环境禁止子进程（受限沙箱、某些 EDR 策略），构建就会失败。
这不是代码问题，换一个允许执行子进程的终端即可。

**`error: unsupported linker arg: --kill-at / --no-insert-timestamp`**
zig 内置的 lld 不支持这两个 GNU ld 参数，已经从 `build.py` 里去掉。

**`'string' file not found`**
用了 `zig cc` 而不是 `zig c++`。C 驱动不会带 C++ 标准库头文件路径。
