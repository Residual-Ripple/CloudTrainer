# 第三方、致谢与许可证

## 1. 本项目许可证

**MIT**，全文见仓库根目录 `LICENSE`。

---

## 2. 技术思路来源

**[JiYuTrainer](https://github.com/imengyu/JiYuTrainer)** — MIT License, © imengyu

本项目是在"读懂了 JiYuTrainer 怎么对付极域电子教室"之后，针对**另一个产品**重新设计的。
**不包含它的任何源码**，也没有它的任何二进制。具体复用了什么、没复用见下表。

| JiYuTrainer 的模块 | 本项目 | 说明 |
|---|---|---|
| `MemoryModule.cpp` | 参考思路，**重写** | 它的实现只能在本进程内加载 DLL；本项目需要跨进程映射，逻辑完全不同 |
| `mhook` + `disasm-lib` | **未使用** | 需要指令长度反汇编器改写函数序言；本项目改用 IAT hook |
| `MsgCenter`（WM_COPYDATA + 冒号字符串） | **未使用** | 改用共享内存 + 序号计数器 |
| `NtHlp` / `SysHlp` / `PathHelper` / `Logger` | 接口思路借鉴，**实现重写** | Unicode 路径、滚动日志、无全局可变状态 |
| `JiYuTrainerHooks` 的 37 个 hook | **未使用** | 只保留 `TerminateProcess` / `CreateProcess` / `WM_CLOSE` 三类，且改到 IAT 层 |
| `JiYuTrainerUI`（Sciter） | **未使用** | Sciter 5.x 已转商用授权；本项目用原生 Win32 |
| `JiYuTrainerDriver` / `JyUdpAttack` / `Updater` | **未使用** | 不碰驱动、不做协议重放、不做更新 |

从它身上学到、并明确规避的坑：

1. 不在 `DllMain` 里装 hook（loader lock 死锁）；
2. 不在 `PROCESS_DETACH` 里 `FreeLibrary(自己)`；
3. 不用窗口标题做 IPC；
4. 不用冒号分隔的字符串协议传路径；
5. 不用 `SetWindowLong` 跨进程子类化；
6. 不用 `SM_CXSCREEN` 做全屏判定；
7. 注入后必须校验返回码，不能"失败了也返回 true"。

---

## 3. 构建工具链

**zig**（https://ziglang.org）— MIT License

- 仅作为**构建期**工具使用，不进入产物。
- `build.py` 会从 PyPI 的 `ziglang` 轮子里取 `zig.exe`（内含 mingw-w64 头文件与静态库）。
- 产物静态链接，**不依赖** zig 或 mingw 的任何运行期 DLL。

**mingw-w64** 运行期头文件 / 静态库 — 随 zig 分发，公共领域 / MIT 类许可。
产物中静态链入的 CRT 部分（`-static`）受 mingw-w64 的许可约束（通常为公共领域或 MIT；
其中的 `libgcc` 部分为 GPL + GCC Runtime Library Exception，静态链接不构成传染）。

---

## 4. 系统组件

产物只依赖 Windows 自带组件：

- `kernel32.dll` / `user32.dll` / `gdi32.dll` / `shell32.dll` / `advapi32.dll` /
  `ole32.dll` / `comctl32.dll` / `psapi.dll` / `shlwapi.dll` / `version.dll`
- UCRT：`api-ms-win-crt-*.dll` → `ucrtbase.dll`（Windows 10 起随系统）

因此**不需要** VC++ 运行库，也不需要 .NET。

---

## 5. 对目标产品的研究说明

本项目的设计依据来自对**联想电子教室（NeiCloud）**安装快照的**纯静态分析**
（PE 头、导入导出表、字符串、反汇编、运行期日志与配置）。分析过程中：

- **未运行**目标产品的任何二进制；
- **未修改**目标产品的任何文件；
- 报告中只保留结论与关键 RVA，**不包含**大段反汇编、反编译代码或任何目标产品的二进制。

`docs/MECHANISM.md` 也是按这个原则写的。

---

## 6. 免责

本项目仅用于个人学习、自有设备，或在明确获得授权的教学环境中使用。
作者不对任何人使用本工具造成的后果负责，包括但不限于违反校规、违反所在机构的使用条款、
或与目标产品厂商的许可协议冲突。
