# CloudTrainer

> 把 [JiYuTrainer](https://github.com/imengyu/JiYuTrainer)（针对极域电子教室 / Mythware）的**技术思路**，
> 重新实现为针对**联想电子教室（NeiCloud）**学生端的 Windows 工具。

**版本** 1.0.0　·　**目标** 联想电子教室 / NeiCloud 学生端（`Student.exe`，2022–2023 构建）
·　**形态** 单文件 exe、x86、原生 Win32、无安装、无运行库依赖
·　**思路来源** JiYuTrainer（MIT, © imengyu），本项目不含其任何业务代码

---

## 先读这一段

**这不是"改个进程名的移植"。** 联想与极域是两个完全独立的产品，业务层代码 0% 可复用：

| 对比项 | 极域 / Mythware | 联想 / NeiCloud |
|---|---|---|
| 学生端 | `StudentMain.exe`（厚主进程） | `Student.exe` + 一堆独立子进程 |
| 广播窗口 | 学生主进程内的窗口 | **独立进程** `MultiRender.exe` |
| 黑屏 | 主进程内窗口 | **独立进程** `BlackSlient.exe` |
| 键盘锁 | 主进程内 LL 钩子 | **独立 x64 进程** `PDelKeyB.exe`（PyInstaller / 5 行 Python） |
| 鼠标锁 | 主进程内 hook | `HookLib.dll` 的一个**独立锁线程** |
| 内核防线 | 2 个专用驱动 + 服务 | **没有**（只有一个不会被加载的 WFP 样例驱动） |
| 自保护 | 服务 + 驱动 + 口令 | Run 键 + 一个用户态看护进程 |

结论：**联想的防护更薄，但结构完全不同**。所以做法是"按它的结构重新设计"，
而不是"把 JiYuTrainer 的 hook 表照搬过来"。

---

## 目录

- [能力矩阵](#能力矩阵)
- [快速上手](#快速上手)（热键 / 配置 / 「全部还原」的语义）
- [它是怎么做到的](#它是怎么做到的)（窗口层 / 进程线程层 / 注入层）
- [代码结构](#代码结构)
- [构建](#构建)
- [验证到了什么程度](#验证到了什么程度)
- [已知限制](#已知限制)
- [与 JiYuTrainer 的对照](#与-jiyutrainer-的对照)
- [合规](#合规)

---

## 能力矩阵

| # | 能力 | 实现方式 | 需要注入 | 需要管理员 |
|---|---|---|---|---|
| G1 | **广播窗口化**：全屏广播变成可拖动 / 可最小化 / 可被遮挡的窗口 | 外部改窗口样式 + `SetWindowPos`，每 250 ms 复查 | 否 | 建议 |
| G2 | **黑屏压制**：`BlackSlient.exe` 一出现就结束 | `TerminateProcess` 循环，带速率退避 | 否 | 否 ᴬ |
| G3 | **解除键盘锁** | 结束 `PDelKeyB.exe`，LL 钩子随线程退出即销毁 | 否 | 是 |
| G4 | **解除鼠标锁** | 给 `HookLib.dll` 的锁线程投 `WM_QUIT`，走厂商自己的析构路径 | 否 | 是 |
| G5 | **拦截结束请求** | 目标进程内 IAT hook `TerminateProcess` | 是 | 是 |
| G6 | **远程命令闸门** | 目标进程内 IAT hook `CreateProcessW/A`、`WinExec`、`ShellExecuteExW` | 是 | 是 |
| G7 | **紧急热键** `Ctrl+Alt+F / H / D` | 假黑屏窗口 + `WH_KEYBOARD_LL` + `RegisterHotKey` | 否 | 否 |
| G8 | **托盘常驻 + 状态窗** | 原生 Win32（`Shell_NotifyIcon` + 运行期自绘图标） | 否 | 否 |
| G9 | **单文件绿色发行** | 载荷追加在 exe 尾部（CRC footer 校验），运行期读回 | — | — |

ᴬ 结束其它用户的进程通常需要管理员；`BlackSlient.exe` 以当前用户身份运行，普通权限往往也够。

**两个设计取舍：**

1. **G1–G4 全部不注入。** 联想的广播、黑屏、键盘锁、鼠标锁都是独立进程 / 线程，
   "让它自己退出"比"注入进去改它的行为"简单一个数量级，也不会让目标进程崩溃。
2. **启动默认全开。** `startupEnableAll=1` 时 7 个能力在每次启动时全部打开；托盘里可以临时关掉
   （只影响本次会话），重启后恢复全开。要"关掉就一直关着"，把它改成 `0`。

---

## 快速上手

```
CloudTrainer.exe                启动（弹 UAC，托盘常驻）
CloudTrainer.exe --probe        只读体检：安装目录 / 指纹比对 / 进程与 HookLib 宿主，打印后退出
CloudTrainer.exe --no-elevate   不提权运行（注入类能力自动降级）
CloudTrainer.exe --elevated     内部使用，提权重启时带上
```

建议第一次先跑 `--probe`，确认那 8 个文件指纹与你的版本对得上（对不上会自动降级为只读模式）。

### 热键

| 热键 | 行为 |
|---|---|
| `Ctrl+Alt+F` | 假装黑屏（全屏黑窗 + 吞键盘，**不锁鼠标**），再按一次退出 |
| `Ctrl+Alt+H` | 全部还原：**3 秒内按两次**才执行 |
| `Ctrl+Alt+D` | 显示 / 隐藏状态窗口 |

### 配置

`%LOCALAPPDATA%\CloudTrainer\config.ini`，改完重启生效；托盘里也能随时切换能力开关。

```ini
startupEnableAll=1    # ★ 启动时默认开启全部能力（1=每次启动全开；0=按下面的开关来）
fixBroadcast=1        # 广播窗口化
fixWidth=1280         # 窗口宽度（keepAspect=1 时按显示器比例换算高度）
keepAspect=1
allowTopmost=0        # 改完是否仍置顶
killBlackScreen=1
unlockKeyboard=1
unlockMouse=1
blockTerminate=1      # 拦截结束请求
blockClose=1          # 拦截跨进程 WM_CLOSE
cmdGate=1             # 远程命令需要本机确认
protectUserApps=1     # G5：挡住对"任意非厂商用户程序"的结束请求
cmdGateTimeout=20     # 裁决等待秒数
autoInject=1
installDir=           # 非默认安装路径时手工指定
```

### 「全部还原」的语义

把我改过的都还回去：撤假黑屏钩子 → 还原广播窗 → 卸载载荷里所有 IAT 补丁 → 请求载荷线程退出，
**同时把 7 个能力开关全部关掉**（否则 5 秒后策略下发又会把注入装回去，按钮就成了摆设）。
**不会**把键鼠重新锁上，那是厂商的事。

因为默认 `startupEnableAll=1`，所以**下次启动又是全开**；只有把这一项改成 `0`，"关掉"才会跨重启保留。

---

## 它是怎么做到的

### 1. 窗口层（G1）

广播窗口是 `MultiRender.exe` 的顶层窗口，类名 `MultiRenderWindowClass`，全屏 + `HWND_TOPMOST`。
外部进程可以直接改它的样式：

```
WS_POPUP     ->  WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX
HWND_TOPMOST ->  HWND_NOTOPMOST（可配）
SetWindowPos(..., SWP_FRAMECHANGED | SWP_NOSENDCHANGING)
```

`SWP_NOSENDCHANGING` 是关键：不通知目标进程，避免它用 `WM_WINDOWPOSCHANGING` 把尺寸改回去。
全屏判定用 `MonitorFromWindow` + `GetMonitorInfo`，**不用** `SM_CXSCREEN`（多显示器必错）。

### 2. 进程/线程层（G2–G4）

- **黑屏**：`BlackSlient.exe` 不在 `protect.map` 里，结束它不会被拉起。250 ms 级别循环 + 速率退避足够。
- **键盘**：`PDelKeyB.exe` 是 PyInstaller 打包的 5 行 Python 脚本，`return False` 无条件吞键，
  没有 IPC、没有看护。进程一退，`WH_KEYBOARD_LL` 随安装线程消失，键盘**立即**恢复。
- **鼠标**：本项目最"巧"的一处。`HookLib.dll` 的 `Lock(int)` 在 `arg == 0` 时**什么也不做**
  （反汇编可见 `cmp [esp+4],0; je end`），它只是 `CreateThread` 起一个装钩子 + 跑消息泵的线程。
  于是我们不调它的导出，而是：

  ```
  1. 枚举目标进程的线程；
  2. 用 NtQueryInformationThread(ThreadQuerySetWin32StartAddress) 取线程入口；
  3. 入口落在 HookLib 模块范围内的，就是锁线程；
  4. PostThreadMessage(tid, WM_QUIT) —— 它的消息循环退出后会自己调用 UnhookWindowsHookEx。
  ```

  这是厂商**自己的析构路径**，比"注入进去强转函数指针"稳得多，也不受调用约定影响。

### 3. 注入层（G5 / G6）

只有"拦截结束请求"和"远程命令闸门"需要进入目标进程。这里做了三处和 JiYuTrainer 不同的选择：

| 议题 | JiYuTrainer | CloudTrainer | 为什么 |
|---|---|---|---|
| 加载方式 | `MemoryModule`（进程内） | 自实现远端映射：本地拼镜像 → 应用重定位 → 解析导入 → 整块写入 → 15 字节调用桩 | 需要**跨进程**映射，不是进程内加载 |
| Hook 方式 | inline hook（mhook + 反汇编器改写序言） | **IAT hook**（只改导入表指针） | 改序言出错就是目标进程崩溃；改 IAT 恢复时写回原值即可 |
| IPC | `FindWindow` + `WM_COPYDATA` + 冒号字符串 | 共享内存 + 序号计数器 | 类型安全、无阻塞、可从外部观察；路径里的冒号不会再解析错 |

**导入表修复里的一个坑**：`kernel32!CreateFileW` 这类函数实际在 `kernelbase.dll` 里（转发导出）。
如果按"LoadLibrary 返回的 HMODULE + RVA"去算，IAT 会指飞。正确做法是先用
`GetModuleHandleEx(FROM_ADDRESS)` 找出**真正包含该地址的模块**再算 RVA。
本项目产物里 72 个导入符号中有 **42 个**是转发导出——这不是理论问题，是必答题
（`tools/check_imports.py` 会把这件事跑一遍给你看）。

**载荷为什么不用 CRT**：手工映射的 DLL 没有加载器替它跑 `_CRT_INIT`，也不会处理 TLS 目录。
所以载荷用 `-nostartfiles` 构建，入口直接是 `CtPayloadEntry`，不使用任何 C++ 标准库设施、
没有全局构造、没有异常、没有 `__thread`。

> 这套工具链仍会在 DLL 里留一个空的 `.tls` 段（连最小的 C DLL 也有），我们不处理它 ——
> 因为载荷代码根本不访问 TLS。`tests/run_inject_test.py` 会在真实进程里把载荷跑起来，
> 等于每次构建都验证了这一点。

---

## 代码结构

```
CloudTrainer/
├─ build.py                     一键构建（自动找 / 下载 zig）
├─ src/
│  ├─ common/
│  │  ├─ TargetDefs.h           ★ 唯一允许出现目标产品标识符的地方
│  │  └─ CtIpc.h                主程序 ↔ 载荷 的共享内存协议
│  ├─ main/                     CloudTrainer.exe（x86 GUI）
│  │  ├─ Core.h / Core.cpp      工具、日志、配置、目标发现、版本指纹
│  │  ├─ Guards.cpp             G1 窗口 / G2 黑屏 / G3 键盘 / G4 鼠标
│  │  ├─ Reflect.h / .cpp       反射加载器（独立模块，可单测）
│  │  ├─ Inject.cpp             共享内存会话 + 注入工作线程
│  │  ├─ Ui.cpp                 托盘 / 状态窗 / 裁决窗 / 假黑屏
│  │  ├─ Probe.cpp              --probe 只读体检
│  │  └─ CtMain.cpp             外壳、消息循环、调度、热键
│  └─ payload/                  CloudTrainerPayload.dll（注入载荷）
│     ├─ dllmain.cpp            入口（无 CRT）
│     ├─ payload.cpp            主循环、心跳、解锁
│     ├─ hooks.cpp              IAT hook + 命令闸门
│     └─ call1.S                安全调用"约定未知的单参数函数"
├─ tests/                       不依赖电子教室的端到端测试（详见 tests/README.md）
├─ tools/
│  ├─ inspect.py                PE 结构自检
│  ├─ check_imports.py          模拟加载器的导入解析
│  └─ zig/                      本地工具链（约 480 MB，已 gitignore）
├─ docs/
│  ├─ IMPLEMENTATION.md         计划书 → 实现 对照（交接先看这个）
│  ├─ MECHANISM.md              逆向结论与证据索引
│  ├─ SECURITY.md               提权 / 注入 / 写盘 / 网络说明
│  └─ BUILD.md                  构建细节与换工具链的方法
└─ dist/                        构建产物（不入库）
   ├─ CloudTrainer.exe           单文件（内含载荷）
   └─ CloudTrainerPayload.dll    留档，便于排错
```

**架构硬约束**：除 `src/common/TargetDefs.h` 外，任何源文件都不允许出现目标产品的
进程名 / 类名 / 导出名 / RVA。适配新版本只改这一个头文件。

---

## 构建

本机没有 MSVC / CMake / MinGW，所以工程自带一个能产出 i686 PE 的工具链：**zig**（自带 mingw-w64 头与库）。

```bash
python build.py            # 增量构建（仓库自带工具链时约 5 秒）
python build.py --clean    # 清理重建
```

`build.py` 会依次：

1. 找 zig（`ZIG` 环境变量 → `tools/zig/zig.exe` → `build/zigpkg/…` → `../.ct-build/zigpkg/…`），
   都没有就去 PyPI 镜像下载；
2. `zig c++ -target x86-windows-gnu` 编译载荷（`-nostartfiles`，入口 `CtPayloadEntry`）；
3. 同样参数编译主程序（`--subsystem windows`，入口 `WinMainCRTStartup`，`-static`）；
4. 把载荷追加到 exe 尾部，附 16 字节 footer（magic / size / crc32 / flags）；
5. 自检：架构必须是 i386、PE32、GUI、footer CRC 正确。

产物：

```
dist/CloudTrainer.exe        677 KB   单文件
dist/CloudTrainerPayload.dll 208 KB   仅留档
```

> 需要一个能**执行子进程**的环境（zig 会 fork 自己来跑各编译单元）。
> 在受限沙箱里构建会报 `Couldn't execute program 'zig.exe': 拒绝访问`，这不是代码问题。

工具链占 476 MB（`zig.exe` + `lib/` + 编译缓存 `cache/`），已在 `.gitignore` 里排除。
缓存放在工具链旁边而不是 `build/` 里，是为了让"清掉 build/ 再构建"仍然是 5 秒而不是 2 分钟。
取舍见 [docs/BUILD.md](docs/BUILD.md)。

---

## 验证到了什么程度

**已在本机验证**（测试目标是仓库自带的 `tests/host.exe`，一个空转的控制台程序 ——
**全程没有启动任何电子教室程序**）：

| 项 | 方法 | 结果 |
|---|---|---|
| PE 结构 | `tools/inspect.py` | i386 / PE32 / GUI；除系统 DLL 外无运行库依赖 |
| 导入可解析 | `tools/check_imports.py` | 72 个符号全部可解析；其中 **42 个是转发导出** |
| 反射注入 | `tests/run_inject_test.py` | 首选基址与**被占用后走重定位**两种场景都成功 |
| 载荷启动 | 同上 | 目标进程内出现共享内存会话，心跳正常 |
| 策略下发 | 同上 | `flags=0x39`、IAT 补丁 2 处（`CreateProcessW` / `TerminateProcess`） |
| 命令闸门 | 同上 | 随机路径被拦下并拒绝 → `ERROR_ACCESS_DENIED` |
| 厂商白名单 | 同上 | `BlackSlient.exe` 被放行（不误伤产品自身） |
| 卸载路径 | 同上 | 载荷退出、目标进程存活 |

> 测试过程中确实抓到过一个致命 bug：厂商白名单数组缺 `nullptr` 哨兵，遍历越界，
> 导致宿主进程当场崩溃。在真机上这就是"一注入就把 `Student.exe` 打没"。
> 现在数组末尾有哨兵，并且测试会持续覆盖这条路径。

**尚未验证**（需要授权环境 + 真实产品）：

- 广播窗口化在真实 `MultiRender.exe` 上的表现（包括它是否会反复把窗口弹回全屏）；
- 给 `HookLib.dll` 的锁线程投 `WM_QUIT` 后鼠标是否真的恢复（逻辑依据是反汇编，未实机跑过）；
- 教师端对"广播窗口变小"是否会察觉；
- 不同版本 / 不同部署路径下的指纹匹配。

---

## 已知限制

1. **版本敏感**。指纹锁定的是 2022–2023 的那份构建（`TargetDefs.h` 的 `kFingerprints`）。
   主链指纹不匹配时自动降级为"只读模式"：只保留 G1 和 G7，不杀进程、不注入。
   换版本请先跑 `--probe` 看匹配情况，再改 `TargetDefs.h`。
2. **IAT hook 的边界**。如果厂商改成 `GetProcAddress` 动态解析 API，G5/G6 会失效（不会崩，只是不生效）。
3. **命令闸门会阻塞目标线程**。裁决期间，调用 `CreateProcess` 的那个线程会等最多 `cmdGateTimeout` 秒。
   主程序不在线（心跳超过 6 秒）时**直接放行**，避免把学生端卡死。
4. **载荷内存不回收**。`Ctrl+Alt+H` 会卸载所有 hook 并让载荷线程退出，但已映射的 ~200 KB
   会留在目标进程地址空间里直到该进程重启（是只读的死内存，不执行任何东西）。
   强行 `VirtualFreeEx` 有把目标进程打崩的风险，不值得。
5. **只针对 x86**。`Student.exe` 是 32 位，载荷也是 32 位；`PDelKeyB.exe` 是 x64，但我们只结束它，不注入。
6. **需要 Windows 10 及以上**。产物依赖 UCRT（`api-ms-win-crt-*`），Win7 未验证。
7. **不做的事**：反监视（屏蔽教师抓屏）、破解教师端 / 卸载口令、启停学生端、断网锁屏、
   UDP 协议重放、驱动、自动更新、多版本自适配、免杀。
8. **副作用**：`BlackSlient.exe` 同时被"断网锁屏"复用（文案"断网锁屏中，联网后恢复！"），
   压制黑屏会顺带压制这个提示。

---

## 与 JiYuTrainer 的对照

复用的是**思路**，不是代码：

| JiYuTrainer 的东西 | 本项目 |
|---|---|
| `MemoryModule.cpp` | 思路参考，但它的实现只能进程内加载；本项目重写为跨进程远端映射 |
| `mhook` + `disasm-lib` | **不用**。改用 IAT hook，避开指令长度反汇编 |
| `MsgCenter`（WM_COPYDATA + 冒号字符串） | **弃用**。改共享内存 + 序号计数器 |
| `NtHlp` / `SysHlp` / `PathHelper` / `Logger` | 接口思路借鉴，实现全部重写（Unicode、滚动日志、无全局状态） |
| 37 个 inline hook | 只保留 `TerminateProcess` / `CreateProcess` / `WM_CLOSE` 三类，且改到 IAT 层 |
| Sciter UI | 换成原生 Win32（Sciter 5.x 已转商用授权） |
| 驱动 / UDP 攻击 / 更新器 | 不做 |

从它身上学到、并明确规避的坑：不在 `DllMain` 里装 hook；不在 `PROCESS_DETACH` 里
`FreeLibrary(自己)`；不用窗口标题做 IPC；不用冒号分隔字符串传路径；不用 `SM_CXSCREEN` 判全屏；
不用 `SetWindowLong` 跨进程子类化；注入后必须校验返回码。

更多内容见 [docs/NOTICE.md](docs/NOTICE.md)。

---

## 合规

- 仅用于**个人学习**与**自有设备**，或在**已获得授权**的教学环境中使用。
- 本项目**不联网**、不上报、不写目标产品目录、不改其配置文件、不启停学生端进程。
- 详细说明见 [docs/SECURITY.md](docs/SECURITY.md)。
- 使用后果自负。如果你不确定自己是否有权这么做，那就不要用。

MIT License。
