# 计划书 → 实现对照

《计划书.md》里的每个条目在本项目里的落点。**这是交接时最先看的一页。**

## 目标能力

| # | 能力 | 实现位置 | 与计划书的差异 |
|---|---|---|---|
| G1 | 广播窗口化 | `WindowFixer` + `IsBroadcastWindowEx`（Guards.cpp）+ `WinGuard`（payload/winguard.cpp） | 第三次实机后修判定：类名是唯一硬锚点（读不到进程名也认），另加“全屏+置顶+厂商进程”兜底；`--winlist` 用同一函数做诊断 |
| G2 | 黑屏压制 | `BlackGuard`（Guards.cpp） | 加了速率退避（>20 次/分钟退到 1s），计划书的风险 R6 |
| G3 | 键盘解锁 | `InputUnlocker::Tick` | 同计划：结束 `PDelKeyB.exe` |
| G4 | 鼠标解锁 | `unlock::QuitThreads` + 载荷 `UnlockPass` | **两条通道**：外部投 `WM_QUIT`（定位锁线程）＋ 进程内 `UnhookWindowsHookEx`。见下 |
| G5 | 拦截结束请求 | 载荷 `DetTerminateProcess` / `DetNtTerminateProcess` | IAT hook；判定从"pid 名单"扩到"非厂商用户程序"；补 ntdll 路径 |
| G6 | 命令闸门 / 网络限制 | 载荷 `DetCreateProcess*/DetWinExec/DetShellExecuteEx*` + `DetCreateFileW/A/2` + `DetDeviceIoControl` + `App::NetGuardTick` | 闸门加“安装目录一律放行 / mmcLimitConsole 立即拒绝”；网络侧加 IOCTL 层（覆盖注入前就打开的老句柄）与执行器清理 |
| G7 | 紧急热键 | `MsgProc` WM_HOTKEY + `Ui::ShowFakeBlack` | 同计划 |
| G8 | 托盘 + 状态窗 | `Ui`（Ui.cpp） | 图标运行期用 GDI 画，不依赖资源编译器 |
| G9 | 单文件发行 | `build.py` + `LoadEmbeddedPayload` | 用"尾部追加 + CRC footer"代替 RCDATA（没有 rc.exe） |

## 两处最重要的改动（以及为什么）

### 1. G4 有两条通道：外部投 WM_QUIT，进程内 UnhookWindowsHookEx

计划书假设 `HookLib!Lock(FALSE)` 是解锁入口。反汇编后发现 **`Lock(0)` 直接 return，什么都不做**：

```
Lock: cmp [esp+4],0 ; je end ; CreateThread(...) ; end: ret
```

真正的清理在锁线程自己的析构路径里（`GetMessage` 返回 0 → `UnhookWindowsHookEx` → 置空 `g_hHook`）。
所以实现改成：枚举目标进程线程 → `NtQueryInformationThread(9)` 取起始地址 → 落在 `HookLib` 模块范围内
的就是锁线程 → `PostThreadMessage(tid, WM_QUIT)`。

好处：不需要注入、不受调用约定影响、走的是厂商自己的代码路径。

**但第一次实机反馈暴露了这条路的边界**："后手启动（先被锁、再开工具）时解不开"。
原因是外部通道要求三件事同时成立：模块能枚举、线程起始地址能读、**线程有消息队列**。
`PostThreadMessage` 对没有消息队列的线程会返回 `ERROR_INVALID_THREAD_ID(1444)`，
而旧实现只看"投递成功几条"，失败时静默返回 0，主程序以为没事发生。

现在：

1. 外部通道投递后**等 450 ms 复查线程是否真的退出**（`survived`），不再以"投递成功"当"已解锁"；
2. 失败/不匹配会写日志并置 `needInProc`，主程序随即下发 `seqUnlock`；
3. 载荷在进程内 `UnhookWindowsHookEx(g_hHook)` —— 不依赖线程配合，也不需要它有消息队列；
4. 解锁后给 3 秒"保持窗口"，每 150 ms 复查，厂商重新装钩子就再摘一次；
5. `CloudTrainer.exe --unlock` 提供无界面的一次性解锁入口（被锁住时托盘可能点不到）。

`Lock(0)` 仍然是空操作，所以从头到尾没有调用过厂商的导出。

### 2. G5/G6 用 IAT hook，不用 inline hook

计划书写的是 mhook + disasm-lib。实际实现改成 IAT hook，理由：

- inline hook 要改写函数序言，需要指令长度反汇编器；算错一个字节就是目标进程崩溃；
- IAT hook 只改导入表里的一个指针，恢复就是写回原值；
- 厂商是常规 C++ 静态导入，IAT 覆盖得到。

代价写在 README 的已知限制里：厂商若改用 `GetProcAddress` 动态解析，这一层失效（不崩，只是不生效）。

## 模块对照

| 计划书模块 | 实现 | 说明 |
|---|---|---|
| M0 App | `CtMain.cpp` | 提权改成"运行时 runas 重启"，不依赖 manifest（没有 rc 编译器）；单实例仍是命名事件 |
| M1 Locator | `Locator`（Core.cpp） | 增加"从安装目录的 exe 名单推候选进程"，避免全系统扫模块 |
| M2 WindowFixer | `WindowFixer`（Guards.cpp） | 仅 L1 |
| M3 BlackScreenGuard | `BlackGuard` | — |
| M4 InputUnlocker | `InputUnlocker` | 见上 |
| M5 Injector / IpcServer | `Inject.cpp` + `Reflect.cpp` | 反射加载器独立成模块，可单测 |
| M6 Payload | `src/payload/*` | 不用 CRT；IAT hook；共享内存 IPC |
| M7 Hotkey / Emergency | `MsgProc` + `App::RestoreAll` | 全部还原会**同时关掉所有能力**，否则 5 秒后策略又把注入装回去 |
| M8 TrayApp | `Ui` | 原生 Win32 |
| M9 VersionGuard | `VersionGuard` | 指纹 = size + PE TimeDateStamp，全部实测值 |

## 没做的

| 项 | 原因 |
|---|---|
| 子类化里的顺序错误 | **已修**。原实现"先改 WINDOWPOS 再 CallWindowProc"，修改被目标过程覆盖，表现为拖动回弹/置顶回弹。现在一律先调原过程再修正 |
| ~~L2 窗口子类化~~ | **已补上**。实机证明 L1 只能缩尺寸：标题栏被 `WM_NCCALCSIZE` 吃掉、置顶被 `WM_WINDOWPOSCHANGING` 抢回、光标被线程级 `ShowCursor(0)` 隐藏，三者都必须在进程内解决 |
| 计划书 4.3 的分频预算（300/800/2000/5000ms） | 统一收敛到 250ms 心跳 + 各模块内部节流（`PidsWithModule` 2s 缓存、`FindInstallDir` 10s 缓存、鼠标解锁 600ms 节流），实测 CPU 占用可以忽略 |
| `--restore` 命令行 | 没有需要持久化的东西（不写注册表、不改配置），"还原"就是关掉能力 + 卸 hook，做成按钮比做成命令行更合理 |
| 驱动 / 反监视 / UDP 重放 / 更新器 | 计划书的非目标 N1–N10，一致 |

## 新增的东西（计划书里没有的）

| 项 | 为什么加 |
|---|---|
| `Reflect.cpp` + `tests/` | 注入是最容易出错的一环，必须能单独测。测试抓到了白名单数组越界的致命 bug |
| `tools/inspect.py` / `tools/check_imports.py` | 产物自检；后者证明了"转发导出"不是理论问题（42/72） |
| `rep.gateCalls` 等诊断计数 | 没有它就无法判断"IAT hook 到底有没有被调用" |
| 载荷里 `SafeRead` / `ClearHookHandle` | 载荷跑在别人家里，任何野指针都会让目标进程消失；读写 `g_hHook` 前先 `VirtualQuery` |
| `protectUserApps` 开关 | 计划书的 G5 只保护固定 pid，挡不住教师端"关闭某个应用"；扩成"非厂商、非系统的用户程序" |
