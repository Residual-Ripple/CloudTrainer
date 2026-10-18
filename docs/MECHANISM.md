# 目标产品机制（逆向结论与证据索引）

> 对象：联想电子教室 / NeiCloud 学生端（`F:\project\harness\Lenovo teaching system` 快照）
> 方法：**纯静态**——PE 头 / 导入导出表 / 字符串 / 反汇编 / 运行期日志与配置。未运行任何二进制。
> 基线：`Student.exe` 1,951,584 B / `TimeDateStamp` 0x635F7F21（2022-10-31）

本文只写结论和地址，不贴反汇编长段。地址随版本变化，仅用于排错。

---

## 1. 身份

| 项 | 值 |
|---|---|
| 产品名 | 联想电子教室 / 联想云教室（`chs.config` 内 `Neicloud`） |
| 内部代码基 | `NeiCloud-1.0`（PDB 路径 `d:\work\branches\NeiCloud-1.0`） |
| 签名 | `CN=联想（北京）有限公司` |
| 与极域关系 | 双向关键词 grep = 0 命中；DLL 命名零交集。**同源的可能性为零** |
| 遗留构件 | `BlackSlient.exe`(2017)、`LockKeyboard.dll`(2014)、`systemoper1.dll`(2015) |

---

## 2. 进程拓扑

```
Startup.exe（只写 Run 键）
└─ Student.exe                      学生端主进程，单实例用命名事件 StudentRunning
   ├─ LoadLibrary: StudentLogic / MainLogic / ScreenMonitorLib / HookLib / ...
   ├─ ProcessProtect.exe            读 protect.map（本机只有一行：Student.exe）
   ├─ MultiRender.exe               屏幕广播渲染（类名 MultiRenderWindowClass）
   ├─ BlackSlient.exe               黑屏安静（类名 DMTWnd）
   ├─ PDelKeyB.exe                  键盘锁（x64, PyInstaller）
   ├─ Multi.exe                     渲染调度（日志 multi.log）
   └─ FileTransferClient.exe / ScreenPen.exe / ScreenRecord.exe / ...
```

**关键事实**

- 全目录**没有服务**（无 `OpenSCManager` / `CreateService` 导入）。
- 全目录**没有有效的内核防线**：唯一驱动 `inspect.sys` 是从 GitHub 的
  `WFP-Traffic-Redirection-Driver` 样例改名编译的，`StartType=2`(Demand)，运行期无人启动。
- 单实例用**命名事件**（`StudentEvent` / `StudentRunning` / `TeacherEvent` / `StudentWarning` /
  `UnInstallEvent`），全产品无 `CreateMutex` 导入。
- `protect.map` 是明文文本，本机内容就一行 `Student.exe`。

---

## 3. 屏幕广播（G1 的目标）

```
Teacher.exe → menu_ScreenCast → MainLogic.dll → ScreenSender.exe
   → UDP 组播 225.0.0.70/72 → StudentLogic.dll 收到 id=19(0x13), type=1
   → 打印 "multi_render.Start" → CreateProcess(MultiRender.exe "<JSON>")
```

- 广播窗口**不在学生主进程里**，是 `MultiRender.exe` 的顶层窗口。
- 类名 `MultiRenderWindowClass`，全屏 + `HWND_TOPMOST` + `ShowCursor(0)`。
- **它自己不装任何输入钩子**（输入锁是另一套）。
- `MultiRender.exe` 参数是 JSON：`teacher_ip / remote / port / local / decoderName / des /
  appType / verityPort / controler_port / controler_host`。

**证据**：`StudentLogic.dll` id 分发器 VA 0x1001EDB0；id=19 分支 VA 0x100202D8；
type==1 判定 VA 0x100202F2；字符串 `multi_render.Start` VA 0x1008A398。

---

## 4. 黑屏安静（G2 的目标）

| 项 | 值 |
|---|---|
| 教师指令 | id = **12 (0x0C)**，载荷 `"blacksilent"` |
| 学生侧 | `StudentLogic` 先 `TerminateProcess` 旧实例，再 `CreateProcess` 新的 |
| 程序 | `BlackSlient.exe`，参数是消息文本（如"请大家保持安静！"） |
| 窗口 | 类 `DMTWnd`，`WS_EX_TOOLWINDOW` + `HWND_TOPMOST` + `ShowCursor(0)` |
| 皮肤 | `skin\StuLockWnd.xml`，800×600，纯黑 |
| 保护 | **不在 `protect.map` 里** → 可单独结束，不会被拉起 |

**复用**：`StudentLogic!LockComputer`（断网锁屏）也用同一个 exe。

**证据**：id=12 分支 VA 0x1001FF94；`BlackSlient.exe` 字符串 VA 0x1008A60。

---

## 5. 键鼠锁（G3 / G4 的目标）

### 5.1 统一开关

`StudentLogic.dll` / `Multi.exe` / `RcfInterfaceLib.dll` 里都有同一个函数（注意厂商拼写）
`MouseKeybroadLimit(int)`：

| 参数 | 行为 |
|---|---|
| `1` | 启动 `PDelKeyB.exe` + `HookLib!Lock(TRUE)` + `mouse_event` 把光标钉到屏幕外 |
| `0` | `HookLib!Lock(FALSE)` + `TerminateProcess(PDelKeyB)` |

### 5.2 键盘锁 = `PDelKeyB.exe`

PyInstaller **onefile**，6.79 MB，x64，内嵌 `python37.dll` + `_cpyHook.cp37-win_amd64.pyd`。
解包后还原的入口脚本完整就是 5 行：

```python
def onMouseEvent(e): return False        # 死代码，从未挂载
def onKeyboardEvent(e): return False     # 无条件吞键
hm = pyWinhook.HookManager(); hm.KeyDown = onKeyboardEvent; hm.HookKeyboard()
pythoncom.PumpMessages()
```

- 无参数解析、无单实例、无 IPC → **没有任何"通知它解锁"的接口**。
- 由 `RcfInterfaceLib!OnNotify` 用 `ShellExecuteExW(verb="runas")` **提权**启动。
- `WH_KEYBOARD_LL` 随安装线程退出即销毁；`protect.map` 里没有它 → **没有看护**。

### 5.3 鼠标锁 = `HookLib.dll` 的锁线程

导出只有两个：`Lock`、`SetMouseFilter`。`Lock(int)` 的真实语义（RVA 0x2A60）：

```
cmp [esp+4], 0
je  end                 ; ★ 参数为 0 时直接返回，什么也不做
CreateThread(sa=0, stack=0, start=0x10001420, param=0x1001A168, flags=0, tid=&0x1001A170)
mov [0x1001A168], eax   ; 存 hThread
end: ret                ; 裸 ret → cdecl
```

线程体（RVA 0x14A0）才是关键：

```
SetWindowsHookExW(WH_MOUSE_LL, 0x10001530, hInst, 0) → [0x1001A1B4] (g_hHook)
while (GetMessageW(&msg, 0, 0, 0) > 0) {
    if (msg.message != 0x401) { TranslateMessage; DispatchMessage; }
}
UnhookWindowsHookEx([0x1001A1B4]); [0x1001A1B4] = 0;
```

钩子过程（0x10001530）：`cmp [ecx+0x14], 0x12452; jz next; mov eax,1; retn 0Ch`
—— `dwExtraInfo == 0x12452` 的合成事件放行，其余全部吞掉。配套 `ShowCursor(0)`，
所以鼠标**完全不动**（不是"能动但点不动"）。

**由此得到本项目的解法**：不调 `Lock`，而是找到这个**锁线程**并给它投 `WM_QUIT`。
它的消息循环 `GetMessageW <= 0` 后会自己 `UnhookWindowsHookEx` —— 走的是厂商自己的析构路径。

**证据**：`SetWindowsHookExW` IAT 槽 0x10012324；`g_hHook` VA 0x1001A1B4；
锁线程入口 RVA 0x1420（thunk）→ 0x14A0（主体）；`Lock` 导出 RVA 0x2A60。

---

## 6. 指令 id

| id | hex | 含义 | 置信度 |
|---|---|---|---|
| **19** | 0x13 | 屏幕广播开始（type=1） | 高（反汇编） |
| **12** | 0x0C | 黑屏安静 / Lock | 高（反汇编） |
| 25 | 0x19 | 文件传输开始 | 高 |
| 38 | 0x26 | 文件传输结束 | 中 |
| 45 | 0x2D | 配置解析 | 高 |
| 43 | 0x2B | 设置字段 | 中高 |
| 67 | 0x43 | 解锁（紧接 id=12 出现） | 中 |
| 83 | 0x53 | 心跳 / 在线状态 | 中 |
| 85 | 0x55 | 握手 / 教师信息 | 中 |
| **93** | 0x5D | **NetLock（网络锁定）**，不是黑屏 | 高（反汇编） |

> 注意：`student.log` 里从没出现过 id=19 —— 抓日志那次没有做广播。不要用日志里的 id 去猜广播。
> 顺带一提：`BlackSlient`、`MouseKeybroadLimit`、`Qulity` 三个拼写错误是这套代码的稳定特征。

---

## 7. 配置与持久化

| 文件 / 位置 | 说明 |
|---|---|
| `general.config` | `/Key/value/` 行式，明文；含 `Password=admin99`（本项目不使用） |
| `mmc.cfg` | 服务器地址与本地过滤 |
| `chs.config` | 543 行界面文案（所以二进制里一个中文都没有） |
| `protect.map` | 看护名单，一行 `Student.exe` |
| `HKCU/HKLM\...\Run` | `Startup.exe` —— 唯一的自启动 |
| 服务 | **无** |

---

## 8. 弱点清单（与本项目相关的那几条）

| # | 弱点 | 影响 |
|---|---|---|
| 1 | 黑屏是独立 exe，且不在保护名单 | G2 只需一个 TerminateProcess 循环 |
| 2 | 键盘锁是独立小进程，无看护、无 IPC | G3 只需结束它 |
| 3 | 鼠标钩子跑在独立线程里，线程一退钩子就没 | G4 只需一个 `WM_QUIT` |
| 4 | 广播窗口是独立顶层窗口 | G1 外部改样式即可，无需注入 |
| 5 | `protect.map` 明文、无服务、无驱动 | 没有需要正面对抗的内核防线 |
| 6 | 厂商是常规 C++ 静态导入 | G5/G6 的 IAT hook 覆盖得到 |

反过来说，**不该做的事**也清楚了：不需要驱动、不需要反监视、不需要碰配置（教师端会覆盖且留痕）、
不需要"破解"口令（它本来就明文写着）。

---

## 9. 未解事项

| # | 事项 | 怎么解 |
|---|---|---|
| 1 | 广播期间鼠标锁到底装在 `Student.exe` 还是 `Multi.exe` | 本项目**不赌**：对所有加载 `HookLib.dll` 的进程都尝试退出锁线程 |
| 2 | `id=67` 是否真是 Unlock | 抓包或反汇编 0x10024D00 |
| 3 | 教师端能否察觉"广播窗口变小" | 需要教师端环境 |
| 4 | `ProcessProtect.exe` 的重启延迟与策略 | 实机观察（本项目不碰它） |
