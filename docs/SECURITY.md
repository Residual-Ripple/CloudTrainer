# 安全与合规说明

这份文档回答一个问题：**CloudTrainer 在系统上到底做了什么、没做什么。**

---

## 1. 自身的暴露面

| 项 | 处理 |
|---|---|
| 提权 | 未提权时用 `ShellExecuteExW(verb="runas")` 重启自己，**弹标准 UAC**；被拒绝就以普通权限继续跑（注入类能力自动失效）。不绕过 UAC，不静默提权 |
| 注入范围 | 只注入**本机、同位数（x86）、已识别**的目标进程：`Student.exe` 与加载了 `HookLib.dll` 的厂商进程。不碰系统进程 |
| 写盘 | 只写 `%LOCALAPPDATA%\CloudTrainer\`（日志 + 配置）。**不写目标产品目录，不改它的任何配置文件** |
| 注册表 | **完全不写**。只读（Run 键、Uninstall 键，用于定位安装目录） |
| 网络 | **完全不联网**。不更新、不统计、不上报、不下载 |
| 自启动 | **不注册**。没有 Run 键、没有计划任务、没有服务 |
| 卸载 | 删除 exe 与 `%LOCALAPPDATA%\CloudTrainer\` 即可。运行期改动见第 4 节 |
| 自我保护 | 给**本进程对象**加一条 DACL：`DENY 当前用户 PROCESS_TERMINATE`。只影响别人杀我们，不影响自己退出；不改系统策略、不装驱动、不注册服务 |

---

## 2. 为什么"改配置"被明确排除

`general.config` 是明文，把 `/BlackSlient/0/` 改掉确实能关黑屏。但：

1. 教师端每次下发会覆盖回去，等于和服务器打架；
2. 会在目标机器上留下修改痕迹，比进程级手段更容易被注意到；
3. 会让产品进入一个"配置说开、实际没开"的异常状态。

所以本项目**一律用进程级手段**，配置只读。

---

## 3. 注入做了什么

注入是风险最高的部分，这里逐条说明。

### 3.1 加载方式：手工映射，不落盘

```
OpenProcess(PROCESS_CREATE_THREAD|QUERY_INFORMATION|VM_OPERATION|VM_WRITE|VM_READ)
VirtualAllocEx(首选基址 0x10000000 → 失败则任意基址)
  本地拼镜像 → 应用 PE 重定位 → 解析并修复导入表（用"实际包含地址的模块"算 RVA）
WriteProcessMemory(整块镜像)
VirtualProtectEx(按节设置 R/X/RW)
VirtualAllocEx(15 字节调用桩) → CreateRemoteThread(桩)
```

- **不产生 DLL 文件**，`%TEMP%` 和目标目录都不会多出东西。
- 载荷在目标进程的模块列表里**没有路径**（手工映射，加载器不知道）。
- 调用桩只有 15 字节，内容固定可审计：`push base; mov eax,entry; call eax; ret 4`。

### 3.2 载荷不初始化 CRT

载荷用 `-nostartfiles` 构建，入口是 `CtPayloadEntry`。因此：

- 没有 `_CRT_INIT`、没有全局构造、没有 atexit、没有 C++ 异常/RTTI；
- 不使用 `__thread`，所以不需要处理 PE 的 TLS 目录（手工映射不会处理它）；
- 只用 Win32 与 `memcpy/wcsncpy/strcmp` 这类 UCRT 导出。

**少一个初始化环节，就少一类"注入成功但一调就崩"的事故。**

### 3.3 Hook 只动导入表

三种拦截全部是 **IAT hook**：找到厂商模块导入表里 `TerminateProcess` / `CreateProcessW/A` /
`WinExec` / `ShellExecuteExW` / `PostMessageW` / `SendMessageW` 的槽位，替换成自己的函数，
**原始地址保存下来**。卸载时逐个写回。

不修改任何指令字节，因此：

- 不会因为指令长度反汇编出错而破坏目标进程；
- 卸载是精确可逆的（写回原值即可）；
- 代价：如果厂商改成 `GetProcAddress` 动态解析，这一层会失效（不崩，只是不生效）。

### 3.4 每一个 hook 都有"放行"出口

| Hook | 什么情况下直接放行 |
|---|---|
| `TerminateProcess` | 目标是自己 / 是系统目录里的进程 / 在厂商白名单里 / 拿不到进程信息 |
| `CreateProcess*` / `ShellExecuteEx*` | 开关关闭 / 主程序心跳超过 6 秒 / 在厂商白名单 / 在目标安装目录内 / 裁决队列已满 |
| `PostMessage/SendMessage(WM_CLOSE)` | 目标窗口属于本进程 / 开关关闭 |

设计原则：**宁可漏挡，也不要把目标进程的正常流程搞坏。**

---

## 4. "全部还原"到底还原了什么

`Ctrl+Alt+H`（3 秒内两次）/ 托盘菜单"全部还原" / 退出程序，都会按下面的顺序执行：

1. 卸载假黑屏的 `WH_KEYBOARD_LL` 钩子（否则热键都被自己吞掉）；
2. 销毁假黑屏窗口；
3. 把所有被改过的广播窗口还原成全屏置顶；
4. 通知载荷：卸载全部 IAT 补丁 → 线程退出 → `rep.alive = 0`；
5. 关闭黑屏压制 / 键鼠解锁的定时任务。

**不还原**：厂商自己加的键鼠锁。语义是"把我改过的还回去"，不是"把墙重新砌起来"。

**残留**：载荷映射的那 ~200KB 内存会留在目标进程地址空间里直到它重启。它是只读死内存，
不执行任何代码、不持有任何句柄。强行 `VirtualFreeEx` 有把目标进程打崩的风险，所以不做。

---

## 4.5 自我保护到底做了什么

```cpp
GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, ...)   // 取现有 DACL
SetEntriesInAclW(DENY, 当前用户 SID, PROCESS_TERMINATE, ...)  // 追加一条拒绝
SetSecurityInfo(GetCurrentProcess(), ...)                     // 写回
```

- **挡得住**：以同一用户身份跑的 `TerminateProcess` / `taskkill /f` / 任务管理器结束任务
  —— 它们都需要 `PROCESS_TERMINATE`，会拿到 `ACCESS_DENIED`。
- **挡不住**：SYSTEM 权限的杀进程、驱动层强制结束、Job Object 的 `KILL_ON_JOB_CLOSE`。
- **副作用**：任务管理器里"结束任务"会失败。这是我们想要的，但要知道。
- **可关闭**：`selfProtect=0`。

## 5. 数据流

```
                     ┌──────────────────────────────┐
   主程序（管理员）   │  CloudTrainer.exe            │
                     │   req  ──写──┐               │
                     └──────────────┼───────────────┘
                                    │  Local\CloudTrainer.Shm.<pid>
                     ┌──────────────┼───────────────┐
   载荷（目标进程内） │  rep / pending ──写──┘        │
                     │  CloudTrainerPayload.dll      │
                     └──────────────────────────────┘
```

- 映射由**载荷创建**、主程序打开。反过来的话，低完整性进程打不开高完整性进程创建的 Section
  （Windows 的 no-read-up 强制策略）。
- 单向写：主程序只写 `req`，载荷只写 `rep` / `pending`，不需要锁。
- 心跳：载荷每 40ms 刷新，主程序 3 秒没更新就判定会话死亡并清理。

**共享内存里只有**：开关位、保护 pid 列表、计数器、待裁决的命令行文本。
**没有**：键盘记录、屏幕内容、账号、任何持久化数据。

---

## 6. 开源合规

- 本项目 **MIT**。
- **不包含** JiYuTrainer 的任何源码；只在 README / NOTICE 中致谢其技术思路。
- 不使用 `mhook` / `disasm-lib` / `MemoryModule`（见 NOTICE 的说明）。
- 不使用 Sciter（其 5.x 已转商用授权）。
- 不附带目标产品的任何二进制、反编译产物或大段反汇编。

---

## 7. 使用边界

允许：

- 在**自己的设备**上，用于在课堂上保留对自己电脑的基本操作权（比如广播时把窗口缩小继续记笔记）；
- 在**获得授权**的教学/实验室环境中做兼容性测试。

不允许：

- 规避考试监控、代替他人上课、干扰正常教学管理；
- 在**非本人管理**的机器上部署；
- 任何商业用途或再分发为收费产品。

如果你不确定自己是否有权这么做，那就不要用。
