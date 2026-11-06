# 测试

这些测试**不依赖电子教室**，只用自己的两个程序：

- `host.exe` —— 一个空转的控制台程序，充当"目标进程"；
  它每 400ms 调用两次 `CreateProcessW`（两个都不存在的路径，不会启动任何东西），
  并把返回值和 `GetLastError` 写到 `cp1.txt` / `cp2.txt`。
- `test_inject.exe` —— 复用 `src/main/Reflect.cpp` 的加载器，把
  `dist/CloudTrainerPayload.dll` 反射映射进 `host.exe`，然后：
  1. 等共享内存会话出现（证明载荷线程跑起来了）；
  2. 下发一次策略（证明 `req -> rep` 链路 + IAT 补丁）；
  3. 等宿主撞上命令闸门，写 `DENY`，检查宿主拿到的确实是 `ERROR_ACCESS_DENIED`；
  4. 检查厂商白名单被放行（`ERROR_FILE_NOT_FOUND`，不是 `ERROR_ACCESS_DENIED`）；
  5. 请求卸载，检查载荷退出且宿主存活。

## 外部解锁（`run_unlock_test.py`）

对应"后手启动无法解除控制"这条反馈。它编一个**同名的假 `HookLib.dll`**
（导出 `Lock`，起一条 `GetMessage` 循环线程）和 `lockhost.exe`，然后调用
`src/main/Unlock.cpp` 里产品真正在用的 `QuitThreads`：

| 场景 | 期望 |
|---|---|
| 锁线程有消息队列（真机常态） | 定位到 1 条线程、`WM_QUIT` 投递成功、线程真的退出、宿主存活 |
| 锁线程**没有**消息队列（反例） | 如实报告 `posted=0 / err=1444`，而不是静默当成功 |

顺序刻意做成"先有锁，再解锁"，也就是用户遇到的后手启动。

## 窗口守卫（`run_winguard_test.py`）

对应"拖动时被立即移回左上角"这条反馈。`winguardhost.exe` 注册一个同名类
`MultiRenderWindowClass` 的窗口，WndProc 仿照真品：`WM_NCCALCSIZE` 返回 0、
`WM_MOVING` / `WM_WINDOWPOSCHANGING` 把位置钉回 `(0,0)`。

测试先验证"注入前确实会被钉住"，再注入载荷让守卫子类化，然后从外部移两次：

| 阶段 | 请求位置 | 期望 |
|---|---|---|
| 注入前 | (320,240) | 实际 (0,0) —— 证明前提成立 |
| 注入后 | (300,200) | 实际 (300,200) |
| 注入后 | (520,360) | 实际 (520,360) |

## 跑法

```bash
python build.py                 # 先出 dist/CloudTrainerPayload.dll
python tests/run_inject_test.py
python tests/run_unlock_test.py
```

会跑两个场景：

- 首选基址空闲（载荷落在 `0x10000000`）；
- `host.exe --occupy` 先占住 `0x10000000`，强制注入走**重定位**路径
  —— 真实环境里这个地址被 `HookLib.dll` 占着，所以这条才是主路径。

预期输出以 `PASS` 结尾。
