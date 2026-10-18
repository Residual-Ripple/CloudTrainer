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

跑法：

```bash
python build.py                 # 先出 dist/CloudTrainerPayload.dll
python tests/run_inject_test.py
```

会跑两个场景：

- 首选基址空闲（载荷落在 `0x10000000`）；
- `host.exe --occupy` 先占住 `0x10000000`，强制注入走**重定位**路径
  —— 真实环境里这个地址被 `HookLib.dll` 占着，所以这条才是主路径。

预期输出以 `PASS` 结尾。
