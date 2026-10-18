// =============================================================================
//  CloudTrainer - Reflect.h
//  反射式加载器（跨进程）。独立成模块，便于单独测试。
// =============================================================================
#pragma once

#include <windows.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace ct {

// 把 x86 PE 映射进 hProc：
//   * 不落盘；
//   * 优先使用映像首选基址，占用则应用重定位；
//   * 导入表按“实际包含该地址的模块 + RVA”重建（处理转发导出）；
//   * 用 15 字节调用桩执行 entry(base)。
// 成功返回 true，outBase 为远端基址（调用方可据此在卸载时 VirtualFreeEx）。
bool ReflectInject(HANDLE hProc, const std::vector<uint8_t>& dll, uint32_t* outBase,
                   std::wstring* err);

// 目标进程里是否已经存在 CloudTrainer 的共享内存会话（用于判定注入是否生效）
bool PayloadSessionAlive(DWORD pid, uint32_t* outMagic);

} // namespace ct
