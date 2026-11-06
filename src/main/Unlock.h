// =============================================================================
//  CloudTrainer - Unlock.h
//  ---------------------------------------------------------------------------
//  解锁原语。刻意做成**自包含**（只依赖 Win32，不碰 App / Log / Settings），
//  这样 tests/test_unlock.exe 可以只链接这一个 .cpp 就验证真实行为。
//
//  G4 鼠标锁有两条独立通道：
//    外部：定位 HookLib 里那条锁线程 -> PostThreadMessage(WM_QUIT)
//          —— 依赖模块可枚举、线程起始地址可读、线程有消息队列，任一不满足就哑火；
//    进程内：注入后拿到 g_hHook -> UnhookWindowsHookEx
//          —— 不依赖上面三件事，是更可靠的一条。
//  这个文件只负责"外部"那条，进程内那条在 payload/payload.cpp。
// =============================================================================
#pragma once

#include <windows.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace ct {
namespace unlock {

// ── 模块范围（Toolhelp32，x86 目标进程） ────────────────────────────────────
bool ModuleRangeOf(DWORD pid, const wchar_t* dll, uint32_t* base, uint32_t* size);

// ── 退出"装着钩子的那条线程" ────────────────────────────────────────────────
struct QuitReport {
    bool     moduleFound = false;   // 目标进程里有没有这个模块
    uint32_t base = 0;
    uint32_t size = 0;
    int      threads = 0;           // 目标进程线程总数
    int      matched = 0;           // 起始地址落在模块内的线程数
    int      exact = 0;             // 命中已知 RVA 的线程数
    int      posted = 0;            // WM_QUIT 投递成功数
    int      survived = 0;          // 投递后仍然存活的线程数
    DWORD    lastErr = 0;           // 最后一次失败的错误码
    std::vector<DWORD> tids;

    bool Ok() const { return moduleFound && posted > 0 && survived == 0; }
};

// knownRva 为 0 时退化为"模块内任意线程"。waitMs 用于投递后确认线程真的退出。
QuitReport QuitThreads(DWORD pid, const wchar_t* dll, uint32_t knownRva, DWORD waitMs);

std::wstring Describe(const QuitReport& r);

// ── 按进程名结束（键盘锁 PDelKeyB.exe） ─────────────────────────────────────
struct KillReport {
    int   found = 0;
    int   killed = 0;
    DWORD lastErr = 0;
    std::vector<DWORD> pids;
};
KillReport KillByName(const wchar_t* exe, DWORD skipPid = 0);

// ── 光标 ────────────────────────────────────────────────────────────────────
// ClipCursor(NULL) 一定做；只有当光标被钳在屏幕边缘时才回中心，
// 免得每次解锁都把用户正在用的鼠标位置挪走。
void ReleaseCursor();

} // namespace unlock
} // namespace ct
