// =============================================================================
//  CloudTrainer - Unlock.cpp
// =============================================================================
#include "Unlock.h"

#include <tlhelp32.h>
#include <stdarg.h>
#include <stdio.h>

namespace ct {
namespace unlock {

namespace {

// 本文件不包含 Core.h（为了能被单测直接链接），所以自带一个格式化。
std::wstring Fmt(const wchar_t* fmt, ...) {
    wchar_t buf[512]{};
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 511, fmt, ap);
    buf[511] = 0;
    va_end(ap);
    return buf;
}

typedef LONG(NTAPI* PNtQit)(HANDLE, ULONG, PVOID, ULONG, PULONG);

PNtQit NtQit() {
    static PNtQit p = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE n = GetModuleHandleW(L"ntdll.dll");
        if (n) p = reinterpret_cast<PNtQit>(GetProcAddress(n, "NtQueryInformationThread"));
    }
    return p;
}

// ThreadQuerySetWin32StartAddress = 9
uint32_t StartAddressOf(DWORD tid) {
    HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!h) return 0;
    ULONG_PTR addr = 0;
    ULONG ret = 0;
    const LONG st = NtQit() ? NtQit()(h, 9, &addr, sizeof(addr), &ret) : -1;
    CloseHandle(h);
    return (st >= 0 && addr) ? static_cast<uint32_t>(addr) : 0;
}

struct ThreadHit {
    DWORD    tid = 0;
    uint32_t start = 0;
    bool     exact = false;
};

// 目标进程的线程快照。returns false = 快照失败。
bool SnapshotThreads(DWORD pid, std::vector<ThreadHit>* out) {
    out->clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            ThreadHit h;
            h.tid = te.th32ThreadID;
            h.start = StartAddressOf(te.th32ThreadID);
            out->push_back(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return true;
}

bool ThreadAlive(DWORD tid) {
    HANDLE h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!h) return false;
    DWORD code = 0;
    const bool alive = GetExitCodeThread(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

} // namespace

bool ModuleRangeOf(DWORD pid, const wchar_t* dll, uint32_t* base, uint32_t* size) {
    if (base) *base = 0;
    if (size) *size = 0;
    if (!pid || !dll || !*dll) return false;

    // 快照可能瞬时失败（ERROR_BAD_LENGTH），重试几次
    for (int attempt = 0; attempt < 3; ++attempt) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) {
            if (GetLastError() != ERROR_BAD_LENGTH) return false;
            Sleep(30);
            continue;
        }
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        bool found = false;
        if (Module32FirstW(snap, &me)) {
            do {
                if (_wcsicmp(me.szModule, dll) == 0) {
                    if (base) *base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(me.modBaseAddr));
                    if (size) *size = me.modBaseSize;
                    found = true;
                    break;
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return found;
    }
    return false;
}

QuitReport QuitThreads(DWORD pid, const wchar_t* dll, uint32_t knownRva, DWORD waitMs) {
    QuitReport r;
    if (!pid || !dll) return r;
    if (!ModuleRangeOf(pid, dll, &r.base, &r.size)) {
        r.lastErr = GetLastError();
        return r;
    }
    r.moduleFound = true;

    std::vector<ThreadHit> hits;
    if (!SnapshotThreads(pid, &hits)) {
        r.lastErr = GetLastError();
        return r;
    }
    r.threads = static_cast<int>(hits.size());

    const uint32_t exactAddr = knownRva ? (r.base + knownRva) : 0;
    std::vector<ThreadHit> matched;
    for (auto& h : hits) {
        if (h.start < r.base || h.start >= r.base + r.size) continue;
        // 线程入口可能被编译器拆出多个符号，给一个很小的容差
        h.exact = exactAddr && h.start >= exactAddr - 0x20 && h.start <= exactAddr + 0x200;
        matched.push_back(h);
    }
    if (matched.empty()) return r;      // 模块在，但没有线程起始地址落在里面

    // 已知 RVA 命中时只动它：别把模块里的普通工作线程一起打掉
    const bool useExact = (exactAddr != 0);
    bool anyExact = false;
    for (auto& h : matched) if (h.exact) { anyExact = true; break; }

    for (auto& h : matched) {
        if (useExact && anyExact && !h.exact) continue;
        ++r.matched;
        if (h.exact) ++r.exact;
        if (PostThreadMessageW(h.tid, WM_QUIT, 0, 0)) {
            ++r.posted;
            r.tids.push_back(h.tid);
        } else {
            r.lastErr = GetLastError();   // 常见 1444 = 该线程没有消息队列
        }
    }
    if (r.posted == 0) return r;

    // 投递成功不代表线程会退出：它可能卡在别的等待上。等一小会儿再数一遍。
    if (waitMs) {
        for (DWORD waited = 0; waited < waitMs; waited += 40) {
            Sleep(40);
            int alive = 0;
            for (DWORD tid : r.tids) if (ThreadAlive(tid)) ++alive;
            r.survived = alive;
            if (alive == 0) break;
        }
    }
    return r;
}

std::wstring Describe(const QuitReport& r) {
    if (!r.moduleFound) {
        return Fmt(L"进程内没有该模块（err=%lu）", r.lastErr);
    }
    if (r.matched == 0) {
        return Fmt(L"模块在（%u KB）但没有线程起始地址落在其中；线程共 %d 个",
                   r.size / 1024, r.threads);
    }
    std::wstring s = Fmt(L"匹配 %d 条线程（精确 %d），投递成功 %d", r.matched, r.exact, r.posted);
    if (r.survived > 0) {
        s += Fmt(L"，仍有 %d 条存活（它没在处理消息）", r.survived);
    } else if (r.posted > 0) {
        s += L"，已退出";
    }
    if (r.posted == 0 && r.lastErr) {
        s += Fmt(L"，投递失败 err=%lu（1444=该线程没有消息队列）", r.lastErr);
    }
    return s;
}

KillReport KillByName(const wchar_t* exe, DWORD skipPid) {
    KillReport r;
    if (!exe || !*exe) return r;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        r.lastErr = GetLastError();
        return r;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe) != 0) continue;
            if (skipPid && pe.th32ProcessID == skipPid) continue;
            ++r.found;
            HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, pe.th32ProcessID);
            if (!h) {
                r.lastErr = GetLastError();
                continue;
            }
            if (TerminateProcess(h, 1)) {
                ++r.killed;
                r.pids.push_back(pe.th32ProcessID);
            } else {
                r.lastErr = GetLastError();
            }
            CloseHandle(h);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return r;
}

void ReleaseCursor() {
    // 厂商常见的钳制方式就是 ClipCursor；这个可以跨进程解除。
    ClipCursor(nullptr);

    POINT p{};
    if (!GetCursorPos(&p)) return;
    RECT wa{};
    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0)) return;
    if (wa.right <= wa.left || wa.bottom <= wa.top) return;

    // 只在"明显被钉在边上"时才回中心，避免每次解锁都抢用户的鼠标
    const bool atEdge = p.x <= wa.left + 1 || p.x >= wa.right - 2 ||
                        p.y <= wa.top + 1 || p.y >= wa.bottom - 2;
    if (atEdge) {
        SetCursorPos((wa.left + wa.right) / 2, (wa.top + wa.bottom) / 2);
    }
}

} // namespace unlock
} // namespace ct
