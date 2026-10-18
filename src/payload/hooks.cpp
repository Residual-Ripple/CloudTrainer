// =============================================================================
//  CloudTrainerPayload - hooks.cpp
//  ---------------------------------------------------------------------------
//  G5 拦截结束请求 / G6 远程命令闸门，用 IAT hook 实现。
//
//  为什么不用 JiYuTrainer 那种 inline hook：
//    * inline hook 需要长度反汇编器改写函数序言，出错就是目标进程崩溃；
//    * IAT hook 只改导入表里的一个指针，恢复时写回原值即可，风险低一个数量级；
//    * 厂商是常规 C++ 静态导入（不是 GetProcAddress 动态解析），IAT 覆盖得到。
//  代价：如果厂商改成动态解析 API，这一层会失效 —— 写进 README 的已知限制。
// =============================================================================
#include "payload.h"

#include <psapi.h>
#include <wchar.h>

namespace ctpayload {

// ── 原始函数指针 ────────────────────────────────────────────────────────────
typedef BOOL(WINAPI* FnCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                       LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                       LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* FnCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                       LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                       LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef UINT(WINAPI* FnWinExec)(LPCSTR, UINT);
typedef BOOL(WINAPI* FnShellExecuteExW)(SHELLEXECUTEINFOW*);
typedef BOOL(WINAPI* FnShellExecuteExA)(SHELLEXECUTEINFOA*);
typedef BOOL(WINAPI* FnTerminateProcess)(HANDLE, UINT);
typedef BOOL(WINAPI* FnPostMessageW)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT(WINAPI* FnSendMessageW)(HWND, UINT, WPARAM, LPARAM);

enum {
    IDX_CPW = 0,
    IDX_CPA,
    IDX_WINEXEC,
    IDX_SEEW,
    IDX_SEEA,
    IDX_TERM,
    IDX_POST,
    IDX_SEND,
    IDX_COUNT
};

static const char* kTargetNames[IDX_COUNT] = {
    "CreateProcessW", "CreateProcessA", "WinExec", "ShellExecuteExW",
    "ShellExecuteExA", "TerminateProcess", "PostMessageW", "SendMessageW",
};

static void* g_detours[IDX_COUNT] = {};
static void* g_orig[IDX_COUNT] = {};

struct Patch {
    void** slot;
    void*  orig;
};
static Patch     g_patches[768];
static int       g_patchCount = 0;
static HMODULE   g_patched[96];
static int       g_patchedCount = 0;
static bool      g_installed = false;

// ── 工具 ────────────────────────────────────────────────────────────────────
static bool IsVendorExeName(const wchar_t* name) {
    if (!name || !*name) return false;
    const wchar_t* base = wcsrchr(name, L'\\');
    if (!base) base = wcsrchr(name, L'/');
    base = base ? base + 1 : name;
    for (int i = 0; ct::target::kVendorExeWhitelist[i]; ++i) {
        if (_wcsicmp(base, ct::target::kVendorExeWhitelist[i]) == 0) return true;
    }
    return false;
}

static const wchar_t* HostDir() {
    static wchar_t dir[MAX_PATH * 2]{};
    if (!dir[0]) {
        GetModuleFileNameW(nullptr, dir, MAX_PATH * 2);
        wchar_t* s = wcsrchr(dir, L'\\');
        if (s) *s = 0;
    }
    return dir;
}

static bool IsInHostDir(const wchar_t* path) {
    if (!path || !*path) return false;
    const wchar_t* d = HostDir();
    size_t n = wcslen(d);
    if (n == 0) return false;
    return _wcsnicmp(path, d, n) == 0;
}

static void FirstToken(const wchar_t* cmd, wchar_t* out, size_t cap) {
    out[0] = 0;
    if (!cmd || !cap) return;
    const wchar_t* p = cmd;
    while (*p == L' ' || *p == L'\t') ++p;
    if (*p == L'"') {
        ++p;
        const wchar_t* e = wcschr(p, L'"');
        size_t len = e ? (size_t)(e - p) : wcslen(p);
        if (len >= cap) len = cap - 1;
        wcsncpy(out, p, len);
        out[len] = 0;
    } else {
        const wchar_t* e = p;
        while (*e && *e != L' ' && *e != L'\t') ++e;
        size_t len = (size_t)(e - p);
        if (len >= cap) len = cap - 1;
        wcsncpy(out, p, len);
        out[len] = 0;
    }
}

static bool MainAlive() {
    if (!g_shm) return false;
    ULONGLONG hb = (static_cast<ULONGLONG>(static_cast<uint32_t>(g_shm->req.mainAliveHi)) << 32) |
                   static_cast<uint32_t>(g_shm->req.mainAliveLo);
    if (hb == 0) return false;
    return (GetTickCount64() - hb) < 6000;
}

// 会话级的“一律允许”名单（不落盘，进程退出即失效）
static wchar_t g_allowAll[32][128];
static int     g_allowAllCount = 0;

static bool IsAllowedAlways(const wchar_t* name) {
    for (int i = 0; i < g_allowAllCount; ++i) {
        if (_wcsicmp(g_allowAll[i], name) == 0) return true;
    }
    return false;
}

static void AddAllowAlways(const wchar_t* name) {
    if (!name || !*name || g_allowAllCount >= 32) return;
    if (IsAllowedAlways(name)) return;
    wcsncpy(g_allowAll[g_allowAllCount], name, 127);
    g_allowAll[g_allowAllCount][127] = 0;
    ++g_allowAllCount;
}

// ── 裁决：问主程序 ──────────────────────────────────────────────────────────
static int AskGate(const wchar_t* app, const wchar_t* cmdline) {
    if (!g_shm) return 1;
    InterlockedIncrement(&g_shm->rep.gateCalls);
    if (!g_shm->req.wantCmdGate) return 1;
    if (!MainAlive()) return 1;                 // 主程序没在跑 -> 放行，不能把目标进程卡死

    wchar_t probe[260]{};
    if (app && *app) {
        wcsncpy(probe, app, 259);
    } else {
        FirstToken(cmdline, probe, 259);
    }
    if (!probe[0]) return 1;
    if (IsVendorExeName(probe)) return 1;
    if (IsInHostDir(probe)) return 1;
    if (app && IsInHostDir(app)) return 1;
    if (IsAllowedAlways(wcsrchr(probe, L'\\') ? wcsrchr(probe, L'\\') + 1 : probe)) return 1;

    int slot = -1;
    for (int i = 0; i < CT_MAX_PENDING; ++i) {
        if (g_shm->pending[i].state == CT_CMD_IDLE) { slot = i; break; }
    }
    if (slot < 0) return 1;                     // 队列满 -> 放行

    CtPendingCmd* p = &g_shm->pending[slot];
    if (app) { wcsncpy(p->app, app, 259); p->app[259] = 0; } else p->app[0] = 0;
    if (cmdline) { wcsncpy(p->cmd, cmdline, 511); p->cmd[511] = 0; } else p->cmd[0] = 0;
    p->hostPid = static_cast<LONG>(GetCurrentProcessId());
    p->decisionPid = 0;
    InterlockedIncrement(&p->seq);
    InterlockedExchange(&p->state, CT_CMD_PENDING);

    LONG timeout = g_shm->req.cmdGateTimeoutMs;
    if (timeout < 3000) timeout = 20000;

    int allow = 0;
    ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < static_cast<ULONGLONG>(timeout)) {
        LONG st = p->state;
        if (st == CT_CMD_ALLOW) { allow = 1; break; }
        if (st == CT_CMD_ALLOWALL) { allow = 1; AddAllowAlways(wcsrchr(probe, L'\\') ? wcsrchr(probe, L'\\') + 1 : probe); break; }
        if (st == CT_CMD_DENY) { allow = 0; break; }
        Sleep(20);
    }
    if (p->state == CT_CMD_PENDING) {
        // 超时：默认拒绝，并计数
        allow = 0;
    }
    InterlockedExchange(&p->state, CT_CMD_IDLE);
    if (!allow && g_shm) InterlockedIncrement(&g_shm->rep.gatedCmd);
    if (allow && g_shm) InterlockedIncrement(&g_shm->rep.gatedCmd);
    return allow;
}

// ── Detour ─────────────────────────────────────────────────────────────────
static BOOL WINAPI DetCreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                     LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
                                     LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si,
                                     LPPROCESS_INFORMATION pi) {
    if (g_shm && g_shm->req.wantCmdGate) {
        if (!AskGate(app, cmd)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    auto fn = reinterpret_cast<FnCreateProcessW>(g_orig[IDX_CPW]);
    if (!fn) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return fn(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}

static BOOL WINAPI DetCreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                     LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
                                     LPVOID env, LPCSTR dir, LPSTARTUPINFOA si,
                                     LPPROCESS_INFORMATION pi) {
    if (g_shm && g_shm->req.wantCmdGate) {
        wchar_t wapp[260]{}, wcmd[1024]{};
        if (app) MultiByteToWideChar(CP_ACP, 0, app, -1, wapp, 259);
        if (cmd) MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, 1023);
        if (!AskGate(app ? wapp : nullptr, cmd ? wcmd : nullptr)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    auto fn = reinterpret_cast<FnCreateProcessA>(g_orig[IDX_CPA]);
    if (!fn) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return fn(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}

static UINT WINAPI DetWinExec(LPCSTR cmd, UINT show) {
    if (g_shm && g_shm->req.wantCmdGate) {
        wchar_t w[1024]{};
        if (cmd) MultiByteToWideChar(CP_ACP, 0, cmd, -1, w, 1023);
        if (!AskGate(nullptr, w)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return 0;
        }
    }
    auto fn = reinterpret_cast<FnWinExec>(g_orig[IDX_WINEXEC]);
    if (!fn) return 0;
    return fn(cmd, show);
}

static BOOL WINAPI DetShellExecuteExW(SHELLEXECUTEINFOW* ei) {
    if (g_shm && g_shm->req.wantCmdGate && ei) {
        if (!AskGate(ei->lpFile, ei->lpParameters)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    auto fn = reinterpret_cast<FnShellExecuteExW>(g_orig[IDX_SEEW]);
    if (!fn) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return fn(ei);
}

static BOOL WINAPI DetShellExecuteExA(SHELLEXECUTEINFOA* ei) {
    if (g_shm && g_shm->req.wantCmdGate && ei) {
        wchar_t f[260]{}, p[1024]{};
        if (ei->lpFile) MultiByteToWideChar(CP_ACP, 0, ei->lpFile, -1, f, 259);
        if (ei->lpParameters) MultiByteToWideChar(CP_ACP, 0, ei->lpParameters, -1, p, 1023);
        if (!AskGate(ei->lpFile ? f : nullptr, ei->lpParameters ? p : nullptr)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    auto fn = reinterpret_cast<FnShellExecuteExA>(g_orig[IDX_SEEA]);
    if (!fn) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return fn(ei);
}

static bool IsSystemPath(const wchar_t* path) {
    if (!path || !*path) return false;
    wchar_t win[MAX_PATH]{};
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    return _wcsnicmp(path, win, wcslen(win)) == 0;
}

// 该不该挡住“结束这个进程”的请求？
//   1) 主程序点名的 pid（本工具自己 / Student.exe / MultiRender.exe / 前台程序）—— 一定挡；
//   2) 开关打开时，任意“非系统、非厂商”的用户程序 —— 也挡（这才是教师端
//      “远程关闭应用程序”真正会命中的目标）；
//   3) 拿不到信息就放行 —— 宁可漏挡，也不要把目标进程的正常清理流程搞坏。
static bool ShouldProtectPid(DWORD pid) {
    if (!pid || pid == GetCurrentProcessId()) return false;
    if (!g_shm) return false;

    LONG n = g_shm->req.protectPidCount;
    if (n > CT_MAX_PROTECT_PIDS) n = CT_MAX_PROTECT_PIDS;
    for (LONG i = 0; i < n; ++i) {
        if (static_cast<DWORD>(g_shm->req.protectPids[i]) == pid) return true;
    }
    if (!g_shm->req.protectAllUserApps) return false;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    wchar_t path[MAX_PATH * 2]{};
    DWORD sz = MAX_PATH * 2;
    BOOL ok = QueryFullProcessImageNameW(h, 0, path, &sz);
    CloseHandle(h);
    if (!ok) return false;
    if (IsSystemPath(path)) return false;
    if (IsVendorExeName(path)) return false;
    return true;
}

static BOOL WINAPI DetTerminateProcess(HANDLE proc, UINT code) {
    if (g_shm && g_shm->req.wantTerminateGuard && proc && proc != GetCurrentProcess()) {
        DWORD pid = GetProcessId(proc);
        if (pid && ShouldProtectPid(pid)) {
            InterlockedIncrement(&g_shm->rep.blockedTerminate);
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    auto fn = reinterpret_cast<FnTerminateProcess>(g_orig[IDX_TERM]);
    if (!fn) return FALSE;
    return fn(proc, code);
}

static BOOL WINAPI DetPostMessageW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (g_shm && g_shm->req.wantCloseGuard && msg == WM_CLOSE && hwnd && IsWindow(hwnd)) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid && pid != GetCurrentProcessId()) {
            InterlockedIncrement(&g_shm->rep.blockedClose);
            return TRUE;
        }
    }
    auto fn = reinterpret_cast<FnPostMessageW>(g_orig[IDX_POST]);
    if (!fn) return FALSE;
    return fn(hwnd, msg, wp, lp);
}

static LRESULT WINAPI DetSendMessageW(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (g_shm && g_shm->req.wantCloseGuard && msg == WM_CLOSE && hwnd && IsWindow(hwnd)) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid && pid != GetCurrentProcessId()) {
            InterlockedIncrement(&g_shm->rep.blockedClose);
            return TRUE;
        }
    }
    auto fn = reinterpret_cast<FnSendMessageW>(g_orig[IDX_SEND]);
    if (!fn) return 0;
    return fn(hwnd, msg, wp, lp);
}

static void InitDetours() {
    g_detours[IDX_CPW] = reinterpret_cast<void*>(&DetCreateProcessW);
    g_detours[IDX_CPA] = reinterpret_cast<void*>(&DetCreateProcessA);
    g_detours[IDX_WINEXEC] = reinterpret_cast<void*>(&DetWinExec);
    g_detours[IDX_SEEW] = reinterpret_cast<void*>(&DetShellExecuteExW);
    g_detours[IDX_SEEA] = reinterpret_cast<void*>(&DetShellExecuteExA);
    g_detours[IDX_TERM] = reinterpret_cast<void*>(&DetTerminateProcess);
    g_detours[IDX_POST] = reinterpret_cast<void*>(&DetPostMessageW);
    g_detours[IDX_SEND] = reinterpret_cast<void*>(&DetSendMessageW);
}

// ── IAT 扫描与改写 ──────────────────────────────────────────────────────────
static void PatchModule(HMODULE mod) {
    if (!mod) return;
    for (int i = 0; i < g_patchedCount; ++i) if (g_patched[i] == mod) return;

    auto* base = reinterpret_cast<BYTE*>(mod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return;

    auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dd.VirtualAddress) return;

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dd.VirtualAddress);
    for (; imp->Name; ++imp) {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA32*>(
            base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        auto* iat = reinterpret_cast<IMAGE_THUNK_DATA32*>(base + imp->FirstThunk);
        for (; thunk->u1.AddressOfData; ++thunk, ++iat) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) continue;
            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + thunk->u1.AddressOfData);
            const char* name = reinterpret_cast<const char*>(ibn->Name);
            for (int k = 0; k < IDX_COUNT; ++k) {
                if (strcmp(name, kTargetNames[k]) != 0) continue;
                if (g_patchCount >= 768) return;
                DWORD old = 0;
                void** slot = reinterpret_cast<void**>(&iat->u1.Function);
                if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) break;
                void* prev = *slot;
                if (prev == g_detours[k]) { VirtualProtect(slot, sizeof(void*), old, &old); break; }
                if (!g_orig[k]) g_orig[k] = prev;
                *slot = g_detours[k];
                VirtualProtect(slot, sizeof(void*), old, &old);
                g_patches[g_patchCount].slot = slot;
                g_patches[g_patchCount].orig = prev;
                ++g_patchCount;
                break;
            }
        }
    }
    if (g_patchedCount < 96) g_patched[g_patchedCount++] = mod;
}

static bool IsSystemModule(HMODULE mod) {
    wchar_t path[MAX_PATH * 2]{};
    if (!GetModuleFileNameW(mod, path, MAX_PATH * 2)) return true;   // 取不到路径 -> 跳过
    wchar_t win[MAX_PATH]{};
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    size_t len = wcslen(win);
    return _wcsnicmp(path, win, len) == 0;
}

static void ScanAllModules() {
    HMODULE mods[512];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return;
    int count = (int)(needed / sizeof(HMODULE));
    if (count > 512) count = 512;
    for (int i = 0; i < count; ++i) {
        if (IsSystemModule(mods[i])) continue;
        PatchModule(mods[i]);
    }
}

void Hooks_Install() {
    if (g_installed) return;
    InitDetours();
    g_installed = true;
    ScanAllModules();
    if (g_shm) g_shm->rep.flags |= CT_FLAG_TERMGUARD | CT_FLAG_CLOSEGUARD | CT_FLAG_CMDGATE;
}

void Hooks_Rescan() {
    if (!g_installed) return;
    ScanAllModules();
}

void Hooks_Remove() {
    if (!g_installed) return;
    for (int i = 0; i < g_patchCount; ++i) {
        DWORD old = 0;
        if (VirtualProtect(g_patches[i].slot, sizeof(void*), PAGE_READWRITE, &old)) {
            *g_patches[i].slot = g_patches[i].orig;
            VirtualProtect(g_patches[i].slot, sizeof(void*), old, &old);
        }
    }
    g_patchCount = 0;
    g_patchedCount = 0;
    for (int k = 0; k < IDX_COUNT; ++k) g_orig[k] = nullptr;
    g_installed = false;
    if (g_shm) g_shm->rep.flags &= ~(CT_FLAG_TERMGUARD | CT_FLAG_CLOSEGUARD | CT_FLAG_CMDGATE);
}

int Hooks_PatchCount() { return g_patchCount; }

void Hooks_HandlePending() {
    // 裁决在主循环之外由 detour 自己等待；这里不需要做事。
}

} // namespace ctpayload
