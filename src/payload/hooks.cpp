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
typedef LONG(NTAPI* FnNtTerminateProcess)(HANDLE, LONG);
typedef HANDLE(WINAPI* FnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* FnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* FnCreateFile2)(LPCWSTR, DWORD, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI* FnDeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef LONG(NTAPI* FnNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

enum {
    IDX_CPW = 0,
    IDX_CPA,
    IDX_WINEXEC,
    IDX_SEEW,
    IDX_SEEA,
    IDX_TERM,
    IDX_POST,
    IDX_SEND,
    IDX_NTTERM,
    IDX_CFW,
    IDX_CFA,
    IDX_CF2,
    IDX_DIOC,
    IDX_COUNT
};

static const char* kTargetNames[IDX_COUNT] = {
    "CreateProcessW", "CreateProcessA", "WinExec", "ShellExecuteExW",
    "ShellExecuteExA", "TerminateProcess", "PostMessageW", "SendMessageW",
    "NtTerminateProcess", "CreateFileW", "CreateFileA", "CreateFile2", "DeviceIoControl",
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

// 明确“不许启动”的厂商程序（网络限制执行器）
static bool IsDeniedExe(const wchar_t* base) {
    if (!base || !*base) return false;
    for (int i = 0; ct::target::kVendorDenyExe[i]; ++i) {
        if (_wcsicmp(base, ct::target::kVendorDenyExe[i]) == 0) return true;
    }
    return false;
}

// 主程序通过共享内存告诉我们的安装目录。目录下的一切都属于广播流水线，
// 一律放行 —— 名单会过期，目录不会。
static bool UnderVendorDir(const wchar_t* path) {
    if (!g_shm || !path || !*path) return false;
    const wchar_t* dir = g_shm->req.vendorDir;
    if (!dir[0]) return false;
    size_t n = wcslen(dir);
    while (n && (dir[n - 1] == L'\\' || dir[n - 1] == L'/')) --n;
    if (n < 3) return false;
    if (_wcsnicmp(path, dir, n) != 0) return false;
    return path[n] == 0 || path[n] == L'\\' || path[n] == L'/';
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

    const wchar_t* slash = wcsrchr(probe, L'\\');
    if (!slash) slash = wcsrchr(probe, L'/');
    const wchar_t* base = slash ? slash + 1 : probe;

    // ① 明确禁止：网络限制执行器。直接拒绝，不给它等 20 秒弹窗的机会。
    //    （超时默认是拒绝，但一次广播里可能被拉起好几次，每次都卡 20 秒，
    //      表现就是“广播半天不出来”。）
    if (IsDeniedExe(base)) {
        if (g_shm) {
            InterlockedIncrement(&g_shm->rep.gatedCmd);
            InterlockedIncrement(&g_shm->rep.deniedLaunch);
        }
        return 0;
    }

    // ② 厂商安装目录下的一切 —— 广播流水线（渲染器/调度器/传输）全在这里。
    //    名单会随版本变，目录不会。这一条是“主动放行广播”的兜底。
    if (UnderVendorDir(probe) || (app && UnderVendorDir(app))) return 1;

    // ③ 已知厂商程序 / 宿主目录 / 会话白名单
    if (IsVendorExeName(probe)) return 1;
    if (IsInHostDir(probe)) return 1;
    if (app && IsInHostDir(app)) return 1;
    if (IsAllowedAlways(base)) return 1;

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

// 记录"最近一次被拦下的目标进程名"，主程序会把它写进日志
static void RecordBlocked(DWORD pid) {
    if (!g_shm || !pid) return;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    wchar_t path[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, path, &sz)) {
        const wchar_t* base = wcsrchr(path, L'\\');
        base = base ? base + 1 : path;
        wcsncpy(g_shm->rep.lastTermName, base, 63);
        g_shm->rep.lastTermName[63] = 0;
    }
    CloseHandle(h);
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
        if (!pid) {
            // 调用方只申请了 PROCESS_TERMINATE 时拿不到 pid，这是 G5 的盲区，单独计数
            if (g_shm) InterlockedIncrement(&g_shm->rep.unknownKills);
        } else if (ShouldProtectPid(pid)) {
            InterlockedIncrement(&g_shm->rep.blockedTerminate);
            RecordBlocked(pid);
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    auto fn = reinterpret_cast<FnTerminateProcess>(g_orig[IDX_TERM]);
    if (!fn) return FALSE;
    return fn(proc, code);
}

// 有些实现绕过 kernel32!TerminateProcess 直接调 ntdll。
// 注意返回值语义相反：NTSTATUS 0 才是成功，所以拦截时要返回 STATUS_ACCESS_DENIED。
static LONG NTAPI DetNtTerminateProcess(HANDLE proc, LONG status) {
    if (g_shm && g_shm->req.wantTerminateGuard && proc && proc != GetCurrentProcess()) {
        DWORD pid = GetProcessId(proc);
        if (!pid) {
            if (g_shm) InterlockedIncrement(&g_shm->rep.unknownKills);
        } else if (ShouldProtectPid(pid)) {
            InterlockedIncrement(&g_shm->rep.blockedTerminate);
            RecordBlocked(pid);
            return static_cast<LONG>(0xC0000022L);   // STATUS_ACCESS_DENIED
        }
    }
    auto fn = reinterpret_cast<FnNtTerminateProcess>(g_orig[IDX_NTTERM]);
    if (!fn) return static_cast<LONG>(0xC0000002L);  // STATUS_NOT_IMPLEMENTED
    return fn(proc, status);
}

// 挡住厂商对 \\.\Inspect 的打开 —— 那是「网络使用限制」的下发通道。
//
// 同一个设备有四五种写法，只比 "\\.\Inspect" 会被 \\?\GLOBALROOT\Device\Inspect
// 之类绕过去。统一归一化后再比。
static bool IsInspectName(const wchar_t* raw) {
    if (!raw || !*raw) return false;
    const wchar_t* p = raw;
    if (_wcsnicmp(p, L"\\\\?\\GLOBALROOT", 14) == 0) p += 14;
    else if (_wcsnicmp(p, L"\\\\?\\", 4) == 0)       p += 4;
    else if (_wcsnicmp(p, L"\\??\\", 4) == 0)        p += 4;
    else if (_wcsnicmp(p, L"\\\\.\\", 4) == 0)       p += 4;

    if (_wcsnicmp(p, L"\\Device\\", 8) == 0) return _wcsicmp(p, L"\\Device\\Inspect") == 0;
    return _wcsicmp(p, L"Inspect") == 0;
}

static bool IsInspectDeviceW(const wchar_t* name) { return IsInspectName(name); }

static bool IsInspectDeviceA(const char* name) {
    if (!name) return false;
    wchar_t w[512]{};
    MultiByteToWideChar(CP_ACP, 0, name, -1, w, 511);
    return IsInspectDeviceW(w);
}

// 一个已经打开的句柄是不是那个设备？
//
// 厂商可能在**我们注入之前**就把设备打开并一直持有，之后只靠 DeviceIoControl
// 下发过滤器。只拦 CreateFile 的话，这种“老句柄”完全拦不到 —— 这正是
// “网络限制时灵时不灵”的主因之一。
static bool HandleIsInspectDevice(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    // 只查字符设备。NtQueryObject 在管道/同步文件句柄上可能死等，
    // 而我们这个 detour 会经过进程里每一次 DeviceIoControl，绝不能卡住。
    if (GetFileType(h) != FILE_TYPE_CHAR) return false;
    static FnNtQueryObject q = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) q = reinterpret_cast<FnNtQueryObject>(GetProcAddress(nt, "NtQueryObject"));
    }
    if (!q) return false;

    struct UniStr { USHORT Length; USHORT MaxLen; PWSTR Buffer; };
    struct ObjName { UniStr Name; };
    ObjName info{};
    ULONG ret = 0;
    if (q(h, 1 /*ObjectNameInformation*/, &info, sizeof(info), &ret) < 0) return false;
    if (!info.Name.Buffer || info.Name.Length == 0) return false;

    wchar_t name[256]{};
    int n = info.Name.Length / (int)sizeof(wchar_t);
    if (n > 255) n = 255;
    memcpy(name, info.Name.Buffer, (size_t)n * sizeof(wchar_t));
    return IsInspectName(name);
}

static HANDLE WINAPI DetCreateFileW(LPCWSTR name, DWORD access, DWORD share,
                                    LPSECURITY_ATTRIBUTES sa, DWORD create, DWORD flags,
                                    HANDLE tmpl) {
    if (g_shm && g_shm->req.wantNetGuard && IsInspectDeviceW(name)) {
        InterlockedIncrement(&g_shm->rep.devBlocked);
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    auto fn = reinterpret_cast<FnCreateFileW>(g_orig[IDX_CFW]);
    if (!fn) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return INVALID_HANDLE_VALUE; }
    return fn(name, access, share, sa, create, flags, tmpl);
}

static HANDLE WINAPI DetCreateFileA(LPCSTR name, DWORD access, DWORD share,
                                    LPSECURITY_ATTRIBUTES sa, DWORD create, DWORD flags,
                                    HANDLE tmpl) {
    if (g_shm && g_shm->req.wantNetGuard && IsInspectDeviceA(name)) {
        InterlockedIncrement(&g_shm->rep.devBlocked);
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    auto fn = reinterpret_cast<FnCreateFileA>(g_orig[IDX_CFA]);
    if (!fn) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return INVALID_HANDLE_VALUE; }
    return fn(name, access, share, sa, create, flags, tmpl);
}

static HANDLE WINAPI DetCreateFile2(LPCWSTR name, DWORD access, DWORD share,
                                    DWORD create, LPVOID params) {
    if (g_shm && g_shm->req.wantNetGuard && IsInspectName(name)) {
        InterlockedIncrement(&g_shm->rep.devBlocked);
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    auto fn = reinterpret_cast<FnCreateFile2>(g_orig[IDX_CF2]);
    if (!fn) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return INVALID_HANDLE_VALUE; }
    return fn(name, access, share, create, params);
}

// G6 的“加强版”：即使 CreateFile 没拦住（老句柄 / 动态解析绕开 IAT），
// 只要最终是往这个设备发 IOCTL，就在这里拒绝。
static BOOL WINAPI DetDeviceIoControl(HANDLE dev, DWORD code, LPVOID in, DWORD inSz,
                                      LPVOID out, DWORD outSz, LPDWORD ret, LPOVERLAPPED ov) {
    if (g_shm && g_shm->req.wantNetGuard && HandleIsInspectDevice(dev)) {
        InterlockedIncrement(&g_shm->rep.ioctlBlocked);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    auto fn = reinterpret_cast<FnDeviceIoControl>(g_orig[IDX_DIOC]);
    if (!fn) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return fn(dev, code, in, inSz, out, outSz, ret, ov);
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
    g_detours[IDX_NTTERM] = reinterpret_cast<void*>(&DetNtTerminateProcess);
    g_detours[IDX_CFW] = reinterpret_cast<void*>(&DetCreateFileW);
    g_detours[IDX_CFA] = reinterpret_cast<void*>(&DetCreateFileA);
    g_detours[IDX_CF2] = reinterpret_cast<void*>(&DetCreateFile2);
    g_detours[IDX_DIOC] = reinterpret_cast<void*>(&DetDeviceIoControl);
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
