// =============================================================================
//  CloudTrainerPayload - payload.cpp
//  主循环：建共享内存、心跳、响应策略/解锁/卸载请求。
// =============================================================================
#include "payload.h"

#include <tlhelp32.h>

namespace ctpayload {

CtShared* g_shm = nullptr;
HANDLE    g_map = nullptr;

static volatile LONG g_stop = 0;
static HMODULE  g_hookLib = nullptr;
static HHOOK*   g_pHook = nullptr;
static LONG     g_lastUnlock = 0;
static LONG     g_lastPolicy = 0;
static LONG     g_lastShutdown = 0;
static ULONGLONG g_lastRescan = 0;
static ULONGLONG g_lastGuard = 0;

// ── HookLib 解析 ────────────────────────────────────────────────────────────
bool ResolveHookLib() {
    g_hookLib = GetModuleHandleW(ct::target::kModHookLib);
    if (!g_hookLib) {
        g_pHook = nullptr;
        if (g_shm) g_shm->rep.hookLibFound = 0;
        return false;
    }
    // g_hHook 的 RVA 来自静态分析；只在 Lock 导出缺失时作为兜底。
    g_pHook = reinterpret_cast<HHOOK*>(reinterpret_cast<BYTE*>(g_hookLib) +
                                       ct::target::kHookLibRvaGHook);
    if (g_shm) g_shm->rep.hookLibFound = 1;
    return true;
}

// ── 安全访问 HookLib 的全局 g_hHook ─────────────────────────────────────────
// 载荷运行在别人家里，任何一次野指针访问都会让目标进程直接消失。
// 所以每次读写前先用 VirtualQuery 确认页面已提交且可访问。
namespace {

bool SafeRead(const void* p, void* out, size_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!p || VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    memcpy(out, p, n);
    return true;
}

HHOOK ReadHookHandle() {
    if (!g_pHook) return nullptr;
    HHOOK h = nullptr;
    if (!SafeRead(g_pHook, &h, sizeof(h))) return nullptr;
    return h;
}

void ClearHookHandle() {
    if (!g_pHook) return;
    DWORD old = 0;
    if (VirtualProtect(g_pHook, sizeof(HHOOK), PAGE_READWRITE, &old)) {
        *g_pHook = nullptr;
        VirtualProtect(g_pHook, sizeof(HHOOK), old, &old);
    }
}

} // namespace

// ── 让本进程内的锁线程退出 ──────────────────────────────────────────────────
namespace {

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

DWORD StartAddressOf(DWORD tid) {
    HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!h) return 0;
    ULONG_PTR addr = 0;
    ULONG ret = 0;
    LONG st = -1;
    if (NtQit()) st = NtQit()(h, 9, &addr, sizeof(addr), &ret);
    CloseHandle(h);
    return (st >= 0 && addr) ? static_cast<DWORD>(addr) : 0;
}

} // namespace

int QuitOwnHookThreads() {
    if (!g_hookLib) return 0;
    const uint32_t base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(g_hookLib));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_hookLib);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
        reinterpret_cast<const BYTE*>(g_hookLib) + dos->e_lfanew);
    const uint32_t size = nt->OptionalHeader.SizeOfImage;

    int n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    const DWORD self = GetCurrentProcessId();
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != self) continue;
            DWORD start = StartAddressOf(te.th32ThreadID);
            if (start >= base && start < base + size) {
                if (PostThreadMessageW(te.th32ThreadID, WM_QUIT, 0, 0)) ++n;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

// ── 解锁鼠标 ────────────────────────────────────────────────────────────────
//  一条"解一次"的通道在两种情况下不够用：
//    * 锁线程被我们投 WM_QUIT 之后，Student.exe 收到教师端指令又会重新起一条；
//    * 目标进程在校验 g_hHook 之后又重新 SetWindowsHookEx。
//  所以请求解锁后给一个"保持窗口"，在这段时间里反复检查、反复摘。
static ULONGLONG g_holdUntil = 0;
static ULONGLONG g_lastHold = 0;

static int UnlockPass() {
    int n = 0;
    ResolveHookLib();

    // 1) 直接摘掉全局钩子 —— 我们在目标进程内，HHOOK 有效，不依赖线程配合
    HHOOK hk = ReadHookHandle();
    if (hk) {
        if (UnhookWindowsHookEx(hk)) ++n;
        // 不管 Unhook 成败都把全局变量清掉：否则 rep.mouseHook 永远是 1，
        // 主程序会误以为一直锁着（也让下面这轮的判断失真）
        ClearHookHandle();
    }
    // 2) 让锁线程退出 —— 它会走厂商自己的析构路径（Unhook + 置空 g_hHook）
    n += QuitOwnHookThreads();

    // 3) 光标钳制（ClipCursor 是跨进程有效的）
    ClipCursor(nullptr);

    if (n > 0 && g_shm) {
        ++g_shm->rep.inprocUnlocks;
        ++g_shm->rep.unlockCalls;
    }
    return n;
}

void DoUnlockMouse() {
    UnlockPass();
    if (!g_shm) return;
    LONG hold = g_shm->req.unlockHoldMs;
    if (hold <= 0) hold = 1000;
    if (hold > 10000) hold = 10000;
    g_holdUntil = GetTickCount64() + static_cast<ULONGLONG>(hold);
    g_lastHold = 0;
    g_shm->rep.mouseHook = ReadHookHandle() ? 1 : 0;
}

void ApplyPolicy() {
    if (!g_shm) return;
    // 以前漏了 wantNetGuard：只开网络守卫时一个 hook 都不装，等于没开。
    if (g_shm->req.wantTerminateGuard || g_shm->req.wantCloseGuard ||
        g_shm->req.wantCmdGate || g_shm->req.wantNetGuard) {
        Hooks_Install();
        Hooks_Rescan();
    }
}

void SetStop() { InterlockedExchange(&g_stop, 1); }

// ── 心跳 ────────────────────────────────────────────────────────────────────
static void Beat() {
    if (!g_shm) return;
    ULONGLONG v = GetTickCount64();
    g_shm->rep.heartbeatLo = static_cast<LONG>(static_cast<uint32_t>(v));
    g_shm->rep.heartbeatHi = static_cast<LONG>(static_cast<uint32_t>(v >> 32));
    g_shm->rep.alive = 1;
    g_shm->rep.hookLibFound = g_hookLib ? 1 : 0;
    g_shm->rep.mouseHook = ReadHookHandle() ? 1 : 0;
    g_shm->rep.patchCount = Hooks_PatchCount();
}

// ── 线程主体 ────────────────────────────────────────────────────────────────
DWORD WINAPI PayloadThread(LPVOID) {
    wchar_t name[128]{};
    _snwprintf(name, 127, CT_SHM_NAME_FMT, GetCurrentProcessId());
    name[127] = 0;

    g_map = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(CtShared), name);
    if (!g_map) return 1;
    // 重复注入时映射已经存在：此时不能清零，否则会把正在跑的那个会话打掉
    const bool fresh = (GetLastError() != ERROR_ALREADY_EXISTS);
    g_shm = reinterpret_cast<CtShared*>(MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(CtShared)));
    if (!g_shm) {
        CloseHandle(g_map);
        g_map = nullptr;
        return 1;
    }
    ApplyPolicy();   // 用默认策略先把 hook 装上（尤其是设备守卫），不等主程序第一次下发

    // 已经有一个"同版本"的载荷在跑：不要重置，否则会把它的计数和请求序号清掉
    if (!fresh && g_shm->magic == CT_IPC_MAGIC && g_shm->version == CT_IPC_VERSION) {
        g_shm->rep.alive = 1;
        Beat();
        return 0;
    }
    // 版本不同 = 上一次运行留下的旧载荷（CloudTrainer 被强杀过就会这样）。
    // 直接接管这块映射：不清掉的话主程序永远读不到新字段，解锁指令也就发不进来。

    memset(g_shm, 0, sizeof(*g_shm));
    // 新建映射时先默认“挡设备”：主程序的第一次策略下发会覆盖它。
    // 反过来（默认 0 等主程序写）会留一个窗口期，网络限制刚好落进去。
    g_shm->req.wantNetGuard = 1;
    g_shm->magic = CT_IPC_MAGIC;
    g_shm->version = CT_IPC_VERSION;
    g_shm->ownerPid = GetCurrentProcessId();
    g_shm->rep.flags = CT_FLAG_INJECTED;
    for (int i = 0; i < CT_MAX_PENDING; ++i) g_shm->pending[i].state = CT_CMD_IDLE;

    ResolveHookLib();
    WinGuard_Tick();
    Beat();

    for (;;) {
        if (InterlockedCompareExchange(&g_stop, 0, 0) != 0) break;
        if (g_shm->req.seqShutdown != g_lastShutdown) break;

        Beat();

        if (g_shm->req.seqPolicy != g_lastPolicy) {
            g_lastPolicy = g_shm->req.seqPolicy;
            ApplyPolicy();
        }
        if (g_shm->req.seqUnlock != g_lastUnlock) {
            g_lastUnlock = g_shm->req.seqUnlock;
            DoUnlockMouse();
        }

        ULONGLONG now = GetTickCount64();

        // 保持窗口内持续纠正：厂商会把钩子重新装上，这里每 150ms 复查一次
        if (g_holdUntil) {
            if (now >= g_holdUntil) {
                g_holdUntil = 0;
            } else if (now - g_lastHold >= 150) {
                g_lastHold = now;
                // 只在"钩子又被装回来"时才做完整解锁。UnlockPass 要枚举本进程所有
                // 线程（Toolhelp 快照），每 150ms 无条件跑一遍是浪费。
                if (ReadHookHandle()) UnlockPass();
            }
        }

        if (now - g_lastRescan > 2500) {
            g_lastRescan = now;
            ResolveHookLib();
            Hooks_Rescan();
        }
        if (now - g_lastGuard > 400) {
            g_lastGuard = now;
            WinGuard_Tick();      // 广播窗口可能在任意时刻被重建，持续扫
        }

        Sleep(40);
    }

    WinGuard_Remove();
    Hooks_Remove();
    if (g_shm) {
        g_shm->rep.alive = 0;
        g_shm->rep.flags = 0;
        g_shm->rep.patchCount = 0;
    }
    return 0;
}

} // namespace ctpayload
