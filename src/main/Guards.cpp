// =============================================================================
//  CloudTrainer - Guards.cpp
//  ---------------------------------------------------------------------------
//  G1 广播窗口化   WindowFixer
//  G2 黑屏压制     BlackGuard
//  G3 键盘解锁     InputUnlocker（结束 PDelKeyB.exe）
//  G4 鼠标解锁     InputUnlocker（让 HookLib 的锁线程退出）
//
//  G3/G4 都不需要注入：厂商把两把锁都做成了“独立进程 / 独立线程”，
//  进程一退、线程一退，钩子随即销毁。这是本工具风险最低的一段。
// =============================================================================
#include "Core.h"

#include <algorithm>

namespace ct {

// ═════════════════════════════════════════════════════════════════════════════
//  WindowFixer
// ═════════════════════════════════════════════════════════════════════════════
bool WindowFixer::IsBroadcastWindow(HWND hwnd, RECT* monRect) {
    if (!IsWindow(hwnd) || !IsWindowVisible(hwnd)) return false;

    wchar_t cls[128]{};
    if (!GetClassNameW(hwnd, cls, 128)) return false;
    if (wcscmp(cls, target::kClsBroadcast) != 0) return false;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid) return false;

    // 双重校验：类名 + 进程名。类名是识别锚点，进程名防止误伤。
    std::wstring exe = ProcessBaseName(pid);
    if (!IEquals(exe, target::kProcMultiRender)) return false;

    // 用窗口所在显示器判定，不用 SM_CXSCREEN（多屏必错）
    HMONITOR mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(mon, &mi)) return false;

    RECT r{};
    if (!GetWindowRect(hwnd, &r)) return false;

    const RECT& m = mi.rcMonitor;
    const int tol = 2;
    bool covers = abs(r.left - m.left) <= tol && abs(r.top - m.top) <= tol &&
                  abs((r.right - r.left) - (m.right - m.left)) <= tol &&
                  abs((r.bottom - r.top) - (m.bottom - m.top)) <= tol;

    if (monRect) *monRect = covers ? m : r;
    return true;   // 只做“是不是广播窗”的判定；是否全屏由 ApplyFix 再判一次
}

WindowFixer::Track* WindowFixer::Find(HWND hwnd) {
    for (auto& t : tracks_) if (t.hwnd == hwnd) return &t;
    return nullptr;
}

bool WindowFixer::ApplyFix(HWND hwnd, const Settings& cfg) {
    HMONITOR mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(mon, &mi)) return false;

    // 已经是窗口态就不再动它（否则会和用户拖动打架）
    RECT r{};
    if (!GetWindowRect(hwnd, &r)) return false;
    {
        const RECT& m = mi.rcMonitor;
        const int tol = 2;
        bool covers = abs(r.left - m.left) <= tol && abs(r.top - m.top) <= tol &&
                      abs((r.right - r.left) - (m.right - m.left)) <= tol &&
                      abs((r.bottom - r.top) - (m.bottom - m.top)) <= tol;
        if (!covers) return false;
    }

    if (IsZoomed(hwnd)) ShowWindow(hwnd, SW_RESTORE);

    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);

    LONG newStyle = style;
    newStyle &= ~(WS_POPUP | WS_MAXIMIZE);
    newStyle |= WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX |
                WS_MAXIMIZEBOX | WS_CLIPCHILDREN;

    LONG newEx = ex & ~WS_EX_TOPMOST;
    if (cfg.allowTopmost) newEx |= WS_EX_TOPMOST;

    SetWindowLongW(hwnd, GWL_STYLE, newStyle);
    SetWindowLongW(hwnd, GWL_EXSTYLE, newEx);

    // 尺寸：默认 1280×720；keepAspect 时按显示器比例换算，避免画面被压扁
    int wantW = cfg.fixWidth;
    int wantH = cfg.fixHeight;
    const int monW = mi.rcMonitor.right - mi.rcMonitor.left;
    const int monH = mi.rcMonitor.bottom - mi.rcMonitor.top;
    if (cfg.keepAspect && monW > 0 && monH > 0) {
        wantH = wantW * monH / monW;
    }

    RECT cr{ 0, 0, wantW, wantH };
    AdjustWindowRectEx(&cr, newStyle, FALSE, newEx);
    int w = cr.right - cr.left;
    int h = cr.bottom - cr.top;

    RECT wa = mi.rcWork;
    const int maxW = static_cast<int>((wa.right - wa.left) * 0.92);
    const int maxH = static_cast<int>((wa.bottom - wa.top) * 0.92);
    if (w > maxW) { h = h * maxW / (w > 0 ? w : 1); w = maxW; }
    if (h > maxH) { w = w * maxH / (h > 0 ? h : 1); h = maxH; }

    int x = wa.left + ((wa.right - wa.left) - w) / 2;
    int y = wa.top + ((wa.bottom - wa.top) - h) / 2;

    // SWP_NOSENDCHANGING：不通知目标进程，避免它用 WM_WINDOWPOSCHANGING 把尺寸改回去
    SetWindowPos(hwnd, cfg.allowTopmost ? HWND_TOPMOST : HWND_NOTOPMOST, x, y, w, h,
                 SWP_FRAMECHANGED | SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_NOSENDCHANGING);
    return true;
}

BOOL CALLBACK WindowFixer::EnumProc(HWND h, LPARAM lp) {
    auto* c = reinterpret_cast<TickCtx*>(lp);
    if (!c || !c->self || !c->cfg) return TRUE;

    RECT mon{};
    if (!WindowFixer::IsBroadcastWindow(h, &mon)) return TRUE;

    const uint64_t now = NowMs();
    WindowFixer::Track* t = c->self->Find(h);
    if (!t) {
        WindowFixer::Track nt;
        nt.hwnd = h;
        nt.firstMs = now;
        c->self->tracks_.push_back(nt);
        t = &c->self->tracks_.back();
    }

    // ApplyFix 内部会判断“现在是不是仍然全屏”，窗口态时直接返回 false，
    // 所以这里可以每 800ms 无脑调用，不会和用户拖动打架。
    if (c->self->ApplyFix(h, *c->cfg)) {
        ++t->fixes;
        t->lastMs = now;
        ++c->self->fixedCount_;
        c->self->lastHwnd_ = h;
    }
    return TRUE;
}

void WindowFixer::Tick(const Settings& cfg, bool enabled) {
    // 清理已经销毁的窗口
    for (auto it = tracks_.begin(); it != tracks_.end();) {
        if (!IsWindow(it->hwnd)) it = tracks_.erase(it);
        else ++it;
    }
    if (!enabled) return;

    TickCtx ctx{ this, &cfg };
    EnumWindows(&WindowFixer::EnumProc, reinterpret_cast<LPARAM>(&ctx));
}

void WindowFixer::RestoreAll() {
    for (auto& t : tracks_) {
        if (!IsWindow(t.hwnd)) continue;
        HMONITOR mon = MonitorFromWindow(t.hwnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{};
        mi.cbSize = sizeof(mi);
        if (!GetMonitorInfoW(mon, &mi)) continue;

        LONG style = GetWindowLongW(t.hwnd, GWL_STYLE);
        style &= ~(WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
        style |= WS_POPUP | WS_VISIBLE;
        SetWindowLongW(t.hwnd, GWL_STYLE, style);

        const RECT& m = mi.rcMonitor;
        SetWindowPos(t.hwnd, HWND_TOPMOST, m.left, m.top,
                     m.right - m.left, m.bottom - m.top,
                     SWP_FRAMECHANGED | SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_NOSENDCHANGING);
    }
    tracks_.clear();
}

std::wstring WindowFixer::StatusText() const {
    if (tracks_.empty()) return L"未发现广播窗口";
    int total = 0;
    for (const auto& t : tracks_) total += t.fixes;
    return Fmt(L"追踪 %d 个窗口 / 修正 %d 次", (int)tracks_.size(), total);
}

// ═════════════════════════════════════════════════════════════════════════════
//  BlackGuard
// ═════════════════════════════════════════════════════════════════════════════
void BlackGuard::Tick(bool enabled) {
    if (!enabled) return;
    uint64_t now = NowMs();
    if (now < backoffUntil_) return;

    std::vector<DWORD> pids = EnumPidsByName(target::kProcBlackSilent);
    for (DWORD pid : pids) {
        if (pid == GetCurrentProcessId()) continue;
        DWORD err = 0;
        if (TerminatePid(pid, &err)) {
            ++kills_;
            ++rateCount_;
            A().log.Info(L"已压制黑屏 pid=%lu 累计=%d", pid, (int)kills_);
        } else {
            A().log.Warn(L"压制黑屏失败 pid=%lu err=%lu", pid, err);
        }
    }

    // 速率限制：一分钟内杀超过 20 次就退避到 1s，避免与教师端反复拉锯把 CPU 拉满
    if (rateWindow_ == 0) rateWindow_ = now;
    if (now - rateWindow_ > 60000) {
        rateWindow_ = now;
        rateCount_ = 0;
    }
    if (rateCount_ > 20) backoffUntil_ = now + 1000;
}

std::wstring BlackGuard::StatusText() const {
    return Fmt(L"已压制 %d 次", (int)kills_);
}

// ═════════════════════════════════════════════════════════════════════════════
//  InputUnlocker
// ═════════════════════════════════════════════════════════════════════════════
namespace {

typedef LONG(NTAPI* PNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

PNtQueryInformationThread NtQit() {
    static PNtQueryInformationThread p = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) p = reinterpret_cast<PNtQueryInformationThread>(
            GetProcAddress(ntdll, "NtQueryInformationThread"));
    }
    return p;
}

// ThreadQuerySetWin32StartAddress = 9
DWORD ThreadStartAddress(DWORD tid) {
    HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!h) return 0;
    ULONG_PTR addr = 0;
    ULONG retLen = 0;
    LONG st = -1;
    if (NtQit()) st = NtQit()(h, 9, &addr, sizeof(addr), &retLen);
    CloseHandle(h);
    if (st < 0 || addr == 0) return 0;
    return static_cast<DWORD>(addr);
}

} // namespace

int InputUnlocker::QuitHookThreads(const Locator& loc, DWORD pid) {
    uint32_t base = 0, size = 0;
    if (!const_cast<Locator&>(loc).ModuleRange(pid, target::kModHookLib, &base, &size)) return 0;
    if (!base || !size) return 0;

    int n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            DWORD start = ThreadStartAddress(te.th32ThreadID);
            if (start >= base && start < base + size) {
                // 这是 HookLib 自己起的锁线程：给它投 WM_QUIT，
                // 它会走自己的收尾路径（UnhookWindowsHookEx + 置空 g_hHook）。
                if (PostThreadMessageW(te.th32ThreadID, WM_QUIT, 0, 0)) ++n;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

void InputUnlocker::RestoreCursor() {
    // 厂商把光标钉到 (-10,-10) 并 ShowCursor(0)，这里把它拉回来
    for (int i = 0; i < 32; ++i) {
        int c = ShowCursor(TRUE);
        if (c >= 0) break;
    }
    RECT wa{};
    if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0)) {
        SetCursorPos((wa.left + wa.right) / 2, (wa.top + wa.bottom) / 2);
    }
}

void InputUnlocker::UnlockMouseNow(const Locator& loc) {
    std::vector<DWORD> hosts = const_cast<Locator&>(loc).PidsWithModule(target::kModHookLib, true);
    int n = 0;
    for (DWORD pid : hosts) n += QuitHookThreads(loc, pid);
    if (n > 0) {
        ++mouseUnlocks_;
        RestoreCursor();
        A().log.Info(L"鼠标锁已解除（退出锁线程 %d 个）", n);
    }
}

void InputUnlocker::Tick(const Settings& cfg, const Locator& loc, bool kbEnabled, bool mouseEnabled) {
    // ── 键盘：PDelKeyB.exe 是 PyInstaller 打包的 5 行 Python，无看护、无 IPC ──
    std::vector<DWORD> kbPids = EnumPidsByName(target::kProcPDelKeyB);
    kbPresent_ = !kbPids.empty();
    if (kbEnabled) {
        for (DWORD pid : kbPids) {
            DWORD err = 0;
            if (TerminatePid(pid, &err)) {
                ++keyKills_;
                A().log.Info(L"键盘锁已解除 pid=%lu", pid);
            } else if (err != ERROR_ACCESS_DENIED && err != ERROR_INVALID_PARAMETER) {
                A().log.Warn(L"结束键盘锁失败 pid=%lu err=%lu", pid, err);
            }
        }
    }

    // ── 鼠标：HookLib 的锁线程存在 = 当前被锁 ──
    if (mouseEnabled) {
        uint64_t now = NowMs();
        if (now - lastMouseTry_ >= 600) {
            lastMouseTry_ = now;
            std::vector<DWORD> hosts = const_cast<Locator&>(loc).PidsWithModule(target::kModHookLib);
            int n = 0;
            for (DWORD pid : hosts) {
                n += QuitHookThreads(loc, pid);
            }
            if (n > 0) {
                ++mouseUnlocks_;
                RestoreCursor();
                A().log.Info(L"鼠标锁已解除（锁线程 %d 个）", n);
                mousePresent_ = true;
            } else {
                mousePresent_ = false;
            }
        }
    } else {
        mousePresent_ = false;
    }
}

std::wstring InputUnlocker::StatusText() const {
    std::wstring s;
    s += kbPresent_ ? L"键盘：锁定中｜" : L"键盘：正常｜";
    s += mousePresent_ ? L"鼠标：锁定中" : L"鼠标：正常";
    if (keyKills_ || mouseUnlocks_) {
        s += Fmt(L"（已解 %d/%d 次）", (int)keyKills_, (int)mouseUnlocks_);
    }
    return s;
}

} // namespace ct
