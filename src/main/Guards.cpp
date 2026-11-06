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
#include "Unlock.h"

#include <algorithm>

namespace ct {

// ═════════════════════════════════════════════════════════════════════════════
//  WindowFixer
// ═════════════════════════════════════════════════════════════════════════════
WindowFixer::Track* WindowFixer::Find(HWND hwnd) {
    for (auto& t : tracks_) {
        if (t.hwnd == hwnd) return &t;
    }
    return nullptr;
}

namespace {

bool ClassIsBroadcast(const wchar_t* cls) {
    for (int i = 0; target::kClsBroadcastAliases[i]; ++i) {
        if (_wcsicmp(cls, target::kClsBroadcastAliases[i]) == 0) return true;
    }
    return false;
}

bool NameInList(const std::wstring& exe, const wchar_t* const* list) {
    if (exe.empty() || !list) return false;
    for (int i = 0; list[i]; ++i) {
        if (_wcsicmp(exe.c_str(), list[i]) == 0) return true;
    }
    return false;
}

bool NameInVendorList(const std::wstring& exe) {
    return NameInList(exe, target::kVendorExeWhitelist) || NameInList(exe, target::kVendorGuardExe);
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
//  广播窗口判定
//
//  2026-11-07 的实机窗口快照给出的关键事实：
//    * 窗口确实存在，类名 MultiRenderWindowClass，1920x1080 @ (0,0)，
//      style=0x94000000（运行时去掉了 CAPTION/THICKFRAME），ex=0x8（置顶）；
//    * 但**读不到进程名**（非管理员上下文里 OpenProcess 直接拒绝访问）。
//
//  旧实现要求“类名 + 进程名”同时成立，于是只要拿不到进程名，就永远认不出
//  广播窗 —— 表现正是“没有出现广播窗口”，而不是“认错了”。
//  现在类名是唯一硬锚点，进程名只用于日志与回退路径的防误伤。
// ─────────────────────────────────────────────────────────────────────────────
bool IsBroadcastWindowEx(HWND hwnd, RECT* monRect, std::wstring* why) {
    if (why) why->clear();
    if (!hwnd || !IsWindow(hwnd)) { if (why) *why = L"不是有效窗口"; return false; }
    if (!IsWindowVisible(hwnd))   { if (why) *why = L"不可见"; return false; }

    wchar_t cls[128]{};
    if (!GetClassNameW(hwnd, cls, 128)) { if (why) *why = L"取不到类名"; return false; }

    RECT r{};
    if (!GetWindowRect(hwnd, &r)) { if (why) *why = L"取不到矩形"; return false; }

    HMONITOR mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(mon, &mi)) { if (why) *why = L"取不到显示器"; return false; }

    const RECT& m = mi.rcMonitor;
    const int tol = 2;
    const bool covers = abs(r.left - m.left) <= tol && abs(r.top - m.top) <= tol &&
                        abs((r.right - r.left) - (m.right - m.left)) <= tol &&
                        abs((r.bottom - r.top) - (m.bottom - m.top)) <= tol;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    const std::wstring exe = pid ? ProcessBaseName(pid) : std::wstring();

    if (ClassIsBroadcast(cls)) {
        // 类名命中即可。进程名读不到（权限不足）也照认，只在读到了且不像
        // 厂商程序时提示一次，方便发现“类名被别的程序复用”这种极端情况。
        static bool warned = false;
        if (!warned && !exe.empty() && !NameInVendorList(exe)) {
            warned = true;
            A().log.Warn(L"广播窗口类名匹配，但进程名是 %s（继续按广播窗口处理）", exe.c_str());
        }
        if (monRect) *monRect = covers ? m : r;
        if (why) *why = L"类名匹配";
        return true;
    }

    // 回退：类名没命中（换版本改了类名），但形态 + 归属都对得上。
    // 三个条件同时成立才认：铺满整块屏 + 置顶 + 进程属于**广播流水线**。
    // 注意这里不能用“厂商进程”这么宽的条件 —— 黑屏窗口（BlackSlient.exe）
    // 也是全屏置顶的厂商窗口，会被误当成广播窗去加边框。
    const LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
    if (covers && (ex & WS_EX_TOPMOST) && NameInList(exe, target::kBroadcastPipeline)) {
        static bool warnedFallback = false;
        if (!warnedFallback) {
            warnedFallback = true;
            A().log.Warn(L"广播窗口类名未匹配（实际类名 %s，进程 %s），按全屏+置顶+厂商程序兜底识别",
                         cls, exe.c_str());
        }
        if (monRect) *monRect = m;
        if (why) *why = L"兜底：全屏+置顶+厂商程序";
        return true;
    }

    if (why) *why = L"类名与形态都不匹配";
    return false;
}

bool WindowFixer::IsBroadcastWindow(HWND hwnd, RECT* monRect) {
    return IsBroadcastWindowEx(hwnd, monRect, nullptr);
}

bool WindowFixer::ApplyFix(HWND hwnd, const Settings& cfg) {
    HMONITOR mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(mon, &mi)) return false;

    RECT wr{};
    if (!GetWindowRect(hwnd, &wr)) return false;

    const RECT& m = mi.rcMonitor;
    const int tol = 2;
    const bool fullscreen =
        abs(wr.left - m.left) <= tol && abs(wr.top - m.top) <= tol &&
        abs((wr.right - wr.left) - (m.right - m.left)) <= tol &&
        abs((wr.bottom - wr.top) - (m.bottom - m.top)) <= tol;

    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);

    // 目标进程会自己把 caption 去掉、把 topmost 加回来，
    // 所以不能"改一次就完事"——每次 tick 都要对照期望状态再纠正一遍。
    const bool styleBad = (style & WS_CAPTION) == 0 || (style & WS_THICKFRAME) == 0;
    const bool topmostBad = (ex & WS_EX_TOPMOST) && !cfg.allowTopmost;
    if (!styleBad && !topmostBad && !fullscreen) return false;

    LONG newStyle = style;
    newStyle &= ~(WS_POPUP | WS_MAXIMIZE);
    newStyle |= WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX |
                WS_MAXIMIZEBOX | WS_CLIPCHILDREN;

    LONG newEx = ex & ~WS_EX_TOPMOST;
    if (cfg.allowTopmost) newEx |= WS_EX_TOPMOST;

    if (style != newStyle) SetWindowLongW(hwnd, GWL_STYLE, newStyle);
    if (ex != newEx) SetWindowLongW(hwnd, GWL_EXSTYLE, newEx);

    if (!fullscreen) {
        // 已经是窗口尺寸：只纠正样式 / 层级，不碰位置，避免和用户拖动打架
        SetWindowPos(hwnd, cfg.allowTopmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                     SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE |
                         SWP_NOSENDCHANGING);
        return true;
    }

    if (IsZoomed(hwnd)) ShowWindow(hwnd, SW_RESTORE);

    // 尺寸：默认 1280×720；keepAspect 时按显示器比例换算，避免画面被压扁
    int wantW = cfg.fixWidth;
    int wantH = cfg.fixHeight;
    const int monW = m.right - m.left;
    const int monH = m.bottom - m.top;
    if (cfg.keepAspect && monW > 0 && monH > 0) wantH = wantW * monH / monW;

    RECT cr{ 0, 0, wantW, wantH };
    AdjustWindowRectEx(&cr, newStyle, FALSE, newEx);
    int w = cr.right - cr.left;
    int h = cr.bottom - cr.top;

    RECT wa = mi.rcWork;
    const int maxW = static_cast<int>((wa.right - wa.left) * 0.92);
    const int maxH = static_cast<int>((wa.bottom - wa.top) * 0.92);
    if (w > maxW) { h = h * maxW / (w > 0 ? w : 1); w = maxW; }
    if (h > maxH) { w = w * maxH / (h > 0 ? h : 1); h = maxH; }

    const int x = wa.left + ((wa.right - wa.left) - w) / 2;
    const int y = wa.top + ((wa.bottom - wa.top) - h) / 2;

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

    RECT wr{}, cr{};
    const bool gotRects = GetWindowRect(h, &wr) && GetClientRect(h, &cr);
    const bool ncStripped = gotRects &&
        (cr.right == wr.right - wr.left) && (cr.bottom == wr.bottom - wr.top);

    if (ncStripped && !t->ncWarned) {
        t->ncWarned = true;
        A().log.Warn(L"广播窗口没有非客户区（目标进程把 WM_NCCALCSIZE 算成 0）——"
                     L"外部加 WS_CAPTION 是看不见的，需要窗口守卫注入");
    }

    if (c->self->ApplyFix(h, *c->cfg)) {
        t->lastMs = now;
        ++c->self->fixedCount_;
        if (ncStripped) ++t->enforces; else ++t->fixes;
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
    int fixes = 0, enforces = 0, nc = 0;
    for (const auto& t : tracks_) {
        fixes += t.fixes;
        enforces += t.enforces;
        if (t.ncWarned) ++nc;
    }
    std::wstring s = Fmt(L"追踪 %d 个窗口 / 缩放 %d 次 / 纠正样式 %d 次",
                         (int)tracks_.size(), fixes, enforces);
    if (nc) s += L"（无边框，需窗口守卫）";
    return s;
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
//
//  G3 键盘：结束 PDelKeyB.exe（独立进程，没有看护，杀掉就没了）
//  G4 鼠标：两条通道
//      外部 —— 找到 HookLib 里那条锁线程，投 WM_QUIT，让它走自己的析构路径；
//      进程内 —— 注入后直接 UnhookWindowsHookEx(g_hHook)（见 payload.cpp），
//                由主程序周期性下发 seqUnlock 触发。
//
//  为什么必须两条：外部通道依赖"模块可枚举 + 线程起始地址可读 + 线程有消息队列"
//  三件事同时成立。后手启动（锁已经在生效）时只要缺一条就哑火，而且以前是**静默**的。
//  现在外部失败会被记下来，并让主程序改用进程内通道。
// ═════════════════════════════════════════════════════════════════════════════
void InputUnlocker::KillKeyboardLocks(bool enabled) {
    std::vector<DWORD> kbPids = EnumPidsByName(target::kProcPDelKeyB);
    kbPresent_ = !kbPids.empty();
    if (!enabled || kbPids.empty()) return;

    for (DWORD pid : kbPids) {
        DWORD err = 0;
        if (TerminatePid(pid, &err)) {
            ++keyKills_;
            A().log.Info(L"键盘锁已解除 pid=%lu（累计 %d 次）", pid, (int)keyKills_);
        } else if (err != ERROR_ACCESS_DENIED && err != ERROR_INVALID_PARAMETER) {
            A().log.Warn(L"结束键盘锁失败 pid=%lu err=%lu", pid, err);
        }
    }
}

void InputUnlocker::AttemptMouse(const Locator& loc, bool force, DWORD waitMs, bool verbose) {
    const bool wasPresent = mousePresent_;
    std::vector<DWORD> hosts = const_cast<Locator&>(loc).PidsWithModule(target::kModHookLib, force);
    lockHost_ = !hosts.empty();
    if (hosts.empty()) {
        mousePresent_ = false;
        needInProc_ = false;
        lastResult_.clear();
        return;
    }

    int matched = 0, posted = 0, survived = 0;
    std::wstring detail;
    for (DWORD pid : hosts) {
        unlock::QuitReport r = unlock::QuitThreads(pid, target::kModHookLib,
                                                   target::kHookLibRvaHookThread, waitMs);
        matched += r.matched;
        posted += r.posted;
        survived += r.survived;
        if (!detail.empty()) detail += L"； ";
        detail += Fmt(L"pid=%lu %s", pid, unlock::Describe(r).c_str());
    }
    ++extTries_;

    mousePresent_ = (matched > 0);
    if (posted > 0 && survived == 0) {
        ++mouseUnlocks_;
        unlock::ReleaseCursor();
    }

    // 能确定"外部通道不行"的两种情形：
    //   * 锁线程在，但 WM_QUIT 投不进去（1444 = 它没有消息队列）；
    //   * 投进去等了也没退出（它没在处理消息）。
    // "模块在但一条线程都匹配不到"不算——那多半是压根没锁，交给 rep.mouseHook 判断。
    needInProc_ = (matched > 0 && posted == 0) || survived > 0;

    if (needInProc_ && (verbose || !wasPresent)) {
        A().log.Warn(L"外部解锁不可靠（%s），改用进程内通道", detail.c_str());
    }
    lastResult_ = detail;

    if (posted > 0 && (verbose || !wasPresent)) {
        A().log.Info(L"鼠标锁：外部通道投递 %d 条，已退出 %d 条%s",
                     posted, posted - survived, survived ? L"（部分仍在）" : L"");
    }
}

void InputUnlocker::UnlockNow(const Locator& loc, bool kbEnabled, bool mouseEnabled) {
    KillKeyboardLocks(kbEnabled);
    if (mouseEnabled) {
        lastMouseTry_ = NowMs();
        // 显式动作：忽略缓存、等一小会儿确认线程真的退了
        AttemptMouse(loc, true, 500, true);
    }
}

void InputUnlocker::Tick(const Settings& cfg, const Locator& loc, bool kbEnabled, bool mouseEnabled) {
    (void)cfg;

    // 键盘：每 tick 都查（进程枚举很便宜，而且它可能被反复拉起）
    KillKeyboardLocks(kbEnabled);

    if (!mouseEnabled) {
        mousePresent_ = false;
        needInProc_ = false;
        return;
    }

    const uint64_t now = NowMs();
    if (now - lastMouseTry_ < 500) return;
    lastMouseTry_ = now;
    // 周期路径不等待：投递是异步的，UI 线程不能为了确认退出而卡住
    AttemptMouse(loc, false, 0, false);
}

std::wstring InputUnlocker::StatusText() const {
    std::wstring s;
    s += kbPresent_ ? L"键盘：锁定中｜" : L"键盘：正常｜";
    s += mousePresent_ ? L"鼠标：锁定中" : L"鼠标：正常";
    if (needInProc_) s += L"（外部失效，走注入通道）";
    if (keyKills_ || mouseUnlocks_) {
        s += Fmt(L"（已解 %d/%d 次）", (int)keyKills_, (int)mouseUnlocks_);
    }
    return s;
}

} // namespace ct
