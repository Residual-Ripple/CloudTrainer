// =============================================================================
//  CloudTrainer - CtMain.cpp
//  ---------------------------------------------------------------------------
//  应用外壳：命令行 / 提权 / 单实例 / 消息窗 / 热键 / 调度 / 能力开关。
//  单线程 + WM_TIMER 驱动：所有模块的 Tick 都在 UI 线程上跑，
//  只有注入工作线程例外（它只碰自己的队列和会话表，全部加锁）。
// =============================================================================
#include "Core.h"

#include <shellapi.h>

namespace ct {

// ─────────────────────────────────────────────────────────────────────────────
//  全局
// ─────────────────────────────────────────────────────────────────────────────
App& App::I() {
    static App inst;
    return inst;
}
App& A() { return App::I(); }

static const wchar_t kMsgClass[] = L"CtMsgWnd";

enum HotkeyId {
    HK_FAKE_BLACK = 1,
    HK_RESTORE_ALL = 2,
    HK_STATUS = 3,
};

// ─────────────────────────────────────────────────────────────────────────────
//  小工具
// ─────────────────────────────────────────────────────────────────────────────
static void EnableDpiAwareness() {
    HMODULE u = GetModuleHandleW(L"user32.dll");
    if (u) {
        typedef BOOL(WINAPI * FnSetCtx)(HANDLE);
        auto p = reinterpret_cast<FnSetCtx>(GetProcAddress(u, "SetProcessDpiAwarenessContext"));
        if (p && p(reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-4)))) return;   // PER_MONITOR_AWARE_V2
    }
    SetProcessDPIAware();
}

static void Balloon(HWND owner, const wchar_t* title, const wchar_t* text, DWORD flags) {
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = owner;
    nid.uID = 1;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = flags;
    wcsncpy(nid.szInfoTitle, title, 63);
    wcsncpy(nid.szInfo, text, 255);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static bool RelaunchElevated() {
    wchar_t path[MAX_PATH * 2]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH * 2)) return false;
    SHELLEXECUTEINFOW ei{};
    ei.cbSize = sizeof(ei);
    ei.fMask = SEE_MASK_NOCLOSEPROCESS;
    ei.lpVerb = L"runas";
    ei.lpFile = path;
    ei.lpParameters = L"--elevated";
    ei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&ei)) return false;
    if (ei.hProcess) CloseHandle(ei.hProcess);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  消息窗
// ─────────────────────────────────────────────────────────────────────────────
static LRESULT CALLBACK MsgProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    static UINT s_showMsg = RegisterWindowMessageW(L"CloudTrainer.ShowStatus");
    App& a = A();

    if (m == s_showMsg && s_showMsg != 0) {
        a.ShowStatus();
        return 0;
    }
    switch (m) {
        case WM_CT_TRAY:
            a.OnTray(static_cast<UINT>(LOWORD(l)));
            return 0;
        case WM_TIMER:
            a.OnTimer();
            return 0;
        case WM_HOTKEY:
            switch (w) {
                case HK_FAKE_BLACK:
                    a.ui.ShowFakeBlack(!a.ui.FakeBlackActive());
                    break;
                case HK_RESTORE_ALL:
                    a.RequestRestoreHotkey();
                    break;
                case HK_STATUS:
                    a.ui.ToggleStatus();
                    break;
                default:
                    break;
            }
            return 0;
        case WM_COMMAND:
            a.OnCommand(LOWORD(w), HIWORD(w));
            return 0;
        case WM_QUERYENDSESSION:
            return TRUE;
        case WM_ENDSESSION:
            if (w) a.RestoreAll(false);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(h, m, w, l);
}

// ─────────────────────────────────────────────────────────────────────────────
//  App::Run
// ─────────────────────────────────────────────────────────────────────────────
int App::Run(HINSTANCE hInstance, int nCmdShow) {
    hInst = hInstance;
    (void)nCmdShow;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MsgProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = kMsgClass;
    RegisterClassExW(&wc);

    // 用"隐藏的顶层窗口"而不是 HWND_MESSAGE：后者不能成为前台窗口，
    // 会导致 TrackPopupMenuEx 弹不出来 / 一弹就消失。
    msgWnd = CreateWindowExW(0, kMsgClass, L"CloudTrainer", WS_POPUP, 0, 0, 0, 0,
                             nullptr, nullptr, hInstance, nullptr);
    if (!msgWnd) return 1;

    if (!Init()) {
        MessageBoxW(nullptr, L"CloudTrainer 初始化失败，详见日志。", L"CloudTrainer",
                    MB_ICONERROR | MB_OK);
        return 2;
    }

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    inj.Stop();
    ui.Destroy();
    if (msgWnd) DestroyWindow(msgWnd);
    return 0;
}

bool App::Init() {
    dataDir = GetDataDir();
    log.Init(dataDir);

    std::wstring ini = dataDir + L"\\config.ini";
    cfg.Load(ini);
    if (!FileExists(ini)) cfg.Save(ini);

    EnablePrivilege(SE_DEBUG_NAME);

    if (!cfg.installDirHint.empty()) loc.SetHint(cfg.installDirHint);
    loc.Refresh(true);
    std::wstring dir;
    loc.FindInstallDir(&dir, true);
    ver.Evaluate(dir);

    log.Info(L"数据目录：%s", dataDir.c_str());
    log.Info(L"安装目录：%s", dir.empty() ? L"(未找到)" : dir.c_str());
    log.Info(L"版本判定：%s（%s）", EnvLevelName(ver.Level()), ver.Detail().c_str());
    log.Info(L"提权：%s", IsElevated() ? L"是" : L"否");
    log.Info(L"能力开关：广播=%d 黑屏=%d 键盘=%d 鼠标=%d 结束拦截=%d 关窗拦截=%d 命令闸门=%d"
             L"（startupEnableAll=%d）",
             cfg.fixBroadcast ? 1 : 0, cfg.killBlackScreen ? 1 : 0,
             cfg.unlockKeyboard ? 1 : 0, cfg.unlockMouse ? 1 : 0,
             cfg.blockTerminate ? 1 : 0, cfg.blockClose ? 1 : 0,
             cfg.cmdGate ? 1 : 0, cfg.startupEnableAll ? 1 : 0);

    inj.Start(dataDir);

    if (!ui.Create(msgWnd, hInst)) {
        log.Warn(L"托盘图标创建失败（可能被系统策略拦截），状态窗仍可用");
    }

    SetTimer(msgWnd, 1, 250, nullptr);

    struct { int id; UINT mod; UINT vk; } hks[] = {
        { HK_FAKE_BLACK, MOD_CONTROL | MOD_ALT, 'F' },
        { HK_RESTORE_ALL, MOD_CONTROL | MOD_ALT, 'H' },
        { HK_STATUS, MOD_CONTROL | MOD_ALT, 'D' },
    };
    for (auto& hk : hks) {
        if (!RegisterHotKey(msgWnd, hk.id, hk.mod, hk.vk)) {
            log.Warn(L"热键注册失败 id=%d vk=%u（可能被别的程序占用）", hk.id, hk.vk);
        }
    }

    uint64_t now = NowMs();
    nextLoc_ = now;
    nextVer_ = now;
    nextBeat_ = now;
    nextPolicy_ = now;
    policyDirty_ = true;

    log.Info(L"启动完成，%s", IsElevated() ? L"管理员权限" : L"普通权限（部分能力不可用）");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  调度
// ─────────────────────────────────────────────────────────────────────────────
void App::OnTimer() { Tick(); }

void App::Tick() {
    if (quitting) return;
    const uint64_t now = NowMs();

    if (now >= nextLoc_) {
        nextLoc_ = now + 1200;
        loc.Refresh(true);
    }
    if (now >= nextVer_) {
        nextVer_ = now + 5000;
        std::wstring dir;
        loc.FindInstallDir(&dir, true);
        ver.Evaluate(dir);
    }

    const bool readOnly = ver.Level() == EnvLevel::ReadOnly;

    black.Tick(cfg.killBlackScreen && !readOnly);
    input.Tick(cfg, loc, cfg.unlockKeyboard && !readOnly, cfg.unlockMouse && !readOnly);
    fixer.Tick(cfg, cfg.fixBroadcast);

    // 只有需要“注入类能力”时才注入；只做窗口/黑屏/键盘时完全不碰目标进程
    const bool needHooks = cfg.blockTerminate || cfg.blockClose || cfg.cmdGate;
    if (cfg.autoInject && !readOnly && needHooks) {
        for (DWORD pid : loc.PidsByExe(target::kProcStudent)) inj.Ensure(pid);
        for (DWORD pid : loc.PidsWithModule(target::kModHookLib)) inj.Ensure(pid);
    }

    if (now >= nextBeat_) {
        nextBeat_ = now + 1000;
        inj.BeatAll();
    }
    if (policyDirty_ || now >= nextPolicy_) {
        nextPolicy_ = now + 5000;
        policyDirty_ = false;
        inj.PushPolicy(cfg, ProtectPids());
    }

    // 远程命令裁决
    if (!ui.GateVisible()) {
        DWORD gpid = 0;
        int gidx = -1;
        CtPendingCmd cmd{};
        if (inj.FindPending(&gpid, &gidx, &cmd)) {
            gatePid_ = gpid;
            gateIdx_ = gidx;
            Balloon(msgWnd, L"远程命令待确认", L"教师端正在本机执行一条命令，请在弹窗里选择。",
                    NIIF_WARNING);
            ui.ShowGate(cmd, gidx);
        }
    }

    ui.Update();
}

std::vector<DWORD> App::ProtectPids() {
    std::vector<DWORD> v;
    v.push_back(GetCurrentProcessId());
    // 用户当前正在用的程序：教师端“远程关闭应用程序”最可能命中的就是它
    HWND fg = GetForegroundWindow();
    if (fg) {
        DWORD fp = 0;
        GetWindowThreadProcessId(fg, &fp);
        if (fp && fp != GetCurrentProcessId()) v.push_back(fp);
    }
    for (DWORD p : loc.PidsByExe(target::kProcStudent)) v.push_back(p);
    for (DWORD p : loc.PidsByExe(target::kProcMultiRender)) v.push_back(p);
    return v;
}

// ─────────────────────────────────────────────────────────────────────────────
//  命令
// ─────────────────────────────────────────────────────────────────────────────
void App::OnCommand(int id, int code) {
    (void)code;
    if (id >= ID_TOGGLE_BASE && id < ID_TOGGLE_END) {
        ToggleCap(id - ID_TOGGLE_BASE);
        return;
    }
    switch (id) {
        case ID_TRAY_STATUS:
        case ID_BTN_ABOUT:
            if (id == ID_BTN_ABOUT) {
                std::wstring msg = Fmt(
                    L"CloudTrainer %s\n\n"
                    L"针对联想电子教室（NeiCloud）学生端的窗口/输入/命令层辅助工具。\n"
                    L"技术思路参考开源项目 JiYuTrainer（MIT, © imengyu），业务代码全部重写。\n\n"
                    L"热键：\n"
                    L"  Ctrl+Alt+F  假装黑屏 / 取消\n"
                    L"  Ctrl+Alt+H  一键全部还原（3 秒内按两次）\n"
                    L"  Ctrl+Alt+D  显示 / 隐藏状态窗\n\n"
                    L"仅限在自有设备与授权环境中使用。",
                    kAppVersion);
                MessageBoxW(ui.StatusWnd() ? ui.StatusWnd() : msgWnd, msg.c_str(),
                            L"关于 CloudTrainer", MB_ICONINFORMATION | MB_OK);
            } else {
                ShowStatus();
            }
            break;
        case ID_TRAY_RESTORE:
        case ID_BTN_RESTORE:
            RestoreAll(false);
            break;
        case ID_TRAY_LOGDIR:
        case ID_BTN_LOGDIR:
            ShellExecuteW(nullptr, L"open", log.Dir().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            break;
        case ID_TRAY_EXIT:
            RestoreAll(true);
            break;
        default:
            break;
    }
}

void App::ToggleCap(int cap) {
    bool* p = cfg.CapPtr(cap);
    if (!p) return;
    *p = !*p;
    cfg.Save(dataDir + L"\\config.ini");
    policyDirty_ = true;
    log.Info(L"能力 [%s] -> %s", CapName(cap), *p ? L"开" : L"关");
    ui.Update();
}

void App::OnTray(UINT evt) {
    switch (evt) {
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU: {
            POINT pt{};
            GetCursorPos(&pt);
            ui.ShowMenu(pt);
            break;
        }
        case WM_LBUTTONDBLCLK:
        case NIN_BALLOONUSERCLICK:
            ui.ShowStatus();
            break;
        default:
            break;
    }
}

void App::ShowStatus() { ui.ShowStatus(); }

void App::RequestRestoreHotkey() {
    uint64_t now = NowMs();
    if (now < restoreConfirmUntil_) {
        restoreConfirmUntil_ = 0;
        RestoreAll(false);
        return;
    }
    restoreConfirmUntil_ = now + 3000;
    Balloon(msgWnd, L"全部还原", L"3 秒内再按一次 Ctrl+Alt+H 确认。", NIIF_WARNING);
    log.Info(L"全部还原：等待二次确认");
}

void App::DecideGate(int decision) {
    if (gatePid_ && gateIdx_ >= 0) {
        inj.AnswerPending(gatePid_, gateIdx_, decision);
        log.Info(L"远程命令裁决：%s（pid=%lu slot=%d）",
                 decision == CT_CMD_ALLOW ? L"允许一次"
                 : decision == CT_CMD_ALLOWALL ? L"一律允许" : L"拒绝",
                 gatePid_, gateIdx_);
        // “一律允许”的会话内白名单由载荷自己维护（不落盘，避免在目标机器留文件）；
        // 这里只记一条日志，方便事后核对。
        if (decision == CT_CMD_ALLOWALL) {
            log.Info(L"该命令名已加入本次会话的白名单");
        }
    }
    gatePid_ = 0;
    gateIdx_ = -1;
    ui.HideGate();
}

void App::RestoreAll(bool exitAfter) {
    if (quitting && !exitAfter) return;
    log.Info(L"开始全部还原（exit=%d）", exitAfter ? 1 : 0);
    quitting = true;

    // 1) 先把所有能力关掉：否则 5 秒后策略下发又会把注入装回去，
    //    "还原"就变成了一个看起来没用的按钮。
    for (int i = 0; i < CAP_COUNT; ++i) {
        bool* p = cfg.CapPtr(i);
        if (p) *p = false;
    }
    cfg.Save(dataDir + L"\\config.ini");
    policyDirty_ = true;

    // 2) 顺序很重要：先撤掉自己造的假黑屏钩子，否则可能连热键都被吞
    ui.DestroyFakeBlack();

    // 3) 把改过的广播窗口还原成全屏置顶
    fixer.RestoreAll();

    // 4) 通知载荷卸载全部 IAT 补丁并退出线程
    inj.PushPolicy(cfg, ProtectPids());
    inj.ShutdownAll();

    log.Info(L"全部还原完成，所有能力已关闭");
    if (exitAfter) {
        PostMessageW(msgWnd, WM_CLOSE, 0, 0);
    } else {
        quitting = false;
        Balloon(msgWnd, L"已全部还原",
                L"广播窗口、假黑屏、注入钩子都已恢复。所有能力已关闭，可在托盘菜单里重新开启。",
                NIIF_INFO);
    }
}

} // namespace ct

// ─────────────────────────────────────────────────────────────────────────────
//  入口
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
    using namespace ct;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool probe = false, noElevate = false;
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--probe") == 0) probe = true;
        else if (_wcsicmp(argv[i], L"--no-elevate") == 0) noElevate = true;
        else if (_wcsicmp(argv[i], L"--elevated") == 0) noElevate = true;
    }
    if (argv) LocalFree(argv);

    if (probe) return RunProbe();

    if (!IsElevated() && !noElevate) {
        if (RelaunchElevated()) return 0;
        // 提权被拒绝：继续以普通权限运行，能力会自动降级
    }

    // 单实例：命名事件，不用 Mutex（与目标产品习惯一致，且可以唤醒已有实例）
    HANDLE inst = CreateEventW(nullptr, TRUE, FALSE, kInstanceEvent);
    if (inst && GetLastError() == ERROR_ALREADY_EXISTS) {
        UINT m = RegisterWindowMessageW(L"CloudTrainer.ShowStatus");
        PostMessageW(HWND_BROADCAST, m, 0, 0);
        CloseHandle(inst);
        return 0;
    }

    EnableDpiAwareness();
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    int rc = App::I().Run(hInst, nCmdShow);
    CoUninitialize();
    if (inst) CloseHandle(inst);
    return rc;
}
