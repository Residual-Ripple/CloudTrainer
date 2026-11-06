// =============================================================================
//  CloudTrainer - Probe.cpp
//  ---------------------------------------------------------------------------
//  `CloudTrainer.exe --probe`
//  只做一次目标发现与指纹比对，把结果打到控制台后退出。
//  不做任何修改、不注入、不结束任何进程 —— 排障用的“只读体检”。
// =============================================================================
#include "Core.h"
#include "Unlock.h"

namespace ct {

namespace {

HANDLE g_out = INVALID_HANDLE_VALUE;

void P(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 2047, fmt, ap);
    buf[2047] = 0;
    va_end(ap);

    if (g_out == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    std::string u8 = WideToUtf8(std::wstring(buf) + L"\r\n");
    WriteFile(g_out, u8.data(), (DWORD)u8.size(), &written, nullptr);
}

} // namespace

int RunProbe() {
    bool ownConsole = false;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        ownConsole = AllocConsole() != FALSE;
    }
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"CloudTrainer 探针");

    P(L"");
    P(L"CloudTrainer %s  探针（只读，不修改任何东西）", kAppVersion);
    P(L"==================================================================");
    P(L"时间       : %s", NowStamp().c_str());
    P(L"自身路径   : %s", GetExePath().c_str());
    P(L"管理员权限 : %s", IsElevated() ? L"是" : L"否（部分能力不可用）");

    Locator loc;
    loc.Refresh(true);

    std::wstring dir;
    loc.FindInstallDir(&dir, true);
    P(L"安装目录   : %s", dir.empty() ? L"(未找到)" : dir.c_str());
    P(L"学生端事件 : %s", loc.StudentEventExists() ? L"StudentRunning 存在" : L"未发现");

    P(L"");
    P(L"-- 文件指纹 ------------------------------------------------------");
    int matched = 0;
    for (int i = 0; i < target::kFingerprintCount; ++i) {
        const auto& fp = target::kFingerprints[i];
        std::wstring path = dir.empty() ? L"" : (dir + L"\\" + fp.file);
        PeInfo info = path.empty() ? PeInfo{} : ReadPeInfo(path);
        bool sizeOk = info.ok && info.size == fp.size;
        bool tdsOk = info.ok && info.timeDateStamp == fp.timeDateStamp;
        if (sizeOk && tdsOk) ++matched;
        P(L"  %-18s %s  size=%8u(期望%8u)  tds=0x%08X(期望0x%08X) %s",
          fp.file, info.ok ? L"OK  " : L"MISS",
          info.size, fp.size, info.timeDateStamp, fp.timeDateStamp,
          (sizeOk && tdsOk) ? L"匹配" : (fp.critical ? L"不匹配[主链]" : L"不匹配"));
    }
    P(L"  合计 %d / %d 匹配", matched, target::kFingerprintCount);

    VersionGuard ver;
    ver.Evaluate(dir);
    P(L"  判定：%s（%s）", EnvLevelName(ver.Level()), ver.Detail().c_str());

    P(L"");
    P(L"-- 进程 ----------------------------------------------------------");
    auto show = [&](const wchar_t* name) {
        auto pids = loc.PidsByExe(name);
        std::wstring s;
        for (size_t i = 0; i < pids.size(); ++i) {
            if (i) s += L", ";
            s += Fmt(L"%lu", pids[i]);
        }
        P(L"  %-20s %s", name, pids.empty() ? L"(未运行)" : s.c_str());
    };
    show(target::kProcStudent);
    show(target::kProcMultiRender);
    show(target::kProcBlackSilent);
    show(target::kProcPDelKeyB);
    show(target::kProcMulti);
    show(target::kProcProtect);

    P(L"");
    P(L"-- HookLib 宿主 ---------------------------------------------------");
    auto hosts = loc.PidsWithModule(target::kModHookLib, true);
    if (hosts.empty()) {
        P(L"  (没有进程加载 %s)", target::kModHookLib);
    } else {
        for (DWORD pid : hosts) {
            uint32_t base = 0, size = 0;
            loc.ModuleRange(pid, target::kModHookLib, &base, &size);
            P(L"  pid=%lu  %s  基址=0x%08lX  大小=%lu",
              pid, ProcessImagePath(pid).c_str(), base, size);
        }
    }

    P(L"");
    P(L"-- 网络参数（仅参考） ---------------------------------------------");
    P(L"  控制组播 %s ｜ 屏幕 %s ｜ 端口 %u/%u/%u/%u",
      target::kMcastControl, target::kMcastScreen,
      target::kPortConnect, target::kPortRcf, target::kPortFileXfer, target::kPortController);

    P(L"");
    P(L"探针结束。");

    if (ownConsole) {
        P(L"");
        P(L"按回车键关闭…");
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        if (in != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(in, &mode)) {
                wchar_t ch;
                DWORD n = 0;
                ReadConsoleW(in, &ch, 1, &n, nullptr);
            }
        }
    }
    return 0;
}


// ─────────────────────────────────────────────────────────────────────────────
//  --netprobe：网络受限时到底是谁动的手
//
//  "上课被控时上不了网" 常见有四种实现，光看现象分不出来，所以这里把可读的
//  状态全部打出来，不做任何修改：
//    1) Windows 防火墙默认出站策略被改成 Block
//    2) 防火墙里被塞了针对某程序 / 全局的 Block 规则
//    3) 系统代理被改（ProxyEnable / AutoConfigURL）
//    4) 厂商的 WFP 驱动在工作（这个读不到，只能看服务是否在跑）
// ─────────────────────────────────────────────────────────────────────────────
namespace {

std::wstring RegStr(HKEY root, const wchar_t* sub, const wchar_t* name, bool* ok = nullptr) {
    HKEY k = nullptr;
    std::wstring out;
    if (ok) *ok = false;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return out;
    wchar_t buf[4096]{};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(k, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        out.assign(buf, sz / sizeof(wchar_t));
        while (!out.empty() && out.back() == L'\0') out.pop_back();
        if (ok) *ok = true;
    }
    RegCloseKey(k);
    return out;
}

bool RegDword(HKEY root, const wchar_t* sub, const wchar_t* name, DWORD* out) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return false;
    DWORD v = 0, sz = sizeof(v), type = 0;
    bool ok = RegQueryValueExW(k, name, nullptr, &type, reinterpret_cast<LPBYTE>(&v), &sz) == ERROR_SUCCESS &&
              type == REG_DWORD;
    RegCloseKey(k);
    if (ok && out) *out = v;
    return ok;
}

// 规则值形如：v2.10|Action=Block|Active=TRUE|Dir=Out|App=...|Name=...
void DumpFirewallRules() {
    const wchar_t* sub =
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
    HKEY k = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) {
        P(L"  (读不到防火墙规则键)");
        return;
    }

    int total = 0, blocked = 0;
    wchar_t name[512];
    std::vector<wchar_t> data(32768);
    DWORD idx = 0;
    while (idx < 1000) {
        DWORD nameLen = 512;
        DWORD dataLen = static_cast<DWORD>(data.size() * sizeof(wchar_t));
        DWORD type = 0;
        LONG rc = RegEnumValueW(k, idx++, name, &nameLen, nullptr, &type,
                                reinterpret_cast<LPBYTE>(data.data()), &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS || type != REG_SZ) continue;

        ++total;
        std::wstring v(data.data(), dataLen / sizeof(wchar_t));
        if (v.find(L"Action=Block") == std::wstring::npos) continue;
        if (v.find(L"Active=TRUE") == std::wstring::npos) continue;
        ++blocked;
        if (blocked <= 12) {
            std::wstring nm, app, dir;
            size_t p;
            if ((p = v.find(L"Name=")) != std::wstring::npos) {
                size_t e = v.find(L'|', p);
                nm = v.substr(p + 5, e == std::wstring::npos ? std::wstring::npos : e - p - 5);
            }
            if ((p = v.find(L"App=")) != std::wstring::npos) {
                size_t e = v.find(L'|', p);
                app = v.substr(p + 4, e == std::wstring::npos ? std::wstring::npos : e - p - 4);
            }
            if ((p = v.find(L"Dir=")) != std::wstring::npos) {
                size_t e = v.find(L'|', p);
                dir = v.substr(p + 4, e == std::wstring::npos ? std::wstring::npos : e - p - 4);
            }
            P(L"    [%d] %s  方向=%s  程序=%s", blocked, nm.c_str(),
              dir.empty() ? L"?" : dir.c_str(), app.empty() ? L"(全部)" : app.c_str());
        }
    }
    RegCloseKey(k);
    P(L"  扫描 %d 条，其中生效的 Block 规则 %d 条%s", total, blocked,
      blocked > 12 ? L"（只列前 12 条）" : L"");
}

} // namespace

int RunNetProbe() {
    bool ownConsole = false;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) ownConsole = AllocConsole() != FALSE;
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"CloudTrainer 网络探针");

    P(L"");
    P(L"CloudTrainer %s  网络探针（只读）", kAppVersion);
    P(L"==================================================================");

    struct Prof { const wchar_t* key; const wchar_t* label; };
    const Prof profs[] = {
        { L"DomainProfile",   L"域" },
        { L"StandardProfile", L"专用" },
        { L"PublicProfile",   L"公用" },
    };
    P(L"-- Windows 防火墙 -------------------------------------------------");
    for (const auto& pr : profs) {
        std::wstring sub = Fmt(
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\%s", pr.key);
        DWORD enable = 0, inAct = 0, outAct = 0;
        bool hasEn = RegDword(HKEY_LOCAL_MACHINE, sub.c_str(), L"EnableFirewall", &enable);
        bool hasIn = RegDword(HKEY_LOCAL_MACHINE, sub.c_str(), L"DefaultInboundAction", &inAct);
        bool hasOut = RegDword(HKEY_LOCAL_MACHINE, sub.c_str(), L"DefaultOutboundAction", &outAct);
        P(L"  %s：启用=%s 入站默认=%s 出站默认=%s",
          pr.label,
          hasEn ? (enable ? L"是" : L"否") : L"是",
          hasIn ? (inAct == 0 ? L"允许" : L"阻止") : L"允许（未显式设置）",
          hasOut ? (outAct == 0 ? L"允许" : L"阻止") : L"允许（未显式设置）");
    }

    P(L"-- 生效的 Block 规则 ----------------------------------------------");
    DumpFirewallRules();

    P(L"-- 系统代理 --------------------------------------------------------");
    const wchar_t* inet = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    DWORD proxyEnable = 0;
    bool hasProxy = RegDword(HKEY_CURRENT_USER, inet, L"ProxyEnable", &proxyEnable);
    std::wstring proxyServer = RegStr(HKEY_CURRENT_USER, inet, L"ProxyServer");
    std::wstring pac = RegStr(HKEY_CURRENT_USER, inet, L"AutoConfigURL");
    P(L"  ProxyEnable=%s  ProxyServer=%s  AutoConfigURL=%s",
      hasProxy ? (proxyEnable ? L"1" : L"0") : L"?",
      proxyServer.empty() ? L"(空)" : proxyServer.c_str(),
      pac.empty() ? L"(空)" : pac.c_str());

    P(L"-- 厂商网络组件 ----------------------------------------------------");
    DWORD startType = 0;
    bool hasSvc = RegDword(HKEY_LOCAL_MACHINE,
                           L"SYSTEM\\CurrentControlSet\\Services\\Inspect", L"Start", &startType);
    if (hasSvc) {
        P(L"  Inspect 驱动：已注册，Start=%lu（2=Demand 表示不会自动加载）", startType);
    } else {
        P(L"  Inspect 驱动：未注册");
    }

    {
        DWORD state = 0xFFFFFFFF;
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scm) {
            SC_HANDLE svc = OpenServiceW(scm, L"Inspect", SERVICE_QUERY_STATUS);
            if (svc) {
                SERVICE_STATUS st{};
                if (QueryServiceStatus(svc, &st)) state = st.dwCurrentState;
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
        const wchar_t* text = L"查询失败";
        switch (state) {
            case SERVICE_RUNNING: text = L"RUNNING（正在过滤网络）"; break;
            case SERVICE_STOPPED: text = L"STOPPED"; break;
            case SERVICE_START_PENDING: text = L"START_PENDING"; break;
            case SERVICE_STOP_PENDING: text = L"STOP_PENDING"; break;
            default: break;
        }
        P(L"  驱动服务状态：%s", text);
    }

    {
        const wchar_t* names[] = { L"mmcLimitConsole_x64.exe", L"mmcLimitConsole_x86.exe",
                                   L"mmcLimitConsole.exe" };
        int total = 0;
        for (int i = 0; i < 3; ++i) total += (int)EnumPidsByName(names[i]).size();
        P(L"  限制执行器 mmcLimitConsole：%s", total ? L"正在运行" : L"未运行");
    }

    P(L"");
    P(L"判读方法：");
    P(L"  * 出站默认=阻止，或出现大量 Block(Out) 规则  -> 是防火墙");
    P(L"  * ProxyEnable=1 / 有 AutoConfigURL           -> 是代理劫持");
    P(L"  * 两者都正常                                 -> 大概率是 WFP 过滤或教师端应用层拦截");
    P(L"");

    if (ownConsole) {
        P(L"按回车键关闭…");
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        if (in != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(in, &mode)) {
                wchar_t ch;
                DWORD n = 0;
                ReadConsoleW(in, &ch, 1, &n, nullptr);
            }
        }
    }
    return 0;
}


// ─────────────────────────────────────────────────────────────────────────────
//  --unlock：不带界面，一次性解除键鼠锁
//
//  为什么需要这个独立入口：被锁住的时候，托盘图标可能根本点不到（鼠标被
//  ClipCursor 钳住、光标被隐藏）。这个模式不创建任何窗口，直接干活。
// ─────────────────────────────────────────────────────────────────────────────
int RunUnlockOnce() {
    bool ownConsole = false;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) ownConsole = AllocConsole() != FALSE;
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"CloudTrainer 解锁");

    P(L"");
    P(L"CloudTrainer %s  一次性解除控制", kAppVersion);
    P(L"==================================================================");

    Locator loc;
    loc.Refresh(true);
    std::wstring dir;
    loc.FindInstallDir(&dir, true);
    P(L"安装目录 : %s", dir.empty() ? L"(未找到)" : dir.c_str());
    P(L"权限     : %s", IsElevated() ? L"管理员" : L"普通（注入/结束进程可能失败）");

    int rc = 0;

    P(L"");
    P(L"-- 键盘锁 PDelKeyB.exe -------------------------------------------");
    {
        unlock::KillReport kb = unlock::KillByName(target::kProcPDelKeyB, GetCurrentProcessId());
        if (kb.found == 0) {
            P(L"  未在运行");
        } else {
            if (kb.lastErr) {
                P(L"  发现 %d 个，已结束 %d 个，最后错误 %lu", kb.found, kb.killed, kb.lastErr);
            } else {
                P(L"  发现 %d 个，已结束 %d 个", kb.found, kb.killed);
            }
            if (kb.killed == 0) rc = 1;
        }
    }

    P(L"");
    P(L"-- 鼠标锁 HookLib.dll --------------------------------------------");
    {
        std::vector<DWORD> hosts = loc.PidsWithModule(target::kModHookLib, true);
        if (hosts.empty()) {
            P(L"  没有进程加载 HookLib.dll");
        } else {
            int posted = 0, survived = 0, unmatched = 0, noModule = 0;
            for (DWORD pid : hosts) {
                unlock::QuitReport r = unlock::QuitThreads(pid, target::kModHookLib,
                                                           target::kHookLibRvaHookThread, 600);
                P(L"  pid=%-6lu %s", pid, unlock::Describe(r).c_str());
                posted += r.posted;
                survived += r.survived;
                if (!r.moduleFound) ++noModule;
                else if (r.matched == 0) ++unmatched;
            }
            if (posted == 0 || survived > 0) {
                rc = 1;
                P(L"");
                P(L"  外部通道无法确认解锁（定位不到锁线程，或投递后线程仍在）。");
                P(L"  让 CloudTrainer 常驻即可走进程内通道：注入 Student.exe 后直接调用");
                P(L"  UnhookWindowsHookEx(g_hHook)，不依赖锁线程配合，也不依赖它有消息队列。");
                if (unmatched || noModule) {
                    P(L"  提示：本次有 %d 个进程匹配不到锁线程、%d 个读不到模块，属于已知盲区。",
                      unmatched, noModule);
                }
            }
        }
    }

    unlock::ReleaseCursor();
    P(L"");
    P(L"已释放光标钳制（ClipCursor）并检查光标是否被钉在屏幕边缘");

    P(L"");
    P(L"结论：%s", rc == 0 ? L"已解除（或本来就没锁）" : L"未能确认解除，见上面的逐条说明");

    // 只在"自己开的窗口 + 真正的控制台"时等回车。被脚本/管道调用时直接返回，
    // 免得 --unlock 卡住调用方。
    if (ownConsole && GetFileType(g_out) == FILE_TYPE_CHAR) {
        P(L"按回车键关闭…");
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        if (in != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(in, &mode)) {
                wchar_t ch;
                DWORD n = 0;
                ReadConsoleW(in, &ch, 1, &n, nullptr);
            }
        }
    }
    return rc;
}


// ─────────────────────────────────────────────────────────────────────────────
//  --winlist：把 CloudTrainer 眼里的窗口列出来（只读）
//
//  用途：当“没有出现广播窗口”时，把它和系统的窗口列表对一遍，就能立刻分清是
//  “没认出”还是“根本没创建”。判定用的是**运行时同一套规则**
//  （IsBroadcastWindowEx），不是另写一份近似逻辑。
// ─────────────────────────────────────────────────────────────────────────────
namespace {

struct WinListCtx {
    int total;
    int matched;
};

BOOL CALLBACK WinListProc(HWND h, LPARAM lp) {
    auto* ctx = reinterpret_cast<WinListCtx*>(lp);
    if (!IsWindowVisible(h)) return TRUE;

    wchar_t cls[128]{};
    GetClassNameW(h, cls, 128);
    wchar_t title[160]{};
    GetWindowTextW(h, title, 160);

    RECT r{};
    GetWindowRect(h, &r);
    const LONG ex = GetWindowLongW(h, GWL_EXSTYLE);

    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    const std::wstring exe = pid ? ProcessBaseName(pid) : std::wstring();

    std::wstring why;
    const bool bc = IsBroadcastWindowEx(h, nullptr, &why);
    if (bc) ++ctx->matched;
    ++ctx->total;

    P(L"%s %-32s pid=%-6lu %-22s %4ldx%-4ld @(%ld,%ld) ex=0x%08lX  %s  [%s]",
      bc ? L"[广播]" : L"[    ]", cls, pid,
      exe.empty() ? L"(读不到进程名)" : exe.c_str(),
      r.right - r.left, r.bottom - r.top, r.left, r.top, ex,
      title[0] ? title : L"(无标题)", why.c_str());
    return TRUE;
}

} // namespace

int RunWinList() {
    bool ownConsole = false;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) ownConsole = AllocConsole() != FALSE;
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"CloudTrainer 窗口列表");

    P(L"");
    P(L"CloudTrainer %s  窗口列表（只读）", kAppVersion);
    P(L"==================================================================");
    P(L"判定规则：类名命中 %s 即认；类名不同时按“全屏+置顶+厂商进程”兜底。",
      target::kClsBroadcast);
    P(L"");

    WinListCtx ctx{ 0, 0 };
    EnumWindows(&WinListProc, reinterpret_cast<LPARAM>(&ctx));

    P(L"");
    P(L"可见顶层窗口 %d 个，其中判定为广播窗口 %d 个。", ctx.total, ctx.matched);
    if (ctx.matched == 0) {
        P(L"");
        P(L"没有广播窗口时请确认：① 教师端确实在广播；② 学生端进程在跑；");
        P(L"③ 广播窗口是否被最小化/隐藏（本工具只处理可见窗口）。");
    }

    if (ownConsole && GetFileType(g_out) == FILE_TYPE_CHAR) {
        P(L"按回车键关闭…");
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        if (in != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(in, &mode)) {
                wchar_t ch;
                DWORD n = 0;
                ReadConsoleW(in, &ch, 1, &n, nullptr);
            }
        }
    }
    return 0;
}

} // namespace ct
