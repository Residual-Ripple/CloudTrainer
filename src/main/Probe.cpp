// =============================================================================
//  CloudTrainer - Probe.cpp
//  ---------------------------------------------------------------------------
//  `CloudTrainer.exe --probe`
//  只做一次目标发现与指纹比对，把结果打到控制台后退出。
//  不做任何修改、不注入、不结束任何进程 —— 排障用的“只读体检”。
// =============================================================================
#include "Core.h"

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

} // namespace ct
