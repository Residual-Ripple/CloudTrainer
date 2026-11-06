// =============================================================================
//  test_unlock —— 外部解锁通道的端到端测试
//
//  用法：test_unlock.exe <pid> <queue|noqueue>
//
//  queue   ：目标进程里那条锁线程有消息队列 —— 必须定位到、投递成功、并且真的退出；
//  noqueue ：锁线程没有消息队列 —— 必须**如实报告失败**（posted=0），
//            而不是像旧实现那样静默返回 0 当没事发生。
//
//  两种情形下都要求宿主进程存活：解锁不能靠杀进程。
// =============================================================================
#include "../src/main/Unlock.h"
#include "../src/common/TargetDefs.h"

#include <stdio.h>
#include <string>

static void Say(const wchar_t* s) {
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return;
    std::string u8(static_cast<size_t>(n), 0);
    WideCharToMultiByte(CP_UTF8, 0, s, -1, &u8[0], n, nullptr, nullptr);
    fputs(u8.c_str(), stdout);
    fflush(stdout);
}

int main() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc < 3) {
        Say(L"用法：test_unlock.exe <pid> <queue|noqueue>\n");
        return 2;
    }
    const DWORD pid = wcstoul(argv[1], nullptr, 10);
    const std::wstring mode = argv[2];
    LocalFree(argv);

    Say(L"[1] 对 pid=");
    Say(std::to_wstring(pid).c_str());
    Say(L" 执行外部解锁（模块 HookLib.dll，已知 RVA 0x1420）\n");

    ct::unlock::QuitReport r = ct::unlock::QuitThreads(pid, L"HookLib.dll",
                                                       ct::target::kHookLibRvaHookThread, 900);
    Say(L"[2] ");
    Say(ct::unlock::Describe(r).c_str());
    Say(L"\n");

    Say(L"[3] 明细：moduleFound=");
    Say(r.moduleFound ? L"1" : L"0");
    Say(L" threads=");
    Say(std::to_wstring(r.threads).c_str());
    Say(L" matched=");
    Say(std::to_wstring(r.matched).c_str());
    Say(L" exact=");
    Say(std::to_wstring(r.exact).c_str());
    Say(L" posted=");
    Say(std::to_wstring(r.posted).c_str());
    Say(L" survived=");
    Say(std::to_wstring(r.survived).c_str());
    Say(L" lastErr=");
    Say(std::to_wstring(r.lastErr).c_str());
    Say(L"\n");

    // 宿主必须活着：解锁不等于杀进程
    bool hostAlive = false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        DWORD code = 0;
        hostAlive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
        CloseHandle(h);
    }
    Say(hostAlive ? L"[4] 宿主进程存活 ✔\n" : L"[4] 宿主进程已消失 ✘\n");
    if (!hostAlive) return 9;

    if (mode == L"queue") {
        const bool ok = r.moduleFound && r.matched >= 1 && r.posted >= 1 && r.survived == 0;
        if (!ok) {
            Say(L"[FAIL] 有消息队列的场景应当能被定位并退出\n");
            return 5;
        }
        Say(L"PASS（定位到锁线程、投递成功、线程已退出）\n");
        return 0;
    }

    // noqueue：必须报告失败，且不能谎报成功
    const bool ok = r.moduleFound && r.matched >= 1 && r.posted == 0 && !r.Ok();
    if (!ok) {
        Say(L"[FAIL] 没有消息队列时应当如实报告投递失败\n");
        return 6;
    }
    Say(L"PASS（正确识别出\"投递不了\"，会交给进程内通道）\n");
    return 0;
}
