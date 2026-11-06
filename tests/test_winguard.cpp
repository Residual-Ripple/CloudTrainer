// =============================================================================
//  test_winguard —— 窗口守卫的端到端验证
//
//  用法：test_winguard.exe <pid> <hwnd> <payload.dll>
//
//  场景：宿主进程里有一个"会把位置钉回 (0,0)"的假广播窗口（见 winguardhost.c）。
//        注入载荷后，winguard 子类化该窗口；我们再从外部 SetWindowPos(300,200)。
//
//  判据：窗口最终停在 (300,200)。
//        * 没注入 / 守卫没生效  -> 会被宿主的 WndProc 拉回 (0,0)；
//        * 守卫生效但顺序错了    -> 同样回 (0,0)（旧实现就是这样）。
// =============================================================================
#include "../src/main/Reflect.h"
#include "../src/common/CtIpc.h"

#include <stdio.h>
#include <string>
#include <vector>

typedef BOOL(WINAPI* FnSetWindowPos)(HWND, HWND, int, int, int, int, UINT);

static void Say(const wchar_t* s) {
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return;
    std::string u8(static_cast<size_t>(n), 0);
    WideCharToMultiByte(CP_UTF8, 0, s, -1, &u8[0], n, nullptr, nullptr);
    fputs(u8.c_str(), stdout);
    fflush(stdout);
}

static std::wstring FmtW(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 1023, fmt, ap);
    buf[1023] = 0;
    va_end(ap);
    return buf;
}

static bool ReadFileBytes(const wchar_t* path, std::vector<uint8_t>* out) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    out->resize(static_cast<size_t>(sz.QuadPart));
    DWORD total = 0;
    while (total < out->size()) {
        DWORD got = 0;
        if (!ReadFile(h, out->data() + total, (DWORD)(out->size() - total), &got, nullptr) || !got) break;
        total += got;
    }
    CloseHandle(h);
    return total == out->size();
}

static bool MoveAndCheck(HWND wnd, int x, int y, int cx, int cy) {
    SetWindowPos(wnd, HWND_TOP, x, y, cx, cy, SWP_NOZORDER | SWP_NOACTIVATE);
    Sleep(350);
    RECT r{};
    if (!GetWindowRect(wnd, &r)) {
        Say(L"      GetWindowRect 失败\n");
        return false;
    }
    const bool ok = (r.left == x && r.top == y);
    Say(FmtW(L"      请求 (%d,%d) -> 实际 (%ld,%ld)  %s\n",
             x, y, r.left, r.top, ok ? L"✔" : L"✘ 被拉回去了").c_str());
    return ok;
}

int main() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc < 4) {
        Say(L"用法：test_winguard.exe <pid> <hwnd> <payload.dll>\n");
        return 2;
    }
    const DWORD pid = wcstoul(argv[1], nullptr, 10);
    const HWND wnd = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(wcstoull(argv[2], nullptr, 0)));
    const std::wstring dllPath = argv[3];
    LocalFree(argv);

    if (!IsWindow(wnd)) {
        Say(L"[FAIL] 目标窗口无效\n");
        return 3;
    }

    Say(L"[1] 注入前先确认：这个窗口确实会把位置钉回左上角\n");
    if (MoveAndCheck(wnd, 320, 240, 800, 600)) {
        Say(L"[FAIL] 宿主没有复现「钉回 (0,0)」，测试前提不成立\n");
        return 4;
    }

    std::vector<uint8_t> payload;
    if (!ReadFileBytes(dllPath.c_str(), &payload)) {
        Say(L"[FAIL] 读不到载荷\n");
        return 5;
    }

    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) {
        Say(FmtW(L"[FAIL] OpenProcess err=%lu\n", GetLastError()).c_str());
        return 6;
    }
    uint32_t base = 0;
    std::wstring err;
    const bool injected = ct::ReflectInject(h, payload, &base, &err);
    CloseHandle(h);
    Say(FmtW(L"[2] ReflectInject=%s base=0x%08X %s\n", injected ? L"成功" : L"失败", base,
             err.c_str()).c_str());
    if (!injected) return 7;

    // 等载荷建会话 + WinGuard_Tick 子类化（载荷里 400ms 一轮）
    int waited = 0;
    for (; waited < 40; ++waited) {
        uint32_t magic = 0;
        if (ct::PayloadSessionAlive(pid, &magic)) break;
        Sleep(100);
    }
    if (waited >= 40) {
        Say(L"[FAIL] 6 秒内没有会话\n");
        return 8;
    }
    Sleep(1200);

    Say(L"[3] 守卫装上后再试两次（含一次和上次完全不同的位置）\n");
    const bool ok1 = MoveAndCheck(wnd, 300, 200, 800, 600);
    const bool ok2 = MoveAndCheck(wnd, 520, 360, 760, 560);

    if (!ok1 || !ok2) {
        Say(L"FAIL —— 位置仍然被目标过程拉回\n");
        return 9;
    }
    Say(L"PASS —— 窗口停在你放的位置\n");
    return 0;
}
