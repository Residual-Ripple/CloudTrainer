// =============================================================================
//  test_inject —— 反射注入的端到端测试（只针对 tests/host.exe）
//  用法：test_inject.exe <pid> <payload.dll>
//  判据：ReflectInject 返回成功，且目标进程里出现了 CloudTrainer 的共享内存会话。
// =============================================================================
#include "../src/main/Reflect.h"
#include "../src/common/CtIpc.h"

#include <stdio.h>
#include <string>
#include <vector>

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

int main() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc < 3) {
        Say(L"用法：test_inject.exe <pid> <payload.dll>\n");
        return 2;
    }
    const DWORD pid = wcstoul(argv[1], nullptr, 10);
    std::wstring dllPath = argv[2];
    LocalFree(argv);

    std::vector<uint8_t> payload;
    if (!ReadFileBytes(dllPath.c_str(), &payload)) {
        Say(L"[FAIL] 读不到载荷文件\n");
        return 3;
    }
    Say(FmtW(L"[1] 载荷 %u 字节：%s\n", (unsigned)payload.size(), dllPath.c_str()).c_str());

    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) {
        Say(FmtW(L"[FAIL] OpenProcess(pid=%lu) err=%lu\n", pid, GetLastError()).c_str());
        return 4;
    }

    uint32_t base = 0;
    std::wstring err;
    const bool ok = ct::ReflectInject(h, payload, &base, &err);
    CloseHandle(h);
    Say(FmtW(L"[2] ReflectInject = %s，base=0x%08X %s\n", ok ? L"成功" : L"失败", base,
             err.empty() ? L"" : err.c_str()).c_str());
    if (!ok) return 5;

    for (int i = 0; i < 60; ++i) {
        uint32_t magic = 0;
        if (ct::PayloadSessionAlive(pid, &magic)) {
            Say(FmtW(L"[3] 目标进程内已出现共享内存会话（magic=0x%08X），载荷线程在跑\n", magic).c_str());
            break;
        }
        if (i == 59) {
            Say(L"[FAIL] 注入返回成功，但 6 秒内没有等到 SharedMemory 会话\n");
            return 6;
        }
        Sleep(100);
    }

    // [4] 走一遍"全部还原"的卸载路径：请求载荷退出，确认目标进程还活着
    wchar_t shmName[128]{};
    _snwprintf(shmName, 127, CT_SHM_NAME_FMT, pid);
    HANDLE map = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, shmName);
    if (!map) {
        Say(L"[FAIL] 打不开共享内存（没有写权限？）\n");
        return 7;
    }
    auto* shm = reinterpret_cast<CtShared*>(MapViewOfFile(map, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                                          sizeof(CtShared)));
    if (!shm) {
        CloseHandle(map);
        Say(L"[FAIL] MapViewOfFile 失败\n");
        return 8;
    }

    // 下发一次策略，验证 req -> rep 的链路（这里没有 HookLib，补丁数应为 0）
    shm->req.wantTerminateGuard = 1;
    shm->req.wantCloseGuard = 1;
    shm->req.wantCmdGate = 1;
    InterlockedIncrement(&shm->req.seqPolicy);
    Sleep(300);
    Say(FmtW(L"[4] 策略下发后：flags=0x%08X 补丁数=%ld hookLib=%ld 闸门调用=%ld\n",
             shm->rep.flags, shm->rep.patchCount, shm->rep.hookLibFound,
             shm->rep.gateCalls).c_str());

    // [5] 触发宿主调用 CreateProcessW，验证 IAT hook + 命令闸门
    ULONGLONG now = GetTickCount64();
    shm->req.mainAliveLo = (LONG)(uint32_t)now;
    shm->req.mainAliveHi = (LONG)(uint32_t)(now >> 32);
    shm->req.cmdGateTimeoutMs = 20000;
    InterlockedIncrement(&shm->req.seqPolicy);
    Sleep(600);   // 等载荷把补丁打上

    // 宿主每 400ms 尝试一次；命中的那次会阻塞在 hook 里等我们裁决
    bool sawPending = false;
    for (int i = 0; i < 30 && !sawPending; ++i) {
        for (int k = 0; k < CT_MAX_PENDING; ++k) {
            if (shm->pending[k].state == CT_CMD_PENDING) {
                Say(FmtW(L"[5] 拦到一条命令：app=\"%s\" cmd=\"%s\"\n",
                         shm->pending[k].app, shm->pending[k].cmd).c_str());
                shm->pending[k].decisionPid = (LONG)GetCurrentProcessId();
                InterlockedExchange(&shm->pending[k].state, CT_CMD_DENY);
                sawPending = true;
                break;
            }
        }
        if (!sawPending) Sleep(100);
    }
    if (!sawPending) {
        LONG g1 = shm->rep.gateCalls;
        Sleep(1200);
        LONG g2 = shm->rep.gateCalls;
        HANDLE hh = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        DWORD hc = 0;
        bool alive = hh && GetExitCodeProcess(hh, &hc) && hc == STILL_ACTIVE;
        if (hh) CloseHandle(hh);
        Say(FmtW(L"     诊断：闸门调用 %ld -> %ld  补丁=%ld  wantCmdGate=%ld  mainAlive=%ld  now=%llu  宿主=%s\n",
                 g1, g2, shm->rep.patchCount, shm->req.wantCmdGate, shm->req.mainAliveLo,
                 (unsigned long long)GetTickCount64(), alive ? L"存活" : L"已退出").c_str());
        Say(FmtW(L"     槽位状态：%ld %ld %ld %ld\n",
                 shm->pending[0].state, shm->pending[1].state,
                 shm->pending[2].state, shm->pending[3].state).c_str());
        Say(L"[FAIL] 3 秒内没有拦到任何命令（IAT hook 没生效？）\n");
        return 10;
    }

    // 宿主的调用应当返回 FALSE / ERROR_ACCESS_DENIED(5)
    bool denied = false;
    for (int i = 0; i < 40; ++i) {
        FILE* rf = _wfopen(L"cp1.txt", L"rb");
        if (rf) {
            int okFlag = -1;
            unsigned long err = 0;
            if (fscanf(rf, "%d %lu", &okFlag, &err) == 2) {
                if (okFlag == 0 && err == 5) denied = true;
            }
            fclose(rf);
        }
        if (denied) break;
        Sleep(100);
    }
    Say(FmtW(L"[6] 随机路径：%s\n", denied ? L"被闸门拒绝（ERROR_ACCESS_DENIED）✔"
                                            : L"没有被拒绝 ✘").c_str());
    if (!denied) return 11;

    // 厂商白名单必须放行，否则会把产品自己搞坏
    bool vendorAllowed = false;
    for (int i = 0; i < 40; ++i) {
        FILE* rf = _wfopen(L"cp2.txt", L"rb");
        if (rf) {
            int okFlag = -1;
            unsigned long err = 0;
            if (fscanf(rf, "%d %lu", &okFlag, &err) == 2) {
                // 2=FILE_NOT_FOUND / 3=PATH_NOT_FOUND 都说明闸门放行了（不是 5=ACCESS_DENIED）
                if (okFlag == 0 && (err == 2 || err == 3)) vendorAllowed = true;
            }
            fclose(rf);
        }
        if (vendorAllowed) break;
        Sleep(100);
    }
    Say(FmtW(L"[7] 厂商白名单（BlackSlient.exe）：%s\n",
             vendorAllowed ? L"放行 ✔" : L"被误拦 ✘").c_str());
    if (!vendorAllowed) return 12;

    InterlockedIncrement(&shm->req.seqShutdown);
    bool exited = false;
    for (int i = 0; i < 40; ++i) {
        if (shm->rep.alive == 0) { exited = true; break; }
        Sleep(100);
    }
    UnmapViewOfFile(shm);
    CloseHandle(map);

    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    DWORD code = 0;
    bool hostAlive = ph && GetExitCodeProcess(ph, &code) && code == STILL_ACTIVE;
    if (ph) CloseHandle(ph);

    Say(FmtW(L"[8] 卸载请求：载荷%s，目标进程%s\n",
             exited ? L"已退出" : L"未退出", hostAlive ? L"存活" : L"已消失").c_str());

    if (!exited || !hostAlive) {
        Say(L"FAIL —— 卸载路径有问题\n");
        return 9;
    }
    Say(L"PASS\n");
    return 0;
}
