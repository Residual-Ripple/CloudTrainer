/* 测试宿主：模拟"厂商进程"的一个最小替身。
 *
 * 每 400ms 做两次 CreateProcessW：
 *   1. 一个绝不存在的随机路径      —— 期望被命令闸门拒绝（GetLastError = 5）
 *   2. 厂商白名单里的名字（不存在）—— 期望放行（GetLastError = 2，文件不存在）
 * 两个都不含真实可执行文件，所以**不会真的启动任何东西**。
 *
 * 另外 --occupy 会先占住 0x10000000（载荷的首选基址），
 * 强制注入器走重定位路径 —— 真实环境里这个地址被 HookLib.dll 占着。
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static void TrySpawn(const wchar_t* target, const char* outfile) {
    wchar_t cmd[512];
    lstrcpynW(cmd, target, 511);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    SetLastError(0xDEADBEEF);
    BOOL ok = CreateProcessW(cmd, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    DWORD err = GetLastError();
    if (ok) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    static int lastOk[2] = { -1, -1 };
    static DWORD lastErr[2] = { 0xFFFFFFFF, 0xFFFFFFFF };
    int slot = (outfile[2] == '2') ? 1 : 0;
    if (ok != lastOk[slot] || err != lastErr[slot]) {
        lastOk[slot] = ok;
        lastErr[slot] = err;
        FILE* f = fopen(outfile, "wb");
        if (f) {
            fprintf(f, "%d %lu", ok ? 1 : 0, err);
            fclose(f);
        }
    }
}

int main(int argc, char** argv) {
    int occupy = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--occupy") == 0) occupy = 1;
    }
    if (occupy) {
        VirtualAlloc((void*)0x10000000, 0x800000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    DWORD pid = GetCurrentProcessId();
    FILE* f = fopen("host.pid", "wb");
    if (f) { fprintf(f, "%lu", pid); fclose(f); }

    for (;;) {
        TrySpawn(L"C:\\definitely_not_exist_ct_test.exe", "cp1.txt");
        TrySpawn(L"C:\\no_such_dir_ct\\BlackSlient.exe", "cp2.txt");
        Sleep(400);
    }
    return 0;
}
