/* =============================================================================
 *  lockhost.exe —— "已经被锁住"的宿主进程
 *
 *  模拟的是**后手启动**的场景：先有锁，再有 CloudTrainer。
 *  它加载同目录下的 HookLib.dll，起一条锁线程，然后什么都不做。
 * ========================================================================== */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    int noqueue = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--noqueue") == 0) noqueue = 1;
    }

    HMODULE h = LoadLibraryW(L"HookLib.dll");
    if (!h) {
        printf("LoadLibrary(HookLib.dll) failed err=%lu\n", GetLastError());
        return 2;
    }

    if (noqueue) {
        typedef int (*FnVoid)(void);
        FnVoid f = (FnVoid)(void*)GetProcAddress(h, "LockNoQueue");
        if (!f || !f()) {
            printf("LockNoQueue failed\n");
            return 3;
        }
    } else {
        typedef int (*FnInt)(int);
        FnInt f = (FnInt)(void*)GetProcAddress(h, "Lock");
        if (!f || !f(1)) {
            printf("Lock(1) failed\n");
            return 3;
        }
    }

    const DWORD pid = GetCurrentProcessId();
    FILE* fp = fopen("lockhost.pid", "wb");
    if (fp) {
        fprintf(fp, "%lu", pid);
        fclose(fp);
    }
    printf("lockhost pid=%lu noqueue=%d\n", pid, noqueue);
    fflush(stdout);

    for (;;) Sleep(500);
    return 0;
}
