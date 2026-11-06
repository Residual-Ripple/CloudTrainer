/* =============================================================================
 *  测试替身：HookLib.dll 的最小仿制品
 *
 *  它只做真品在"锁鼠标"时最关键的举两件事：
 *    1. 导出 Lock(int)，Lock(1) 起一条线程；
 *    2. 那条线程跑 GetMessage 循环（真品就是这样等 WM_QUIT 的）。
 *
 *  这不是电子教室的任何文件，只是同名的空壳，用于验证 CloudTrainer 的
 *  "外部解锁"能不能真的定位并退出这条线程。
 * ========================================================================== */
#include <windows.h>

static HANDLE g_thread = NULL;
static DWORD  g_tid = 0;
static volatile LONG g_stop = 0;

/* 有消息队列：和真品一致 */
static DWORD WINAPI LockThread(LPVOID p) {
    (void)p;
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

/* 没有消息队列：用来验证"投递失败会被如实报告"，而不是假装成功 */
static DWORD WINAPI BusyThread(LPVOID p) {
    (void)p;
    while (!g_stop) Sleep(30);
    return 0;
}

__declspec(dllexport) int Lock(int on) {
    if (!on) return 0;              /* 和真品一样：Lock(0) 是空操作 */
    if (g_thread) return 0;
    g_thread = CreateThread(NULL, 0, LockThread, NULL, 0, &g_tid);
    return g_thread ? 1 : 0;
}

__declspec(dllexport) int LockNoQueue(void) {
    if (g_thread) return 0;
    g_thread = CreateThread(NULL, 0, BusyThread, NULL, 0, &g_tid);
    return g_thread ? 1 : 0;
}

__declspec(dllexport) DWORD LockTid(void) { return g_tid; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)h; (void)reason; (void)reserved;
    return TRUE;
}
