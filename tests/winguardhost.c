/* =============================================================================
 *  winguardhost.exe —— "会把窗口钉回左上角"的假广播窗口
 *
 *  仿的是 MultiRender.exe 的窗口过程：
 *    * 类名 MultiRenderWindowClass（和真品一样，winguard 靠类名识别）；
 *    * WM_NCCALCSIZE 返回 0 —— 把非客户区吃掉，所以看起来无边框；
 *    * WM_MOVING / WM_WINDOWPOSCHANGING 把位置钉回 (0,0) ——
 *      这就是"能拖，但一拖就弹回左上角"的成因。
 *
 *  这个程序与电子教室无关，只是同名空壳，用来验证窗口守卫能不能顶住。
 * ========================================================================== */
#include <windows.h>
#include <stdio.h>

static LRESULT CALLBACK ClampProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_NCCALCSIZE:
            if (w) return 0;               /* 吃掉非客户区（仿 MultiRender） */
            break;

        case WM_MOVING: {                   /* 拖动位置钉回左上角 */
            RECT* rc = (RECT*)l;
            if (rc) {
                const LONG w2 = rc->right - rc->left;
                const LONG h2 = rc->bottom - rc->top;
                rc->left = 0;
                rc->top = 0;
                rc->right = w2;
                rc->bottom = h2;
            }
            return FALSE;
        }

        case WM_WINDOWPOSCHANGING: {        /* 任何移动都改回 (0,0) */
            WINDOWPOS* pos = (WINDOWPOS*)l;
            if (pos && !(pos->flags & SWP_NOMOVE)) {
                pos->x = 0;
                pos->y = 0;
            }
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            break;
    }
    return DefWindowProcW(h, m, w, l);
}

int main(void) {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = ClampProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"MultiRenderWindowClass";
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));   /* IDC_ARROW */
    if (!RegisterClassExW(&wc)) {
        printf("RegisterClassExW failed err=%lu\n", GetLastError());
        return 2;
    }

    HWND h = CreateWindowExW(0, wc.lpszClassName, L"fake broadcast",
                             WS_POPUP | WS_CAPTION | WS_THICKFRAME,
                             100, 100, 800, 600, NULL, NULL, wc.hInstance, NULL);
    if (!h) {
        printf("CreateWindowExW failed err=%lu\n", GetLastError());
        return 3;
    }
    ShowWindow(h, SW_SHOW);
    UpdateWindow(h);

    FILE* f = fopen("winguard.pid", "wb");
    if (f) {
        fprintf(f, "%lu %lu", GetCurrentProcessId(),
                (unsigned long)(ULONG_PTR)h);
        fclose(f);
    }
    printf("winguardhost pid=%lu hwnd=0x%lX\n", GetCurrentProcessId(),
           (unsigned long)(ULONG_PTR)h);
    fflush(stdout);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
