// =============================================================================
//  CloudTrainerPayload - winguard.cpp
//  ---------------------------------------------------------------------------
//  窗口守卫：注入到 MultiRender.exe 之后，对它的广播窗口做子类化。
//
//  为什么必须进到它进程里：
//    单纯从外部 SetWindowLong + SetWindowPos 只能改一次，目标进程下一帧就会
//    把状态抢回去。实测表现就是"窗口缩小了，但还是没有标题栏、还是置顶、
//    鼠标移上去光标还是消失"，因为这三件事都由它自己的 WndProc 决定：
//      * WM_NCCALCSIZE  -> 它把非客户区算成 0，所以 WS_CAPTION 画不出来
//      * WM_WINDOWPOSCHANGING -> 它每次移动都把 hwndInsertAfter 设回 HWND_TOPMOST
//      * WM_SETCURSOR / ShowCursor(0) -> 光标在它的窗口上被隐藏
//
//  子类化之后，这三个消息在到达它的 WndProc 之前就被我们改掉：
//      * WM_NCCALCSIZE        -> 交给 DefWindowProc 正常算，边框就回来了
//      * WM_MOVING / WM_WINDOWPOSCHANGING -> 先调它的过程，再把调用方要的位置
//        写回去（顺序很关键：先改后调会被它覆盖，表现为"拖动立刻弹回左上角"）
//      * WM_SETCURSOR         -> SetCursor(箭头) + 把本线程显示计数拉回 >= 0
//      * WM_STYLECHANGING     -> 强制补回 WS_CAPTION 等位
//
//  注意：ShowCursor 的显示计数是**按线程**的，所以必须在窗口所属线程执行
//  （下面的代码运行在 WndProc 上下文，正好是那个线程）。
// =============================================================================
#include "payload.h"

namespace ctpayload {
namespace {

constexpr int kMaxGuard = 8;

struct Entry {
    HWND    hwnd = nullptr;
    WNDPROC orig = nullptr;
    bool    ncForced = false;
    int     movesFixed = 0;   // 拦下"强制归位"的次数（诊断用）
};

Entry g_entries[kMaxGuard];
int   g_count = 0;
bool  g_inited = false;

Entry* Find(HWND h) {
    for (int i = 0; i < g_count; ++i) {
        if (g_entries[i].hwnd == h) return &g_entries[i];
    }
    return nullptr;
}

bool IsBroadcastWindow(HWND h) {
    wchar_t cls[128]{};
    if (!GetClassNameW(h, cls, 128)) return false;
    for (int i = 0; ct::target::kClsBroadcastAliases[i]; ++i) {
        if (_wcsicmp(cls, ct::target::kClsBroadcastAliases[i]) == 0) return true;
    }
    return false;
}

// 在窗口所属线程里把显示计数拉回 >= 0，同时不把正常状态改乱
void EnsureCursorOnThisThread() {
    int c = ShowCursor(TRUE);
    if (c > 0) ShowCursor(FALSE);   // 本来就是可见的，撤销这次 +1
}

LRESULT CALLBACK GuardProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    Entry* e = Find(h);
    WNDPROC orig = (e && e->orig) ? e->orig : DefWindowProcW;

    switch (msg) {
        case WM_NCCALCSIZE:
            // wParam=TRUE 时目标进程返回 0 把非客户区吃掉；这里强制走系统默认计算
            if (wp) {
                if (e && !e->ncForced) {
                    e->ncForced = true;
                    OutputDebugStringW(L"[CloudTrainer] 广播窗口的非客户区已被强制恢复\n");
                }
                return DefWindowProcW(h, msg, wp, lp);
            }
            break;

        case WM_SETCURSOR:
            EnsureCursorOnThisThread();
            SetCursor(LoadCursorW(nullptr, IDC_ARROW));
            return TRUE;

        // ── 位置：先记下"调用方请求的位置"，等它改完再把我们的值写回去 ──────
        //
        //  以前是"先改 WINDOWPOS，再 CallWindowProc"，我们的修改会被它自己的
        //  处理覆盖 —— 表现就是拖动时窗口立刻弹回左上角（它的 WndProc 把
        //  x/y 钉死成 0,0），置顶也怎么改都回弹。
        //
        //  现在不去猜它想干什么，只守住一条：**调用方要的位置就是最终位置**。
        //  它想在过程里把窗口拽回原点？改完我们照原样放回去。
        case WM_MOVING: {
            auto* rc = reinterpret_cast<RECT*>(lp);
            const RECT req = rc ? *rc : RECT{};
            LRESULT r = CallWindowProcW(orig, h, msg, wp, lp);
            if (rc) *rc = req;      // 拖动位置以系统提的那份为准
            return r;
        }

        case WM_WINDOWPOSCHANGING: {
            auto* pos = reinterpret_cast<WINDOWPOS*>(lp);
            const bool moves = pos && (pos->flags & SWP_NOMOVE) == 0;
            const int reqX = pos ? pos->x : 0;
            const int reqY = pos ? pos->y : 0;

            LRESULT r = CallWindowProcW(orig, h, msg, wp, lp);

            if (pos) {
                if (pos->hwndInsertAfter == HWND_TOPMOST) pos->hwndInsertAfter = HWND_NOTOPMOST;
                if (moves && (pos->x != reqX || pos->y != reqY)) {
                    pos->x = reqX;
                    pos->y = reqY;
                    if (e) ++e->movesFixed;
                }
            }
            return r;
        }

        case WM_STYLECHANGING: {
            auto* st = reinterpret_cast<STYLESTRUCT*>(lp);
            if (st && wp == GWL_STYLE) {
                st->styleNew &= ~(DWORD)WS_POPUP;
                st->styleNew |= WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX;
            }
            break;
        }

        case WM_NCDESTROY:
            if (e) e->hwnd = nullptr;   // 留个空位，别再去 CallWindowProc
            break;

        default:
            break;
    }
    return CallWindowProcW(orig, h, msg, wp, lp);
}

BOOL CALLBACK EnumProc(HWND h, LPARAM) {
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    if (!IsBroadcastWindow(h)) return TRUE;
    if (Find(h)) return TRUE;
    if (g_count >= kMaxGuard) return FALSE;

    WNDPROC orig = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(h, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(GuardProc)));
    if (!orig || orig == GuardProc) return TRUE;

    g_entries[g_count] = Entry{};
    g_entries[g_count].hwnd = h;
    g_entries[g_count].orig = orig;
    ++g_count;
    OutputDebugStringW(L"[CloudTrainer] 已接管广播窗口\n");
    return TRUE;
}

} // namespace

void WinGuard_Tick() {
    if (!g_inited) {
        g_inited = true;
    }
    // 清掉已经销毁的
    for (int i = 0; i < g_count;) {
        if (!g_entries[i].hwnd || !IsWindow(g_entries[i].hwnd)) {
            for (int k = i; k + 1 < g_count; ++k) g_entries[k] = g_entries[k + 1];
            --g_count;
        } else {
            ++i;
        }
    }
    if (g_count >= kMaxGuard) return;
    EnumWindows(&EnumProc, 0);
}

void WinGuard_Remove() {
    for (int i = 0; i < g_count; ++i) {
        HWND h = g_entries[i].hwnd;
        if (h && IsWindow(h) && g_entries[i].orig) {
            SetWindowLongPtrW(h, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(g_entries[i].orig));
            // 把窗口还原成全屏（不再干预）
            HMONITOR mon = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
            MONITORINFO mi{};
            mi.cbSize = sizeof(mi);
            if (GetMonitorInfoW(mon, &mi)) {
                LONG st = GetWindowLongW(h, GWL_STYLE);
                st &= ~(WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX);
                st |= WS_POPUP;
                SetWindowLongW(h, GWL_STYLE, st);
                SetWindowPos(h, HWND_TOPMOST, mi.rcMonitor.left, mi.rcMonitor.top,
                             mi.rcMonitor.right - mi.rcMonitor.left,
                             mi.rcMonitor.bottom - mi.rcMonitor.top,
                             SWP_FRAMECHANGED | SWP_SHOWWINDOW | SWP_NOACTIVATE);
            }
        }
        g_entries[i].hwnd = nullptr;
        g_entries[i].orig = nullptr;
    }
    g_count = 0;
}

} // namespace ctpayload
