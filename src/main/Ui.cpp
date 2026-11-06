// =============================================================================
//  CloudTrainer - Ui.cpp
//  ---------------------------------------------------------------------------
//  自绘 UI（GDI+）+ 托盘 + 远程命令裁决窗 + 假黑屏。
//
//  为什么自绘：原来的 STATIC/BUTTON 组合在 Win10 上就是 2005 年的观感。
//  GDI+ 是系统自带（gdiplus.dll，XP 起就有），静态链接进 exe，不引入任何外部
//  运行时；渐变、圆角、抗锯齿文字都能画，单文件属性不变。
//
//  为什么不用 Sciter：官方 FREE 档只允许**动态加载**它发布的 sciter.dll，
//  静态链接要 Indie 授权（$310/年）。原版 JiYuTrainer 也是 Release 里带一个
//  sciter.zip 运行时解压。那会让本工具从"单文件"变成"exe + 5MB dll"。
// =============================================================================
#include "Core.h"

#include <commctrl.h>
#include <shellapi.h>
#include <windowsx.h>

using namespace Gdiplus;

namespace ct {

Ui* Ui::s_self_ = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
//  运行期生成托盘图标（不依赖资源编译器）
// ─────────────────────────────────────────────────────────────────────────────
static HICON MakeIcon(int sz, bool alert) {
    if (sz < 8) sz = 16;

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = sz;
    bi.bmiHeader.biHeight = -sz;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HDC hdc = CreateCompatibleDC(nullptr);
    HBITMAP color = CreateDIBSection(hdc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!color || !bits) {
        if (color) DeleteObject(color);
        DeleteDC(hdc);
        return nullptr;
    }
    HGDIOBJ oldBmp = SelectObject(hdc, color);
    memset(bits, 0, (size_t)sz * sz * 4);
    SetBkMode(hdc, TRANSPARENT);

    const COLORREF bgCol = alert ? RGB(196, 58, 42) : RGB(28, 104, 208);
    const COLORREF scrCol = alert ? RGB(96, 22, 14) : RGB(16, 56, 112);

    HBRUSH bg = CreateSolidBrush(bgCol);
    HGDIOBJ oldBrush = SelectObject(hdc, bg);
    HPEN pen = CreatePen(PS_SOLID, 1, bgCol);
    HGDIOBJ oldPen = SelectObject(hdc, pen);
    RoundRect(hdc, 0, 0, sz, sz, sz / 3, sz / 3);

    const int m = sz / 5;
    HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
    HPEN wpen = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
    SelectObject(hdc, white);
    SelectObject(hdc, wpen);
    RoundRect(hdc, m, m, sz - m, sz - m * 2, sz / 8, sz / 8);
    RECT stand{ sz / 2 - sz / 12, sz - m * 2, sz / 2 + sz / 12, sz - m + sz / 16 };
    FillRect(hdc, &stand, white);

    HBRUSH inner = CreateSolidBrush(scrCol);
    RECT ir{ m + sz / 22, m + sz / 22, sz - m - sz / 22, sz - m * 2 - sz / 22 };
    FillRect(hdc, &ir, inner);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(bg);
    DeleteObject(pen);
    DeleteObject(white);
    DeleteObject(wpen);
    DeleteObject(inner);

    // GDI 不写 alpha：把非纯黑像素标成不透明
    auto* px = reinterpret_cast<uint8_t*>(bits);
    for (int i = 0; i < sz * sz; ++i) {
        if (px[i * 4] || px[i * 4 + 1] || px[i * 4 + 2]) px[i * 4 + 3] = 255;
    }

    HBITMAP mask = CreateBitmap(sz, sz, 1, 1, nullptr);
    ICONINFO ii{};
    ii.fIcon = TRUE;
    ii.hbmMask = mask;
    ii.hbmColor = color;
    HICON icon = CreateIconIndirect(&ii);

    SelectObject(hdc, oldBmp);
    DeleteObject(mask);
    DeleteObject(color);
    DeleteDC(hdc);
    return icon;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Ui 生命周期
// ─────────────────────────────────────────────────────────────────────────────
Ui* Ui::SelfFrom(HWND h) {
    (void)h;
    return s_self_;
}

bool Ui::Create(HWND msgWnd, HINSTANCE hInst) {
    (void)hInst;
    s_self_ = this;
    msgWnd_ = msgWnd;
    metrics_ = ui::DefaultMetrics();

    HDC screen = GetDC(nullptr);
    int dpi = GetDeviceCaps(screen, LOGPIXELSY);
    ReleaseDC(nullptr, screen);
    if (dpi <= 0) dpi = 96;
    scale_ = (float)dpi / 96.0f;

    iconNormal_ = MakeIcon(32, false);
    iconAlert_ = MakeIcon(32, true);
    iconSmall_ = MakeIcon(16, false);

    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = msgWnd_;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_CT_TRAY;
    nid.hIcon = iconNormal_;
    wcscpy(nid.szTip, L"CloudTrainer");
    trayAdded_ = Shell_NotifyIconW(NIM_ADD, &nid) != FALSE;
    if (trayAdded_) {
        nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid);
    }
    return trayAdded_;
}

void Ui::Destroy() {
    DestroyFakeBlack();

    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = msgWnd_;
    nid.uID = 1;
    if (trayAdded_) Shell_NotifyIconW(NIM_DELETE, &nid);

    if (statusWnd_) { DestroyWindow(statusWnd_); statusWnd_ = nullptr; }
    if (gateWnd_) { DestroyWindow(gateWnd_); gateWnd_ = nullptr; }

    ReleaseSurface();

    if (iconNormal_) DeleteObject(iconNormal_);
    if (iconAlert_) DeleteObject(iconAlert_);
    if (iconSmall_) DeleteObject(iconSmall_);
    s_self_ = nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
//  托盘 + 节拍
// ─────────────────────────────────────────────────────────────────────────────
void Ui::Update() {
    App& a = A();

    if (trayAdded_) {
        const bool alert = a.fixer.TrackedCount() > 0 || a.black.KillCount() > 0 ||
                           a.input.KeyboardLockPresent();
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = msgWnd_;
        nid.uID = 1;
        nid.uFlags = NIF_ICON | NIF_TIP;
        nid.hIcon = alert ? iconAlert_ : iconNormal_;
        std::wstring tip = Fmt(L"CloudTrainer · %s\n%s\n%s",
                               a.ver.Level() == EnvLevel::Unknown ? L"目标未识别"
                                                                  : EnvLevelName(a.ver.Level()),
                               a.inj.StatusText().c_str(),
                               a.input.StatusText().c_str());
        if (tip.size() > 120) tip = tip.substr(0, 120);
        wcsncpy(nid.szTip, tip.c_str(), 127);
        nid.szTip[127] = 0;
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }

    if (!statusWnd_ || !IsWindowVisible(statusWnd_)) return;

    BuildModel();

    std::wstring sig = model_.title + L"|" + model_.subtitle + L"|" + model_.meta1 + L"|" +
                       model_.meta2 + L"|" + std::to_wstring((int)model_.tone);
    for (int i = 0; i < model_.rowCount; ++i) {
        sig += model_.rows[i].state;
        sig += model_.rows[i].on ? L"1" : L"0";
        sig += model_.rows[i].warn ? L"!" : L".";
    }
    if (sig != sig_) {
        sig_ = sig;
        PaintStatus();
    }
}

void Ui::BuildModel() {
    App& a = A();
    ui::Model& m = model_;
    m.version = kAppVersion;
    m.hot = hot_;

    bool anyOn = false;
    for (int i = 0; i < CAP_COUNT; ++i) anyOn = anyOn || a.cfg.Cap(i);

    const EnvLevel lv = a.ver.Level();
    if (lv == EnvLevel::ReadOnly || lv == EnvLevel::Unknown) {
        m.tone = ui::Tone::Offline;
        m.title = L"未连接";
    } else if (!IsElevated()) {
        m.tone = ui::Tone::Degraded;
        m.title = L"权限不足";
    } else if (lv == EnvLevel::Degraded) {
        m.tone = ui::Tone::Degraded;
        m.title = L"降级运行";
    } else if (!anyOn) {
        m.tone = ui::Tone::Idle;
        m.title = L"待机";
    } else {
        m.tone = ui::Tone::Active;
        m.title = L"防护中";
    }

    std::wstring sub;
    if (a.fixer.TrackedCount() > 0) sub += L"广播已窗口化";
    if (a.input.KeyboardLockPresent()) {
        if (!sub.empty()) sub += L" · ";
        sub += L"键盘锁定中";
    } else {
        if (!sub.empty()) sub += L" · ";
        sub += L"键鼠已解除";
    }
    if (sub.empty()) sub = L"等待上课广播";
    m.subtitle = sub;

    m.meta1 = Fmt(L"注入 %d 个进程", (int)a.inj.SessionCount());

    auto stats = a.inj.Snapshot();
    LONG term = 0, close = 0, gated = 0, inproc = 0, dev = 0, denied = 0;
    for (auto& s : stats) {
        term += s.blockedTerm;
        close += s.blockedClose;
        gated += s.gated;
        inproc += s.inprocUnlocks;
        dev += s.devBlocked + s.ioctlBlocked;
        denied += s.deniedLaunch;
    }
    m.meta2 = Fmt(L"今日拦截 %ld 次", term + close);

    m.rowCount = CAP_COUNT;
    for (int i = 0; i < CAP_COUNT; ++i) {
        m.rows[i].name = CapName(i);
        m.rows[i].on = a.cfg.Cap(i);
        m.rows[i].warn = false;
        m.rows[i].icon = i;
    }

    m.rows[CAP_FIX_BROADCAST].state =
        a.fixer.TrackedCount() > 0 ? Fmt(L"已接管 %d 个窗口", a.fixer.TrackedCount()) : L"未发现广播";
    m.rows[CAP_KILL_BLACK].state = Fmt(L"已压制 %d 次", (int)a.black.KillCount());
    m.rows[CAP_UNLOCK_KEYBOARD].state = Fmt(L"已解除 %d 次", (int)a.input.KeyKills());
    m.rows[CAP_UNLOCK_MOUSE].state = Fmt(L"外部 %d / 进程内 %ld",
                                         (int)a.input.MouseUnlocks(), inproc);
    if (a.input.NeedInProc()) m.rows[CAP_UNLOCK_MOUSE].warn = true;
    {
        std::wstring last = a.inj.LastBlockedName();
        m.rows[CAP_BLOCK_TERMINATE].state = last.empty() ? Fmt(L"已拦 %ld 次", term)
                                                         : (L"最近 " + last);
    }
    m.rows[CAP_BLOCK_CLOSE].state = Fmt(L"已拦 %ld 次", close);
    if (GateVisible()) {
        m.rows[CAP_CMD_GATE].state = L"待裁决 1 条";
        m.rows[CAP_CMD_GATE].warn = true;
    } else {
        if (denied > 0 || dev > 0) {
            m.rows[CAP_CMD_GATE].state = Fmt(L"裁决 %ld / 设备拦截 %ld", gated, dev);
        } else {
            m.rows[CAP_CMD_GATE].state = Fmt(L"已裁决 %ld 次", gated);
        }
    }
}

void Ui::ShowMenu(POINT pt) {
    App& a = A();
    HMENU menu = CreatePopupMenu();

    std::wstring l1 = Fmt(L"目标：%s（%s）",
                          a.ver.Level() == EnvLevel::Unknown ? L"未识别" : EnvLevelName(a.ver.Level()),
                          a.loc.FirstPid(target::kProcStudent)
                              ? Fmt(L"Student.exe %lu", a.loc.FirstPid(target::kProcStudent)).c_str()
                              : L"未运行");
    AppendMenuW(menu, MF_STRING | MF_DISABLED, 0, l1.c_str());
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    // 救命项放最上面：被锁住时其它入口都可能点不到
    AppendMenuW(menu, MF_STRING, ID_TRAY_UNLOCK, L"立即解除控制（键鼠）");
    AppendMenuW(menu, MF_STRING, ID_TRAY_STATUS, L"显示状态窗口");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    for (int i = 0; i < CAP_COUNT; ++i) {
        UINT flags = MF_STRING | (a.cfg.Cap(i) ? MF_CHECKED : MF_UNCHECKED);
        AppendMenuW(menu, flags, ID_TOGGLE_BASE + i, CapName(i));
    }
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_RESTORE, L"全部还原");
    AppendMenuW(menu, MF_STRING, ID_TRAY_LOGDIR, L"打开日志目录");
    AppendMenuW(menu, MF_STRING, ID_TRAY_ABOUT, L"关于");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"退出");

    SetForegroundWindow(msgWnd_);
    TrackPopupMenuEx(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                     pt.x, pt.y, msgWnd_, nullptr);
    DestroyMenu(menu);
    PostMessageW(msgWnd_, WM_NULL, 0, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
//  状态窗口
// ─────────────────────────────────────────────────────────────────────────────
bool Ui::EnsureSurface(int w, int h) {
    if (mem_ && memW_ == w && memH_ == h) return true;
    ReleaseSurface();

    HDC screen = GetDC(nullptr);
    mem_ = CreateCompatibleDC(screen);
    ReleaseDC(nullptr, screen);
    if (!mem_) return false;

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;          // 自上而下
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    memBmp_ = CreateDIBSection(mem_, &bi, DIB_RGB_COLORS, &memBits_, nullptr, 0);
    if (!memBmp_ || !memBits_) {
        ReleaseSurface();
        return false;
    }
    SelectObject(mem_, memBmp_);
    memW_ = w;
    memH_ = h;
    return true;
}

void Ui::ReleaseSurface() {
    if (mem_) { DeleteDC(mem_); mem_ = nullptr; }
    if (memBmp_) { DeleteObject(memBmp_); memBmp_ = nullptr; }
    memBits_ = nullptr;
    memW_ = memH_ = 0;
}

// 分层窗口：整块 32bpp PARGB 画布 → UpdateLayeredWindow。
// 这样圆角是**每像素 alpha 抗锯齿**，不再靠 SetWindowRgn 做 1-bit 裁剪
// （region 的锯齿就是之前白边/毛边的来源）。
void Ui::PaintStatus() {
    if (!statusWnd_) return;

    const int cw = (int)(metrics_.w * scale_);
    const int ch = (int)(metrics_.h * scale_);
    const int m = margin_;
    const int w = cw + m * 2;
    const int hgt = ch + m * 2;
    if (!EnsureSurface(w, hgt)) return;

    memset(memBits_, 0, (size_t)w * hgt * 4);
    {
        Gdiplus::Bitmap bmp(w, hgt, w * 4, PixelFormat32bppPARGB,
                            reinterpret_cast<BYTE*>(memBits_));
        Gdiplus::Graphics g(&bmp);
        g.SetSmoothingMode(SmoothingModeAntiAlias);
        g.SetPixelOffsetMode(PixelOffsetModeNone);
        g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);

        ui::PaintShadow(g, Gdiplus::RectF((REAL)m, (REAL)m, (REAL)cw, (REAL)ch),
                        (REAL)(12 * scale_), (REAL)m);
        g.TranslateTransform((REAL)m, (REAL)m);
        ui::PaintWindow(g, model_, metrics_, scale_);
    }

    HDC screen = GetDC(nullptr);
    POINT src{ 0, 0 };
    SIZE size{ w, hgt };
    BLENDFUNCTION blend{ AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    UpdateLayeredWindow(statusWnd_, screen, nullptr, &size, mem_, &src, 0, &blend, ULW_ALPHA);
    ReleaseDC(nullptr, screen);
}

void Ui::CreateStatus() {
    if (statusWnd_) return;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = Ui::StatusProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    wc.lpszClassName = L"CtStatusWnd";
    RegisterClassExW(&wc);

    const int cw = (int)(metrics_.w * scale_);
    const int ch = (int)(metrics_.h * scale_);
    const int m = margin_;
    const int w = cw + m * 2;
    const int hgt = ch + m * 2;

    RECT wa{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    const int x = wa.right - w - (int)(24 * scale_);
    const int y = wa.bottom - hgt - (int)(24 * scale_);

    statusWnd_ = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_LAYERED, L"CtStatusWnd",
                                 L"CloudTrainer", WS_POPUP,
                                 x, y, w, hgt, nullptr, nullptr, wc.hInstance, nullptr);
    if (!statusWnd_) return;

    BuildModel();
    PaintStatus();          // 分层窗口必须先 UpdateLayeredWindow 才有内容
    ShowWindow(statusWnd_, SW_SHOWNA);
}

int Ui::HitTest(int x, int y) const {
    const float s = scale_;
    const int W = (int)(metrics_.w * s);
    const int pad = (int)(18 * s);

    const int bw = (int)(26 * s);
    const int closeX = W - pad - bw;
    const int minX = closeX - bw - (int)(6 * s);
    if (y < (int)(44 * s)) {
        if (x >= closeX && x < W - pad + 1) return ui::HIT_CLOSE;
        if (x >= minX && x < closeX) return ui::HIT_MIN;
        return ui::HIT_NONE;
    }

    const int heroB = (int)((44 + 132) * s);
    const int rowTop = heroB + (int)(12 * s);
    const int rowH = (int)(46 * s);
    if (y >= rowTop && y < rowTop + rowH * model_.rowCount) {
        const int i = (y - rowTop) / rowH;
        if (i >= 0 && i < model_.rowCount) return ui::HIT_ROW_BASE + i;
    }

    const int fy = (int)(metrics_.h * s) - (int)(58 * s);
    if (y >= fy) {
        if (x >= pad && x < pad + (int)(94 * s)) return ui::HIT_RESTORE;
        if (x >= pad + (int)(104 * s) && x < pad + (int)(150 * s)) return ui::HIT_LOG;
        if (x >= pad + (int)(154 * s) && x < pad + (int)(200 * s)) return ui::HIT_ABOUT;
    }
    return ui::HIT_NONE;
}

LRESULT CALLBACK Ui::StatusProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    Ui* ui = s_self_;
    if (!ui) return DefWindowProcW(h, m, w, l);

    switch (m) {
        case WM_NCCALCSIZE:
            if (w) return 0;      // 客户区 = 窗口矩形，系统边框不可见
            break;

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT: {
            // 分层窗口的内容由 UpdateLayeredWindow 直接提交，这里只需要把
            // 无效区域标记为已处理，否则会收到无穷无尽的 WM_PAINT。
            ValidateRect(h, nullptr);
            return 0;
        }

        case WM_MOUSEMOVE: {
            const int hit = ui->HitTest(GET_X_LPARAM(l), GET_Y_LPARAM(l));
            if (hit != ui->hot_) {
                ui->hot_ = hit;
                ui->model_.hot = hit;
                ui->PaintStatus();
            }
            TRACKMOUSEEVENT tme{};
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = h;
            TrackMouseEvent(&tme);
            return 0;
        }

        case WM_MOUSELEAVE:
            if (ui->hot_ != ui::HIT_NONE) {
                ui->hot_ = ui::HIT_NONE;
                ui->model_.hot = ui::HIT_NONE;
                ui->PaintStatus();
            }
            return 0;

        case WM_LBUTTONUP: {
            const int hit = ui->HitTest(GET_X_LPARAM(l), GET_Y_LPARAM(l));
            App& a = A();
            if (hit == ui::HIT_CLOSE) {
                a.RequestQuit();
            } else if (hit == ui::HIT_MIN) {
                ShowWindow(h, SW_MINIMIZE);
            } else if (hit >= ui::HIT_ROW_BASE && hit < ui::HIT_ROW_BASE + CAP_COUNT) {
                a.ToggleCap(hit - ui::HIT_ROW_BASE);
            } else if (hit == ui::HIT_RESTORE) {
                a.RestoreAll(false);
            } else if (hit == ui::HIT_LOG) {
                ShellExecuteW(nullptr, L"open", a.log.Dir().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            } else if (hit == ui::HIT_ABOUT) {
                a.OnCommand(ID_TRAY_ABOUT, 0);
            }
            return 0;
        }

        case WM_NCHITTEST: {
            POINT pt{ GET_X_LPARAM(l), GET_Y_LPARAM(l) };
            ScreenToClient(h, &pt);
            const int cx = pt.x - ui->margin_;
            const int cy = pt.y - ui->margin_;
            const int cw = (int)(ui->metrics_.w * ui->scale_);
            const int ch = (int)(ui->metrics_.h * ui->scale_);
            // 阴影区（内容矩形之外）不接鼠标，点击直接落到下面的窗口
            if (cx < 0 || cy < 0 || cx >= cw || cy >= ch) return HTTRANSPARENT;
            if (ui->HitTest(cx, cy) != ui::HIT_NONE) return HTCLIENT;
            if (cy < (int)(44 * ui->scale_)) return HTCAPTION;
            return HTCLIENT;
        }

        case WM_NCLBUTTONDBLCLK:
            return 0;   // 标题栏双击不要触发最大化

        case WM_KEYDOWN:
            if (w == VK_ESCAPE) ShowWindow(h, SW_HIDE);
            return 0;

        case WM_CLOSE:
            ShowWindow(h, SW_HIDE);   // 关闭 = 隐藏；退出走托盘
            return 0;

        case WM_DESTROY:
            ui->statusWnd_ = nullptr;
            return 0;

        default:
            break;
    }
    return DefWindowProcW(h, m, w, l);
}

void Ui::ToggleStatus() {
    if (statusWnd_ && IsWindowVisible(statusWnd_)) {
        ShowWindow(statusWnd_, SW_HIDE);
        return;
    }
    ShowStatus();
}

void Ui::ShowStatus() {
    CreateStatus();
    if (!statusWnd_) return;
    BuildModel();
    PaintStatus();
    ShowWindow(statusWnd_, SW_SHOW);
    SetForegroundWindow(statusWnd_);
}

// ─────────────────────────────────────────────────────────────────────────────
//  远程命令裁决窗
// ─────────────────────────────────────────────────────────────────────────────
void Ui::CreateGate() {
    if (gateWnd_) return;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = Ui::GateProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    wc.lpszClassName = L"CtGateWnd";
    RegisterClassExW(&wc);

    const int cw = (int)(460 * scale_);
    const int ch = (int)(286 * scale_);
    const int m = margin_;
    const int w = cw + m * 2;
    const int hgt = ch + m * 2;

    RECT wa{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    const int x = wa.left + ((wa.right - wa.left) - w) / 2;
    const int y = wa.top + ((wa.bottom - wa.top) - hgt) / 2;

    gateWnd_ = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_LAYERED,
                               L"CtGateWnd", L"远程命令", WS_POPUP,
                               x, y, w, hgt, nullptr, nullptr, wc.hInstance, nullptr);
    if (!gateWnd_) return;
}

void Ui::PaintGateSurface() {
    if (!gateWnd_) return;

    const int cw = (int)(460 * scale_);
    const int ch = (int)(286 * scale_);
    const int m = margin_;
    const int w = cw + m * 2;
    const int hgt = ch + m * 2;
    if (!EnsureSurface(w, hgt)) return;

    memset(memBits_, 0, (size_t)w * hgt * 4);
    {
        Gdiplus::Bitmap bmp(w, hgt, w * 4, PixelFormat32bppPARGB,
                            reinterpret_cast<BYTE*>(memBits_));
        Gdiplus::Graphics g(&bmp);
        g.SetSmoothingMode(SmoothingModeAntiAlias);
        g.SetPixelOffsetMode(PixelOffsetModeNone);
        g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);

        ui::PaintShadow(g, Gdiplus::RectF((REAL)m, (REAL)m, (REAL)cw, (REAL)ch),
                        (REAL)(12 * scale_), (REAL)m);
        g.TranslateTransform((REAL)m, (REAL)m);
        ui::PaintGate(g, gmodel_, 460, 286, scale_);
    }

    HDC screen = GetDC(nullptr);
    POINT src{ 0, 0 };
    SIZE size{ w, hgt };
    BLENDFUNCTION blend{ AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    UpdateLayeredWindow(gateWnd_, screen, nullptr, &size, mem_, &src, 0, &blend, ULW_ALPHA);
    ReleaseDC(nullptr, screen);
}

int Ui::GateHitTest(int x, int y) const {
    const float s = scale_;
    const int W = (int)(460 * s);
    const int H = (int)(286 * s);
    const int by = H - (int)(56 * s);
    const int bh = (int)(32 * s);
    if (y < by || y >= by + bh) return ui::HIT_NONE;

    const int bAllX = W - (int)(16 * s) - (int)(96 * s);
    const int bDenX = bAllX - (int)(8 * s) - (int)(76 * s);
    const int bAllowX = bDenX - (int)(8 * s) - (int)(96 * s);
    if (x >= bAllowX && x < bAllowX + (int)(96 * s)) return 4001;
    if (x >= bDenX && x < bDenX + (int)(76 * s)) return 4002;
    if (x >= bAllX && x < bAllX + (int)(96 * s)) return 4003;
    return ui::HIT_NONE;
}

LRESULT CALLBACK Ui::GateProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    Ui* ui = s_self_;
    if (!ui) return DefWindowProcW(h, m, w, l);

    switch (m) {
        case WM_NCCALCSIZE:
            if (w) return 0;
            break;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            ValidateRect(h, nullptr);
            return 0;
        case WM_MOUSEMOVE: {
            const int hit = ui->GateHitTest(GET_X_LPARAM(l), GET_Y_LPARAM(l));
            if (hit != ui->gateHot_) {
                ui->gateHot_ = hit;
                ui->gmodel_.hot = hit;
                ui->PaintGateSurface();
            }
            TRACKMOUSEEVENT tme{};
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = h;
            TrackMouseEvent(&tme);
            return 0;
        }
        case WM_MOUSELEAVE:
            ui->gateHot_ = ui::HIT_NONE;
            ui->gmodel_.hot = ui::HIT_NONE;
            ui->PaintGateSurface();
            return 0;
        case WM_LBUTTONUP: {
            const int hit = ui->GateHitTest(GET_X_LPARAM(l), GET_Y_LPARAM(l));
            if (hit == 4001) A().DecideGate(CT_CMD_ALLOW);
            else if (hit == 4002) A().DecideGate(CT_CMD_DENY);
            else if (hit == 4003) A().DecideGate(CT_CMD_ALLOWALL);
            return 0;
        }
        case WM_NCHITTEST: {
            POINT pt{ GET_X_LPARAM(l), GET_Y_LPARAM(l) };
            ScreenToClient(h, &pt);
            const int cx = pt.x - ui->margin_;
            const int cy = pt.y - ui->margin_;
            const int cw = (int)(460 * ui->scale_);
            const int ch = (int)(286 * ui->scale_);
            if (cx < 0 || cy < 0 || cx >= cw || cy >= ch) return HTTRANSPARENT;
            if (ui->GateHitTest(cx, cy) != ui::HIT_NONE) return HTCLIENT;
            if (cy < (int)(64 * ui->scale_)) return HTCAPTION;
            return HTCLIENT;
        }
        case WM_CLOSE:
            A().DecideGate(CT_CMD_DENY);
            return 0;
        case WM_DESTROY:
            ui->gateWnd_ = nullptr;
            return 0;
        default:
            break;
    }
    return DefWindowProcW(h, m, w, l);
}

void Ui::ShowGate(const CtPendingCmd& cmd, int index) {
    CreateGate();
    if (!gateWnd_) return;

    gateIndex_ = index;
    gateApp_ = cmd.app;
    gateCmd_ = cmd.cmd;
    gmodel_.app = gateApp_;
    gmodel_.cmd = gateCmd_;
    gmodel_.index = index;
    gmodel_.remainSec = A().cfg.cmdGateTimeout;
    gmodel_.hot = ui::HIT_NONE;
    gateHot_ = ui::HIT_NONE;
    gateTick_ = 0;

    PaintGateSurface();
    ShowWindow(gateWnd_, SW_SHOW);
    SetForegroundWindow(gateWnd_);
}

void Ui::UpdateGate() {
    if (!gateWnd_ || !IsWindowVisible(gateWnd_)) return;
    if (++gateTick_ >= 4) {          // 4 × 250ms = 1 秒
        gateTick_ = 0;
        if (gmodel_.remainSec > 0) --gmodel_.remainSec;
        PaintGateSurface();
    }
}

void Ui::HideGate() {
    if (gateWnd_) ShowWindow(gateWnd_, SW_HIDE);
    gateIndex_ = -1;
    gateHot_ = ui::HIT_NONE;
}

bool Ui::GateVisible() const {
    return gateWnd_ != nullptr && IsWindowVisible(gateWnd_) != FALSE;
}

// ─────────────────────────────────────────────────────────────────────────────
//  假黑屏（Ctrl+Alt+F）
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK Ui::BlackKeyboardHook(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && wp == WM_KEYDOWN) {
        auto* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        const bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        const bool alt = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
        if (kb->vkCode == 'F' && ctrl && alt) {
            return CallNextHookEx(nullptr, code, wp, lp);
        }
        return 1;   // 其它键全部吞掉
    }
    return CallNextHookEx(nullptr, code, wp, lp);
}

LRESULT CALLBACK Ui::BlackProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_ERASEBKGND: {
            HDC dc = (HDC)w;
            RECT rc{};
            GetClientRect(h, &rc);
            HBRUSH b = CreateSolidBrush(RGB(0, 0, 0));
            FillRect(dc, &rc, b);
            DeleteObject(b);
            return 1;
        }
        case WM_SETCURSOR:
            SetCursor(nullptr);
            return TRUE;
        case WM_LBUTTONDOWN:
        case WM_RBUTTONDOWN:
        case WM_KEYDOWN:
            return 0;
        default:
            break;
    }
    return DefWindowProcW(h, m, w, l);
}

void Ui::ShowFakeBlack(bool on) {
    if (!on) {
        DestroyFakeBlack();
        return;
    }
    if (fakeBlack_) return;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = Ui::BlackProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = nullptr;
    wc.lpszClassName = L"CtBlackWnd";
    RegisterClassExW(&wc);

    const int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    const int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    fakeBlack_ = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"CtBlackWnd", L"",
                                 WS_POPUP | WS_VISIBLE, vx, vy, vw, vh,
                                 nullptr, nullptr, wc.hInstance, nullptr);
    if (!fakeBlack_) return;
    ShowWindow(fakeBlack_, SW_SHOW);
    SetWindowPos(fakeBlack_, HWND_TOPMOST, vx, vy, vw, vh, SWP_SHOWWINDOW);
    SetForegroundWindow(fakeBlack_);

    kbHook_ = SetWindowsHookExW(WH_KEYBOARD_LL, Ui::BlackKeyboardHook,
                                GetModuleHandleW(nullptr), 0);
    A().log.Info(L"假黑屏已开启（Ctrl+Alt+F 退出）");
}

void Ui::DestroyFakeBlack() {
    if (kbHook_) {
        UnhookWindowsHookEx(kbHook_);
        kbHook_ = nullptr;
    }
    if (fakeBlack_) {
        DestroyWindow(fakeBlack_);
        fakeBlack_ = nullptr;
    }
}

} // namespace ct
