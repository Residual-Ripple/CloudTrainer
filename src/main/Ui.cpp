// =============================================================================
//  CloudTrainer - Ui.cpp
//  ---------------------------------------------------------------------------
//  原生 Win32：托盘图标 + 状态窗 + 远程命令裁决窗 + 假黑屏。
//  不用 Sciter（5.x 已转商用授权），不用 MFC/Qt。
//  图标在运行期用 GDI 画出来，避免依赖资源编译器。
// =============================================================================
#include "Core.h"

#include <commctrl.h>

namespace ct {

Ui* Ui::s_self_ = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
//  运行期生成图标
// ─────────────────────────────────────────────────────────────────────────────
static HICON MakeIcon(int sz, bool alert) {
    if (sz < 8) sz = 16;

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = sz;
    bi.bmiHeader.biHeight = -sz;      // 负数 = 自上而下
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

    // 显示器外框
    const int m = sz / 5;
    HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
    HPEN wpen = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
    SelectObject(hdc, white);
    SelectObject(hdc, wpen);
    RoundRect(hdc, m, m, sz - m, sz - m * 2, sz / 8, sz / 8);
    RECT stand{ sz / 2 - sz / 12, sz - m * 2, sz / 2 + sz / 12, sz - m + sz / 16 };
    FillRect(hdc, &stand, white);

    // 屏幕内芯
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
bool Ui::Create(HWND msgWnd, HINSTANCE hInst) {
    s_self_ = this;
    msgWnd_ = msgWnd;

    HDC screen = GetDC(nullptr);
    int dpi = GetDeviceCaps(screen, LOGPIXELSY);
    ReleaseDC(nullptr, screen);
    if (dpi <= 0) dpi = 96;

    LOGFONTW lf{};
    lf.lfHeight = -MulDiv(9, dpi, 72);
    lf.lfWeight = FW_NORMAL;
    lf.lfCharSet = DEFAULT_CHARSET;
    wcscpy(lf.lfFaceName, L"Microsoft YaHei UI");
    fontUi_ = CreateFontIndirectW(&lf);

    lf.lfHeight = -MulDiv(9, dpi, 72);
    wcscpy(lf.lfFaceName, L"Consolas");
    fontMono_ = CreateFontIndirectW(&lf);

    lf.lfHeight = -MulDiv(11, dpi, 72);
    lf.lfWeight = FW_BOLD;
    wcscpy(lf.lfFaceName, L"Microsoft YaHei UI");
    fontBold_ = CreateFontIndirectW(&lf);

    brushBg_ = CreateSolidBrush(RGB(250, 250, 252));

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

    if (iconNormal_) DeleteObject(iconNormal_);
    if (iconAlert_) DeleteObject(iconAlert_);
    if (iconSmall_) DeleteObject(iconSmall_);
    if (fontUi_) DeleteObject(fontUi_);
    if (fontMono_) DeleteObject(fontMono_);
    if (fontBold_) DeleteObject(fontBold_);
    if (brushBg_) DeleteObject(brushBg_);
    s_self_ = nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
//  托盘
// ─────────────────────────────────────────────────────────────────────────────
void Ui::Update() {
    if (!trayAdded_) return;

    App& a = A();
    bool alert = a.fixer.TrackedCount() > 0 || a.black.KillCount() > 0 ||
                 a.input.KeyboardLockPresent();
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = msgWnd_;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_TIP;
    nid.hIcon = alert ? iconAlert_ : iconNormal_;
    std::wstring tip = Fmt(L"CloudTrainer · %s\n%s\n%s",
                           a.ver.Level() == EnvLevel::Unknown ? L"目标未识别" : EnvLevelName(a.ver.Level()),
                           a.inj.StatusText().c_str(),
                           a.input.StatusText().c_str());
    if (tip.size() > 120) tip = tip.substr(0, 120);
    wcsncpy(nid.szTip, tip.c_str(), 127);
    nid.szTip[127] = 0;
    Shell_NotifyIconW(NIM_MODIFY, &nid);

    // 状态窗 1 秒刷一次就够：每 250ms 重刷会让编辑框一直闪
    if (statusWnd_ && IsWindowVisible(statusWnd_) && (++updateTick_ % 4) == 0) RefreshStatus();
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
    std::wstring l2 = Fmt(L"注入：%s", a.inj.StatusText().c_str());
    AppendMenuW(menu, MF_STRING | MF_DISABLED, 0, l2.c_str());
    std::wstring l3 = Fmt(L"广播：%s", a.fixer.StatusText().c_str());
    AppendMenuW(menu, MF_STRING | MF_DISABLED, 0, l3.c_str());
    std::wstring l4 = Fmt(L"键鼠：%s", a.input.StatusText().c_str());
    AppendMenuW(menu, MF_STRING | MF_DISABLED, 0, l4.c_str());
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    for (int i = 0; i < CAP_COUNT; ++i) {
        UINT flags = MF_STRING | (a.cfg.Cap(i) ? MF_CHECKED : MF_UNCHECKED);
        AppendMenuW(menu, flags, ID_TOGGLE_BASE + i, CapName(i));
    }
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_STATUS, L"显示状态窗口");
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
static void SetFont(HWND h, HFONT f) { SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE); }

LRESULT CALLBACK Ui::StatusProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    Ui* ui = s_self_;
    switch (m) {
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)w;
            HWND ctl = (HWND)l;
            if (ui) {
                for (int i = 0; i < CAP_COUNT; ++i) {
                    if (ctl == ui->rowState_[i]) {
                        SetTextColor(dc, RGB(60, 60, 60));
                        SetBkColor(dc, RGB(250, 250, 252));
                        return (LRESULT)ui->brushBg_;
                    }
                }
                SetBkColor(dc, RGB(250, 250, 252));
            }
            return (LRESULT)(ui ? ui->brushBg_ : nullptr);
        }
        case WM_ERASEBKGND: {
            HDC dc = (HDC)w;
            RECT rc{};
            GetClientRect(h, &rc);
            if (ui && ui->brushBg_) FillRect(dc, &rc, ui->brushBg_);
            return 1;
        }
        case WM_SIZE:
            if (ui) ui->LayoutStatus();
            return 0;
        case WM_TIMER:
            if (ui && w == 1) ui->RefreshStatus();
            return 0;
        case WM_COMMAND:
            A().OnCommand(LOWORD(w), HIWORD(w));
            return 0;
        case WM_CLOSE:
            ShowWindow(h, SW_HIDE);
            if (ui) ui->statusVisible_ = false;
            return 0;
        default:
            break;
    }
    return DefWindowProcW(h, m, w, l);
}

void Ui::CreateStatus() {
    if (statusWnd_) return;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = Ui::StatusProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"CtStatusWnd";
    wc.hIcon = iconNormal_;
    RegisterClassExW(&wc);

    statusWnd_ = CreateWindowExW(0, L"CtStatusWnd", L"CloudTrainer 状态",
                                 WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
                                     WS_SIZEBOX,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 620, 640,
                                 nullptr, nullptr, wc.hInstance, nullptr);
    if (!statusWnd_) return;

    hdr_ = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                           0, 0, 10, 10, statusWnd_, nullptr, wc.hInstance, nullptr);
    SetFont(hdr_, fontBold_);

    for (int i = 0; i < CAP_COUNT; ++i) {
        rowEnable_[i] = CreateWindowExW(0, L"BUTTON", CapName(i),
                                        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                        0, 0, 10, 10, statusWnd_,
                                        (HMENU)(INT_PTR)(ID_TOGGLE_BASE + i), wc.hInstance, nullptr);
        SetFont(rowEnable_[i], fontUi_);
        std::wstring d = Fmt(L"%s", CapDesc(i));
        rowState_[i] = CreateWindowExW(0, L"STATIC", d.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                       0, 0, 10, 10, statusWnd_, nullptr, wc.hInstance, nullptr);
        SetFont(rowState_[i], fontUi_);
    }

    logBox_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                              WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                  ES_READONLY | ES_AUTOVSCROLL,
                              0, 0, 10, 10, statusWnd_, nullptr, wc.hInstance, nullptr);
    SetFont(logBox_, fontMono_);

    btnRestore_ = CreateWindowExW(0, L"BUTTON", L"全部还原", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  0, 0, 10, 10, statusWnd_, (HMENU)(INT_PTR)ID_BTN_RESTORE,
                                  wc.hInstance, nullptr);
    btnLog_ = CreateWindowExW(0, L"BUTTON", L"打开日志", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              0, 0, 10, 10, statusWnd_, (HMENU)(INT_PTR)ID_BTN_LOGDIR,
                              wc.hInstance, nullptr);
    btnAbout_ = CreateWindowExW(0, L"BUTTON", L"关于", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                0, 0, 10, 10, statusWnd_, (HMENU)(INT_PTR)ID_BTN_ABOUT,
                                wc.hInstance, nullptr);
    SetFont(btnRestore_, fontUi_);
    SetFont(btnLog_, fontUi_);
    SetFont(btnAbout_, fontUi_);

    SetTimer(statusWnd_, 1, 500, nullptr);
    LayoutStatus();
}

void Ui::LayoutStatus() {
    if (!statusWnd_) return;
    RECT rc{};
    GetClientRect(statusWnd_, &rc);
    const int pad = 16;
    const int rowH = 30;
    int y = pad;

    MoveWindow(hdr_, pad, y, rc.right - pad * 2, 58, TRUE);
    y += 66;

    for (int i = 0; i < CAP_COUNT; ++i) {
        MoveWindow(rowEnable_[i], pad, y, 150, 22, TRUE);
        MoveWindow(rowState_[i], pad + 158, y + 2, rc.right - pad * 2 - 158, 40, TRUE);
        y += rowH + 12;
    }

    y += 4;
    const int btnH = 30;
    int bw = 100;
    MoveWindow(btnRestore_, pad, rc.bottom - pad - btnH, bw, btnH, TRUE);
    MoveWindow(btnLog_, pad + bw + 8, rc.bottom - pad - btnH, bw, btnH, TRUE);
    MoveWindow(btnAbout_, pad + (bw + 8) * 2, rc.bottom - pad - btnH, bw, btnH, TRUE);

    int logTop = y;
    int logBottom = rc.bottom - pad - btnH - 12;
    if (logBottom < logTop + 60) logBottom = logTop + 60;
    MoveWindow(logBox_, pad, logTop, rc.right - pad * 2, logBottom - logTop, TRUE);
}

void Ui::RefreshStatus() {
    if (!statusWnd_) return;
    App& a = A();

    std::wstring head = Fmt(L"目标：%s　｜　%s\r\n%s",
                            a.ver.Level() == EnvLevel::Unknown ? L"未识别" : EnvLevelName(a.ver.Level()),
                            a.inj.StatusText().c_str(), a.ver.Detail().c_str());
    SetWindowTextW(hdr_, head.c_str());

    for (int i = 0; i < CAP_COUNT; ++i) {
        SendMessageW(rowEnable_[i], BM_SETCHECK, a.cfg.Cap(i) ? BST_CHECKED : BST_UNCHECKED, 0);
    }

    auto setRow = [&](int idx, const std::wstring& text) {
        SetWindowTextW(rowState_[idx], text.c_str());
    };

    setRow(CAP_FIX_BROADCAST, Fmt(L"%s　%s", CapDesc(CAP_FIX_BROADCAST), a.fixer.StatusText().c_str()));
    setRow(CAP_KILL_BLACK, Fmt(L"%s　%s", CapDesc(CAP_KILL_BLACK), a.black.StatusText().c_str()));
    setRow(CAP_UNLOCK_KEYBOARD, a.input.StatusText());
    setRow(CAP_UNLOCK_MOUSE, Fmt(L"%s　已解 %d 次", CapDesc(CAP_UNLOCK_MOUSE),
                                 (int)a.input.MouseUnlocks()));
    {
        auto stats = a.inj.Snapshot();
        LONG term = 0, close = 0, gated = 0;
        for (auto& s : stats) { term += s.blockedTerm; close += s.blockedClose; gated += s.gated; }
        setRow(CAP_BLOCK_TERMINATE, Fmt(L"%s　已拦截 %ld 次", CapDesc(CAP_BLOCK_TERMINATE), term));
        setRow(CAP_BLOCK_CLOSE, Fmt(L"%s　已拦截 %ld 次", CapDesc(CAP_BLOCK_CLOSE), close));
        setRow(CAP_CMD_GATE, Fmt(L"%s　已裁决 %ld 次", CapDesc(CAP_CMD_GATE), gated));
        if (GateVisible()) setRow(CAP_CMD_GATE, L"有远程命令等待你的裁决…");
    }

    auto lines = a.log.Recent(60);
    std::wstring text;
    for (auto& l : lines) { text += l; text += L"\r\n"; }
    SetWindowTextW(logBox_, text.c_str());
    SendMessageW(logBox_, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(logBox_, EM_SCROLLCARET, 0, 0);
}

void Ui::ToggleStatus() {
    if (statusWnd_ && IsWindowVisible(statusWnd_)) {
        ShowWindow(statusWnd_, SW_HIDE);
        statusVisible_ = false;
        return;
    }
    ShowStatus();
}

void Ui::ShowStatus() {
    CreateStatus();
    if (!statusWnd_) return;
    ShowWindow(statusWnd_, SW_SHOW);
    SetForegroundWindow(statusWnd_);
    statusVisible_ = true;
    RefreshStatus();
}

// ─────────────────────────────────────────────────────────────────────────────
//  远程命令裁决窗
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK Ui::GateProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    Ui* ui = s_self_;
    switch (m) {
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)w;
            SetBkColor(dc, RGB(255, 255, 255));
            return (LRESULT)GetStockObject(WHITE_BRUSH);
        }
        case WM_COMMAND:
            if (ui) {
                int id = LOWORD(w);
                if (id == ID_GATE_ALLOW) { A().DecideGate(CT_CMD_ALLOW); return 0; }
                if (id == ID_GATE_DENY) { A().DecideGate(CT_CMD_DENY); return 0; }
                if (id == ID_GATE_ALLOWALL) { A().DecideGate(CT_CMD_ALLOWALL); return 0; }
            }
            return 0;
        case WM_TIMER:
            if (ui) ui->UpdateGate();
            return 0;
        case WM_CLOSE:
            A().DecideGate(CT_CMD_DENY);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(h, m, w, l);
}

void Ui::CreateGate() {
    if (gateWnd_) return;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = Ui::GateProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"CtGateWnd";
    wc.hIcon = iconAlert_;
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    RegisterClassExW(&wc);

    gateWnd_ = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"CtGateWnd",
                               L"CloudTrainer · 远程命令确认",
                               WS_POPUP | WS_CAPTION | WS_SYSMENU,
                               CW_USEDEFAULT, CW_USEDEFAULT, 560, 320,
                               nullptr, nullptr, wc.hInstance, nullptr);
    if (!gateWnd_) return;

    gateText_ = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                0, 0, 10, 10, gateWnd_, nullptr, wc.hInstance, nullptr);
    SetFont(gateText_, fontUi_);

    gateCount_ = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                 0, 0, 10, 10, gateWnd_, nullptr, wc.hInstance, nullptr);
    SetFont(gateCount_, fontBold_);

    gateAllow_ = CreateWindowExW(0, L"BUTTON", L"允许一次", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                 0, 0, 10, 10, gateWnd_, (HMENU)(INT_PTR)ID_GATE_ALLOW,
                                 wc.hInstance, nullptr);
    gateDeny_ = CreateWindowExW(0, L"BUTTON", L"拒绝", WS_CHILD | WS_VISIBLE,
                                0, 0, 10, 10, gateWnd_, (HMENU)(INT_PTR)ID_GATE_DENY,
                                wc.hInstance, nullptr);
    gateAll_ = CreateWindowExW(0, L"BUTTON", L"一律允许", WS_CHILD | WS_VISIBLE,
                               0, 0, 10, 10, gateWnd_, (HMENU)(INT_PTR)ID_GATE_ALLOWALL,
                               wc.hInstance, nullptr);
    SetFont(gateAllow_, fontUi_);
    SetFont(gateDeny_, fontUi_);
    SetFont(gateAll_, fontUi_);

    SetTimer(gateWnd_, 1, 200, nullptr);
    LayoutGate();
}

void Ui::LayoutGate() {
    if (!gateWnd_) return;
    RECT rc{};
    GetClientRect(gateWnd_, &rc);
    const int pad = 18;
    MoveWindow(gateText_, pad, pad, rc.right - pad * 2, 150, TRUE);
    MoveWindow(gateCount_, pad, rc.bottom - pad - 76, 260, 22, TRUE);
    const int bw = 110, bh = 32;
    int x = rc.right - pad - bw * 3 - 8 * 2;
    MoveWindow(gateAllow_, x, rc.bottom - pad - bh, bw, bh, TRUE);
    MoveWindow(gateDeny_, x + bw + 8, rc.bottom - pad - bh, bw, bh, TRUE);
    MoveWindow(gateAll_, x + (bw + 8) * 2, rc.bottom - pad - bh, bw, bh, TRUE);
}

void Ui::ShowGate(const CtPendingCmd& cmd, int index) {
    CreateGate();
    if (!gateWnd_) return;

    gateIndex_ = index;
    gateDeadline_ = NowMs() + (uint64_t)A().cfg.cmdGateTimeout * 1000;

    std::wstring text;
    text += L"教师端正在本机执行一条远程命令：\r\n\r\n";
    if (cmd.app[0]) { text += L"程序："; text += cmd.app; text += L"\r\n"; }
    text += L"命令行：\r\n";
    text += cmd.cmd;
    text += L"\r\n\r\n来源进程 PID：";
    text += Fmt(L"%ld", cmd.hostPid);
    text += L"\r\n\r\n30 秒内没有选择将按“拒绝”处理。";
    SetWindowTextW(gateText_, text.c_str());
    SetWindowTextW(gateCount_, L"");

    ShowWindow(gateWnd_, SW_SHOW);
    SetForegroundWindow(gateWnd_);
    UpdateGate();
}

void Ui::UpdateGate() {
    if (!gateWnd_ || !IsWindowVisible(gateWnd_)) return;
    uint64_t now = NowMs();
    int left = 0;
    if (now < gateDeadline_) left = (int)((gateDeadline_ - now) / 1000) + 1;
    SetWindowTextW(gateCount_, Fmt(L"剩余 %d 秒", left).c_str());
    if (left <= 0) A().DecideGate(CT_CMD_DENY);
}

void Ui::HideGate() {
    if (!gateWnd_) return;
    KillTimer(gateWnd_, 1);
    DestroyWindow(gateWnd_);
    gateWnd_ = nullptr;
    gateText_ = gateCount_ = nullptr;
    gateAllow_ = gateDeny_ = gateAll_ = nullptr;
    gateIndex_ = -1;
}

// ─────────────────────────────────────────────────────────────────────────────
//  假黑屏（Ctrl+Alt+F）
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK Ui::BlackKeyboardHook(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && wp == WM_KEYDOWN) {
        auto* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        bool alt = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
        if (kb->vkCode == 'F' && ctrl && alt) {
            // 放行退出组合，否则 RegisterHotKey 永远收不到
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
        A().log.Info(L"假黑屏已关闭");
    }
}

} // namespace ct
