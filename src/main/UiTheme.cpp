// =============================================================================
//  CloudTrainer - UiTheme.cpp
//  纯绘制层：GDI+ 画圆角卡片、渐变、图标与文字。不碰窗口消息。
// =============================================================================
#include "UiTheme.h"

#include <algorithm>
#include <cmath>
#include <stdio.h>

using namespace Gdiplus;

namespace ct {
namespace ui {
namespace {

inline Color C(const Rgba& c) { return Color(c.a, c.r, c.g, c.b); }

Color Mix(const Rgba& a, const Rgba& b, float t) {
    t = std::max(0.0f, std::min(1.0f, t));
    return Color(255,
                 (BYTE)(a.r + (b.r - a.r) * t),
                 (BYTE)(a.g + (b.g - a.g) * t),
                 (BYTE)(a.b + (b.b - a.b) * t));
}

void RoundedPath(GraphicsPath* p, const RectF& r, float rad) {
    const float d = rad * 2;
    p->Reset();
    if (rad <= 0.5f) { p->AddRectangle(r); return; }
    p->AddArc(r.X, r.Y, d, d, 180, 90);
    p->AddArc(r.X + r.Width - d, r.Y, d, d, 270, 90);
    p->AddArc(r.X + r.Width - d, r.Y + r.Height - d, d, d, 0, 90);
    p->AddArc(r.X, r.Y + r.Height - d, d, d, 90, 90);
    p->CloseFigure();
}

// 只圆指定的角：卡片头部只圆上两角、主体只圆下两角，两者都不必互相裁切。
void RoundPath(GraphicsPath* p, const RectF& r, float rad, bool top, bool bottom) {
    const float d = rad * 2;
    p->Reset();
    if (top) {
        p->AddArc(r.X, r.Y, d, d, 180, 90);
        p->AddArc(r.X + r.Width - d, r.Y, d, d, 270, 90);
    } else {
        p->AddLine(r.X, r.Y, r.X + r.Width, r.Y);
    }
    if (bottom) {
        p->AddLine(r.X + r.Width, r.Y + d, r.X + r.Width, r.Y + r.Height - d);
        p->AddArc(r.X + r.Width - d, r.Y + r.Height - d, d, d, 0, 90);
        p->AddArc(r.X, r.Y + r.Height - d, d, d, 90, 90);
        p->AddLine(r.X, r.Y + r.Height - d, r.X, r.Y + d);
    } else {
        p->AddLine(r.X + r.Width, r.Y + d, r.X + r.Width, r.Y + r.Height);
        p->AddLine(r.X + r.Width, r.Y + r.Height, r.X, r.Y + r.Height);
        p->AddLine(r.X, r.Y + r.Height, r.X, r.Y + d);
    }
    p->CloseFigure();
}

void FillRound(Graphics& g, const RectF& r, float rad, const Rgba& c) {
    GraphicsPath p;
    RoundedPath(&p, r, rad);
    SolidBrush b(C(c));
    g.FillPath(&b, &p);
}

void StrokeRound(Graphics& g, const RectF& r, float rad, const Rgba& c, float w) {
    GraphicsPath p;
    RoundedPath(&p, r, rad);
    Pen pen(C(c), w);
    g.DrawPath(&pen, &p);
}

void FillGradientRound(Graphics& g, const RectF& r, float rad, const Rgba& top, const Rgba& bottom) {
    GraphicsPath p;
    RoundedPath(&p, r, rad);
    LinearGradientBrush b(r, C(top), C(bottom), LinearGradientModeVertical);
    g.FillPath(&b, &p);
}

const FontFamily& UiFamily() {
    // 故意 new 出来不释放：这些对象的析构会在进程退出时跑到 GdiplusShutdown 之后，
    // 那一步会访问已经关掉的 GDI+ 令牌，直接段错误。
    static FontFamily* ya = new FontFamily(L"Microsoft YaHei UI");
    if (ya && ya->IsAvailable()) return *ya;
    static FontFamily* fb = new FontFamily(L"Microsoft YaHei");
    if (fb && fb->IsAvailable()) return *fb;
    return *FontFamily::GenericSansSerif();
}

// 文字：按矩形框排版，vcenter 恒定
void Text(Graphics& g, const std::wstring& s, const RectF& r, float sizePx, const Rgba& c,
          StringAlignment halign = StringAlignmentNear, bool wrap = false) {
    if (s.empty()) return;
    // 亚像素字号 + 小数坐标会让 GDI+ 反复 hinting，小字直接糊成一团。
    // 统一取整到像素：宁可少半像素的精度，也要清晰。
    const float px = std::max(9.0f, std::floor(sizePx + 0.5f));
    Font font(&UiFamily(), px, FontStyleRegular, UnitPixel);
    StringFormat fmt;
    fmt.SetAlignment(halign);
    fmt.SetLineAlignment(wrap ? StringAlignmentNear : StringAlignmentCenter);
    fmt.SetFormatFlags(wrap ? StringFormatFlagsLineLimit : (StringFormatFlagsNoWrap | StringFormatFlagsNoClip));
    SolidBrush b(C(c));
    const RectF rr(std::floor(r.X + 0.5f), std::floor(r.Y + 0.5f),
                   std::floor(r.Width + 0.5f), std::floor(r.Height + 0.5f));
    g.DrawString(s.c_str(), (INT)s.size(), &font, rr, &fmt, &b);
}

// 在 24×24 坐标系里画图标
struct IconPen {
    Graphics& g;
    Pen& pen;
    RectF box;
    float k;
    void Line(float x1, float y1, float x2, float y2) {
        g.DrawLine(&pen, (REAL)(box.X + x1 * k), (REAL)(box.Y + y1 * k),
                   (REAL)(box.X + x2 * k), (REAL)(box.Y + y2 * k));
    }
    void Rect(float x, float y, float w, float h, float rad) {
        RectF rr(box.X + x * k, box.Y + y * k, w * k, h * k);
        GraphicsPath p;
        RoundedPath(&p, rr, rad * k);
        g.DrawPath(&pen, &p);
    }
    void Circle(float cx, float cy, float r0) {
        g.DrawEllipse(&pen, box.X + (cx - r0) * k, box.Y + (cy - r0) * k, r0 * 2 * k, r0 * 2 * k);
    }
};

} // namespace

Metrics DefaultMetrics() { return Metrics{}; }

int ScaleForWindow(HWND hwnd) {
    // 取窗口所在显示器的 DPI。Win10 用 GetDpiForWindow，退路是系统 DPI。
    typedef UINT(WINAPI * FnGetDpiForWindow)(HWND);
    static FnGetDpiForWindow fn = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE u = GetModuleHandleW(L"user32.dll");
        if (u) fn = reinterpret_cast<FnGetDpiForWindow>(GetProcAddress(u, "GetDpiForWindow"));
    }
    UINT dpi = 96;
    if (fn && hwnd) dpi = fn(hwnd);
    if (!dpi) {
        HDC dc = GetDC(nullptr);
        if (dc) {
            dpi = (UINT)GetDeviceCaps(dc, LOGPIXELSX);
            ReleaseDC(nullptr, dc);
        }
    }
    if (!dpi) dpi = 96;
    return (int)(dpi >= 120 ? 120 : dpi);   // 用实际 DPI，下面按 /96 缩放
}

void DrawIcon(Graphics& g, int id, const RectF& r, const Rgba& c, float strokeW) {
    Pen pen(C(c), std::max(1.0f, std::floor(strokeW + 0.5f)));
    pen.SetLineJoin(LineJoinRound);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    const float k = r.Width / 24.0f;
    IconPen ip{ g, pen, r, k };

    switch (id) {
        case 0:   // 显示器
            ip.Rect(3, 4, 18, 13, 2);
            ip.Line(8, 21, 16, 21);
            ip.Line(12, 17, 12, 21);
            break;
        case 1:   // 黑屏：圆 + 斜杠
            ip.Circle(12, 12, 8);
            ip.Line(6.5f, 17.5f, 17.5f, 6.5f);
            break;
        case 2:   // 键盘
            ip.Rect(2, 6, 20, 12, 2);
            ip.Line(6, 10, 7, 10);
            ip.Line(10.5f, 10, 11.5f, 10);
            ip.Line(15, 10, 16, 10);
            ip.Line(6, 14, 18, 14);
            break;
        case 3:   // 鼠标
            ip.Rect(6, 3, 12, 18, 6);
            ip.Line(12, 7, 12, 11.5f);
            break;
        case 4: { // 盾牌
            GraphicsPath p;
            const float x = r.X, y = r.Y, w = r.Width, h = r.Height;
            auto X = [&](float v) { return x + v / 24.0f * w; };
            auto Y = [&](float v) { return y + v / 24.0f * h; };
            auto P = [&](float px, float py) { return PointF(X(px), Y(py)); };
            p.AddLine(P(12, 3), P(19, 6));
            p.AddLine(P(19, 6), P(19, 12));
            p.AddBezier(P(19, 12), P(19, 16), P(16, 19.5f), P(12, 21));
            p.AddBezier(P(12, 21), P(8, 19.5f), P(5, 16), P(5, 12));
            p.AddLine(P(5, 12), P(5, 6));
            p.CloseFigure();
            g.DrawPath(&pen, &p);
            ip.Line(9, 12, 11.2f, 14.2f);
            ip.Line(11.2f, 14.2f, 15.4f, 9.4f);
            break;
        }
        case 5:   // 窗口 + 叉（关窗拦截）
            ip.Rect(3.5f, 5, 17, 14, 2);
            ip.Line(10, 12, 14, 16);
            ip.Line(14, 12, 10, 16);
            break;
        case 6: { // 警告三角
            GraphicsPath p;
            const float x = r.X, y = r.Y, w = r.Width, h = r.Height;
            auto X = [&](float v) { return x + v / 24.0f * w; };
            auto Y = [&](float v) { return y + v / 24.0f * h; };
            auto P = [&](float px, float py) { return PointF(X(px), Y(py)); };
            p.AddLine(P(12, 3.5f), P(21, 20));
            p.AddLine(P(21, 20), P(3, 20));
            p.CloseFigure();
            g.DrawPath(&pen, &p);
            ip.Line(12, 9.5f, 12, 14);
            ip.Line(12, 17, 12, 17);
            break;
        }
        default:  // 7 还原（箭头绕回）
            ip.Circle(12, 12, 7.5f);
            ip.Line(12, 4.5f, 12, 8.5f);
            ip.Line(12, 4.5f, 15.5f, 6.5f);
            break;
    }
}

void PaintShadow(Graphics& g, const RectF& content, float radius, float margin) {
    // 用一圈圈**描边**（不是填充）画阴影：每环只覆盖自己那一条带，α 不叠加，
    // 之前用填充叠 14 层，边缘会积到 40% 黑，看着像描边而不是投影。
    auto roundPath = [&](GraphicsPath* p, const RectF& r, float rad) {
        const float d = rad * 2;
        p->Reset();
        p->AddArc(r.X, r.Y, d, d, 180, 90);
        p->AddArc(r.X + r.Width - d, r.Y, d, d, 270, 90);
        p->AddArc(r.X + r.Width - d, r.Y + r.Height - d, d, d, 0, 90);
        p->AddArc(r.X, r.Y + r.Height - d, d, d, 90, 90);
        p->CloseFigure();
    };

    const int layers = 16;
    const float step = margin / layers;
    const float dy = margin * 0.22f;

    for (int i = 0; i < layers; ++i) {
        const float t = (float)i / layers;                 // 0 = 最外，1 = 最内
        const float grow = margin - step * 0.5f - t * (margin - step);
        if (grow < 0) continue;
        const RectF r(content.X - grow, content.Y - grow + dy,
                      content.Width + grow * 2, content.Height + grow * 2);
        GraphicsPath p;
        roundPath(&p, r, radius + grow);
        Pen pen(Color((BYTE)(4 + t * 58), 15, 23, 42), step * 1.8f);
        g.DrawPath(&pen, &p);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  主窗口
// ─────────────────────────────────────────────────────────────────────────────
void PaintWindow(Graphics& g, const Model& m, const Metrics& mt, float s) {
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeNone);
    g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);

    const float W = mt.w * s, H = mt.h * s;
    auto S = [s](float v) { return v * s; };

    // 卡片由两块拼成：上层渐变只圆上两角、下层主体只圆下两角。
    // 之前是"整块白壳 + 更大的圆角渐变"，两个半径不一致就露出一圈白边，
    // 而且渐变的抗锯齿混在白底上，边缘永远发浅。现在两者都直接对透明画布合成。
    const float radius = S(12);
    const float heroBottom = S(mt.titleH + mt.heroH);

    Rgba top, bot;
    switch (m.tone) {
        case Tone::Active:   top = {255, 0, 204, 5};     bot = {255, 40, 140, 0};    break;
        case Tone::Idle:     top = {255, 46, 164, 240};  bot = {255, 46, 140, 240};  break;
        case Tone::Degraded: top = {255, 245, 146, 0};   bot = {255, 201, 106, 0};   break;
        default:             top = {255, 108, 117, 125}; bot = {255, 77, 88, 99};    break;
    }

    {   // 主体（白，圆下角），上沿藏到头区下面 1px，避免接缝
        GraphicsPath body;
        RoundPath(&body, RectF(0, heroBottom - S(1), W, H - heroBottom + S(1)),
                  radius, false, true);
        SolidBrush w(Color(255, 255, 255, 255));
        g.FillPath(&w, &body);
    }
    {   // 头区（渐变，圆上角）
        GraphicsPath head;
        RoundPath(&head, RectF(0, 0, W, heroBottom), radius, true, false);
        LinearGradientBrush lb(RectF(0, 0, W, heroBottom), C(top), C(bot),
                               LinearGradientModeVertical);
        g.FillPath(&lb, &head);
    }


    // ── 标题栏 ──
    const Rgba whiteTxt{255, 255, 255, 255};
    const Rgba dimTxt{200, 255, 255, 255};
    {
        RectF logo(S(mt.pad), S(13), S(20), S(20));
        FillRound(g, logo, S(6), Rgba{240, 255, 255, 255});
        DrawIcon(g, 4, RectF(logo.X + S(3), logo.Y + S(3), S(14), S(14)), Rgba{255, 0, 130, 0}, S(1.6f));

        Text(g, L"CloudTrainer", RectF(S(mt.pad + 28), S(12), S(180), S(22)), S(13), whiteTxt);

        const float by = S(11), bs = S(26);
        RectF bmin(W - S(mt.pad) - bs * 2 - S(6), by, bs, bs);
        RectF bcls(W - S(mt.pad) - bs, by, bs, bs);
        auto chromeBtn = [&](const RectF& r, int hit, bool close) {
            if (m.hot == hit) FillRound(g, r, S(13), Rgba{46, 255, 255, 255});
            Rgba c{230, 255, 255, 255};
            if (close && m.hot == hit) c = whiteTxt;
            const float cx = r.X + r.Width / 2, cy = r.Y + r.Height / 2;
            Pen pen(C(c), S(1.5f));
            pen.SetStartCap(LineCapRound);
            pen.SetEndCap(LineCapRound);
            if (close) {
                g.DrawLine(&pen, (REAL)(cx - S(4.5f)), (REAL)(cy - S(4.5f)),
                           (REAL)(cx + S(4.5f)), (REAL)(cy + S(4.5f)));
                g.DrawLine(&pen, (REAL)(cx + S(4.5f)), (REAL)(cy - S(4.5f)),
                           (REAL)(cx - S(4.5f)), (REAL)(cy + S(4.5f)));
            } else {
                g.DrawLine(&pen, (REAL)(cx - S(5)), (REAL)cy, (REAL)(cx + S(5)), (REAL)cy);
            }
        };
        chromeBtn(bmin, HIT_MIN, false);
        chromeBtn(bcls, HIT_CLOSE, true);
    }

    // ── 状态区 ──
    {
        const float cx = S(mt.pad + 37), cy = S(mt.titleH + mt.heroH * 0.5f);
        const float rOut = S(33), rIn = S(26);
        Pen ring(Color(115, 255, 255, 255), S(1.5f));
        g.DrawEllipse(&ring, cx - rOut, cy - rOut, rOut * 2, rOut * 2);
        SolidBrush inner(Color(42, 0, 0, 0));
        g.FillEllipse(&inner, cx - rIn, cy - rIn, rIn * 2, rIn * 2);
        DrawIcon(g, 4, RectF(cx - S(15), cy - S(15), S(30), S(30)), whiteTxt, S(1.7f));

        const float tx = S(mt.pad + 88);
        Text(g, m.title, RectF(tx, cy - S(26), W - tx - S(mt.pad), S(26)), S(18), whiteTxt);
        Text(g, m.subtitle, RectF(tx, cy + S(1), W - tx - S(mt.pad), S(18)), S(12), dimTxt);

        RectF metaR(W - S(mt.pad) - S(150), cy - S(26), S(150), S(16));
        Text(g, m.meta1, metaR, S(11), Rgba{190, 255, 255, 255}, StringAlignmentFar);
        metaR.Y += S(15);
        Text(g, m.meta2, metaR, S(11), Rgba{190, 255, 255, 255}, StringAlignmentFar);
    }

    // ── 能力列表 ──
    const float rowTop = heroBottom + S(12);
    for (int i = 0; i < m.rowCount && i < kMaxRows; ++i) {
        const CapRow& row = m.rows[i];
        const float y = rowTop + S(mt.rowH) * i;
        const float rh = S(mt.rowH);

        if (m.hot == HIT_ROW_BASE + i) {
            FillRound(g, RectF(S(8), y + S(2), W - S(16), rh - S(4)), S(8), Rgba{255, 245, 248, 252});
        }

        const Rgba iconBg = row.on ? Rgba{255, 232, 245, 233} : Rgba{255, 237, 242, 247};
        const Rgba iconFg = row.on ? Rgba{255, 46, 125, 50} : Rgba{255, 74, 85, 104};
        RectF ib(S(mt.pad), y + (rh - S(28)) / 2, S(28), S(28));
        FillRound(g, ib, S(8), iconBg);
        DrawIcon(g, row.icon, RectF(ib.X + S(7), ib.Y + S(7), S(14), S(14)), iconFg, S(1.5f));

        Text(g, row.name, RectF(S(mt.pad + 38), y, S(180), rh), S(13.5f), Rgba{255, 42, 49, 64});

        const Rgba st = row.warn ? Rgba{255, 178, 106, 0} : Rgba{255, 122, 134, 153};
        Text(g, row.state, RectF(W - S(mt.pad) - S(190), y, S(140), rh), S(11.5f), st,
             StringAlignmentFar);

        // 开关
        const float tw = S(38), th = S(21);
        RectF tr(W - S(mt.pad) - tw, y + (rh - th) / 2, tw, th);
        FillRound(g, tr, th / 2, row.on ? Rgba{255, 47, 168, 79} : Rgba{255, 215, 220, 227});
        const float kn = th - S(4);
        RectF kr(row.on ? tr.X + tw - kn - S(2) : tr.X + S(2), tr.Y + S(2), kn, kn);
        SolidBrush kb(Color(255, 255, 255, 255));
        g.FillEllipse(&kb, kr);
    }

    // ── 底栏 ──
    {
        const float fy = S(mt.h - mt.footH);
        Pen sep(Color(255, 237, 240, 244), S(1));
        g.DrawLine(&sep, (REAL)0, (REAL)fy, (REAL)W, (REAL)fy);

        RectF btn(S(mt.pad), fy + (S(mt.footH) - S(30)) / 2, S(94), S(30));
        const bool hov = (m.hot == HIT_RESTORE);
        FillRound(g, btn, S(8), hov ? Rgba{255, 252, 232, 229} : Rgba{255, 253, 240, 238});
        Text(g, L"全部还原", btn, S(12.5f), Rgba{255, 192, 57, 43}, StringAlignmentCenter);

        const float linkY = fy + (S(mt.footH) - S(30)) / 2;
        auto link = [&](const wchar_t* label, float x, float w, int hit) {
            RectF r(x, linkY, w, S(30));
            if (m.hot == hit) FillRound(g, r, S(6), Rgba{255, 242, 245, 250});
            Text(g, label, r, S(12.5f), Rgba{255, 107, 114, 128}, StringAlignmentCenter);
        };
        link(L"日志", S(mt.pad + 104), S(46), HIT_LOG);
        link(L"关于", S(mt.pad + 154), S(46), HIT_ABOUT);

        Text(g, m.version, RectF(W - S(mt.pad) - S(80), linkY, S(80), S(30)), S(11),
             Rgba{255, 180, 188, 200}, StringAlignmentFar);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  命令裁决弹窗
// ─────────────────────────────────────────────────────────────────────────────
void PaintGate(Graphics& g, const GateModel& gm, int w, int h, float s) {
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeNone);
    g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);

    const float W = w * s, H = h * s;
    auto S = [s](float v) { return v * s; };
    const float radius = S(12);
    {   // 主体：白，只圆下两角
        GraphicsPath body;
        RoundPath(&body, RectF(0, S(63), W, H - S(63)), radius, false, true);
        SolidBrush w(Color(255, 255, 255, 255));
        g.FillPath(&w, &body);
    }
    {   // 头区：橙，只圆上两角
        GraphicsPath head;
        RoundPath(&head, RectF(0, 0, W, S(64)), radius, true, false);
        LinearGradientBrush lb(RectF(0, 0, W, S(64)),
                               Color(255, 255, 153, 0), Color(255, 224, 122, 0),
                               LinearGradientModeVertical);
        g.FillPath(&lb, &head);
    }

    DrawIcon(g, 6, RectF(S(18), S(20), S(24), S(24)), Rgba{255, 255, 255, 255}, S(1.7f));
    Text(g, L"远程命令待确认", RectF(S(52), S(18), S(220), S(28)), S(15),
         Rgba{255, 255, 255, 255});
    {
        wchar_t buf[32];
        _snwprintf(buf, 31, L"%d 秒后自动拒绝", gm.remainSec);
        Text(g, buf, RectF(W - S(170), S(20), S(152), S(24)), S(11.5f),
             Rgba{235, 255, 255, 255}, StringAlignmentFar);
    }

    // 命令内容
    RectF box(S(16), S(78), W - S(32), S(112));
    FillRound(g, box, S(8), Rgba{255, 247, 249, 252});
    // 两行都是"标签在上、值在下"，统一版式
    Text(g, L"程序", RectF(box.X + S(12), box.Y + S(8), S(60), S(15)), S(10.5f),
         Rgba{255, 140, 149, 165});
    Text(g, gm.app.empty() ? L"(未知)" : gm.app,
         RectF(box.X + S(12), box.Y + S(23), box.Width - S(24), S(20)), S(13),
         Rgba{255, 42, 49, 64});
    Text(g, L"命令行", RectF(box.X + S(12), box.Y + S(49), S(60), S(15)), S(10.5f),
         Rgba{255, 140, 149, 165});
    Text(g, gm.cmd.empty() ? L"(无参数)" : gm.cmd,
         RectF(box.X + S(12), box.Y + S(64), box.Width - S(24), S(42)), S(12),
         Rgba{255, 90, 99, 115}, StringAlignmentNear, true);

    // 按钮
    const float by = H - S(56), bh = S(32);
    auto button = [&](const wchar_t* label, const RectF& r, Rgba bg, Rgba fg, int hit) {
        FillRound(g, r, S(8), (gm.hot == hit) ? Rgba{bg.a, (BYTE)std::min(255, bg.r + 14),
                                                    (BYTE)std::min(255, bg.g + 8),
                                                    (BYTE)std::min(255, bg.b + 8)} : bg);
        Text(g, label, r, S(12.5f), fg, StringAlignmentCenter);
    };
    RectF bAll(W - S(16) - S(96), by, S(96), bh);
    RectF bDen(W - S(16) - S(96) - S(8) - S(76), by, S(76), bh);
    RectF bAllow(W - S(16) - S(96) - S(8) - S(76) - S(8) - S(96), by, S(96), bh);
    button(L"允许一次", bAllow, Rgba{255, 47, 168, 79}, Rgba{255, 255, 255, 255}, 4001);
    button(L"拒绝", bDen, Rgba{255, 242, 245, 249}, Rgba{255, 74, 85, 104}, 4002);
    button(L"一律允许", bAll, Rgba{255, 232, 240, 254}, Rgba{255, 58, 118, 216}, 4003);
}

} // namespace ui
} // namespace ct
