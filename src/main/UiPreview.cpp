// =============================================================================
//  CloudTrainer - UiPreview.cpp
//  ---------------------------------------------------------------------------
//  `CloudTrainer.exe --uipreview <输出目录>`
//  把主窗口 / 裁决窗按 2 倍缩放直接渲染成 PNG，不创建任何窗口。
//
//  为什么需要它：自绘 UI 没法靠"编译通过"验收，也没法在无人值守的机器上截图。
//  有了这个入口，设计稿就是**真实绘制代码的输出**，不是另外画的示意图。
// =============================================================================
#include "Core.h"
#include "UiTheme.h"

#include <gdiplus.h>
#include <objidl.h>

using namespace Gdiplus;

namespace ct {
namespace {

int GetEncoderClsid(const wchar_t* mime, CLSID* out) {
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    std::vector<uint8_t> buf(size);
    auto* codecs = reinterpret_cast<ImageCodecInfo*>(buf.data());
    GetImageEncoders(num, size, codecs);
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(codecs[i].MimeType, mime) == 0) {
            *out = codecs[i].Clsid;
            return (int)i;
        }
    }
    return -1;
}

bool SavePng(Bitmap& bmp, const std::wstring& path) {
    CLSID clsid{};
    if (GetEncoderClsid(L"image/png", &clsid) < 0) return false;
    return bmp.Save(path.c_str(), &clsid, nullptr) == Ok;
}

ui::Model SampleActive() {
    ui::Model m;
    m.tone = ui::Tone::Active;
    m.title = L"防护中";
    m.subtitle = L"广播已窗口化 · 键鼠已解除";
    m.meta1 = L"注入 2 个进程";
    m.meta2 = L"今日拦截 14 次";
    m.version = kAppVersion;
    const wchar_t* names[7] = { L"广播窗口化", L"黑屏压制", L"键盘解锁", L"鼠标解锁",
                                L"结束拦截", L"关窗拦截", L"命令闸门" };
    const wchar_t* states[7] = { L"已生效", L"已压制 3 次", L"已解除 2 次", L"外部 1 / 进程内 4",
                                 L"最近 chrome.exe", L"已拦 0 次", L"待裁决 1 条" };
    for (int i = 0; i < 7; ++i) {
        m.rows[i].name = names[i];
        m.rows[i].state = states[i];
        m.rows[i].on = true;
        m.rows[i].warn = (i == 6);
        m.rows[i].icon = (i == 4) ? 4 : (i == 6 ? 6 : (i == 5 ? 5 : (i == 3 ? 3 : (i == 2 ? 2 : i))));
    }
    m.rowCount = 7;
    return m;
}

} // namespace

int RunUiPreview(const wchar_t* outDir) {
    GdiplusStartupInput in;
    ULONG_PTR token = 0;
    if (GdiplusStartup(&token, &in, nullptr) != Ok) return 2;

    std::wstring dir = outDir && *outDir ? outDir : L".";
    while (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/')) dir.pop_back();
    CreateDirectoryW(dir.c_str(), nullptr);

    const float s = 2.0f;
    const ui::Metrics mt = ui::DefaultMetrics();

    int rc = 0;
    {
        const int w = (int)(mt.w * s), h = (int)(mt.h * s);
        Bitmap bmp(w, h, PixelFormat32bppARGB);
        Graphics g(&bmp);
        g.Clear(Color(255, 255, 255, 255));
        ui::PaintWindow(g, SampleActive(), mt, s);
        if (!SavePng(bmp, dir + L"\\preview-main.png")) rc = 3;
    }
    {
        // 降级态：验证渐变与文字在橙色下的对比
        ui::Model m = SampleActive();
        m.tone = ui::Tone::Degraded;
        m.title = L"降级运行";
        m.subtitle = L"版本未验证 · 功能仍全部启用";
        const int w = (int)(mt.w * s), h = (int)(mt.h * s);
        Bitmap bmp(w, h, PixelFormat32bppARGB);
        Graphics g(&bmp);
        g.Clear(Color(255, 255, 255, 255));
        ui::PaintWindow(g, m, mt, s);
        SavePng(bmp, dir + L"\\preview-degraded.png");
    }
    {
        // 1:1 渲染：这才是屏幕上真正的样子（96 DPI）
        const int w = 420, h = 568;
        Bitmap bmp(w, h, PixelFormat32bppARGB);
        Graphics g(&bmp);
        g.Clear(Color(255, 255, 255, 255));
        ui::PaintWindow(g, SampleActive(), mt, 1.0f);
        SavePng(bmp, dir + L"\\preview-1x.png");
    }
    {
        // 和真实窗口一样：阴影 + 圆角卡片，放在浅灰桌面上看合成效果
        const float s2 = 2.0f;
        const int cw = (int)(mt.w * s2), ch = (int)(mt.h * s2);
        const int m = (int)(16 * s2);
        Bitmap bmp(cw + m * 2, ch + m * 2, PixelFormat32bppARGB);
        Graphics g(&bmp);
        g.Clear(Color(255, 233, 237, 243));
        ui::PaintShadow(g, RectF((REAL)m, (REAL)m, (REAL)cw, (REAL)ch), 12 * s2, (REAL)m);
        g.TranslateTransform((REAL)m, (REAL)m);
        ui::PaintWindow(g, SampleActive(), mt, s2);
        SavePng(bmp, dir + L"\\preview-window.png");
    }
    {
        const int w = 460, h = 286;
        ui::GateModel gm;
        gm.app = L"C:\\Windows\\System32\\notepad.exe";
        gm.cmd = L"notepad.exe C:\\Users\\Public\\课件\\第3章-笔记.txt";
        gm.remainSec = 18;
        Bitmap bmp((int)(w * s), (int)(h * s), PixelFormat32bppARGB);
        Graphics g(&bmp);
        g.Clear(Color(255, 255, 255, 255));
        ui::PaintGate(g, gm, w, h, s);
        SavePng(bmp, dir + L"\\preview-gate.png");
    }

    GdiplusShutdown(token);
    return rc;
}

} // namespace ct
