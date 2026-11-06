// =============================================================================
//  CloudTrainer - UiTheme.h
//  ---------------------------------------------------------------------------
//  自绘 UI 的主题与绘制层。
//
//  设计语言沿用 JiYuTrainer（MIT, © imengyu）：
//    * 10~12px 圆角卡片 + 系统投影
//    * 头区按状态做纵向渐变（绿=防护中 / 蓝=待机 / 橙=降级 / 灰=未连接）
//    * 圆环 + 盾牌图标作为状态锚点
//  但信息架构换成"状态条 + 能力列表"，因为本工具是 7 项能力而不是 5 个动作。
//
//  这一层是**纯绘制**：不建窗口、不读全局状态，只吃一个 Model。
//  好处是 --uipreview 可以把它直接渲染成 PNG 做视觉验收。
// =============================================================================
#pragma once

#include <windows.h>
#include <gdiplus.h>
#include <string>

namespace ct {
namespace ui {

// 命中区 id（绘制层用它在 hover 时高亮）
enum HitId : int {
    HIT_NONE      = -1,
    HIT_MIN       = 1001,
    HIT_CLOSE     = 1002,
    HIT_ROW_BASE  = 2000,     // +i
    HIT_RESTORE   = 3001,
    HIT_LOG       = 3002,
    HIT_ABOUT     = 3003,
};

enum class Tone { Active, Idle, Degraded, Offline };

struct Rgba {
    BYTE a = 255, r = 0, g = 0, b = 0;
};

struct CapRow {
    std::wstring name;
    std::wstring state;     // 右侧灰字
    bool on = true;
    bool warn = false;      // 状态文字用橙色（待裁决 / 失败）
    int  icon = 0;
};

constexpr int kMaxRows = 8;

struct Model {
    Tone tone = Tone::Active;
    std::wstring title;      // 防护中
    std::wstring subtitle;   // 广播已窗口化 · 键鼠已解除
    std::wstring meta1;      // 注入 2 进程
    std::wstring meta2;      // 拦截 14 次
    CapRow rows[kMaxRows];
    int  rowCount = 0;
    std::wstring version;
    int  hot = HIT_NONE;     // 鼠标悬停的命中区
    bool gateAlert = false;  // 有远程命令待裁决：底部闪一下
};

// 96 DPI 下的基准尺寸；实际窗口按 dpi/96 缩放
struct Metrics {
    int w = 420, h = 568;
    int titleH = 44;
    int heroH = 132;        // 标题栏以下的渐变高度（总渐变 = titleH + heroH）
    int rowH = 46;
    int footH = 58;
    int pad = 18;
};

Metrics DefaultMetrics();
int ScaleForWindow(HWND hwnd);

// 图标：0 显示器 / 1 黑屏 / 2 键盘 / 3 鼠标 / 4 盾牌 / 5 窗口 / 6 警告 / 7 还原
void DrawIcon(Gdiplus::Graphics& g, int id, const Gdiplus::RectF& r, const Rgba& c,
              float strokeW = 1.6f);

// 多层圆角矩形堆出来的柔和投影（GDI+ 没有模糊，用叠加近似）
void PaintShadow(Gdiplus::Graphics& g, const Gdiplus::RectF& content, float radius, float margin);

// 整窗绘制。scale = dpi/96。
void PaintWindow(Gdiplus::Graphics& g, const Model& m, const Metrics& mt, float scale);

// 命令裁决弹窗（同一套语言）
struct GateModel {
    std::wstring app;
    std::wstring cmd;
    int  remainSec = 20;
    int  index = 0;
    int  total = 1;
    int  hot = HIT_NONE;
};
void PaintGate(Gdiplus::Graphics& g, const GateModel& gm, int w, int h, float scale);

} // namespace ui
} // namespace ct
