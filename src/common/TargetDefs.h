// =============================================================================
//  CloudTrainer - TargetDefs.h
//  ---------------------------------------------------------------------------
//  【架构硬约束】整个工程只有本文件允许出现目标产品（联想电子教室 / NeiCloud）
//  的进程名、模块名、窗口类名、导出名、文件指纹与关键 RVA。
//  其余任何源文件都必须通过 ct::target 命名空间间接引用。
//  将来适配新版本，只改这一个文件。
//
//  数据来源：docs/MECHANISM.md（静态逆向结论），指纹为 2026-10-17 快照实测值。
// =============================================================================
#pragma once
#include <stdint.h>

namespace ct {
namespace target {

// ── 进程 ─────────────────────────────────────────────────────────────────────
inline constexpr wchar_t kProcStudent[]      = L"Student.exe";        // 学生端主进程 x86
inline constexpr wchar_t kProcMultiRender[]  = L"MultiRender.exe";    // 广播接收渲染器 x86
inline constexpr wchar_t kProcBlackSilent[]  = L"BlackSlient.exe";    // 黑屏安静（注意厂商拼写）
inline constexpr wchar_t kProcPDelKeyB[]     = L"PDelKeyB.exe";       // 键盘锁 x64 / PyInstaller
inline constexpr wchar_t kProcMulti[]        = L"Multi.exe";          // 渲染调度
inline constexpr wchar_t kProcProtect[]      = L"ProcessProtect.exe"; // 看护进程
inline constexpr wchar_t kProcStartup[]      = L"Startup.exe";        // 持久化

// ── 模块 / 导出 ─────────────────────────────────────────────────────────────
inline constexpr wchar_t kModHookLib[]  = L"HookLib.dll";   // 鼠标锁宿主，导出 Lock / SetMouseFilter
inline constexpr char    kFnLock[]      = "Lock";

// HookLib 内部结构（版本相关，仅作为 Lock 导出不可用时的兜底）
inline constexpr uint32_t kHookLibRvaHookThread = 0x1420;   // 锁线程入口（SetWindowsHookExW + 消息泵）
inline constexpr uint32_t kHookLibRvaGHook      = 0x1A1B4;  // 全局 HHOOK

// ── 窗口类 ─────────────────────────────────────────────────────────────────
// 2026-11-07 实机窗口快照（广播进行中）：类名 MultiRenderWindowClass，
// 1920x1080 @ (0,0)，style=0x94000000（WS_POPUP|WS_VISIBLE|WS_CLIPSIBLINGS，
// 运行时把 WS_CAPTION/WS_THICKFRAME 去掉了），ex=0x8（WS_EX_TOPMOST 是后加的）。
inline constexpr wchar_t kClsBroadcast[]  = L"MultiRenderWindowClass";
inline constexpr wchar_t kClsBlackScreen[] = L"DMTWnd";

// 只认一个类名太脆：换版本就是白屏。按优先级匹配，越靠前越可信。
inline constexpr const wchar_t* kClsBroadcastAliases[] = {
    L"MultiRenderWindowClass",
    L"MultiRenderWindow",
    L"McmRenderWindowClass",
    L"MultiWindowsRender",
    nullptr,
};

// ── 命名事件（注意：全产品用 Event 而不是 Mutex） ───────────────────────────
inline constexpr wchar_t kEvtStudentRunning[] = L"StudentRunning";

// ── 配置文件 ────────────────────────────────────────────────────────────────
inline constexpr wchar_t kFileGeneralCfg[] = L"general.config";
inline constexpr wchar_t kFileProtectMap[] = L"protect.map";

// ── 教师指令 id（仅用于日志与诊断，不参与控制） ─────────────────────────────
enum TeacherCmd : uint32_t {
    CmdLock         = 12,   // 黑屏安静 / Lock
    CmdScreenCast   = 19,   // 屏幕广播（type=1）
    CmdFileTransfer = 25,   // 文件传输开始
    CmdFileStop     = 38,   // 文件传输结束
    CmdConfigParse  = 45,   // 配置解析
    CmdUnlock       = 67,   // 解锁（强推断）
    CmdHeartbeat    = 83,   // 心跳
    CmdHandshake    = 85,   // 握手
    CmdNetLock      = 93,   // 网络锁定（不是黑屏）
};

// ── 厂商内部自启动白名单（命令闸门必须放行，否则会把产品自己搞坏） ───────────
inline constexpr const wchar_t* kVendorExeWhitelist[] = {
    L"BlackSlient.exe", L"PDelKeyB.exe", L"MultiRender.exe", L"MultiWindowsRender.exe",
    L"Multi.exe", L"ScreenSender.exe", L"AudioRender.exe", L"AudioSender.exe",
    L"FileTransferClient.exe", L"ScreenPen.exe", L"ScreenRecord.exe", L"SharedDesktop.exe",
    L"AudioOrVideoBroadcast.exe", L"VideoMultiStream.exe", L"vlc.exe", L"ffmpeg.exe",
    L"MmcFtpServer.exe", L"ScreenMonitor.exe", L"Loader.exe", L"ProcessProtect.exe",
    L"Student.exe", L"Teacher.exe", L"Startup.exe", L"UnInstall.exe", L"uninst.exe",
    L"remotesetting.exe", L"locationsetting.exe", L"DeviceControl_x86.exe",
    L"DeviceControl_x64.exe",
    // ★ 注意：mmcLimitConsole_x86/x64.exe 故意不列在这里。
    //   它是「网络使用限制」的执行器（Student.exe 的启动名单里有它），
    //   列进白名单等于放行断网。让它走命令闸门，由用户裁决。
    L"CSimulateMouse.exe", L"MacRender.exe", L"Group.exe", L"ecr_http.exe",
    L"VdiChannel.exe", L"typeeasy.exe", L"AdmPluginRequestServerConsole.exe",
    L"transfer_console.exe",
    L"StudentLogic.dll", L"HookLib.dll", L"HookManager.dll", L"HookProcDll.dll",
    L"InlineHook.dll",
    nullptr,   // ★ 哨兵：遍历时必须用这个终止，不要用 sizeof 推长度
};

// ── 明确禁止启动的厂商程序 ──────────────────────────────────────────────────
// 这些不是“可疑命令”，而是**网络使用限制的执行器**。命中就立刻拒绝，
// 不走裁决 —— 让用户去点一个 20 秒的弹窗，本身就是不稳定的来源。
inline constexpr const wchar_t* kVendorDenyExe[] = {
    L"mmcLimitConsole_x86.exe",
    L"mmcLimitConsole_x64.exe",
    L"mmcLimitConsole.exe",
    nullptr,
};

// ── 广播流水线（一律放行，绝不询问、绝不保护性拦截） ────────────────────────
// 名单之外的兜底规则在载荷里：只要路径在安装目录下就放行。
inline constexpr const wchar_t* kBroadcastPipeline[] = {
    L"MultiRender.exe", L"Multi.exe", L"McmRender.exe", L"MultiWindowsRender.exe",
    L"ScreenMonitor.exe", L"ScreenSender.exe", L"MacRender.exe", L"AudioRender.exe",
    nullptr,
};

// ── 需要注入的“管理类”进程 ──────────────────────────────────────────────────
// 这些进程都导入了 CreateToolhelp32Snapshot + OpenProcess + TerminateProcess，
// 也就是说“程序使用限制”（上课时清理非白名单进程）可能由其中任意一个执行，
// 不只是 Student.exe。实测里出现“广播一开始别的程序全没了”，就是这一族干的。
inline constexpr const wchar_t* kVendorGuardExe[] = {
    L"Student.exe", L"ProcessProtect.exe", L"Loader.exe", L"Multi.exe",
    // 网络限制执行器也注入：万一没杀掉（权限不足/被看护拉起），
    // 至少它的 DeviceIoControl 会被我们的 hook 挡住。
    L"mmcLimitConsole_x86.exe", L"mmcLimitConsole_x64.exe", L"mmcLimitConsole.exe",
    nullptr,
};

// ── 网络限制用的设备 ────────────────────────────────────────────────────────
// Student.exe 里有 "\\.\Inspect" 这个打开串，对应 inspect.sys（WFP 重定向样例）。
// “网络使用限制”就是通过它下发过滤器；把它挡住比事后删防火墙规则干净得多。
inline constexpr wchar_t kInspectDevice[] = L"\\\\.\\Inspect";

// ── 指纹（file size + PE TimeDateStamp） ────────────────────────────────────
struct Fingerprint {
    const wchar_t* file;
    uint32_t       size;
    uint32_t       timeDateStamp;
    bool           critical;   // true = 主链件，缺失/不匹配直接降级
};

inline constexpr Fingerprint kFingerprints[] = {
    // file                    size        TimeDateStamp   critical
    { L"Student.exe",          1951584u,   0x635F7F21u,    true  },
    { L"StudentLogic.dll",      737032u,   0x64119005u,    true  },
    { L"MainLogic.dll",         908640u,   0x635F7614u,    false },
    { L"HookLib.dll",           132456u,   0x626B6676u,    false },
    { L"Multi.exe",             443744u,   0x635F5EF0u,    false },
    { L"MultiRender.exe",       645120u,   0x650BB8E9u,    false },
    { L"BlackSlient.exe",       493928u,   0x599E7AE3u,    false },
    { L"PDelKeyB.exe",         6792016u,   0x5F2E9A84u,    false },
};
inline constexpr int kFingerprintCount =
    static_cast<int>(sizeof(kFingerprints) / sizeof(kFingerprints[0]));

// ── 组播与端口（诊断输出用） ────────────────────────────────────────────────
inline constexpr const wchar_t* kMcastControl = L"225.0.0.37";
inline constexpr const wchar_t* kMcastScreen  = L"225.0.0.70/72";
inline constexpr uint16_t kPortConnect        = 9003;
inline constexpr uint16_t kPortRcf            = 8444;
inline constexpr uint16_t kPortFileXfer       = 9100;
inline constexpr uint16_t kPortController     = 8040;

} // namespace target
} // namespace ct
