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
inline constexpr wchar_t kClsBroadcast[]  = L"MultiRenderWindowClass";
inline constexpr wchar_t kClsBlackScreen[] = L"DMTWnd";

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
    L"DeviceControl_x64.exe", L"mmcLimitConsole_x86.exe", L"mmcLimitConsole_x64.exe",
    L"CSimulateMouse.exe", L"MacRender.exe", L"Group.exe", L"ecr_http.exe",
    L"VdiChannel.exe", L"typeeasy.exe", L"AdmPluginRequestServerConsole.exe",
    L"transfer_console.exe",
    L"StudentLogic.dll", L"HookLib.dll", L"HookManager.dll", L"HookProcDll.dll",
    L"InlineHook.dll",
    nullptr,   // ★ 哨兵：遍历时必须用这个终止，不要用 sizeof 推长度
};

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
