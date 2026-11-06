// =============================================================================
//  CloudTrainer - Core.h
//  ---------------------------------------------------------------------------
//  主程序所有模块的声明。单线程 UI（WM_TIMER 驱动）+ 一个注入工作线程，
//  没有线程池、没有全局对象跨线程裸访问。
// =============================================================================
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include <wctype.h>

#include <string>
#include <vector>
#include <map>
#include <set>

#include "TargetDefs.h"
#include "UiTheme.h"
#include "CtIpc.h"

namespace ct {

// ─────────────────────────────────────────────────────────────────────────────
//  常量 / 消息
// ─────────────────────────────────────────────────────────────────────────────
inline constexpr wchar_t kAppName[]    = L"CloudTrainer";
inline constexpr wchar_t kAppVersion[] = L"1.4.0";
inline constexpr wchar_t kInstanceEvent[] = L"Local\\CloudTrainer.Instance";

enum : UINT {
    WM_CT_TRAY       = WM_APP + 1,   // 托盘回调
    WM_CT_SHOWSTATUS = WM_APP + 2,   // 第二实例唤起
    WM_CT_WORKER     = WM_APP + 3,   // 注入线程完成通知
    WM_CT_TICK       = WM_APP + 4,   // 内部节拍
};

// 命令 id（托盘 / 窗口按钮）
enum CmdId : int {
    ID_TRAY_STATUS = 100,
    ID_TRAY_UNLOCK,          // 立即解除控制（键鼠）
    ID_TRAY_RESTORE,
    ID_TRAY_LOGDIR,
    ID_TRAY_ABOUT,
    ID_TRAY_EXIT,

    ID_TOGGLE_BASE = 200,          // +0..7 能力开关
    ID_TOGGLE_END  = 208,

    ID_GATE_ALLOW = 300,
    ID_GATE_DENY,
    ID_GATE_ALLOWALL,

    ID_BTN_RESTORE = 400,
    ID_BTN_LOGDIR,
    ID_BTN_ABOUT,
};

// 能力序号（与托盘菜单、状态窗、Settings 一一对应）
enum Cap : int {
    CAP_FIX_BROADCAST = 0,
    CAP_KILL_BLACK,
    CAP_UNLOCK_KEYBOARD,
    CAP_UNLOCK_MOUSE,
    CAP_BLOCK_TERMINATE,
    CAP_BLOCK_CLOSE,
    CAP_CMD_GATE,
    CAP_COUNT
};

// ─────────────────────────────────────────────────────────────────────────────
//  基础工具
// ─────────────────────────────────────────────────────────────────────────────
std::wstring Fmt(const wchar_t* fmt, ...);
std::wstring ToLower(const std::wstring& s);
bool IEquals(const std::wstring& a, const wchar_t* b);
bool EndsWithI(const std::wstring& s, const wchar_t* suffix);
bool StartsWithI(const std::wstring& s, const wchar_t* prefix);
std::wstring BaseName(const std::wstring& path);
std::wstring Trim(const std::wstring& s);
bool ParseBool(const std::wstring& v, bool def);
int  ParseInt(const std::wstring& v, int def);

std::wstring GetExePath();
std::wstring GetExeDir();
std::wstring GetDataDir();
bool EnsureDir(const std::wstring& p);
bool FileExists(const std::wstring& p);
bool ReadAllBytes(const std::wstring& path, std::vector<uint8_t>* out);
uint64_t NowMs();
bool IsElevated();
bool HardenSelf(std::wstring* why);   // DACL 拒绝 PROCESS_TERMINATE
// 广播窗口判定（窗口修正与 --winlist 共用同一套规则）
bool IsBroadcastWindowEx(HWND hwnd, RECT* monRect, std::wstring* why);
bool EnablePrivilege(const wchar_t* name);
bool IsProcessAlive(DWORD pid);
std::wstring ProcessImagePath(DWORD pid);
std::wstring ProcessBaseName(DWORD pid);
bool TerminatePid(DWORD pid, DWORD* lastErr);
std::vector<DWORD> EnumPidsByName(const wchar_t* exeName);

std::string  WideToUtf8(const std::wstring& s);
std::wstring Utf8ToWide(const std::string& s);
std::wstring NowStamp();          // 2026-10-18 11:20:31.123

// PE 指纹（只读，不加载）
struct PeInfo { uint32_t size = 0; uint32_t timeDateStamp = 0; bool ok = false; };
PeInfo ReadPeInfo(const std::wstring& path);

// 内嵌载荷
bool LoadEmbeddedPayload(std::vector<uint8_t>* out, std::wstring* err);

// ─────────────────────────────────────────────────────────────────────────────
//  Logger
// ─────────────────────────────────────────────────────────────────────────────
class Logger {
public:
    void Init(const std::wstring& dir);
    void Info(const wchar_t* fmt, ...);
    void Warn(const wchar_t* fmt, ...);
    void Error(const wchar_t* fmt, ...);
    void Raw(const wchar_t* level, const wchar_t* msg);
    std::vector<std::wstring> Recent(size_t n) const;
    std::wstring Dir() const { return dir_; }
    std::wstring Path() const { return path_; }
private:
    void Append(const std::wstring& line);
    mutable CRITICAL_SECTION cs_{};
    bool init_ = false;
    std::wstring dir_, path_;
    std::vector<std::wstring> ring_;
    size_t ringMax_ = 400;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Settings
// ─────────────────────────────────────────────────────────────────────────────
struct Settings {
    bool fixBroadcast    = true;
    int  fixWidth        = 1280;
    int  fixHeight       = 720;
    bool keepAspect      = true;
    bool allowTopmost    = false;

    bool killBlackScreen = true;
    bool unlockKeyboard  = true;
    bool unlockMouse     = true;
    bool blockTerminate  = true;
    bool blockClose      = true;
    bool cmdGate         = true;
    bool protectUserApps = true;    // G5：拦截对任意非厂商用户程序的结束请求
    int  cmdGateTimeout  = 20;      // 秒
    bool autoInject      = true;
    std::wstring installDirHint;     // 非默认安装路径时手工指定

    // 启动时是否把所有能力强制打开（默认 1）。
    // =1：每次启动都全开，运行时可以临时关，但重启后恢复全开；
    // =0：完全按 ini 里的开关来（关掉的就一直关着）。
    bool startupEnableAll = true;
    bool selfProtect      = true;   // 拒绝其它进程结束自己
    bool appShield        = true;   // 给所有非厂商用户程序加"禁止结束"的 DACL
    bool netGuard         = true;   // 拒绝打开 \\.\Inspect / 拒绝其 IOCTL
    bool netKillLimit     = true;   // 发现 mmcLimitConsole 直接结束（网络限制执行器）
    bool netStopDriver    = false;  // 额外停掉 Inspect 驱动服务（更彻底，默认关）
    bool strictVersion    = false;  // 1 = 指纹不符就降只读

    void Load(const std::wstring& path);
    void Save(const std::wstring& path) const;
    bool* CapPtr(int cap);
    bool  Cap(int cap) const;
};

const wchar_t* CapName(int cap);
const wchar_t* CapDesc(int cap);

// ─────────────────────────────────────────────────────────────────────────────
//  Locator —— 所有对目标产品的“认识”都走这里
// ─────────────────────────────────────────────────────────────────────────────
struct ProcEntry {
    DWORD pid = 0;
    std::wstring exe;
};

class Locator {
public:
    void SetHint(const std::wstring& d) { hint_ = d; }
    void Refresh(bool force = false);
    const std::vector<ProcEntry>& Procs() const { return procs_; }

    std::vector<DWORD> PidsByExe(const wchar_t* exe) const;
    DWORD FirstPid(const wchar_t* exe) const;
    bool  AnyRunning(const wchar_t* exe) const;

    // 缓存 2s；只对候选进程枚举模块
    std::vector<DWORD> PidsWithModule(const wchar_t* dll, bool force = false);
    bool ModuleRange(DWORD pid, const wchar_t* dll, uint32_t* base, uint32_t* size);

    std::wstring ImagePath(DWORD pid) const;
    bool FindInstallDir(std::wstring* out, bool force = false);
    bool StudentEventExists() const;

private:
    std::vector<ProcEntry> procs_;
    uint64_t lastRefresh_ = 0;
    struct ModCache { uint64_t stamp; std::vector<DWORD> pids; };
    std::map<std::wstring, ModCache> modCache_;
    std::wstring installDir_;
    std::wstring hint_;
    uint64_t installStamp_ = 0;
};

// 给"别人"的进程也加一条 DENY PROCESS_TERMINATE（需要 WRITE_DAC）
int ShieldApps(Locator& loc, const std::wstring& installDir, std::set<DWORD>& done);

// ─────────────────────────────────────────────────────────────────────────────
//  VersionGuard —— 指纹比对与降级
// ─────────────────────────────────────────────────────────────────────────────
enum class EnvLevel { Unknown = 0, ReadOnly, Degraded, Full };
const wchar_t* EnvLevelName(EnvLevel lv);

class VersionGuard {
public:
    void SetStrict(bool s) { strictVersion = s; }
    void Evaluate(const std::wstring& installDir);
    EnvLevel Level() const { return level_; }
    const std::wstring& InstallDir() const { return dir_; }
    std::wstring Detail() const { return detail_; }
    bool FullMode() const { return level_ == EnvLevel::Full; }
private:
    EnvLevel level_ = EnvLevel::Unknown;
    bool strictVersion = false;
    std::wstring detail_;
    std::wstring dir_;
};

// ─────────────────────────────────────────────────────────────────────────────
//  WindowFixer —— G1 广播窗口化
// ─────────────────────────────────────────────────────────────────────────────
class WindowFixer {
public:
    void Tick(const Settings& cfg, bool enabled);
    int  FixedCount() const { return fixedCount_; }
    int  TrackedCount() const { return static_cast<int>(tracks_.size()); }
    void RestoreAll();
    std::wstring StatusText() const;
private:
    struct Track {
        HWND hwnd = nullptr;
        int fixes = 0;          // 尺寸纠正次数
        int enforces = 0;       // 样式/置顶纠正次数
        uint64_t firstMs = 0;
        uint64_t lastMs = 0;
        bool ncWarned = false;  // 是否已经提示过"非客户区被剥离"
    };
    struct TickCtx {
        WindowFixer* self = nullptr;
        const Settings* cfg = nullptr;
    };
    static BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lp);
    static bool IsBroadcastWindow(HWND hwnd, RECT* monRect);
    bool ApplyFix(HWND hwnd, const Settings& cfg);
    Track* Find(HWND hwnd);
    std::vector<Track> tracks_;
    int fixedCount_ = 0;
    HWND lastHwnd_ = nullptr;
};

// ─────────────────────────────────────────────────────────────────────────────
//  BlackGuard —— G2 黑屏压制
// ─────────────────────────────────────────────────────────────────────────────
class BlackGuard {
public:
    void Tick(bool enabled);
    size_t KillCount() const { return kills_; }
    std::wstring StatusText() const;
private:
    size_t kills_ = 0;
    uint64_t rateWindow_ = 0;
    int rateCount_ = 0;
    uint64_t backoffUntil_ = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  InputUnlocker —— G3 键盘 / G4 鼠标
// ─────────────────────────────────────────────────────────────────────────────
class InputUnlocker {
public:
    void Tick(const Settings& cfg, const Locator& loc, bool kbEnabled, bool mouseEnabled);

    // 立即执行一次（不看 500ms 节流）。启动时 / 托盘 / 热键 / 检测到新锁都用它。
    void UnlockNow(const Locator& loc, bool kbEnabled, bool mouseEnabled);

    size_t KeyKills() const { return keyKills_; }
    size_t MouseUnlocks() const { return mouseUnlocks_; }
    bool   KeyboardLockPresent() const { return kbPresent_; }
    bool   MouseHookPresent() const { return mousePresent_; }

    // 外部通道是否不可靠（需要主程序改用进程内 UnhookWindowsHookEx）
    bool   NeedInProc() const { return needInProc_; }
    bool   HasLockHost() const { return lockHost_; }
    std::wstring LastResult() const { return lastResult_; }
    std::wstring StatusText() const;

private:
    void KillKeyboardLocks(bool enabled);
    // force=忽略模块缓存；waitMs=投递后等待线程退出的时间（0 表示不阻塞 UI）；
    // verbose=无论状态变化都写日志
    void AttemptMouse(const Locator& loc, bool force, DWORD waitMs, bool verbose);

    size_t keyKills_ = 0;
    size_t mouseUnlocks_ = 0;
    size_t extTries_ = 0;
    bool kbPresent_ = false;
    bool mousePresent_ = false;
    bool needInProc_ = false;
    bool lockHost_ = false;
    uint64_t lastMouseTry_ = 0;
    std::wstring lastResult_;
};

// ─────────────────────────────────────────────────────────────────────────────
//  IpcClient —— 单个目标进程的共享内存会话
// ─────────────────────────────────────────────────────────────────────────────
class IpcSession {
public:
    ~IpcSession() { Close(); }
    bool Open(DWORD pid);
    void Close();
    bool Valid() const { return shm_ != nullptr; }
    CtShared* Shm() { return shm_; }
    DWORD Pid() const { return pid_; }
    uint64_t HeartbeatAgeMs() const;

    void RequestUnlock();
    void PushPolicy(const Settings& cfg, const std::vector<DWORD>& protect,
                    const std::wstring& vendorDir);
    void Beat();
    void RequestShutdown();
    void SetRemoteBase(uint32_t base) { remoteBase_ = base; }
    uint32_t RemoteBase() const { return remoteBase_; }
private:
    HANDLE   map_ = nullptr;
    CtShared* shm_ = nullptr;
    DWORD    pid_ = 0;
    uint32_t remoteBase_ = 0;
    LONG     lastSeqUnlock_ = 0;
    LONG     lastSeqPolicy_ = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Injector —— 反射注入 + 会话管理 + 工作线程
// ─────────────────────────────────────────────────────────────────────────────
class Injector {
public:
    void Start(const std::wstring& dataDir);
    void Stop();

    void Ensure(DWORD pid);                 // 排队（去重）
    void RequestUnlockAll();
    void PushPolicy(const Settings& cfg, const std::vector<DWORD>& protect,
                    const std::wstring& vendorDir);
    void BeatAll();
    void ShutdownAll();

    bool FindPending(DWORD* outPid, int* outIdx, CtPendingCmd* outCmd);
    void AnswerPending(DWORD pid, int idx, LONG decision);

    size_t SessionCount();
    std::wstring StatusText();
    struct Stat {
        DWORD pid = 0;
        bool alive = false;
        uint64_t hbAgeMs = 0;
        LONG blockedTerm = 0, blockedClose = 0, gated = 0, unlockCalls = 0, devBlocked = 0;
        LONG inprocUnlocks = 0;
        LONG ioctlBlocked = 0;
        LONG deniedLaunch = 0;
    };
    std::vector<Stat> Snapshot();

    int InjectedCount() { return (int)injectedCount_; }
    int FailCount() { return (int)failCount_; }
    std::wstring LastError();
    std::wstring LastBlockedName();

    // 某个会话里 g_hHook 非空 = 鼠标确实被钩住了（比外部猜更可靠）
    bool AnyMouseHook();

private:
    static DWORD WINAPI ThreadProc(LPVOID self);
    void Loop();
    bool InjectNow(DWORD pid, std::wstring* err);
    void PruneDead();
    void OpenSession(DWORD pid);

    CRITICAL_SECTION cs_{};
    bool started_ = false;
    HANDLE thread_ = nullptr;
    HANDLE wake_ = nullptr;
    volatile LONG stop_ = 0;

    std::set<DWORD> queue_;
    std::map<DWORD, uint64_t> failedAt_;    // pid -> 上次失败时间（30s 退避）
    std::map<DWORD, uint64_t> injectedAt_;  // pid -> 上次注入时间（防止反复注入堆线程）
    std::map<DWORD, IpcSession*> sessions_;
    std::map<DWORD, uint32_t> bases_;       // pid -> 载荷映射基址（卸载时释放）
    std::wstring dataDir_;
    std::wstring lastError_;

    volatile LONG injectedCount_ = 0;
    volatile LONG failCount_ = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Ui —— 托盘 / 状态窗 / 裁决窗 / 假黑屏（全部原生 Win32，不用 Sciter）
// ─────────────────────────────────────────────────────────────────────────────
class Ui {
public:
    bool Create(HWND msgWnd, HINSTANCE hInst);
    void Destroy();

    void Update();                     // 由主循环节拍调用
    void ShowMenu(POINT pt);
    void ToggleStatus();
    void ShowStatus();

    void ShowGate(const CtPendingCmd& cmd, int index);
    void HideGate();
    void UpdateGate();
    bool GateVisible() const;
    int  GateIndex() const { return gateIndex_; }

    void ShowFakeBlack(bool on);
    bool FakeBlackActive() const { return fakeBlack_ != nullptr; }
    void DestroyFakeBlack();

    HWND MsgWnd() const { return msgWnd_; }
    HWND StatusWnd() const { return statusWnd_; }
    HWND GateWndRef() const { return gateWnd_; }

private:
    static Ui* s_self_;
    static LRESULT CALLBACK StatusProc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK GateProc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK BlackProc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK BlackKeyboardHook(int, WPARAM, LPARAM);
    static Ui* SelfFrom(HWND h);

    void CreateStatus();
    void BuildModel();
    int  HitTest(int x, int y) const;
    bool EnsureSurface(int w, int h);
    void ReleaseSurface();
    void PaintStatus();
    void PaintGateSurface();

    void CreateGate();
    int  GateHitTest(int x, int y) const;

    HWND msgWnd_ = nullptr;
    HWND statusWnd_ = nullptr;
    HWND gateWnd_ = nullptr;
    HWND fakeBlack_ = nullptr;
    HHOOK kbHook_ = nullptr;

    HICON iconNormal_ = nullptr;
    HICON iconAlert_ = nullptr;
    HICON iconSmall_ = nullptr;
    bool trayAdded_ = false;
    bool statusVisible_ = false;
    int  updateTick_ = 0;
    int  hot_ = -1;
    int  gateHot_ = -1;

    ui::Model  model_;
    ui::Metrics metrics_;
    float scale_ = 1.0f;

    HDC     mem_ = nullptr;
    HBITMAP memBmp_ = nullptr;
    void*   memBits_ = nullptr;
    int     memW_ = 0;
    int     memH_ = 0;
    int     margin_ = 16;

    ui::GateModel gmodel_;
    std::wstring sig_;
    int  gateIndex_ = -1;
    int  gateTick_ = 0;
    std::wstring gateApp_;
    std::wstring gateCmd_;
};

// ─────────────────────────────────────────────────────────────────────────────
//  App
// ─────────────────────────────────────────────────────────────────────────────
class App {
public:
    static App& I();

    int  Run(HINSTANCE hInst, int nCmdShow);
    void RequestQuit();
    void ShowStatus();

    // 供 WndProc 转发
    void OnTimer();
    void OnCommand(int id, int code);
    void OnTray(UINT msg);
    void ToggleCap(int cap);
    void RestoreAll(bool exitAfter);
    void UnlockControlNow(bool announce);   // 立即抢回键鼠控制
    void NetGuardTick(bool operational, uint64_t now);   // 网络限制的反制
    void DecideGate(int decision);
    void RequestRestoreHotkey();     // Ctrl+Alt+H：3 秒内两次才执行

    Settings       cfg;
    Logger         log;
    Locator        loc;
    VersionGuard   ver;
    WindowFixer    fixer;
    BlackGuard     black;
    InputUnlocker  input;
    Injector       inj;
    Ui             ui;
    std::wstring   dataDir;
    HINSTANCE      hInst = nullptr;
    HWND           msgWnd = nullptr;
    bool           quitting = false;
    bool           mouseActive = false;

private:
    bool Init();
    void Tick();
    std::vector<DWORD> ProtectPids();

    uint64_t nextLoc_ = 0;
    uint64_t nextVer_ = 0;
    uint64_t nextBeat_ = 0;
    uint64_t nextPolicy_ = 0;
    bool     policyDirty_ = true;
    uint64_t restoreConfirmUntil_ = 0;
    uint64_t nextShield_ = 0;
    uint64_t nextNet_ = 0;
    uint64_t nextDriverStop_ = 0;
    int      netKills_ = 0;
    bool     driverStopLogged_ = false;
    uint64_t nextInProc_ = 0;          // 进程内解锁请求节流
    std::set<DWORD> shieldedPids_;
    std::set<DWORD> lockHosts_;        // 上一轮看到的 HookLib 宿主（检测新锁）
    size_t   lastSessionCount_ = 0;
    uint64_t lastLockSeen_ = 0;
    DWORD    gatePid_ = 0;
    int      gateIdx_ = -1;
};

// 全局访问
App& A();

// 探针模式
int RunProbe();       // --probe：只读体检
int RunNetProbe();    // --netprobe：网络受限的成因
int RunUnlockOnce();  // --unlock：不带界面，一次性解除键鼠锁
int RunUiPreview(const wchar_t* outDir);  // --uipreview：把自绘界面渲染成 PNG
int RunWinList();                          // --winlist：列出所有可见窗口 + 广播判定

} // namespace ct
