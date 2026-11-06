// =============================================================================
//  CloudTrainer - CtIpc.h
//  ---------------------------------------------------------------------------
//  主程序 <-> 注入载荷 的通信协议。
//
//  设计取舍（相对 JiYuTrainer 的 WM_COPYDATA + 冒号字符串协议）：
//    * 共享内存 + 序号计数器，类型安全、无阻塞、可从外部观察；
//    * 单向写：主程序只写 req，载荷只写 rep / pending，不需要锁；
//    * 心跳：载荷每 500ms 刷新，主程序 3s 未更新即判定会话死亡。
//
//  载荷运行在目标进程（普通用户完整性级别），主程序是管理员（高完整性）。
//  因此必须由**载荷创建**映射、主程序打开 —— 反过来的话，低完整性进程
//  打不开高完整性进程创建的 Section（Windows 的 no-read-up 强制策略）。
// =============================================================================
#pragma once

#include <windows.h>
#include <stdint.h>

#define CT_SHM_NAME_FMT    L"Local\\CloudTrainer.Shm.%lu"
#define CT_EVENT_NAME_FMT  L"Local\\CloudTrainer.Ready.%lu"

#define CT_IPC_MAGIC   0x43544D31u   /* 'CTM1' */
#define CT_IPC_VERSION 3

/* rep.flags 位 */
#define CT_FLAG_INJECTED    0x00000001
#define CT_FLAG_HOOKLIB     0x00000002
#define CT_FLAG_MOUSEHOOK   0x00000004
#define CT_FLAG_TERMGUARD   0x00000008
#define CT_FLAG_CLOSEGUARD  0x00000010
#define CT_FLAG_CMDGATE     0x00000020
#define CT_FLAG_LASTFAILED  0x00000040

/* pending.state */
#define CT_CMD_IDLE      0
#define CT_CMD_PENDING   1
#define CT_CMD_ALLOW     2
#define CT_CMD_DENY      3
#define CT_CMD_ALLOWALL  4

#define CT_MAX_PROTECT_PIDS 8
#define CT_MAX_PENDING      4

#pragma pack(push, 4)

/* 主程序 -> 载荷。写方：主程序。读方：载荷。 */
typedef struct CtReq {
    volatile LONG seqUnlock;        /* +1 = 请求一次鼠标解锁 */
    volatile LONG seqPolicy;        /* +1 = 策略已变更，重新读取下面的开关 */
    volatile LONG seqShutdown;      /* +1 = 卸载所有 hook 并退出载荷线程 */

    volatile LONG wantTerminateGuard;   /* 0/1 拦截对 protectPids 的 TerminateProcess */
    volatile LONG wantCloseGuard;       /* 0/1 拦截跨进程 WM_CLOSE */
    volatile LONG wantCmdGate;          /* 0/1 远程命令闸门 */
    volatile LONG cmdGateTimeoutMs;     /* 等待用户裁决的超时 */

    volatile LONG protectPidCount;
    volatile LONG protectPids[CT_MAX_PROTECT_PIDS];
    volatile LONG unlockHoldMs;     /* 解锁后保持多久（对抗重新上锁），默认 3000 */
    volatile LONG protectAllUserApps; /* 1 = 拦截对“任意非厂商用户程序”的结束请求（G5） */
    volatile LONG wantNetGuard;       /* 1 = 拒绝打开 \\.\Inspect 设备（挡住网络限制） */
    volatile LONG mainAliveLo;      /* 主程序心跳（GetTickCount64），用于超时失败放行 */
    volatile LONG mainAliveHi;
    wchar_t       vendorDir[260];   /* 厂商安装目录：此目录下的一切进程一律放行（广播流水线） */
} CtReq;

/* 载荷 -> 主程序 */
typedef struct CtRep {
    volatile LONG alive;
    volatile LONG flags;
    volatile LONG heartbeatLo;      /* GetTickCount64 低 32 位 */
    volatile LONG heartbeatHi;
    volatile LONG hookLibFound;
    volatile LONG mouseHook;        /* 当前 g_hHook 值（0 = 未上锁） */
    volatile LONG blockedTerminate;
    volatile LONG blockedClose;
    volatile LONG gatedCmd;
    volatile LONG unlockCalls;
    volatile LONG inprocUnlocks;    /* 进程内 UnhookWindowsHookEx 成功次数 */
    volatile LONG patchCount;       /* 已打补丁的 IAT 槽位数 */
    volatile LONG gateCalls;        /* 进入命令闸门的次数（诊断用） */
    volatile LONG devBlocked;       /* 被拒绝的 \\.\Inspect 打开次数 */
    volatile LONG ioctlBlocked;     /* 被拒绝的、针对该设备的 DeviceIoControl 次数 */
    volatile LONG deniedLaunch;     /* 直接拒绝启动的次数（网络限制执行器） */
    volatile LONG unknownKills;     /* 拿不到目标 pid 的结束请求（G5 的盲区计数） */
    wchar_t       lastTermName[64]; /* 最近一次被拦下的目标进程名 */
    volatile LONG lastError;
} CtRep;

/* 需要用户裁决的远程命令 */
typedef struct CtPendingCmd {
    volatile LONG state;            /* CT_CMD_* */
    volatile LONG seq;
    volatile LONG hostPid;
    volatile LONG decisionPid;
    wchar_t       app[260];
    wchar_t       cmd[512];
} CtPendingCmd;

typedef struct CtShared {
    DWORD         magic;
    WORD          version;
    WORD          reserved;
    DWORD         ownerPid;
    DWORD         hostBuild;
    CtReq         req;
    CtRep         rep;
    CtPendingCmd  pending[CT_MAX_PENDING];
} CtShared;

#pragma pack(pop)

#ifdef __cplusplus
namespace ct { namespace ipc {
inline uint64_t Heartbeat(const CtRep& r) {
    return (static_cast<uint64_t>(static_cast<uint32_t>(r.heartbeatHi)) << 32) |
           static_cast<uint32_t>(r.heartbeatLo);
}
inline void SetHeartbeat(CtRep* r, uint64_t v) {
    r->heartbeatLo = static_cast<LONG>(static_cast<uint32_t>(v));
    r->heartbeatHi = static_cast<LONG>(static_cast<uint32_t>(v >> 32));
}
}} // namespace ct::ipc
#endif
