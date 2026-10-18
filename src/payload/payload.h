// =============================================================================
//  CloudTrainerPayload - payload.h
//  注入到目标进程内运行的载荷。只依赖 Win32，不用 STL 容器，
//  避免在“手工映射”环境下出现 CRT 初始化顺序问题。
// =============================================================================
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <shellapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../common/CtIpc.h"
#include "../common/TargetDefs.h"

// 由 call1.S 提供：安全调用"单参数、约定未知"的函数
// （HookLib!Lock 是 cdecl，别的版本可能是 stdcall，这个桩两种都能兜住）
extern "C" void ct_call1(void* fn, int arg);

namespace ctpayload {

// ── 全局 ────────────────────────────────────────────────────────────────────
extern CtShared* g_shm;
extern HANDLE    g_map;

// ── payload.cpp ─────────────────────────────────────────────────────────────
DWORD WINAPI PayloadThread(LPVOID param);
void  SetStop(void);
bool  ResolveHookLib(void);
void  DoUnlockMouse(void);
int   QuitOwnHookThreads(void);
void  ApplyPolicy(void);

// ── hooks.cpp ───────────────────────────────────────────────────────────────
void Hooks_Install(void);
void Hooks_Remove(void);
void Hooks_Rescan(void);
int  Hooks_PatchCount(void);
void Hooks_HandlePending(void);

} // namespace ctpayload
