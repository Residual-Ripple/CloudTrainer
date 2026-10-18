// =============================================================================
//  CloudTrainer - Inject.cpp
//  ---------------------------------------------------------------------------
//  反射式注入（不落盘）+ 共享内存会话管理 + 注入工作线程。
//
//  JiYuTrainer 用注入后 FindWindow + WM_COPYDATA 做 IPC；这里改成共享内存：
//  类型安全、无阻塞、可从外部观察，路径里的冒号也不会再解析错。
//  载荷映射的细节（重定位 / 导入表 / 调用桩）全部在 Reflect.cpp。
// =============================================================================
#include "Core.h"
#include "Reflect.h"

#include <algorithm>

namespace ct {

// ─────────────────────────────────────────────────────────────────────────────
//  会话
// ─────────────────────────────────────────────────────────────────────────────
bool IpcSession::Open(DWORD pid) {
    Close();
    if (!pid) return false;

    wchar_t name[128]{};
    _snwprintf(name, 127, CT_SHM_NAME_FMT, pid);
    HANDLE m = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
    if (!m) return false;

    void* p = MapViewOfFile(m, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(CtShared));
    if (!p) {
        CloseHandle(m);
        return false;
    }
    CtShared* shm = reinterpret_cast<CtShared*>(p);
    if (shm->magic != CT_IPC_MAGIC || shm->version != CT_IPC_VERSION) {
        UnmapViewOfFile(p);
        CloseHandle(m);
        return false;
    }
    map_ = m;
    shm_ = shm;
    pid_ = pid;
    return true;
}

void IpcSession::Close() {
    if (shm_) { UnmapViewOfFile(shm_); shm_ = nullptr; }
    if (map_) { CloseHandle(map_); map_ = nullptr; }
    pid_ = 0;
}

uint64_t IpcSession::HeartbeatAgeMs() const {
    if (!shm_) return 0xFFFFFFFFull;
    uint64_t hb = ipc::Heartbeat(shm_->rep);
    uint64_t now = NowMs();
    return now >= hb ? now - hb : 0;
}

void IpcSession::RequestUnlock() {
    if (!shm_) return;
    InterlockedIncrement(&shm_->req.seqUnlock);
}

void IpcSession::PushPolicy(const Settings& cfg, const std::vector<DWORD>& protect) {
    if (!shm_) return;
    CtReq* r = &shm_->req;
    r->wantTerminateGuard = cfg.blockTerminate ? 1 : 0;
    r->wantCloseGuard = cfg.blockClose ? 1 : 0;
    r->wantCmdGate = cfg.cmdGate ? 1 : 0;
    r->cmdGateTimeoutMs = cfg.cmdGateTimeout * 1000;
    r->protectAllUserApps = cfg.protectUserApps ? 1 : 0;
    r->unlockHoldMs = 3000;

    int n = (int)protect.size();
    if (n > CT_MAX_PROTECT_PIDS) n = CT_MAX_PROTECT_PIDS;
    r->protectPidCount = n;
    for (int i = 0; i < n; ++i) r->protectPids[i] = (LONG)protect[i];

    InterlockedIncrement(&r->seqPolicy);
}

void IpcSession::Beat() {
    if (!shm_) return;
    uint64_t v = NowMs();
    shm_->req.mainAliveLo = static_cast<LONG>(static_cast<uint32_t>(v));
    shm_->req.mainAliveHi = static_cast<LONG>(static_cast<uint32_t>(v >> 32));
}

void IpcSession::RequestShutdown() {
    if (!shm_) return;
    InterlockedIncrement(&shm_->req.seqShutdown);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Injector
// ─────────────────────────────────────────────────────────────────────────────
void Injector::Start(const std::wstring& dataDir) {
    if (started_) return;
    dataDir_ = dataDir;
    InitializeCriticalSection(&cs_);
    wake_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    thread_ = CreateThread(nullptr, 0, ThreadProc, this, 0, nullptr);
    started_ = true;
}

void Injector::Stop() {
    if (!started_) return;
    InterlockedExchange(&stop_, 1);
    if (wake_) SetEvent(wake_);
    if (thread_) {
        WaitForSingleObject(thread_, 3000);
        CloseHandle(thread_);
        thread_ = nullptr;
    }
    if (wake_) { CloseHandle(wake_); wake_ = nullptr; }

    EnterCriticalSection(&cs_);
    for (auto& kv : sessions_) {
        kv.second->RequestShutdown();
        delete kv.second;
    }
    sessions_.clear();
    LeaveCriticalSection(&cs_);
    started_ = false;
}

void Injector::Ensure(DWORD pid) {
    if (!started_ || !pid || pid == GetCurrentProcessId()) return;
    EnterCriticalSection(&cs_);
    bool have = sessions_.find(pid) != sessions_.end();
    if (!have) queue_.insert(pid);
    LeaveCriticalSection(&cs_);
    if (wake_) SetEvent(wake_);
}

void Injector::OpenSession(DWORD pid) {
    IpcSession* s = new IpcSession();
    if (!s->Open(pid)) {
        delete s;
        return;
    }
    EnterCriticalSection(&cs_);
    s->SetRemoteBase(bases_.count(pid) ? bases_[pid] : 0);
    sessions_[pid] = s;
    LeaveCriticalSection(&cs_);
    A().log.Info(L"IPC 会话已建立 pid=%lu", pid);
}

void Injector::PruneDead() {
    std::vector<DWORD> dead;
    EnterCriticalSection(&cs_);
    for (auto& kv : sessions_) {
        if (!IsProcessAlive(kv.first) || kv.second->HeartbeatAgeMs() > 5000) dead.push_back(kv.first);
    }
    for (DWORD pid : dead) {
        auto it = sessions_.find(pid);
        if (it != sessions_.end()) {
            it->second->RequestShutdown();
            delete it->second;
            sessions_.erase(it);
        }
    }
    LeaveCriticalSection(&cs_);
    for (DWORD pid : dead) A().log.Warn(L"IPC 会话失效，已清理 pid=%lu", pid);
}

bool Injector::InjectNow(DWORD pid, std::wstring* err) {
    std::wstring exePath = ProcessImagePath(pid);
    if (exePath.empty()) {
        *err = L"取不到目标进程路径";
        return false;
    }
    PeInfo info = ReadPeInfo(exePath);
    if (!info.ok) {
        *err = L"目标不是有效 PE";
        return false;
    }
    // 位数校验：只注入 x86
    {
        HANDLE f = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            uint8_t hdr[0x400]{};
            DWORD got = 0;
            ReadFile(f, hdr, sizeof(hdr), &got, nullptr);
            CloseHandle(f);
            if (got > 0x40) {
                uint32_t lf = *reinterpret_cast<uint32_t*>(hdr + 0x3c);
                if (lf + 6 <= got) {
                    uint16_t machine = *reinterpret_cast<uint16_t*>(hdr + lf + 4);
                    if (machine != IMAGE_FILE_MACHINE_I386) {
                        *err = Fmt(L"目标不是 x86（machine=0x%04x），跳过", machine);
                        return false;
                    }
                }
            }
        }
    }

    std::vector<uint8_t> payload;
    std::wstring perr;
    if (!LoadEmbeddedPayload(&payload, &perr)) {
        *err = perr;
        return false;
    }

    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) {
        *err = Fmt(L"OpenProcess 失败 err=%lu", GetLastError());
        return false;
    }

    uint32_t base = 0;
    bool ok = ReflectInject(h, payload, &base, err);
    if (ok) {
        EnterCriticalSection(&cs_);
        bases_[pid] = base;
        LeaveCriticalSection(&cs_);
        InterlockedIncrement(&injectedCount_);
        A().log.Info(L"注入成功 pid=%lu base=0x%08lx", pid, base);
    }
    CloseHandle(h);
    return ok;
}

DWORD WINAPI Injector::ThreadProc(LPVOID self) {
    reinterpret_cast<Injector*>(self)->Loop();
    return 0;
}

void Injector::Loop() {
    std::set<DWORD> waiting;
    while (InterlockedCompareExchange(&stop_, 0, 0) == 0) {
        DWORD pid = 0;
        EnterCriticalSection(&cs_);
        if (!queue_.empty()) {
            pid = *queue_.begin();
            queue_.erase(queue_.begin());
        }
        LeaveCriticalSection(&cs_);

        if (pid) {
            if (!IsProcessAlive(pid)) {
                // 进程已经退出，直接丢掉
            } else {
                uint64_t now = NowMs();
                bool backoff = false;
                auto it = failedAt_.find(pid);
                if (it != failedAt_.end() && now - it->second < 30000) backoff = true;
                if (!backoff) {
                    std::wstring err;
                    if (InjectNow(pid, &err)) {
                        failedAt_.erase(pid);
                        waiting.insert(pid);
                    } else {
                        failedAt_[pid] = now;
                        InterlockedIncrement(&failCount_);
                        EnterCriticalSection(&cs_);
                        lastError_ = err;
                        LeaveCriticalSection(&cs_);
                        A().log.Warn(L"注入失败 pid=%lu：%s", pid, err.c_str());
                    }
                }
            }
        }

        // 等待载荷建好共享内存
        for (auto it = waiting.begin(); it != waiting.end();) {
            DWORD wpid = *it;
            if (!IsProcessAlive(wpid)) { it = waiting.erase(it); continue; }
            bool already = false;
            EnterCriticalSection(&cs_);
            already = sessions_.find(wpid) != sessions_.end();
            LeaveCriticalSection(&cs_);
            if (already) { it = waiting.erase(it); continue; }
            if (IpcSession probe; probe.Open(wpid)) {
                probe.Close();
                OpenSession(wpid);
                it = waiting.erase(it);
            } else {
                ++it;
            }
        }

        PruneDead();

        if (wake_) WaitForSingleObject(wake_, 150);
        else Sleep(150);
    }
}

void Injector::BeatAll() {
    EnterCriticalSection(&cs_);
    for (auto& kv : sessions_) kv.second->Beat();
    LeaveCriticalSection(&cs_);
}

bool Injector::FindPending(DWORD* outPid, int* outIdx, CtPendingCmd* outCmd) {
    bool found = false;
    EnterCriticalSection(&cs_);
    for (auto& kv : sessions_) {
        CtShared* shm = kv.second->Shm();
        if (!shm) continue;
        for (int i = 0; i < CT_MAX_PENDING; ++i) {
            if (shm->pending[i].state == CT_CMD_PENDING && shm->pending[i].seq != 0) {
                *outPid = kv.first;
                *outIdx = i;
                if (outCmd) *outCmd = shm->pending[i];
                found = true;
                break;
            }
        }
        if (found) break;
    }
    LeaveCriticalSection(&cs_);
    return found;
}

void Injector::AnswerPending(DWORD pid, int idx, LONG decision) {
    EnterCriticalSection(&cs_);
    auto it = sessions_.find(pid);
    if (it != sessions_.end() && it->second->Shm()) {
        CtShared* shm = it->second->Shm();
        if (idx >= 0 && idx < CT_MAX_PENDING) {
            shm->pending[idx].decisionPid = static_cast<LONG>(GetCurrentProcessId());
            // 只在仍然等待裁决时写入：载荷自己也会超时，别把空闲槽位永久置脏
            if (InterlockedCompareExchange(&shm->pending[idx].state, decision, CT_CMD_PENDING) != CT_CMD_PENDING) {
                shm->pending[idx].state = CT_CMD_IDLE;
            }
        }
    }
    LeaveCriticalSection(&cs_);
}

void Injector::RequestUnlockAll() {
    EnterCriticalSection(&cs_);
    for (auto& kv : sessions_) kv.second->RequestUnlock();
    LeaveCriticalSection(&cs_);
}

void Injector::PushPolicy(const Settings& cfg, const std::vector<DWORD>& protect) {
    EnterCriticalSection(&cs_);
    for (auto& kv : sessions_) kv.second->PushPolicy(cfg, protect);
    LeaveCriticalSection(&cs_);
}

void Injector::ShutdownAll() {
    EnterCriticalSection(&cs_);
    for (auto& kv : sessions_) kv.second->RequestShutdown();
    LeaveCriticalSection(&cs_);
}

size_t Injector::SessionCount() {
    EnterCriticalSection(&cs_);
    size_t n = sessions_.size();
    LeaveCriticalSection(&cs_);
    return n;
}

std::wstring Injector::StatusText() {
    EnterCriticalSection(&cs_);
    size_t n = sessions_.size();
    LeaveCriticalSection(&cs_);
    if (!started_) return L"未启动";
    if (n == 0) {
        if (failCount_ > 0) return Fmt(L"未注入（失败 %d 次）", failCount_);
        return L"未注入";
    }
    return Fmt(L"已注入 %d 个进程", (int)n);
}

std::vector<Injector::Stat> Injector::Snapshot() {
    std::vector<Stat> out;
    EnterCriticalSection(&cs_);
    for (auto& kv : sessions_) {
        Stat s;
        s.pid = kv.first;
        CtShared* shm = kv.second->Shm();
        if (shm) {
            s.alive = shm->rep.alive != 0;
            s.hbAgeMs = kv.second->HeartbeatAgeMs();
            s.blockedTerm = shm->rep.blockedTerminate;
            s.blockedClose = shm->rep.blockedClose;
            s.gated = shm->rep.gatedCmd;
            s.unlockCalls = shm->rep.unlockCalls;
        }
        out.push_back(s);
    }
    LeaveCriticalSection(&cs_);
    return out;
}

std::wstring Injector::LastError() {
    EnterCriticalSection(&cs_);
    std::wstring e = lastError_;
    LeaveCriticalSection(&cs_);
    return e;
}

} // namespace ct
