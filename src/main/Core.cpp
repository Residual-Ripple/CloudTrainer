// =============================================================================
//  CloudTrainer - Core.cpp
//  基础工具 / 日志 / 配置 / 目标发现 / 版本指纹
// =============================================================================
#include "Core.h"

#include <winreg.h>
#include <aclapi.h>
#include <algorithm>
#include <cstdarg>
#include <cstring>

namespace ct {

// ─────────────────────────────────────────────────────────────────────────────
//  基础工具
// ─────────────────────────────────────────────────────────────────────────────
std::wstring Fmt(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    buf[0] = 0;
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 2047, fmt, ap);
    buf[2047] = 0;
    va_end(ap);
    return std::wstring(buf);
}

std::wstring ToLower(const std::wstring& s) {
    std::wstring r = s;
    for (auto& c : r) c = static_cast<wchar_t>(towlower(c));
    return r;
}

bool IEquals(const std::wstring& a, const wchar_t* b) {
    if (!b) return false;
    return _wcsicmp(a.c_str(), b) == 0;
}

bool EndsWithI(const std::wstring& s, const wchar_t* suffix) {
    if (!suffix) return false;
    size_t n = wcslen(suffix);
    if (s.size() < n) return false;
    return _wcsicmp(s.c_str() + s.size() - n, suffix) == 0;
}

bool StartsWithI(const std::wstring& s, const wchar_t* prefix) {
    if (!prefix) return false;
    size_t n = wcslen(prefix);
    if (s.size() < n) return false;
    return _wcsnicmp(s.c_str(), prefix, n) == 0;
}

std::wstring BaseName(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return (p == std::wstring::npos) ? path : path.substr(p + 1);
}

std::wstring Trim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return L"";
    size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool ParseBool(const std::wstring& v, bool def) {
    std::wstring t = ToLower(Trim(v));
    if (t == L"1" || t == L"true" || t == L"yes" || t == L"on") return true;
    if (t == L"0" || t == L"false" || t == L"no" || t == L"off") return false;
    return def;
}

int ParseInt(const std::wstring& v, int def) {
    std::wstring t = Trim(v);
    if (t.empty()) return def;
    return _wtoi(t.c_str());
}

std::wstring GetExePath() {
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
    if (n == 0) return L"";
    return std::wstring(buf, n);
}

std::wstring GetExeDir() {
    std::wstring p = GetExePath();
    size_t s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? L"." : p.substr(0, s);
}

std::wstring GetDataDir() {
    wchar_t* p = nullptr;
    std::wstring r;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &p)) && p) {
        r = std::wstring(p) + L"\\CloudTrainer";
    }
    if (p) CoTaskMemFree(p);
    if (r.empty()) {
        wchar_t tmp[MAX_PATH];
        DWORD n = GetTempPathW(MAX_PATH, tmp);
        if (n) r = std::wstring(tmp) + L"CloudTrainer";
    }
    EnsureDir(r);
    return r;
}

bool EnsureDir(const std::wstring& p) {
    if (p.empty()) return false;
    if (CreateDirectoryW(p.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool ReadAllBytes(const std::wstring& path, std::vector<uint8_t>* out) {
    out->clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (64ll << 20)) {
        CloseHandle(h);
        return false;
    }
    out->resize(static_cast<size_t>(sz.QuadPart));
    DWORD total = 0;
    while (total < out->size()) {
        DWORD got = 0;
        if (!ReadFile(h, out->data() + total, static_cast<DWORD>(out->size() - total), &got, nullptr) || got == 0) {
            CloseHandle(h);
            out->clear();
            return false;
        }
        total += got;
    }
    CloseHandle(h);
    return true;
}

uint64_t NowMs() { return GetTickCount64(); }

bool IsElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{};
    DWORD sz = sizeof(el);
    BOOL ok = GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &sz);
    CloseHandle(tok);
    return ok && el.TokenIsElevated != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  自我保护：给"本进程对象"加一条 DENY ACE，拒绝当前用户 PROCESS_TERMINATE。
//
//  能挡住什么：Student.exe / ProcessProtect.exe 这类以**同一个用户身份**运行的
//            杀进程逻辑（TerminateProcess、taskkill /f 都要这个权限）。
//  挡不住什么：SYSTEM 权限的杀进程、驱动层、Job Object 的
//            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE。
//  不影响：自己退出（我们走消息循环，不调 TerminateProcess）。
// ─────────────────────────────────────────────────────────────────────────────
namespace {

bool CurrentUserSid(std::vector<uint8_t>* out) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    std::vector<uint8_t> buf(len ? len : 256);
    if (!GetTokenInformation(tok, TokenUser, buf.data(), (DWORD)buf.size(), &len)) {
        CloseHandle(tok);
        return false;
    }
    auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    const DWORD sidLen = GetLengthSid(tu->User.Sid);
    out->resize(sidLen);
    const bool ok = CopySid(sidLen, out->data(), tu->User.Sid) != FALSE;
    CloseHandle(tok);
    return ok;
}

bool DenyTerminateOn(HANDLE proc, const std::vector<uint8_t>& sid, std::wstring* why) {
    PACL oldAcl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(proc, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, &oldAcl, nullptr, &sd) != ERROR_SUCCESS) {
        if (why) *why = Fmt(L"GetSecurityInfo err=%lu", GetLastError());
        return false;
    }

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = PROCESS_TERMINATE;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(const_cast<uint8_t*>(sid.data()));

    PACL newAcl = nullptr;
    bool ok = false;
    if (SetEntriesInAclW(1, &ea, oldAcl, &newAcl) == ERROR_SUCCESS && newAcl) {
        ok = SetSecurityInfo(proc, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                             nullptr, nullptr, newAcl, nullptr) == ERROR_SUCCESS;
        if (!ok && why) *why = Fmt(L"SetSecurityInfo err=%lu", GetLastError());
        LocalFree(newAcl);
    } else if (why) {
        *why = Fmt(L"SetEntriesInAcl err=%lu", GetLastError());
    }
    if (sd) LocalFree(sd);
    return ok;
}

bool IsVendorName(const std::wstring& exe) {
    for (int i = 0; target::kVendorExeWhitelist[i]; ++i) {
        if (_wcsicmp(exe.c_str(), target::kVendorExeWhitelist[i]) == 0) return true;
    }
    for (int i = 0; target::kVendorGuardExe[i]; ++i) {
        if (_wcsicmp(exe.c_str(), target::kVendorGuardExe[i]) == 0) return true;
    }
    return false;
}

} // namespace

bool HardenSelf(std::wstring* why) {
    std::vector<uint8_t> sid;
    if (!CurrentUserSid(&sid)) {
        if (why) *why = L"取不到当前用户 SID";
        return false;
    }
    return DenyTerminateOn(GetCurrentProcess(), sid, why);
}

// 给"别人"也上锁：上课清理进程时，被清理的程序会拿到 ACCESS_DENIED。
// 只处理"非厂商、非系统、非安装目录"的进程；需要 WRITE_DAC（管理员）。
int ShieldApps(Locator& loc, const std::wstring& installDir, std::set<DWORD>& done) {
    std::vector<uint8_t> sid;
    if (!CurrentUserSid(&sid)) return 0;

    wchar_t win[MAX_PATH]{};
    const UINT winLen = GetWindowsDirectoryW(win, MAX_PATH);
    if (winLen == 0 || winLen >= MAX_PATH) return 0;

    loc.Refresh(false);
    const DWORD self = GetCurrentProcessId();
    int newly = 0;

    for (const auto& p : loc.Procs()) {
        if (!p.pid || p.pid == self || p.pid <= 4) continue;
        if (done.count(p.pid)) continue;
        if (done.size() > 512) done.clear();          // 防止无限增长
        if (IsVendorName(p.exe)) { done.insert(p.pid); continue; }

        HANDLE h = OpenProcess(WRITE_DAC | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
        if (!h) { done.insert(p.pid); continue; }

        wchar_t path[MAX_PATH * 2]{};
        DWORD sz = MAX_PATH * 2;
        const bool gotPath = QueryFullProcessImageNameW(h, 0, path, &sz) != FALSE;
        const bool skip = !gotPath ||
                          _wcsnicmp(path, win, winLen) == 0 ||
                          (!installDir.empty() && _wcsnicmp(path, installDir.c_str(), installDir.size()) == 0);
        if (skip) {
            CloseHandle(h);
            done.insert(p.pid);
            continue;
        }

        std::wstring why;
        if (DenyTerminateOn(h, sid, &why)) ++newly;
        CloseHandle(h);
        done.insert(p.pid);
    }
    return newly;
}

bool EnablePrivilege(const wchar_t* name) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) != FALSE;
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) ok = false;
    }
    CloseHandle(tok);
    return ok;
}

bool IsProcessAlive(DWORD pid) {
    if (!pid) return false;
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    DWORD w = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return w == WAIT_TIMEOUT;
}

std::wstring ProcessImagePath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";
    wchar_t buf[MAX_PATH * 2];
    DWORD n = MAX_PATH * 2;
    std::wstring r;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) r.assign(buf, n);
    CloseHandle(h);
    return r;
}

std::wstring ProcessBaseName(DWORD pid) {
    return BaseName(ProcessImagePath(pid));
}

bool TerminatePid(DWORD pid, DWORD* lastErr) {
    if (lastErr) *lastErr = 0;
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (!h) {
        if (lastErr) *lastErr = GetLastError();
        return false;
    }
    BOOL ok = TerminateProcess(h, 0);
    if (!ok && lastErr) *lastErr = GetLastError();
    WaitForSingleObject(h, 200);
    CloseHandle(h);
    return ok != FALSE;
}

std::vector<DWORD> EnumPidsByName(const wchar_t* exeName) {
    std::vector<DWORD> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) out.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string r(static_cast<size_t>(n), 0);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &r[0], n, nullptr, nullptr);
    return r;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring r(static_cast<size_t>(n), 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &r[0], n);
    return r;
}

std::wstring NowStamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    return Fmt(L"%04d-%02d-%02d %02d:%02d:%02d.%03d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

PeInfo ReadPeInfo(const std::wstring& path) {
    PeInfo out;
    std::vector<uint8_t> buf;
    // 只读头部 0x400 字节即可
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return out;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return out; }
    out.size = static_cast<uint32_t>(sz.QuadPart);

    uint8_t hdr[0x400]{};
    DWORD got = 0;
    ReadFile(h, hdr, sizeof(hdr), &got, nullptr);
    CloseHandle(h);
    if (got < 0x40 || hdr[0] != 'M' || hdr[1] != 'Z') return out;

    uint32_t lfanew = *reinterpret_cast<uint32_t*>(hdr + 0x3c);
    if (lfanew + 24 + 4 > got) return out;
    if (memcmp(hdr + lfanew, "PE\0\0", 4) != 0) return out;
    out.timeDateStamp = *reinterpret_cast<uint32_t*>(hdr + lfanew + 8);
    out.ok = true;
    return out;
}

// ── 内嵌载荷：exe 尾部 16 字节 footer ───────────────────────────────────────
//   布局：[ exe ][ payload.dll bytes ][ footer(16) ]
//   footer = magic('CTPL') / size / crc32 / flags
#pragma pack(push, 1)
struct PayloadFooter {
    uint32_t magic;
    uint32_t size;
    uint32_t crc32;
    uint32_t flags;
};
#pragma pack(pop)
static constexpr uint32_t kPayloadMagic = 0x4C504354u; // 'CTPL'

static uint32_t Crc32(const uint8_t* data, size_t len) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

bool LoadEmbeddedPayload(std::vector<uint8_t>* out, std::wstring* err) {
    out->clear();
    std::wstring exe = GetExePath();
    HANDLE h = CreateFileW(exe.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (err) *err = L"无法打开自身";
        return false;
    }
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart < 1024) { CloseHandle(h); if (err) *err = L"自身文件异常"; return false; }

    PayloadFooter ft{};
    LARGE_INTEGER pos{};
    pos.QuadPart = sz.QuadPart - (LONGLONG)sizeof(ft);
    SetFilePointerEx(h, pos, nullptr, FILE_BEGIN);
    DWORD got = 0;
    ReadFile(h, &ft, sizeof(ft), &got, nullptr);
    if (got != sizeof(ft) || ft.magic != kPayloadMagic || ft.size == 0 ||
        (LONGLONG)ft.size > sz.QuadPart - (LONGLONG)sizeof(ft)) {
        CloseHandle(h);
        if (err) *err = L"未找到内嵌载荷（构建脚本未附加 payload）";
        return false;
    }
    out->resize(ft.size);
    pos.QuadPart = sz.QuadPart - (LONGLONG)sizeof(ft) - (LONGLONG)ft.size;
    SetFilePointerEx(h, pos, nullptr, FILE_BEGIN);
    DWORD total = 0;
    while (total < ft.size) {
        DWORD n = 0;
        if (!ReadFile(h, out->data() + total, ft.size - total, &n, nullptr) || n == 0) break;
        total += n;
    }
    CloseHandle(h);
    if (total != ft.size) { out->clear(); if (err) *err = L"载荷读取不完整"; return false; }
    if (Crc32(out->data(), out->size()) != ft.crc32) {
        out->clear();
        if (err) *err = L"载荷 CRC 校验失败";
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Logger
// ─────────────────────────────────────────────────────────────────────────────
void Logger::Init(const std::wstring& dir) {
    dir_ = dir;
    InitializeCriticalSection(&cs_);
    EnsureDir(dir_);
    SYSTEMTIME st{};
    GetLocalTime(&st);
    path_ = dir_ + Fmt(L"\\CloudTrainer-%04d%02d%02d.log", st.wYear, st.wMonth, st.wDay);
    init_ = true;
    Info(L"---- CloudTrainer %s 启动 ----", kAppVersion);
}

void Logger::Append(const std::wstring& line) {
    if (!init_) return;
    EnterCriticalSection(&cs_);
    ring_.push_back(line);
    if (ring_.size() > ringMax_) ring_.erase(ring_.begin(), ring_.begin() + (ring_.size() - ringMax_));

    std::string u8 = WideToUtf8(line) + "\r\n";
    HANDLE h = CreateFileW(path_.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(h, u8.data(), (DWORD)u8.size(), &written, nullptr);
        LARGE_INTEGER sz{};
        if (GetFileSizeEx(h, &sz) && sz.QuadPart > (2ll << 20)) {
            CloseHandle(h);
            // 超过 2MB 就换名，下一条会重建
            std::wstring old = path_ + L".1";
            DeleteFileW(old.c_str());
            MoveFileW(path_.c_str(), old.c_str());
            SYSTEMTIME st{};
            GetLocalTime(&st);
            path_ = dir_ + Fmt(L"\\CloudTrainer-%04d%02d%02d.log", st.wYear, st.wMonth, st.wDay);
        } else {
            CloseHandle(h);
        }
    }
    LeaveCriticalSection(&cs_);
}

void Logger::Raw(const wchar_t* level, const wchar_t* msg) {
    Append(Fmt(L"[%s] [%s] %s", NowStamp().c_str(), level, msg ? msg : L""));
}

void Logger::Info(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf(buf, 1023, fmt, ap); buf[1023] = 0;
    va_end(ap);
    Raw(L"INFO", buf);
}

void Logger::Warn(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf(buf, 1023, fmt, ap); buf[1023] = 0;
    va_end(ap);
    Raw(L"WARN", buf);
}

void Logger::Error(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf(buf, 1023, fmt, ap); buf[1023] = 0;
    va_end(ap);
    Raw(L"ERR ", buf);
}

std::vector<std::wstring> Logger::Recent(size_t n) const {
    EnterCriticalSection(&cs_);
    std::vector<std::wstring> r;
    size_t start = ring_.size() > n ? ring_.size() - n : 0;
    for (size_t i = start; i < ring_.size(); ++i) r.push_back(ring_[i]);
    LeaveCriticalSection(&cs_);
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Settings
// ─────────────────────────────────────────────────────────────────────────────
const wchar_t* CapName(int cap) {
    switch (cap) {
        case CAP_FIX_BROADCAST:   return L"广播窗口化";
        case CAP_KILL_BLACK:      return L"黑屏压制";
        case CAP_UNLOCK_KEYBOARD: return L"解除键盘锁";
        case CAP_UNLOCK_MOUSE:    return L"解除鼠标锁";
        case CAP_BLOCK_TERMINATE: return L"拦截结束请求";
        case CAP_BLOCK_CLOSE:     return L"拦截关窗请求";
        case CAP_CMD_GATE:        return L"远程命令确认";
        default:                  return L"未知";
    }
}

const wchar_t* CapDesc(int cap) {
    switch (cap) {
        case CAP_FIX_BROADCAST:   return L"把全屏广播窗口改成可移动/可最小化的窗口";
        case CAP_KILL_BLACK:      return L"BlackSlient.exe 出现即结束";
        case CAP_UNLOCK_KEYBOARD: return L"结束 PDelKeyB.exe，键盘立即恢复";
        case CAP_UNLOCK_MOUSE:    return L"让 HookLib 的锁线程退出，鼠标恢复";
        case CAP_BLOCK_TERMINATE: return L"拦截教师端对学生端/本工具的结束请求";
        case CAP_BLOCK_CLOSE:     return L"拦截跨进程 WM_CLOSE";
        case CAP_CMD_GATE:        return L"教师端远程执行程序时先在本机确认";
        default:                  return L"";
    }
}

bool* Settings::CapPtr(int cap) {
    switch (cap) {
        case CAP_FIX_BROADCAST:   return &fixBroadcast;
        case CAP_KILL_BLACK:      return &killBlackScreen;
        case CAP_UNLOCK_KEYBOARD: return &unlockKeyboard;
        case CAP_UNLOCK_MOUSE:    return &unlockMouse;
        case CAP_BLOCK_TERMINATE: return &blockTerminate;
        case CAP_BLOCK_CLOSE:     return &blockClose;
        case CAP_CMD_GATE:        return &cmdGate;
        default:                  return nullptr;
    }
}

bool Settings::Cap(int cap) const {
    bool* p = const_cast<Settings*>(this)->CapPtr(cap);
    return p ? *p : false;
}

void Settings::Load(const std::wstring& path) {
    std::vector<uint8_t> data;
    if (!ReadAllBytes(path, &data)) return;
    std::wstring text = Utf8ToWide(std::string(data.begin(), data.end()));

    size_t pos = 0;
    while (pos < text.size()) {
        size_t eol = text.find(L'\n', pos);
        if (eol == std::wstring::npos) eol = text.size();
        std::wstring line = Trim(text.substr(pos, eol - pos));
        pos = eol + 1;
        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring k = Trim(line.substr(0, eq));
        std::wstring v = Trim(line.substr(eq + 1));

        if (k == L"fixBroadcast")        fixBroadcast = ParseBool(v, fixBroadcast);
        else if (k == L"fixWidth")       fixWidth = ParseInt(v, fixWidth);
        else if (k == L"fixHeight")      fixHeight = ParseInt(v, fixHeight);
        else if (k == L"keepAspect")     keepAspect = ParseBool(v, keepAspect);
        else if (k == L"allowTopmost")   allowTopmost = ParseBool(v, allowTopmost);
        else if (k == L"killBlackScreen")killBlackScreen = ParseBool(v, killBlackScreen);
        else if (k == L"unlockKeyboard") unlockKeyboard = ParseBool(v, unlockKeyboard);
        else if (k == L"unlockMouse")    unlockMouse = ParseBool(v, unlockMouse);
        else if (k == L"blockTerminate") blockTerminate = ParseBool(v, blockTerminate);
        else if (k == L"blockClose")     blockClose = ParseBool(v, blockClose);
        else if (k == L"cmdGate")        cmdGate = ParseBool(v, cmdGate);
        else if (k == L"protectUserApps") protectUserApps = ParseBool(v, protectUserApps);
        else if (k == L"cmdGateTimeout") cmdGateTimeout = ParseInt(v, cmdGateTimeout);
        else if (k == L"autoInject")     autoInject = ParseBool(v, autoInject);
        else if (k == L"installDir")     installDirHint = v;
        else if (k == L"startupEnableAll") startupEnableAll = ParseBool(v, startupEnableAll);
        else if (k == L"selfProtect")      selfProtect = ParseBool(v, selfProtect);
        else if (k == L"strictVersion")    strictVersion = ParseBool(v, strictVersion);
        else if (k == L"appShield")        appShield = ParseBool(v, appShield);
        else if (k == L"netGuard")         netGuard = ParseBool(v, netGuard);
        else if (k == L"netKillLimit")     netKillLimit = ParseBool(v, netKillLimit);
        else if (k == L"netStopDriver")    netStopDriver = ParseBool(v, netStopDriver);
    }
    if (fixWidth < 320) fixWidth = 320;
    if (fixHeight < 240) fixHeight = 240;
    if (cmdGateTimeout < 3) cmdGateTimeout = 3;
    if (cmdGateTimeout > 120) cmdGateTimeout = 120;

    // 启动默认全开：把 7 个能力全部打开。
    // 运行时可以用托盘菜单临时关掉（只影响本次会话），重启后又会回到全开；
    // 想要"关掉就一直关着"，把 startupEnableAll 改成 0。
    if (startupEnableAll) {
        fixBroadcast    = true;
        killBlackScreen = true;
        unlockKeyboard  = true;
        unlockMouse     = true;
        blockTerminate  = true;
        blockClose      = true;
        cmdGate         = true;
    }
}

void Settings::Save(const std::wstring& path) const {
    std::wstring t;
    t += L"# CloudTrainer 配置\r\n";
    t += L"# 改完保存后，重启本程序生效。\r\n\r\n";
    t += L"# 启动时默认开启全部能力（1=开，0=按下面的开关来）\r\n";
    t += Fmt(L"startupEnableAll=%d\r\n", startupEnableAll ? 1 : 0);
    t += L"# 自我保护：拒绝其它进程结束本程序（DACL 拒绝 PROCESS_TERMINATE）\r\n";
    t += Fmt(L"selfProtect=%d\r\n", selfProtect ? 1 : 0);
    t += L"# 严格版本校验：1=指纹不匹配就降只读；0=照常启用，仅标注未验证\r\n";
    t += Fmt(L"strictVersion=%d\r\n", strictVersion ? 1 : 0);
    t += L"# 给所有非厂商用户程序加一条 DACL，拒绝别人结束它们（上课清理进程时保命）\r\n";
    t += Fmt(L"appShield=%d\r\n", appShield ? 1 : 0);
    t += L"# 设备层：拒绝打开 \\\\.\\Inspect，并拒绝对它的 DeviceIoControl\r\n";
    t += Fmt(L"netGuard=%d\r\n", netGuard ? 1 : 0);
    t += L"# 发现 mmcLimitConsole（网络限制执行器）直接结束，不走弹窗\r\n";
    t += Fmt(L"netKillLimit=%d\r\n", netKillLimit ? 1 : 0);
    t += L"# 额外停掉 Inspect 驱动服务：更彻底，但会影响所有依赖它的功能，默认关\r\n";
    t += Fmt(L"netStopDriver=%d\r\n\r\n", netStopDriver ? 1 : 0);
    t += L"# ── 广播窗口化 ──\r\n";
    t += Fmt(L"fixBroadcast=%d\r\n", fixBroadcast ? 1 : 0);
    t += Fmt(L"fixWidth=%d\r\n", fixWidth);
    t += Fmt(L"fixHeight=%d\r\n", fixHeight);
    t += Fmt(L"keepAspect=%d\r\n", keepAspect ? 1 : 0);
    t += Fmt(L"allowTopmost=%d\r\n", allowTopmost ? 1 : 0);
    t += L"\r\n# ── 黑屏 / 键鼠 ──\r\n";
    t += Fmt(L"killBlackScreen=%d\r\n", killBlackScreen ? 1 : 0);
    t += Fmt(L"unlockKeyboard=%d\r\n", unlockKeyboard ? 1 : 0);
    t += Fmt(L"unlockMouse=%d\r\n", unlockMouse ? 1 : 0);
    t += L"\r\n# ── 注入类能力 ──\r\n";
    t += Fmt(L"blockTerminate=%d\r\n", blockTerminate ? 1 : 0);
    t += Fmt(L"blockClose=%d\r\n", blockClose ? 1 : 0);
    t += Fmt(L"cmdGate=%d\r\n", cmdGate ? 1 : 0);
    t += Fmt(L"protectUserApps=%d\r\n", protectUserApps ? 1 : 0);
    t += Fmt(L"cmdGateTimeout=%d\r\n", cmdGateTimeout);
    t += Fmt(L"autoInject=%d\r\n", autoInject ? 1 : 0);
    t += L"\r\n# 非默认安装路径时在这里写死（留空则自动探测）\r\n";
    t += L"installDir=" + installDirHint + L"\r\n";

    std::string u8 = WideToUtf8(t);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, u8.data(), (DWORD)u8.size(), &w, nullptr);
    CloseHandle(h);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Locator
// ─────────────────────────────────────────────────────────────────────────────
void Locator::Refresh(bool force) {
    uint64_t now = NowMs();
    if (!force && now - lastRefresh_ < 1200) return;
    lastRefresh_ = now;
    procs_.clear();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcEntry e;
            e.pid = pe.th32ProcessID;
            e.exe = pe.szExeFile;
            procs_.push_back(e);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

std::vector<DWORD> Locator::PidsByExe(const wchar_t* exe) const {
    std::vector<DWORD> r;
    if (!exe) return r;
    for (const auto& p : procs_) {
        if (_wcsicmp(p.exe.c_str(), exe) == 0) r.push_back(p.pid);
    }
    return r;
}

DWORD Locator::FirstPid(const wchar_t* exe) const {
    auto v = PidsByExe(exe);
    return v.empty() ? 0 : v[0];
}

bool Locator::AnyRunning(const wchar_t* exe) const {
    return !PidsByExe(exe).empty();
}

bool Locator::ModuleRange(DWORD pid, const wchar_t* dll, uint32_t* base, uint32_t* size) {
    if (base) *base = 0;
    if (size) *size = 0;
    if (!pid || !dll) return false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, dll) == 0) {
                if (base) *base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(me.modBaseAddr));
                if (size) *size = me.modBaseSize;
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

std::vector<DWORD> Locator::PidsWithModule(const wchar_t* dll, bool force) {
    std::wstring key = ToLower(dll ? dll : L"");
    uint64_t now = NowMs();
    auto it = modCache_.find(key);
    if (!force && it != modCache_.end() && now - it->second.stamp < 2000) return it->second.pids;

    std::vector<DWORD> out;
    if (!dll) return out;

    // 只对“可能是宿主”的进程枚举模块：镜像路径在安装目录下的进程 + 已知进程名。
    // 这样既覆盖 HookLib 的真实宿主，又不用对全系统几百个进程做快照。
    std::set<std::wstring> names;
    names.insert(ToLower(target::kProcStudent));
    names.insert(ToLower(target::kProcMulti));
    names.insert(ToLower(target::kProcMultiRender));
    names.insert(ToLower(target::kProcBlackSilent));

    std::wstring dir;
    if (FindInstallDir(&dir, false) && !dir.empty()) {
        WIN32_FIND_DATAW fd{};
        HANDLE f = FindFirstFileW((dir + L"\\*.exe").c_str(), &fd);
        if (f != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) names.insert(ToLower(fd.cFileName));
            } while (FindNextFileW(f, &fd));
            FindClose(f);
        }
    }

    for (const auto& p : procs_) {
        if (p.pid == 0 || p.pid == GetCurrentProcessId()) continue;
        if (names.find(ToLower(p.exe)) == names.end()) continue;
        uint32_t b = 0, s = 0;
        if (ModuleRange(p.pid, dll, &b, &s)) out.push_back(p.pid);
    }

    ModCache c;
    c.stamp = now;
    c.pids = out;
    modCache_[key] = c;
    return out;
}

std::wstring Locator::ImagePath(DWORD pid) const { return ProcessImagePath(pid); }

bool Locator::StudentEventExists() const {
    HANDLE h = OpenEventW(SYNCHRONIZE, FALSE, (std::wstring(L"Global\\") + target::kEvtStudentRunning).c_str());
    if (!h) h = OpenEventW(SYNCHRONIZE, FALSE, target::kEvtStudentRunning);
    if (!h) return false;
    CloseHandle(h);
    return true;
}

static bool DirLooksLikeInstall(const std::wstring& dir) {
    return FileExists(dir + L"\\" + target::kFileGeneralCfg) ||
           FileExists(dir + L"\\" + target::kProcStudent);
}

bool Locator::FindInstallDir(std::wstring* out, bool force) {
    uint64_t now = NowMs();
    if (!force && !installDir_.empty() && now - installStamp_ < 10000) {
        *out = installDir_;
        return !installDir_.empty();
    }
    installStamp_ = now;

    auto accept = [&](const std::wstring& d) -> bool {
        if (d.empty()) return false;
        std::wstring t = d;
        while (!t.empty() && (t.back() == L'\\' || t.back() == L'/')) t.pop_back();
        if (t.size() < 3) return false;
        if (!DirLooksLikeInstall(t)) return false;
        installDir_ = t;
        return true;
    };

    // 0) 配置里手工指定的路径
    if (!hint_.empty() && accept(hint_)) { *out = installDir_; return true; }

    // 1) 正在运行的学生端进程 —— 最可靠
    Refresh(false);
    for (DWORD pid : PidsByExe(target::kProcStudent)) {
        std::wstring p = ProcessImagePath(pid);
        if (p.empty()) continue;
        size_t s = p.find_last_of(L"\\/");
        if (s != std::wstring::npos && accept(p.substr(0, s))) { *out = installDir_; return true; }
    }

    // 2) Run 键
    const wchar_t* runKeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    };
    HKEY roots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    for (HKEY root : roots) {
        for (const wchar_t* rk : runKeys) {
            HKEY k = nullptr;
            if (RegOpenKeyExW(root, rk, 0, KEY_READ, &k) != ERROR_SUCCESS) continue;
            wchar_t name[256];
            wchar_t val[1024];
            DWORD nameLen = 256, valLen = sizeof(val);
            DWORD idx = 0;
            while (RegEnumValueW(k, idx++, name, &nameLen, nullptr, nullptr,
                                 reinterpret_cast<LPBYTE>(val), &valLen) == ERROR_SUCCESS) {
                std::wstring v = val;
                if (v.find(target::kProcStartup) != std::wstring::npos ||
                    v.find(target::kProcStudent) != std::wstring::npos) {
                    std::wstring exePath;
                    if (v.size() > 1 && v[0] == L'"') {
                        size_t q = v.find(L'"', 1);
                        if (q != std::wstring::npos) exePath = v.substr(1, q - 1);
                    } else {
                        size_t sp = v.find(L" ");
                        exePath = (sp == std::wstring::npos) ? v : v.substr(0, sp);
                    }
                    size_t s = exePath.find_last_of(L"\\/");
                    if (s != std::wstring::npos && accept(exePath.substr(0, s))) {
                        RegCloseKey(k);
                        *out = installDir_;
                        return true;
                    }
                }
                nameLen = 256; valLen = sizeof(val);
            }
            RegCloseKey(k);
        }
    }

    // 3) 卸载项 DisplayIcon
    const wchar_t* unKeys[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    };
    for (const wchar_t* uk : unKeys) {
        HKEY k = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, uk, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &k) != ERROR_SUCCESS) continue;
        wchar_t sub[256];
        DWORD idx = 0;
        while (RegEnumKeyW(k, idx++, sub, 256) == ERROR_SUCCESS) {
            HKEY sk = nullptr;
            if (RegOpenKeyExW(k, sub, 0, KEY_READ, &sk) != ERROR_SUCCESS) continue;
            wchar_t icon[1024];
            DWORD sz = sizeof(icon);
            DWORD type = 0;
            if (RegQueryValueExW(sk, L"DisplayIcon", nullptr, &type,
                                 reinterpret_cast<LPBYTE>(icon), &sz) == ERROR_SUCCESS) {
                std::wstring v = icon;
                if (v.find(L".exe") != std::wstring::npos) {
                    size_t s = v.find_last_of(L"\\/");
                    if (s != std::wstring::npos && accept(v.substr(0, s))) {
                        RegCloseKey(sk);
                        RegCloseKey(k);
                        *out = installDir_;
                        return true;
                    }
                }
            }
            RegCloseKey(sk);
        }
        RegCloseKey(k);
    }

    // 4) 候选路径
    const wchar_t* drives[] = { L"C:", L"D:", L"E:", L"F:" };
    const wchar_t* subs[] = {
        L"\\Program Files\\Lenovo\\Lenovo Classroom",
        L"\\Program Files (x86)\\Lenovo\\Lenovo Classroom",
        L"\\Program Files\\Lenovo\\联想电子教室",
        L"\\Program Files (x86)\\Lenovo\\联想电子教室",
        L"\\Program Files\\Lenovo\\NeiCloud",
        L"\\Program Files (x86)\\Lenovo\\NeiCloud",
        L"\\Lenovo\\Lenovo Classroom",
        L"\\NeiCloud",
    };
    for (const wchar_t* dr : drives) {
        for (const wchar_t* sub2 : subs) {
            std::wstring d = std::wstring(dr) + sub2;
            if (accept(d)) { *out = installDir_; return true; }
        }
    }

    // 5) 配置里手工指定（config.ini 的 installDir 由 App 读取后 SetInstallDirHint）
    installDir_.clear();
    *out = L"";
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  VersionGuard
// ─────────────────────────────────────────────────────────────────────────────
const wchar_t* EnvLevelName(EnvLevel lv) {
    switch (lv) {
        case EnvLevel::Full:     return L"完整模式";
        case EnvLevel::Degraded: return L"降级模式";
        case EnvLevel::ReadOnly: return L"只读模式";
        default:                 return L"未识别";
    }
}

void VersionGuard::Evaluate(const std::wstring& dir) {
    dir_ = dir;
    if (dir.empty()) {
        level_ = EnvLevel::Unknown;
        detail_ = L"未找到安装目录";
        return;
    }
    // 产品在不在，只看主程序有没有。指纹只是"是不是我验证过的那版"，不是"能不能用"。
    if (!FileExists(dir + L"\\" + target::kProcStudent)) {
        level_ = EnvLevel::ReadOnly;
        detail_ = L"目录里没有 Student.exe";
        return;
    }

    int matched = 0, total = 0;
    std::wstring miss;

    for (int i = 0; i < target::kFingerprintCount; ++i) {
        const auto& fp = target::kFingerprints[i];
        ++total;
        PeInfo info = ReadPeInfo(dir + L"\\" + fp.file);
        bool ok = info.ok && info.size == fp.size && info.timeDateStamp == fp.timeDateStamp;
        if (ok) {
            ++matched;
        } else {
            if (!miss.empty()) miss += L", ";
            miss += fp.file;
        }
    }

    // 指纹只回答"是不是我逐字节验证过的那一版"，不回答"能不能用"。
    // 原来的规则是"主链不匹配就降只读"，那会让换一个维护版本就整体罢工（G2–G6 全关），
    // 而 G1 仍然工作 —— 这种"半死不活"的状态最难排查，所以改成降级但仍全功能，
    // 只在界面上标注"版本未验证"。要旧行为把 strictVersion 设成 1。
    if (matched == total) {
        level_ = EnvLevel::Full;
        detail_ = Fmt(L"%d/%d 指纹匹配", matched, total);
    } else if (strictVersion) {
        level_ = EnvLevel::ReadOnly;
        detail_ = Fmt(L"%d/%d 匹配，严格模式下拒绝运行：%s", matched, total, miss.c_str());
    } else {
        level_ = EnvLevel::Degraded;
        detail_ = Fmt(L"%d/%d 匹配（版本未验证，功能照常启用）：%s", matched, total, miss.c_str());
    }
}

} // namespace ct
