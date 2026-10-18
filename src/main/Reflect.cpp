// =============================================================================
//  CloudTrainer - Reflect.cpp
//  ---------------------------------------------------------------------------
//  跨进程反射式加载器。
//
//  为什么不用 MemoryModule（fancycode / JiYuTrainer 里那份）：
//    它设计成"在本进程内加载 DLL"，调用的都是不带进程句柄的 VirtualAlloc /
//    GetProcAddress / LoadLibrary。这里需要的是"把 x86 DLL 映射到另一个 x86 进程"，
//    API 全都要带 hProc，导入解析也必须在目标进程里完成 —— 是另一套逻辑。
//
//  流程：
//    1. 校验 PE32 / i386；
//    2. VirtualAllocEx（优先首选基址）；
//    3. 本地按节表拼出完整镜像；
//    4. 已知远端基址 -> 在本地应用重定位；
//    5. 导入表：本地解析 -> 找到"真正包含该地址的模块" -> 远端取同名模块基址
//       -> IAT 写 (远端基址 + RVA)。这样连 kernel32 -> kernelbase 的转发也正确；
//    6. WriteProcessMemory 整块写入，按节 VirtualProtectEx；
//    7. 写 15 字节调用桩，CreateRemoteThread 执行 entry(base)。
// =============================================================================
#include "Reflect.h"

#include "../common/CtIpc.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <map>

namespace ct {

namespace {

std::wstring RFmt(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 1023, fmt, ap);
    buf[1023] = 0;
    va_end(ap);
    return std::wstring(buf);
}

std::string Lower(const char* s) {
    std::string r = s ? s : "";
    for (auto& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

struct PeView {
    const IMAGE_DOS_HEADER* dos = nullptr;
    const IMAGE_NT_HEADERS32* nt = nullptr;
    bool ok = false;
};

bool ParsePe32(const std::vector<uint8_t>& buf, PeView* v) {
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew <= 0 ||
        (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > buf.size()) return false;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return false;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;

    v->dos = dos;
    v->nt = nt;
    v->ok = true;
    return true;
}

// 在目标进程里 LoadLibraryA(name)，返回远端模块基址
uint32_t RemoteLoadLibrary(HANDLE hProc, const char* name, std::wstring* err) {
    if (!name || !*name) return 0;
    const size_t len = strlen(name) + 1;
    void* remote = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        if (err) *err = RFmt(L"VirtualAllocEx(模块名) 失败 err=%lu", GetLastError());
        return 0;
    }
    uint32_t base = 0;
    if (WriteProcessMemory(hProc, remote, name, len, nullptr)) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        auto pLoad = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryA"));
        HANDLE th = CreateRemoteThread(hProc, nullptr, 0, pLoad, remote, 0, nullptr);
        if (th) {
            if (WaitForSingleObject(th, 5000) == WAIT_OBJECT_0) {
                DWORD code = 0;
                if (GetExitCodeThread(th, &code)) base = code;
            }
            CloseHandle(th);
        } else if (err) {
            *err = RFmt(L"CreateRemoteThread(LoadLibraryA) 失败 err=%lu", GetLastError());
        }
    } else if (err) {
        *err = RFmt(L"WriteProcessMemory(模块名) 失败 err=%lu", GetLastError());
    }
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    return base;
}

HMODULE ContainingModule(const void* addr) {
    HMODULE h = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(addr), &h)) {
        return h;
    }
    return nullptr;
}

std::string ModuleBaseNameA(HMODULE h) {
    wchar_t path[MAX_PATH * 2]{};
    if (!GetModuleFileNameW(h, path, MAX_PATH * 2)) return std::string();
    std::wstring full(path);
    size_t s = full.find_last_of(L"\\/");
    std::wstring base = (s == std::wstring::npos) ? full : full.substr(s + 1);
    std::string out;
    int n = WideCharToMultiByte(CP_ACP, 0, base.c_str(), (int)base.size(), nullptr, 0, nullptr, nullptr);
    if (n > 0) {
        out.resize(n);
        WideCharToMultiByte(CP_ACP, 0, base.c_str(), (int)base.size(), &out[0], n, nullptr, nullptr);
    }
    return out;
}

DWORD ProtFromCharacteristics(DWORD ch) {
    const bool exec = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool write = (ch & IMAGE_SCN_MEM_WRITE) != 0;
    const bool read = (ch & IMAGE_SCN_MEM_READ) != 0;
    if (exec) return write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    if (write) return PAGE_READWRITE;
    return read ? PAGE_READONLY : PAGE_NOACCESS;
}

struct RemoteMods {
    HANDLE proc = nullptr;
    std::map<std::string, uint32_t> cache;
    std::wstring err;

    uint32_t Get(const char* name) {
        std::string key = Lower(name);
        auto it = cache.find(key);
        if (it != cache.end()) return it->second;
        uint32_t base = RemoteLoadLibrary(proc, name, &err);
        cache[key] = base;
        return base;
    }
};

bool ApplyRelocations(uint8_t* img, const PeView& pe, uint32_t delta) {
    if (delta == 0) return true;
    auto& dd = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dd.VirtualAddress == 0 || dd.Size == 0) return false;

    const uint8_t* p = img + dd.VirtualAddress;
    const uint8_t* end = p + dd.Size;
    while (p + sizeof(IMAGE_BASE_RELOCATION) <= end) {
        const auto* blk = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(p);
        if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        const int count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        const uint16_t* item = reinterpret_cast<const uint16_t*>(p + sizeof(IMAGE_BASE_RELOCATION));
        for (int i = 0; i < count; ++i) {
            const int type = item[i] >> 12;
            const int off = item[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != IMAGE_REL_BASED_HIGHLOW) return false;
            uint8_t* at = img + blk->VirtualAddress + off;
            uint32_t v = 0;
            memcpy(&v, at, 4);
            v += delta;
            memcpy(at, &v, 4);
        }
        p += blk->SizeOfBlock;
    }
    return true;
}

bool FixImports(uint8_t* img, const PeView& pe, RemoteMods& mods, std::wstring* err) {
    auto& dd = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dd.VirtualAddress == 0) return true;

    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(img + dd.VirtualAddress);
    for (; desc->Name != 0; ++desc) {
        const char* dllName = reinterpret_cast<const char*>(img + desc->Name);
        const uint32_t remoteBase = mods.Get(dllName);
        if (!remoteBase) {
            if (err) *err = RFmt(L"目标进程加载 %S 失败", dllName);
            return false;
        }

        HMODULE localBase = LoadLibraryA(dllName);
        if (!localBase) {
            if (err) *err = RFmt(L"本进程加载 %S 失败", dllName);
            return false;
        }

        const uint32_t thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA32*>(img + thunkRva);
        auto* iat = reinterpret_cast<IMAGE_THUNK_DATA32*>(img + desc->FirstThunk);

        // 没有 OriginalFirstThunk 时名字表与 IAT 是同一块内存：先整体复制，
        // 否则一边写 IAT 一边读名字会把自己踩坏。
        std::vector<IMAGE_THUNK_DATA32> thunkCopy;
        if (desc->OriginalFirstThunk == 0) {
            const IMAGE_THUNK_DATA32* p = iat;
            while (p->u1.AddressOfData != 0 && thunkCopy.size() < 65536) thunkCopy.push_back(*p++);
            IMAGE_THUNK_DATA32 term{};
            thunkCopy.push_back(term);
            thunk = thunkCopy.data();
        }

        for (; thunk->u1.AddressOfData != 0; ++thunk, ++iat) {
            void* pLocal = nullptr;
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                pLocal = reinterpret_cast<void*>(
                    GetProcAddress(localBase, MAKEINTRESOURCEA(thunk->u1.Ordinal & 0xFFFF)));
            } else {
                auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(img + thunk->u1.AddressOfData);
                pLocal = reinterpret_cast<void*>(
                    GetProcAddress(localBase, reinterpret_cast<LPCSTR>(ibn->Name)));
            }
            if (!pLocal) {
                if (err) *err = RFmt(L"解析 %S 的导入函数失败", dllName);
                return false;
            }

            // 关键：函数可能被转发到另一个模块（kernel32 -> kernelbase）。
            // 必须用“真正包含该地址的模块”来算 RVA，否则 IAT 会指飞。
            HMODULE cont = ContainingModule(pLocal);
            if (!cont) {
                if (err) *err = L"无法确定导入函数所属模块";
                return false;
            }
            uint32_t contBase = remoteBase;
            if (cont != localBase) {
                std::string contName = ModuleBaseNameA(cont);
                contBase = mods.Get(contName.c_str());
                if (!contBase) {
                    if (err) *err = RFmt(L"目标进程加载 %S 失败", contName.c_str());
                    return false;
                }
            }
            const uint32_t rva = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pLocal) -
                                                       reinterpret_cast<uintptr_t>(cont));
            iat->u1.Function = contBase + rva;
        }
    }
    return true;
}

// 15 字节调用桩：entry(base) —— stdcall，单参数
//   push base ; mov eax,entry ; call eax ; ret 4
bool BuildEntryStub(uint32_t base, uint32_t entry, uint8_t out[32], size_t* len) {
    uint8_t code[32]{};
    code[0] = 0x68;
    memcpy(code + 1, &base, 4);
    code[5] = 0xB8;
    memcpy(code + 6, &entry, 4);
    code[10] = 0xFF;
    code[11] = 0xD0;
    code[12] = 0xC2;
    code[13] = 0x04;
    code[14] = 0x00;
    memcpy(out, code, 15);
    *len = 15;
    return true;
}

} // namespace

bool ReflectInject(HANDLE hProc, const std::vector<uint8_t>& dll, uint32_t* outBase,
                   std::wstring* err) {
    if (err) err->clear();
    PeView pe;
    if (!ParsePe32(dll, &pe)) {
        if (err) *err = L"载荷不是有效的 PE32 i386 镜像";
        return false;
    }
    const auto& oh = pe.nt->OptionalHeader;
    const uint32_t imageSize = oh.SizeOfImage;
    if (imageSize == 0 || imageSize > (64u << 20)) {
        if (err) *err = L"载荷 SizeOfImage 异常";
        return false;
    }

    // 1) 远端分配（优先首选基址，减少重定位）
    void* remote = VirtualAllocEx(hProc, reinterpret_cast<void*>(static_cast<uintptr_t>(oh.ImageBase)),
                                  imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        remote = VirtualAllocEx(hProc, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!remote) {
        if (err) *err = RFmt(L"VirtualAllocEx 失败 err=%lu", GetLastError());
        return false;
    }
    const uint32_t remoteBase = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(remote));

    // 2) 本地拼镜像
    std::vector<uint8_t> img(imageSize, 0);
    const size_t hdrSize = (std::min)(static_cast<size_t>(oh.SizeOfHeaders), dll.size());
    memcpy(img.data(), dll.data(), hdrSize);
    for (WORD i = 0; i < pe.nt->FileHeader.NumberOfSections; ++i) {
        const auto* sec = IMAGE_FIRST_SECTION(pe.nt) + i;
        if (sec->SizeOfRawData == 0) continue;
        if ((size_t)sec->PointerToRawData + sec->SizeOfRawData > dll.size()) continue;
        if ((size_t)sec->VirtualAddress + sec->SizeOfRawData > img.size()) continue;
        memcpy(img.data() + sec->VirtualAddress, dll.data() + sec->PointerToRawData, sec->SizeOfRawData);
    }

    // 3) 重定位
    if (remoteBase != oh.ImageBase) {
        if (!ApplyRelocations(img.data(), pe, remoteBase - oh.ImageBase)) {
            VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
            if (err) *err = L"重定位失败（载荷缺少重定位表，且首选基址被占用）";
            return false;
        }
    }

    // 4) 导入表
    RemoteMods mods;
    mods.proc = hProc;
    if (!FixImports(img.data(), pe, mods, err)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        if (err && err->empty()) *err = L"导入表修复失败";
        return false;
    }

    // 5) 写入
    if (!WriteProcessMemory(hProc, remote, img.data(), imageSize, nullptr)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        if (err) *err = RFmt(L"WriteProcessMemory 失败 err=%lu", GetLastError());
        return false;
    }

    // 6) 按节设置保护
    VirtualProtectEx(hProc, remote, oh.SizeOfHeaders, PAGE_READONLY, nullptr);
    for (WORD i = 0; i < pe.nt->FileHeader.NumberOfSections; ++i) {
        const auto* sec = IMAGE_FIRST_SECTION(pe.nt) + i;
        const DWORD sz = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (sz == 0) continue;
        DWORD old = 0;
        VirtualProtectEx(hProc, reinterpret_cast<uint8_t*>(remote) + sec->VirtualAddress, sz,
                         ProtFromCharacteristics(sec->Characteristics), &old);
    }

    // 7) 入口桩
    uint8_t stub[32]{};
    size_t stubLen = 0;
    BuildEntryStub(remoteBase, remoteBase + oh.AddressOfEntryPoint, stub, &stubLen);

    void* stubRemote = VirtualAllocEx(hProc, nullptr, stubLen, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!stubRemote) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        if (err) *err = RFmt(L"VirtualAllocEx(桩) 失败 err=%lu", GetLastError());
        return false;
    }
    WriteProcessMemory(hProc, stubRemote, stub, stubLen, nullptr);
    FlushInstructionCache(hProc, stubRemote, stubLen);

    HANDLE th = CreateRemoteThread(hProc, nullptr, 0,
                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(stubRemote),
                                   nullptr, 0, nullptr);
    bool ok = false;
    if (th) {
        const DWORD wr = WaitForSingleObject(th, 8000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        CloseHandle(th);
        ok = (wr == WAIT_OBJECT_0) && code != 0;
        if (!ok && err) *err = RFmt(L"远端入口执行失败 wr=%lu code=%lu", wr, code);
    } else if (err) {
        *err = RFmt(L"CreateRemoteThread 失败 err=%lu", GetLastError());
    }

    VirtualFreeEx(hProc, stubRemote, 0, MEM_RELEASE);
    if (!ok) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return false;
    }

    if (outBase) *outBase = remoteBase;
    return true;
}

bool PayloadSessionAlive(DWORD pid, uint32_t* outMagic) {
    if (outMagic) *outMagic = 0;
    wchar_t name[128]{};
    _snwprintf(name, 127, CT_SHM_NAME_FMT, pid);
    HANDLE m = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
    if (!m) return false;
    bool ok = false;
    void* p = MapViewOfFile(m, FILE_MAP_READ, 0, 0, sizeof(CtShared));
    if (p) {
        const auto* shm = reinterpret_cast<const CtShared*>(p);
        ok = (shm->magic == CT_IPC_MAGIC) && (shm->version == CT_IPC_VERSION) &&
             (shm->rep.alive != 0);
        if (outMagic) *outMagic = shm->magic;
        UnmapViewOfFile(p);
    }
    CloseHandle(m);
    return ok;
}

} // namespace ct
