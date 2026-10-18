// =============================================================================
//  CloudTrainerPayload - dllmain.cpp
//  ---------------------------------------------------------------------------
//  入口点：CtPayloadEntry(HMODULE self)
//
//  【为什么不用 DllMain + CRT】
//  载荷是被“手工映射”进目标进程的，系统加载器没有参与，所以：
//    * PE 的 TLS 目录不会被处理（我们自己有 .tls 段，CRT 会访问到空的 TLS 槽）；
//    * CRT 的初始化（_CRT_INIT / __main / pseudo-reloc）没有调用者；
//    * DllMain 里装 hook 更是 JiYuTrainer 踩过的 loader-lock 死锁。
//  于是这里干脆不要 CRT：链接时 -nostartfiles，入口直接指向本函数。
//  载荷只用 Win32 + 内存/字符串函数（都是 ucrtbase 的导出，随进程加载即可用），
//  没有全局构造、没有异常、没有 RTTI，因此完全不需要 CRT 初始化。
// =============================================================================
#include "payload.h"

namespace ctpayload {

} // namespace ctpayload

extern "C" __declspec(dllexport) DWORD WINAPI CtPayloadEntry(void* param) {
    // param = 载荷在目标进程里的基址（由注入器的调用桩压栈）
    (void)param;
    HANDLE t = CreateThread(nullptr, 0, ctpayload::PayloadThread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
    return 1;
}
