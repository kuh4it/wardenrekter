// Warden Rekter
// Tested and working on Overwatch 2

#include <Windows.h>
#include <TlHelp32.h>

UINT64 FindKiUserExceptionDispatcherAddress() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) {
        return 0;
    }
    return reinterpret_cast<UINT64>(GetProcAddress(hNtdll, "KiUserExceptionDispatcher"));
}

BOOL APIENTRY DllMain(HMODULE mod, ULONG reason, UINT64 junk)
{
    if(reason != DLL_PROCESS_ATTACH) return false;
    
    UINT64 KiUserExceptionDispatcherAddrress = FindKiUserExceptionDispatcherAddress();
    // Disable KiUserExceptionDispatcher hook
    DWORD oldProtect;
    VirtualProtect((PVOID)KiUserExceptionDispatcherAddrress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)KiUserExceptionDispatcherAddrress = 0xC3;
    VirtualProtect((PVOID)KiUserExceptionDispatcherAddrress, 1, oldProtect, &oldProtect);

    // Disable DbgBreakPoint and DbgUserBreakPoint integrity checks
    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    DWORD oldProtect;
    VirtualProtect((PVOID)(hNtdll + 0x1CA880), 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)(hNtdll + 0x1CA880) = 0xCC;
    VirtualProtect((PVOID)(hNtdll + 0x1CA880), 1, oldProtect, &oldProtect);
    VirtualProtect((PVOID)(hNtdll + 0x1CA883), 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)(hNtdll + 0x1CA883) = 0xCC;
    VirtualProtect((PVOID)(hNtdll + 0x1CA883), 1, oldProtect, &oldProtect);

    // Spoof PEB IsDebuggerPresent and NtGlobalFlag
    PEB* pPeb = (PEB*)__readgsqword(0x60);
    pPeb->BeingDebugged = 0;
    pPeb->NtGlobalFlag = 0;

    // Disable timing checks
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    FARPROC pGetTickCount64 = GetProcAddress(hKernel32, "GetTickCount64");
    DWORD oldProtect;
    VirtualProtect(pGetTickCount64, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)pGetTickCount64 = 0xC3;
    VirtualProtect(pGetTickCount64, 5, oldProtect, &oldProtect);

    // Hook NtQuerySystemInformation to disable manual syscalls
    HMODULE hNtDll = GetModuleHandle(TEXT("ntdll.dll"));
    FARPROC pNtQuerySystemInformation = GetProcAddress(hNtDll, "NtQuerySystemInformation");
    DWORD oldProtect;
    VirtualProtect(pNtQuerySystemInformation, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)pNtQuerySystemInformation = 0xC3;
    VirtualProtect(pNtQuerySystemInformation, 5, oldProtect, &oldProtect);

    // Modify DR0
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr0 = 0x12345678;
    context.Dr7 = 0x00000001;
    SetThreadContext(GetCurrentThread(), &context);

    printf("Warden rekted with success!\n");

    return true;
}
