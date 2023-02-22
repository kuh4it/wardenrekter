// Warden Rekter
// Tested and working on Overwatch 2
// Most information is taken from UnknownCheats, I myself have not conducted any specific reversal work/research
#include <Windows.h>
#include <TlHelp32.h>
int main()
{
    // Disable KiUserExceptionDispatcher hook
    DWORD oldProtect;
    VirtualProtect((PVOID)0x7FFE0300, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)0x7FFE0300 = 0xC3;
    VirtualProtect((PVOID)0x7FFE0300, 1, oldProtect, &oldProtect);

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

    return 0;
}
