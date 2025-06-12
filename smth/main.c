#include "cleany.h"
#include <stdio.h>

int main() {
    CLEAN_COPY_INFO cleanCopyInfo = {0};
    
    printf("[+] Initializing clean copy loader\n");
    fflush(stdout);
    BOOL ok = InitializeCleanCopy(&cleanCopyInfo);
    if (!ok) {
        printf("[-] Failed to initialize clean copy\n");
        return 1;
    }
    printf("[+] Successfully initialized clean copy\n");
    fflush(stdout);

    printf("[*] Testing syscall stubs...\n");
    fflush(stdout);
    
    PVOID testBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!testBuffer) {
        printf("[-] Failed to allocate test buffer (err=%lu)\n", GetLastError());
        fflush(stdout);
        CleanupCleanCopy(&cleanCopyInfo);
        return 1;
    }
    printf("[+] Test buffer allocated at %p\n", testBuffer);
    fflush(stdout);

    SIZE_T testSize = 0x1000;
    PVOID testAddr = testBuffer;
    DWORD testOldProt;

    PSYSCALL_STUB protectStub = NULL;
    for (DWORD i = 0; i < cleanCopyInfo.StubCount; i++) {
        if (cleanCopyInfo.Stubs[i].OriginalFunction == 
            GetProcAddress(cleanCopyInfo.OriginalModule, "NtProtectVirtualMemory")) {
            protectStub = &cleanCopyInfo.Stubs[i];
            break;
        }
    }

    if (!protectStub) {
        printf("[-] Failed to find NtProtectVirtualMemory stub\n");
        fflush(stdout);
        VirtualFree(testBuffer, 0, MEM_RELEASE);
        CleanupCleanCopy(&cleanCopyInfo);
        return 1;
    }

    printf("[*] Testing NtProtectVirtualMemory stub (syscall: 0x%X)...\n", 
        protectStub->SyscallNumber);
    fflush(stdout);

    if (!DecryptCleanCopy(&cleanCopyInfo)) {
        printf("[-] Failed to decrypt clean copy\n");
        fflush(stdout);
        VirtualFree(testBuffer, 0, MEM_RELEASE);
        CleanupCleanCopy(&cleanCopyInfo);
        return 1;
    }

    __try {
        typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
            HANDLE ProcessHandle,
            PVOID *BaseAddress,
            PSIZE_T RegionSize,
            ULONG NewProtect,
            PULONG OldProtect
        );

        pNtProtectVirtualMemory stubFunc = (pNtProtectVirtualMemory)protectStub->Code;
        NTSTATUS status = stubFunc(
            GetCurrentProcess(),
            &testAddr,
            &testSize,
            PAGE_READONLY,
            &testOldProt
        );

        printf("[*] Stub call returned status: 0x%08X\n", status);
        fflush(stdout);

        if (!NT_SUCCESS(status)) {
            printf("[-] Stub call failed\n");
            fflush(stdout);
            VirtualFree(testBuffer, 0, MEM_RELEASE);
            CleanupCleanCopy(&cleanCopyInfo);
            return 1;
        }

        DWORD dummy;
        VirtualProtect(testAddr, testSize, testOldProt, &dummy);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception during stub test: 0x%08X\n", GetExceptionCode());
        fflush(stdout);
        VirtualFree(testBuffer, 0, MEM_RELEASE);
        CleanupCleanCopy(&cleanCopyInfo);
        return 1;
    }

    if (!EncryptCleanCopy(&cleanCopyInfo)) {
        printf("[-] Failed to re-encrypt clean copy\n");
        fflush(stdout);
        VirtualFree(testBuffer, 0, MEM_RELEASE);
        CleanupCleanCopy(&cleanCopyInfo);
        return 1;
    }

    printf("[*] Cleaning up...\n");
    fflush(stdout);
    VirtualFree(testBuffer, 0, MEM_RELEASE);
    CleanupCleanCopy(&cleanCopyInfo);
    printf("[+] Done\n");
    fflush(stdout);
    return 0;
} 