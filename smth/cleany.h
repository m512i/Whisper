#pragma once

#define WIN32_NO_STATUS      
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>       

#pragma comment(lib, "bcrypt.lib")
#ifndef _WIN64
#error "This code requires 64-bit Windows"
#endif

typedef struct _PEB *PPEB;
typedef struct _PEB_LDR_DATA *PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY *PLDR_DATA_TABLE_ENTRY;

#ifdef __cplusplus
extern "C" {
#endif

NTSYSAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID    *BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     NewProtect,
    PULONG    OldProtect
);


#define SYSCALL_STUB_SIZE 16

typedef struct _SYSCALL_STUB {
    BYTE   Code[SYSCALL_STUB_SIZE];  
    PVOID  OriginalFunction;          
    DWORD  SyscallNumber;             
} SYSCALL_STUB, *PSYSCALL_STUB;

typedef struct _CLEAN_COPY_INFO {
    HMODULE OriginalModule;
    PVOID CleanCopyBase;
    SIZE_T CleanCopySize;
    PVOID TextSectionBase;
    SIZE_T TextSectionSize;
    BYTE EncryptionKey[32];
    BOOL IsEncrypted;
    PSYSCALL_STUB Stubs;
    DWORD StubCount;
    PLDR_DATA_TABLE_ENTRY FakeLdrEntry;  
} CLEAN_COPY_INFO, *PCLEAN_COPY_INFO;

BOOL InitializeCleanCopy(
    _Out_ PCLEAN_COPY_INFO CleanCopyInfo
);

BOOL PatchIAT(
    _In_ PCLEAN_COPY_INFO CleanCopyInfo,
    _In_ LPCSTR FunctionName
);

BOOL AddCleanCopyToPEB(
    _In_ PCLEAN_COPY_INFO CleanCopyInfo
);

BOOL HideFromPEB(
    _In_ PCLEAN_COPY_INFO CleanCopyInfo
);

void CleanupCleanCopy(
    _In_ PCLEAN_COPY_INFO CleanCopyInfo
);

PVOID GetFunctionRVA(
    _In_ PVOID ModuleBase,
    _In_ LPCSTR FunctionName
);

BOOL GenerateSyscallStubs(
    _In_ PCLEAN_COPY_INFO CleanCopyInfo
);

BOOL EncryptCleanCopy(
    _In_ PCLEAN_COPY_INFO CleanCopyInfo
);

BOOL DecryptCleanCopy(
    _In_ PCLEAN_COPY_INFO CleanCopyInfo
);

#ifdef __cplusplus
}
#endif 