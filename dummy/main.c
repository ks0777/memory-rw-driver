#include "main.h"

UINT64 clientPID = 0;
PVOID sharedBuffer;
CHAR actionCompleted = 'x';

void handler() {
    if (clientPID == 0) {
        clientPID = GetPidFromProcessName("apeks.exe");
        if (clientPID != 0) _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PID: %llu\n", clientPID);
    }

    //ExFreePoolWithTag(Context, 'krow');
    if (sharedBuffer && clientPID != 0) {
        NTSTATUS status = readVirtualMemory(clientPID, 0x42000000, sharedBuffer, 0x100);

        if (NT_SUCCESS(status)) {
            if (*(CHAR*)sharedBuffer == 'r') {
                *(CHAR*)sharedBuffer = 'x';
                //_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found read instruction pid: %u addr: %llx size: %u\n", *(UINT32*)((CHAR*)sharedBuffer + 1), *(UINT64*)((CHAR*)sharedBuffer + 5), *(UINT32*)((CHAR*)sharedBuffer + 13));
                memset((CHAR*)sharedBuffer + 17, 0, *(UINT32*)((CHAR*)sharedBuffer + 13));
                readVirtualMemory(*(UINT32*)((CHAR*)sharedBuffer + 1), *(UINT64*)((CHAR*)sharedBuffer + 5), (CHAR*)sharedBuffer + 17, *(UINT32*)((CHAR*)sharedBuffer + 13));
                writeVirtualMemory(clientPID, 0x42000000, sharedBuffer, 0x100);
            }
            else if (*(CHAR*)sharedBuffer == 'w') {
                writeVirtualMemory(*(UINT32*)((CHAR*)sharedBuffer + 1), *(UINT64*)((CHAR*)sharedBuffer + 5), (CHAR*)sharedBuffer + 17, *(UINT32*)((CHAR*)sharedBuffer + 13));
                writeVirtualMemory(clientPID, 0x42000000, &actionCompleted, sizeof(CHAR));
            }
            else if (*(CHAR*)sharedBuffer == 'm') {
                //_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PID: %u Module name: %s\n", *(UINT32*)((CHAR*)sharedBuffer + 1), (CHAR*)sharedBuffer + 5);
                PVOID baseAddr = GetProcessModuleBase(*(UINT32*)((CHAR*)sharedBuffer + 1), (CHAR*)sharedBuffer + 5);
                *(CHAR*)sharedBuffer = 'x';
                *(UINT64*)((CHAR*)sharedBuffer + 0x38) = baseAddr;
                writeVirtualMemory(clientPID, 0x42000000, sharedBuffer, 0x100);
            }
            else if (*(CHAR*)sharedBuffer == 'p') {
                UINT32 pid = GetPidFromProcessName((CHAR*)sharedBuffer + 5);
                *(CHAR*)sharedBuffer = 'x';
                *(UINT32*)((CHAR*)sharedBuffer + 1) = pid;
                writeVirtualMemory(clientPID, 0x42000000, sharedBuffer, 0x100);
            }
        }
        else if (status == STATUS_INVALID_CID) {
            clientPID = GetPidFromProcessName("apeks.exe");
        }
        else {
            //_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Error while reading from Client: %d\n", status);
        }
    }
}

void hookFn() {
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
    __nop();
}

NTSTATUS hookTcpReceive() {
    PVOID ntfsBase = GetSystemModuleBase("\\SystemRoot\\System32\\Drivers\\Npfs.SYS", NULL);
    _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Base address for module: %p\n", ntfsBase);
    if (!ntfsBase) {
        return STATUS_ACCESS_DENIED;
    }
    PVOID hookLocation = (UCHAR*)ntfsBase + 0xd0b7;
    
    *(UINT64*)((UCHAR*)&hookFn + 84) = (UINT64)((UCHAR*)hookLocation + 13);

    PMDL pMdl = IoAllocateMdl(hookLocation, 0x20, FALSE, FALSE, NULL);
    if (!pMdl) {
        _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Could not allocate Mdl\n");
        return STATUS_ACCESS_DENIED;
    }

    __try {
        MmProbeAndLockPages(pMdl, KernelMode, ReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Probing and Locking Pages failed %u\n", GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }

    PVOID dst = MmMapLockedPages(pMdl, KernelMode);
    if (!dst) {
        _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmMapLockedPages failed!\n");
        IoFreeMdl(pMdl);
        return STATUS_ACCESS_DENIED;
    }

    NTSTATUS status = MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Error occured while changing protection: 0x%lx\n", status);
        IoFreeMdl(pMdl);
        return STATUS_ACCESS_DENIED;
    }

    _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "hookFn: %p\n", &hookFn);

    CHAR* shellcode = "\x50\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0\x58";
    RtlCopyMemory(dst, shellcode, 14);

    *(UINT64*)((UCHAR*)dst + 3) = (UINT64)&hookFn;


    MmUnmapLockedPages(dst, pMdl);
    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);

    _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Successfully placed hook into Ntfs.sys!\n");

    return STATUS_SUCCESS;
}

void buildHookFn() {
    CHAR* shellcodePush = "\x53\x51\x52\x55\x56\x57\x54\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xec\x70";
    RtlCopyMemory((PVOID)&hookFn, shellcodePush, 27);

    CHAR* shellcodeCallHandler = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xd0";
    RtlCopyMemory((UCHAR*)&hookFn + 27, shellcodeCallHandler, 12);
    *(UINT64*)((UCHAR*)&hookFn + 29) = (UINT64)&handler;

    CHAR* shellcodePop = "\x48\x83\xC4\x70\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5C\x5F\x5E\x5D\x5A\x59\x5B\x58\x50";
    RtlCopyMemory((UCHAR*)&hookFn + 39, shellcodePop, 29);

    CHAR* shellcodeOverwritten = "\x48\x8b\x9a\xb8\x00\x00\x00\x4c\x8b\xf2\x49\x89\x43\xb0";
    RtlCopyMemory((UCHAR*)&hookFn + 68, shellcodeOverwritten, 14);

    CHAR* shellcodeJump = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0";
    RtlCopyMemory((UCHAR*)&hookFn + 82, shellcodeJump, 12);
}

NTSTATUS DriverEntry(
    _In_  struct _DRIVER_OBJECT *DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    PEPROCESS Process;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Hello from kernel mode, system range start is %p, code mapped at %p\n", MmSystemRangeStart, DriverEntry);

    Process = PsGetCurrentProcess();
    _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "I'm at %s, Process : %llu (%p)\n",
        __FUNCTION__,
        (UINT64)PsGetCurrentProcessId(),
        Process);

    cleanupDDBEntry();

    sharedBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, 0x100, 'aBcD');

    //PrintCurrentIRQL();

    buildHookFn();

    hookTcpReceive();

    return STATUS_SUCCESS;
}