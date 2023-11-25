#include "utils.h"

UNICODE_STRING CharsToUni(CHAR* in) {
	ANSI_STRING as;
	UNICODE_STRING us;

	RtlInitAnsiString(&as, in);
	if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&us, &as, TRUE))) {
		return us;
	}

	RtlInitUnicodeString(&us, L"");
	return us;
}

PVOID FindPattern(PVOID startAddress, UINT64 length, UCHAR* signature, UCHAR* pattern) {
	size_t sigLen = strlen(pattern);
	UINT64 offset = 0;
	UINT32 sigOffset = 0;

	while (offset + sigLen <= length) {
		if (pattern[sigOffset] == '?' || (pattern[sigOffset] == 'x' && signature[sigOffset] == *((UCHAR*)startAddress + offset + sigOffset))) {
			if (++sigOffset == sigLen) {
				return (UCHAR*)startAddress + offset;
			}
		}
		else {
			offset++;
			sigOffset = 0;
		}
	}

	_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Did not find signature %s\n", signature);
	return 0;
}

PVOID GetSystemModuleBase(CHAR* modulePath, size_t* moduleSize) {
	UNICODE_STRING functionName;
	RtlInitUnicodeString(&functionName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = MmGetSystemRoutineAddress(&functionName);

	ULONG neededSize = 0;
	ZwQuerySystemInformation(SystemModuleInformation, 0, neededSize, &neededSize);
	PVOID buffer = ExAllocatePoolWithTag(NonPagedPoolNx, neededSize, 'yeet');
	if (buffer == 0) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Pool allocation failed\n");
		return 0;
	}

	if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, buffer, neededSize, NULL))) {
		PSYSTEM_MODULE_INFORMATION pModuleInfo = buffer;
		PSYSTEM_MODULE_INFORMATION_ENTRY pEntry = pModuleInfo->Module;

		for (ULONG i = 0; i < pModuleInfo->Count; i++) {
			//_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[GetModuleBase]: %s\n", pEntry->ImageName);
			if (strcmp(pEntry->ImageName, modulePath) == 0) {
				ExFreePoolWithTag(buffer, 0);
				if (moduleSize) {
					*moduleSize = pEntry->Size;
				}
				return pEntry->Base;
			}
			pEntry++;
		}
	}
	//else _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Couldn't query module information!\n");

	ExFreePoolWithTag(buffer, 'yeet');

	return 0;
}

UINT64 GetPidFromProcessName(CHAR* processName) {
	UNICODE_STRING uProcessName = CharsToUni(processName);


	UNICODE_STRING functionName;
	RtlInitUnicodeString(&functionName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = MmGetSystemRoutineAddress(&functionName);


	ULONG neededSize = 0;
	ZwQuerySystemInformation(SystemProcessInformation, 0, neededSize, &neededSize);
	PVOID buffer = ExAllocatePoolWithTag(NonPagedPoolNx, neededSize, 'teey');
	if (buffer == 0) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Pool allocation failed\n");
		return 0;
	}


	if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, buffer, neededSize, NULL))) {

		PSYSTEM_PROCESS_INFORMATION pProcessInfo = buffer;
		do {
			if (RtlEqualUnicodeString(&pProcessInfo->ImageName, &uProcessName, FALSE)) {
				UINT64 pid = (UINT64)pProcessInfo->UniqueProcessId;
				_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found PID for %wZ: %llu\n", &pProcessInfo->ImageName, (UINT64)pProcessInfo->UniqueProcessId);
				ExFreePoolWithTag(buffer, 'teey');
				return pid;
			}
			pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)(((UCHAR*)pProcessInfo) + pProcessInfo->NextEntryOffset);
		} while (pProcessInfo->NextEntryOffset != 0);
	}
	else _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Couldn't query proccess information!\n");

	ExFreePoolWithTag(buffer, 'teey');

	return 0;
}

NTSTATUS
readVirtualMemory(
	UINT64 pid,
	UINT64 addr,
	PVOID buffer,
	ULONG bytesToRead
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS proc;

	//_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Read request at virtual %p in PID %llu!\n", (PVOID)addr, pid);

	status = PsLookupProcessByProcessId((HANDLE)pid, &proc);
	if (!NT_SUCCESS(status)) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Error while looking up process %x!\n", status);
		return status;
	}


	/*LARGE_INTEGER time;
	KeQuerySystemTime(&time);
	if (time.QuadPart - PsGetProcessCreateTimeQuadPart(proc) < 5000000) {
		return STATUS_PROCESS_IN_JOB; // Process had no time to allocate shared buffer yet
	}*/
	

	KAPC_STATE state;
	KeStackAttachProcess(proc, &state);

	if (!MmIsAddressValid(addr)) {
		//_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Invalid address: 0x%llx\n", addr);
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(proc);
		return STATUS_INVALID_ADDRESS;
	}

	PMDL mdl = IoAllocateMdl((PVOID)addr, bytesToRead, FALSE, FALSE, NULL);
	if (!mdl) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Failed allocating mdl!\n");
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(proc);
		return STATUS_ACCESS_VIOLATION;
	}

	MmProbeAndLockPages(mdl, UserMode, IoReadAccess);

	PVOID dst = MmGetSystemAddressForMdlSafe(mdl, UserMode|MdlMappingNoExecute);
	if (!dst) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmGetSystemAddressForMdlSafe failed!\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(proc);
		return STATUS_ACCESS_VIOLATION;
	}

	if (MmIsAddressValid(dst)) {
		__try {
			RtlCopyMemory(buffer, dst, bytesToRead);
		}
		__except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ?
			EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Reading Memory failed\n");
			MmUnmapLockedPages(dst, mdl);
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			KeUnstackDetachProcess(&state);
			ObDereferenceObject(proc);
			return STATUS_ACCESS_VIOLATION;
		}
	}
	else {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "System MDL address invalid %p\n", dst);
		status = STATUS_INVALID_ADDRESS;
	}

	MmUnmapLockedPages(dst, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	KeUnstackDetachProcess(&state);

	ObDereferenceObject(proc);

	return status;
}

NTSTATUS
writeVirtualMemory(
	UINT64 pid,
	UINT64 addr,
	PVOID buffer,
	ULONG bytesToWrite
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS proc;

	//_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Write request at virtual %p in PID %llu with data %lx!\n", (PVOID)addr, pid, *(UINT32*)buffer);

	status = PsLookupProcessByProcessId((HANDLE)pid, &proc);
	if (!NT_SUCCESS(status)) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Error while looking up process %x!\n", status);
		return status;
	}

	KAPC_STATE state;
	KeStackAttachProcess(proc, &state);

	if (!MmIsAddressValid(addr)) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Invalid address: 0x%llx\n", addr);
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(proc);
		return STATUS_ACCESS_VIOLATION;
	}

	PMDL mdl = IoAllocateMdl((PVOID)addr, bytesToWrite, FALSE, FALSE, NULL);

	MmProbeAndLockPages(mdl, UserMode, IoReadAccess);

	PVOID dst = MmGetSystemAddressForMdlSafe(mdl, UserMode|MdlMappingNoExecute);
	if (!dst) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmGetSystemAddressForMdlSafe failed!\n");
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(proc);
		return STATUS_ACCESS_VIOLATION;
	}

	status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmProtectMdlSystemAddress returned status %lx\n", status);
		MmUnmapLockedPages(dst, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(proc);
		return status;
	}

	
	if (MmIsAddressValid(dst)) {
		__try {
			RtlCopyMemory(dst, buffer, bytesToWrite);
		}
		__except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ?
			EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Writing Memory failed\n");
			status = STATUS_ACCESS_VIOLATION;
		}
	}
	else {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "System MDL address invalid %p\n", dst);
		status = STATUS_INVALID_ADDRESS;
	}

	MmUnmapLockedPages(dst, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	KeUnstackDetachProcess(&state);

	ObDereferenceObject(proc);

	return status;
}

void PrintCurrentIRQL() {
	PWSTR sIrql;
	KIRQL Irql = KeGetCurrentIrql();

	switch (Irql) {

	case PASSIVE_LEVEL:
		sIrql = L"PASSIVE_LEVEL";
		break;
	case APC_LEVEL:
		sIrql = L"APC_LEVEL";
		break;
	case DISPATCH_LEVEL:
		sIrql = L"DISPATCH_LEVEL";
		break;
	case CMCI_LEVEL:
		sIrql = L"CMCI_LEVEL";
		break;
	case CLOCK_LEVEL:
		sIrql = L"CLOCK_LEVEL";
		break;
	case IPI_LEVEL:
		sIrql = L"IPI_LEVEL";
		break;
	case HIGH_LEVEL:
		sIrql = L"HIGH_LEVEL";
		break;
	default:
		sIrql = L"Unknown Value";
		break;
	}

	_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "KeGetCurrentIrql=%ws\n", sIrql);
}

PVOID GetProcessModuleBase(UINT64 pid, CHAR* moduleName) {
	PVOID base = 0;
	UNICODE_STRING uModuleName = CharsToUni(moduleName);

	PEPROCESS proc;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &proc);
	if (!NT_SUCCESS(status)) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Error %x while looking up process with pid %llu!\n", status, pid);
		return base;
	}

	PVOID PEB32 = PsGetProcessWow64Process(proc);

	PPEB pPeb = *(UINT64*)((UCHAR*)proc+0x550);

	KAPC_STATE apcState;
	KeStackAttachProcess(proc, &apcState);


	if (pPeb) {
		PPEB_LDR_DATA pLdr = *(UINT64*)((UCHAR*)pPeb + 0x18);
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PEB_LDR_DATA @0x%p\n", pLdr);

		PLIST_ENTRY entry = &pLdr->InLoadOrderModuleList;
		PLDR_DATA_TABLE_ENTRY tableEntry;

		PLIST_ENTRY firstEntry = entry;
		do {
			tableEntry = entry;
			entry = entry->Flink;

			if (RtlCompareUnicodeString(&uModuleName, &tableEntry->BaseDllName, TRUE) == 0) {
				_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found Module @0x%p (0x%p)\n", tableEntry->DllBase, &tableEntry->DllBase);
				//RtlCopyMemory(&base, &tableEntry->DllBase, sizeof(PVOID));
				base = tableEntry->DllBase;
				break;
			}
			_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[Module] %wZ (%u B) @0x%p\n", tableEntry->BaseDllName, tableEntry->SizeOfImage, tableEntry->DllBase);
		} while (firstEntry != entry);
	}


	if (PEB32 && !base) {
		ULONG PEB32_LDR_DATA = *(ULONG*)((UINT64)PEB32 + 0xC);
		ULONG entry = *(ULONG*)((UINT64)PEB32_LDR_DATA + 0xC);

		ULONG firstEntry = entry;
		do {
			USHORT strLength = *(USHORT*)(entry + 0x2C);
			ULONG baseDLLName = *(ULONG*)(entry + 0x30);
			_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[Module] %ws @0x%lx\n", baseDLLName, *(ULONG*)(entry + 0x18));
			if (strLength == uModuleName.Length) {
				if (!memcmp(uModuleName.Buffer, (PVOID)baseDLLName, strLength)) {
					base = *(ULONG*)(entry + 0x18);
					break;
				}

			}
			entry = *(ULONG*)entry;
		} while (entry != firstEntry);
	}

	KeUnstackDetachProcess(&apcState);

	ObDereferenceObject(proc);

	return base;

}

/*NTSTATUS cleanupUnloadedDrivers() {
	size_t moduleSize;
	PVOID ntoskrnlBase = GetModuleBase("\\SystemRoot\\system32\\ntoskrnl.exe", &moduleSize);
	if (ntoskrnlBase) _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found ntsokrnl base at %p\n", ntoskrnlBase);
	else return STATUS_DRIVER_INTERNAL_ERROR;

	PVOID addr = FindPattern(ntoskrnlBase, moduleSize, "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\xD2\x74\x3C", "xxx????xxxxxxxx");
	if (addr) _DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found signature address at %p\n", addr);
	else return STATUS_DRIVER_INTERNAL_ERROR;

	UINT32 offset = 0;
	__try {
		offset = *(UINT32*)((UCHAR*)addr + 3) + 7;
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found MmUnloadedDrivers offset %lx\n", offset);
	} except(EXCEPTION_EXECUTE_HANDLER) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Failed reading offset\n", offset);
		return STATUS_DRIVER_INTERNAL_ERROR;
	}

	PUNLOADED_DRIVERS pMmUnloadedDrivers = *(PUNLOADED_DRIVERS*)((UCHAR*)addr + offset);
	for (int i = 0; i < 50; i++) {
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "MmUnloadedDrivers[%d]: %wZ\n", i, pMmUnloadedDrivers[i].Name);
	}
}*/

NTSTATUS cleanupDDBEntry() {
	size_t moduleSize;
	PVOID ntoskrnlBase = GetSystemModuleBase("\\SystemRoot\\system32\\ntoskrnl.exe", &moduleSize);
	PVOID patternAddr = FindPattern(ntoskrnlBase, moduleSize, "\x48\x8d\x0d\x00\x00\x00\x00\x45\x33\xf6\x48\x89\x44\x24\x50", "xxx????xxxxxxxx");

	if (patternAddr) {
		PVOID PiDDBCacheTable = (UCHAR*)patternAddr + *(UINT32*)((UCHAR*)patternAddr + 3) + 7;
		_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PiDDBCacheTable@0x%p\n", PiDDBCacheTable);

		patternAddr = 0;
		patternAddr = FindPattern(ntoskrnlBase, moduleSize, "\x48\x8d\x0d\x00\x00\x00\x00\xe8\x84\x5c\xbc\xff", "xxx????xxxxx");
		if (patternAddr) {
			_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "0x%p\n", patternAddr);
			PVOID PiDDBLock = (UCHAR*)patternAddr + *(UINT32*)((UCHAR*)patternAddr + 3) + 7;
			_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PiDDBLock@0x%p\n", PiDDBLock);

			PiDDBCacheEntry dummyEntry;
			UNICODE_STRING driverName;
			RtlInitUnicodeString(&driverName, L"iqvw64e.sys");
			dummyEntry.DriverName = driverName;
			dummyEntry.TimeDateStamp = 0x5284EAC3;

			ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

			pPiDDBCacheEntry foundEntry = RtlLookupElementGenericTableAvl(PiDDBCacheTable, &dummyEntry);

			if (foundEntry) {
				//_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found entry for %wZ@0x%p!\n", foundEntry->DriverName, foundEntry);

				RemoveEntryList(&foundEntry->List);
				if (RtlDeleteElementGenericTableAvl(PiDDBCacheTable, foundEntry)) {
					//_DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Sucessfully deleted entry!\n");
				}
			}

			ExReleaseResourceLite(PiDDBLock);
		}
	}

	return STATUS_SUCCESS;
}