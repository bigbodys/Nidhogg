#include "pch.h"
#include "MemoryHelper.h"

/*
* Description:
* FindPatterns is responsible for finding one or more patterns in memory range.
*
* Parameters:
* @patterns		 [_In_ Pattern[]]	-- Pattern to search for.
* @patternsCount [_In_ SIZE_T]		-- Number of patterns to search for.
* @base			 [_In_ const PVOID] -- Base address for searching.
* @size			 [_In_ SIZE_T]		-- Address range to search in.
* @foundIndex	 [_Out_ PULONG]		-- Index of the found signature.
* @reversed		 [_In_ bool]		-- If want to reverse search or regular search.
*
* Returns:
* @address		 [PVOID]			-- Pattern's address if found, else 0.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID FindPatterns(_In_ const Pattern patterns[],
	_In_ SIZE_T patternsCount,
	_In_ const PVOID base,
	_In_ SIZE_T size,
	_Out_opt_ PULONG foundIndex,
	_In_ KPROCESSOR_MODE mode) noexcept {
	PVOID address = nullptr;

	if (foundIndex)
		*foundIndex = 0;

	for (SIZE_T i = 0; i < patternsCount; i++) {
		address = FindPattern(patterns[i], base, size, foundIndex, mode);

		if (address)
			break;
	}
	return address;
}
/*
* Description:
* FindPattern is responsible for finding a pattern in memory range.
*
* Parameters:
* @pattern	  [_In_ Pattern]	 -- Pattern to search for.
* @base		  [_In_ const PVOID] -- Base address for searching.
* @size		  [_In_ SIZE_T]		 -- Address range to search in.
* @foundIndex [_Out_ PULONG]	 -- Index of the found signature.
* @reversed	  [_In_ bool]		 -- If want to reverse search or regular search.
*
* Returns:
* @address	  [PVOID]			 -- Pattern's address if found, else 0.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID FindPattern(_In_ Pattern pattern,
	_In_ const PVOID base, 
	_In_ SIZE_T size, 
	_Out_opt_ PULONG foundIndex,
	_In_ KPROCESSOR_MODE mode) noexcept {
	bool found = false;

	if (foundIndex)
		*foundIndex = 0;

	if (!pattern.Data || !base || pattern.Length == 0 || size == 0 || pattern.Length > size)
		return nullptr;

	if (pattern.Versions.MinVersion > WindowsBuildNumber ||
		pattern.Versions.MaxVersion < WindowsBuildNumber)
		return nullptr;
	MemoryGuard guard(const_cast<PVOID>(base), static_cast<ULONG>(size), mode);

	if (!guard.IsValid())
		return nullptr;

	if (!pattern.Reversed) [[ likely ]] {
		for (ULONG_PTR i = 0; i < size; i++) {
			found = true;

			for (ULONG_PTR j = 0; j < pattern.Length; j++) {
				if (i + j >= size) {
					found = false;
					break;
				}

				if (pattern.Data[j] != pattern.Wildcard && pattern.Data[j] != (static_cast<PCUCHAR>(base))[i + j]) {
					found = false;
					break;
				}
			}

			if (found) {
				if (foundIndex)
					*foundIndex = static_cast<ULONG>(i);
				return static_cast<PUCHAR>(base) + i + pattern.RelativeOffset;
			}
		}
	}
	else {
		for (int i = static_cast<int>(size); i >= 0; i--) {
			found = true;

			for (ULONG_PTR j = 0; j < pattern.Length; j++) {
				if (pattern.Data[j] != pattern.Wildcard && pattern.Data[j] != *(static_cast<PCUCHAR>(base) - i + j)) {
					found = false;
					break;
				}
			}

			if (found) {
				if (foundIndex)
					*foundIndex = i;
				return static_cast<PUCHAR>(base) - i - pattern.RelativeOffset;
			}
		}
	}

	return nullptr;
}

/*
* Description:
* CopyUnicodeString is responsible for copying unicode string.
*
* Parameters:
* @sourceProcess [_In_ const PEPROCESS&]   -- Source process.
* @source	     [_In_ PUNICODE_STRING]	   -- Source string.
* @targetProcess [_In_ const PEPROCESS&]   -- Target process.
* @target		 [_Inout_ PUNICODE_STRING] -- Target string.
* @mode			 [_In_ MODE]			   -- KernelMode / UserMode.
*
* Returns:
* @status		 [NTSTATUS]				   -- NTSUCCESS if succeeded else failure code.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS CopyUnicodeString(_In_ const PEPROCESS& sourceProcess, _In_ PUNICODE_STRING source, _In_ const PEPROCESS& targetProcess,
	_Inout_ PUNICODE_STRING target, _In_ MODE mode) {
	SIZE_T bytesWritten = 0;
	NTSTATUS status = STATUS_SUCCESS;

	target->Length = source->Length;
	target->MaximumLength = source->MaximumLength;

	if (!target->Buffer && mode == KernelMode) {
		target->Buffer = AllocateMemory<WCHAR*>(static_cast<SIZE_T>(target->Length));

		if (!target->Buffer)
			return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = MmCopyVirtualMemory(sourceProcess, source->Buffer, targetProcess,
		target->Buffer, target->Length, static_cast<KPROCESSOR_MODE>(mode), &bytesWritten);

	if (!NT_SUCCESS(status))
		FreeVirtualMemory(target->Buffer);
	return status;
}

/*
* Description:
* ProbeAddress is responsible for probing an address and returning specific status code on failure.
*
* Parameters:
* @address	   [PVOID]	  -- Address to probe.
* @len		   [SIZE_T]   -- Structure size.
* @alignment   [ULONG]    -- Address' required alignment.
*
* Returns:
* @status	   [NTSTATUS] -- NTSUCCESS if succeeded else failure code.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProbeAddress(_In_ const PVOID& address, _In_ SIZE_T len, _In_ ULONG alignment) {
	NTSTATUS status = STATUS_SUCCESS;

	if (!IsValidUmMemory(reinterpret_cast<ULONGLONG>(address)))
		return STATUS_INVALID_ADDRESS;

	__try {
		ProbeForRead(address, len, alignment);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	return status;
}

/*
* Description:
* WriteProcessMemory is responsible for writing data to any target process.
*
* Parameters:
* @sourceDataAddress [_In_ PVOID]			 -- The address of data to write.
* @targetProcess	 [_In_ const PEPROCESS&] -- Target process to write.
* @targetAddress	 [_In_ PVOID]			 -- Target address to write.
* @dataSize			 [_In_ SIZE_T]			 -- Size of data to write.
* @mode			     [_In_ MODE]			 -- Mode of the request (UserMode or KernelMode allowed).
* @alignAddr		 [_In_ bool]			 -- Whether to align the address or not.
*
* Returns:
* @status			 [NTSTATUS]				 -- Whether successfuly written or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS WriteProcessMemory(_In_ PVOID sourceDataAddress, _In_ const PEPROCESS& targetProcess, _Inout_ PVOID targetAddress,
	_In_ SIZE_T dataSize, _In_ MODE mode, _In_ bool alignAddr) {
	HANDLE hTargetProcess;
	ULONG oldProtection;
	SIZE_T patchLen;
	SIZE_T bytesWritten;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG alignment = static_cast<ULONG>(alignAddr ? dataSize : 1);

	if (mode != KernelMode && mode != UserMode)
		return STATUS_UNSUCCESSFUL;

	// Making sure that the given kernel mode address is valid.
	if (mode == KernelMode && (!IsValidKmMemory(reinterpret_cast<ULONG64>(sourceDataAddress)) ||
		(!IsValidKmMemory(reinterpret_cast<ULONG64>(targetAddress)) &&
			!NT_SUCCESS(ProbeAddress(targetAddress, dataSize, alignment))))) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	else if (mode == UserMode && (
		!NT_SUCCESS(ProbeAddress(sourceDataAddress, dataSize, static_cast<ULONG>(dataSize))) ||
		(!IsValidKmMemory(reinterpret_cast<ULONG64>(targetAddress)) &&
			!NT_SUCCESS(ProbeAddress(targetAddress, dataSize, alignment))))) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	// Adding write permissions.
	status = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, 
		static_cast<KPROCESSOR_MODE>(mode), &hTargetProcess);

	if (!NT_SUCCESS(status))
		return status;

	patchLen = dataSize;
	PVOID addressToProtect = targetAddress;
	status = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);

	if (!NT_SUCCESS(status)) {
		ZwClose(hTargetProcess);
		return status;
	}

	// Writing the data.
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceDataAddress, targetProcess, targetAddress, dataSize, KernelMode, &bytesWritten);

	// Restoring permissions and cleaning up.
	patchLen = dataSize;
	status = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, oldProtection, &oldProtection);
	ZwClose(hTargetProcess);
	return status;
}

/*
* Description:
* GetModuleBase is responsible for getting the base address of given module inside a given process.
*
* Parameters:
* @Process    [PEPROCESS] -- The process to search on.
* @moduleName [WCHAR*]	  -- Module's name to search.
*
* Returns:
* @moduleBase [PVOID]	  -- Base address of the module if found, else null.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID GetModuleBase(_In_ PEPROCESS process, _In_ const wchar_t* moduleName) {
	PVOID moduleBase = NULL;
	LARGE_INTEGER time = { 0 };
	time.QuadPart = ONE_SECOND;
	SIZE_T moduleLen = wcslen(moduleName);

	if (!process || moduleLen == 0)
		ExRaiseStatus(STATUS_INVALID_PARAMETER);

	PREALPEB targetPeb = reinterpret_cast<PREALPEB>(PsGetProcessPeb(process));

	if (!targetPeb)
		ExRaiseStatus(STATUS_ABANDONED);

	for (int i = 0; !targetPeb->LoaderData && i < 10; i++) {
		KeDelayExecutionThread(KernelMode, FALSE, &time);
	}

	if (!targetPeb->LoaderData)
		ExRaiseStatus(STATUS_ABANDONED);

	// Getting the module's image base.
	for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
		pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (pEntry->FullDllName.Length == static_cast<USHORT>(moduleLen * 2)) {
			if (RtlCompareUnicodeStrings(pEntry->FullDllName.Buffer, moduleLen, moduleName, moduleLen, TRUE) == 0) {
				moduleBase = pEntry->DllBase;
				break;
			}
		}
	}

	if (!moduleBase)
		ExRaiseStatus(STATUS_NOT_FOUND);
	return moduleBase;
}

/*
* Description:
* GetUserModeFuncAddress is responsible for getting the function address inside given module from its EAT.
*
* Parameters:
* @functionName [_In_ const char*]	  -- Function name to search.
* @moduleName   [_In_ const wchar_t*] -- Module's name to search.
* @processName 	[_In_ wchar_t*]		  -- Process name to search.
*
* Returns:
* @PVOID							  -- Function address if found, else status is raised.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID GetUserModeFuncAddress(_In_ const char* functionName, _In_ const wchar_t* moduleName, _In_ const wchar_t* processName) {
	ULONG searchedPid = 0;

	__try {
		searchedPid = FindPidByName(processName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(GetExceptionCode());
	}

	return GetUserModeFuncAddress(functionName, moduleName, searchedPid);
}

/*
* Description:
* GetUserModeFuncAddress is responsible for getting the function address inside given module from its EAT.
*
* Parameters:
* @functionName [_In_ const char*]	  -- Function name to search.
* @moduleName   [_In_ const wchar_t*] -- Module's name to search.
* @pid 			[_In_ ULONG]		  -- Process id to search.
*
* Returns:
* @PVOID							  -- Function address if found, else status is raised.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID GetUserModeFuncAddress(_In_ const char* functionName, _In_ const wchar_t* moduleName, _In_ ULONG pid) {
	KAPC_STATE state;
	PVOID moduleBase = nullptr;
	PEPROCESS process = nullptr;
	PVOID functionAddress = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);

	if (!NT_SUCCESS(status))
		ExRaiseStatus(status);

	// Attaching to the process's stack to be able to walk the PEB.
	KeStackAttachProcess(process, &state);

	__try {
		moduleBase = GetModuleBase(process, moduleName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(process);
		ExRaiseStatus(GetExceptionCode());
	}

	if (!moduleBase) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(process);
		ExRaiseStatus(STATUS_NOT_FOUND);
	}
	functionAddress = RtlFindExportedRoutineByName(moduleBase, functionName);

	KeUnstackDetachProcess(&state);
	ObDereferenceObject(process);

	if (!functionAddress)
		ExRaiseStatus(STATUS_NOT_FOUND);
	return functionAddress;
}

/*
* Description:
* GetSSDTFunctionAddress is responsible for getting the SSDT's location.
*
* Parameters:
* @ssdt			   [_In_ const PSYSTEM_SERVICE_DESCRIPTOR_TABLE] -- SSDT to search in.
* @functionName	   [_In_ const char*]							 -- Function name to search.
*
* Returns:
* @functionAddress [PVOID]										 -- Function address if found.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID GetSSDTFunctionAddress(_In_ const PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt, _In_ const char* functionName) {
	KAPC_STATE state;
	PEPROCESS csrssProcess = NULL;
	PVOID functionAddress = NULL;
	PVOID ntdllFunctionAddress = NULL;
	SIZE_T index = 0;
	UCHAR syscall = 0;
	ULONG csrssPid = 0;
	errno_t err = 0;
	WCHAR* mainDriveLetter = nullptr;
	const WCHAR ntdllPath[] = L"\\Windows\\System32\\ntdll.dll";
	const SIZE_T fullPathLength = DRIVE_LETTER_SIZE + wcslen(ntdllPath) + 1;
	MemoryAllocator<WCHAR*> fullPath(fullPathLength * sizeof(WCHAR));

	if (!fullPath.IsValid())
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	__try {
		csrssPid = FindPidByName(L"csrss.exe");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(GetExceptionCode());
	}
	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(csrssPid), &csrssProcess);

	if (!NT_SUCCESS(status))
		ExRaiseStatus(status);

	// Attaching to the process's stack to be able to walk the PEB.
	IrqlGuard irqlGuard(PASSIVE_LEVEL);
	__try {
		mainDriveLetter = GetMainDriveLetter();
		err = wcscpy_s(fullPath.Get(), fullPathLength, mainDriveLetter);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		err = wcscat_s(fullPath.Get(), fullPathLength, ntdllPath);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		ntdllFunctionAddress = GetUserModeFuncAddress(functionName, fullPath.Get(), csrssPid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ObDereferenceObject(csrssProcess);
		FreeVirtualMemory(mainDriveLetter);
		ExRaiseStatus(GetExceptionCode());
	}
	FreeVirtualMemory(mainDriveLetter);
	irqlGuard.UnsetIrql();

	KeStackAttachProcess(csrssProcess, &state);

	// Searching for the syscall
	while ((static_cast<PUCHAR>(ntdllFunctionAddress))[index] != RETURN_OPCODE) {
		if ((static_cast<PUCHAR>(ntdllFunctionAddress))[index] == MOV_EAX_OPCODE) {
			syscall = (static_cast<PUCHAR>(ntdllFunctionAddress))[index + 1];
		}
		index++;
	}
	KeUnstackDetachProcess(&state);

	if (!syscall) {
		ObDereferenceObject(csrssProcess);
		ExRaiseStatus(STATUS_NOT_FOUND);
	}
	ObDereferenceObject(csrssProcess);

	__try {
		if (syscall != 0)
			functionAddress = reinterpret_cast<PUCHAR>(ssdt->ServiceTableBase) + 
			(reinterpret_cast<PLONG>(ssdt->ServiceTableBase)[syscall] >> SYSCALL_SHIFT);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(GetExceptionCode());
	}

	if (functionAddress == nullptr)
		ExRaiseStatus(STATUS_NOT_FOUND);

	return functionAddress;
}


/*
* Description:
* GetSSDTAddress is responsible for getting the SSDT's location.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if found, else error.
*/
_IRQL_requires_max_(APC_LEVEL)
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTAddress() {
	ULONG infoSize = 0;
	PVOID ssdtRelativeLocation = NULL;
	PVOID ntoskrnlBase = NULL;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = NULL;
	PRTL_PROCESS_MODULES info = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	// Getting ntoskrnl base first.
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		FreeVirtualMemory(info);
		info = AllocateMemory<PRTL_PROCESS_MODULES>(infoSize);

		if (!info) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info)
		ExRaiseStatus(status);
	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		if (NtCreateFile >= modules[i].ImageBase &&
			static_cast<PVOID>(static_cast<PUCHAR>(modules[i].ImageBase) + modules[i].ImageSize) > NtCreateFile) {
			ntoskrnlBase = modules[i].ImageBase;
			break;
		}
	}

	if (!ntoskrnlBase) {
		FreeVirtualMemory(info);
		ExRaiseStatus(STATUS_NOT_FOUND);
	}
	PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(ntoskrnlBase);

	// Finding the SSDT address.
	status = STATUS_NOT_FOUND;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		FreeVirtualMemory(info);
		ExRaiseStatus(STATUS_INVALID_ADDRESS);
	}

	PFULL_IMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PFULL_IMAGE_NT_HEADERS>(static_cast<PUCHAR>(ntoskrnlBase) + 
		dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		FreeVirtualMemory(info);
		ExRaiseStatus(STATUS_INVALID_ADDRESS);
	}

	PIMAGE_SECTION_HEADER firstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(ntHeaders + 1);

	for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeaders->FileHeader.NumberOfSections; section++) {
		if (strcmp(reinterpret_cast<const char*>(section->Name), ".text") == 0) {
			ssdtRelativeLocation = FindPattern(SsdtPattern, static_cast<PUCHAR>(ntoskrnlBase) + section->VirtualAddress, 
				section->Misc.VirtualSize, nullptr, KernelMode);

			if (ssdtRelativeLocation) {
				status = STATUS_SUCCESS;
				ssdt = reinterpret_cast<PSYSTEM_SERVICE_DESCRIPTOR_TABLE>(static_cast<PUCHAR>(ssdtRelativeLocation) + 
					*static_cast<PULONG>(ssdtRelativeLocation) + 4);
				break;
			}
		}
	}
	FreeVirtualMemory(info);

	if (!NT_SUCCESS(status))
		ExRaiseStatus(status);
	return ssdt;
}

/*
* Description:
* ConvertAnsiToUnicode is responsible for converting ANSI string to UNICODE.
*
* Parameters:
* @ansiString [_In_ PCHAR]			  -- Source string to convert.
* @outString  [_Out_ PUNICODE_STRING] -- Output unicode string.
*
* Returns:
* @status	  [NTSTATUS]			  -- Whether successfuly converted or not.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ConvertAnsiToUnicode(_In_ PCHAR ansiString, _Out_ PUNICODE_STRING outString) {
	if (!ansiString || !outString)
		return STATUS_INVALID_PARAMETER;
	ANSI_STRING aFunctionName = { 0 };
	RtlInitAnsiString(&aFunctionName, ansiString);
	return RtlAnsiStringToUnicodeString(outString, &aFunctionName, TRUE);;
}

constexpr ULONG KPROCESS_DIRECTORY_TABLE_BASE_OFFSET = 0x28;
constexpr ULONG64 PTE_PRESENT_FLAG = 0x1;
constexpr ULONG64 PTE_LARGE_PAGE_FLAG = 0x80;
constexpr ULONG64 PTE_PFN_MASK = 0x000FFFFFFFFFF000ULL;
constexpr ULONG64 PDE_1GB_PFN_MASK = 0x000FFFFFC0000000ULL;
constexpr ULONG64 PDE_2MB_PFN_MASK = 0x000FFFFFFFE00000ULL;
constexpr SIZE_T PAGE_SIZE_4KB = 0x1000;
constexpr SIZE_T PAGE_SIZE_2MB = 0x200000;
constexpr SIZE_T PAGE_SIZE_1GB = 0x40000000;

/*
* Description:
* GetUserDirectoryTableBaseOffset is responsible for returning the KPROCESS.UserDirectoryTableBase
* offset for the current Windows build.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @offset [ULONG] -- Offset from KPROCESS, or 0 if the field does not exist.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG GetUserDirectoryTableBaseOffset() {
	if (WindowsBuildNumber >= WIN_2004)
		return 0x388;

	if (WindowsBuildNumber >= WIN_1903)
		return 0x280;

	if (WindowsBuildNumber >= WIN_1803)
		return 0x278;

	return 0;
}

/*
* Description:
* GetProcessCr3 is responsible for resolving a process CR3 from a PID.
* When KVA shadow is enabled, UserDirectoryTableBase is preferred.
*
* Parameters:
* @pid [_In_ ULONG]	   -- Target process id.
* @cr3 [_Out_ PULONG64] -- Receives the process CR3.
*
* Returns:
* @status [NTSTATUS] -- Whether the CR3 was resolved successfully or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS GetProcessCr3(_In_ ULONG pid, _Out_ PULONG64 cr3) {
	if (!pid || !cr3)
		return STATUS_INVALID_PARAMETER;

	*cr3 = 0;
	PEPROCESS process = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);

	if (!NT_SUCCESS(status))
		return status;

	ULONG64 directoryTableBase = *reinterpret_cast<PULONG64>(
		reinterpret_cast<PUCHAR>(process) + KPROCESS_DIRECTORY_TABLE_BASE_OFFSET);
	ULONG userDirectoryTableBaseOffset = GetUserDirectoryTableBaseOffset();
	ULONG64 resolvedCr3 = directoryTableBase;

	if (userDirectoryTableBaseOffset) {
		ULONG64 userDirectoryTableBase = *reinterpret_cast<PULONG64>(
			reinterpret_cast<PUCHAR>(process) + userDirectoryTableBaseOffset);

		if ((userDirectoryTableBase & PTE_PFN_MASK) != 0)
			resolvedCr3 = userDirectoryTableBase;
	}

	ObDereferenceObject(process);

	if ((resolvedCr3 & PTE_PFN_MASK) == 0)
		return STATUS_NOT_FOUND;

	*cr3 = resolvedCr3;
	return STATUS_SUCCESS;
}

/*
* Description:
* ReadPhysicalMemory is responsible for reading physical memory into a kernel buffer.
*
* Parameters:
* @physicalAddress [_In_ ULONG64] -- Physical address to read.
* @buffer		   [_Out_ PVOID]  -- Destination buffer.
* @size			   [_In_ SIZE_T]  -- Number of bytes to read.
*
* Returns:
* @status [NTSTATUS] -- Whether the read succeeded or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ReadPhysicalMemory(_In_ ULONG64 physicalAddress, _Out_writes_bytes_(size) PVOID buffer, _In_ SIZE_T size) {
	if (!buffer || size == 0)
		return STATUS_INVALID_PARAMETER;

	MM_COPY_ADDRESS source{};
	source.PhysicalAddress.QuadPart = static_cast<LONGLONG>(physicalAddress);
	SIZE_T bytesRead = 0;
	NTSTATUS status = MmCopyMemory(buffer, source, size, MM_COPY_MEMORY_PHYSICAL, &bytesRead);

	if (!NT_SUCCESS(status))
		return status;

	return bytesRead == size ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

/*
* Description:
* TranslateVirtualToPhysical is responsible for walking a process page table using CR3
* and translating a virtual address to a physical address.
*
* Parameters:
* @cr3			   [_In_ ULONG64]	  -- Process CR3 / directory table base.
* @virtualAddress  [_In_ ULONG64]	  -- Virtual address to translate.
* @physicalAddress [_Out_ PULONG64]	  -- Receives the translated physical address.
* @pageSize		   [_Out_opt_ PSIZE_T] -- Receives the leaf page size if provided.
*
* Returns:
* @status [NTSTATUS] -- Whether the translation succeeded or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS TranslateVirtualToPhysical(_In_ ULONG64 cr3, _In_ ULONG64 virtualAddress, _Out_ PULONG64 physicalAddress,
	_Out_opt_ PSIZE_T pageSize) {
	if (!physicalAddress || (cr3 & PTE_PFN_MASK) == 0)
		return STATUS_INVALID_PARAMETER;

	*physicalAddress = 0;

	if (pageSize)
		*pageSize = 0;

	ULONG64 entry = 0;
	NTSTATUS status = ReadPhysicalMemory((cr3 & PTE_PFN_MASK) + ((virtualAddress >> 39) & 0x1FF) * sizeof(ULONG64),
		&entry, sizeof(entry));

	if (!NT_SUCCESS(status) || (entry & PTE_PRESENT_FLAG) == 0)
		return NT_SUCCESS(status) ? STATUS_INVALID_ADDRESS : status;

	status = ReadPhysicalMemory((entry & PTE_PFN_MASK) + ((virtualAddress >> 30) & 0x1FF) * sizeof(ULONG64),
		&entry, sizeof(entry));

	if (!NT_SUCCESS(status) || (entry & PTE_PRESENT_FLAG) == 0)
		return NT_SUCCESS(status) ? STATUS_INVALID_ADDRESS : status;

	if (entry & PTE_LARGE_PAGE_FLAG) {
		*physicalAddress = (entry & PDE_1GB_PFN_MASK) | (virtualAddress & (PAGE_SIZE_1GB - 1));

		if (pageSize)
			*pageSize = PAGE_SIZE_1GB;
		return STATUS_SUCCESS;
	}

	status = ReadPhysicalMemory((entry & PTE_PFN_MASK) + ((virtualAddress >> 21) & 0x1FF) * sizeof(ULONG64),
		&entry, sizeof(entry));

	if (!NT_SUCCESS(status) || (entry & PTE_PRESENT_FLAG) == 0)
		return NT_SUCCESS(status) ? STATUS_INVALID_ADDRESS : status;

	if (entry & PTE_LARGE_PAGE_FLAG) {
		*physicalAddress = (entry & PDE_2MB_PFN_MASK) | (virtualAddress & (PAGE_SIZE_2MB - 1));

		if (pageSize)
			*pageSize = PAGE_SIZE_2MB;
		return STATUS_SUCCESS;
	}

	status = ReadPhysicalMemory((entry & PTE_PFN_MASK) + ((virtualAddress >> 12) & 0x1FF) * sizeof(ULONG64),
		&entry, sizeof(entry));

	if (!NT_SUCCESS(status) || (entry & PTE_PRESENT_FLAG) == 0)
		return NT_SUCCESS(status) ? STATUS_INVALID_ADDRESS : status;

	*physicalAddress = (entry & PTE_PFN_MASK) | (virtualAddress & (PAGE_SIZE_4KB - 1));

	if (pageSize)
		*pageSize = PAGE_SIZE_4KB;
	return STATUS_SUCCESS;
}

/*
* Description:
* ReadVirtualMemoryByCr3 is responsible for reading virtual memory by translating it through
* the provided process CR3 and reading the backing physical pages.
*
* Parameters:
* @cr3			  [_In_ ULONG64] -- Process CR3 / directory table base.
* @virtualAddress [_In_ ULONG64] -- Virtual address to read.
* @buffer		  [_Out_ PVOID]  -- Destination buffer.
* @size			  [_In_ SIZE_T]  -- Number of bytes to read.
*
* Returns:
* @status [NTSTATUS] -- Whether the read succeeded or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ReadVirtualMemoryByCr3(_In_ ULONG64 cr3, _In_ ULONG64 virtualAddress, _Out_writes_bytes_(size) PVOID buffer,
	_In_ SIZE_T size) {
	if (!buffer || size == 0 || (cr3 & PTE_PFN_MASK) == 0)
		return STATUS_INVALID_PARAMETER;

	auto dest = static_cast<PUCHAR>(buffer);

	while (size) {
		ULONG64 physicalAddress = 0;
		SIZE_T mappedPageSize = 0;
		NTSTATUS status = TranslateVirtualToPhysical(cr3, virtualAddress, &physicalAddress, &mappedPageSize);

		if (!NT_SUCCESS(status) || mappedPageSize == 0)
			return NT_SUCCESS(status) ? STATUS_INVALID_ADDRESS : status;

		SIZE_T remainingInPage = mappedPageSize - (virtualAddress & (mappedPageSize - 1));
		SIZE_T toRead = size < remainingInPage ? size : remainingInPage;
		status = ReadPhysicalMemory(physicalAddress, dest, toRead);

		if (!NT_SUCCESS(status))
			return status;

		virtualAddress += toRead;
		dest += toRead;
		size -= toRead;
	}

	return STATUS_SUCCESS;
}