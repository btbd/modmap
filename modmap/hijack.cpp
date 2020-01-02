#include "stdafx.h"

namespace Hijack {
	BOOLEAN HijackViaHook(Comm::Process &process, PVOID entry, LPCWSTR moduleName, LPCSTR functionName) {
		printf("\n[-] hijacking execution via hook\n");

		PBYTE remoteModuleBase = NULL;
		DWORD remoteModuleSize = 0;
		if (process.Module(moduleName, &remoteModuleBase, &remoteModuleSize) != ERROR_SUCCESS) {
			errorf("failed to find module %ws in process\n", moduleName);
			return FALSE;
		}

		auto module = LoadLibrary(moduleName);
		if (!module) {
			errorf("failed to load module %ws\n", moduleName);
			return FALSE;
		}

		auto function = reinterpret_cast<PBYTE>(GetProcAddress(module, functionName));
		if (!function) {
			errorf("failed to find function %ws:%s\n", moduleName, functionName);
			return FALSE;
		}

		auto remoteFunction = remoteModuleBase + (function - reinterpret_cast<PBYTE>(module));

		BYTE shellcode[] = { 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x10, 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x50, 0x08, 0x48, 0x83, 0xEC, 0x28, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0x48, 0x31, 0xC0, 0xC6, 0x05, 0xAE, 0xFF, 0xFF, 0xFF, 0x01, 0xC3 };
		*reinterpret_cast<PVOID *>(&shellcode[3]) = remoteFunction;
		process.Read(&shellcode[13], remoteFunction, sizeof(ULONG64));
		process.Read(&shellcode[26], remoteFunction + sizeof(ULONG64), sizeof(ULONG64));
		*reinterpret_cast<PVOID *>(&shellcode[60]) = entry;

		auto mappedShellcode = reinterpret_cast<PBYTE>(process.Alloc(sizeof(shellcode), PAGE_EXECUTE_READWRITE));
		if (!mappedShellcode) {
			errorf("failed to allocate virtual memory for hook hijack shellcode\n");
			return FALSE;
		}

		process.Write(mappedShellcode, shellcode, sizeof(shellcode));

		BYTE jump[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
		*reinterpret_cast<PVOID *>(&jump[6]) = mappedShellcode + 1;

		DWORD protect = PAGE_EXECUTE_READWRITE;
		process.Protect(remoteFunction, 2 * sizeof(ULONG64), &protect);

		process.Write(remoteFunction, jump, sizeof(jump));

		printf("[+] waiting for shellcode to execute...\n");
		for (auto functionBytes = 0ULL;; Sleep(1)) {
			if (process.Read(&functionBytes, remoteFunction + 6, sizeof(functionBytes)) != ERROR_SUCCESS) {
				errorf("failed to read function bytes at %p\n", remoteFunction + 6);
				return FALSE;
			}

			if (functionBytes != *reinterpret_cast<PULONG64>(&jump[6])) {
				break;
			}
		}

		process.Protect(remoteFunction, sizeof(jump), &protect);

		for (BYTE status = 0;; Sleep(1)) {
			if (process.Read(&status, mappedShellcode, sizeof(status)) != ERROR_SUCCESS) {
				errorf("failed to read shellcode status at %p\n", mappedShellcode);
				return FALSE;
			}

			if (status) {
				break;
			}
		}

		process.Free(mappedShellcode);

		printf("[+] executed\n");

		return TRUE;
	}
}