#include "stdafx.h"

PVOID(NTAPI *NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(PVOID, PVOID, PVOID, PVOID);

namespace Comm {
	BOOL Setup() {
		auto module = LoadLibrary(L"ntdll.dll");
		if (!module) {
			errorf("Failed to get a handle for NTDLL\n");
			return FALSE;
		}

		*reinterpret_cast<PVOID *>(&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) = GetProcAddress(module, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
		if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
			errorf("Failed to find \"NtConvertBetweenAuxiliaryCounterAndPerformanceCounter\"\n");
			return FALSE;
		}

		return TRUE;
	}

	NTSTATUS SendRequest(REQUEST_TYPE type, PVOID args, SIZE_T argsSize) {
		REQUEST_DATA request = { 0 };
		request.Unique = DATA_UNIQUE;
		request.Type = type;
		request.Arguments = args;

		auto requestPtr = &request;

		auto status = 0ULL;
		NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &requestPtr, &status, 0);
		return static_cast<NTSTATUS>(status);
	}

	Process::Process(LPCWSTR processName) {
		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			return;
		}

		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		if (Process32First(snapshot, &entry)) {
			do {
				if (_wcsicmp(entry.szExeFile, processName) == 0) {
					this->ProcessId = entry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	BOOLEAN Process::Valid() {
		return this->ProcessId != 0;
	}

	NTSTATUS Process::Extend(LPCWSTR moduleName, DWORD size) {
		REQUEST_EXTEND req = { 0 };
		req.ProcessId = this->ProcessId;
		req.Size = size;
		wcscpy_s(req.Module, sizeof(req.Module) / sizeof(req.Module[0]), moduleName);

		return SendRequest(REQUEST_TYPE::EXTEND, &req, sizeof(req));
	}

	NTSTATUS Process::Write(PVOID dest, PVOID src, DWORD size) {
		REQUEST_WRITE req = { 0 };
		req.ProcessId = this->ProcessId;
		req.Dest = dest;
		req.Src = src;
		req.Size = size;

		return SendRequest(REQUEST_TYPE::WRITE, &req, sizeof(req));
	}

	NTSTATUS Process::Read(PVOID dest, PVOID src, DWORD size) {
		REQUEST_READ req = { 0 };
		req.ProcessId = this->ProcessId;
		req.Dest = dest;
		req.Src = src;
		req.Size = size;

		return SendRequest(REQUEST_TYPE::READ, &req, sizeof(req));
	}

	NTSTATUS Process::Protect(PVOID address, DWORD size, PDWORD inOutProtect) {
		REQUEST_PROTECT req = { 0 };
		req.ProcessId = this->ProcessId;
		req.Address = address;
		req.Size = size;
		req.InOutProtect = inOutProtect;

		return SendRequest(REQUEST_TYPE::PROTECT, &req, sizeof(req));
	}

	PVOID Process::Alloc(DWORD size, DWORD protect) {
		PVOID outAddress = NULL;

		REQUEST_ALLOC req = { 0 };
		req.ProcessId = this->ProcessId;
		req.OutAddress = &outAddress;
		req.Size = size;
		req.Protect = protect;

		SendRequest(REQUEST_TYPE::ALLOC, &req, sizeof(req));

		return outAddress;
	}

	NTSTATUS Process::Free(PVOID address) {
		REQUEST_FREE req = { 0 };
		req.ProcessId = this->ProcessId;
		req.Address = address;

		return SendRequest(REQUEST_TYPE::FREE, &req, sizeof(req));
	}

	NTSTATUS Process::Module(LPCWSTR moduleName, PBYTE *base, PDWORD size) {
		REQUEST_MODULE req = { 0 };
		req.ProcessId = this->ProcessId;
		req.OutAddress = base;
		req.OutSize = size;
		wcscpy_s(req.Module, sizeof(req.Module) / sizeof(req.Module[0]), moduleName);

		return SendRequest(REQUEST_TYPE::MODULE, &req, sizeof(req));
	}
}
