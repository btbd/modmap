#pragma once

namespace Comm {
	const auto DATA_UNIQUE = 0x1234UL;

	enum class REQUEST_TYPE {
		EXTEND,
		WRITE,
		READ,
		PROTECT,
		ALLOC,
		FREE,
		MODULE,
	};

	typedef struct _REQUEST_DATA {
		DWORD Unique;
		REQUEST_TYPE Type;
		PVOID Arguments;
	} REQUEST_DATA, *PREQUEST_DATA;

	typedef struct _REQUEST_EXTEND {
		DWORD ProcessId;
		WCHAR Module[0xFF];
		DWORD Size;
	} REQUEST_EXTEND, *PREQUEST_EXTEND;

	typedef struct _REQUEST_WRITE {
		DWORD ProcessId;
		PVOID Dest;
		PVOID Src;
		DWORD Size;
	} REQUEST_WRITE, *PREQUEST_WRITE;

	typedef struct _REQUEST_READ {
		DWORD ProcessId;
		PVOID Dest;
		PVOID Src;
		DWORD Size;
	} REQUEST_READ, *PREQUEST_READ;

	typedef struct _REQUEST_PROTECT {
		DWORD ProcessId;
		PVOID Address;
		DWORD Size;
		PDWORD InOutProtect;
	} REQUEST_PROTECT, *PREQUEST_PROTECT;

	typedef struct _REQUEST_ALLOC {
		DWORD ProcessId;
		PVOID OutAddress;
		DWORD Size;
		DWORD Protect;
	} REQUEST_ALLOC, *PREQUEST_ALLOC;

	typedef struct _REQUEST_FREE {
		DWORD ProcessId;
		PVOID Address;
	} REQUEST_FREE, *PREQUEST_FREE;

	typedef struct _REQUEST_MODULE {
		DWORD ProcessId;
		WCHAR Module[0xFF];
		PBYTE *OutAddress;
		PDWORD OutSize;
	} REQUEST_MODULE, *PREQUEST_MODULE;

	BOOL Setup();

	class Process {
	private:
		DWORD ProcessId = 0;

	public:
		Process(DWORD processId) : ProcessId{ processId } {}
		Process(LPCWSTR processName);

		BOOLEAN Valid();
		NTSTATUS Extend(LPCWSTR module, DWORD size);
		NTSTATUS Write(PVOID dest, PVOID src, DWORD size);
		NTSTATUS Read(PVOID dest, PVOID src, DWORD size);
		NTSTATUS Protect(PVOID address, DWORD size, PDWORD inOutProtect);
		PVOID Alloc(DWORD size, DWORD protect);
		NTSTATUS Free(PVOID address);
		NTSTATUS Module(LPCWSTR moduleName, PBYTE *base, PDWORD size);
	};
}