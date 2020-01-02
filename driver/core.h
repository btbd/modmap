#pragma once

#define DATA_UNIQUE (0x1234)

typedef enum _REQUEST_TYPE {
	RequestTypeExtend,
	RequestTypeWrite,
	RequestTypeRead,
	RequestTypeProtect,
	RequestTypeAlloc,
	RequestTypeFree,
	RequestTypeModule,
} REQUEST_TYPE;

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
	PVOID *OutAddress;
	PDWORD OutSize;
} REQUEST_MODULE, *PREQUEST_MODULE;

NTSTATUS CoreExtend(PREQUEST_EXTEND args);
NTSTATUS CoreWrite(PREQUEST_WRITE args);
NTSTATUS CoreRead(PREQUEST_READ args);
NTSTATUS CoreProtect(PREQUEST_PROTECT args);
NTSTATUS CoreAlloc(PREQUEST_ALLOC args);
NTSTATUS CoreFree(PREQUEST_FREE args);
NTSTATUS CoreModule(PREQUEST_MODULE args);
