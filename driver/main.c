#include "stdafx.h"

INT64(NTAPI *EnumerateDebuggingDevicesOriginal)(PVOID, PVOID);

PMMVAD(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable);
NTSTATUS(*MiInsertVadCharges)(PMMVAD vad, PEPROCESS process);
VOID(*MiInsertVad)(PMMVAD vad, PEPROCESS process);

INT64 NTAPI EnumerateDebuggingDevicesHook(PREQUEST_DATA data, PINT64 status) {
	if (ExGetPreviousMode() != UserMode || !data) {
		return EnumerateDebuggingDevicesOriginal(data, status);
	}

	// Can't use inline SEH for safe dereferences cause PG
	REQUEST_DATA safeData = { 0 };
	if (!SafeCopy(&safeData, data, sizeof(safeData)) || safeData.Unique != DATA_UNIQUE) {
		return EnumerateDebuggingDevicesOriginal(data, status);
	}
	
	switch (safeData.Type) {
		HANDLE_REQUEST(Extend, REQUEST_EXTEND);
		HANDLE_REQUEST(Write, REQUEST_WRITE);
		HANDLE_REQUEST(Read, REQUEST_READ);
		HANDLE_REQUEST(Protect, REQUEST_PROTECT);
		HANDLE_REQUEST(Alloc, REQUEST_ALLOC);
		HANDLE_REQUEST(Free, REQUEST_FREE);
		HANDLE_REQUEST(Module, REQUEST_MODULE);
	}

	*status = STATUS_NOT_IMPLEMENTED;
	return 0;
}

NTSTATUS Main() {
	PCHAR base = GetKernelBase();
	if (!base) {
		printf("! failed to get ntoskrnl base !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	// MiAllocateVad (yes I'm this lazy)
	PBYTE addr = (PBYTE)FindPatternImage(base, "\x41\xB8\x00\x00\x00\x00\x48\x8B\xD6\x49\x8B\xCE\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xx????xxxxxxx????xxx");
	if (!addr) {
		printf("! failed to find MiAllocateVad !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*(PVOID *)&MiAllocateVad = RELATIVE_ADDR(addr + 12, 5);

	// MiInsertVadCharges
	addr = FindPatternImage(base, "\xE8\x00\x00\x00\x00\x8B\xF8\x85\xC0\x78\x31", "x????xxxxxx");
	if (!addr) {
		printf("! failed to find MiInsertVadCharges !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*(PVOID *)&MiInsertVadCharges = RELATIVE_ADDR(addr, 5);

	// MiInsertVad
	addr = FindPatternImage(base, "\x48\x2B\xD1\x48\xFF\xC0\x48\x03\xC2", "xxxxxxxxx");
	if (!addr) {
		printf("! failed to find MiInsertVad !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	for (; *addr != 0xE8 || *(addr + 5) != 0x8B; ++addr);
	*(PVOID *)&MiInsertVad = RELATIVE_ADDR(addr, 5);

	// Intended be manually mapped
	addr = FindPatternImage(base, "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\x85\xC0\x78\x40", "xxx????x????xxxxxx");
	if (!addr) {
		printf("! failed to find xKdEnumerateDebuggingDevices  !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*(PVOID *)&EnumerateDebuggingDevicesOriginal = InterlockedExchangePointer(RELATIVE_ADDR(addr, 7), (PVOID)EnumerateDebuggingDevicesHook);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);

	return Main();
}