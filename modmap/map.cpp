#include "stdafx.h"

// CBA to make this cleaner
namespace Map {
	PIMAGE_SECTION_HEADER TranslateRawSection(PIMAGE_NT_HEADERS nt, DWORD rva) {
		auto section = IMAGE_FIRST_SECTION(nt);
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
			if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
				return section;
			}
		}

		return NULL;
	}

	PVOID TranslateRaw(PBYTE base, PIMAGE_NT_HEADERS nt, DWORD rva) {
		auto section = TranslateRawSection(nt, rva);
		if (!section) {
			return NULL;
		}

		return base + section->PointerToRawData + (rva - section->VirtualAddress);
	}

	BOOLEAN ResolveImports(Comm::Process &process, PBYTE base, PIMAGE_NT_HEADERS nt) {
		auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (!rva) {
			return TRUE;
		}

		auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(TranslateRaw(base, nt, rva));
		if (!importDescriptor) {
			return TRUE;
		}

		for (; importDescriptor->FirstThunk; ++importDescriptor) {
			auto moduleName = reinterpret_cast<PCHAR>(TranslateRaw(base, nt, importDescriptor->Name));
			if (!moduleName) {
				break;
			}

			auto module = LoadLibraryA(moduleName);
			if (!module) {
				errorf("failed to load module: %s\n", moduleName);
				return FALSE;
			}

			PBYTE processModuleBase = NULL;
			DWORD processModuleSize = 0;
			if (process.Module(StrToWStr(moduleName), &processModuleBase, &processModuleSize) != ERROR_SUCCESS) {
				errorf("target process does not have %s loaded\n", moduleName);
				return FALSE;
			}

			for (auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(TranslateRaw(base, nt, importDescriptor->FirstThunk)); thunk->u1.AddressOfData; ++thunk) {
				auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(TranslateRaw(base, nt, static_cast<DWORD>(thunk->u1.AddressOfData)));
				thunk->u1.Function = reinterpret_cast<UINT_PTR>(processModuleBase + (reinterpret_cast<PBYTE>(GetProcAddress(module, importByName->Name)) - reinterpret_cast<PBYTE>(module)));
			}
		}

		return TRUE;
	}

	VOID ResolveRelocations(PBYTE base, PIMAGE_NT_HEADERS nt, PBYTE mapped) {
		auto &baseRelocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (!baseRelocDir.VirtualAddress) {
			return;
		}

		auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(TranslateRaw(base, nt, baseRelocDir.VirtualAddress));
		if (!reloc) {
			return;
		}

		for (auto currentSize = 0UL; currentSize < baseRelocDir.Size; ) {
			auto relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			auto relocData = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
			auto relocBase = reinterpret_cast<PBYTE>(TranslateRaw(base, nt, reloc->VirtualAddress));

			for (auto i = 0UL; i < relocCount; ++i, ++relocData) {
				auto data = *relocData;
				auto type = data >> 12;
				auto offset = data & 0xFFF;

				if (type == IMAGE_REL_BASED_DIR64) {
					*reinterpret_cast<PBYTE *>(relocBase + offset) += (mapped - reinterpret_cast<PBYTE>(nt->OptionalHeader.ImageBase));
				}
			}

			currentSize += reloc->SizeOfBlock;
			reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocData);
		}
	}

	BOOLEAN MapHeaders(Comm::Process &process, PBYTE base, PIMAGE_NT_HEADERS nt, PBYTE mapped) {
		return process.Write(mapped, base, sizeof(nt->Signature) + sizeof(nt->FileHeader) + nt->FileHeader.SizeOfOptionalHeader) == ERROR_SUCCESS;
	}

	BOOLEAN MapSections(Comm::Process &process, PBYTE base, PIMAGE_NT_HEADERS nt, PBYTE mapped) {
		auto section = IMAGE_FIRST_SECTION(nt);
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
			auto sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
			if (!sectionSize) {
				continue;
			}

			auto mappedSection = mapped + section->VirtualAddress;
			if (process.Write(mappedSection, base + section->PointerToRawData, sectionSize) != ERROR_SUCCESS) {
				errorf("failed to map section %s at %p (%x)\n", section->Name, mappedSection, sectionSize);
				return FALSE;
			}
		}

		return TRUE;
	}

	PBYTE ExtendModule(Comm::Process &process, PIMAGE_NT_HEADERS nt, LPCWSTR module) {
		PBYTE moduleBase = NULL;
		DWORD moduleSize = 0;

		printf("[-] extending %ws\n", module);

		auto status = process.Module(module, &moduleBase, &moduleSize);
		if (status != ERROR_SUCCESS || !moduleBase) {
			errorf("failed to find module %ws (%X)\n", module, status);
			return NULL;
		}

		status = process.Extend(module, nt->OptionalHeader.SizeOfImage);
		if (status != ERROR_SUCCESS) {
			errorf("module %ws does not having enough free trailing memory (%X)\n", module, status);
			return NULL;
		}

		printf("[+] extended %ws to %x\n", module, moduleSize + nt->OptionalHeader.SizeOfImage);
		return moduleBase + moduleSize;
	}

	PVOID ExtendMap(Comm::Process &process, PBYTE base, LPCWSTR module) {
		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
			errorf("invalid DOS signature\n");
			return NULL;
		}

		auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) {
			errorf("invalid NT signature\n");
			return NULL;
		}

		nt->Signature = dos->e_magic = 0;

		auto mapped = ExtendModule(process, nt, module);
		if (!mapped) {
			return NULL;
		}

		printf("[+] mapped base: %p\n", mapped);

		if (!ResolveImports(process, base, nt)) {
			return NULL;
		}

		ResolveRelocations(base, nt, mapped);

		if (!MapHeaders(process, base, nt, mapped)) {
			errorf("failed to map headers\n");
			return NULL;
		}

		if (!MapSections(process, base, nt, mapped)) {
			return NULL;
		}

		return mapped + nt->OptionalHeader.AddressOfEntryPoint;
	}

	PVOID ExtendMap(Comm::Process &process, LPCWSTR filePath, LPCWSTR module) {
		std::ifstream file(filePath, std::ios::ate | std::ios::binary);
		if (!file) {
			errorf("failed to open file: \"%ws\"\n", filePath);
			return NULL;
		}

		auto size = file.tellg();
		auto buffer = new BYTE[size];

		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<PCHAR>(buffer), size);
		file.close();

		auto entryPoint = ExtendMap(process, buffer, module);

		delete[] buffer;

		return entryPoint;
	}
}