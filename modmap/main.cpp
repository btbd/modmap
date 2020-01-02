#include "stdafx.h"

INT main(INT argc, LPCSTR *argv) {
	if (argc < 4) {
		printf("usage: modmap <PROCESS> <TARGETMODULE> <DLL>\n");
		return 1;
	}

	if (!Comm::Setup()) {
		return 1;
	}

	Comm::Process process(StrToWStr(argv[1]));
	if (!process.Valid()) {
		errorf("process not found\n");
		return 1;
	}

	auto entry = Map::ExtendMap(process, StrToWStr(argv[3]), StrToWStr(argv[2]));
	if (!entry) {
		return 1;
	}

	printf("\n[-] entry point: %p\n", entry);

	if (!Hijack::HijackViaHook(process, entry, L"user32.dll", "PeekMessageW")) {
		return 1;
	}
	
	return 0;
}