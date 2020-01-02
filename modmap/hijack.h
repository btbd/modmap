#pragma once

namespace Hijack {
	BOOLEAN HijackViaHook(Comm::Process &process, PVOID entry, LPCWSTR moduleName, LPCSTR functionName);
}