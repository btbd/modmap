#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <minwindef.h>

#define printf(fmt, ...) DbgPrint("[dbg] "fmt, ##__VA_ARGS__)
#define HANDLE_REQUEST(name, args) \
    case RequestType##name: {                                     \
        args safe = { 0 };                                        \
        if (!SafeCopy(&safe, safeData.Arguments, sizeof(args))) { \
            *status = STATUS_ACCESS_VIOLATION;                    \
            return 0;                                             \
        }                                                         \
        *status = Core##name(&safe);                              \
        return 0;                                                 \
    }

#include "util.h"
#include "core.h"