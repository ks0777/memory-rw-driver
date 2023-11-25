#pragma once

#include <ntifs.h>
#include <wdf.h>
#include <intrin.h>

#include "utils.h"

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

