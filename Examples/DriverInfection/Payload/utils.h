#pragma once
#include "pch.h"

UINT64 GetImageBase( PUINT64 Address );
UINT64 GetKernelBase();
UINT64 GetExportAddress( UINT64 BaseAddress, const char* FunctionName );