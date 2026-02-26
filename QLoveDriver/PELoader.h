#pragma once


#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include<wdm.h>	
#include<ntimage.h>

#include "SYSTEM_MODULE_STRUCT.h"

ULONG64 LoadDriverFromFile(PUCHAR buffer, PUNICODE_STRING uString, PULONG64 pEntry, DWORD64* nSize, DWORD64* hAttchModDriver);

ULONG64 LoadDriver(PUCHAR buffer, PULONG64 pEntry, DWORD64* hDriver, DWORD64* hAttchModDriver);


ULONG64 LoadDriverV(PUCHAR buffer, PULONG64 pEntry, DWORD64* nSize, PLDR_DATA_TABLE_ENTRY Ldr, PVOID* pSectionObject);

ULONG64 LoadDriverSection(PVOID DriverSection, PUCHAR buffer, PULONG64 pEntry, DWORD64* nSize);
