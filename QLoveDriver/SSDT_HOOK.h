#pragma once
#include "BASE_TABLE.h"
#include "PAGE_CR0_DISABLE.h"

#include "cdetours.h"

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

typedef enum _SSDT_TYPE {
	HOOK_SSDT = 1,
	HOOK_SSDTSHOW = 2
}SSDTTYPE;



static HANDLE CsrssPID = 0;

BOOLEAN SSDT_Initialization_HOOK(int SSDT_STYLE);


// TableHook

BOOLEAN SSDT_HOOK(ULONG ID, PVOID pNewFun, PVOID pOldFun);

BOOLEAN SSDT_HOOKW(wchar_t * Pfun, PVOID pNewFun, PVOID pOldFun);

BOOLEAN SSDT_SHOW_HOOK(ULONG ID, PVOID pNewFun, PVOID pOldFun);

// 		UNICODE_STRING routineName;
//RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
// NtQuerySystemInformation = (QuerySystemInformation)MmGetSystemRoutineAddress(&routineName);

BOOLEAN SSDT_SHOW_HOOKW(wchar_t * Pfun, PVOID pNewFun, PVOID pOldFun);

BOOLEAN SSDT_UNHOOK(ULONG ID);

BOOLEAN SSDT_SHOW_UNHOOK(ULONG ID);

BOOLEAN SSDT_ISHOOK(int SSDT_STYLE);

// inLine HOOK

//ULONGLONG getTablePtr(int SSDT_TYPE, char * FUN_NAME);

BOOLEAN SSDT_Initialization_HOOK2(int SSDT_STYLE);

//BOOLEAN SSDT_HOOK2(char * FUN_NAME, PVOID pNewFun, PVOID pOldFun);

BOOLEAN SSDT_HOOK3(ULONG ID, PVOID pNewFun, PVOID pOldFun);

BOOLEAN SSDT_SHOW_HOOK2(ULONG ID, PVOID pNewFun, PVOID pOldFun);

BOOLEAN SSDT_STOP_HOOK(int SSDT_STYLE);

ULONGLONG GetSSDTFuncAddr(ULONG id);

ULONGLONG GetSSDTSHOWFuncAddr(ULONG id);

BOOLEAN SSDT_HOOK_NOW_TYPE(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN, BOOLEAN bGlobal);

BOOLEAN SSDT_SHOW_HOOK_NOW_TYPE(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN, BOOLEAN bGlobal);
