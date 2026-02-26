#pragma once




#include "gGlobal.h"
#include "SSDT_HOOK.h"


#include <ntifs.h>
#include<wdm.h>
#include<ntddk.h>
#include <ntimage.h>


#include "HandleHide.h"





BOOLEAN get_PspCidTable(ULONG64* tableAddr);









int  mGetVersion();
//BOOL HideProcess7(HANDLE pid);
//
//BOOL HideProcess10(HANDLE pid);
DWORD64 getProcessOffset();

BOOLEAN IsOpenProcessHide(HANDLE ID);

BOOLEAN HideProcess(HANDLE pid, int Type);

BOOLEAN ShowProcess(HANDLE pid);





//BOOLEAN InitializeHide(PVOID pFUN);