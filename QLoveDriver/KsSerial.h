#pragma once

#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include<wdm.h>	








typedef int (*hBufferFile)(HANDLE hFile, char* pBuffer, int nLen);

BOOL IniComMsg(hBufferFile _CALLBACK_HANDLE);