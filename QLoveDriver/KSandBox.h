#pragma once

#include "SSDT_HOOK.h"
#include "SYSTEM_MODULE_STRUCT.h"
#include <ntstrsafe.h>

typedef struct _K_SANDBOX {

	DWORD64 LockSelf;
	HANDLE dwPID;
	UNICODE_STRING SandBoxDirectory;  // 用于会话的转向路径
	UNICODE_STRING SessionDirectory;  // 会话标记
	DWORD64 SessionNumber;
	HANDLE hObjectDirectory;
	//RTL_AVL_TABLE  DirectoryTable;

}K_SANDBOX;


typedef struct _K_SANDBOX_TABLE {
	KSPIN_LOCK Lock;
	RTL_AVL_TABLE  Table;
}K_SANDBOX_TABLE;

typedef struct _K_SANDBOX_REPLACE {
	DWORD64 LockSelf;
	DWORD64 SessionNumber;
	K_SANDBOX_TABLE  EventTable;
	K_SANDBOX_TABLE  MuantTable;
	K_SANDBOX_TABLE  SectionTable;
}K_SANDBOX_REPLACE;



typedef struct _SandBoxUserMemory
{
	PMDL pMdl;
	void* kBuffer;  //内核内存指针
	void* UserBuffer; // 映射到用户的内存指针
	SIZE_T nSize;
}SandBoxUserMemory;

typedef struct _K_SANDBOX_REPLACE_STRING {
	DWORD64 LockSelf;
	DWORD64 SessionNumber;
	UNICODE_STRING String;  
	UNICODE_STRING ReplaceString; 
	SandBoxUserMemory uMemory;

}K_SANDBOX_REPLACE_STRING;


BOOLEAN GetFirstMoudleFromProcess(HANDLE dwPID, UNICODE_STRING* pWchar);

NTSTATUS GetPathByProcessId(HANDLE dwPID, UNICODE_STRING* pWchar);

K_SANDBOX* SandBoxCreateSession(HANDLE dwPID, UNICODE_STRING SandBoxDirectory, DWORD64 uSessionNumber);

K_SANDBOX* SandBoxLockSession(HANDLE dwPID);

K_SANDBOX* SandBoxUnLockSession(HANDLE dwPID);

K_SANDBOX* SandBoxRemoveSession(HANDLE dwPID);

BOOLEAN IniSandBox();
