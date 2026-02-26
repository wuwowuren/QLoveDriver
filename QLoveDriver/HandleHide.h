#ifndef __ROUTINES_H__
#define __ROUTINES_H__

#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include<wdm.h>

#define MAKEPTR( ptr, addValue ) ( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))


typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONG ObAttributes;                                                 //0x0
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;                         //0x0
		ULONG Value;                                                        //0x0
	};
	union
	{
		ULONG GrantedAccess;                                                //0x4
		struct
		{
			USHORT GrantedAccessIndex;                                      //0x4
			USHORT CreatorBackTraceIndex;                                   //0x6
		};
		ULONG NextFreeTableEntry;                                           //0x4
	};
}HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef struct _TABLE_HANDLE_INFO
{
	DWORD64 LockSelf;
	LIST_ENTRY Link;
	HANDLE hID;
	HANDLE MainThead;
	HANDLE ModifyID;
	PVOID Object;
	HANDLE_TABLE_ENTRY* pCidTable;
	HANDLE_TABLE_ENTRY TableEntry;
	HANDLE fID;
	LIST_ENTRY ThreadListEntry0;
	LIST_ENTRY ThreadListEntry1;
	KSPIN_LOCK Lock;
	//char pIv[2048];
}TABLE_HANDLE_INFO, * PTABLE_HANDLE_INFO;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section; //Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef enum _WinVer
{
	WINVER_7     = 0x0610,
	WINVER_7_SP1 = 0x0611,
	WINVER_8     = 0x0620,
	WINVER_81    = 0x0630,
	WINVER_10    = 0x0A00,
} WinVer;

typedef struct _DYNAMIC_DATA
{
	WinVer  ver;            // OS version
	BOOLEAN correctBuild;   // OS kernel build number is correct and supported

	ULONG ActiveProcessLinks;	// EPROCESS::ActiveProcessLinks
	ULONG SessionProcessLinks;	// EPROCESS::SessionProcessLinks
	ULONG ObjTable;				// EPROCESS::ObjectTable
	ULONG UniqueProcessId;		// EPROCESS::UniqueProcessId
	ULONG ThreadListHead;		// EPROCESS::ThreadListHead
	ULONG ThreadListEntry;		// ETHREAD::ThreadListEntry
	ULONG UniqueProcess;		// ETHREAD::Cid::UniqueProcess
	ULONG UniqueThread;			// ETHREAD::Cid::UniqueThread
	ULONG ExDestroyHandle;		// ExDestroyHandle offset
	ULONG ExRemoveHandleTable;	// ExRemoveHandleTable offset
	ULONG PspCidTable;			// PspCidTable offset
} DYNAMIC_DATA, *PDYNAMIC_DATA;


//typedef enum _SYSTEM_INFORMATION_CLASS
//{
//	SystemModuleInformation = 0xb,
//} SYSTEM_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
						 IN int SystemInformationClass,
						 OUT PVOID SystemInformation,
						 IN ULONG SystemInformationLength,
						 OUT PULONG ReturnLength OPTIONAL 
						 );


NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
	IN int SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

PVOID GetKernelBase2();



typedef struct _HANDLE_TABLE_FREE_LIST
{
	EX_PUSH_LOCK FreeListLock;
	HANDLE_TABLE_ENTRY FirstFreeHandleEntry;
	HANDLE_TABLE_ENTRY LastFreeHandleEntry;
	int HandleCount;
	ULONG32 HighWaterMark;
} HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;

typedef struct _HANDLE_TRACE_DB_ENTRY
{
	CLIENT_ID ClientId;
	HANDLE Handle;
	ULONGLONG Type;
	PVOID StackTrace;
} HANDLE_TRACE_DB_ENTRY, * PHANDLE_TRACE_DB_ENTRY;

typedef struct _HANDLE_TRACE_DEBUG_INFO
{
	int RefCount;
	ULONG32 TableSize;
	ULONGLONG BitMaskFlags;
	FAST_MUTEX CloseCompactionLock;
	ULONGLONG CurrentStackIndex;
	HANDLE_TRACE_DB_ENTRY TraceDb;
} HANDLE_TRACE_DEBUG_INFO, * PHANDLE_TRACE_DEBUG_INFO;

typedef struct _HANDLE_TABLE
{
	ULONG NextHandleNeedingPool;
	INT32 ExtraInfoPages;
	ULONGLONG TableCode;
	PEPROCESS QuotaProcess;
	LIST_ENTRY HandleTableList;
	ULONG UniqueProcessId;
	ULONG Flags;
	EX_PUSH_LOCK HandleContentionEvent;
	EX_PUSH_LOCK HandleTableLock;
	HANDLE_TABLE_FREE_LIST FreeLists;
	HANDLE_TRACE_DEBUG_INFO DebugInfo;
} HANDLE_TABLE, *PHANDLE_TABLE;


typedef struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;
	ULONG MaxRelativeAccessMask;
}HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;



typedef struct _TABLE_ANGLE
{
	HANDLE hID;
	PVOID Object;
}TABLE_ANGLE, * PTABLE_ANGLE;

typedef struct _eTable_Info {
	DWORD64 uType;
	HANDLE hProcessID;
	TABLE_ANGLE* pArry;
	DWORD MaxCount; // 最大
	DWORD nCount;   //当前
}eTable_Info;


typedef __int64(__fastcall* fPspCreateThread)(
	PHANDLE ThreadHandle,
	ULONG DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PEPROCESS a5,
	__int64 a6,
	PCLIENT_ID ClientId,
	PCONTEXT ThreadContext,
	__int64 a9,
	BOOLEAN CreateSuspended,
	__int64 a11,
	__int64 a12,
	PVOID a13);//[char  32]



//typedef struct _KAPC_STATE
//{
//	LIST_ENTRY ApcListHead[2];
//	PKPROCESS Process;
//	UCHAR KernelApcInProgress;
//	UCHAR KernelApcPending;
//	UCHAR UserApcPending;
//} KAPC_STATE, * PKAPC_STATE;

typedef NTSTATUS( NTAPI* fnExRemoveHandleTable )(IN PHANDLE_TABLE pTable);
typedef NTSTATUS( NTAPI* fnExExDestroyHandle )(IN PHANDLE_TABLE pTable, 
											   IN HANDLE Handle, 
											   IN PVOID HandleTableEntry );

//NTSTATUS PsActiveProcessListHiding(PEPROCESS pep, BOOLEAN bHiding);
NTSTATUS SessionProcessListHiding(PEPROCESS pep, BOOLEAN bHiding);
NTSTATUS RemoveProcessHandleTable(PEPROCESS pep);
NTSTATUS RemovePspCidTable(PEPROCESS pep, HANDLE pid);
BOOLEAN Is64BitWindows();
NTSTATUS GetRevisionBuildNO( OUT PULONG pRevisionBuildNo );
NTSTATUS InitDynamicData( IN OUT PDYNAMIC_DATA pData );


BOOLEAN IniLoadSys_HIDE();

BOOLEAN  IniHandle();

NTSTATUS RemoveSelfThread();


NTSTATUS wRemovePspCidTable(HANDLE hPID);

NTSTATUS wRemoveProcessFromPspCidTable(HANDLE hPID);

NTSTATUS wRecoveryidTableProcess(HANDLE hPID);

NTSTATUS wRecoveryidTableThread(HANDLE hProcess, HANDLE hThread);






#endif /// __ROUTINES_H__

BOOLEAN wfindEntryProcessAvl(TABLE_HANDLE_INFO* TableInfo);

PTABLE_HANDLE_INFO wGetEntryProcessAvl(TABLE_HANDLE_INFO* TableInfo);

BOOLEAN wRemoveEntryProcessAvl(TABLE_HANDLE_INFO* TableInfo);




BOOLEAN wfindEntryThreadAvl(TABLE_HANDLE_INFO* TableInfo);

BOOLEAN wRemoveEntryThreadAvl(TABLE_HANDLE_INFO* TableInfo);





//--------------------------- ASM_FIND

char* _ASM_GET_CALL(char* pAdr, int num);