#include "Hide.h"
#include <ntstrsafe.h>

#include "gGlobal.h"

#include "HandleHide.h"

static PEPROCESS g_Eprocess = NULL;

DWORD64 g_offset = 0;

















BOOLEAN RemoveAcessProcessId(DWORD dwID);

int mGetVersion()
{
	RTL_OSVERSIONINFOW os_version = {0};
	auto status = RtlGetVersion(&os_version);
	if (!NT_SUCCESS(status)) {
		return 0;
	}
	if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
		return 0;
	}
	return os_version.dwMajorVersion;
}

DWORD64 getProcessOffset()
{

	char* pFun = (char *)&PsGetProcessId;
	g_offset = (*((DWORD*)(pFun + 3))) / 8 + 1;

	//RtlFreeAnsiString
	//HANDLE hPID = PsGetCurrentProcessId();
	//PEPROCESS hEprocess = PsGetCurrentProcess();


	//PEPROCESS pEprocess = NULL;
	//NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &pEprocess);
	//if (!NT_SUCCESS(status)) {
	//	LOG_DEBUG("PsLookupProcessByProcessId ERROR PID:%d\n", hPID);
	//	return 0;
	//}

	//for (auto i = 40; i < 0x150; i++)
	//{
	//	HANDLE tPID = (HANDLE)*(DWORD64 *)((DWORD64)hEprocess + i * 8);
	//	if (tPID == hPID)
	//	{
	//		g_offset = i + 1;
	//		HANDLE tPID4 = (HANDLE)*(DWORD64 *)((DWORD64)pEprocess + i * 8);
	//		if (tPID4 == (HANDLE)4)
	//		{
	//			break;
	//		}
	//	}
	//}
	LOG_DEBUG("offset:%08X\n", g_offset);
	//ObDereferenceObject(pEprocess);
	return g_offset;
}


BOOLEAN IsShowProcess(HANDLE pid)
{
	PEPROCESS SpEprocess = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &SpEprocess);
	if (SpEprocess == 0)
	{
		return FALSE;
	}
	LIST_ENTRY* Link = (PLIST_ENTRY)((ULONGLONG)SpEprocess + g_offset * 8);
	if (Link->Flink == Link && Link->Blink == Link)
	{
		return FALSE;
	}
	return TRUE;

	//PEPROCESS pEprocess = NULL;
	//NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &pEprocess);
	//if (!NT_SUCCESS(status)) {
	//	LOG_DEBUG("PsLookupProcessByProcessId ERROR PID:%d\n", pid);
	//	return FALSE;
	//}
	//PEPROCESS SpEprocess = NULL;
	//status = PsLookupProcessByProcessId((HANDLE)pid, &SpEprocess);
	//if (!NT_SUCCESS(status))
	//{
	//	ObDereferenceObject(pEprocess);
	//	LOG_DEBUG("PsLookupProcessByProcessId ERROR PID:%d\n", 4);
	//	return FALSE;
	//}
	//LIST_ENTRY * fEprocess = (PLIST_ENTRY)((UINT8*)pEprocess + g_offset * 8);

	//LIST_ENTRY * SfEprocess = (PLIST_ENTRY)((UINT8*)SpEprocess + g_offset * 8);

	//LIST_ENTRY * tfEprocess = fEprocess->Flink;

	////KIRQL irql = WPOFFx64();


	//while (tfEprocess != fEprocess)
	//{
	//	if (SfEprocess == tfEprocess)
	//	{
	//		ObDereferenceObject(pEprocess);
	//		ObDereferenceObject(SpEprocess);
	//		//RemoveAcessProcessId((DWORD)pid);
	//		//WPONx64(irql);
	//		return TRUE;
	//	}
	//	tfEprocess = tfEprocess->Flink;
	//}
	////WPONx64(irql);
	//ObDereferenceObject(pEprocess);
	//ObDereferenceObject(SpEprocess);
	return FALSE;
}



PEPROCESS g_system_process = 0;

BOOLEAN ShowProcess(HANDLE pid)
{
	if (g_offset == 0)
	{
		getProcessOffset();
	}
	if (IsShowProcess(pid)) {
		return FALSE;
	}
	LIST_ENTRY * fEprocess = (PLIST_ENTRY)((UINT8*)g_system_process + g_offset * 8);
	PEPROCESS SpEprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &SpEprocess);
	if (status != STATUS_SUCCESS)
	{
		return FALSE;
	}
	LIST_ENTRY * SfEprocess = (PLIST_ENTRY)((UINT8*)SpEprocess + g_offset * 8);
	InsertHeadList(fEprocess, SfEprocess);
	ObDereferenceObject(SpEprocess);
	return FALSE;
}

typedef NTSTATUS(__fastcall* MiProcessLoaderEntry)(PVOID pDriverSection, BOOLEAN bLoad);
extern MiProcessLoaderEntry Get_MiProcessLoaderEntry();
extern RTL_OSVERSIONINFOEXW OsVersion;







typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct __PEB // 65 elements, 0x210 bytes
{
	BYTE bInheritedAddressSpace;
	BYTE bReadImageFileExecOptions;
	BYTE bBeingDebugged;
	BYTE bSpareBool;
	DWORD Padding0;
	LPVOID lpMutant;
	LPVOID lpImageBaseAddress;
	PEB_LDR_DATA *pLdr;
	LPVOID lpProcessParameters;
	LPVOID lpSubSystemData;
	LPVOID lpProcessHeap;
	//PRTL_CRITICAL_SECTION pFastPebLock;
	//LPVOID lpFastPebLockRoutine;
	//LPVOID lpFastPebUnlockRoutine;
	//DWORD dwEnvironmentUpdateCount;
	//LPVOID lpKernelCallbackTable;
	//DWORD dwSystemReserved;
	//DWORD dwAtlThunkSListPtr32;
	//PPEB_FREE_BLOCK pFreeList;
	//DWORD dwTlsExpansionCounter;
	//LPVOID lpTlsBitmap;
	//DWORD dwTlsBitmapBits[2];
	//LPVOID lpReadOnlySharedMemoryBase;
	//LPVOID lpReadOnlySharedMemoryHeap;
	//LPVOID lpReadOnlyStaticServerData;
	//LPVOID lpAnsiCodePageData;
	//LPVOID lpOemCodePageData;
	//LPVOID lpUnicodeCaseTableData;
	//DWORD dwNumberOfProcessors;
	//DWORD dwNtGlobalFlag;
	//LARGE_INTEGER liCriticalSectionTimeout;
	//DWORD dwHeapSegmentReserve;
	//DWORD dwHeapSegmentCommit;
	//DWORD dwHeapDeCommitTotalFreeThreshold;
	//DWORD dwHeapDeCommitFreeBlockThreshold;
	//DWORD dwNumberOfHeaps;
	//DWORD dwMaximumNumberOfHeaps;
	//LPVOID lpProcessHeaps;
	//LPVOID lpGdiSharedHandleTable;
	//LPVOID lpProcessStarterHelper;
	//DWORD dwGdiDCAttributeList;
	//LPVOID lpLoaderLock;
	//DWORD dwOSMajorVersion;
	//DWORD dwOSMinorVersion;
	//WORD wOSBuildNumber;
	//WORD wOSCSDVersion;
	//DWORD dwOSPlatformId;
	//DWORD dwImageSubsystem;
	//DWORD dwImageSubsystemMajorVersion;
	//DWORD dwImageSubsystemMinorVersion;
	//DWORD dwImageProcessAffinityMask;
	//DWORD dwGdiHandleBuffer[34];
	//LPVOID lpPostProcessInitRoutine;
	//LPVOID lpTlsExpansionBitmap;
	//DWORD dwTlsExpansionBitmapBits[32];
	//DWORD dwSessionId;
	//ULARGE_INTEGER liAppCompatFlags;
	//ULARGE_INTEGER liAppCompatFlagsUser;
	//LPVOID lppShimData;
	//LPVOID lpAppCompatInfo;
	//UNICODE_STRING usCSDVersion;
	//LPVOID lpActivationContextData;
	//LPVOID lpProcessAssemblyStorageMap;
	//LPVOID lpSystemDefaultActivationContextData;
	//LPVOID lpSystemAssemblyStorageMap;
	//DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;


typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks; 
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase; //7
	PVOID EntryPoint; //8
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;  //13
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;



NTKERNELAPI
PPEB
PsGetProcessPeb(
	PEPROCESS Process
);



typedef __int64(__fastcall* fMiProcessDeleteOnClose)(__int64 a1);

extern fMiProcessDeleteOnClose get_MiProcessDeleteOnClose();




extern DWORD offsetKprocess_ProcessList;

BOOLEAN _HideProcess_(HANDLE pid)
{
	//MiProcessLoaderEntry MiEntry = Get_MiProcessLoaderEntry();
	//sizeof(UNICODE_STRING)
	//if (!IsShowProcess(pid))
	//{
	//	return FALSE;
	//}
	PEPROCESS pEprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &pEprocess);
	if (!NT_SUCCESS(status)) {
		LOG_DEBUG("PsLookupProcessByProcessId ERROR PID:%d\n", pid);
		return FALSE;
	}
	PLIST_ENTRY ListEntry = (PLIST_ENTRY)((ULONGLONG)pEprocess + g_offset * 8);

	RemoveEntryList(ListEntry);
	InitializeListHead(ListEntry);

	//if (offsetKprocess_ProcessList != 0)
	//{
	//	ListEntry = (PLIST_ENTRY)((ULONGLONG)pEprocess + offsetKprocess_ProcessList);
 //          RemoveEntryList(ListEntry);
 //          InitializeListHead(ListEntry);
	//}

	g_Eprocess = pEprocess;
	ObDereferenceObject(pEprocess);
	return 0;
}



typedef NTSTATUS(*h_NtOpenProcess)(PHANDLE rocessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

typedef struct _HIDE_OPENPROCESS
{
  LIST_ENTRY List;
  DWORD PID;
}HIDE_OPENPROCESS;



HIDE_OPENPROCESS ArryOpenProcess;

BOOLEAN iFirstHideProcess = TRUE;

h_NtOpenProcess BrY_NtOpenProcess = 0;

//extern FILTER_PID* findPIDAvl(RTL_AVL_TABLE* TableBase, FILTER_PID* TableInfo);




NTSTATUS Br_NtOpenProcess(PHANDLE rocessHandle, ACCESS_MASK DesiredAccess, 
POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
   if (!IsOpenProcessHide(ClientId->UniqueProcess))
   {
	   return BrY_NtOpenProcess(rocessHandle, DesiredAccess, ObjectAttributes, ClientId);
   }
   LOG_DEBUG("PID:%d PID:%d\n",ClientId->UniqueProcess,PsGetCurrentProcessId());
   return STATUS_SUCCESS;
}


//extern RTL_AVL_TABLE TableAvl_HideProcess;



extern BOOLEAN  AddProcessHide(HANDLE ID);



BOOLEAN DisableAcessProcessId(HANDLE dwID) {

	if (IsOpenProcessHide(dwID))
	{
	    return TRUE;
	}
	return AddProcessHide(dwID);
}


BOOLEAN RemoveAcessProcessId(DWORD dwID) {


	return FALSE;
}


BOOLEAN bIniTable = FALSE;



extern BOOLEAN IniHideProcess();


BOOLEAN bIniHideR = FALSE;


BOOLEAN HideProcess(HANDLE pid, int Type)
{
	//return 0;
	if (!bIniHideR)
	{
		bIniHideR = IniHideProcess();
	}
	if (g_offset == 0)
	{
		getProcessOffset();
		
	}
	//LOG_DEBUG(L"g_offset:%08x \n", g_offset);
	if (Type == 0)
	{
		LOG_DEBUG("HideProcess 1\n");
		_HideProcess_(pid);
		LOG_DEBUG("HideProcess 2\n");
		DisableAcessProcessId(pid);
		//wRemovePspCidTable(pid);

		//wRemoveProcessFromPspCidTable((DWORD)pid);
		LOG_DEBUG("HideProcess 3\n");

	}
	else if (Type == 1) {
		DisableAcessProcessId(pid);
	}
	else if (Type == 2)
	{
		_HideProcess_(pid);
	}
	else if (Type == 3) 
	{

		if (!bIniTable)
		{
			bIniTable = TRUE;
			//if (OsVersion.dwBuildNumber < 9600)
			//{
				IniHandle();
			//}
		}
		LOG_DEBUG("HideProcess 1\n");
		_HideProcess_(pid);
		LOG_DEBUG("HideProcess 2\n");
		//DisableAcessProcessId((DWORD)pid);
		//wRemovePspCidTable(pid);
		LOG_DEBUG("HideProcess 3\n");
		wRemovePspCidTable(pid);

	}


	return FALSE;
}





//OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
//{
//	HANDLE dwID = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
//	char szProcName[16] = { 0 };
//	UNREFERENCED_PARAMETER(RegistrationContext);
//
//	if (IsOpenProcessHide(dwID))
//	{
//		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
//		{
//			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
//			{
//
//				//Terminate the process, such as by calling the user-mode TerminateProcess routine..
//				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
//			}
//			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
//			{
//				//Modify the address space of the process, such as by calling the user-mode WriteProcessMemory and VirtualProtectEx routines.
//				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
//			}
//			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
//			{
//				//Read to the address space of the process, such as by calling the user-mode ReadProcessMemory routine.
//				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
//			}
//			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
//			{
//				//Write to the address space of the process, such as by calling the user-mode WriteProcessMemory routine.
//				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
//			}
//		}
//	}
//	return OB_PREOP_SUCCESS;
//}



typedef NTSTATUS(*h_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID  SystemInformation, ULONG  SystemInformationLength, PULONG ReturnLength);

//extern NTSTATUS  IOSysBuffer(DWORD IOMajor, LPIOINFO gBuffer);




typedef BOOLEAN(*h_IOSysBuffer)(unsigned long IOMajor, PVOID gBuffer);

h_IOSysBuffer pIOgIZ = 0;

h_NtQuerySystemInformation TrueNtQuerySystemInformation2 = 0;

NTSTATUS Br_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass ,
          PVOID  SystemInformation,
          ULONG  SystemInformationLength, 
          PULONG ReturnLength)
{

	if (SystemInformationLength == 0 && ReturnLength == 0 && pIOgIZ != 0)
	{
		if (pIOgIZ(SystemInformationClass, SystemInformation))
		{
			return STATUS_SUCCESS;
		}
	}
    return TrueNtQuerySystemInformation2(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}




//BOOLEAN InitializeHide(PVOID nFun)
//{
//	//pIOgIZ = nFun;
//	//return SSDT_HOOKW(L"NtQuerySystemInformation", &Br_NtQuerySystemInformation, &TrueNtQuerySystemInformation2);
//	return TRUE;
//}


//typedef struct _HANDLE_TABLE_ENTRY_INFO {
//	ULONG AuditMask;
//	ULONG MaxRelativeAccessMask;
//} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;
//
//
//typedef struct _HANDLE_TABLE_ENTRY {
//	union {
//		PVOID Object;                          // 指向句柄所代表的对象
//		ULONG ObAttributes;                    // 最低三位有特别含义，参见
//											   // OBJ_HANDLE_ATTRIBUTES 宏定义
//		PHANDLE_TABLE_ENTRY_INFO InfoTable;    // 各个句柄表页面的第一个表项
//											   // 使用此成员指向一张表
//		ULONG_PTR Value;
//	};
//	union {
//		union {
//			ACCESS_MASK GrantedAccess;         // 访问掩码
//			struct {                           // 当NtGlobalFlag 中包含
//											   // FLG_KERNEL_STACK_TRACE_DB 标记时使用
//				USHORT GrantedAccessIndex;
//				USHORT CreatorBackTraceIndex;
//			};
//		};
//		LONG NextFreeTableEntry;               // 空闲时表示下一个空闲句柄索引
//	};
//} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;



typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);


NTKERNELAPI
HANDLE
ExCreateHandle(
	IN  PHANDLE_TABLE HandleTable,
	IN  PHANDLE_TABLE_ENTRY HandleTableEntry
);


NTKERNELAPI
BOOLEAN
ExEnumHandleTable(
	IN  PHANDLE_TABLE HandleTable,
	IN  EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	IN  PVOID EnumParameter,
	OUT PHANDLE Handle OPTIONAL
);

// 关闭进程所有句柄表
NTKERNELAPI
VOID
ExSweepHandleTable(
	__in PHANDLE_TABLE HandleTable,
	__in EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	__in PVOID EnumParameter
);


//BOOLEAN  Table_EX_ENUMERATE_HANDLE_ROUTINE(
//	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
//	IN HANDLE Handle,
//	IN PVOID EnumParameter
//) 
//{
//
//
//	return FALSE;
//}

