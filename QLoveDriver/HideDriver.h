#pragma once



//--------------  隐藏驱动 WIN7 ----------------- WIN10


#include "GET_MIPROCESSLOADERENTRY.h"
#include "SYSTEM_MODULE_STRUCT.h"

BOOLEAN GetDriverObjectByName(PDRIVER_OBJECT *DriverObject, WCHAR *DriverName)
{
	PDRIVER_OBJECT TempObject = NULL;
	UNICODE_STRING u_DriverName = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&u_DriverName, DriverName);
	
	__try
	{
		Status = ObReferenceObjectByName(&u_DriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&TempObject);
	}
	__except (1) {

		LOG_DEBUG("获取驱动对象%ws失败!错误码是：%x!\n", GetExceptionCode());
	}
	

	if (!NT_SUCCESS(Status))
	{
		LOG_DEBUG("获取驱动对象%ws失败!错误码是：%x!\n", Status);
		*DriverObject = NULL;
		return FALSE;
	}

	*DriverObject = TempObject;
	return TRUE;
}

BOOLEAN SupportSEH(PDRIVER_OBJECT DriverObject)
{
	//因为驱动从链表上摘除之后就不再支持SEH了
	//驱动的SEH分发是根据从链表上获取驱动地址，判断异常的地址是否在该驱动中
	//因为链表上没了，就会出问题
	//学习（抄袭）到的方法是用别人的驱动对象改他链表上的地址

	PDRIVER_OBJECT BeepDriverObject = NULL;;
	PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;
	GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\Beep");
	if (BeepDriverObject == NULL){
		GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\Null");
		if (BeepDriverObject == NULL)
		{
			return FALSE;
		}
	}
		

	//MiProcessLoaderEntry这个函数内部会根据Ldr中的DllBase然后去RtlxRemoveInvertedFunctionTable表中找到对应的项
	//之后再移除他，根据测试来讲..这个表中没有的DllBase就没法接收SEH，具体原理还没懂...
	//所以这里用系统的Driver\\beep用来替死...
	
	
	LdrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	LdrEntry->DllBase = BeepDriverObject->DriverStart;
	//DriverObject->DriverStart = BeepDriverObject->DriverStart;
	ObDereferenceObject(BeepDriverObject);
	return TRUE;
}



BOOLEAN NewNamePow(PDRIVER_OBJECT DriverObject)
{
	//因为驱动从链表上摘除之后就不再支持SEH了
	//驱动的SEH分发是根据从链表上获取驱动地址，判断异常的地址是否在该驱动中
	//因为链表上没了，就会出问题
	//学习（抄袭）到的方法是用别人的驱动对象改他链表上的地址

	PDRIVER_OBJECT BeepDriverObject = NULL;;
	PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;
	GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\Beep");
	if (BeepDriverObject == NULL) {
		GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\Null");
		if (BeepDriverObject == NULL)
		{
			return FALSE;
		}
	}


	//MiProcessLoaderEntry这个函数内部会根据Ldr中的DllBase然后去RtlxRemoveInvertedFunctionTable表中找到对应的项
	//之后再移除他，根据测试来讲..这个表中没有的DllBase就没法接收SEH，具体原理还没懂...
	//所以这里用系统的Driver\\beep用来替死...


    //	0LdrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    //	LdrEntry->DllBase = BeepDriverObject->DriverStart;
	//DriverObject->DriverStart = BeepDriverObject->DriverStart;
	DriverObject->DriverName = BeepDriverObject->DriverName;
	DriverObject->DriverSection = BeepDriverObject->DriverSection;
	ObDereferenceObject(BeepDriverObject);
	return TRUE;
}


BOOLEAN repairLinks(PLIST_ENTRY Entry) {

	PLIST_ENTRY NextEntry = Entry->Flink;
	PLIST_ENTRY PrevEntry = Entry->Blink;
	if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {

		//LOG_DEBUG("RemoveEntryList  BigError\n");
		InitializeListHead(Entry);
		return TRUE;
	}
	return FALSE;
}

//MmIsNonPagedSystemAddressValid
BOOLEAN IsLinks(PLIST_ENTRY Entry) {

	PLIST_ENTRY NextEntry = Entry->Flink;
	PLIST_ENTRY PrevEntry = Entry->Blink;

	//RemoveEntryList()
	__try
	{
		if (MmIsAddressValid(NextEntry) && MmIsAddressValid(PrevEntry)) {
			
			if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {

				//LOG_DEBUG("RemoveEntryList  BigError\n");
				return FALSE;
			}
			else
			{
				return TRUE;
			}
		}
		//if (MmIsNonPagedSystemAddressValid(NextEntry) && MmIsNonPagedSystemAddressValid(PrevEntry)) {
		//	LOG_DEBUG("MmIsNonPagedSystemAddressValid sucess\n");
		//	if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {

		//		//LOG_DEBUG("RemoveEntryList  BigError\n");
		//		return FALSE;
		//	}
		//	else
		//	{
		//		return TRUE;
		//	}
		//}
	}
	__except (1) {

		LOG_DEBUG("IsLinks __except\n");
	}


	return FALSE;
}




VOID InitInLoadOrderLinks(PLDR_DATA_TABLE_ENTRY LdrEntry)
{
	//PLIST_ENTRY PrevEntry;
	//PLIST_ENTRY NextEntry;

	//PLIST_ENTRY Entry = &LdrEntry->InLoadOrderLinks;
	//NextEntry = Entry->Flink;
	//PrevEntry = Entry->Blink;
	//if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {

	//	LOG_DEBUG("RemoveEntryList  BigError\n");
	//	InitializeListHead((PLIST_ENTRY)&LdrEntry->InLoadOrderLinks);
	//}




	if (repairLinks((PLIST_ENTRY)&LdrEntry->InLoadOrderLinks))
	{
		LOG_DEBUG("repairLinks LdrEntry->InLoadOrderLinks\n");
	}
	
	if (repairLinks((PLIST_ENTRY)&LdrEntry->InMemoryOrderLinks))
	{
		LOG_DEBUG("repairLinks LdrEntry->InMemoryOrderLinks\n");
	}

	if (repairLinks((PLIST_ENTRY)&LdrEntry->InInitializationOrderLinks))
	{
		LOG_DEBUG("repairLinks LdrEntry->InInitializationOrderLinks\n");
	}
	//RemoveEntryList((PLIST_ENTRY)&LdrEntry->InLoadOrderLinks);
	

	//RemoveEntryList((PLIST_ENTRY)&LdrEntry->InMemoryOrderLinks);
	//InitializeListHead((PLIST_ENTRY)&LdrEntry->InMemoryOrderLinks);

	//InitializeListHead((PLIST_ENTRY)&LdrEntry->InInitializationOrderLinks);
}
extern BOOLEAN writeSafeMemory(PVOID adr, PVOID val, DWORD valSize);


extern	char* _ASM_GET_TEST_PTR_CODE(char* pAdr, int num);
typedef  void  (NTAPI* _RtlInsertInvertedFunctionTable)(HANDLE hMod, int Size);
typedef  void  (NTAPI* _RtlRemoveInvertedFunctionTable)(HANDLE hMod);
extern ULONGLONG _CODE_GET_REAL_ADDRESS(char* pEl);

VOID HideDriver(PDRIVER_OBJECT DriverObject)
{
	
	MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;
	BOOLEAN bFlag = FALSE;

	//
	RTL_OSVERSIONINFOEXW OsVersion = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;
	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);


	if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1)
	{
		PLDR_DATA_TABLE_ENTRY Ldr = NULL;
		bFlag = SupportSEH(DriverObject);
		Ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		//DriverObject->DriverSection = Ldr->InLoadOrderLinks.Flink;
		RemoveEntryList((PLIST_ENTRY)&Ldr->InLoadOrderLinks);
	}
	else
	{
		//PLDR_DATA_TABLE_ENTRY Ldr = NULL;
		//bFlag = SupportSEH(DriverObject);
		//Ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		//DriverObject->DriverSection = Ldr->InLoadOrderLinks.Flink;
		//RemoveEntryList(&Ldr->InLoadOrderLinks);
		//InitInLoadOrderLinks((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);

		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry();
		if (m_MiProcessLoaderEntry == NULL) {

			//PLDR_DATA_TABLE_ENTRY Ldr = NULL;
			//bFlag = SupportSEH(DriverObject);
			//Ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
			//DriverObject->DriverSection = Ldr->InLoadOrderLinks.Flink;
			//RemoveEntryList(&Ldr->InLoadOrderLinks);
			//InitInLoadOrderLinks((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);

			return;
		}


		PLDR_DATA_TABLE_ENTRY Ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

		char* pLink = Ldr;


		//if (IsLinks(&Ldr->InLoadOrderLinks))
		//{
		//	LOG_DEBUG("Ldr->InLoadOrderLinks\n");
		//}

		//if (IsLinks(&Ldr->InMemoryOrderLinks))
		//{
		//	LOG_DEBUG("Ldr->InMemoryOrderLinks\n");
		//}

		//if (IsLinks(&Ldr->InInitializationOrderLinks))
		//{
		//	LOG_DEBUG("Ldr->InInitializationOrderLinks\n");
		//}

		DWORD uoffsetNow[0x100] = { 0 };
		DWORD uMax = 0;
		for (int i = 0; i < 0xA0; i+=8){

		//	LOG_DEBUG("Now TEST   %08X \n", i);
			if (IsLinks((PLIST_ENTRY)(pLink + i )))
			{
				LOG_DEBUG("LDR_DATA_TABLE_ENTRY LIST_ENTRY   %08X \n",  i);
				uoffsetNow[uMax] = i * 4;
				uMax++;
			}


		}


		bFlag = SupportSEH(DriverObject);
		DWORD* MiFlags = (DWORD*)((ULONGLONG)PsProcessType - 0x10);
		//LOG_DEBUG("PsProcessType <%p> <%p>\n", PsProcessType, &PsProcessType);

		DWORD CFlags = *MiFlags;
		LOG_DEBUG("uMiFlags <%p> %08X\n", MiFlags, CFlags);

		//*MiFlags = CFlags | 0x80000;



		char* pTestMiFlags = _ASM_GET_TEST_PTR_CODE((char*)m_MiProcessLoaderEntry, 1);
		if (pTestMiFlags == 0)
		{
			LOG_DEBUG("can't find  TestMiFlags\n");
			return;
		}

		_RtlInsertInvertedFunctionTable  RtlInsertInvertedFunctionTable = (_RtlInsertInvertedFunctionTable)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pTestMiFlags, 1));
		if (RtlInsertInvertedFunctionTable == 0)
		{
			LOG_DEBUG("can't find   RtlInsertInvertedFunctionTable\n");
			return;
		}

		LOG_DEBUG("RtlInsertInvertedFunctionTable  %I64X\n", RtlInsertInvertedFunctionTable);

		//NewNamePow(DriverObject);
		
		m_MiProcessLoaderEntry(DriverObject->DriverSection, 0);

		//RtlInsertInvertedFunctionTable(Ldr->DllBase, Ldr->SizeOfImage);

		char ZeroMemory[0x100] = { 0 };

		//char ZeroMemoryCopy[0x100] = { 0 };
		// 
		// 
		
		//char* pMemory = ExAllocatePoolWithTag(PagedPool, Ldr->SizeOfImage, 'Tag');
		//RtlCopyMemory(pMemory, Ldr->DllBase, 0x1000);

		//ExFreePoolWithTag(pMemory, 'Tag');

		//KIRQL irql = KeGetCurrentIrql();
		//if (irql >= DISPATCH_LEVEL) {
		//	KeLowerIrql(PASSIVE_LEVEL);//  __writecr8(PASSIVE_LEVEL);
		//}
		//if (!writeSafeMemory(Ldr->DllBase, ZeroMemory, sizeof(IMAGE_DOS_HEADER) - 4)) //0x100
		//	LOG_DEBUG("writeSafeMemory FALSE  Ldr->DllBase  %I64X   \n", Ldr->DllBase);
		//__writecr8(irql);



		// RtlInsertInvertedFunctionTable(Ldr->DllBase, Ldr->SizeOfImage);







		for (DWORD i = 0; i < uMax; i++)
		{
			if (repairLinks(pLink + uoffsetNow[i])){

				LOG_DEBUG("repairLinks Offset   %08X   \n", uoffsetNow[i]);

			}
		}



		//*MiFlags = CFlags;

		//CFlags = *MiFlags;
		//LOG_DEBUG("uMiFlags <%p> %08X\n", MiFlags, CFlags);



		//InitInLoadOrderLinks((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);
		//InitializeListHead(&Ldr->InLoadOrderLinks);
		//InitializeListHead(&Ldr->InMemoryOrderLinks);


		//EXCEPTION_RECORD
		//IMAGE_DOS_HEADER
		//sizeof(IMAGE_DOS_HEADER)






		//RtlZeroMemory(Ldr->DllBase, sizeof(IMAGE_DOS_HEADER));


		LOG_DEBUG("Ldr->DllBase   %I64X\n", Ldr->DllBase);

		//RtlZeroMemory(Ldr->DllBase,)


#ifdef DEBUG

		//if (bFlag)
		//{
		__try {
			DWORD64* p = 0;
			*p = 0x100;
		}
		__except (1)
		{
			LOG_DEBUG("SEH正确处理！\n");
		}
		//}


#endif // DEBUG


			//DWORD64 * Buffer = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'Tag');


			//for (size_t i = 0; i < 512; i++){
			//	Buffer[i] = Buffer;

			//}

			//sizeof(CSHORT)

		//DriverObject->DriverSection = 0;
		//	DriverObject->DriverStart = NULL;
		//	DriverObject->DriverSize = 0;
		//DriverObject->DriverUnload = NULL;
		//DriverObject->DriverInit = NULL;
		//DriverObject->DeviceObject = 0;
	}
	
	
}


//NTKERNELAPI  NTSTATUS MmUnloadSystemImage(DWORD64 * Mod);

typedef PVOID(*MmAcquireLoadLock)();
typedef NTSTATUS(*MmReleaseLoadLock)(PVOID);













#include "SSDT_NEW_FUN.h"

VOID Reinitialize(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Count);



	GetBasePTE();

	UNICODE_STRING FuncName;
	RtlInitUnicodeString(&FuncName, L"MmUnloadSystemImage");
	char* pfnMmUnloadSystemImage = (char *)MmGetSystemRoutineAddress(&FuncName);

	RTL_OSVERSIONINFOEXW OsVersion = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;
	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);
	MmAcquireLoadLock pMmAcquireLoadLock = 0;
	MmReleaseLoadLock pMmReleaseLoadLock = 0;
	if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 18362)
	{
		 pMmAcquireLoadLock = (MmAcquireLoadLock)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pfnMmUnloadSystemImage, 1));
		 pMmReleaseLoadLock = (MmReleaseLoadLock)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pfnMmUnloadSystemImage, 3));
	}
	if (OsVersion.dwBuildNumber >= 19041)
	{
		pMmAcquireLoadLock = (MmAcquireLoadLock)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pfnMmUnloadSystemImage, 2));
		pMmReleaseLoadLock = (MmReleaseLoadLock)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pfnMmUnloadSystemImage, 4));
	}
	LOG_DEBUG("MmAcquireLoadLock: %I64X MmReleaseLoadLock: %I64X\n", pMmAcquireLoadLock, pMmReleaseLoadLock);

	if (pMmAcquireLoadLock != 0)
	{
		PVOID Lock = pMmAcquireLoadLock();
		HideDriver(DriverObject);
		pMmReleaseLoadLock(Lock);
	}
	else
	{

		HideDriver(DriverObject);

	}





}
