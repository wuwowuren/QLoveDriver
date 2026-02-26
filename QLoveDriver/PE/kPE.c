#include "KPE.h"

#include <ntimage.h>


BOOLEAN _cmpMemoryNop(char* A, char* B, DWORD nSize) {
	for (DWORD i = 0; i < nSize; i++) {

		if ((char)B[i] == (char)0x90)
			continue;
		if (A[i] != B[i])
			return FALSE;
	}
	return TRUE;
}

char* _findMemoryMod(char* va, DWORD vaSize, char* val, DWORD nSize) {

	for (DWORD i = 0; i < (vaSize - nSize); i++) {
		if (_cmpMemoryNop(va + i, val, nSize)) {
			return va + i;
		}
	}
	return 0;
}



NTSTATUS InitializationModInfo(ULONG64 ModBaseAddress, PMOD_INFO Mod)
{
	if (!MmIsAddressValid((PVOID)ModBaseAddress)) {
		return STATUS_INVALID_HANDLE;
	}
	if (!MmIsAddressValid(Mod)) {
		return STATUS_ACCESS_VIOLATION;
	}
	Mod->ModBase = ModBaseAddress;
	Mod->DosHeader = (PIMAGE_DOS_HEADER)(ModBaseAddress);


	Mod->pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)(ModBaseAddress)+Mod->DosHeader->e_lfanew);
	Mod->SectionSize = Mod->pNtHeader->FileHeader.NumberOfSections;
	Mod->SectionsArray = (PIMAGE_SECTION_HEADER)((PUCHAR)(Mod->pNtHeader)+sizeof(IMAGE_NT_HEADERS));
	Mod->ModSize = Mod->pNtHeader->OptionalHeader.SizeOfImage;
	return STATUS_SUCCESS;
}

// 节点搜索 
NTSTATUS ZqSearchMoudleCode(PMOD_INFO Mod,
	char* Code,
	DWORD CodeSize,
	char* SectionName,
	DWORD dFlags,
	PVOID* pAdr) {

	ULONG64 ReturnFunctionAddress = 0;

	if (!MmIsAddressValid(pAdr)) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (!MmIsAddressValid(Code) || !MmIsAddressValid(Code + CodeSize)) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (SectionName != 0) {
		if (!MmIsAddressValid(SectionName)) {
			return STATUS_ACCESS_VIOLATION;
		}
	}
	for (auto i = 0; i < Mod->SectionSize; i++) {
		char Name[32] = { 0 };
		RtlCopyMemory(Name, Mod->SectionsArray[i].Name, 8);
		BOOLEAN bName = FALSE;
		if (SectionName != 0) {
			if (_stricmp(Name, SectionName) == 0) {
				bName = TRUE;
			}
		}
		else {
			bName = TRUE;
		}
		if (bName) {

			char* SecrchBase = (char*)((ULONG64)(Mod->ModBase)+ Mod->SectionsArray[i].VirtualAddress);
			DWORD nSize = Mod->SectionsArray[i].SizeOfRawData;
			if (!MmIsAddressValid(SecrchBase)) {
				continue;
			}
			*pAdr = _findMemoryMod(SecrchBase, nSize, Code, CodeSize);
			if (*pAdr != 0) {
				return STATUS_SUCCESS;
			}
		}
	}
	return STATUS_BAD_INITIAL_STACK;
}

NTSTATUS  ZqGetSectionPtr(PMOD_INFO Mod,
	char* SectionName,
	PVOID* Ptr,
	DWORD* pSize) {

	if (!MmIsAddressValid(SectionName)) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (!MmIsAddressValid(Ptr) || !MmIsAddressValid(pSize)) {
		return STATUS_ACCESS_VIOLATION;
	}
	for (auto i = 0; i < Mod->SectionSize; i++) {
		char Name[32] = { 0 };
		RtlCopyMemory(Name, Mod->SectionsArray[i].Name, 8);
		BOOLEAN bName = FALSE;
		if (_stricmp(Name, SectionName) == 0) {
			char* SecrchBase = (char*)((ULONG64)(Mod->ModBase) + Mod->SectionsArray[i].VirtualAddress);
			DWORD nSize = Mod->SectionsArray[i].Misc.VirtualSize;
			if (!MmIsAddressValid(SecrchBase)) {
				return STATUS_INVALID_HANDLE;
			}
			*Ptr = SecrchBase;
			*pSize = nSize;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_BAD_INITIAL_STACK;
}

NTSTATUS  ZqGetModRunTime(PMOD_INFO Mod, PRUNTIME_FUNCTION* pRunTime, DWORD* pCount) {
	PVOID kPtr = 0;
	DWORD nSzie = 0;
	NTSTATUS status = ZqGetSectionPtr(Mod, ".pdata", &kPtr, &nSzie);
	if (!NT_SUCCESS(status))
		return status;
	*pRunTime = (PRUNTIME_FUNCTION)kPtr;
	*pCount = nSzie / sizeof(RUNTIME_FUNCTION);
	return status;
}

NTSTATUS ZqSearchFunction(PMOD_INFO Mod, char* pCode, DWORD CodeSize, 
	_Outptr_ PVOID* fPtr, PRUNTIME_FUNCTION pRunTime)
{
	PRUNTIME_FUNCTION fRunTime = 0;
	DWORD nCount = 0;
	NTSTATUS status = ZqGetModRunTime(Mod, &fRunTime, &nCount);
	if (!NT_SUCCESS(status))
		return status;
	for (DWORD i = 0; i < nCount; i++){
		char * BeginAddress = (char *)Mod->ModBase + fRunTime[i].BeginAddress;
		if (_cmpMemoryNop(BeginAddress, pCode, CodeSize)){
			*fPtr = BeginAddress;
			*pRunTime = fRunTime[i];			
			return STATUS_SUCCESS;
		} 
	}
	return STATUS_BAD_INITIAL_STACK;
}

NTSTATUS ZqGetRunTimeUnwindHandler(PMOD_INFO Mod, PRUNTIME_FUNCTION pRuntime, 
	_Outptr_ PRUNTIME_HANDLER * pRunHandler){

	PUNWIND_INFO_HDR pHDR = (PUNWIND_INFO_HDR)(Mod->ModBase + pRuntime->UnwindData);
	if ((pHDR->Flags & UNW_FLAG_EHANDLER) == 0){
		if ((pHDR->Flags & UNW_FLAG_CHAININFO) == 0)
			return STATUS_NOT_FOUND;
		do
		{
			ULONG LenthV = pHDR->CntUnwindCodes * sizeof(UNWIND_CODE);
			ULONG offsetV = (LenthV / 4) * 4;
			if ((LenthV % 4) != 0)
				offsetV += 4;
			PRUNTIME_FUNCTION pRunNow = (ULONG64)pHDR + 4 + offsetV;
			pHDR = (PUNWIND_INFO_HDR)(Mod->ModBase + pRunNow->UnwindData);
		} while (pHDR->Flags & UNW_FLAG_CHAININFO);

		if ((pHDR->Flags & UNW_FLAG_EHANDLER) == 0)
			return STATUS_NOT_FOUND;

	}

	if (!MmIsAddressValid(pHDR))
		return STATUS_NOT_FOUND;

	DWORD Lenth = pHDR->CntUnwindCodes * sizeof(UNWIND_CODE);
	DWORD offset = (Lenth / 4) * 4;
	if ((Lenth % 4) != 0)
		offset += 4;
	PRUNTIME_HANDLER  _Handler = (PRUNTIME_HANDLER)((DWORD64)pHDR + offset + sizeof(UNWIND_INFO_HDR));
	*pRunHandler = _Handler;
	return STATUS_SUCCESS;
}

NTSTATUS ZqGetFunctionHander(PMOD_INFO Mod,
	char* pCode,
	DWORD nSize,
	_Outptr_ PRUNTIME_HANDLER* pRunHandler,
	_Outptr_ LPVOID* fPtr)
{
	PVOID CmpEnableLazyFlushDpcRoutinePtr = 0;
	RUNTIME_FUNCTION RunTime = { 0 };
	NTSTATUS status = ZqSearchFunction(Mod, pCode,nSize, fPtr, &RunTime);
	if (!NT_SUCCESS(status))
		return status;
	return ZqGetRunTimeUnwindHandler(Mod, &RunTime, &pRunHandler);
}

NTSTATUS ZqGetFunctionSize(PMOD_INFO Mod, PVOID fPtr, _Out_ DWORD* pSize) {

	PRUNTIME_FUNCTION pRunTimeMod = 0;
	DWORD dCount = 0;
	NTSTATUS status = ZqGetModRunTime(Mod, &pRunTimeMod, &dCount);;
	if (!NT_SUCCESS(status))
		return status;
	ULONG uOffset = (ULONG)((DWORD64)fPtr - Mod->ModBase);
	for (DWORD i = 0; i < dCount; i++) {
		if (uOffset == pRunTimeMod[i].BeginAddress){
			*pSize = pRunTimeMod[i].EndAddress - pRunTimeMod[i].BeginAddress;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}

NTSTATUS ZqGetFunctionBlock(PMOD_INFO Mod, 
	PVOID fPtr, 
	PRUNTIME_FUNCTION pRuntime, 
	DWORD InCount, 
	DWORD* pCount)
{


	DWORD64 _kPtr = (DWORD64)fPtr;
 
	//检查地址是否在模块范围内
	if (_kPtr < Mod->ModBase ||
		_kPtr  >(Mod->ModBase + Mod->ModSize))
		return STATUS_INVALID_ADDRESS;


	PRUNTIME_FUNCTION pRunTimeMod = 0;
	DWORD dCount = 0;
	NTSTATUS status = ZqGetModRunTime(Mod, &pRunTimeMod, &dCount);;
	if (!NT_SUCCESS(status))
		return status;
	ULONG uOffset = (ULONG)((DWORD64)fPtr - Mod->ModBase);

	DWORD iBuy = 0;

	RUNTIME_FUNCTION pRunTimeBase = { 0 };

	
	// 查找主要节点

	for (DWORD i = 0; i < dCount; i++) {
		if (uOffset >= pRunTimeMod[i].BeginAddress &&
			uOffset <= pRunTimeMod[i].EndAddress) {
			pRunTimeBase = pRunTimeMod[i];
			if (iBuy < InCount){
				RtlCopyMemory(&pRuntime[iBuy], &pRunTimeMod[i], sizeof(RUNTIME_FUNCTION));
			}
			break;
		}
	}



	if (pRunTimeBase.BeginAddress == 0)
		return STATUS_NOT_FOUND;


	//已经找找到了主要节点
	iBuy++;
	for (DWORD i = 0; i < dCount; i++) {
		if (pRunTimeBase.BeginAddress != pRunTimeMod[i].BeginAddress) {
			PUNWIND_INFO_HDR pHDR = (PUNWIND_INFO_HDR)(Mod->ModBase + pRunTimeMod[i].UnwindData);
			if ((pHDR->Flags & UNW_FLAG_CHAININFO) == 0) //没有链 直接返回
				continue;
			do
			{
				ULONG LenthV = pHDR->CntUnwindCodes * sizeof(UNWIND_CODE);
				ULONG offsetV = (LenthV / 4) * 4;
				if ((LenthV % 4) != 0)
					offsetV += 4;
				PRUNTIME_FUNCTION pRunNow = (ULONG64)pHDR + 4 + offsetV;
				if (pRunNow->BeginAddress == pRunTimeBase.BeginAddress)
				{
					if (iBuy < InCount) {
						RtlCopyMemory(&pRuntime[iBuy], &pRunTimeMod[i], sizeof(RUNTIME_FUNCTION));
					}
					iBuy++;
					break;
				}
				pHDR = (PUNWIND_INFO_HDR)(Mod->ModBase + pRunNow->UnwindData);

			} while (pHDR->Flags & UNW_FLAG_CHAININFO);

		}
	}
	if (iBuy > InCount){
		*pCount = iBuy;
		return STATUS_INVALID_BLOCK_LENGTH;
	}
	*pCount = iBuy;
	return STATUS_SUCCESS;
}

NTSTATUS ZqGetFunctionBlockCopy(PMOD_INFO Mod, PVOID fPtr, PF_BLOCK_COPY pRuntimeCopy, DWORD InCount, DWORD* pCount)
{
	PRUNTIME_FUNCTION pRunTime = 0;
	DWORD iBlock = 0;
	NTSTATUS status = ZqGetFunctionBlock(Mod, fPtr, 0, 0, &iBlock);
	if (status != STATUS_INVALID_BLOCK_LENGTH){
		return status;
	}
	if (InCount < iBlock) {
		return STATUS_INVALID_BLOCK_LENGTH;
	}
	do
	{
		pRunTime = ExAllocatePoolWithTag(NonPagedPool, sizeof(RUNTIME_FUNCTION) * iBlock, 'Tag');
	} while (pRunTime == 0);
	
	status = ZqGetFunctionBlock(Mod, fPtr, pRunTime, iBlock, &iBlock);
	if (!NT_SUCCESS(status)){
		if (pRunTime!= 0){
			ExFreePoolWithTag(pRunTime, 'Tag');
		}
		return status;
	}
	for (DWORD i = 0; i < iBlock; i++){
		pRuntimeCopy[i].RunTime = pRunTime[i];
		DWORD nSzie = pRunTime[i].EndAddress - pRunTime[i].BeginAddress;
		pRuntimeCopy[i].Ptr = ExAllocatePoolWithTag(NonPagedPool, nSzie, 'lock');
		RtlCopyMemory(pRuntimeCopy[i].Ptr, Mod->ModBase + pRunTime[i].BeginAddress, nSzie);
	}
	if (pRunTime != 0) {
		ExFreePoolWithTag(pRunTime, 'Tag');
	}
	return status;
}

VOID ZqFreeBlockCopy(PF_BLOCK_COPY pRuntimeCopy, DWORD iBlock){
	for (DWORD i = 0; i < iBlock; i++) {
		if (pRuntimeCopy[i].Ptr != 0)
			ExFreePoolWithTag(pRuntimeCopy[i].Ptr, 'lock');
		pRuntimeCopy[i].Ptr = 0;
	}
}

NTSTATUS ZqLoadModSection(UNICODE_STRING* pModName, PMOD_SECTION pModSection)
{
	OBJECT_ATTRIBUTES ObjectAttributes;

	RtlZeroMemory(pModSection, sizeof(MOD_SECTION));

	InitializeObjectAttributes(
		&ObjectAttributes,
		pModName,
		(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
		NULL,
		NULL);

	HANDLE FileHandle = 0;
	HANDLE SectionHandle = 0;
	PVOID ViewBase = NULL;
	ULONGLONG ViewSize = 0;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	NTSTATUS Status = ZwOpenFile(
		&FileHandle,
		FILE_EXECUTE,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		0);

	if (!NT_SUCCESS(Status)) {
		ZqUnLoadModSection(pModSection);
		return Status;
	}
		

	pModSection->FileHandle = FileHandle;

	InitializeObjectAttributes(
		&ObjectAttributes,
		NULL,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	Status = ZwCreateSection(
		&SectionHandle,
		SECTION_MAP_READ | SECTION_MAP_EXECUTE,
		&ObjectAttributes,
		NULL,
		PAGE_EXECUTE,
		SEC_IMAGE,
		FileHandle);


	if (!NT_SUCCESS(Status)) {
		ZqUnLoadModSection(pModSection);
		return Status;
	}

	pModSection->SectionHandle = SectionHandle;

	Status = ZwMapViewOfSection(
		SectionHandle,
		ZwCurrentProcess(),
		&ViewBase,
		0L,
		0L,
		NULL,
		&ViewSize,
		ViewShare,
		0L,
		PAGE_EXECUTE);
	if (!NT_SUCCESS(Status)) {
		ZqUnLoadModSection(pModSection);
		return Status;
	}
	pModSection->Process = IoGetCurrentProcess();
	pModSection->ViewBase = ViewBase;
	pModSection->ViewSize = ViewSize;
	return Status;
}

NTSTATUS ZqUnLoadModSection(PMOD_SECTION pModSection) {
	NTSTATUS status = 0;
	if (pModSection->ViewBase != 0){
		status = ZwUnmapViewOfSection(pModSection->Process, pModSection->ViewBase);
	}
	if (pModSection->SectionHandle){
		ZwClose(pModSection->SectionHandle);
	}
	if (pModSection->FileHandle){
		ZwClose(pModSection->FileHandle);
	}
	RtlZeroMemory(pModSection, sizeof(MOD_SECTION));
	return status;
}

NTSTATUS ZqPtrGetFunctionName(PMOD_INFO Mod, PVOID Ptr, CHAR** cSearchFnName)
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
	doshdr = (IMAGE_DOS_HEADER*)Mod->ModBase;
	if (NULL == doshdr) {
		return STATUS_INVALID_HANDLE;
	}
#ifdef AMD64
	opthdr = (IMAGE_OPTIONAL_HEADER64*)(Mod->ModBase + doshdr->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
#else
	opthdr = (IMAGE_OPTIONAL_HEADER32*)(Mod->ModBase + doshdr->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
#endif
	if (NULL == opthdr)
	{
		return STATUS_INVALID_HANDLE;
	}
	pExportTable = (IMAGE_EXPORT_DIRECTORY*)(Mod->ModBase + opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (NULL == pExportTable)
	{
		return STATUS_INVALID_HANDLE;
	}
	dwAddrFns = (ULONG*)(Mod->ModBase + pExportTable->AddressOfFunctions);
	dwAddrNames = (ULONG*)(Mod->ModBase + pExportTable->AddressOfNames);
	dwAddrNameOrdinals = (USHORT*)(Mod->ModBase + pExportTable->AddressOfNameOrdinals);

	ULONG Offset = (DWORD64)Ptr - Mod->ModBase;
	*cSearchFnName = 0;
	for (i = 0; i < pExportTable->NumberOfNames; ++i){
		if (Offset == dwAddrFns[i]) {
			cFunName = (char*)(Mod->ModBase + dwAddrNames[i]);
			*cSearchFnName = cFunName;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}

PVOID ZqAllocateMemoryWithTag(SSIZE_T Size, char* SectionName)
{



	return 0;
}

