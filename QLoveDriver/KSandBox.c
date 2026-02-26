#include "KSandBox.h"

#include<ntstrsafe.h>
#include<ntifs.h>
//  主要拦截     写文件  读文件
//  各种信号创建


#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#else
#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#endif


// 这里需要初始化各种  API地址  方便以后HOOK

typedef NTSTATUS(NTAPI* fNtReadFile)(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_writes_bytes_(Length) PVOID Buffer,
	_In_ ULONG Length,
	_In_opt_ PLARGE_INTEGER ByteOffset,
	_In_opt_ PULONG Key
	);

typedef NTSTATUS(NTAPI* fNtWriteFile)(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_reads_bytes_(Length) PVOID Buffer,
	_In_ ULONG Length,
	_In_opt_ PLARGE_INTEGER ByteOffset,
	_In_opt_ PULONG Key
	);


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

typedef NTSTATUS (NTAPI * fObCreateDirectoryObject)(
	PHANDLE DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	void* a4, int a5);



//0-------------------------------------

NTSTATUS SandBoxObCreateObjectEx(
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
NTSTATUS  SandBoxObOpenObjectByName(
	POBJECT_ATTRIBUTES ObjectAttributes,
	POBJECT_TYPE ObjectType OPTIONAL,
	KPROCESSOR_MODE AccessMode,
	PACCESS_STATE AccessState OPTIONAL,
	ACCESS_MASK DesiredAccess OPTIONAL,
	PVOID ParseContext OPTIONAL,
	PHANDLE Handle
);

NTSTATUS NTAPI SandBoxObCreateDirectoryObject(
	PHANDLE DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	void* a4, int a5);

extern POBJECT_TYPE* ExMutantObjectType;
extern POBJECT_TYPE* MmSectionObjectType;

POBJECT_TYPE* ObpDirectoryObjectType;

extern BOOLEAN  SSDT_HOOK_NOW(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN);


fNtReadFile TrueNtReadFile = 0;
fNtWriteFile TrueNtWriteFile = 0;

fObCreateObjectEx TrueSandBoxObCreateObjectEx = 0;
fObOpenObjectByName  TrueSandBoxObOpenObjectByName = 0;
fObCreateDirectoryObject TrueSandBoxObCreateDirectoryObject = 0;


ULONGLONG KF_ObCreateObject = 0;
ULONGLONG KF_ObOpenObjectByName = 0;
ULONGLONG KF_ObpCreateDirectoryObject = 0;

#define AVL_SANDBOX_ADD 0
#define AVL_SANDBOX_DEL 1
#define AVL_SANDBOX_MOD 2
#define AVL_SANDBOX_GET 3
#define AVL_SANDBOX_LOCK 4
#define AVL_SANDBOX_UNLOCK 5

RTL_AVL_TABLE SandBoxTable;
KSPIN_LOCK SandBoxLock;

RTL_AVL_TABLE SandBoxSessionNumberTable;
KSPIN_LOCK SandBoxSessionNumberLock;

volatile DWORD64 SessionNumber = 1;

extern char* _ASM_MOV_RBX(char* pAdr, int num);

extern char* _ASM_MOV_RCX_NOW(char* pAdr, int num);

extern char* _ASM_AND_EDI_NOW(char* pAdr, int num);

extern  ULONGLONG _CODE_GET_REAL_QDWORD(char* pEl, int nCodeSize);

extern  ULONG _CODE_GET_REAL_DWORD(char* pEl, int nCodeSize);

extern ULONGLONG _CODE_GET_REAL_ADDRESS_0(char* pEl, int nCodeSize);

extern ULONGLONG _CODE_GET_REAL_ADDRESS(char* pEl);

extern char* _ASM_GET_CALL(char* pAdr, int num);

extern char* _ASM_MOV_RDX(char* pAdr, int num);


PVOID AVL_LOCK_SANDBOX_VOID(int flags, PVOID pInfo, int nSize);
PVOID AVL_LOCK_SANDBOX_SessionNumber_VOID(int flags, PVOID pInfo, int nSize);
PVOID AVL_LOCK_SANDBOX_STRING_VOID(int flags, K_SANDBOX_TABLE* SandBoxTableString, PVOID pInfo, int nSize);





_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS CompareHandleTableSandBox(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	K_SANDBOX * first = (K_SANDBOX *)FirstStruct;
	K_SANDBOX * second = (K_SANDBOX *)SecondStruct;
	UNREFERENCED_PARAMETER(Table);
	if (first->dwPID > second->dwPID)
		return GenericGreaterThan;
	if (first->dwPID < second->dwPID)
		return GenericLessThan;
	return GenericEqual;
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocateHandleTableSandBox(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
}

_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreeHandleTableSandBox(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'tag');
}


_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS CompareHandleTableSandBoxString(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	K_SANDBOX_REPLACE_STRING* first = (K_SANDBOX_REPLACE_STRING*)FirstStruct;
	K_SANDBOX_REPLACE_STRING* second = (K_SANDBOX_REPLACE_STRING*)SecondStruct;
	UNREFERENCED_PARAMETER(Table);

	if (first->String.Length > second->String.Length)
		return GenericGreaterThan;
	if (first->String.Length < second->String.Length)
		return GenericLessThan;
	
	char* A = (char *)first->String.Buffer;
	char* B = (char*)second->String.Buffer;

	//  这里可能出现内存异常
	__try
	{
		PHYSICAL_ADDRESS phyA = MmGetPhysicalAddress(A);
		PHYSICAL_ADDRESS phyB = MmGetPhysicalAddress(B);
		if (phyA.QuadPart == 0 || phyB.QuadPart == 0)
		{
			return GenericEqual;
		}
		for (size_t i = 0; i < first->String.Length; i++) {
			if ((char)A[i] > (char)B[i])
				return GenericGreaterThan;
			if ((char)A[i] < (char)B[i])
				return GenericLessThan;
		}
	}
	__except (1) {


	}
	return GenericEqual;
}






NTKERNELAPI
PPEB
PsGetProcessPeb(
	PEPROCESS Process
);


BOOLEAN  GetFirstMoudleFromProcess(HANDLE dwPID, UNICODE_STRING * pWchar) {

	PEPROCESS pEprocess = NULL;
	KIRQL oldIrql;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(dwPID, &pEprocess))){
		return FALSE;
	}

	PPEB pEb = 0;
	KAPC_STATE ApcState = {0};
	BOOLEAN uOK = FALSE;

	KeStackAttachProcess(pEprocess, &ApcState);
	uOK = TRUE;
	pEb = PsGetProcessPeb(pEprocess);
	PVOID BaseAddress = NULL;
	ULONG nSzie = 0;
	__try {
		ULONG64 ldr = *(PULONG64)((ULONG64)pEb + 0x18);
		PLIST_ENTRY pListHead = (PLIST_ENTRY)(ldr + 0x10);
		PLIST_ENTRY pMod = pListHead->Flink;
		PLDR_DATA_TABLE_ENTRY pTable = (PLDR_DATA_TABLE_ENTRY)pMod;
		RtlInitUnicodeString(pWchar, pTable->FullDllName.Buffer);
	}
	__except (1) {
		LOG_DEBUG("GetFirstMoudleFromProcess Faild!\n");
	}
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(pEprocess);
	return TRUE;
}

NTKERNELAPI
NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG  ReturnLength
);

NTKERNELAPI
NTSTATUS NTAPI ZwSetInformationProcess(
	IN HANDLE ProcessHandle,                                //-1 表示当前进程
	IN PROCESSINFOCLASS ProcessInformationClass,   //信息类
	IN PVOID ProcessInformation,                            //用来设置_KEXECUTE_OPTIONS
	IN ULONG ProcessInformationLength                       //第三个参数的长度
);

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationObject(
	__in HANDLE Handle,
	__in OBJECT_INFORMATION_CLASS ObjectInformationClass,
	__in_bcount(ObjectInformationLength) PVOID ObjectInformation,
	__in ULONG ObjectInformationLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
	__in HANDLE DirectoryHandle,
	__out_bcount_opt(Length) PVOID Buffer,
	__in ULONG Length,
	__in BOOLEAN ReturnSingleEntry,
	__in BOOLEAN RestartScan,
	__inout PULONG Context,
	__out_opt PULONG ReturnLength
);

//NTKERNELAPI
//BOOLEAN
//NTAPI
//ExEnumHandleTable(
//	_In_ PHANDLE_TABLE HandleTable,
//	_In_ PEX_ENUM_HANDLE_CALLBACK EnumHandleProcedure,
//	_Inout_ PVOID Context,
//	_Out_opt_ PHANDLE Handle
//);



BOOLEAN GetProcessImageName(UNICODE_STRING* pWchar)
{
//	UNICODE_STRING  ImageName = { 0 };
	PUNICODE_STRING Buffer = NULL;
	ULONG ReturnLength = 0;
	NTSTATUS status = 0;

	HANDLE FileHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	PFILE_OBJECT FileObj = NULL;
	UNICODE_STRING DosName = { 0 };

	status = ZwQueryInformationProcess(
		NtCurrentProcess(),
		ProcessImageFileName,
		NULL,
		0,
		&ReturnLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status || 0 == ReturnLength) {
		return FALSE;
	}

	Buffer = ExAllocatePool(NonPagedPool, ReturnLength);
	if (NULL == Buffer) {
		goto Clean;
	}

	status = ZwQueryInformationProcess(
		NtCurrentProcess(),
		ProcessImageFileName,
		Buffer,
		ReturnLength,
		&ReturnLength);

	if (!NT_SUCCESS(status)) {
		goto Clean;
	}

	InitializeObjectAttributes(&ObjectAttributes,
		Buffer,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenFile(&FileHandle, 0, &ObjectAttributes, &IoStatusBlock, 0, 0);
	if (!NT_SUCCESS(status)) {
		goto Clean;
	}

	status = ObReferenceObjectByHandle(FileHandle, 0, NULL, KernelMode, &FileObj, NULL);
	if (!NT_SUCCESS(status)) {
		goto Clean;
	}

	if (FileObj->DeviceObject && FileObj->FileName.Buffer) {

		//if (KeAreAllApcsDisabled())
		//{

		//} 
		// 必须在未禁用APC 下使用
		IoVolumeDeviceToDosName(FileObj->DeviceObject, &DosName);

		pWchar->MaximumLength = DosName.Length + FileObj->FileName.Length;
		pWchar->Buffer = ExAllocatePool(NonPagedPool, pWchar->MaximumLength);

		RtlCopyUnicodeString(pWchar, &DosName);
		RtlAppendUnicodeStringToString(pWchar, &FileObj->FileName);

		//RtlUnicodeStringToAnsiString(ImageFileName, &ImageName, TRUE);

		//RtlFreeUnicodeString(&ImageName);
		RtlFreeUnicodeString(&DosName);

		ExFreePool(Buffer);
		ZwClose(FileHandle);
		ObDereferenceObject(FileObj);
		return TRUE;
	}

Clean:

	if (Buffer) {
		ExFreePool(Buffer);
	}
	if (FileHandle) {
		ZwClose(FileHandle);
	}
	if (FileObj) {
		ObDereferenceObject(FileObj);
	}
	return FALSE;
}

NTSTATUS GetPathByProcessId(HANDLE dwPID, UNICODE_STRING* pWchar)
{
	if (dwPID == PsGetCurrentProcessId())
	{
		if (GetProcessImageName(pWchar)){
			return STATUS_SUCCESS;
		} 
		return STATUS_UNSUCCESSFUL;
	}
	PEPROCESS eprocess;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(dwPID, &eprocess)))
		return STATUS_UNSUCCESSFUL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KAPC_STATE stack = { 0 };
	KeStackAttachProcess(eprocess, &stack);
	status = GetProcessImageName(pWchar) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	KeUnstackDetachProcess(&stack);
	ObDereferenceObject(eprocess);
	return status;
}



NTKERNELAPI
ULONG
PsGetCurrentProcessSessionId(
	VOID
);


typedef struct _OBJECT_DIRECTORY_INFORMATION
{
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectTypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;



typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING          TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE               PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

//extern PSE_EXPORTS  SeExports;
 



OBJECT_DIRECTORY_INFORMATION* GetDirectoryObjectInformation(HANDLE hObjectDirectory, PULONG pReturnLength) {

	NTSTATUS status;
	ULONG Context;
	OBJECT_DIRECTORY_INFORMATION* Buffer = 0;
	DWORD nSize = PAGE_SIZE;
	do
	{
		Buffer = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'tag');
		if (Buffer == NULL)
		{
			return NULL;
		}
		status = ZwQueryDirectoryObject(hObjectDirectory, Buffer, PAGE_SIZE, TRUE, FALSE, &Context, pReturnLength);
		if (NT_SUCCESS(status))
		{
			return Buffer;
		}
		if (status == STATUS_MORE_ENTRIES || status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePoolWithTag(Buffer, 'tag');
			nSize += PAGE_SIZE;
			continue;
		}



		//status = ZwQueryDirectoryObject(hObjectDirectory, NULL, NULL, FALSE, TRUE, &Context, pReturnLength);
		//if (*pReturnLength != 0)
		//{


		//}
	} while (FALSE);
	return NULL;
}



BOOLEAN  CreateObjectDirectoryObject(K_SANDBOX* pSandBox) {


	SSIZE_T DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 +
		RtlLengthSid(SeExports->SeLocalSystemSid) +
		RtlLengthSid(SeExports->SeAliasAdminsSid) +
		RtlLengthSid(SeExports->SeWorldSid);

	PACL Dacl = ExAllocatePoolWithTag(PagedPool, DaclLength, 'lcaD');
	NTSTATUS status = RtlCreateAcl(Dacl, (ULONG)DaclLength, ACL_REVISION);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(Dacl, 'lcaD');
		return FALSE;
	}
	status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL,
		SeExports->SeWorldSid);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(Dacl, 'lcaD');
		return FALSE;
	}

	status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, DIRECTORY_ALL_ACCESS,
		SeExports->SeAliasAdminsSid);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(Dacl, 'lcaD');
		return FALSE;
	}

	status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, DIRECTORY_ALL_ACCESS,
		SeExports->SeLocalSid);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(Dacl, 'lcaD');
		return FALSE;
	}

	SECURITY_DESCRIPTOR SecurityDescriptor = { 0 };
	HANDLE hObjectDirectory = 0;
	status = RtlCreateSecurityDescriptor(&SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(status)){
		return FALSE;
	}
	OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING TypeDirectoryName;

	wchar_t DirectoryName[260] = { 0 };



	RtlInitUnicodeString(&TypeDirectoryName, DirectoryName);
	RtlSetDaclSecurityDescriptor(&SecurityDescriptor, TRUE, Dacl, FALSE);
	InitializeObjectAttributes(&ObjectAttributes,
		&TypeDirectoryName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		&SecurityDescriptor);
	// \Sessions\1\BaseNamedObjects
	// 删除一个子目录




	ULONG SessionsId = PsGetCurrentProcessSessionId();
	RtlStringCbPrintfW(DirectoryName, 256, L"\\Sessions\\%d\\BaseNamedObjects\\%d", 
		SessionsId, (int)pSandBox->SessionNumber);

	RtlInitUnicodeString(&TypeDirectoryName, DirectoryName);
	status = ZwOpenDirectoryObject(&hObjectDirectory, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
	if (NT_SUCCESS(status))
	{
		LOG_DEBUG("LogObject open sucess %wZ\n", &TypeDirectoryName);
		pSandBox->hObjectDirectory = hObjectDirectory;
		//ZwClose(hObjectDirectory);
		return TRUE;
	}
	status = ZwCreateDirectoryObject(&hObjectDirectory, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
	if (NT_SUCCESS(status)) {
		LOG_DEBUG("LogObject sucess %wZ\n", &TypeDirectoryName);
		pSandBox->hObjectDirectory = hObjectDirectory;
		//ZwClose(hObjectDirectory);
		return TRUE;
	}
	//if (status == STATUS_OBJECT_NAME_COLLISION)
	//{

	//}



	
	//POOL_TYPE




	//RtlStringCbPrintfW(DirectoryName, 256, L"\\Sessions");
	//RtlInitUnicodeString(&TypeDirectoryName, DirectoryName);
	//status = ZwCreateDirectoryObject(&hObjectDirectory, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
	//if (NT_SUCCESS(status) || status == STATUS_OBJECT_NAME_COLLISION)
	//{
	//	RtlStringCbPrintfW(DirectoryName, 256, L"\\Sessions\\%d", SessionsId);
	//	RtlInitUnicodeString(&TypeDirectoryName, DirectoryName);
	//	status = ZwCreateDirectoryObject(&hObjectDirectory, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
	//	if (NT_SUCCESS(status) || status == STATUS_OBJECT_NAME_COLLISION)
	//	{
	//		RtlStringCbPrintfW(DirectoryName, 256, L"\\Sessions\\%d\\BaseNamedObjects", SessionsId);
	//		RtlInitUnicodeString(&TypeDirectoryName, DirectoryName);
	//		status = ZwCreateDirectoryObject(&hObjectDirectory, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
	//		if (NT_SUCCESS(status) || status == STATUS_OBJECT_NAME_COLLISION)
	//		{

	//		}
	//	}
	//}


	LOG_DEBUG("LogObject Error %08X\n", status);

	return FALSE;

}




BOOLEAN bSandBoxInit = FALSE;




// 创建一个 SANDBOX 会话 //
K_SANDBOX * SandBoxCreateSession(HANDLE dwPID , UNICODE_STRING SandBoxDirectory, DWORD64 uSessionNumber) {

	K_SANDBOX boxInfo = { 0 };
	boxInfo.dwPID = dwPID;
	if (uSessionNumber == -1){
		boxInfo.SessionNumber = SessionNumber;
		SessionNumber++;
	}
	else
	{
		boxInfo.SessionNumber = uSessionNumber;
	}
	if (SandBoxDirectory.Buffer == 0)
		return NULL;
	void* pBuffer = ExAllocatePoolWithTag(PagedPool, SandBoxDirectory.MaximumLength, 'tag');
	if (pBuffer == NULL)
		return NULL;
	RtlCopyMemory(pBuffer, SandBoxDirectory.Buffer, SandBoxDirectory.MaximumLength);
	RtlInitUnicodeString(&boxInfo.SandBoxDirectory, pBuffer);



	//boxInfo.SandBoxDirectory = SandBoxDirectory;
	//boxInfo.SandBoxDirectory.Buffer = pBuffer;
	//boxInfo.SandBoxDirectory.MaximumLength = SandBoxDirectory.MaximumLength
	//RtlZeroMemory(pBuffer, SandBoxDirectory.MaximumLength);
	//RtlCopyUnicodeString(&boxInfo.SandBoxDirectory, &SandBoxDirectory);

	//SystemHandleInformation
	if (PsGetCurrentProcessId() == dwPID)
	{
		//SSDT_HOOK_NOW_TYPE(&SandBoxObCreateObjectEx, KF_ObCreateObject, &TrueSandBoxObCreateObjectEx, FALSE);
		//SSDT_HOOK_NOW_TYPE(&SandBoxObOpenObjectByName, KF_ObOpenObjectByName, &TrueSandBoxObOpenObjectByName, FALSE);

		

		//NTSTATUS status;
		//PROCESS_SESSION_INFORMATION info;
		//ULONG len;
		//len = sizeof(info);
		//status = ZwQueryInformationProcess(
		//	NtCurrentProcess(), ProcessSessionInformation,
		//	&info, sizeof(info), &len);
		//if (boxInfo.SessionNumber != info.SessionId)
		//{
		//	info.SessionId = boxInfo.SessionNumber;
		//	status = ZwSetInformationProcess(NtCurrentProcess(), ProcessSessionInformation, &info, sizeof(info));
		//	if (NT_SUCCESS(status))
		//	{
		//		LOG_DEBUG("set  Session %d  sucess\n", boxInfo.SessionNumber);
		//	}
		//	else
		//	{
		//		LOG_DEBUG("set  Session %d  False  %08X\n", boxInfo.SessionNumber, status);
		//	}
		//}

	}
	else
	{
		//PEPROCESS eprocess = 0;
		//if (!NT_SUCCESS(PsLookupProcessByProcessId(dwPID, &eprocess)))
		//{
		//	return FALSE;
		//}
		//KAPC_STATE stack = { 0 };
		//KeStackAttachProcess(eprocess, &stack);

		////CreateObjectDirectoryObject(boxInfo.SessionNumber);

		//SSDT_HOOK_NOW_TYPE(&SandBoxObCreateObjectEx, KF_ObCreateObject, &TrueSandBoxObCreateObjectEx, FALSE);
		//SSDT_HOOK_NOW_TYPE(&SandBoxObOpenObjectByName, KF_ObOpenObjectByName, &TrueSandBoxObOpenObjectByName, FALSE);
		////SSDT_HOOK_NOW(&SandBoxObCreateDirectoryObject, KF_ObpCreateDirectoryObject, &TrueSandBoxObCreateDirectoryObject);

		//KeUnstackDetachProcess(&stack);
		//ObfDereferenceObject(eprocess);
	}
	K_SANDBOX* pSandBox = AVL_LOCK_SANDBOX_VOID(AVL_SANDBOX_ADD, &boxInfo, sizeof(boxInfo));
	if (pSandBox == NULL)
	{
		return FALSE;
	}
	if (!bSandBoxInit)
	{
		SSDT_HOOK_NOW_TYPE(&SandBoxObCreateObjectEx, (PVOID)KF_ObCreateObject, &TrueSandBoxObCreateObjectEx, TRUE);
        SSDT_HOOK_NOW_TYPE(&SandBoxObOpenObjectByName, (PVOID)KF_ObOpenObjectByName, &TrueSandBoxObOpenObjectByName, TRUE);
		bSandBoxInit = TRUE;
	}
	if (CreateObjectDirectoryObject(pSandBox))
	{
		return pSandBox;
	} 

	return NULL;
}

K_SANDBOX* SandBoxLockSession(HANDLE dwPID) 
{
	K_SANDBOX boxInfo = { 0 };
	boxInfo.dwPID = dwPID;
	return AVL_LOCK_SANDBOX_VOID(AVL_SANDBOX_LOCK, &boxInfo, sizeof(boxInfo));
}

K_SANDBOX* SandBoxUnLockSession(HANDLE dwPID) 
{
	K_SANDBOX boxInfo = { 0 };
	boxInfo.dwPID = dwPID;
	return AVL_LOCK_SANDBOX_VOID(AVL_SANDBOX_UNLOCK, &boxInfo, sizeof(boxInfo));
}

K_SANDBOX* SandBoxRemoveSession(HANDLE dwPID)
{
	K_SANDBOX boxInfo = { 0 };
	boxInfo.dwPID = dwPID;
	return AVL_LOCK_SANDBOX_VOID(AVL_SANDBOX_DEL, &boxInfo, sizeof(boxInfo));
}

//----------------------------------------------------



K_SANDBOX_REPLACE* SandBoxLockSessionNumber(DWORD64 SessionNumber)
{
	K_SANDBOX_REPLACE boxReplaceInfo = { 0 };
	boxReplaceInfo.SessionNumber = SessionNumber;
	return AVL_LOCK_SANDBOX_SessionNumber_VOID(AVL_SANDBOX_LOCK, &boxReplaceInfo, sizeof(boxReplaceInfo));
}

K_SANDBOX_REPLACE* SandBoxUnLockSessionNumber(DWORD64 SessionNumber)
{
	K_SANDBOX_REPLACE boxReplaceInfo = { 0 };
	boxReplaceInfo.SessionNumber = SessionNumber;
	return AVL_LOCK_SANDBOX_SessionNumber_VOID(AVL_SANDBOX_UNLOCK, &boxReplaceInfo, sizeof(boxReplaceInfo));
}

K_SANDBOX_REPLACE* SandBoxRemoveSessionNumber(DWORD64 SessionNumber)
{
	K_SANDBOX_REPLACE boxReplaceInfo = { 0 };
	boxReplaceInfo.SessionNumber = SessionNumber;
	return AVL_LOCK_SANDBOX_SessionNumber_VOID(AVL_SANDBOX_DEL, &boxReplaceInfo, sizeof(boxReplaceInfo));
}

K_SANDBOX_REPLACE* SandBoxCreateSessionNumber(DWORD64 SessionNumber)
{
	K_SANDBOX_REPLACE boxReplaceInfo = { 0 };
	boxReplaceInfo.SessionNumber = SessionNumber;
	if (SandBoxLockSessionNumber(SessionNumber) != 0)
	{
		return SandBoxUnLockSessionNumber(SessionNumber);
	}
	AVL_LOCK_SANDBOX_SessionNumber_VOID(AVL_SANDBOX_ADD, &boxReplaceInfo, sizeof(boxReplaceInfo));
	K_SANDBOX_REPLACE* pReplaceInfo = SandBoxLockSessionNumber(SessionNumber);
	if (pReplaceInfo == NULL){
		return  NULL;
	}
	RtlInitializeGenericTableAvl(&pReplaceInfo->EventTable.Table, CompareHandleTableSandBoxString, AllocateHandleTableSandBox, FreeHandleTableSandBox, NULL);
	RtlInitializeGenericTableAvl(&pReplaceInfo->MuantTable.Table, CompareHandleTableSandBoxString, AllocateHandleTableSandBox, FreeHandleTableSandBox, NULL);
	RtlInitializeGenericTableAvl(&pReplaceInfo->SectionTable.Table, CompareHandleTableSandBoxString, AllocateHandleTableSandBox, FreeHandleTableSandBox, NULL);



	

	KeInitializeSpinLock(&pReplaceInfo->EventTable.Lock);
	KeInitializeSpinLock(&pReplaceInfo->MuantTable.Lock);
	KeInitializeSpinLock(&pReplaceInfo->SectionTable.Lock);
	return pReplaceInfo;
}



//BOOLEAN SandBoxFindStringForm(DWORD64 SessionNumber)








NTSTATUS   SandBoxCreateFile(HANDLE* hFile, K_SANDBOX* pSandBox, UNICODE_STRING tFile) {


	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	InitializeObjectAttributes(&ObjectAttributes,
		&tFile,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	//ZwCreateFile(hFile, FILE_ALL_ACCESS, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_SYSTEM, );



	return STATUS_SUCCESS;
}



 






extern ULONGLONG ZwFuncGetNtFun(wchar_t* _FunName);

BOOLEAN IniSandBox()
{
	if ((KF_ObOpenObjectByName != 0) && (KF_ObCreateObject != 0))
		return TRUE;
	RTL_OSVERSIONINFOW OsVersion = { 0 };
	RtlGetVersion(&OsVersion);

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
	if (pNtCreateMutantW != 0)
	{
		ExMutantObjectType = (POBJECT_TYPE*)_CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RBX((char *)pNtCreateMutantW, 1), 3);
		KF_ObCreateObject = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pNtCreateMutantW, 1));
		LOG_DEBUG("ExMutantObjectType<%p>\n", ExMutantObjectType);
		LOG_DEBUG("KF_ObCreateObject<%p>\n", KF_ObCreateObject);

	}
	if (pNtOpenMutantW != 0)
	{
		KF_ObOpenObjectByName = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)pNtOpenMutantW, 1));
		LOG_DEBUG("uObOpenObjectByName<%p>\n", KF_ObOpenObjectByName);
	}
	RtlInitializeGenericTableAvl(&SandBoxTable, CompareHandleTableSandBox, AllocateHandleTableSandBox, FreeHandleTableSandBox, NULL);
	KeInitializeSpinLock(&SandBoxLock);

	RtlInitializeGenericTableAvl(&SandBoxSessionNumberTable, CompareHandleTableSandBox, AllocateHandleTableSandBox, FreeHandleTableSandBox, NULL);
	KeInitializeSpinLock(&SandBoxSessionNumberLock);
	
	//ObpDirectoryObjectType
	//ZwCreateDirectoryObject
	ULONGLONG NtCreateDirectoryObject = ZwFuncGetNtFun(L"ZwCreateDirectoryObject");
	if (NtCreateDirectoryObject != 0)
	{
		KF_ObpCreateDirectoryObject = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL((char*)NtCreateDirectoryObject, 1));
	}
	LOG_DEBUG("Ini SandBox  ObCreateObjectEx<%p>  ObOpenObjectByName<%p> KF_ObpCreateDirectoryObject<%p>\n",
		KF_ObCreateObject, KF_ObOpenObjectByName, KF_ObpCreateDirectoryObject);
	if (KF_ObpCreateDirectoryObject != 0)
	{
		ObpDirectoryObjectType = (POBJECT_TYPE*)_CODE_GET_REAL_ADDRESS_0(_ASM_MOV_RDX((char*)KF_ObpCreateDirectoryObject, 1), 3);
		LOG_DEBUG("ObpDirectoryObjectType<%p>\n", ObpDirectoryObjectType);
		//SSDT_HOOK_NOW(&SandBoxObCreateDirectoryObject, KF_ObpCreateDirectoryObject, &TrueSandBoxObCreateDirectoryObject);
	}
	//SSDT_HOOK_NOW(SandBoxObCreateObjectEx, KF_ObCreateObject, &TrueSandBoxObCreateObjectEx);


	//ExEnumHandleTable()

	//SSDT_HOOK_NOW_TYPE(&SandBoxObCreateObjectEx, KF_ObCreateObject, &TrueSandBoxObCreateObjectEx, TRUE);
	//SSDT_HOOK_NOW_TYPE(&SandBoxObOpenObjectByName, KF_ObOpenObjectByName, &TrueSandBoxObOpenObjectByName, TRUE);


	return (KF_ObOpenObjectByName != 0) && (KF_ObCreateObject != 0  && KF_ObpCreateDirectoryObject != 0);
}



//NTSTATUS NTAPI BrNtReadFile(
//	_In_ HANDLE FileHandle,
//	_In_opt_ HANDLE Event,
//	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
//	_In_opt_ PVOID ApcContext,
//	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
//	_Out_writes_bytes_(Length) PVOID Buffer,
//	_In_ ULONG Length,
//	_In_opt_ PLARGE_INTEGER ByteOffset,
//	_In_opt_ PULONG Key
//) {
//
//	K_SANDBOX* pSandBox = SandBoxLockSession(PsGetCurrentProcessId());
//	if (pSandBox == NULL){
//		return	TrueNtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
//			IoStatusBlock, Buffer, Length, ByteOffset, Key);
//	}
//}

//NTSTATUS NTAPI BrNtWriteFile(
//	_In_ HANDLE FileHandle,
//	_In_opt_ HANDLE Event,
//	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
//	_In_opt_ PVOID ApcContext,
//	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
//	_In_reads_bytes_(Length) PVOID Buffer,
//	_In_ ULONG Length,
//	_In_opt_ PLARGE_INTEGER ByteOffset,
//	_In_opt_ PULONG Key
//) {
//
//
//
//
//	return	TrueNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
//		IoStatusBlock, Buffer, Length, ByteOffset, Key);
//}

typedef enum _SANDBOX_OBJECT_TYPE
{
	SANDBOX_OBJECT_NO = -1,
	SANDBOX_OBJECT_FILE = 0,
	SANDBOX_OBJECT_MUTANT,
	SANDBOX_OBJECT_EVENT,
	SANDBOX_OBJECT_SECTION,
}SANDBOX_OBJECT_TYPE;





extern PVOID  LoadMemoryToUser(PMDL* pMdl, PVOID addr, unsigned long nSize, KPROCESSOR_MODE Mode, ULONG Protect);


int GetOBJECT_TYPE(POBJECT_TYPE ObjectType) {
	if (ObjectType == *IoFileObjectType)
		return SANDBOX_OBJECT_FILE;
	if (ObjectType == *ExMutantObjectType)
		return SANDBOX_OBJECT_MUTANT;
	if (ObjectType == *ExEventObjectType)
		return SANDBOX_OBJECT_EVENT;
	if (ObjectType == *MmSectionObjectType)
		return SANDBOX_OBJECT_SECTION;
	return SANDBOX_OBJECT_NO;
}


wchar_t * GetOBJECT_wstring(POBJECT_TYPE ObjectType) {
	if (ObjectType == *IoFileObjectType)
		return L"FILE";
	if (ObjectType == *ExMutantObjectType)
		return L"MUTANT";
	if (ObjectType == *ExEventObjectType)
		return L"EVENT";
	if (ObjectType == *MmSectionObjectType)
		return L"SECTION";
	return L"NO";
}






void ExFreeSandBoxMemUser(SandBoxUserMemory* pMemUser) {
	__try
	{
		if (pMemUser != 0) {
			
			MmUnmapLockedPages(pMemUser->UserBuffer, pMemUser->pMdl);
			IoFreeMdl(pMemUser->pMdl);
			//ZwFreeVirtualMemory(ZwCurrentProcess(), &pMemUser->kBuffer, &pMemUser->nSize, MEM_DECOMMIT);
			ExFreePoolWithTag(pMemUser->kBuffer, 'tag');
		}
	}
	__except (1) {
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
}


PVOID ExAllocateSandBoxMemUser(size_t nSize, SandBoxUserMemory* pMemUser) {
	__try
	{

		//ZwAllocateVirtualMemory(NtGetCurrentProcess(),)
		//ZwFreeVirtualMemory
		PVOID pMemory = ExAllocatePoolWithTag(NonPagedPool, nSize, 'tag');
		
		//ZwAllocateVirtualMemory()
		//size_t size = nSize;
		//NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &pMemory, 0, &size, MEM_COMMIT, PAGE_READWRITE);
		//if (!NT_SUCCESS(status)){
		//	return NULL;
		//}
		
		if (pMemory == NULL) {
			LOG_DEBUG("Memory ExAllocatePoolWithTag error\n");
			return NULL;
		}
		PMDL pMdl = 0;
		PVOID Addr = LoadMemoryToUser(&pMdl, pMemory, nSize, UserMode, PAGE_READWRITE);
		if (Addr == 0) {
			ExFreePoolWithTag(pMemory, 'tag');
			return NULL;
		}
		RtlZeroMemory(Addr, nSize);

		//RtlZeroMemory(pMemory, size);
		
		pMemUser->pMdl = pMdl;
		pMemUser->kBuffer = pMemory;
		pMemUser->UserBuffer = Addr;
		pMemUser->nSize = nSize;
		return Addr;
	}
	__except (1) {

		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}

	return 0;
}



BOOLEAN   NewObjectName(POBJECT_ATTRIBUTES ObjectAttributes, UNICODE_STRING* pWchar, 
	DWORD64 SandBoxSessionNumber, SandBoxUserMemory * uMemory, BOOLEAN bGlobal) {

	if (bGlobal)
	{

		//ZwAllocateVirtualMemory

		SIZE_T nSize = ObjectAttributes->ObjectName->MaximumLength + 0x20;
		wchar_t* userMemory = ExAllocateSandBoxMemUser(nSize, uMemory);
		if (userMemory == NULL)
		{
			return FALSE;
		}
		RtlStringCbPrintfW(userMemory, nSize, L"%ws@%d", 
			ObjectAttributes->ObjectName->Buffer, SandBoxSessionNumber);
		RtlInitUnicodeString(pWchar, userMemory);
	}
	else
	{
		return FALSE;
		wchar_t * newObjName  = ExAllocateSandBoxMemUser(0x200, uMemory);

		if (newObjName == NULL)
		{
			return FALSE;
		}
		RtlStringCbPrintfW(newObjName, 256, L"\\Sessions\\%d\\BaseNamedObjects\\%d\\", PsGetCurrentProcessSessionId(), SandBoxSessionNumber);

		UNICODE_STRING uLOCAL;
		RtlInitUnicodeString(&uLOCAL, L"LOCAL\\*");

		BOOLEAN bLocal = FsRtlIsNameInExpression(&uLOCAL, ObjectAttributes->ObjectName, TRUE, NULL);
		if (!bLocal)
		{
			//RtlAppendUnicodeStringToString(&ObjectString, ObjectAttributes->ObjectName);
			RtlStringCbCatW(newObjName, 0x200, ObjectAttributes->ObjectName->Buffer);

		}
		else
		{
			//RtlCopyMemory(,ObjectAttributes.)
			RtlStringCbCatW(newObjName, 0x200,   (NTSTRSAFE_PCWSTR)(((char*)ObjectAttributes->ObjectName->Buffer) + 12));
		}
		//UNICODE_STRING ObjectString;
		RtlInitUnicodeString(pWchar, newObjName);
	}
	return TRUE;
}




BOOLEAN  NeedNewObjectName(K_SANDBOX* pSandBoxSession,
	POBJECT_ATTRIBUTES ObjectAttributes, SANDBOX_OBJECT_TYPE SandBoxObjectType, UNICODE_STRING* pWchar) {

	K_SANDBOX_REPLACE* pSandBoxReplace = SandBoxLockSessionNumber(pSandBoxSession->SessionNumber);
	if (pSandBoxReplace == 0){
		return FALSE;
	}
	K_SANDBOX_REPLACE_STRING SandBoxReplaceString = { 0 };
	RtlInitUnicodeString(&SandBoxReplaceString.String, ObjectAttributes->ObjectName->Buffer);
	K_SANDBOX_REPLACE_STRING * r = 0;
	if (SandBoxObjectType == SANDBOX_OBJECT_MUTANT) {
		r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_LOCK, &pSandBoxReplace->MuantTable, &SandBoxReplaceString, sizeof(SandBoxReplaceString));
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_EVENT) {
		r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_LOCK, &pSandBoxReplace->EventTable, &SandBoxReplaceString, sizeof(SandBoxReplaceString));
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_SECTION) {
		r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_LOCK, &pSandBoxReplace->SectionTable, &SandBoxReplaceString, sizeof(SandBoxReplaceString));
	}
	if (r == NULL){
		return FALSE;
	}
	SandBoxUnLockSessionNumber(pSandBoxSession->SessionNumber);
	return 1;
}




BOOLEAN  NewSessionNumber(SANDBOX_OBJECT_TYPE SandBoxObjectType, K_SANDBOX* pSandBoxSession, POBJECT_ATTRIBUTES ObjectAttributes) {

	K_SANDBOX_REPLACE* pSandBoxReplace = SandBoxLockSessionNumber(pSandBoxSession->SessionNumber);
	if (pSandBoxReplace == 0) {
		SandBoxCreateSessionNumber(pSandBoxSession->SessionNumber);
		pSandBoxReplace = SandBoxLockSessionNumber(pSandBoxSession->SessionNumber);
	}
	if (pSandBoxReplace == 0)
	{
		return FALSE;
	}
	K_SANDBOX_REPLACE_STRING rString = { 0 };
	wchar_t* pBuffer = ExAllocatePool(PagedPool, ObjectAttributes->ObjectName->MaximumLength);
	RtlCopyMemory(pBuffer, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->MaximumLength);
	RtlInitUnicodeString(&rString.String, pBuffer);
	K_SANDBOX_REPLACE_STRING *r = 0;
	if (SandBoxObjectType == SANDBOX_OBJECT_MUTANT) {
		r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_ADD, &pSandBoxReplace->MuantTable, &rString, sizeof(rString));
		//LOG_DEBUG("New MUTANT %wZ\n", &rString.String);
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_EVENT) {
		r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_ADD, &pSandBoxReplace->EventTable, &rString, sizeof(rString));
		//LOG_DEBUG("New EVENT %wZ\n", &rString.String);
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_SECTION) {
		r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_ADD, &pSandBoxReplace->SectionTable, &rString, sizeof(rString));
		//LOG_DEBUG("New SECTION %wZ\n", &rString.String);
	}
	if (r == 0){
		return FALSE;
	}
	//BOOLEAN bNew = NewObjectName(ObjectAttributes, &r->ReplaceString, pSandBoxSession->SessionNumber, &r->uMemory, TRUE);
	//if (bNew)
	//{
	//	return TRUE;
	//}
	//if (SandBoxObjectType == SANDBOX_OBJECT_MUTANT) {
	//	r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_DEL, &pSandBoxReplace->MuantTable, &rString, sizeof(rString));
	//	//LOG_DEBUG("New MUTANT %wZ\n", &rString.String);
	//}
	//else if (SandBoxObjectType == SANDBOX_OBJECT_EVENT) {
	//	r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_DEL, &pSandBoxReplace->EventTable, &rString, sizeof(rString));
	//	//LOG_DEBUG("New EVENT %wZ\n", &rString.String);
	//}
	//else if (SandBoxObjectType == SANDBOX_OBJECT_SECTION) {
	//	r = AVL_LOCK_SANDBOX_STRING_VOID(AVL_SANDBOX_DEL, &pSandBoxReplace->SectionTable, &rString, sizeof(rString));
	//	//LOG_DEBUG("New SECTION %wZ\n", &rString.String);
	//}
	return TRUE;
}

BOOLEAN  HANDLE_WITH_CREATE(SANDBOX_OBJECT_TYPE SandBoxObjectType, K_SANDBOX* pSandBoxSession,
	POBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, UNICODE_STRING* pWchar, SandBoxUserMemory* uMemory, BOOLEAN bGlobal)
{
	if ((ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE)!= 0){
		return FALSE;
	}
	if (SandBoxObjectType == SANDBOX_OBJECT_FILE){
		
		return FALSE;
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_MUTANT) {
		if (NewSessionNumber(SandBoxObjectType, pSandBoxSession, ObjectAttributes))
		{
			return NewObjectName(ObjectAttributes, pWchar, pSandBoxSession->SessionNumber, uMemory, bGlobal);
		}
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_EVENT) {
		if (NewSessionNumber(SandBoxObjectType, pSandBoxSession, ObjectAttributes))
		{
			return NewObjectName(ObjectAttributes, pWchar, pSandBoxSession->SessionNumber, uMemory, bGlobal);
		}
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_SECTION) {
		if (NewSessionNumber(SandBoxObjectType, pSandBoxSession, ObjectAttributes))
		{
			return NewObjectName(ObjectAttributes, pWchar, pSandBoxSession->SessionNumber, uMemory, bGlobal);
		}
	}
	return FALSE;
}


BOOLEAN  HANDLE_WITH_OPEN(SANDBOX_OBJECT_TYPE SandBoxObjectType, K_SANDBOX* pSandBoxSession,
	POBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, UNICODE_STRING* pWchar, SandBoxUserMemory* uMemory,BOOLEAN bGlobal)
{
	if ((ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE) != 0) {
		return FALSE;
	}

	if (SandBoxObjectType == SANDBOX_OBJECT_FILE) {

		return FALSE;
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_MUTANT) {
		if (NeedNewObjectName(pSandBoxSession, ObjectAttributes, SandBoxObjectType, pWchar))
		{
			return NewObjectName(ObjectAttributes, pWchar, pSandBoxSession->SessionNumber, uMemory, bGlobal);
		}
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_EVENT) {
		if (NeedNewObjectName(pSandBoxSession, ObjectAttributes, SandBoxObjectType, pWchar))
		{
			return NewObjectName(ObjectAttributes, pWchar, pSandBoxSession->SessionNumber, uMemory, bGlobal);
		}
	}
	else if (SandBoxObjectType == SANDBOX_OBJECT_SECTION) {
		if (NeedNewObjectName(pSandBoxSession, ObjectAttributes, SandBoxObjectType, pWchar))
		{
			return NewObjectName(ObjectAttributes, pWchar, pSandBoxSession->SessionNumber, uMemory, bGlobal);
		}
	}
	return FALSE;
}




// #define FAT_NTC_FCB               0x0502
// #define FAT_NTC_DCB               0x0503
// #define FAT_NTC_ROOT_DCB          0x0504
// #define NTFS_NTC_DCB              0x0703
// #define NTFS_NTC_ROOT_DCB         0x0704
// #define NTFS_NTC_FCB              0x0705
//
// #ifndef NodeType
// //
// //  So all records start with
// //
// //  typedef struct _RECORD_NAME {
// //      NODE_TYPE_CODE NodeTypeCode; 
// // //      NODE_BYTE_SIZE NodeByteSize;
// //          :
// //  } RECORD_NAME;
// //  typedef RECORD_NAME *PRECORD_NAME;
////
// #define NodeType(Ptr) (*((PNODE_TYPE_CODE)(Ptr)))
// #endif
//
//
//BOOLEAN
//IsDirectoryEx(PFILE_OBJECT FileObject)
//{
//	if ((NodeType(FileObject->FsContext) == FAT_NTC_DCB) ||
//		(NodeType(FileObject->FsContext) == FAT_NTC_ROOT_DCB) ||
//		(NodeType(FileObject->FsContext) == NTFS_NTC_DCB) ||
//		(NodeType(FileObject->FsContext) == NTFS_NTC_ROOT_DCB))
//		return TRUE;
//	else
//		return FALSE;
//}


//()

//Rtls
//RtlSetDaclSecurityDescriptor


NTSTATUS NTAPI SandBoxObCreateDirectoryObject(
	PHANDLE DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	void* a4, int a5)
{

	if (ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer &&
		ObjectAttributes->ObjectName->Length)
	{
		LOG_DEBUG("ObCreateDirectoryObject %wZ\n", ObjectAttributes->ObjectName);
	}
	return TrueSandBoxObCreateDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes, a4, a5);
}











NTSTATUS SandBoxObCreateObjectEx(
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
) {

	__try
	{
		if (ObjectAttributes &&
			ObjectAttributes->ObjectName &&
			ObjectAttributes->ObjectName->Buffer)
		{
			//if (ObjectType == *ObpDirectoryObjectType)
			//{
			//	//LOG_DEBUG("[%d] ObpDirectoryObject %ws  %08X\n", PsGetCurrentProcessId(), 
			//	//	ObjectAttributes->ObjectName->Buffer, ObjectAttributes->Attributes);
			//}
			//LOG_DEBUG("run %d \n", __LINE__);
			if (UserMode == OwnershipMode)
			{
				//LOG_DEBUG("run %d \n", __LINE__);
				K_SANDBOX* pSandBoxSession = SandBoxLockSession(PsGetCurrentProcessId());
				if (pSandBoxSession != NULL)
				{
					//LOG_DEBUG("run %d \n", __LINE__);

					UNICODE_STRING IPCWrapper;
					RtlInitUnicodeString(&IPCWrapper, L"GLOBAL\\*");
					BOOLEAN bGlobal = FsRtlIsNameInExpression(&IPCWrapper, ObjectAttributes->ObjectName, TRUE, NULL);
					if (bGlobal)
					{
						//LOG_DEBUG("run %d \n", __LINE__);
						UNICODE_STRING Replace = { 0 };
						SandBoxUserMemory uMemory = { 0 };
						BOOLEAN bHander = HANDLE_WITH_CREATE(GetOBJECT_TYPE(ObjectType),
							pSandBoxSession, ObjectAttributes, 0, &Replace, &uMemory, bGlobal);
						SandBoxUnLockSession(PsGetCurrentProcessId());
						wchar_t* Real = ObjectAttributes->ObjectName->Buffer;

						//	LOG_DEBUG("%ws create  %ws  %08X\n", GetOBJECT_wstring(ObjectType), Real, ObjectAttributes->Attributes);
						//LOG_DEBUG("run %d \n", __LINE__);
						if (bHander) {

							RtlInitUnicodeString(ObjectAttributes->ObjectName, Replace.Buffer);

							//LOG_DEBUG("%ws %ws  %08X\n", GetOBJECT_wstring(ObjectType), Replace.Buffer, ObjectAttributes->Attributes);
							NTSTATUS status = TrueSandBoxObCreateObjectEx(ProbeMode, ObjectType, ObjectAttributes, OwnershipMode,
								ParseContext, ObjectBodySize, PagedPoolCharge, NonPagedPoolCharge,
								Object, Flags);
							RtlInitUnicodeString(ObjectAttributes->ObjectName, Real);
							ExFreeSandBoxMemUser(&uMemory);
							//LOG_DEBUG("run %d \n", __LINE__);
							//LOG_DEBUG("%08X ProbeMode1:%d  ObjectAttributes<%p> OwnershipMode:%d ParseContext<%p> ObjectBodySize<%d> PagedPoolCharge<%08X> NonPagedPoolCharge<%08X> Flags<%d>\n",
							//	status,
							//	ProbeMode,
							//	ObjectType,
							//	ObjectAttributes OPTIONAL,
							//	OwnershipMode,
							//	ParseContext OPTIONAL,
							//	ObjectBodySize,
							//	PagedPoolCharge,
							//	NonPagedPoolCharge,
							//	Object,
							//	Flags);

							return status;
						}
					}
				}
			}
		}
	}
	__except (1) {

		LOG_DEBUG("run %s  %08X   %d\n", __FUNCTION__, GetExceptionCode(), __LINE__);

	}


	//LOG_DEBUG("run %d \n", __LINE__);
	return TrueSandBoxObCreateObjectEx(ProbeMode, ObjectType, ObjectAttributes, OwnershipMode,
		ParseContext, ObjectBodySize, PagedPoolCharge, NonPagedPoolCharge,
		Object, Flags);
}



BOOLEAN KEqualUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN bCase) {

	if (String1->Length != String2->Length)
		return FALSE;
	return RtlEqualUnicodeString(String1, String2, bCase);
}



NTSTATUS  SandBoxObOpenObjectByName(
	POBJECT_ATTRIBUTES ObjectAttributes,
	POBJECT_TYPE ObjectType OPTIONAL,
	KPROCESSOR_MODE AccessMode,
	PACCESS_STATE AccessState OPTIONAL,
	ACCESS_MASK DesiredAccess OPTIONAL,
	PVOID ParseContext OPTIONAL,
	PHANDLE Handle
) {

	__try
	{
		if (ObjectAttributes &&
			ObjectAttributes->ObjectName &&
			ObjectAttributes->ObjectName->Buffer)
		{

			//LOG_DEBUG("run %d \n", __LINE__);
			K_SANDBOX* pSandBoxSession = SandBoxLockSession(PsGetCurrentProcessId());
			if (pSandBoxSession != NULL)
			{
				//LOG_DEBUG("run %d \n", __LINE__);
				if (ObjectType == *ObpDirectoryObjectType)
				{
					//LOG_DEBUG("run %d \n", __LINE__);
					//LOG_DEBUG("[%d] Open ObpDirectoryObject %ws  %08X\n", PsGetCurrentProcessId(),
					//	ObjectAttributes->ObjectName->Buffer, ObjectAttributes->Attributes);
					wchar_t pBaseObjectDirectory[260] = { 0 };
					RtlStringCbPrintfW(pBaseObjectDirectory, 256, L"\\Sessions\\%ld\\BaseNamedObjects",
						PsGetCurrentProcessSessionId());
					UNICODE_STRING uBaseObjectDirectory;
					RtlInitUnicodeString(&uBaseObjectDirectory, pBaseObjectDirectory);
					if (KEqualUnicodeString(&uBaseObjectDirectory, ObjectAttributes->ObjectName, FALSE))
					{
						//LOG_DEBUG("run %d \n", __LINE__);
						UNICODE_STRING Replace = { 0 };
						SandBoxUserMemory uMemory = { 0 };
						wchar_t* userMemory = ExAllocateSandBoxMemUser(260, &uMemory);
						//if (userMemory != 0){
						//	RtlZeroMemory(userMemory, 260);
						//}
						//LOG_DEBUG("run %d \n", __LINE__);
						RtlStringCbPrintfW(userMemory, 256, L"\\Sessions\\%d\\BaseNamedObjects\\%d",
							PsGetCurrentProcessSessionId(), pSandBoxSession->SessionNumber);

						//LOG_DEBUG("[%d] Rname ObpDirectoryObject %ws  %08X\n", PsGetCurrentProcessId(),
						//	userMemory, ObjectAttributes->Attributes);
						//LOG_DEBUG("run %d \n", __LINE__);
						wchar_t* Real = ObjectAttributes->ObjectName->Buffer;
						//LOG_DEBUG("run %d \n", __LINE__);
						RtlInitUnicodeString(ObjectAttributes->ObjectName, userMemory);
						NTSTATUS status = TrueSandBoxObOpenObjectByName(ObjectAttributes, ObjectType, AccessMode, AccessState,
							DesiredAccess, ParseContext, Handle);
						//LOG_DEBUG("run %d \n", __LINE__);
						RtlInitUnicodeString(ObjectAttributes->ObjectName, Real);
						ExFreeSandBoxMemUser(&uMemory);
						//LOG_DEBUG(" status %08X\n", status);
						//LOG_DEBUG("run %d \n", __LINE__);
						if (!NT_SUCCESS(status))
						{
							status = TrueSandBoxObOpenObjectByName(ObjectAttributes, ObjectType, AccessMode, AccessState,
								DesiredAccess, ParseContext, Handle);
						}
						//LOG_DEBUG("run %d \n", __LINE__);
						//STATUS_ABANDONED
						return status;
					}
				}

				//LOG_DEBUG("run %d \n", __LINE__);
				UNICODE_STRING IPCWrapper;
				RtlInitUnicodeString(&IPCWrapper, L"GLOBAL\\*");
				BOOLEAN bGlobal = FsRtlIsNameInExpression(&IPCWrapper, ObjectAttributes->ObjectName, TRUE, NULL);
				if (bGlobal)
				{
					UNICODE_STRING Replace = { 0 };
					SandBoxUserMemory uMemory = { 0 };
					BOOLEAN bHander = HANDLE_WITH_OPEN(GetOBJECT_TYPE(ObjectType),
						pSandBoxSession, ObjectAttributes, DesiredAccess, &Replace, &uMemory, bGlobal);
					SandBoxUnLockSession(PsGetCurrentProcessId());
					wchar_t* Real = ObjectAttributes->ObjectName->Buffer;
					//if (GetOBJECT_TYPE(ObjectType) != SANDBOX_OBJECT_NO){
					//	LOG_DEBUG("%ws open %ws  %08X\n", GetOBJECT_wstring(ObjectType), Real, ObjectAttributes->Attributes);
					//}
					//LOG_DEBUG("run %d \n", __LINE__);
					if (bHander) {


						// 

						RtlInitUnicodeString(ObjectAttributes->ObjectName, Replace.Buffer);
						//ObjectAttributes->RootDirectory = pSandBoxSession->hObjectDirectory;
						//LOG_DEBUG("%ws open %ws  %08X\n", GetOBJECT_wstring(ObjectType), Real, ObjectAttributes->Attributes);

						//LOG_DEBUG("%ws %ws  %08X\n", GetOBJECT_wstring(ObjectType), Replace.Buffer, ObjectAttributes->Attributes);
						NTSTATUS status = TrueSandBoxObOpenObjectByName(ObjectAttributes, ObjectType, AccessMode, AccessState,
							DesiredAccess, ParseContext, Handle);
						RtlInitUnicodeString(ObjectAttributes->ObjectName, Real);
						ExFreeSandBoxMemUser(&uMemory);

						//LOG_DEBUG("%08X AccessMode<%p> AccessState<%p> DesiredAccess<%08X> ParseContext<%p>\n", status, AccessMode,
						//	AccessState,
						//	DesiredAccess,
						//	ParseContext);
						//LOG_DEBUG("run %d \n", __LINE__);
						return status;
					}
				}
			}
		}


	}
	__except (1) {

		LOG_DEBUG("run %s  %08X   %d\n", __FUNCTION__, GetExceptionCode(), __LINE__);

	}
	//LOG_DEBUG("run %d \n", __LINE__);
	return TrueSandBoxObOpenObjectByName(ObjectAttributes, ObjectType, AccessMode, AccessState,
		DesiredAccess, ParseContext, Handle);
}














// 根据初始化 来PID
BOOLEAN SandBoxInitWithPID(HANDLE dwPID) {

	
	//SSDT_HOOK_NOW()









	return FALSE;
}






PVOID AVL_LOCK_SANDBOX_VOID(int flags, PVOID pInfo, int nSize)
{
	PVOID fID = 0;
	KIRQL irql = 0;
	KeAcquireSpinLock(&SandBoxLock, &irql);
	__try
	{
		//KeAcquireSpinLockAtDpcLevel(&Avl->Lock);
		if (flags == AVL_SANDBOX_ADD) {
			BOOLEAN r = FALSE;
			RtlInsertElementGenericTableAvl(&SandBoxTable, pInfo, nSize, &r);
			if (r) {
				fID = pInfo;
			}
		}
		else if (flags == AVL_SANDBOX_DEL) {

			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTable, pInfo);
			if (pInfoV != 0) {
				//RtlCopyMemory(pInfo, pInfoV, nSize);
				if (*(DWORD64*)pInfoV == 0)
				{
					if (RtlDeleteElementGenericTableAvl(&SandBoxTable, pInfo)) {
						fID = pInfo;
					}
				}
			}
		}
		else if (flags == AVL_SANDBOX_GET) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTable, pInfo);
			if (pInfoV != 0)
			{
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_SANDBOX_MOD) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTable, pInfo);
			if (pInfoV != 0) {
				RtlCopyMemory(pInfoV, pInfo, nSize);
				fID = pInfoV;
			}
		}
		else if (flags == AVL_SANDBOX_LOCK) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTable, pInfo);
			if (pInfoV != 0)
			{
				(*(DWORD64*)pInfoV)++;
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_SANDBOX_UNLOCK) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTable, pInfo);
			if (pInfoV != 0) {
				if (*(DWORD64*)pInfoV > 0)
				{
					(*(DWORD64*)pInfoV)--;
				}
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
	}
	__except (1) {

		//STATUS_ABANDONED_WAIT_0
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	KeReleaseSpinLock(&SandBoxLock, irql);
	return fID;
}


PVOID AVL_LOCK_SANDBOX_SessionNumber_VOID(int flags, PVOID pInfo, int nSize)
{
	PVOID fID = 0;
	KIRQL irql = 0;
	KeAcquireSpinLock(&SandBoxSessionNumberLock, &irql);
	__try
	{
		//KeAcquireSpinLockAtDpcLevel(&Avl->Lock);
		if (flags == AVL_SANDBOX_ADD) {
			BOOLEAN r = FALSE;
			RtlInsertElementGenericTableAvl(&SandBoxSessionNumberTable, pInfo, nSize, &r);
			if (r) {
				fID = pInfo;
			}
		}
		else if (flags == AVL_SANDBOX_DEL) {

			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxSessionNumberTable, pInfo);
			if (pInfoV != 0) {
				//RtlCopyMemory(pInfo, pInfoV, nSize);
				if (*(DWORD64*)pInfoV == 0)
				{
					if (RtlDeleteElementGenericTableAvl(&SandBoxSessionNumberTable, pInfo)) {
						fID = pInfo;
					}
				}
			}
		}
		else if (flags == AVL_SANDBOX_GET) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxSessionNumberTable, pInfo);
			if (pInfoV != 0)
			{
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_SANDBOX_MOD) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxSessionNumberTable, pInfo);
			if (pInfoV != 0) {
				RtlCopyMemory(pInfoV, pInfo, nSize);
				fID = pInfoV;
			}
		}
		else if (flags == AVL_SANDBOX_LOCK) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxSessionNumberTable, pInfo);
			if (pInfoV != 0)
			{
				(*(DWORD64*)pInfoV)++;
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_SANDBOX_UNLOCK) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxSessionNumberTable, pInfo);
			if (pInfoV != 0) {
				if (*(DWORD64*)pInfoV > 0)
				{
					(*(DWORD64*)pInfoV)--;
				}
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
	}
	__except (1) {

		//STATUS_ABANDONED_WAIT_0
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	KeReleaseSpinLock(&SandBoxSessionNumberLock, irql);
	return fID;
}

PVOID AVL_LOCK_SANDBOX_STRING_VOID(int flags, K_SANDBOX_TABLE* SandBoxTableString, PVOID pInfo, int nSize)
{
	PVOID fID = 0;
	KIRQL irql = 0;
	KeAcquireSpinLock(&SandBoxTableString->Lock, &irql);
	__try
	{
		//KeAcquireSpinLockAtDpcLevel(&Avl->Lock);
		if (flags == AVL_SANDBOX_ADD) {
			BOOLEAN r = FALSE;
			PVOID NewInfo =  RtlInsertElementGenericTableAvl(&SandBoxTableString->Table, pInfo, nSize, &r);
			if (r) {
				fID = NewInfo;
			}
		}
		else if (flags == AVL_SANDBOX_DEL) {

			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTableString->Table, pInfo);
			if (pInfoV != 0) {
				//RtlCopyMemory(pInfo, pInfoV, nSize);
				if (*(DWORD64*)pInfoV == 0)
				{
					if (RtlDeleteElementGenericTableAvl(&SandBoxTableString->Table, pInfo)) {
						fID = pInfo;
					}
				}
			}
		}
		else if (flags == AVL_SANDBOX_GET) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTableString->Table, pInfo);
			if (pInfoV != 0)
			{
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_SANDBOX_MOD) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTableString->Table, pInfo);
			if (pInfoV != 0) {
				RtlCopyMemory(pInfoV, pInfo, nSize);
				fID = pInfoV;
			}
		}
		else if (flags == AVL_SANDBOX_LOCK) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTableString->Table, pInfo);
			if (pInfoV != 0)
			{
				(*(DWORD64*)pInfoV)++;
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_SANDBOX_UNLOCK) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&SandBoxTableString->Table, pInfo);
			if (pInfoV != 0) {
				if (*(DWORD64*)pInfoV > 0)
				{
					(*(DWORD64*)pInfoV)--;
				}
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
	}
	__except (1) {

		//STATUS_ABANDONED_WAIT_0
		LOG_DEBUG("_except %s %08X\n", __FUNCTION__, GetExceptionCode());
	}
	KeReleaseSpinLock(&SandBoxTableString->Lock, irql);
	return fID;
}