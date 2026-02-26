



#ifdef __cplusplus
extern "C" {
#endif

#include<ntifs.h>
#include<windef.h>
#include<ntddk.h>
#include<wdm.h>	

#ifdef __cplusplus

}


#include <iostream>
#include <string>
//#include "..\QLoveDriver\src\"
//#include "kernel_utils.h"
//#include "pattern.h"


#endif




//#include "infinity_hook/hook.hpp"


//#include "ByePgLib/ByePg.h"
//#ifdef _KERNEL_MODE
//#include "Detours/detours.h"


//#define   RELOAD_IMAGE


#ifdef __cplusplus
extern "C" {
#endif

#include "TCP.h"
#include "Hide.h"
#include "HideDriver.h"
#include "SSDT_NEW_FUN.h"
#include "PhysicalMemory.h"
#include "KSandBox.h"
#include "KsSocket/berkeley.h"
#include "KServer.h"
#include "KsSerial.h"
#include "FilterDriverIo.h"
#include "PELoader.h"


#ifdef __cplusplus
}
#endif

#ifdef DEBUG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format "\n",__LINE__, __VA_ARGS__);
#else
#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#endif // DEBUG



//#pragma section( ".block", read, write, execute )
//
//__declspec(allocate(".block")) RTB RtBlock = { 0 };
//__declspec(allocate(".block")) PGBLOCK PgBlock = { 0 };
//
//void
//NTAPI
//InitializeGpBlock(
//	__in PVOID Rtb
//);
//
//void
//NTAPI
//InitializeSpace(
//	__inout PVOID Block
//);




//void EntryPoint()
//{
//	NTSTATUS Status = ByePgInitialize([](CONTEXT* ContextRecord, EXCEPTION_RECORD* ExceptionRecord) -> LONG
//		{
//			//// If it is due to #BP
//			//if (ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
//			//{
//			//	//Log("Discarding #BP at RIP = %p, Processor ID: %d!\n", ContextRecord->Rip, KeGetCurrentProcessorIndex());
//
//			//	// Continue execution
//			//	ContextRecord->Rip++;
//			//	return EXCEPTION_CONTINUE_EXECUTION;
//			//}
//			if (ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION)
//			{
//				char* pCode = (char*)ContextRecord->Rip;
//				if (pCode[0] == (char)0x0F  &&
//					pCode[1] == (char)0x22 &&
//					pCode[2] == (char)0xc0)
//				{
//					ContextRecord->Rip += 3;
//
//					//ContextRecord->crc
//					return EXCEPTION_CONTINUE_EXECUTION;
//
//				}
//			}
//			return EXCEPTION_CONTINUE_SEARCH;
//		}, TRUE);
//
//	//if (NT_SUCCESS(Status))
//	//{
//	//	KeIpiGenericCall([](ULONG64 x)
//	//		{
//	//			__debugbreak();
//	//			return 0ull;
//	//		}, 0);
//	//}
//	//else
//	//{
//	//	//Log("ByePg failed to initialize with status: %x\n", Status);
//	//}
//}

#ifdef __cplusplus
extern "C" {
#endif
	NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

	PVOID BufDeviceString = NULL;

	UNICODE_STRING  uszDriverString;
	UNICODE_STRING  uszDeviceString;
	UNICODE_STRING  uszSymLinkString;

	UNICODE_STRING  uszStringRegPepi;

	UNICODE_STRING SandBoxDirectory;
	UNICODE_STRING ImageForSandBox;

	WCHAR DeviceBuffer[MAX_PATH + 1];
	WCHAR SymLinkBuffer[MAX_PATH + 1];


	static uint32_t wKey = 0;

	extern SOCKET_BUFFER BufferArry[128];

	extern VOID wSleepNs(LONG msec);



#pragma pack(1)

#define KERNEL_READ 0
#define KERNEL_WRITE 1
#define KERNEL_POOL 2
#define KERNEL_READ_LIST 3
#define KERNEL_READ_OFFSET 4
#define KERNEL_KeServiceDescriptorTableShadow 3
#define KERNEL_HIDE_PROCESS 4
#define KERNEL_SHOW_PROCESS 5
#define KERNEL_PICTURE 6


#define KERNEL_READ_NEWWORLD_1 0x1001
#define KERNEL_READ_NEWWORLD_2 0x1002
#define KERNEL_READ_NEWWORLD_3 0x1003


#define KERNEL_READ_MEMORY_0 0x8000
#define KERNEL_READ_MEMORY_1 0x8001

#pragma pack(push)
#pragma pack(4)

	typedef struct IOINFO {
		DWORD Error; //要读写的数据,
		DWORD Type; // 需要操作的代码
		DWORD pID;//要读写的进程ID
		void* pAdr; //要读写的地址
		DWORD pAdrSize;//读写长度
		void* pVal;//要读写的数据,
		DWORD pValSize;//读写长度
	}IOINFO, * LPIOINFO;



	typedef unsigned int uint32_t;
#define MSGHEAD 	uint32_t len; uint32_t checknum; uint32_t sgin; 

	typedef struct MSGCOMMAND {
		MSGHEAD
			uint32_t Extra;
		char command[16];
	}*LPMSGCOMMAND;

	// 通用
	typedef struct MSGCOMMON {
		MSGHEAD
			uint32_t common;
	}MSGCOMMON,*LPMSGCOMMON;


#pragma pack(pop)

	typedef struct _LDR_MODULE {
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID BaseAddress;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		SHORT LoadCount;
		SHORT TlsIndex;
		LIST_ENTRY HashTableEntry;
		ULONG TimeDateStamp;
	} LDR_MODULE, * PLDR_MODULE;

	typedef struct _PEB_LDR_DATA {
		ULONG                   Length;
		BOOLEAN                 Initialized;
		PVOID                   SsHandle;
		LIST_ENTRY              InLoadOrderModuleList;
		LIST_ENTRY              InMemoryOrderModuleList;
		LIST_ENTRY              InInitializationOrderModuleList;
		// x64
		PVOID                   EntryInProgress;
		PVOID                   ShutdownInProgress;
		PVOID                   ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;



	typedef struct _MMPTE_TEST {
		ULONGLONG  Header : 50;
		ULONGLONG   Valid : 1;
	}MMPTE_TEST;

	typedef struct _MMPTE_TEST_0 {
		union {
			ULONGLONG Long;
			MMPTE_TEST MPTE_T;
		}u;
	}MMPTE_TEST0;


#include "BrotherEncrypt.h"



	BOOLEAN  IOSysBuffer(DWORD IOMajor, PVOID64 gBuffer);
	//void IniComMsg();

	int hookShow(char *Arg);

	//LONG FiltereExceptin(EXCEPTION_POINTERS* pEXCEOTION) {

	//	//LOG_DEBUG("%s __except  pEXCEOTION->ExceptionRecord->ExceptionAddress  %I64X\n", __FUNCTION__, pEXCEOTION->ExceptionRecord->ExceptionAddress);
	//	if (pEXCEOTION->ExceptionRecord->ExceptionCode == 0x80000003)
	//	{
	//		//pEXCEOTION->ContextRecord->Rip = pEXCEOTION->ContextRecord->Rip + 1;;
	//		return EXCEPTION_CONTINUE_EXECUTION;
	//	}
	//	return EXCEPTION_EXECUTE_HANDLER;
	//}

	//int NTAPI DetourGetInstructionLength(PVOID ControlPc)
	//{
	//	//LOG_DEBUG("DetourGetInstructionLength  0x80000003\n");
	//	__try
	//	{
	//		PVOID gBuffer = DetourCopyInstruction(NULL, NULL, ControlPc, NULL, NULL);
	//		return  (DWORD64)gBuffer - (DWORD64)ControlPc;
	//	}
	//	__except (FiltereExceptin(GetExceptionInformation())) {


	//	}
	//	return 0;
	//}



#define BROTHER_DRIVERCODE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN,0x1000,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define BROTHER_DRIVERCODE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,0x1001,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define BROTHER_DRIVERCODE_WINDOWS CTL_CODE(FILE_DEVICE_UNKNOWN,0x1002,METHOD_BUFFERED,FILE_ALL_ACCESS)
#define BROTHER_DRIVERCODE_KEY CTL_CODE(FILE_DEVICE_UNKNOWN,0x1003,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define BROTHER_DRIVERCODE_MOUDLE CTL_CODE(FILE_DEVICE_UNKNOWN,0x1004,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define BROTHER_DRIVERCODE_KEYBORAD CTL_CODE(FILE_DEVICE_UNKNOWN,0x1010,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define BROTHER_DRIVERCODE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN,0x1030,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define BROTHER_DRIVERCODE_MUTEX CTL_CODE(FILE_DEVICE_UNKNOWN,0x1040,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define BROTHER_DRIVERCODE_OPENPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,0x2001,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define BROTHER_DRIVERCODE_MSG CTL_CODE(FILE_DEVICE_UNKNOWN,0x1080,METHOD_BUFFERED,FILE_ALL_ACCESS)



	NTSTATUS DriverIrpCtl(PDEVICE_OBJECT device, PIRP pirp);
	NTSTATUS CreateDriverObject(PDRIVER_OBJECT pDriver);
	NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp);
	NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp);

	ULONG64 NTAPI m_MmGround();

	NTSTATUS Brother_getKey(LPIOINFO pValue);
	BOOLEAN Brother_Verification(LPIOINFO pValue);
	int  IOSocketBuffer(SOCKET s, DWORD IOMajor, LPIOINFO pInfo, char* rBuffer);
	int  IOSocketBufferUdp(SOCKET s, DWORD IOMajor, LPIOINFO pInfo, char* rBuffer, struct sockaddr* Addr, int Len);
	int  IOFileBuffer(HANDLE hFile, DWORD IOMajor, LPIOINFO pInfo, char* rBuffer);

	int sendEncrypt(SOCKET s, uint32_t Sgin, void* pBuffer, uint32_t nLen)
	{
		__try {
			char* Buffer = 0;
			if (pBuffer == 0){
				Buffer = BufferArry[s].BufferSend;
			}
			else
			{
				Buffer = (char*)pBuffer - 12;
			}
			LPMSGCOMMON pCommon = (LPMSGCOMMON)Buffer;
			pCommon->len = nLen + 12;
			pCommon->sgin = Sgin;
			//if (pBuffer != NULL) {
			//	memcpy(&pCommon->common, pBuffer, nLen);
			//}
			//_hEncrypt_DEC(wKey, &pCommon->common, nLen);
			pCommon->checknum = _hEncrypt(wKey, &pCommon->sgin, pCommon->len - 8);
			BufferArry[s].SendBuF.Length = pCommon->len;
			WSK_BUF WskBuffer = BufferArry[s].SendBuF;
			WskBuffer.Length = pCommon->len;
			return sendfast(s, &WskBuffer, WSK_FLAG_NODELAY);
		}
		__except (1) {
			return 0;
		}
		return 0;
	}

	int sendEncryptFile(HANDLE hFile, uint32_t Sgin, void* pBuffer, uint32_t nLen)
	{
		__try {

			char* Buffer = 0;
			char tBuffer[0x1000];
			if (pBuffer == 0)
			{
				Buffer = tBuffer;
			}
			else
			{
				Buffer = (char*)pBuffer - 12;
			}
			LPMSGCOMMON pCommon = (LPMSGCOMMON)Buffer;
			pCommon->len = nLen + 12;
			pCommon->sgin = Sgin;
			//if (pBuffer != NULL) {
			//	memcpy(&pCommon->common, pBuffer, nLen);
			//}
			//_hEncrypt_DEC(wKey, &pCommon->common, nLen);
			pCommon->checknum = _hEncrypt(wKey, &pCommon->sgin, pCommon->len - 8);
			IO_STATUS_BLOCK IoBlok;
			LARGE_INTEGER Large;
			Large.QuadPart = 0;
			NtWriteFile(hFile, 0, 0, 0, &IoBlok, Buffer, pCommon->len, &Large, 0);
		}
		__except (1) {
			return 0;
		}
		return 0;
	}

	int sendEncryptUdp(SOCKET s, uint32_t Sgin, void* pBuffer, uint32_t nLen, struct sockaddr* Addr, int SockLen)
	{
		__try {
			char* Buffer = 0;
			if (pBuffer == 0) {
				Buffer = BufferArry[s].BufferSend;
			}
			else
			{
				Buffer = (char*)pBuffer - 12;
			}
			LPMSGCOMMON pCommon = (LPMSGCOMMON)Buffer;
			pCommon->len = nLen + 12;
			pCommon->sgin = Sgin;
			//if (pBuffer != NULL) {
			//	memcpy(&pCommon->common, pBuffer, nLen);
			//}
			//_hEncrypt_DEC(wKey, &pCommon->common, nLen);
			pCommon->checknum = _hEncrypt(wKey, &pCommon->sgin, pCommon->len - 8);

			//BufferArry[s].SendBuF.Length = pCommon->len;
			//WSK_BUF WskBuffer = BufferArry[s].SendBuF;
			//WskBuffer.Length = pCommon->len;
			return sendto(s, Buffer, pCommon->len, 0, Addr, SockLen);
		}
		__except (1) {
			return 0;
		}
		return 0;
	}


	int sendEncryptNo(SOCKET s, uint32_t Sgin, void* pBuffer, uint32_t nLen)
	{
		__try {


			if (nLen > 0xFF4)
				return -1;
			char Buffer[0x1000];
			LPMSGCOMMON pCommon = (LPMSGCOMMON)Buffer;
			pCommon->len = nLen + 12;
			pCommon->sgin = Sgin;
			if (pBuffer != NULL) {
				memcpy(&pCommon->common, pBuffer, nLen);
			}
			//_hEncrypt_DEC(wKey, &pCommon->common, nLen);
			//pCommon->checknum = _hEncrypt(wKey, &pCommon->sgin, pCommon->len - 8);
			return send(s, Buffer, pCommon->len, WSK_FLAG_NODELAY);
		}
		__except (1) {
			return 0;
		}
		return 0;
	}







	//char * BufferArry[128] = { 0 };

	int hBufferSocket(SOCKET s, char* pBuffer, uint32_t nLen) {

		if (nLen < (sizeof(MSGCOMMON) - 4)) {
			return sendEncrypt(s, 0xC0000001, NULL, 0);
		}
		LPMSGCOMMON pCommon = (LPMSGCOMMON)pBuffer;
		if (pCommon->len != nLen){
			return sendEncrypt(s, 0xC0000002, NULL, 0);
		}

		//LOG_DEBUG("pCommon->sgin  %08X \n", pCommon->sgin);
		if (pCommon->sgin == 0x80001000){
			IOINFO rInfo = {0};
			rInfo.pAdr = &rInfo.pAdr;
			Brother_getKey(&rInfo);
			return sendEncryptNo(s, 0x80002000, &rInfo, sizeof(rInfo));
		}
		if (!Brother_Verification((LPIOINFO)pBuffer))
		{
			return sendEncrypt(s, 0xC0000003, NULL, 0);
		} 
		if (s >= 128) {
			return sendEncrypt(s, 0xC0000004, NULL, 0);
		}
		char* rBuffer = BufferArry[s].BufferSend;
		//if (rBuffer == NULL) {
		//	BufferArry[s].BufferSend = ExAllocatePoolWithTag(PagedPool, SEND_SIZE, 'Mem');
		//	rBuffer = BufferArry[s].BufferSend;
		//}
		if (rBuffer == NULL) {
			return sendEncrypt(s, 0xC0000009, NULL, 0);
		}
		LPMSGCOMMON pCommonSend = (LPMSGCOMMON)rBuffer;
		return IOSocketBuffer(s, pCommon->sgin, (LPIOINFO)&pCommon->common, (char*)&pCommonSend->common);
	}



	int hBufferSocketUdp(SOCKET s, char* pBuffer, uint32_t nLen, struct sockaddr* Addr, int SockLen) {

		LOG_DEBUG("In Handle Udp\n");
		if (nLen < (sizeof(MSGCOMMON) - 4)) {
			return sendEncryptUdp(s, 0xC0000001, NULL, 0, Addr, SockLen);
		}
		LPMSGCOMMON pCommon = (LPMSGCOMMON)pBuffer;
		if (pCommon->len != nLen) {
			return sendEncryptUdp(s, 0xC0000002, NULL, 0, Addr, SockLen);
		}

		LOG_DEBUG("pCommon->sgin  %08X \n", pCommon->sgin);
		if (pCommon->sgin == 0x80001000) {
			IOINFO rInfo = { 0 };
			rInfo.pAdr = &rInfo.pAdr;
			Brother_getKey(&rInfo);
			return sendEncryptUdp(s, 0x80002000, &rInfo, sizeof(rInfo), Addr, SockLen);
		}
		if (!Brother_Verification((LPIOINFO)pBuffer))
		{
			return sendEncryptUdp(s, 0xC0000003, NULL, 0, Addr, SockLen);
		}
		if (s >= 128) {
			return sendEncryptUdp(s, 0xC0000004, NULL, 0, Addr, SockLen);
		}
		char* rBuffer = BufferArry[s].BufferSend;
		if (rBuffer == NULL) {
			BufferArry[s].BufferSend = (char *)ExAllocatePoolWithTag(PagedPool, SEND_SIZE, 'Mem');
			rBuffer = BufferArry[s].BufferSend;
		}
		if (rBuffer == NULL) {
			return sendEncryptUdp(s, 0xC0000009, NULL, 0, Addr, SockLen);
		}
		LPMSGCOMMON pCommonSend = (LPMSGCOMMON)rBuffer;
		return IOSocketBufferUdp(s, pCommon->sgin, (LPIOINFO)&pCommon->common, (char*)&pCommonSend->common, Addr, SockLen);
	}


	//(SOCKET s, char* pBuffer, uint32_t nLen, struct sockaddr* Addr, int SockLen)


	char* BufferFile = 0;

	int hBufferFileV(HANDLE hFile, char* pBuffer, int nLen) {

		if (nLen < (sizeof(MSGCOMMON) - 4)) {
			return sendEncryptFile(hFile, 0xC0000001, NULL, 0);
		}
		LPMSGCOMMON pCommon = (LPMSGCOMMON)pBuffer;
		if (pCommon->len != nLen) {
			return sendEncryptFile(hFile, 0xC0000002, NULL, 0);
		}

		LOG_DEBUG("pCommon->sgin  %08X \n", pCommon->sgin);
		if (pCommon->sgin == 0x80001000) {
			IOINFO rInfo = { 0 };
			rInfo.pAdr = &rInfo.pAdr;
			Brother_getKey(&rInfo);
			return sendEncryptFile(hFile, 0x80002000, &rInfo, sizeof(rInfo));
		}
		if (!Brother_Verification((LPIOINFO)pBuffer))
		{
			return sendEncryptFile(hFile, 0xC0000003, NULL, 0);
		}
		char* rBuffer = BufferFile;
		if (rBuffer == NULL) {
			BufferFile = (char *)ExAllocatePoolWithTag(PagedPool, SEND_SIZE, 'Mem');
			rBuffer = BufferFile;
		}
		if (rBuffer == NULL) {
			return sendEncryptFile(hFile, 0xC0000009, NULL, 0);
		}
		LPMSGCOMMON pCommonSend = (LPMSGCOMMON)rBuffer;
		return IOFileBuffer(hFile, pCommon->sgin, (LPIOINFO)&pCommon->common, (char*)&pCommonSend->common);

	}








	BOOLEAN SandBoxFilter(PUNICODE_STRING FilterName, PUNICODE_STRING PathName);


	NTSTATUS FD_SetFileCompletion(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp,
		IN PVOID Context
	)
	{
		UNREFERENCED_PARAMETER(DeviceObject);
		UNREFERENCED_PARAMETER(Context);
		Irp->UserIosb->Status = Irp->IoStatus.Status;
		Irp->UserIosb->Information = Irp->IoStatus.Information;
		KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);
		IoFreeIrp(Irp);
		return STATUS_MORE_PROCESSING_REQUIRED;
	}

	HANDLE	FD_OpenFile(WCHAR szFileName[])
	{
		NTSTATUS			ntStatus;
		UNICODE_STRING		FileName;
		OBJECT_ATTRIBUTES	objectAttributes;
		HANDLE				hFile;
		IO_STATUS_BLOCK		ioStatus;

		// 确保IRQL在PASSIVE_LEVEL上
		if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
			LOG_DEBUG("FD_OpenFile Over   Irql\n");
			return NULL;
		}


		// 初始化文件名
		RtlInitUnicodeString(&FileName, szFileName);
		LOG_DEBUG("%ws\n", FileName.Buffer);

		//初始化对象属性
		InitializeObjectAttributes(&objectAttributes, &FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		// 打开文件

		//sizeof(IOINFO)
	//	ntStatus = ZwOpenFile(&hFile, FILE_READ_ATTRIBUTES, &objectAttributes, &ioStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

		ntStatus = IoCreateFile(&hFile, FILE_READ_ATTRIBUTES, &objectAttributes, &ioStatus,
			0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);

		if (!NT_SUCCESS(ntStatus)) {
	
			LOG_DEBUG("IoCreateFile Error  %08X \n", ntStatus)

			return NULL;

		}
		return  hFile;
	}

	BOOLEAN	FD_StripFileAttributes(HANDLE FileHandle)
	{
		NTSTATUS				ntStatus = STATUS_SUCCESS;
		PFILE_OBJECT			fileObject;
		PDEVICE_OBJECT			DeviceObject;
		PIRP					Irp;
		KEVENT					SycEvent;
		FILE_BASIC_INFORMATION	FileInformation;
		IO_STATUS_BLOCK			ioStatus;
		PIO_STACK_LOCATION		irpSp;

		// 获取文件对象
		ntStatus = ObReferenceObjectByHandle(FileHandle, DELETE,
			*IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			LOG_DEBUG("ObReferenceObjectByHandle error!\n");
			return FALSE;
		}

		// 获取与指定文件对象相关联的设备对象
		DeviceObject = IoGetRelatedDeviceObject(fileObject);




		// 创建IRP
		Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
		if (Irp == NULL)
		{
			ObDereferenceObject(fileObject);

			LOG_DEBUG("FD_StripFileAttributes IoAllocateIrp error\n");
			return FALSE;
		}

		// 初始化同步事件对象
		KeInitializeEvent(&SycEvent, SynchronizationEvent, FALSE);

		memset(&FileInformation, 0, 0x28);
		FileInformation.FileAttributes = FILE_ATTRIBUTE_NORMAL;

		// 初始化IRP
		Irp->AssociatedIrp.SystemBuffer = &FileInformation;
		Irp->UserEvent = &SycEvent;
		Irp->UserIosb = &ioStatus;
		Irp->Tail.Overlay.OriginalFileObject = fileObject;
		Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
		Irp->RequestorMode = KernelMode;

		// 设置IRP堆栈信息
		irpSp = IoGetNextIrpStackLocation(Irp);
		irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
		irpSp->DeviceObject = DeviceObject;
		irpSp->FileObject = fileObject;
		irpSp->Parameters.SetFile.Length = sizeof(FILE_BASIC_INFORMATION);
		irpSp->Parameters.SetFile.FileInformationClass = FileBasicInformation;
		irpSp->Parameters.SetFile.FileObject = fileObject;

		// 设置完成例程
		IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

		// 派发IRP
		KeEnterCriticalRegion();
		IoCallDriver(DeviceObject, Irp);
		KeLeaveCriticalRegion();
		// 等待IRP的完成
		KeWaitForSingleObject(&SycEvent, Executive, KernelMode, TRUE, NULL);

		// 递减引用计数
		ObDereferenceObject(fileObject);

		return TRUE;
	}

	BOOLEAN FD_DeleteFile(HANDLE FileHandle)
	{
		NTSTATUS          ntStatus = STATUS_SUCCESS;
		PFILE_OBJECT      fileObject;
		PDEVICE_OBJECT    DeviceObject;
		PIRP              Irp;
		KEVENT            SycEvent;
		FILE_DISPOSITION_INFORMATION    FileInformation;
		IO_STATUS_BLOCK					ioStatus;
		PIO_STACK_LOCATION				irpSp;
		PSECTION_OBJECT_POINTERS		pSectionObjectPointer;

		// 获取文件对象
		ntStatus = ObReferenceObjectByHandle(FileHandle, DELETE,
			*IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			LOG_DEBUG("ObReferenceObjectByHandle error!\n");
			return FALSE;
		}

		// 获取与指定文件对象相关联的设备对象
		DeviceObject = IoGetRelatedDeviceObject(fileObject);

		// 创建IRP
		Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
		if (Irp == NULL)
		{
			ObDereferenceObject(fileObject);
			LOG_DEBUG("FD_DeleteFile IoAllocateIrp error\n");
			return FALSE;
		}

		// 初始化同步事件对象
		KeInitializeEvent(&SycEvent, SynchronizationEvent, FALSE);

		FileInformation.DeleteFile = TRUE;

		// 初始化IRP
		Irp->AssociatedIrp.SystemBuffer = &FileInformation;
		Irp->UserEvent = &SycEvent;
		Irp->UserIosb = &ioStatus;
		Irp->Tail.Overlay.OriginalFileObject = fileObject;
		Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
		Irp->RequestorMode = KernelMode;

		// 设置IRP堆栈
		irpSp = IoGetNextIrpStackLocation(Irp);
		irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
		irpSp->DeviceObject = DeviceObject;
		irpSp->FileObject = fileObject;
		irpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
		irpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
		irpSp->Parameters.SetFile.FileObject = fileObject;

		// 设置完成例程
		IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

		// 如果没有这3行，就无法删除正在运行的文件
		pSectionObjectPointer = fileObject->SectionObjectPointer;
		pSectionObjectPointer->ImageSectionObject = 0;
		pSectionObjectPointer->DataSectionObject = 0;

		// 派发IRP
		IoCallDriver(DeviceObject, Irp);

		// 等待IRP完成
		KeWaitForSingleObject(&SycEvent, Executive, KernelMode, TRUE, NULL);

		// 递减引用计数
		ObDereferenceObject(fileObject);

		return TRUE;
	}

	BOOLEAN	ForceDeleteFile(WCHAR szFileName[])
	{
		HANDLE		hFile = NULL;
		BOOLEAN		status = FALSE;

		__try {
			// 打开文件
			if ((hFile = FD_OpenFile(szFileName)) == NULL)
			{
				LOG_DEBUG("FD_OpenFile error!\n");
				return FALSE;
			}
			// //去掉只读属性，才能删除只读文件
			if (FD_StripFileAttributes(hFile) == FALSE)
			{
				ZwClose(hFile);
				LOG_DEBUG("FD_StripFileAttributes error!\n");
				return FALSE;
			}
			// 删除文件
			status = FD_DeleteFile(hFile);
			ZwClose(hFile);
			return status;
		}
		__except (1) {
			LOG_DEBUG("execption!\n");
		}
		return FALSE;
	}
	//static PEPROCESS g_system_process = 0;

	PVOID pRegistrationHandle = 0;

	void DriverUnload(PDRIVER_OBJECT pDriver)
	{
		//StopVirtualTechnology();
		SSDT_STOP_HOOK(HOOK_SSDT | HOOK_SSDTSHOW);
		if (pRegistrationHandle != 0)
		{
			ObUnRegisterCallbacks(pRegistrationHandle);
		}
		if (pDriver->DeviceObject)
		{

			PDEVICE_OBJECT pDev;         // 用来取得要删除设备对象
		//	UNICODE_STRING SymLinkName;  // 局部变量symLinkName
			pDev = pDriver->DeviceObject;
			IoDeleteDevice(pDev);                                       // 调用IoDeleteDevice用于删除设备
			// 初始化字符串将symLinkName定义成需要删除的符号链接名称
			IoDeleteSymbolicLink(&uszSymLinkString);


		}
		//	LOG_DEBUG("驱动已卸载\n");


	}



	VOID PostProcessHandle(
		_In_ PVOID RegistrationContext,
		_In_ POB_POST_OPERATION_INFORMATION OperationInformation
	)
	{
		UNREFERENCED_PARAMETER(RegistrationContext);
		UNREFERENCED_PARAMETER(OperationInformation);
	}


#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020  
	//extern int* ObTypeIndexTable;
	OB_PREOP_CALLBACK_STATUS PreProcessHandle(
		_In_ PVOID RegistrationContext,
		_Inout_ POB_PRE_OPERATION_INFORMATION pOperationInformation
	)
	{
		HANDLE hProcess = PsGetProcessId((PEPROCESS)pOperationInformation->Object); // 操作句柄
		if (IsOpenProcessHide(hProcess))
		{
			//LOG_DEBUG("开始过滤\n");
			if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{

				//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				int code = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				//if ((code & PROCESS_TERMINATE) == PROCESS_TERMINATE)
				//{
				//	//Terminate the process, such as by calling the user-mode TerminateProcess routine..
				//	//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;

				//	//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				//	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				//}
				//if ((code & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
				//{
				//	//Modify the address space of the process, such as by calling the user-mode WriteProcessMemory and VirtualProtectEx routines.
				//	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				//}
				//if ((code & PROCESS_VM_READ) == PROCESS_VM_READ)
				//{
				//	//Read to the address space of the process, such as by calling the user-mode ReadProcessMemory routine.
				//	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				//	//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				//}
				//if ((code & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
				//{
				//	//Write to the address space of the process, such as by calling the user-mode WriteProcessMemory routine.
				//	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				//	//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				//}
			}
			//else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			//{
			//	pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

			//}
		}
		// 区分操作类型

		return OB_PREOP_SUCCESS;
	}

















	typedef struct _DEVICE_EXTENSION {
		PDEVICE_OBJECT pDevice;
		UNICODE_STRING ustrDeviceName;	//设备名称
		UNICODE_STRING ustrSymLinkName;	//符号链接名
	} DEVICE_EXTENSION, * PDEVICE_EXTENSION;  //设备扩展信息结构体


	typedef struct _LDR_DATA_TABLE_ENTRY64
	{
		LIST_ENTRY64    InLoadOrderLinks;
		LIST_ENTRY64    InMemoryOrderLinks;
		LIST_ENTRY64    InInitializationOrderLinks;
		LIST_ENTRY64    InLoadOrderLinksA;
		LIST_ENTRY64    InMemoryOrderLinksA;
		LIST_ENTRY64    InInitializationOrderLinksA;
		PVOID            pAdr;
		ULONG            Flags;
	} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

	PVOID  CallBackHandle = NULL;
	typedef struct _OBJECT_TYPE_INITIALIZER
	{
		UINT16       Length;
		union
		{
			UINT8        ObjectTypeFlags;
			struct
			{
				UINT8        CaseInsensitive : 1;                                                                               UINT8        UnnamedObjectsOnly : 1;                                                                              UINT8        UseDefaultObject : 1;                                                                                    UINT8        SecurityRequired : 1;                                                                                    UINT8        MaintainHandleCount : 1;                                                                                 UINT8        MaintainTypeList : 1;                                                                                    UINT8        SupportsObjectCallbacks : 1;
			};
		};
		ULONG32      ObjectTypeCode;
		ULONG32      InvalidAttributes;
		struct _GENERIC_MAPPING GenericMapping;
		ULONG32      ValidAccessMask;
		ULONG32      RetainAccess;
		enum _POOL_TYPE PoolType;
		ULONG32      DefaultPagedPoolCharge;
		ULONG32      DefaultNonPagedPoolCharge;
		PVOID        DumpProcedure;
		PVOID        OpenProcedure;
		PVOID         CloseProcedure;
		PVOID         DeleteProcedure;
		PVOID         ParseProcedure;
		PVOID        SecurityProcedure;
		PVOID         QueryNameProcedure;
		PVOID         OkayToCloseProcedure;
	}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;
	typedef struct _OBJECT_TYPE_TEMP
	{
		struct _LIST_ENTRY TypeList;
		struct _UNICODE_STRING Name;
		VOID* DefaultObject;
		UINT8        Index;
		UINT8        _PADDING0_[0x3];
		ULONG32      TotalNumberOfObjects;
		ULONG32      TotalNumberOfHandles;
		ULONG32      HighWaterNumberOfObjects;
		ULONG32      HighWaterNumberOfHandles;
		UINT8        _PADDING1_[0x4];
		struct _OBJECT_TYPE_INITIALIZER TypeInfo;
		ULONG64 TypeLock;
		ULONG32      Key;
		UINT8        _PADDING2_[0x4];
		struct _LIST_ENTRY CallbackList;
	}OBJECT_TYPE_TEMP, * POBJECT_TYPE_TEMP;

	UNICODE_STRING  GetFilePathByFileObject(PVOID FileObject)
	{
		POBJECT_NAME_INFORMATION ObjetNameInfor;
		if (NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)FileObject, &ObjetNameInfor)))
		{
			return ObjetNameInfor->Name;
		}
		UNICODE_STRING str;
		RtlInitUnicodeString(&str, L"");
		return str;
	}

	OB_PREOP_CALLBACK_STATUS PreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
	{
		UNICODE_STRING uniDosName;
		UNICODE_STRING uniFilePath;
		PFILE_OBJECT FileObject = (PFILE_OBJECT)OperationInformation->Object;
		HANDLE CurrentProcessId = PsGetCurrentProcessId();
		if (OperationInformation->ObjectType != *IoFileObjectType)
		{
			return OB_PREOP_SUCCESS;
		}
		//过滤无效指针
		if (FileObject->FileName.Buffer == NULL ||
			!MmIsAddressValid(FileObject->FileName.Buffer) ||
			FileObject->DeviceObject == NULL ||
			!MmIsAddressValid(FileObject->DeviceObject))
		{
			return OB_PREOP_SUCCESS;
		}
		uniFilePath = GetFilePathByFileObject(FileObject);
		if (uniFilePath.Buffer == NULL || uniFilePath.Length == 0)
		{
			return OB_PREOP_SUCCESS;
		}

		//HANDLE hProcess = PsGetProcessId((PEPROCESS)OperationInformation->Object);
		//LOG_DEBUG("1:PID : %ld  File : %wZ\n", (ULONG64)CurrentProcessId, &uniFilePath);
		//if (IsFileAcess(PsGetCurrentProcessId(), &uniFilePath))
		//{
		//	LOG_DEBUG("Access d %d w %d r %d\n", FileObject->DeleteAccess, FileObject->WriteAccess, FileObject->ReadAccess);

		//	if (FileObject->DeleteAccess == TRUE ||
		//		FileObject->WriteAccess == TRUE ||
		//		FileObject->ReadAccess == TRUE)
		//	{
		//		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		//		{
		//			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
		//		}
		//		if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		//		{
		//			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
		//		}
		//	}
		//	LOG_DEBUG("2:PID : %ld  File : %wZ\n", (ULONG64)CurrentProcessId, &uniFilePath);
		//}
		//else
		//{
		//	LOG_DEBUG("4:PID : %ld  File:  %wZ\n", (ULONG64)CurrentProcessId, &uniFilePath);
		//}
		return OB_PREOP_SUCCESS;



	


	}



	VOID EnableObType(POBJECT_TYPE ObjectType)
	{
		POBJECT_TYPE_TEMP  ObjectTypeTemp = (POBJECT_TYPE_TEMP)ObjectType;
		ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;
	}


	NTSTATUS ProtectFileByObRegisterCallbacks()
	{
		OB_CALLBACK_REGISTRATION  CallBackReg;
		OB_OPERATION_REGISTRATION OperationReg;
		NTSTATUS  Status;

		EnableObType(*IoFileObjectType);      //开启文件对象回调

		memset(&CallBackReg, 0, sizeof(OB_CALLBACK_REGISTRATION));
		CallBackReg.Version = ObGetFilterVersion();
		CallBackReg.OperationRegistrationCount = 1;
		CallBackReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&CallBackReg.Altitude, L"370030");
		memset(&OperationReg, 0, sizeof(OB_OPERATION_REGISTRATION)); //初始化结构体变量


		OperationReg.ObjectType = IoFileObjectType;
		OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

		OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PreCallBack; //在这里注册一个回调函数指针
		CallBackReg.OperationRegistration = &OperationReg; //注意这一条语句   将结构体信息放入大结构体
		Status = ObRegisterCallbacks(&CallBackReg, &CallBackHandle);
		if (!NT_SUCCESS(Status))
		{
			Status = STATUS_UNSUCCESSFUL;
			KdPrint(("Protect File Error!!!"));
		}
		else
		{
			KdPrint(("Protect File Success!!!"));
			Status = STATUS_SUCCESS;
		}
		return Status;
	}



	PVOID  DriverCallBackHandle = NULL;

	OB_PREOP_CALLBACK_STATUS DriverCreateCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);




	NTSTATUS DriverObjectCreateByObRegisterCallbacks()
	{
		OB_CALLBACK_REGISTRATION  CallBackReg;
		OB_OPERATION_REGISTRATION OperationReg;
		NTSTATUS  Status;

		EnableObType(*IoDriverObjectType);      //开启文件对象回调

		memset(&CallBackReg, 0, sizeof(OB_CALLBACK_REGISTRATION));
		CallBackReg.Version = ObGetFilterVersion();
		CallBackReg.OperationRegistrationCount = 1;
		CallBackReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&CallBackReg.Altitude, L"370030");
		memset(&OperationReg, 0, sizeof(OB_OPERATION_REGISTRATION)); //初始化结构体变量


		OperationReg.ObjectType = IoDriverObjectType;
		OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

		OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&DriverCreateCallBack; //在这里注册一个回调函数指针
		CallBackReg.OperationRegistration = &OperationReg; //注意这一条语句   将结构体信息放入大结构体
		Status = ObRegisterCallbacks(&CallBackReg, &DriverCallBackHandle);
		if (!NT_SUCCESS(Status))
		{
			LOG_DEBUG("ObRegisterCallbacks Driver Error!!!  %08X",Status);
			Status = STATUS_UNSUCCESSFUL;
		}
		else
		{
			LOG_DEBUG("ObRegisterCallbacks Driver Success!!! %08X",Status);
			Status = STATUS_SUCCESS;
		}
		return Status;
	}





	//extern h_IOSysBuffer pIOgIZ;




	extern BOOL Start_Hook_Http();

	extern PDEVICE_OBJECT  gDevObj;

	//extern VOID _CREATE_THREAD_NOTIFY_ROUTINE(
	//	IN HANDLE  ProcessId,
	//	IN HANDLE  ThreadId,
	//	IN BOOLEAN  Create
	//);


	extern void RemoveThreadSingle(HANDLE hProcess, HANDLE hThread);


	AVL_INFO TableAvl_UCHAR_NAME;
	//RTL_AVL_TABLE TableAvl_PID;


	typedef  struct _LIST_PID {
		LIST_ENTRY Link;
		HANDLE dwPID;
		KEVENT Notify;
		BOOLEAN Run;
	}LIST_PID, * PLIST_PID;


	typedef  struct _TABLE_STRING_FILTER {
		DWORD64 LockSelf;
		ANSI_STRING stringSrc;
		ANSI_STRING stringReplace;
		KSPIN_LOCK  Lock;
		LIST_ENTRY Link;
	}TABLE_STRING_FILTER, * PTABLE_STRING_FILTER;


#define TABLE_ADD 0
#define TABLE_DEL 1
#define TABLE_FIND 2
#define TABLE_GET 3


	PVOID changeTableLIST(PTABLE_STRING_FILTER fTable, DWORD Type, LIST_PID* Link)
	{
		PVOID r = 0;
		//KeAcquireSpinLockAtDpcLevel(&fTable->Lock);


		KIRQL IRQL;
		KeAcquireSpinLock(&fTable->Lock, &IRQL);
		if (Type == TABLE_ADD) {
			InsertTailList(&fTable->Link, &Link->Link);
			r = Link;
		}
		else if (Type == TABLE_DEL) {
			PLIST_ENTRY pHead = &fTable->Link;
			PLIST_ENTRY nEntry = pHead->Flink;
			while (nEntry != pHead) {
				LIST_PID* pVl = (LIST_PID*)nEntry;
				if (pVl->dwPID == Link->dwPID) {
					RemoveEntryList(nEntry);
					//ExFreePoolWithTag(nEntry, 'tag');
					r = nEntry;
				}
				nEntry = nEntry->Flink;
			}
		}
		else if (Type == TABLE_FIND) {

			PLIST_ENTRY pHead = &fTable->Link;
			PLIST_ENTRY nEntry = pHead->Flink;
			while (nEntry != pHead) {
				LIST_PID* pVl = (LIST_PID*)nEntry;
				if (pVl->dwPID == Link->dwPID) {
					r = nEntry;
				}
				nEntry = nEntry->Flink;
			}
		}
		else if (Type == TABLE_GET) {

			PLIST_ENTRY pHead = &fTable->Link;
			PLIST_ENTRY nEntry = pHead->Flink;
			if (nEntry != pHead) {
				r = nEntry;
			}
		}
		//KeReleaseSpinLockFromDpcLevel(&fTable->Lock);
		KeReleaseSpinLock(&fTable->Lock, IRQL);
		return r;
	}
	_Function_class_(RTL_AVL_COMPARE_ROUTINE)
		RTL_GENERIC_COMPARE_RESULTS CompareHandleTableEntryAnsiString(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
	{
		PTABLE_STRING_FILTER Left = (PTABLE_STRING_FILTER)FirstStruct;
		PTABLE_STRING_FILTER Right = (PTABLE_STRING_FILTER)SecondStruct;
		UNREFERENCED_PARAMETER(Table);


		//KIRQL IRQL = 0;
		//KeRaiseIrql(PASSIVE_LEVEL, &IRQL);

		//LONG r = RtlCompareString(&Left->stringSrc, &Right->stringSrc, TRUE);


		//KeLowerIrql(IRQL);

		KIRQL IRQL = KeGetCurrentIrql();
		__writecr8(PASSIVE_LEVEL);
		LONG r = -1;
		__try
		{
			r = RtlCompareString(&Left->stringSrc, &Right->stringSrc, TRUE);
		}
		__except (1) {

		}
		__writecr8(IRQL);


		//LOG_DEBUG("[%d]<%Z><%Z>\n", r, &Left->stringSrc, &Right->stringSrc);
		if (r > 0)
			return GenericGreaterThan;
		if (r < 0)
			return GenericLessThan;
		return GenericEqual;
	}

	_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
		PVOID AllocateHandleTableEntryAnsiString(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
	{
		UNREFERENCED_PARAMETER(Table);
		PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
		if (buffer != 0)
		{
			RtlZeroMemory(buffer, ByteSize);
		}
		return buffer;
	}

	_Function_class_(RTL_AVL_FREE_ROUTINE)
		VOID FreeHandleTableEntryAnsiString(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
	{
		UNREFERENCED_PARAMETER(Table);
		ExFreePoolWithTag(Buffer, 'tag');
	}



	BOOLEAN wAddStringAvl(TABLE_STRING_FILTER* TableInfo) {
		return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_ADD, &TableAvl_UCHAR_NAME, TableInfo, sizeof(TABLE_STRING_FILTER));
	}

	BOOLEAN wfindStringAvl(TABLE_STRING_FILTER* TableInfo) {

		return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_GET, &TableAvl_UCHAR_NAME, TableInfo, sizeof(TABLE_STRING_FILTER));
	}

	TABLE_STRING_FILTER* wGetStringAvl(TABLE_STRING_FILTER* TableInfo) {
		return (TABLE_STRING_FILTER*)AVL_LOCK_CHANGE_VOID(AVL_GET, &TableAvl_UCHAR_NAME, TableInfo, sizeof(TABLE_STRING_FILTER));
	}


	BOOLEAN wRemoveStringAvl(TABLE_STRING_FILTER* TableInfo) {
		return (BOOLEAN)AVL_LOCK_CHANGE_VOID(AVL_DEL, &TableAvl_UCHAR_NAME, TableInfo, sizeof(TABLE_STRING_FILTER));
	}


	//--------------------------------------------------------------------------------------------------------------------



	BOOLEAN FilterAnsiString(ANSI_STRING* FilterName, ANSI_STRING* PathName) {

		//IoCreateFile()
		TABLE_STRING_FILTER sFilter = { 0 };
		//RtlCopyMemory(&sFilter.stringSrc, FilterName, sizeof(ANSI_STRING));
		//RtlCopyMemory(&sFilter.stringReplace, PathName, sizeof(ANSI_STRING));
		RtlInitString(&sFilter.stringSrc, "steam.exe");

		TABLE_STRING_FILTER* pTable = wGetStringAvl(&sFilter);
		if (pTable == 0)
		{
			BOOLEAN r = wAddStringAvl(&sFilter);
			pTable = wGetStringAvl(&sFilter);
			LOG_DEBUG("[%d]<%p>\n", __LINE__, pTable);
			if (pTable == 0)
			{
				return FALSE;
			}
			InitializeListHead(&pTable->Link);
			KeInitializeSpinLock(&pTable->Lock);
		}
		//LOG_DEBUG("%Z\n", &sFilter.stringSrc);
		//return TRUE;
		return TRUE;
	}




	//_Function_class_(RTL_AVL_COMPARE_ROUTINE)
	//RTL_GENERIC_COMPARE_RESULTS CompareProcessId(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
	//{
	//	PTABLE_STRING_FILTER Left = (PTABLE_STRING_FILTER)FirstStruct;
	//	PTABLE_STRING_FILTER Right = (PTABLE_STRING_FILTER)SecondStruct;
	//	UNREFERENCED_PARAMETER(Table);
	//	LONG r = RtlCompareString(&Left->stringSrc, &Right->stringSrc, TRUE);
	//	if (r > 0)
	//		return GenericGreaterThan;
	//	if (r < 0)
	//		return GenericLessThan;
	//	return GenericEqual;
	//}
	//
	//_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
	//PVOID AllocateProcessId(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
	//{
	//	UNREFERENCED_PARAMETER(Table);
	//	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
	//	if (buffer != 0)
	//	{
	//		RtlZeroMemory(buffer, ByteSize);
	//	}
	//	return buffer;
	//}
	//
	//_Function_class_(RTL_AVL_FREE_ROUTINE)
	//VOID FreeProcrssId(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
	//{
	//	UNREFERENCED_PARAMETER(Table);
	//	ExFreePoolWithTag(Buffer, 'tag');
	//}

	//--------------------------------------------------------------------------------------------



	BOOLEAN  AddTable(TABLE_STRING_FILTER* pFilter, HANDLE dwPID) {

		PLIST_PID K = (PLIST_PID)ExAllocatePoolWithTag(NonPagedPool, sizeof(LIST_PID), 'tag');
		if (K == NULL)
		{
			return FALSE;
		}
		RtlZeroMemory(K, sizeof(LIST_PID));
		KeInitializeEvent(&K->Notify, SynchronizationEvent, FALSE);
		K->dwPID = dwPID;
		PLIST_PID pTable = (PLIST_PID)changeTableLIST(pFilter, TABLE_ADD, K);
		if (pTable == 0)
		{
			return FALSE;
		}
		KeWaitForSingleObject(&K->Notify, Executive, KernelMode, FALSE, NULL);
		ExFreePoolWithTag(pTable, 'tag');
		return TRUE;

	}

	BOOLEAN DelTable(TABLE_STRING_FILTER* pFilter, HANDLE dwPID) {

		LIST_PID lPID = { 0 };
		lPID.dwPID = dwPID;
		PLIST_PID pTable = (PLIST_PID)changeTableLIST(pFilter, TABLE_DEL, &lPID);
		if (pTable != 0)
		{
			KeSetEvent(&pTable->Notify, LOW_PRIORITY, FALSE);
			if (&pFilter->Link == pFilter->Link.Flink)
			{
				AVL_LOCK_CHANGE_VOID(AVL_UNLOCK, &TableAvl_UCHAR_NAME, pFilter, sizeof(TABLE_STRING_FILTER));
			}
		}
		//ExFreePoolWithTag(pTable, 'tag'); //  内存已经泄露

		LOG_DEBUG("down steam.exe\n");
		if (pTable == 0)
		{
			return FALSE;
		}
		return TRUE;
	}



	HANDLE  findTablePID(TABLE_STRING_FILTER* pFilter) {
		PLIST_PID pTable = (PLIST_PID)changeTableLIST(pFilter, TABLE_GET, NULL);
		if (pTable != 0) {
			return pTable->dwPID;
		}
		return 0;
	}





	LONG ThreadStartRoutineOffsetBegin = 0;

	VOID FindSystemThreadRoutineStart(
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
			LONG t_ThreadStartRoutineOffsetBegin = 0;
			for (t_ThreadStartRoutineOffsetBegin = 0; t_ThreadStartRoutineOffsetBegin < 0x1000; t_ThreadStartRoutineOffsetBegin += 8)
			{
				if (*(PVOID**)(CurrentThread + t_ThreadStartRoutineOffsetBegin) == (PVOID)FindSystemThreadRoutineStart) {
					ThreadStartRoutineOffsetBegin = t_ThreadStartRoutineOffsetBegin;
					break;
				}
				
			}
			LOG_DEBUG("Thread start routine offset is 0x%.4x.\n", ThreadStartRoutineOffsetBegin);
		} while (0);

	}




	VOID _CREATE_THREAD_NOTIFY_ROUTINE2(
		IN HANDLE  ProcessId,
		IN HANDLE  ThreadId,
		IN BOOLEAN  Create
	) {
		//TABLE_HANDLE_INFO nTable = { 0 };
		//nTable.hID = ProcessId;
		if (Create) {


			if (ProcessId == (HANDLE)4)
			{
				//sizeof(KTIMER) + sizeof(KEVENT) + sizeof(KDPC)
				LOG_DEBUG("Create SystemID thread %d  processid %d \n", ThreadId, ProcessId);


				if (ThreadStartRoutineOffsetBegin != 0)
				{
					PETHREAD ethread = 0;
					if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &ethread)))
					{

						PVOID StartRoutine = *(PVOID**)((DWORD64)ethread + ThreadStartRoutineOffsetBegin);
						LOG_DEBUG("Create SystemID thread %d  startRoutine <%p> \n", ThreadId, StartRoutine);

						ObDereferenceObject(ethread);
					}
				}


				





			}
			
			//if (wfindEntryProcessAvl(&nTable))
			//{
			//	LOG_DEBUG("Remove New thread %d  processid %d \n", ThreadId, ProcessId);
			//	RemoveThreadSingle(ProcessId, ThreadId);
			//}
			//return;
		}
		else
		{
			//if (wfindEntryProcessAvl(&nTable))
			//{
			//	LOG_DEBUG(" thread Must Recovery  %d  processid %d \n", ThreadId, ProcessId);
			//	//RemoveThreadSingle(ProcessId, ThreadId);

			//	wRecoveryidTableThread(ProcessId, ThreadId);
			//}
		}
	}


	NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS pProcessObject);
	NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS pProcessObject);


	DWORD dwPIDsteam = 0;

	extern BOOLEAN wAddMetuxAvl_0(PTABLE_HANDLE_INFO TalbeAvl);





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


	void PcreateProcessNotifyRoutine2(
		HANDLE ParentId,
		HANDLE ProcessId,
		BOOLEAN Create
	)
	{


		__try
		{
			if (Create)
			{
				K_SANDBOX* pSandBoxSession = SandBoxLockSession(ParentId);
				if (pSandBoxSession != NULL) {
					// 查看父进程是否有会话
					UNICODE_STRING ProcessFullName;
					if (NT_SUCCESS(GetPathByProcessId(ProcessId, &ProcessFullName))) {

						UNICODE_STRING ROOT_SYSTEM;
						RtlInitUnicodeString(&ROOT_SYSTEM, L"*\\SYSTEM32\\*");
						if (!FsRtlIsNameInExpression(&ROOT_SYSTEM, &ProcessFullName, TRUE, FALSE))
						{
							LOG_DEBUG("Parent  %wZ %d \n", &ProcessFullName, ProcessId);
							SandBoxCreateSession(ProcessId, SandBoxDirectory, pSandBoxSession->SessionNumber);
							//SandBoxUnLockSession(ProcessId);
						}
						RtlFreeUnicodeString(&ProcessFullName);
					}
					return;
				}
				UNICODE_STRING ProcessFullName;
				if (NT_SUCCESS(GetPathByProcessId(ProcessId, &ProcessFullName))) {
					//	LOG_DEBUG("ProcessFullName:0 %wZ   %d  %d\n", &ProcessFullName, ProcessId, ParentId);
						//LOG_DEBUG("ProcessFullName:1%wZ\n", &ImageForSandBox);
					if (RtlEqualUnicodeString(&ProcessFullName, &ImageForSandBox, TRUE)) {
						//必须要创建一个新的会话

						//STATUS_ABANDONED

						LOG_DEBUG("New  %wZ %d  curID:%d\n", &ProcessFullName, ProcessId, PsGetCurrentProcessId());
						SandBoxCreateSession(ProcessId, SandBoxDirectory, -1);
					}
					RtlFreeUnicodeString(&ProcessFullName);
				}
			}
			else
			{
				K_SANDBOX* pSandBoxSession = SandBoxLockSession(ProcessId);
				if (pSandBoxSession != NULL) {
					SandBoxUnLockSession(ProcessId);
					SandBoxRemoveSession(ProcessId);
				}

				// 恢复
				TABLE_HANDLE_INFO HIDE_Info = { 0 };
				HIDE_Info.hID = ProcessId;
				PTABLE_HANDLE_INFO pTableProcess = wGetEntryProcessAvl(&HIDE_Info);
				if (pTableProcess != 0)
				{
					wRecoveryidTableProcess(ProcessId);
				}
			}
		}
		__except (1) {
			LOG_DEBUG("run %s  %08X   %d\n", __FUNCTION__, GetExceptionCode(), __LINE__);
		}

	}





	void PcreateProcessNotifyRoutine_FilterProcess(
		HANDLE ParentId,
		HANDLE ProcessId,
		BOOLEAN Create
	)
	{


		__try
		{
			if (Create)
			{
				PEPROCESS eprocess = 0;
				NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &eprocess);
				if (NT_SUCCESS(status)){
					UCHAR* pName = PsGetProcessImageFileName(eprocess);
					char ProcessName[16] = { 0 };
					RtlCopyMemory(ProcessName, pName, 15);
					TABLE_STRING_FILTER sFilter = {0};
					RtlInitAnsiString(&sFilter.stringSrc, ProcessName);
					PTABLE_STRING_FILTER pFilter = wGetStringAvl(&sFilter);
					if (pFilter != 0){
						//LOG_DEBUG()
							AddTable(pFilter, ProcessId);
					}
				}

			}
		}
		__except (1) {
			LOG_DEBUG("run %s  %08X   %d\n", __FUNCTION__, GetExceptionCode(), __LINE__);
		}

	}



	
	
	LONG FindMemoryPos(char* pA, int Alen, char* pB, int Blen) {

		__try
		{
			if (Alen < Blen) {
				return -1;
			}
			for (int i = 0; i < ((Alen - Blen) + 1); i++)
			{
				if (RtlEqualMemory(pA + i, pB, Blen))
				{
					return i;
				}
			}
		}
		__except (1) {

			LOG_DEBUG("FindMemoryPos except %08X\n", GetExceptionCode());

		}
		return -1;
	}
	extern BOOLEAN FindMemory(char* pA, int Alen, char* pB, int Blen);



	LONG RtlFindUnicodeString(PUNICODE_STRING src, PUNICODE_STRING dec) {

		return FindMemoryPos((char *)src->Buffer, src->Length, (char *)dec->Buffer, dec->Length);
	}
	//LONG RtlRFindUnicodeString(PUNICODE_STRING src, PUNICODE_STRING dec) {
	//	if (dec->Length > src->Length)
	//		return -1;
	//	SIZE_T WcharSize = (src->Length - dec->Length) / 2;
	//	for (size_t i = 0; i < (WcharSize + 1); i++)
	//	{
	//		if (RtlCompareUnicodeStrings(src->Buffer + WcharSize - i, dec->Length, src->Buffer, dec->Length,TRUE) == 0)
	//		{
	//			return (WcharSize - i);
	//		}
	//	}
	//	return -1;
	//}

	extern 	ULONGLONG KF_ObCreateObject;

	extern BOOLEAN  CreateObjectDirectoryObject(DWORD64 uSessionNumber);


	extern BOOLEAN GetDriverObjectByName(PDRIVER_OBJECT* DriverObject, WCHAR* DriverName);

	extern BOOLEAN UNLoadProcess();

	extern BOOLEAN IniHideProcess();




	HOOK_DRIVER_DISPATH  EAC_HOOK;

	//NTSTATUS EACDispatchCtl(PDEVICE_OBJECT pDevObj, PIRP pIrp) {

	//	PIO_STACK_LOCATION IrpSp = NULL;
	//	IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	//	ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	//	LOG_DEBUG("IoControlCode %s  %08X\n", __FUNCTION__, IoControlCode);


	//	//wSleepNs(1000);
	//	//LOG_DEBUG("end");
	//	NTSTATUS r = STATUS_SUCCESS;
	//	if (EAC_HOOK.OLD_DISPATH_CTL != 0){
	//		UNLoadProcess();
	//		r = EAC_HOOK.OLD_DISPATH_CTL(pDevObj, pIrp);
	//		IniHideProcess();
	//	}
	//	return r;
	//}


	NTSTATUS EACDispatchCtl(PDEVICE_OBJECT pDevObj, PIRP pIrp) {

		PIO_STACK_LOCATION IrpSp = NULL;
		IrpSp = IoGetCurrentIrpStackLocation(pIrp);
		ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
		LOG_DEBUG("IoControlCode %s  %08X\n", __FUNCTION__, IoControlCode);
		NTSTATUS r = STATUS_SUCCESS;
		
		
		//UNLoadProcess();


		r = EAC_HOOK.MajorFunction[IrpSp->MajorFunction](pDevObj, pIrp);
		
		
		//IniHideProcess();

		return r;
	}



	//NTSTATUS EACDispatchCREATE(PDEVICE_OBJECT pDevObj, PIRP pIrp) {


	//	PIO_STACK_LOCATION IrpSp = NULL;
	//	IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	//	ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	//	LOG_DEBUG("IoControlCode %s  %08X\n", __FUNCTION__, IoControlCode);

	//	NTSTATUS r = STATUS_SUCCESS;
	//	if (EAC_HOOK.OLD_DISPATH_CREATE != 0) {
	//		UNLoadProcess();
	//		r = EAC_HOOK.OLD_DISPATH_CREATE(pDevObj, pIrp);
	//		IniHideProcess();
	//	}

	//	return r;
	//}
	//NTSTATUS EACDispatchCLOSE(PDEVICE_OBJECT pDevObj, PIRP pIrp) {

	//	PIO_STACK_LOCATION IrpSp = NULL;
	//	IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	//	ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	//	LOG_DEBUG("IoControlCode %s  %08X\n", __FUNCTION__, IoControlCode);

	//	//wSleepNs(1000);
	//	//LOG_DEBUG("end");
	//	NTSTATUS r = STATUS_SUCCESS;
	//	if (EAC_HOOK.OLD_DISPATH_CLOSE != 0) {
	//		UNLoadProcess();
	//		r = EAC_HOOK.OLD_DISPATH_CLOSE(pDevObj, pIrp);
	//		IniHideProcess();
	//	}
	//	return r;
	//}
	//NTSTATUS EACDispatchREAD(PDEVICE_OBJECT pDevObj, PIRP pIrp) {

	//	//LOG_DEBUG("EACDispatch\n");

	//	PIO_STACK_LOCATION IrpSp = NULL;
	//	IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	//	ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	//	LOG_DEBUG("IoControlCode %s  %08X\n", __FUNCTION__, IoControlCode);


	//	//wSleepNs(1000);
	//	//LOG_DEBUG("end");
	//	NTSTATUS r = STATUS_SUCCESS;
	//	if (EAC_HOOK.OLD_DISPATH_READ != 0) {
	//		UNLoadProcess();
	//		r = EAC_HOOK.OLD_DISPATH_READ(pDevObj, pIrp);
	//		IniHideProcess();
	//	}
	//	return r;

	//}
	//NTSTATUS EACDispatchWRITE(PDEVICE_OBJECT pDevObj, PIRP pIrp) {

	//	//LOG_DEBUG("EACDispatch\n");

	//	PIO_STACK_LOCATION IrpSp = NULL;
	//	IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	//	ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	//	LOG_DEBUG("IoControlCode %s  %08X\n", __FUNCTION__, IoControlCode);

	//	//wSleepNs(1000);
	//	//LOG_DEBUG("end");

	//	NTSTATUS r = STATUS_SUCCESS;
	//	if (EAC_HOOK.OLD_DISPATH_WRITE != 0) {
	//		UNLoadProcess();
	//		r = EAC_HOOK.OLD_DISPATH_WRITE(pDevObj, pIrp);
	//		IniHideProcess();
	//	}
	//	return r;
	//}



	extern PDRIVER_OBJECT FindDrvs(PUNICODE_STRING pBaseName);

	void  CheckEacLoader(void* NoThing) {


		UNICODE_STRING EacDriverBaseName;
		RtlInitUnicodeString(&EacDriverBaseName, L"EasyAntiCheat.sys");
		PDRIVER_OBJECT EacDriverObject  = FindDrvs(&EacDriverBaseName);

	//	PDRIVER_OBJECT EacDriverObject = NULL;
		//if (!GetDriverObjectByName(&EacDriverObject, L"\\Driver\\EasyAntiCheat")) {
		//	LOG_DEBUG("Find EAC Object  Fail...");
		//	return 0;
		//}




		if (EacDriverObject != 0/*GetDriverObjectByName(&EacDriverObject, L"\\Driver\\EasyAntiCheat")*/) {

			LOG_DEBUG("Find EAC Object");
			//DbgPrint("find object");
			if (EAC_HOOK.pDevObj == EacDriverObject) {
				return;
			}


			//IoGetRelatedDeviceObject()

			//STATUS_ABANDONED_WAIT_0

		//	RtlFailFast(FAST_FAIL_CORRUPT_LIST_ENTRY);

			//RtlZeroMemory(&EAC_HOOK, sizeof(EAC_HOOK));
			//EAC_HOOK.DISPATH_CLOSE = EACDispatchCLOSE;
			//EAC_HOOK.DISPATH_CTL = EACDispatchCtl;
			//EAC_HOOK.DISPATH_READ = EACDispatchREAD;
			//EAC_HOOK.DISPATH_WRITE = EACDispatchWRITE;
			//EAC_HOOK.DISPATH_CREATE = EACDispatchCREATE;

			//START_HOOK_DRIVER(EacDriverObject, &EAC_HOOK);
			//ObDereferenceObject(EacDriverObject);
		}
		else
		{
			//RtlFailFast(FAST_FAIL_INCORRECT_STACK);
		};
		//IniHideProcess();
	}



	ULONGLONG EAC_ImageBase = 0;
	ULONGLONG EAC_ImageSize = 0;

 	extern BOOLEAN IniHideProcess();

	extern void server_IniHide(void* nothing);

	extern DWORD PathGuardNumber;

	extern VOID wSleep(LONG msec);



	extern DWORD* KiBugCheckActive;
	extern DWORD KiBugCheckActiveFlags;

	extern DWORD  DebugNumber;

	VOID PLOAD_IMAGE_NOTIFY_ROUTINE_SANDBOX(
		__in PUNICODE_STRING FullImageName,
		__in HANDLE ProcessId,                // pid into which image is being mapped
		__in PIMAGE_INFO ImageInfo
	) 
	{
		__try {


			if (ProcessId)
			{
				//K_SANDBOX* pSandBoxSession = SandBoxLockSession(ProcessId);
				//if (pSandBoxSession != NULL) {
				//	// 查看父进程是否有会话
				//	//PHYSICAL_ADDRESS phy = MmGetPhysicalAddress(KF_ObCreateObject);
				//	//LOG_DEBUG("LoadImage %wZ  <%p>\n", FullImageName, phy.QuadPart);
				//	if (pSandBoxSession->hObjectDirectory == 0)
				//	{
				//		UNICODE_STRING uString;
				//		RtlInitUnicodeString(&uString, L"*NTDLL.DLL");
				//		if (FsRtlIsNameInExpression(&uString, FullImageName, TRUE, NULL))
				//		{
				//			CreateObjectDirectoryObject(pSandBoxSession);
				//		}
				//	}
				//	SandBoxUnLockSession(ProcessId);
				//}
				// NewWorld

				if (FullImageName != 0 &&  MmIsAddressValid(FullImageName))
				{
					if (FullImageName->Buffer != 0  && FullImageName->Length < MAX_PATH)
					{

						wchar_t wBuffer[MAX_PATH] = { 0 };
						RtlCopyMemory(wBuffer, FullImageName->Buffer, FullImageName->Length);

						if (wcsstr(wBuffer, L"NewWorld.exe") != 0) {

							//EAC_ImageBase = 0;
							//EAC_ImageSize = 0;

							//UNLoadProcess();

							HANDLE thread_handle;
							NTSTATUS r = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_IniHide, NULL);

						}
						if (wcsstr(wBuffer, L"NewWorldLauncher.exe") != 0) {

							//EAC_ImageBase = 0;
							//EAC_ImageSize = 0;
							
							if (EAC_ImageBase != 0)
							{
								UNLoadProcess();
							}

							//HANDLE thread_handle;
							//NTSTATUS r = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_IniHide, NULL);

						}

					}
				}
				//STATUS_ABANDONED
			}
			else
			{
				if (FullImageName != 0  && MmIsAddressValid(FullImageName))
				{
					if (FullImageName->Buffer != 0 && FullImageName->Length < MAX_PATH)
					{
						wchar_t str[MAX_PATH] = {0};
						wcsncpy(str, FullImageName->Buffer, FullImageName->Length / 2);
						//str[FullImageName->Length / 2] = 0;

						if (wcsstr(str, L"EasyAntiCheat") != 0)
						{

							EAC_ImageBase = (ULONGLONG)ImageInfo->ImageBase;
							EAC_ImageSize = ImageInfo->ImageSize;

							EAC_HOOK.pDevObj = 0;


							//while (DebugNumber == 0){
							//	wSleepNs(10);
							//}

							UNLoadProcess();

							//HANDLE thread_handle;
							//NTSTATUS r = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_IniHide, NULL);

						}

					}
				}
			}

		}
		__except (1) {





		}


	}


	VOID PUNLOAD_IMAGE_NOTIFY_ROUTINE_SANDBOX(
		__in PUNICODE_STRING FullImageName,
		__in HANDLE ProcessId,                // pid into which image is being mapped
		__in PIMAGE_INFO ImageInfo
	)
	{

		if (ProcessId)
		{
			if (FullImageName != 0 && MmIsAddressValid(FullImageName))
			{
				if (FullImageName->Buffer != 0 && FullImageName->Length < MAX_PATH)
				{

					wchar_t wBuffer[MAX_PATH] = { 0 };
					RtlCopyMemory(wBuffer, FullImageName->Buffer, FullImageName->Length);

					if (wcsstr(wBuffer, L"NewWorld.exe") != 0) {

						EAC_ImageBase = 0;
						EAC_ImageSize = 0;
						UNLoadProcess();
					}
				}
			}
		}
		else
		{
			if (FullImageName != 0 && MmIsAddressValid(FullImageName))
			{
				if (FullImageName->Buffer != 0 && FullImageName->Length < MAX_PATH)
				{
					wchar_t str[MAX_PATH] = { 0 };
					wcsncpy(str, FullImageName->Buffer, FullImageName->Length / 2);
					if (wcsstr(str, L"EasyAntiCheat") != 0)
					{
						EAC_ImageBase = (ULONGLONG)ImageInfo->ImageBase;
						EAC_ImageSize = ImageInfo->ImageSize;
						EAC_HOOK.pDevObj = 0;
						UNLoadProcess();

					}
				}
			}
		}
	}

	extern AVL_INFO  TableAvl_MEYUX_1;



	extern RTL_GENERIC_COMPARE_RESULTS CompareHandleTableEntry_1(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct);

	extern PVOID AllocateHandleTableEntry_1(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize);


	extern VOID FreeHandleTableEntry_1(struct _RTL_AVL_TABLE* Table, PVOID  Buffer);



	NTSTATUS IniRegisterCallbacks(PDRIVER_OBJECT  Driver) {

		OB_OPERATION_REGISTRATION obr;
		obr.ObjectType = PsProcessType;
		obr.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE; // 创建和复制
		obr.PreOperation = PreProcessHandle;
		obr.PostOperation = PostProcessHandle;

		OB_CALLBACK_REGISTRATION ocr;
		ocr.Version = OB_FLT_REGISTRATION_VERSION; // 版本
		ocr.RegistrationContext = NULL; // 自定义数据
		ocr.OperationRegistrationCount = 1; // 回调函数个数
		ocr.OperationRegistration = &obr;
		RtlInitUnicodeString(&ocr.Altitude, L"321000"); // 加载顺序

		pRegistrationHandle = NULL;

		PLDR_DATA_TABLE_ENTRY64 ldrDataTable;
		ldrDataTable = (PLDR_DATA_TABLE_ENTRY64)Driver->DriverSection;
		//LOG_DEBUG("驱动已加载 <%p> %08X\n", ldrDataTable->Flags, rStatus);
		ULONG Flags = ldrDataTable->Flags;
		ldrDataTable->Flags |= 0x20;
		NTSTATUS rStatus = ObRegisterCallbacks(&ocr, &pRegistrationHandle);
		ldrDataTable->Flags = Flags;
		return rStatus;

	}

	 
	extern void Kenerl_WriteFile(wchar_t* FileUnicodeStr, UNICODE_STRING * Log);

	BOOLEAN IniRegistryPath(PUNICODE_STRING RegistryPath) {

		HANDLE reg = 0;
		NTSTATUS Status = STATUS_SUCCESS;
		PVOID           BufDriverString = NULL, BufProcessEventString = NULL, BufThreadEventString = NULL;
		OBJECT_ATTRIBUTES oa = { 0 };
		InitializeObjectAttributes(&oa, RegistryPath, OBJ_KERNEL_HANDLE, NULL, NULL);
		NTSTATUS ntStatus = ZwOpenKey(&reg, KEY_QUERY_VALUE, &oa);
		if (ntStatus == STATUS_SUCCESS)
		{
			UNICODE_STRING A, B, C, D;
			PKEY_VALUE_PARTIAL_INFORMATION bufA, bufB, bufC, bufD;
			ULONG ActualSize;

			BufDriverString = ExAllocatePoolWithTag(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, 'tag');

			bufA = (PKEY_VALUE_PARTIAL_INFORMATION)BufDriverString;
			RtlInitUnicodeString(&A, L"DisplayName");
			if (ntStatus == STATUS_SUCCESS) {
				ntStatus = ZwQueryValueKey(reg, &A, KeyValuePartialInformation, bufA, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, &ActualSize);
				if (ntStatus != STATUS_SUCCESS) {
					ExFreePoolWithTag(bufA, 'tag');
				}
			}
			if (ntStatus == STATUS_SUCCESS) {
				RtlInitUnicodeString(&uszDriverString, (PCWSTR)bufA->Data);
			}
			LOG_DEBUG("uszDriverString: %wZ \n", &uszDriverString);
			
//#ifndef RELOAD_IMAGE
//			ZwDeleteKey(reg);
//#endif // RELOAD_IMAGE

			//Kenerl_WriteFile(L"\\??\\C:\\1.LOG", &uszDriverString);
			//Kenerl_WriteFile()

			ZwClose(reg);
			return TRUE;
		}
		return FALSE;
	}


	NTSTATUS IniLinkMsg(PDRIVER_OBJECT  Driver) {

		char* pDeviceString = (char*)ExAllocatePoolWithTag(PagedPool, uszDriverString.Length + 100, 'tag');
		RtlStringCbPrintfW((NTSTRSAFE_PWSTR)pDeviceString, uszDriverString.Length + 100, L"\\Device\\%s", uszDriverString.Buffer);
		RtlInitUnicodeString(&uszDeviceString, (PCWSTR)pDeviceString);

		char* pLinkString = (char*)ExAllocatePoolWithTag(PagedPool, uszDriverString.Length + 100, 'tag');
		RtlStringCbPrintfW((NTSTRSAFE_PWSTR)pLinkString, uszDriverString.Length + 100, L"\\??\\%s", uszDriverString.Buffer);
		RtlInitUnicodeString(&uszSymLinkString, (PCWSTR)pLinkString);

		NTSTATUS ntStatus = STATUS_SUCCESS;

		__try {

			ntStatus = CreateDriverObject(Driver);

		}
		__except (1) {

			ULONG dwEx = GetExceptionCode();
			LOG_DEBUG("ExceptionCode: %p \n", dwEx);
			ntStatus = dwEx;
		}
		return ntStatus;
	}


	NTSTATUS IniLinkMsgString(PDRIVER_OBJECT  Driver, PCUNICODE_STRING ws) {

		char* pDeviceString = (char*)ExAllocatePoolWithTag(PagedPool, ws->Length + 100, 'tag');
		RtlStringCbPrintfW((NTSTRSAFE_PWSTR)pDeviceString, ws->Length + 100, L"\\Device\\%s", ws->Buffer);
		RtlInitUnicodeString(&uszDeviceString, (PCWSTR)pDeviceString);

		char* pLinkString = (char*)ExAllocatePoolWithTag(PagedPool, ws->Length + 100, 'tag');
		RtlStringCbPrintfW((NTSTRSAFE_PWSTR)pLinkString, ws->Length + 100, L"\\??\\%s", ws->Buffer);
		RtlInitUnicodeString(&uszSymLinkString, (PCWSTR)pLinkString);

		NTSTATUS ntStatus = STATUS_SUCCESS;

		__try {

			ntStatus = CreateDriverObject(Driver);

		}
		__except (1) {

			ULONG dwEx = GetExceptionCode();
			LOG_DEBUG("ExceptionCode: %p \n", dwEx);
			ntStatus = dwEx;
		}
		return ntStatus;
	}



	NTSTATUS IniLinkMsgR(PDRIVER_OBJECT  Driver) {

		char* pDeviceString = (char*)ExAllocatePoolWithTag(PagedPool, uszDriverString.Length + 100, 'tag');
		RtlStringCbPrintfW((NTSTRSAFE_PWSTR)pDeviceString, uszDriverString.Length + 100, L"\\Device\\%sR", uszDriverString.Buffer);
		RtlInitUnicodeString(&uszDeviceString, (PCWSTR)pDeviceString);

		char* pLinkString = (char*)ExAllocatePoolWithTag(PagedPool, uszDriverString.Length + 100, 'tag');
		RtlStringCbPrintfW((NTSTRSAFE_PWSTR)pLinkString, uszDriverString.Length + 100, L"\\??\\%sR", uszDriverString.Buffer);
		RtlInitUnicodeString(&uszSymLinkString, (PCWSTR)pLinkString);

		NTSTATUS ntStatus = STATUS_SUCCESS;

		__try {

			ntStatus = CreateDriverObject(Driver);

		}
		__except (1) {

			ULONG dwEx = GetExceptionCode();
			LOG_DEBUG("ExceptionCode: %p \n", dwEx);
			ntStatus = dwEx;
		}
		return ntStatus;
	}

	//NTKERNELAPI	NTSTATUS ZwCreateNamedPipeFile(
	//	/*[out] */         PHANDLE            FileHandle,
	//	/*[in] */          ULONG              DesiredAccess,
	//	/*[in] */          POBJECT_ATTRIBUTES ObjectAttributes,
	//	/*[out]*/          PIO_STATUS_BLOCK   IoStatusBlock,
	//	/*[in] */          ULONG              ShareAccess,
	//	/*[in]*/           ULONG              CreateDisposition,
	//	/*[in]*/           ULONG              CreateOptions,
	//	/*[in]*/           ULONG              NamedPipeType,
	//	/*[in]*/           ULONG              ReadMode,
	//	/*[in]*/           ULONG              CompletionMode,
	//	/*[in]*/           ULONG              MaximumInstances,
	//	/*[in]  */         ULONG              InboundQuota,
	//	/*[in] */          ULONG              OutboundQuota,
	//	/*[in, optional]*/ PLARGE_INTEGER     DefaultTimeout
	//);


	typedef	NTSTATUS (*fNtCreateNamedPipeFile)(
		/*[out] */         PHANDLE            FileHandle,
		/*[in] */          ULONG              DesiredAccess,
		/*[in] */          POBJECT_ATTRIBUTES ObjectAttributes,
		/*[out]*/          PIO_STATUS_BLOCK   IoStatusBlock,
		/*[in] */          ULONG              ShareAccess,
		/*[in]*/           ULONG              CreateDisposition,
		/*[in]*/           ULONG              CreateOptions,
		/*[in]*/           ULONG              NamedPipeType,
		/*[in]*/           ULONG              ReadMode,
		/*[in]*/           ULONG              CompletionMode,
		/*[in]*/           ULONG              MaximumInstances,
		/*[in]  */         ULONG              InboundQuota,
		/*[in] */          ULONG              OutboundQuota,
		/*[in, optional]*/ PLARGE_INTEGER     DefaultTimeout
	);



	__kernel_entry NTSTATUS NtQueryInformationProcess(
		/*[in]*/            HANDLE           ProcessHandle,
		/*[in]*/            PROCESSINFOCLASS ProcessInformationClass,
		/*[out]*/           PVOID            ProcessInformation,
		/*[in]*/            ULONG            ProcessInformationLength,
		/*[out, optional]*/ PULONG           ReturnLength
	);


	__kernel_entry NTSTATUS NtOpenDirectoryObject(
		PHANDLE DirectoryHandle,
	    ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes
	);

	__kernel_entry NTSTATUS WINAPI NtQuerySymbolicLinkObject(
		_In_ HANDLE LinkHandle,
		_Inout_ PUNICODE_STRING LinkTarget,
		_Out_opt_ PULONG ReturnedLength
	);

	__kernel_entry DWORD PsGetProcessSessionId(PEPROCESS eprocess);


	//DWORD __stdcall GetLogicalDrives()
	//{
	//	NTSTATUS InformationProcess; // eax
	//	DWORD result; // eax
	//	DWORD ProcessInformation[14]; // [rsp+30h] [rbp-38h] BYREF

	//	InformationProcess = NtQueryInformationProcess(
	//		(HANDLE)0xFFFFFFFFFFFFFFFFi64,
	//		ProcessDeviceMap,
	//		ProcessInformation,
	//		0x24u,
	//		0i64);
	//	if (InformationProcess < 0)
	//	{
	//		//BaseSetLastNTError((unsigned int)InformationProcess);
	//		return 0;
	//	}
	//	else
	//	{
	//		result = ProcessInformation[0];
	//		if (!ProcessInformation[0])
	//		{
	//			//RtlSetLastWin32Error(0);
	//			return ProcessInformation[0];
	//		}
	//	}
	//	return result;
	//}

	//DWORD __stdcall GetLogicalDriveStringsW(DWORD nBufferLength, LPWSTR lpBuffer)
	//{
	//	unsigned __int16 v3; // r14
	//	unsigned int v4; // edi
	//	int v5; // ebp
	//	DWORD LogicalDrives; // r15d
	//	signed int i; // ebx
	//	unsigned __int8 v8; // cf
	//	unsigned int v9; // eax
	//	struct _UNICODE_STRING v11; // [rsp+20h] [rbp-48h] BYREF
	//	__int64 v12; // [rsp+30h] [rbp-38h] BYREF

	//	v3 = 2 * nBufferLength;
	//	v12 = 0x5C003A0041i64;
	//	v4 = 0;
	//	v5 = 0;
	//	RtlInitUnicodeString(&v11, (PCWSTR)&v12);
	//	LogicalDrives = GetLogicalDrives();
	//	for (i = 0; i < 26; ++i)
	//	{
	//		v8 = _bittest((const int*)&LogicalDrives, i);
	//		*v11.Buffer = (char)i + 65;
	//		if (v8)
	//		{
	//			v4 += v11.MaximumLength;
	//			if ((unsigned __int64)v4 + 2 > v3)
	//			{
	//				v5 = 1;
	//			}
	//			else
	//			{
	//				memcpy(lpBuffer, v11.Buffer, v11.MaximumLength);
	//				lpBuffer = (LPWSTR)((char*)lpBuffer + v11.MaximumLength);
	//				*lpBuffer = 0;
	//			}
	//		}
	//	}
	//	v9 = v4 + 2;
	//	if (!v5)
	//		v9 = v4;
	//	return v9 >> 1;
	//}
	//DWORD __stdcall QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax)
	//{
	//	WCHAR* v4; // rdi
	//	NTSTATUS v6; // eax
	//	NTSTATUS v7; // ebx
	//	unsigned __int16* Heap; // r14
	//	DWORD v9; // esi
	//	NTSTATUS v10; // eax
	//	unsigned __int16* v11; // rsi
	//	__int64 v12; // r13
	//	WCHAR* v13; // rdi
	//	NTSTATUS v15; // [rsp+40h] [rbp-D8h]
	//	DWORD v16; // [rsp+44h] [rbp-D4h]
	//	DWORD v17; // [rsp+44h] [rbp-D4h]
	//	unsigned __int16 i; // [rsp+48h] [rbp-D0h]
	//	DWORD BufferLength; // [rsp+50h] [rbp-C8h]
	//	void* FileHandle; // [rsp+58h] [rbp-C0h] BYREF
	//	PVOID P; // [rsp+60h] [rbp-B8h]
	//	ULONG DataWritten; // [rsp+68h] [rbp-B0h] BYREF
	//	int v23; // [rsp+6Ch] [rbp-ACh]
	//	ULONG Context; // [rsp+70h] [rbp-A8h] BYREF
	//	struct _UNICODE_STRING DestinationString; // [rsp+78h] [rbp-A0h] BYREF
	//	unsigned __int16* v26; // [rsp+88h] [rbp-90h]
	//	void* SymbolicLinkHandle; // [rsp+90h] [rbp-88h] BYREF
	//	struct _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+98h] [rbp-80h] BYREF
	//	LPWSTR v29; // [rsp+C8h] [rbp-50h]
	//	char Source1[32]; // [rsp+D0h] [rbp-48h] BYREF

	//	v4 = lpTargetPath;
	//	FileHandle = 0i64;
	//	Context = 0;
	//	v29 = lpTargetPath;
	//	RtlInitUnicodeString(&DestinationString, L"\\??");
	//	ObjectAttributes.Length = 48;
	//	ObjectAttributes.RootDirectory = 0i64;
	//	ObjectAttributes.Attributes = 64;
	//	ObjectAttributes.ObjectName = &DestinationString;
	//	*(DWORD64*)&ObjectAttributes.SecurityDescriptor = 0i64;
	//	v6 = NtOpenDirectoryObject(&FileHandle, 1u, &ObjectAttributes);
	//	v7 = v6;
	//	v15 = v6;
	//	if (v6 < 0)
	//	{
	//		BaseSetLastNTError((unsigned int)v6);
	//		return 0;
	//	}
	//	v16 = 0;
	//	Heap = 0i64;
	//	P = 0i64;
	//	if (lpDeviceName)
	//	{
	//		RtlInitUnicodeString(&DestinationString, lpDeviceName);
	//		ObjectAttributes.Length = 48;
	//		ObjectAttributes.RootDirectory = FileHandle;
	//		ObjectAttributes.Attributes = 64;
	//		ObjectAttributes.ObjectName = &DestinationString;
	//		*(DWORD64*)&ObjectAttributes.SecurityDescriptor = 0i64;
	//		v7 = NtOpenSymbolicLinkObject(&SymbolicLinkHandle, 1u, &ObjectAttributes);
	//		v15 = v7;
	//		if (v7 < 0)
	//			goto LABEL_56;
	//		DestinationString.Buffer = v4;
	//		DestinationString.Length = 0;
	//		if (ucchMax > 0x7FFFFFFF || 2 * ucchMax > 0xFFFF)
	//			DestinationString.MaximumLength = -1;
	//		else
	//			DestinationString.MaximumLength = 2 * ucchMax;
	//		DataWritten = 0;
	//		v7 = NtQuerySymbolicLinkObject(SymbolicLinkHandle, &DestinationString, &DataWritten);
	//		v15 = v7;
	//		NtClose(SymbolicLinkHandle);
	//		if (v7 < 0)
	//			goto LABEL_56;
	//		v17 = DataWritten >> 1;
	//		if (!(DataWritten >> 1) || v4[(DataWritten >> 1) - 1])
	//		{
	//			if (v17 >= ucchMax)
	//			{
	//			LABEL_16:
	//				v16 = 0;
	//				goto LABEL_17;
	//			}
	//			v4[v17++] = 0;
	//		}
	//		if (v17 < ucchMax)
	//		{
	//			v4[v17] = 0;
	//			v16 = v17 + 1;
	//			goto LABEL_56;
	//		}
	//		goto LABEL_16;
	//	}
	//	if (*(BYTE*)(BaseStaticServerData + 2676) == 1)
	//	{
	//		v7 = IsGlobalDeviceMap(FileHandle);
	//		v15 = v7;
	//	}
	//	v23 = 0;
	//	memset_0(Source1, 0, sizeof(Source1));
	//	if (ucchMax <= 0x7FFFFFFF)
	//	{
	//		v9 = 2 * ucchMax;
	//		BufferLength = 2 * ucchMax;
	//	}
	//	else
	//	{
	//		BufferLength = -1;
	//		v9 = -1;
	//	}
	//	for (i = 0; ; ++i)
	//	{
	//		Heap = 0i64;
	//		P = 0i64;
	//		if (i >= 3u)
	//			break;
	//		Heap = (unsigned __int16*)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, KernelBaseGlobalData, v9);
	//		P = Heap;
	//		if (!Heap)
	//		{
	//			v7 = -1073741670;
	//			goto LABEL_18;
	//		}
	//		v10 = NtQueryDirectoryObject(FileHandle, Heap, BufferLength, 0, 1u, &Context, &DataWritten);
	//		v7 = v10;
	//		v15 = v10;
	//		if (v10 < 0)
	//		{
	//			if (v10 != -2147483622)
	//				goto LABEL_56;
	//			v7 = 0;
	//			v15 = 0;
	//			v4 = lpTargetPath;
	//			goto LABEL_39;
	//		}
	//		if (v10 != 261)
	//		{
	//			v11 = Heap;
	//			v26 = Heap;
	//			v4 = lpTargetPath;
	//			while (RtlCompareMemory(Source1, v11, 0x20ui64) != 32)
	//			{
	//				if (!wcscmp(*((const wchar_t**)v11 + 3), L"SymbolicLink"))
	//				{
	//					v12 = *v11 >> 1;
	//					if (v16 > ucchMax || (unsigned int)v12 > ucchMax - v16 || ucchMax - (DWORD)v12 - v16 < 2)
	//						goto LABEL_17;
	//					memcpy_0(v4, *((const void**)v11 + 1), *v11);
	//					v13 = &v4[v12];
	//					*v13 = 0;
	//					v4 = v13 + 1;
	//					v16 += v12 + 1;
	//					++v23;
	//				}
	//				v11 += 16;
	//				v26 = v11;
	//			}
	//			break;
	//		}
	//		//RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, P);
	//		Heap = 0i64;
	//		P = 0i64;
	//		if (v9 == -1)
	//		{
	//			v4 = lpTargetPath;
	//			v7 = v15;
	//			break;
	//		}
	//		if (~v9 < v9)
	//		{
	//			BufferLength = -1;
	//			v9 = -1;
	//		}
	//		else
	//		{
	//			v9 *= 2;
	//			BufferLength = v9;
	//		}
	//		v4 = lpTargetPath;
	//		v7 = v15;
	//	}
	//	if (v7 == 261)
	//		goto LABEL_17;
	//LABEL_39:
	//	if (*(BYTE*)(BaseStaticServerData + 2676) == 1 && v7 < 0 || v7 < 0)
	//		goto LABEL_56;
	//	if (!v16)
	//	{
	//		if (!ucchMax)
	//			goto LABEL_17;
	//		*v4++ = 0;
	//		v16 = 1;
	//	}
	//	if (v16 >= ucchMax)
	//	{
	//	LABEL_17:
	//		v7 = -1073741789;
	//	LABEL_18:
	//		v15 = v7;
	//		goto LABEL_56;
	//	}
	//	*v4 = 0;
	//	++v16;
	//LABEL_56:
	//	if (FileHandle)
	//		NtClose(FileHandle);
	//	if (Heap)
	//	{
	//		//RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, P);
	//		v7 = v15;
	//	}
	//	if (v7 < 0)
	//	{
	//		v16 = 0;
	//		//BaseSetLastNTError((unsigned int)v7);
	//	}
	//	return v16;
	//}

	//BOOL DeviceDosPathToNtPath(wchar_t* pszDosPath, wchar_t* pszNtPath)
	//{
	//	static TCHAR    szDriveStr[MAX_PATH] = { 0 };
	//	static TCHAR    szDevName[MAX_PATH] = { 0 };
	//	TCHAR            szDrive[3];
	//	INT             cchDevName;
	//	INT             i;

	//	//检查参数  
	//	//if (IsBadReadPtr(pszDosPath, 1) != 0)return FALSE;
	//	//if (IsBadWritePtr(pszNtPath, 1) != 0)return FALSE;


	//	//获取本地磁盘字符串  
	//	RtlZeroMemory(szDriveStr, ARRAYSIZE(szDriveStr));
	//	RtlZeroMemory(szDevName, ARRAYSIZE(szDevName));
	//	if (GetLogicalDriveStringsW(sizeof(szDriveStr), szDriveStr))
	//	{
	//		for (i = 0; szDriveStr[i]; i += 4)
	//		{
	//			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
	//				continue;

	//			szDrive[0] = szDriveStr[i];
	//			szDrive[1] = szDriveStr[i + 1];
	//			szDrive[2] = '\0';


	//			if (!QueryDosDevice(szDrive, szDevName, MAX_PATH))//查询 Dos 设备名  
	//				return FALSE;

	//			cchDevName = lstrlen(szDevName);
	//			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中  
	//			{
	//				lstrcpy(pszNtPath, szDrive);//复制驱动器  
	//				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径  

	//				return TRUE;
	//			}
	//		}
	//	}

	//	lstrcpy(pszNtPath, pszDosPath);

	//	return FALSE;
	//}




extern LONG ZwFunGetIndex(wchar_t* _FunName);

fNtCreateNamedPipeFile  wNtCreateNamedPipeFile = 0;


NTSTATUS _NtCreateNamedPipeFile(
	/*[out] */         PHANDLE            FileHandle,
	/*[in] */          ULONG              DesiredAccess,
	/*[in] */          POBJECT_ATTRIBUTES ObjectAttributes,
	/*[out]*/          PIO_STATUS_BLOCK   IoStatusBlock,
	/*[in] */          ULONG              ShareAccess,
	/*[in]*/           ULONG              CreateDisposition,
	/*[in]*/           ULONG              CreateOptions,
	/*[in]*/           ULONG              NamedPipeType,
	/*[in]*/           ULONG              ReadMode,
	/*[in]*/           ULONG              CompletionMode,
	/*[in]*/           ULONG              MaximumInstances,
	/*[in]  */         ULONG              InboundQuota,
	/*[in] */          ULONG              OutboundQuota,
	/*[in, optional]*/ PLARGE_INTEGER     DefaultTimeout
) {

	if (wNtCreateNamedPipeFile == 0)
	{
		LONG Index = ZwFunGetIndex(L"ZwCreatePartition");
		if (Index == -1){
			return -1;
		}
		LONG PipeFileIndex = Index - 2;
		wNtCreateNamedPipeFile = (fNtCreateNamedPipeFile)GetSSDTFuncAddr(PipeFileIndex);
	}
	if (wNtCreateNamedPipeFile == 0)
	{
		return -1;
	}
	return wNtCreateNamedPipeFile(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		NamedPipeType,
		ReadMode,
		CompletionMode,
		MaximumInstances,
		InboundQuota,
		OutboundQuota,
		DefaultTimeout);
}







	HANDLE __stdcall _CreateNamedPipeW(
		LPCWSTR lpName,
		DWORD dwOpenMode,
		DWORD dwPipeMode,
		DWORD nMaxInstances,
		DWORD nOutBufferSize,
		DWORD nInBufferSize,
		DWORD nDefaultTimeOut
		/*PACL pAcl*/)
	{
		DWORD MaxInstances; // r14d
		ULONG v11; // ecx
		PWSTR Buffer; // rdi
		LPVOID lpSecurityDescriptor; // rax
		union _LARGE_INTEGER v14; // rcx
		ULONG ShareAccess; // r11d
		int v16; // esi
		DWORD WriteModeMessage; // edx
		NTSTATUS v18; // eax
		int v19; // ebx
		ULONG v20; // ecx
		NTSTATUS v22; // esi
		__int64 v23; // rcx
		PACL pAcl; // [rsp+78h] [rbp-90h] BYREF
		union _LARGE_INTEGER DefaultTimeOut; // [rsp+80h] [rbp-88h] BYREF
		void* NamedPipeFileHandle; // [rsp+88h] [rbp-80h] BYREF
		struct _UNICODE_STRING NtPathName; // [rsp+90h] [rbp-78h] BYREF
		struct _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+A0h] [rbp-68h] BYREF
		PCWSTR NtFileNamePart; // [rsp+D0h] [rbp-38h] BYREF
		struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+D8h] [rbp-30h] BYREF
		char SecurityDescriptor[48]; // [rsp+E8h] [rbp-20h] BYREF

		pAcl = 0i64;
		if (nMaxInstances - 1 > 0xFE)
		{
		LABEL_34:
			v23 = 3221225485i64;
		LABEL_35:
			//BaseSetLastNTError(v23);
			return (HANDLE)-1i64;
		}
		MaxInstances = -1;
		if (nMaxInstances != 255)
			MaxInstances = nMaxInstances;

		//RtlDosPathNameToNtPathName_U()



		RtlInitUnicodeString(&NtPathName, lpName);


		//if (!RtlDosPathNameToNtPathName_U(lpName, &NtPathName, &NtFileNamePart, 0i64))
		//{
		//	//RtlSetLastWin32Error(3u);
		//	return (HANDLE)-1i64;
		//}


		//初始化对象属性
		InitializeObjectAttributes(&ObjectAttributes, &NtPathName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);


		//ObjectAttributes.Length = 48;
		//ObjectAttributes.Attributes = 64;
		//ObjectAttributes.ObjectName = &NtPathName;



		//*(DWORD64*)&ObjectAttributes.SecurityDescriptor = 0i64;

		//if (!lpSecurityAttributes)
		//	goto LABEL_28;
		//lpSecurityDescriptor = lpSecurityAttributes->lpSecurityDescriptor;
		//if (lpSecurityAttributes->bInheritHandle)
		//	v11 = 66;
		//ObjectAttributes.SecurityDescriptor = lpSecurityAttributes->lpSecurityDescriptor;
		//ObjectAttributes.Attributes = v11;
		//if (!lpSecurityDescriptor)
		//{
		//LABEL_28:

		//}


		//v22 = RtlDefaultNpAcl(&pAcl);
		//if (v22 < 0)
		//{
		//	//RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
		//	v23 = (unsigned int)v22;
		//	goto LABEL_35;
		//}



		RtlCreateSecurityDescriptor(SecurityDescriptor, 1u);
		RtlSetDaclSecurityDescriptor(SecurityDescriptor, 1u, pAcl, 0);
		ObjectAttributes.SecurityDescriptor = SecurityDescriptor;

		if (nDefaultTimeOut)
			v14.QuadPart = -10000i64 * nDefaultTimeOut;
		else
			v14.QuadPart = -500000i64;
		DefaultTimeOut = v14;
		if ((dwOpenMode & 0x3EF3FFFC) != 0 || (dwPipeMode & 0xFFFFFFF0) != 0)
		{
		LABEL_32:
			//RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
			if (pAcl)
				//RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pAcl);
			goto LABEL_34;
		}
		ShareAccess = 3;
		switch (dwOpenMode & 3)
		{
		case 1u:
			v16 = -2146435072;
			ShareAccess = 2;
			break;
		case 2u:
			v16 = 1074790400;
			ShareAccess = 1;
			break;
		case 3u:
			v16 = -1072693248;
			break;
		default:
			goto LABEL_32;
		}
		WriteModeMessage = (dwPipeMode >> 2) & 1 | 2;
		if ((dwPipeMode & 8) == 0)
			WriteModeMessage = (dwPipeMode >> 2) & 1;



		v18 = _NtCreateNamedPipeFile(
			&NamedPipeFileHandle,
			v16 | dwOpenMode & 0x10C0000,
			&ObjectAttributes,
			&IoStatusBlock,
			ShareAccess,
			(int)((dwOpenMode & 0x80000) == 0) | 2,
			((int)dwOpenMode >> 31) & 2 | ~(dwOpenMode >> 25) & 0x20,
			WriteModeMessage,
			(dwPipeMode >> 1) & 1,
			dwPipeMode & 1,
			MaxInstances,
			nInBufferSize,
			nOutBufferSize,
			&DefaultTimeOut);
		v19 = v18;
		if (v18 == -1073741637 || v18 == -1073741808)
			v19 = -1073741773;
		//RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
		if (pAcl)
			//RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pAcl);
		if (v19 < 0)
		{
			v23 = (unsigned int)v19;
			goto LABEL_35;
		}
		if (IoStatusBlock.Information == 1)
			v20 = 183;
		else
			v20 = 0;
	//	RtlSetLastWin32Error(v20);
		return NamedPipeFileHandle;
	}



	HANDLE hPipeFile = 0;

	BOOLEAN IniLinkMsg_Pipe(PDRIVER_OBJECT  Driver) {

		char* pDeviceString = (char*)ExAllocatePoolWithTag(PagedPool, uszDriverString.Length + 100, 'tag');
		RtlStringCbPrintfW((NTSTRSAFE_PWSTR)pDeviceString, uszDriverString.Length + 100, L"\\\\.\\pipe\\%s", uszDriverString.Buffer);
		RtlInitUnicodeString(&uszStringRegPepi, (PCWSTR)pDeviceString);
		//OBJECT_ATTRIBUTES ObjectAttributes = {0};
		//InitializeObjectAttributes(&ObjectAttributes, &uszStringRegPepi, OBJ_KERNEL_HANDLE, NULL, NULL)
		IO_STATUS_BLOCK IoStatus;
		//NtCreateNamedPipeFile(&hPipeFile, FILE_READ_DATA | FILE_WRITE_DATA,0, &IoStatus,FILE_SHARE_READ, FILE_SUPERSEDE,);


		return TRUE;
	}



	typedef  NTSTATUS(NTAPI* _PspSetCreateThreadNotifyRoutine)(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine, int Flags); //0 1 2

	BOOLEAN IniFilterProcessEntry() {




		OBJECT_ATTRIBUTES Attributes;
		NTSTATUS Status;
		HANDLE ThreadHandle = NULL;
		InitializeObjectAttributes(
			&Attributes,
			NULL,
			OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		Status = PsCreateSystemThread(
			&ThreadHandle,
			THREAD_ALL_ACCESS,
			&Attributes,
			NULL,
			NULL,
			FindSystemThreadRoutineStart,
			0);


		//char* Plmg = &PsSetCreateThreadNotifyRoutine;
		//_PspSetCreateThreadNotifyRoutine PspSetCreateThreadNotifyRoutine  = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(Plmg, 1));
		//if (NT_SUCCESS( PspSetCreateThreadNotifyRoutine(_CREATE_THREAD_NOTIFY_ROUTINE2, 2)))
		//{


		//	LOG_DEBUG("SUCESSS PsSetCreateThreadNotifyRoutine\n");
		//}

		//;



		//if (NT_SUCCESS(PsSetCreateThreadNotifyRoutine(_CREATE_THREAD_NOTIFY_ROUTINE2)))
		//{
		//	LOG_DEBUG("SUCESSS PsSetCreateThreadNotifyRoutine\n");
		//}



		RtlInitializeGenericTableAvl(&TableAvl_MEYUX_1.AVL_Table, CompareHandleTableEntry_1,
			AllocateHandleTableEntry_1, FreeHandleTableEntry_1, NULL);
		KeInitializeSpinLock(&TableAvl_MEYUX_1.Lock);


		RtlInitializeGenericTableAvl(&TableAvl_UCHAR_NAME.AVL_Table, CompareHandleTableEntryAnsiString,
			AllocateHandleTableEntryAnsiString, FreeHandleTableEntryAnsiString, NULL);
		KeInitializeSpinLock(&TableAvl_UCHAR_NAME.Lock);


		//if (NT_SUCCESS(PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine_FilterProcess, FALSE)))
		//{
		//	LOG_DEBUG("SUCESSS PsSetCreateProcessNotifyRoutine\n");
		//	//return TRUE;
		//}

//#ifndef RELOAD_IMAGE

		if (NT_SUCCESS(PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE_SANDBOX)))
		{
			LOG_DEBUG("SUCESSS PsSetLoadImageNotifyRoutine\n");
		}


		
		//if (NT_SUCCESS(PsRemoveLoadImageNotifyRoutine(PUNLOAD_IMAGE_NOTIFY_ROUTINE_SANDBOX)))
		//{
		//	LOG_DEBUG("SUCESSS PsRemoveLoadImageNotifyRoutine\n");
		//}

//#endif // IMAGE_RELOAD




	
		return FALSE;
	}


	char* _ASM_GET_TEST_PTR_CODE(char* pAdr, int num) {
		int bi = 0;
		int gLen = 0;
		while (bi < num)
		{
			int bLen = DetourGetInstructionLength(pAdr + gLen);
			if (bLen == 10) {
				char* p = pAdr + gLen;
				if (p[0] == (char)0xF7 &&
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



	typedef  void  (NTAPI* _RtlInsertInvertedFunctionTable)(HANDLE hMod, int Size);



	typedef NTSTATUS(NTAPI* _DriverEntry)(
		_In_ PDRIVER_OBJECT  Driver,
		_In_ PUNICODE_STRING RegistryPath);





	//
	typedef NTSTATUS(NTAPI* _ObCreateObjectEx)(
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

	typedef NTSTATUS(NTAPI* _ObInsertObjectEx)(
		PVOID Object,
		PACCESS_STATE PassedAccessState,
		ACCESS_MASK DesiredAccess,
		ULONG ObjectPointerBias,
		DWORD64 Flags,
		PVOID* NewObject,
		PHANDLE Handle);



	_Kernel_entry_ NTSTATUS __stdcall NtCreateEvent(
		PHANDLE EventHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		EVENT_TYPE EventType,
		BOOLEAN InitialState);



	_Kernel_entry_ NTSTATUS NTAPI ObCreateObject(
		KPROCESSOR_MODE ProbeMode,
		POBJECT_TYPE ObjectType,
		POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		KPROCESSOR_MODE OwnershipMode,
		PVOID ParseContext OPTIONAL,
		ULONG ObjectBodySize,
		ULONG PagedPoolCharge,
		ULONG NonPagedPoolCharge,
		PVOID* Object
		);

	//_Kernel_entry_	NTSTATUS __stdcall ObInsertObject(
	//	PVOID Object,
	//	PACCESS_STATE PassedAccessState,
	//	ACCESS_MASK DesiredAccess,
	//	ULONG ObjectPointerBias,
	//	PVOID* NewObject,
	//	PHANDLE Handle);


	NTSTATUS __fastcall IopInvalidDeviceRequest(__int64 a1, IRP* a2)
	{
		a2->IoStatus.Status = 0xC0000010;
		IofCompleteRequest(a2, 0);
		return 0xC0000010i64;
	}



	PVOID FindImageBaseDrvs(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pBaseName,ULONG* nSize)
	{

		PLDR_DATA_TABLE_ENTRY pLdrTblEntry = (PLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection;
		PLIST_ENTRY pListHdr = &pLdrTblEntry->InLoadOrderLinks;
		PLIST_ENTRY pListEntry = NULL;
		pListEntry = pListHdr->Flink;
		int i = 0;

		PVOID fObject = 0;
		//wchar_t* Name = ExAllocatePoolWithTag(PagedPool, 0x1000, 'Tg');
		do
		{
			pLdrTblEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (pLdrTblEntry->BaseDllName.Buffer != 0)
			{



				//GetDeviceInfo(pLdrTblEntry);

				//LOG_DEBUG("%d  %wZ\t0x%I64X\t%I64u(B)\t0x%I64X\t%wZ\r\n", i,
				//	&pLdrTblEntry->BaseDllName,
				//	pLdrTblEntry->DllBase,
				//	pLdrTblEntry->SizeOfImage,
				//	pLdrTblEntry,
				//	&pLdrTblEntry->FullDllName
				//);


				if (RtlEqualUnicodeString(&pLdrTblEntry->BaseDllName, pBaseName, TRUE))
				{
					LOG_DEBUG("Find Driver DllBase %wZ  <%p>\n", pBaseName, pLdrTblEntry);
					//return (PDRIVER_OBJECT)pLdrTblEntry;
					fObject = pLdrTblEntry->DllBase;
					*nSize = pLdrTblEntry->SizeOfImage;
					break;
				}

			}
			i++;
			pListEntry = pListEntry->Flink;
		} while (pListEntry != pListHdr);
		return fObject;
	}


	PVOID FindImageBase(wchar_t * pBaseName , ULONG *nSize) {
		PDRIVER_OBJECT BeepDriverObject = NULL;
		if (!GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\Beep")) {
			return 0;
		}
		UNICODE_STRING Fname;
		RtlInitUnicodeString(&Fname, pBaseName);
		PVOID pBaseObject = FindImageBaseDrvs(BeepDriverObject, &Fname, nSize);
		ObDereferenceObject(BeepDriverObject);
		return pBaseObject;
	}

	

	void ReloadEntryPoint(PUNICODE_STRING RegistryPath) {








	}


	extern ULONG_PTR kernelBase;

	extern void RemoveFlushDpcTimer();


	typedef  NTSTATUS(NTAPI * _IopGetDriverNameFromKeyNode)(HANDLE KeyHandle, PUNICODE_STRING Destination);



typedef	 NTSTATUS( *_k_MmLoadSystemImage)(IN PUNICODE_STRING FileName,
		IN PUNICODE_STRING NamePrefix OPTIONAL,
		IN PUNICODE_STRING LoadedName OPTIONAL,
		IN ULONG Flags,
		OUT PVOID* ModuleObject,
		OUT PVOID* ImageBaseAddress);



extern char* _ASM_MOV_EAX_2(char* pAdr, int num);

extern ULONGLONG _CODE_GET_REAL_ADDRESS_0(char* pEl, int nCodeSize);

NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);
//__kernel_entry NTSTATUS MmLoadSystemImage(PUNICODE_STRING a1,
//	__int64 a2, __int64 a3,
//	int a4, PLDR_DATA_TABLE_ENTRY* a5, PVOID* a6);



typedef struct _RELOAD_INFO{
	
	PDRIVER_OBJECT  Driver;

//	PUNICODE_STRING RegistryPath;

	PVOID SectionObject;
	PVOID DllBase;



	 DWORD64 hModBase;
	 DWORD hModSize;
	 DWORD64 PDATA_EXCEPTION;
	 DWORD  PDATA_EXCEPTION_SIZE;


	 PVOID hModSginPtr;
	 DWORD ModSgin;

	 _RtlInsertInvertedFunctionTable  RtlInsertInvertedFunctionTable;
	 _RtlRemoveInvertedFunctionTable  RtlRemoveInvertedFunctionTable;

}RELOAD_INFO;


void RELOAD_HIDE_MEMORY(ULONGLONG Ptr) 
{

	DWORD64 PLM4[4] = { 0 };
	MiFillPteHierarchy((ULONGLONG)Ptr, PLM4);
	BOOLEAN uFun = TRUE;
	int i = 4;
	do
	{
		i--;
		MMPTE pCurMM = *(MMPTE*)PLM4[i];
		MMPTE_TEST0 pCurMM0 = *(MMPTE_TEST0*)PLM4[i];
		//LOG_DEBUG("MMPTE %d  <%I64X>  Flags: %d\n", i, pCurMM.u.Long, pCurMM0.u.MPTE_T.Valid);


		if (i == 3){
			pCurMM.u.Hard.Valid = 0;
			*(MMPTE*)PLM4[i] = pCurMM;
			__invlpg(PLM4[i]);
		}
		if (pCurMM0.u.MPTE_T.Valid == 1) {
			pCurMM0.u.MPTE_T.Valid = 0;
			*(MMPTE_TEST0*)PLM4[i] = pCurMM0;
			__invlpg(PLM4[i]);
			LOG_DEBUG("SET MMPTE %d  <%I64X>  Flags: %d\n", i, pCurMM.u.Long, pCurMM0.u.MPTE_T.Valid);
		}
		if (pCurMM.u.Hard.LargePage != 0) {

			break;
		}
	} while (i > 0);
}







extern DWORD64 hModBase;
extern DWORD hModSize;
extern DWORD64  PDATA_EXCEPTION;
extern DWORD  PDATA_EXCEPTION_SIZE;
//extern DWORD64 Ptr;
extern DWORD ModSgin;

_RtlInsertInvertedFunctionTable  RtlInsertInvertedFunctionTable = 0;
_RtlRemoveInvertedFunctionTable  RtlRemoveInvertedFunctionTable = 0;

	 void ReloadSelf(PDRIVER_OBJECT  Driver, PUNICODE_STRING RegistryPath) {


		UNICODE_STRING FuncName;
		RtlInitUnicodeString(&FuncName, L"MmUnloadSystemImage");
		char* pfnMmUnloadSystemImage = (char *)MmGetSystemRoutineAddress(&FuncName);

		RtlInitUnicodeString(&FuncName, L"MmLoadSystemImage");
		_k_MmLoadSystemImage MmLoadSystemImage = (_k_MmLoadSystemImage)MmGetSystemRoutineAddress(&FuncName);


		RTL_OSVERSIONINFOEXW OsVersion = { 0 };
		NTSTATUS Status = STATUS_SUCCESS;
		OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
		Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVersion);
		MmAcquireLoadLock pMmAcquireLoadLock = 0;
		MmReleaseLoadLock pMmReleaseLoadLock = 0;
		if (OsVersion.dwBuildNumber >= 17763 && OsVersion.dwBuildNumber < 19041)
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

		 ULONG64 m_MiProcessLoaderEntry = (ULONG64)Get_MiProcessLoaderEntry();

		 char* pTestMiFlags = _ASM_GET_TEST_PTR_CODE((char *)m_MiProcessLoaderEntry, 1);

		 char* pTestMiFlags2 = _ASM_GET_TEST_PTR_CODE((char*)m_MiProcessLoaderEntry, 2);

		 if (pTestMiFlags == 0)
		 {
			 LOG_DEBUG("can't find  TestMiFlags\n");
			 return;
		 }

		 typedef  void  (NTAPI* _RtlRemoveInvertedFunctionTable)(HANDLE hMod);
		 _RtlInsertInvertedFunctionTable  RtlInsertInvertedFunctionTable = (_RtlInsertInvertedFunctionTable)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pTestMiFlags, 1));
		 _RtlRemoveInvertedFunctionTable  RtlRemoveInvertedFunctionTable = (_RtlRemoveInvertedFunctionTable)_CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(pTestMiFlags2, 1));

		 if (RtlInsertInvertedFunctionTable == 0)
		 {
			 LOG_DEBUG("can't find   RtlInsertInvertedFunctionTable\n");
			 return;
		 }

		 LOG_DEBUG("RtlInsertInvertedFunctionTable  %I64X\n", RtlInsertInvertedFunctionTable);


		 PVOID RtlpInsertInvertedFunctionTableEntry = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(RtlInsertInvertedFunctionTable, 3));
		 if (RtlpInsertInvertedFunctionTableEntry == 0)
		 {
			 LOG_DEBUG("can't find   RtlInsertInvertedFunctionTable\n");
			 return;
		 }
		 LOG_DEBUG("RtlpInsertInvertedFunctionTableEntry  %I64X\n", RtlpInsertInvertedFunctionTableEntry);

		// PsInvertedFunctionTable
		 int * PsInvertedFunctionTableV  = (int*)_CODE_GET_REAL_ADDRESS_0(_ASM_MOV_EAX_2((char*)RtlpInsertInvertedFunctionTableEntry, 1), 2);




		 //_ASM_MOV_EAX_2(RtlpInsertInvertedFunctionTableEntry)












		 LOG_DEBUG("RegistryPath  %wZ\n", RegistryPath);


		 // %wZ  ImagePath



		 


		 OBJECT_ATTRIBUTES oa = { 0 };
		 HANDLE hKey = 0;
		 InitializeObjectAttributes(&oa, RegistryPath, OBJ_KERNEL_HANDLE, NULL, NULL);
		 NTSTATUS ntStatus = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);

		 if (! NT_SUCCESS(ntStatus))
		 {
			 LOG_DEBUG("ZwOpenKey  Error  %wZ\n", RegistryPath);
			 return;
		 }


		// GetKernelBase2()
		 //DWORD64(base) +70B658


		 //_IopGetDriverNameFromKeyNode  IopGetDriverNameFromKeyNode = (DWORD64)kernelBase + 0x70B658;

		 //UNICODE_STRING RegLinkString = {0};
		 //IopGetDriverNameFromKeyNode(hKey, &RegLinkString);

		 //LOG_DEBUG("IopGetDriverNameFromKeyNode %wZ  %wZ\n", RegistryPath, &RegLinkString);




		 UNICODE_STRING A, B, C, D;
		 PKEY_VALUE_PARTIAL_INFORMATION bufA, bufB, bufC, bufD;
		 ULONG ActualSize;



		 PVOID pDisplayName = ExAllocatePoolWithTag(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, 'tag');


		 UNICODE_STRING ImagePath = { 0 };
		 PVOID pImagePath = ExAllocatePoolWithTag(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, 'tag');
		 bufA = (PKEY_VALUE_PARTIAL_INFORMATION)pImagePath;
		 RtlInitUnicodeString(&A, L"ImagePath");
		 if (ntStatus == STATUS_SUCCESS) {
			 ntStatus = ZwQueryValueKey(hKey, &A, KeyValuePartialInformation, bufA, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, &ActualSize);
			 if (ntStatus != STATUS_SUCCESS) {
				 ExFreePoolWithTag(bufA, 'tag');
			 }
		 }

		 if (ntStatus == STATUS_SUCCESS) {
			 RtlInitUnicodeString(&ImagePath, (PCWSTR)bufA->Data);
		 }
		 LOG_DEBUG("ImagePath: %wZ \n", &ImagePath);



		 bufB = (PKEY_VALUE_PARTIAL_INFORMATION)pDisplayName;

		 RtlInitUnicodeString(&B, L"DisplayName");
		 if (ntStatus == STATUS_SUCCESS) {
			 ntStatus = ZwQueryValueKey(hKey, &B, KeyValuePartialInformation, bufB, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, &ActualSize);
			 if (ntStatus != STATUS_SUCCESS) {
				 ExFreePoolWithTag(bufB, 'tag');
			 }
		 }
		 if (ntStatus == STATUS_SUCCESS) {
			 RtlInitUnicodeString(&uszDriverString, (PCWSTR)bufB->Data);
		 }
		 LOG_DEBUG("uszDriverString: %wZ \n", &uszDriverString);
		 //ZwDeleteKey(hKey);
		 ZwClose(hKey);

		 
		 
		 //OBJECT_ATTRIBUTES objectAttributes;
		 //InitializeObjectAttributes(&objectAttributes, &ImagePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		 HANDLE hFile = NULL;
		 OBJECT_ATTRIBUTES objectAttributes = { 0 };
		 IO_STATUS_BLOCK iosb = { 0 };
		 NTSTATUS status = STATUS_SUCCESS;
		 FILE_STANDARD_INFORMATION fsi = { 0 };
		 // 初始化结构
		 InitializeObjectAttributes(&objectAttributes, &ImagePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		 // 打开文件
		 status = ZwCreateFile(&hFile, GENERIC_READ, &objectAttributes, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		 if (!NT_SUCCESS(status))
		 {
			 LOG_DEBUG("File Create File Error\n");
			 return ;
		 }
		 status = ZwQueryInformationFile(hFile, &iosb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		 if (!NT_SUCCESS(status))
		 {
			 ZwClose(hFile);
			 return ;
		 }

		 char* pFileBuffer = (char *)ExAllocatePoolWithTag(PagedPool, fsi.EndOfFile.QuadPart, 'Tag');

		 LARGE_INTEGER nReadReady = {0};
		 status = ZwReadFile(hFile, 0, 0, 0, &iosb, pFileBuffer, fsi.EndOfFile.QuadPart, &nReadReady, 0);


		 LOG_DEBUG("File Size : <%p><%p>", pFileBuffer, fsi.EndOfFile.QuadPart);

		// STATUS_ABANDONED
		 //UNICODE_STRING ImagePathW = { 0 };

		 //wchar_t* pNewName = ExAllocatePoolWithTag(PagedPool, MAX_PATH, 'Tag');

		 //RtlCopyMemory(pNewName, ImagePath.Buffer, ImagePath.Length);

		 //for (size_t i = 0; i < ImagePath.Length / 2; i++)
		 //{

		 //}


		 //HANDLE hNewFile = NULL;
		 //NTSTATUS ntStatus = ZwCreateFile(&hNewFile,
			// GENERIC_WRITE,
			// &objectAttri,
			// &iosb,
			// NULL,
			// FILE_ATTRIBUTE_NORMAL,
			// FILE_SHARE_READ,
			// FILE_OPEN_IF, // 即使存在该文件，也创建
			// FILE_SYNCHRONOUS_IO_NONALERT,
			// NULL,
			// 0
		 //);

		 if (!NT_SUCCESS(status))
		 {
			 ZwClose(hFile);
			 return ;
		 }
		 ZwClose(hFile);
		
		 
		 _DriverEntry pEntyPoint = 0;
		 HANDLE hModDriver = 0;
		 DWORD64 nSize = 0;

		 HANDLE hAttchModDriver = 0;


		 PLDR_DATA_TABLE_ENTRY Ldr = (PLDR_DATA_TABLE_ENTRY)Driver->DriverSection;


		// MmLoadSystemImage()
		 //MmLoadSystemImage()
		// _k_MmLoadSystemImage()
		// PVOID ModObject;

		// MmLoadSystemImage(&ImagePath, 0, 0, 0, &ModObject, &hModDriver);


		 //LOG_DEBUG("LoadDriverV Size: <%p><%p>", ldr, Ldr->DllBase);

	    // hModDriver = LoadDriver((PUCHAR)pFileBuffer, (PULONG64)&pEntyPoint, &nSize, &hAttchModDriver);

		 PVOID SectionObject = 0;

		 hModDriver = (HANDLE)LoadDriverV((PUCHAR)pFileBuffer, (PULONG64)&pEntyPoint, &nSize, Ldr, &SectionObject);







		 PVOID Object = 0;

		 //MmLoadSystemImage(&ImagePath, 0, 0, 0, &Object, &hModDriver);

		 hModBase = hModDriver;

		// PIMAGE_NT_HEADERS pNtHeader = RtlImageNtHeader(hModDriver);
		 PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(hModDriver);

		 hModSize = nSize;
		 PDATA_EXCEPTION = GetModNodePtr(hModBase, ".pdata", &PDATA_EXCEPTION_SIZE);

		 LOG_DEBUG("Exception <%p><%08X><%p><%08X>\n", hModBase, hModSize, PDATA_EXCEPTION, PDATA_EXCEPTION_SIZE);




		 // NT 头
		 //PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((char *)MappedBase + pDos->e_lfanew);
		 // 入口点
		// pEntyPoint = (ULONG64)(pNtHeader->OptionalHeader.AddressOfEntryPoint + (char*)hModDriver);

		// sizeof(IMAGE_DOS_HEADER)

		 LOG_DEBUG("LoadDriver Size: <%p><%p>", hAttchModDriver, nSize);





		 LARGE_INTEGER TimesN;
		 KeQuerySystemTime(&TimesN);
		 ModSgin = TimesN.QuadPart / 1000000;


		// vSgin = time(0);




		 //PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(hModDriver);
		// pDos->e_magic = 0;

		//RtlZeroMemory((DWORD64)hModDriver + sizeof(IMAGE_DOS_HEADER), pDos->e_lfanew - sizeof(IMAGE_DOS_HEADER));//sizeof(IMAGE_DOS_HEADER) - 4
		// RtlZeroMemory((DWORD64)hModDriver, PAGE_SIZE);//sizeof(IMAGE_DOS_HEADER) - 4

		LOG_DEBUG("ModSgin<%08X>\n", ModSgin);
		//for (DWORD Sgin = 0; Sgin < (PAGE_SIZE / 0x20); Sgin++) {
		//	_hEncrypt_DEC(ModSgin + Sgin, (DWORD64)hModBase + 0x20 * Sgin, 0x20);
		//}

		 DWORD64 sysDLD = Ldr->DllBase;
		 for (DWORD64 iPtr = 0; iPtr < nSize; iPtr += 0x1000)
		 {
			 MMPTE * pNew = GetAddressPfn((ULONGLONG)hModDriver + iPtr);
			 MMPTE* pOld = GetAddressPfn(sysDLD + iPtr);

			 if (!pNew || !pOld){
				 LOG_DEBUG("出现了一个巨大的异常\n");
				 return;
			 }
			 

			 MMPTE NewNow = *pNew;
			 NewNow.u.Hard.NoExecute = pOld->u.Hard.NoExecute;

			 if (NewNow.u.Hard.NoExecute == 0)
			 {
				 NewNow.u.Hard.Write = 0;
				 NewNow.u.Hard.Writable = 0;
			 }
			 else
			 {
				 NewNow.u.Hard.Write = pOld->u.Hard.Write;
				 NewNow.u.Hard.Writable = pOld->u.Hard.Writable;
			 }
			// NewNow.u.Hard.SoftwareWsIndex = 160;

			 //NewNow.u.Hard.Valid = 0;

			 *pNew = NewNow;
			 __invlpg(pNew);
			 


			// LOG_DEBUG("set MPTE <%08X> <%p>", iPtr, NewNow.u.Long);

		 }

		 LOG_DEBUG("hModDriver %I64X  pEntyPoint %I64X  Object<%p>  Size<%p>\n", hModDriver, pEntyPoint, Ldr->DllBase, nSize);

		 if (hModDriver == 0)
		 {

			 return;

		 }

		 ExFreePoolWithTag(pFileBuffer, 'Tag');


		 //if (RtlInsertInvertedFunctionTable != 0)
		 //{
			// RtlInsertInvertedFunctionTable(hModDriver, nSize);
		 //}


		 RELOAD_INFO* pReload = ExAllocatePoolWithTag(PagedPool, sizeof(RELOAD_INFO), 'Tag');

		 pReload->Driver = Driver;
		 pReload->SectionObject = SectionObject;
		 pReload->DllBase = hModDriver;
		 pReload->hModBase = hModDriver;
		 pReload->hModSize = nSize;
		 pReload->PDATA_EXCEPTION = PDATA_EXCEPTION;
		 pReload->PDATA_EXCEPTION_SIZE = PDATA_EXCEPTION_SIZE;
		 pReload->ModSgin = ModSgin;
		 pReload->RtlRemoveInvertedFunctionTable = RtlRemoveInvertedFunctionTable;
		 pReload->RtlInsertInvertedFunctionTable = RtlInsertInvertedFunctionTable;
		 pEntyPoint((PDRIVER_OBJECT)((DWORD64)pReload | 1), RegistryPath);





		 


		// 
//		if (pMmAcquireLoadLock != 0)
//		{
//
//
//			//char* NtCreateE = NtCreateEvent;
//
//
//			//_ObCreateObjectEx ObCreateObjectEx = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(NtCreateE, 1));
//			//_ObInsertObjectEx  ObInsertObjectEx = _CODE_GET_REAL_ADDRESS(_ASM_GET_CALL(NtCreateE, 1));
//
//
//			//LOG_DEBUG("ObCreateObjectEx %I64X  ObInsertObjectEx %I64X\n", ObCreateObjectEx, ObInsertObjectEx);
//
//
//			wchar_t pszDest[64];
//			RtlStringCchPrintfW(pszDest, 0x3C, L"\\Driver\\%wZ", uszDriverString);
//
//
//			//ObCreateObjectEx(0, *IoDriverObjectType,)
//
//			
//			//return;
//
//
//
//
//			//RemoveFlushDpcTimer();
//
//			PVOID Lock = pMmAcquireLoadLock();
//			RtlInsertInvertedFunctionTable(hModDriver, nSize);
//
//
//
//
//
//			//RtlRemoveInvertedFunctionTable(hAttchModDriver);
//			//RtlInsertInvertedFunctionTable(hAttchModDriver, nSize + ((ULONGLONG)hModDriver - (ULONGLONG)hAttchModDriver));
//			
//
//
//			//LOG_DEBUG("PsInvertedFunctionTableV Size  %d\n", PsInvertedFunctionTableV[0]);
//			//for (size_t i = 0; i < PsInvertedFunctionTableV[0]; i++)
//			//{
//
//			//	ULONGLONG BaseMod = *((ULONGLONG*)&PsInvertedFunctionTableV[2 * i * 3 + 6]);
//
//			//	ULONG  nSize = *((ULONG*)&PsInvertedFunctionTableV[2 * i * 3 + 8]);
//			//	//
//			//	if (BaseMod == hAttchModDriver)
//			//	{
//			//		LOG_DEBUG("Now %d   <%p><%08X>\n", i, BaseMod, nSize);
//			//		*((ULONG*)&PsInvertedFunctionTableV[2 * i * 3 + 8]) = nSize + ((ULONGLONG)hModDriver - (ULONGLONG)hAttchModDriver);
//			//		nSize = *((ULONG*)&PsInvertedFunctionTableV[2 * i * 3 + 8]);
//			//		LOG_DEBUG("New %d   <%p><%08X>\n", i, BaseMod, nSize);
//			//		break;
//			//	}
//
//
//			//}
//
//			pMmReleaseLoadLock(Lock);
//
//
//
////#ifndef DEBUG
//			//char ZeroMemoryCopy[0x100] = { 0 };
//			//char ZeroMemory[0x100] = { 0 };
//
//			//RtlCopyMemory(ZeroMemoryCopy, hModDriver, 0x100);
//			//KIRQL irql = KeGetCurrentIrql();
//			//if (irql >= DISPATCH_LEVEL) {
//			//	KeLowerIrql(PASSIVE_LEVEL);//  __writecr8(PASSIVE_LEVEL);
//			//}
//			//if (!writeSafeMemory(hModDriver, ZeroMemory, sizeof(IMAGE_DOS_HEADER) - 4/*sizeof(IMAGE_DOS_HEADER)*/))
//			//	LOG_DEBUG("writeSafeMemory FALSE  Ldr->DllBase  %I64X   \n", hModDriver);
//			//__writecr8(irql);
////#endif // !DEBUG
//
//
//			//hookShow(RegistryPath);
//		//	OBJECT_ATTRIBUTES attr;
//		//	InitializeObjectAttributes(&attr, &ImagePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_PERMANENT, NULL, NULL);
//	
//		//	ULONG64 out = 0;
//		//	PDRIVER_OBJECT  DriverObject = 0;
//		//	status = ObCreateObject(KernelMode,
//		//		*IoDriverObjectType,
//		//		&attr,// POBJECT_ATTRIBUTES
//		//		0,
//		//		&out,//这个是一个ULONG64 类型 没啥用
//		//		0x1A0,
//		//		0,
//		//		0,
//		//		&DriverObject);//返回新的 DriverObject);
//		//	//result = ObCreateObjectEx(0, IoDriverObjectType, (int)v25, 0, (__int64)Object, 416, 0, 0, &DmaAdapter, 0i64);
//
//
//		//
//		////	MmCreateSection()
//
//		//	if (!NT_SUCCESS(status))
//		//	{
//		//		LOG_DEBUG("error %08X\n", status);
//		//		return;
//		//	}
//
//
//
//		//	LOG_DEBUG(" ObCreateObject Sucess  %I64X\n", DriverObject);
//
//		//	//return;
//		//	DriverObject->Flags = 4;
//		//	DriverObject->DriverExtension = &DriverObject[1];
//		//	DriverObject->Type = 4;
//		//	DriverObject->Size = 0x150;
//		//	DriverObject->DriverSize = nSize;
//		//	DriverObject->DriverSection = 0;
//		//	DriverObject->DriverStart = hModDriver;
//
//		//	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
//		//	{
//		//		DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)IopInvalidDeviceRequest;
//		//	}
//			//memset64(DriverObject->MajorFunction, (unsigned __int64)&IopInvalidDeviceRequest, 0x1Cui64);
//
//			//DriverObject->DriverInit = pEntyPoint;
//
//			//status = STATUS_ABANDONED;
//			//HANDLE hHandle = 0;
//			//status = ObInsertObject(DriverObject, 0i64, 1i64, 0, 0i64, &hHandle);
//			//if (!NT_SUCCESS(status)){
//			//	LOG_DEBUG("error %08X\n", status);
//			//	return;
//			//}
//
//
//			//ULONG stack_base, stack_limit;
//			//EXECUTIVE executive;
//
//			//// 获取当前线程的栈信息
//			//KeQueryCurrentStackInformation(&executive, &stack_base, &stack_limit);
//			
//
//
//			//RtlZeroMemory(hModDriver, sizeof(IMAGE_DOS_HEADER) - 4);
//
//
//
//
//
//
//
//
//			//HANDLE thread_handle;
//			//NTSTATUS r = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, (PKSTART_ROUTINE)ReloadEntryPoint, RegistryPath);
//
//
//			//E00010
//		}
//		else
//		{
//		//LOG_DEBUG("PsInvertedFunctionTableV Size  %d\n", PsInvertedFunctionTableV[0]);
//		//for (size_t i = 0; i < PsInvertedFunctionTableV[0]; i++)
//		//{
//
//		//	ULONGLONG BaseMod = *((ULONGLONG*)&PsInvertedFunctionTableV[2 * i * 3 + 6]);
//
//		//	ULONG  nSize = *((ULONG*)&PsInvertedFunctionTableV[2 * i * 3 + 8]);
//		//	//LOG_DEBUG("%d   <%p><%08X>\n", i, BaseMod, nSize);
//		//	if (BaseMod == hAttchModDriver)
//		//	{
//		//		*((ULONG*)&PsInvertedFunctionTableV[2 * i * 3 + 8]) = nSize + ((ULONGLONG)hModDriver - (ULONGLONG)hAttchModDriver);
//		//		nSize = *((ULONG*)&PsInvertedFunctionTableV[2 * i * 3 + 8]);
//		//		LOG_DEBUG("%d   <%p><%08X>\n", i, BaseMod, nSize);
//		//		break;
//		//	}
//
//
//		//}
//		  //RemoveFlushDpcTimer();
//		
//		  //RtlRemoveInvertedFunctionTable(hAttchModDriver);
//		  //RtlInsertInvertedFunctionTable(hAttchModDriver, nSize + ((ULONGLONG)hModDriver - (ULONGLONG)hAttchModDriver));
//		  RtlInsertInvertedFunctionTable(hModDriver, nSize);
//		 // RtlZeroMemory(hModDriver, 0x100);
//		 // RtlInsertInvertedFunctionTable(hAttchModDriver, nSize + ((ULONGLONG)hModDriver - (ULONGLONG)hAttchModDriver));
//		 
//		  
////#ifndef DEBUG
////char ZeroMemoryCopy[0x100] = { 0 };
////char ZeroMemory[0x100] = { 0 };
//		 // RtlZeroMemory(hModDriver, sizeof(IMAGE_DOS_HEADER) - 4);
//		  //RtlCopyMemory(ZeroMemoryCopy, hModDriver, 0x100);
//		  //KIRQL irql = KeGetCurrentIrql();
//		  //if (irql >= DISPATCH_LEVEL) {
//			 // KeLowerIrql(PASSIVE_LEVEL);//  __writecr8(PASSIVE_LEVEL);
//		  //}
//		  //if (!writeSafeMemory(hModDriver, ZeroMemory, sizeof(IMAGE_DOS_HEADER) - 4/*sizeof(IMAGE_DOS_HEADER)*/))
//			 // LOG_DEBUG("writeSafeMemory FALSE  Ldr->DllBase  %I64X   \n", hModDriver);
//		  //__writecr8(irql);
////#endif // !DEBUG
//		  
//		  pEntyPoint( (PDRIVER_OBJECT)((DWORD64)Driver | 1), RegistryPath);
//
//
//
//
//
//
//		}
		




		//sizeof(MMPTE_TEST0)




		//for (DWORD64 iPtr = hModDriver; iPtr < ((DWORD64)hModDriver + nSize); iPtr += 0x1000)
		//{
		//	DWORD64 PLM4[4] = { 0 };
		//	MiFillPteHierarchy((ULONGLONG)iPtr, PLM4);
		//	RELOAD_HIDE_MEMORY(iPtr);
		//	BOOLEAN uFun = TRUE;
		//	int i = 4;
		//	do
		//	{
		//		i--;
		//		//MMPTE pCurMM = *(MMPTE*)PLM4[i];
		//		RELOAD_HIDE_MEMORY(PLM4[i]);
		//	} while (i > 0);
		//}



		//RtlCopyMemory









	}


	extern VOID wSleep(LONG msec);


	PCUNICODE_STRING DriverServiceName;

	_Kernel_entry_ NTSTATUS __stdcall NtUnloadDriver(PUNICODE_STRING DriverServiceName);



	//BOOL DeviceDosPathToNtPath(wchar_t* pDosPath, wchar_t* pNtPath)
	//{
	//	static TCHAR    DriveStr[MAX_PATH] = { 0 };
	//	static TCHAR    DevName[MAX_PATH] = { 0 };
	//	TCHAR           Drive[3];
	//	INT             cchDevName;
	//	INT             i = 0;
	//	//检查参数  
	//	if (IsBadReadPtr(pDosPath, 1) != 0)return FALSE;
	//	if (IsBadWritePtr(pNtPath, 1) != 0)return FALSE;

	//	if (!lstrcmpi(pDosPath, _T("A:\\")) || !lstrcmpi(pDosPath, _T("B:\\")))
	//		return FALSE;

	//	Drive[0] = pDosPath[i];
	//	Drive[1] = pDosPath[i + 1];
	//	Drive[2] = '\0';
	//	if (!QueryDosDevice(Drive, DevName, MAX_PATH))//查询设备名，这里是重点
	//		return FALSE;
	//	cchDevName = lstrlen(DevName);
	//	lstrcpy(pNtPath, DevName);//复制设备名  
	//	lstrcat(pNtPath, pDosPath + 2);//复制路径  
	//	return TRUE;
	//}

	DWORD  QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax) {


		UNICODE_STRING BasePath;
		RtlInitUnicodeString(&BasePath, L"\\??");

		HANDLE FileHandle = 0;

		OBJECT_ATTRIBUTES ObjectAttributes;

		InitializeObjectAttributes(
			&ObjectAttributes,
			&BasePath,
			OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		NTSTATUS status = ZwOpenDirectoryObject(&FileHandle, 1, &ObjectAttributes);
		if (!NT_SUCCESS(status))
		{
			LOG_DEBUG("NtOpenDirectoryObject error  %08X\n", status);
			return status;
		}

		UNICODE_STRING DeviceName;
		RtlInitUnicodeString(&DeviceName, lpDeviceName);
		OBJECT_ATTRIBUTES ObjectAttributesDevice;
		InitializeObjectAttributes(
			&ObjectAttributesDevice,
			&DeviceName,
			OBJ_KERNEL_HANDLE,
			FileHandle,
			NULL);


		HANDLE SymbolicLinkHandle = 0;
		status = ZwOpenSymbolicLinkObject(&SymbolicLinkHandle, 1u, &ObjectAttributesDevice);

		if (!NT_SUCCESS(status))
		{
			LOG_DEBUG("ZwOpenSymbolicLinkObject error  %08X  %wZ\n", status, &DeviceName);
			ZwClose(FileHandle);
			return status;
		}

		UNICODE_STRING NtNamePath;
		NtNamePath.Buffer = lpTargetPath;
		NtNamePath.Length = 0;
		NtNamePath.MaximumLength = ucchMax * 2;
		ULONG nSize = 0;
		status = ZwQuerySymbolicLinkObject(SymbolicLinkHandle, &NtNamePath, &nSize);

		LOG_DEBUG("ZwQuerySymbolicLinkObject error  %08X  %wZ\n", status, &DeviceName);

		ZwClose(SymbolicLinkHandle);
		ZwClose(FileHandle);
		return 0;
	}


	BOOL DeviceDosPathToNtPath(wchar_t* pDosPath, wchar_t* pNtPath)
	{
		wchar_t    DriveStr[MAX_PATH] = { 0 };
		wchar_t    DevName[MAX_PATH] = { 0 };
		wchar_t           Drive[3];
		INT             cchDevName;
		INT             i = 0;
		//检查参数  

		Drive[0] = pDosPath[i];
		Drive[1] = pDosPath[i + 1];
		Drive[2] = '\0';
		if (!NT_SUCCESS(QueryDosDeviceW(Drive, DevName, MAX_PATH)))//查询设备名，这里是重点
		{
			return FALSE;
		}
																   //cchDevName = lstrlen(DevName);
		RtlStringCbPrintfW(pNtPath, MAX_PATH * 2, L"%s%s", DevName, pDosPath + 2);
		//lstrcpy(pNtPath, DevName);//复制设备名  
		//lstrcat(pNtPath, pDosPath + 2);//复制路径  
		return TRUE;
	}


	typedef	struct _UnLoader_FN {
		KEVENT UnLoadEvent;
		LPCWSTR str;
	}UnLoader_FN;


	void UnLoadDriver_Mother(void *arg) {

		UnLoader_FN* UnLoaderL = (UnLoader_FN*)arg;

		UNICODE_STRING ImagePath = { 0 };
		UNICODE_STRING uString;
		RtlInitUnicodeString(&uString, (LPCWSTR)UnLoaderL->str);

		HANDLE hKey = 0;
		OBJECT_ATTRIBUTES oa = { 0 };
		InitializeObjectAttributes(&oa, &uString, OBJ_KERNEL_HANDLE, NULL, NULL);
		NTSTATUS ntStatus = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
		if (NT_SUCCESS(ntStatus))
		{

			UNICODE_STRING A, B, C, D;
			PKEY_VALUE_PARTIAL_INFORMATION bufA, bufB, bufC, bufD;
			ULONG ActualSize;

			PVOID pImagePath = ExAllocatePoolWithTag(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, 'tag');
			bufA = (PKEY_VALUE_PARTIAL_INFORMATION)pImagePath;
			RtlInitUnicodeString(&A, L"ImagePath");
			if (ntStatus == STATUS_SUCCESS) {
				ntStatus = ZwQueryValueKey(hKey, &A, KeyValuePartialInformation, bufA, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, &ActualSize);
				if (ntStatus != STATUS_SUCCESS) {
					ExFreePoolWithTag(bufA, 'tag');
				}
			}
			if (ntStatus == STATUS_SUCCESS) {

				RtlInitUnicodeString(&ImagePath, (PCWSTR)bufA->Data + ((sizeof(L"\\??\\")) / 2 - 1));//
				//IoVolumeDeviceToDosName()

				//UNICODE_STRING 
			}
			LOG_DEBUG("ImagePath:%wZ \n", &ImagePath);
			//ZwDeleteKey(hKey);
			ZwClose(hKey);
		}
		//ExFreePoolWithTag(arg, 'Tag');
		//wSleep(2000);



		NTSTATUS status = 0;
		int i = 0;
		do
		{
			LOG_DEBUG("ZwUnloadDriver");
			status = ZwUnloadDriver(&uString);
			LOG_DEBUG("ZwUnloadDriver  %08X   %wZ", status, &uString);
			i++;
			if (i > 10) {
				break;
			}
			wSleep(10);
		} while (!NT_SUCCESS(status));


		InitializeObjectAttributes(&oa, &uString, OBJ_KERNEL_HANDLE, NULL, NULL);
		ntStatus = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
		if (NT_SUCCESS(ntStatus))
		{
		//	ZwDeleteKey(hKey);
			ZwClose(hKey);
		}
		ExFreePoolWithTag(arg, 'Tag');

		wchar_t NtPath[MAX_PATH] = { 0 };
		DeviceDosPathToNtPath(ImagePath.Buffer, NtPath);

		UNICODE_STRING uPath;
		RtlInitUnicodeString(&uPath, NtPath);
		LOG_DEBUG("NtPath:%wZ \n", &uPath);
		ForceDeleteFile(NtPath);
		//KeSetEvent(&UnLoaderL->UnLoadEvent, LOW_PRIORITY, FALSE);

	}


	void DeleteDriverFile(void* arg) {

		UNICODE_STRING ImagePath = { 0 };


		UNICODE_STRING uString;
		RtlInitUnicodeString(&uString, (LPCWSTR)arg);

		HANDLE hKey = 0;
		OBJECT_ATTRIBUTES oa = { 0 };
		InitializeObjectAttributes(&oa, &uString, OBJ_KERNEL_HANDLE, NULL, NULL);
		NTSTATUS ntStatus = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
		if (NT_SUCCESS(ntStatus))
		{

			UNICODE_STRING A, B, C, D;
			PKEY_VALUE_PARTIAL_INFORMATION bufA, bufB, bufC, bufD;
			ULONG ActualSize;

			PVOID pImagePath = ExAllocatePoolWithTag(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, 'tag');
			bufA = (PKEY_VALUE_PARTIAL_INFORMATION)pImagePath;
			RtlInitUnicodeString(&A, L"ImagePath");
			if (ntStatus == STATUS_SUCCESS) {
				ntStatus = ZwQueryValueKey(hKey, &A, KeyValuePartialInformation, bufA, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 100, &ActualSize);
				if (ntStatus != STATUS_SUCCESS) {
					ExFreePoolWithTag(bufA, 'tag');
				}
			}
			if (ntStatus == STATUS_SUCCESS) {

				RtlInitUnicodeString(&ImagePath, (PCWSTR)bufA->Data + ((sizeof(L"\\??\\")) / 2 - 1));//
				//IoVolumeDeviceToDosName()

				//UNICODE_STRING 
			}
			LOG_DEBUG("ImagePath:%wZ \n", &ImagePath);
			//ZwDeleteKey(hKey);
			ZwClose(hKey);
		}
		//ExFreePoolWithTag(arg, 'Tag');

		InitializeObjectAttributes(&oa, &uString, OBJ_KERNEL_HANDLE, NULL, NULL);
		ntStatus = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
		if (NT_SUCCESS(ntStatus))
		{
			ZwDeleteKey(hKey);
			ZwClose(hKey);
		}
		ExFreePoolWithTag(arg, 'Tag');

		wchar_t NtPath[MAX_PATH] = { 0 };
		DeviceDosPathToNtPath(ImagePath.Buffer, NtPath);

		UNICODE_STRING uPath;
		RtlInitUnicodeString(&uPath, NtPath);
		LOG_DEBUG("NtPath:%wZ \n", &uPath);
		ForceDeleteFile(NtPath);
	}


	typedef struct _WORK_INFO
	{
		BOOLEAN bSucess;
		KEVENT Notify;
		WORK_QUEUE_ITEM Worker;
		HANDLE hPID;
	}WORK_INFO;


	void NewDriverObjectWork(void * arg) {

		wchar_t* pszDestDriver = (wchar_t *)ExAllocatePoolWithTag(PagedPool, 260, 'Tag');
		RtlZeroMemory(pszDestDriver, 260);
		RtlStringCchPrintfW(pszDestDriver, 256, L"\\Driver\\%wZR", &uszDriverString);

		UNICODE_STRING ByString;
		RtlInitUnicodeString(&ByString, pszDestDriver);

		LOG_DEBUG("  pszDestDriver  %wZ ", &ByString);

		PDRIVER_OBJECT DriverObject = 0;

		OBJECT_ATTRIBUTES Attributes;
		InitializeObjectAttributes(&Attributes, &ByString, OBJ_KERNEL_HANDLE | OBJ_PERMANENT, 0, 0);
		NTSTATUS   ntStatus = ObCreateObject(ExGetPreviousMode(), *IoDriverObjectType, &Attributes, 0, 0, 0x1A0, 0, 0, (PVOID *)&DriverObject);
		if (!NT_SUCCESS(ntStatus)) {

			LOG_DEBUG(" Can't Create Object  %08X\n", ntStatus);
			return ;
		}
		RtlZeroMemory(DriverObject, 0, 0x1A0);

		DriverObject->DriverExtension = (PDRIVER_EXTENSION)&DriverObject[1];
		for (size_t i = 0; i < 0x1C; i++) {
			DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)&IopInvalidDeviceRequest;
		}
		DriverObject->Type = 4;
		DriverObject->Size = 0x150;

		//DriverObject->DriverInit = &DriverEntry;

		*(DWORD64*)(&DriverObject[1]) = (DWORD64)DriverObject;

		//sizeof(DRIVER_OBJECT)

		RtlInitUnicodeString(&DriverObject->DriverName, pszDestDriver);


		HANDLE Handle = 0;
		LOG_DEBUG("0 ObInsertObject Object Error Work %08X\n", ntStatus);
		ntStatus = ObInsertObject(DriverObject, 0, 1, 0, 0, &Handle);
		if (!NT_SUCCESS(ntStatus)) {

			LOG_DEBUG(" ObInsertObject Object Error Work %08X\n", ntStatus);
		}
		WORK_INFO* pWorkInfo = (WORK_INFO *)arg;
		pWorkInfo->hPID = DriverObject;
		KeSetEvent(&pWorkInfo->Notify, LOW_PRIORITY, FALSE);

	}


	int FilterEX(EXCEPTION_POINTERS* Info) {

		LOG_DEBUG(" Filter Base  kernelBase + %08X\n", Info->ContextRecord->Rip - kernelBase);

		return 1;
	}


	//__int64 __fastcall MiAllocateTempLoaderEntry(__int64 a1)
	//{
	//	__int64 result; // rax

	//	result = (__int64)MiAllocatePool(64, 0xA0i64, 1682730317i64);
	//	if (result)
	//	{
	//		*(dword*)(result + 0x70) = a1;
	//		*(_WORD*)(result + 0x6C) = 1;
	//		*(_DWORD*)(result + 0x68) = 0x1000000;
	//		*(_QWORD*)(result + 0x88) = -2i64;
	//	}
	//	return result;
	//}



	PDRIVER_OBJECT NewDriverObject(PDRIVER_OBJECT  DriverReal, RELOAD_INFO* pReload) {

		if (IoGetCurrentProcess() == PsInitialSystemProcess)
		{
			wchar_t* pszDestDriver = (wchar_t *)ExAllocatePoolWithTag(PagedPool, 260, 'Tag');
			RtlZeroMemory(pszDestDriver, 260);
			RtlStringCchPrintfW(pszDestDriver, 256, L"\\Driver\\%wZR", &uszDriverString);


			UNICODE_STRING ByString;
			RtlInitUnicodeString(&ByString, pszDestDriver);

			LOG_DEBUG("  pszDestDriver  %wZ ", &ByString);

			PDRIVER_OBJECT DriverObject = 0;

			OBJECT_ATTRIBUTES Attributes;
			InitializeObjectAttributes(&Attributes, &ByString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, 0, 0);


			

			NTSTATUS   ntStatus = ObCreateObject(ExGetPreviousMode(), *IoDriverObjectType, &Attributes, 0, 0, 0x1A0, 0, 0, (PVOID *)&DriverObject);

			//PFILE_OBJECT FileObject = 0;

			//ntStatus = ObCreateObject(ExGetPreviousMode(), *IoFileObjectType, &Attributes, 0, 0, 0x1A0, 0, 0, (PVOID *)&FileObject);

			if (!NT_SUCCESS(ntStatus)) {

				LOG_DEBUG(" Can't Create Object %08X \n", ntStatus);
				return STATUS_SUCCESS;
			}
			RtlZeroMemory(DriverObject, 0, 0x1A0);

			RtlCopyMemory(DriverObject, DriverReal, 0x1A0);


			DriverObject->DriverExtension = (PDRIVER_EXTENSION)&DriverObject[1];
			*(DWORD64*)&DriverObject[1].Type = (DWORD64)DriverObject;

			for (size_t i = 0; i < 0x1C; i++) {
				DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)&IopInvalidDeviceRequest;
			}
		    *(DWORD *)(&DriverObject->Type) = 0x1500004;

			PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)RtlImageNtHeader(pReload->DllBase);
			if ((pNt->OptionalHeader.DllCharacteristics & 0x2000) == 0)
				DriverObject->Flags |= 2u;

			DriverObject->DriverInit = (int(__fastcall*)(DRIVER_OBJECT*, UNICODE_STRING*))((char*)pReload->DllBase
				+ pNt->OptionalHeader.AddressOfEntryPoint);

			DriverObject->DriverSection = pReload->SectionObject;
			DriverObject->DriverStart = pReload->DllBase;
			DriverObject->DriverSize = pNt->OptionalHeader.SizeOfImage;

			HANDLE Handle = 0;
			//LOG_DEBUG("0 ObInsertObject Object Error Work %08X\n", ntStatus);

			ntStatus = ObInsertObject(DriverObject, 0, 1, 0, 0, &Handle);
			if (!NT_SUCCESS(ntStatus)) {

				LOG_DEBUG(" ObInsertObject Object Error %08X\n", ntStatus);
			}
			else
			{

				//v22 = Handle;

				PVOID Object = 0;

				ntStatus = ObReferenceObjectByHandle(
					Handle,
					0,
					*IoDriverObjectType,
					ExGetPreviousMode(),
					&Object,
					0);
				ZwClose(Handle);

				LOG_DEBUG(" Create Object Sucess Object Sucess\n");

			}
			//__try
			//{

			//}
			//__except (FilterEX(GetExceptionInformation())) {

			//	LOG_DEBUG(" ObInsertObject __except Error %08X\n", GetExceptionCode());
			//}


			return DriverObject;
		}
		else
		{

		     LOG_DEBUG("NoWork\n");

			//WORK_INFO gWorkInfo;

			//KEVENT Notify;
			//KeInitializeEvent(&gWorkInfo.Notify, SynchronizationEvent, FALSE);

			//ExInitializeWorkItem(&gWorkInfo.Worker, NewDriverObjectWork, &gWorkInfo);

			//ExQueueWorkItem(&gWorkInfo.Worker, CriticalWorkQueue);

			//KeWaitForSingleObject(
			//	&Notify,
			//	Executive,
			//	KernelMode,
			//	FALSE,
			//	NULL);

			//return (PDRIVER_OBJECT)gWorkInfo.hPID;

		}


		return 0;

	}







	extern BOOLEAN NTAPI SetPtrWriteable(PVOID Ptr);

	extern BOOLEAN NTAPI SetPtrNoWrite(PVOID Ptr);



	extern DWORD64 KernelBaseSize;


	void FlushTlbPtr(PVOID Ptr) {
		KIRQL irql = KeGetCurrentIrql();
		WriteCR8(HIGH_LEVEL);
		__invlpg(Ptr);
		WriteCR8(irql);
	}


	void NTAPI _Mod_Encrypt_Header(){
		SetPtrWriteable(hModBase);
		for (DWORD Sgin = 0; Sgin < (PAGE_SIZE / 0x20); Sgin++) {
			_hEncrypt_DEC(ModSgin + Sgin, (DWORD64)hModBase + 0x20 * Sgin, 0x20);
		}
		SetPtrNoWrite(hModBase);
	}









	// NtSetSystemTime


	NTSTATUS DriverEntry(
		_In_ PDRIVER_OBJECT  Driver,
		_In_ PUNICODE_STRING RegistryPath)
	{
		PAGED_CODE();
		UNREFERENCED_PARAMETER(Driver);
		UNREFERENCED_PARAMETER(RegistryPath);




#ifdef RELOAD_IMAGE

		if (((DWORD64)Driver & 1) == 0)
		{
			LOG_DEBUG("Driver  %I64X\n", Driver);

			//gDevObj = (PDEVICE_OBJECT)Driver;
			//gDevObj->Flags |= DO_BUFFERED_IO;

			Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIrpCtl;
			Driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;    // 创建成功派遣函数
			Driver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;      // 关闭派遣函数

			Driver->DriverUnload = DriverUnload;





		

			//NtCreateSection()


			//hookShow(Driver);

			getKeServiceDescriptorTable7_10();


			LOG_DEBUG("Driver  %I64X\n", Driver);

			ReloadSelf(Driver, RegistryPath);


			//IniRegistryPath(RegistryPath);
			//IniLinkMsg(Driver);

			return STATUS_SUCCESS;
		}



		RELOAD_INFO* pReload = (RELOAD_INFO*)((DWORD64)Driver - 1);


		hModBase = pReload->hModBase;
		hModSize = pReload->hModSize;
	    PDATA_EXCEPTION = pReload->PDATA_EXCEPTION;
		PDATA_EXCEPTION_SIZE = pReload->PDATA_EXCEPTION_SIZE;
		ModSgin = pReload->ModSgin;


		RtlRemoveInvertedFunctionTable = pReload->RtlRemoveInvertedFunctionTable;
		RtlInsertInvertedFunctionTable = pReload->RtlInsertInvertedFunctionTable;


	//	MMPTE* pMpte = GetAddressPfn(hModBase);
	//	MMPTE OLD_PTE = *pMpte;

	//	pMpte->u.Hard.Write = 1;
	////	pMpte->u.Hard.Writable = 1;
	////	pMpte->u.Hard.WriteThrough = 1;
	//	FlushTlbPtr(pMpte);
	//	//__invlpg(pMpte);


		_Mod_Encrypt_Header();

		//*pMpte = OLD_PTE;
		//FlushTlbPtr(pMpte);
		//__invlpg(pMpte);

		PDRIVER_OBJECT  DriverReal = pReload->Driver;
		LOG_DEBUG("Driver  %I64X\n", DriverReal);



#else


		Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIrpCtl;
		Driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;    // 创建成功派遣函数
		Driver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;      // 关闭派遣函数

		Driver->DriverUnload = DriverUnload;


#endif // RELOAD_IMAGE





		NTSTATUS        ntStatus;







		__try
		{

			getKeServiceDescriptorTable7_10();

			IniRegistryPath(RegistryPath);








			

			
			//RtlZeroMemory(&EAC_HOOK, sizeof(EAC_HOOK));
			//for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
			//	EAC_HOOK.NewMajorFunction[i] = EACDispatchCtl;
			//}

			////Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIrpCtl;
			//EAC_HOOK.NewMajorFunction[IRP_MJ_CREATE] = DispatchCreate;    // 创建成功派遣函数
			//EAC_HOOK.NewMajorFunction[IRP_MJ_CLOSE] = DispatchClose;      // 关闭派遣函数
			//EAC_HOOK.NewMajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIrpCtl;

			//PDRIVER_OBJECT  pDriverObj = 0;
			//if (GetDriverObjectByName(&pDriverObj, L"\\Driver\\Null")){
			//	START_HOOK_DRIVER(pDriverObj, &EAC_HOOK);
			//	LOG_DEBUG("Driver Null  HOOK\n");
			//	UNICODE_STRING NullString = RTL_CONSTANT_STRING(L"Null");
			//	IniLinkMsgString(pDriverObj, &NullString);
			//	IniLinkMsg(Driver);
			//}



			//DRIVER_OBJECT DriverValue = { 0 };
			//RtlCopyMemory(&DriverValue, DriverReal, sizeof(DRIVER_OBJECT));

			//PDRIVER_OBJECT DriverObject = NewDriverObject(&DriverValue, pReload);

			

			//if (DriverObject != 0){
			//	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIrpCtl;
			//	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;    // 创建成功派遣函数
			//	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;      // 关闭派遣函数
			//	DriverObject->DriverUnload = DriverUnload;
			//	IniLinkMsgR(DriverObject);
			//}


			

		//	LOG_DEBUG("1111111111111111111111111111");
//#ifndef USE_NT_MSG
			
//#endif // !USE_NT_MSG


		//	LOG_DEBUG("1111111111111111111111111111");
			//ULONG_PTR pDrvSection = (ULONG_PTR)Driver->DriverSection;
			//*(PULONG)(pDrvSection + 0x68) |= 0x20;

			//DriverObjectCreateByObRegisterCallbacks();




			
			
			IniFilterProcessEntry();

			//HANDLE thread_handle;
			//NTSTATUS r = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, hookShow, NULL);
			//LOG_DEBUG("2");
			
			hookShow(0);

			IniLinkMsg(Driver);
			//LOG_DEBUG("1");


#ifdef RELOAD_IMAGE

			 char* pszDest = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'Tag');

			 UnLoader_FN* pUnloder = pszDest;

			 KeInitializeEvent(&pUnloder->UnLoadEvent, SynchronizationEvent, FALSE);

			 pUnloder->str = pszDest + 0x200;
			 RtlStringCchPrintfW(pUnloder->str, 256, L"%wZ", RegistryPath);

			 HANDLE thread_handle;

			 NTSTATUS r = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, UnLoadDriver_Mother, pUnloder);

			 //NTSTATUS status = KeWaitForSingleObject(&pUnloder->UnLoadEvent, Executive, KernelMode, TRUE, NULL);

			 //if (!NT_SUCCESS(status))
			 //{
				// LOG_DEBUG("KeWaitForSingleObject  Error  %08X\n", status);
			 //}
			 //else
			 //{
				// LOG_DEBUG("KeWaitForSingleObject  sucess  %08X\n", status);
			 //}

			// ExFreePoolWithTag(pszDest, 'Tag');


			 //UNICODE_STRING FuncName;
			 //RtlInitUnicodeString(&FuncName, L"MmLoadSystemImage");
			 //_k_MmLoadSystemImage MmLoadSystemImage = (_k_MmLoadSystemImage)MmGetSystemRoutineAddress(&FuncName);

			 ////MmLoadSystemImage()




			 //ExInitializeWorkItem()



#else

			 IoRegisterDriverReinitialization(Driver, Reinitialize, NULL);

			 wchar_t* pszDest = ExAllocatePoolWithTag(PagedPool, 260 * 2, 'Tag');
			 if (pszDest != 0)
			 {
				 RtlStringCchPrintfW(pszDest, 256, L"%wZ", RegistryPath);
				 HANDLE thread_handle;
				 NTSTATUS r = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, DeleteDriverFile, pszDest);
			 }

#endif // RELOAD_IMAGE



			//KServer_Start(9999, hBufferSocket);
			//OFFSET()
			if (uszDriverString.Buffer != 0) {
				KServer_StartSign(*((DWORD*)uszDriverString.Buffer), hBufferSocket);
			}




			//HANDLE SectionHandle;
			//PVOID SectionObject = NULL;
			//PVOID MappingAddress = 0;
			//SIZE_T MappingSize = 0;
			//LARGE_INTEGER MaximumSize = { 0 };
			//MaximumSize.QuadPart = 0x1000;

			//NTSTATUS status = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

			//LOG_DEBUG("ZwCreateSection  %08X\n", status);
			//NTKERNELAPI POBJECT_TYPE MmSectionObjectType;
			//status = ObReferenceObjectByHandle(SectionHandle, SECTION_ALL_ACCESS, MmSectionObjectType, KernelMode, &SectionObject, NULL);

			////映射到session空间
		 //  // MmMapViewInSessionSpace(SectionObject, &MappingAddress, &MappingSize);
			//LOG_DEBUG("ObReferenceObjectByHandle  %08X\n", status);
			//status = MmMapViewInSystemSpace(SectionObject, &MappingAddress, &MappingSize);



			//DWORD64 PLM4[4] = { 0 };
			//MiFillPteHierarchy((ULONGLONG)MappingAddress, PLM4);

			//BOOLEAN uFun = TRUE;
			//int i = 4;
			//do
			//{
			//	i--;
			//	MMPTE pCurMM = *(MMPTE*)PLM4[i];
			//	MMPTE_TEST0 pCurMM0 = *(MMPTE_TEST0*)PLM4[i];
			//	//LOG_DEBUG("MMPTE %d  <%I64X>  Flags: %d\n", i, pCurMM.u.Long, pCurMM0.u.MPTE_T.Valid);
			//	if (pCurMM0.u.MPTE_T.Valid == 1) {
			//		pCurMM0.u.MPTE_T.Valid = 0;
			//		*(MMPTE_TEST0*)PLM4[i] = pCurMM0;
			//		__invlpg(PLM4[i]);
			//		LOG_DEBUG("SET MMPTE %d  <%I64X>  Flags: %d\n", i, pCurMM.u.Long, pCurMM0.u.MPTE_T.Valid);
			//	}
			//	if (pCurMM.u.Hard.LargePage != 0) {

			//		break;
			//	}


			//} while (i > 0);
		


			//MMPTE_PROTOTYPE
			







			//DISPATCH_LEVEL


		}
		__except (1) {
			
			
			LOG_DEBUG("Driver Load __except %08X\n",GetExceptionCode());


		}
		LOG_DEBUG("Driver Load Sucess\n");
		return STATUS_SUCCESS;
	
	}


	NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
	{
		UNREFERENCED_PARAMETER(pDevObj);
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		//LOG_DEBUG("派遣函数 IRP_MJ_CREATE 成功执行 !\n");
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
	{
		//PsSetCreateProcessNotifyRoutine
		//PsSetCreateProcessNotifyRoutine
		UNREFERENCED_PARAMETER(pDevObj);
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;

	}




	// 内核中获取 PEB 没有任何问题

	typedef PPEB(__stdcall* PFNPsGetProcessPeb)(PEPROCESS pEProcess);

	PPEB getPeb(PEPROCESS pEprocess)
	{
		//查找的函数名称  
		UNICODE_STRING uniFunctionName;
		RtlInitUnicodeString(&uniFunctionName, L"PsGetProcessPeb");
		PFNPsGetProcessPeb PsGetProcessPeb = (PFNPsGetProcessPeb)MmGetSystemRoutineAddress(&uniFunctionName);
		if (PsGetProcessPeb != NULL)
		{
			return PsGetProcessPeb(pEprocess);
		}
		return NULL;
	}


	//typedef  ULONG64 (NTAPI *OneParam)();

	//OneParam b_NtUserGetForegroundWindow = NULL;
	//
	//ULONGLONG OLD_SSDT_ADDRESS[4096];
	//PULONG OLD_TABLEBASE = 0;

	// 验证密文








	BOOLEAN Brother_Verification(LPIOINFO pValue) {

		LPMSGCOMMON Msg = (LPMSGCOMMON)pValue;
		if (_hEncrypt(wKey, &Msg->sgin, Msg->len - 8) == Msg->checknum)
		{
			_hEncrypt_DEC(wKey, &Msg->common, Msg->len - 12);
			return TRUE;
		}
		return FALSE;
	}




	//NTSTATUS
	//NtQueryVirtualMemory(
	//	IN HANDLE ProcessHandle,
	//	IN PVOID BaseAddress,
	//	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	//	OUT PVOID MemoryInformation,
	//	IN ULONG MemoryInformationLength,
	//	OUT PULONG ReturnLength OPTIONAL
	//)
	//
	///*++
	//Routine Description:
	//	This function provides the capability to determine the state,
	//	protection, and type of a region of pages within the virtual address
	//	space of the subject process.
	//	The state of the first page within the region is determined and then
	//	subsequent entries in the process address map are scanned from the
	//	base address upward until either the entire range of pages has been
	//	scanned or until a page with a nonmatching set of attributes is
	//	encountered. The region attributes, the length of the region of pages
	//	with matching attributes, and an appropriate status value are
	//	returned.
	//	If the entire region of pages does not have a matching set of
	//	attributes, then the returned length parameter value can be used to
	//	calculate the address and length of the region of pages that was not
	//	scanned.
	//Arguments:
	//	ProcessHandle - An open handle to a process object.
	//	BaseAddress - The base address of the region of pages to be
	//		queried. This value is rounded down to the next host-page-
	//		address boundary.
	//	MemoryInformationClass - The memory information class about which
	//		to retrieve information.
	//	MemoryInformation - A pointer to a buffer that receives the
	//		specified information.  The format and content of the buffer
	//		depend on the specified information class.
	//		MemoryBasicInformation - Data type is PMEMORY_BASIC_INFORMATION.
	//			MEMORY_BASIC_INFORMATION Structure
	//			ULONG RegionSize - The size of the region in bytes
	//				beginning at the base address in which all pages have
	//				identical attributes.
	//			ULONG State - The state of the pages within the region.
	//				State Values                        State Values
	//				MEM_COMMIT - The state of the pages within the region
	//					is committed.
	//				MEM_FREE - The state of the pages within the region
	//					is free.
	//				MEM_RESERVE - The state of the pages within the
	//					region is reserved.
	//			ULONG Protect - The protection of the pages within the
	//				region.
	//				Protect Values                        Protect Values
	//				PAGE_NOACCESS - No access to the region of pages is
	//					allowed. An attempt to read, write, or execute
	//					within the region results in an access violation
	//					(i.e., a GP fault).
	//				PAGE_EXECUTE - Execute access to the region of pages
	//					is allowed. An attempt to read or write within
	//					the region results in an access violation.
	//				PAGE_READONLY - Read-only and execute access to the
	//					region of pages is allowed. An attempt to write
	//					within the region results in an access violation.
	//				PAGE_READWRITE - Read, write, and execute access to
	//					the region of pages is allowed. If write access
	//					to the underlying section is allowed, then a
	//					single copy of the pages are shared. Otherwise,
	//					the pages are shared read-only/copy-on-write.
	//				PAGE_GUARD - Read, write, and execute access to the
	//					region of pages is allowed; however, access to
	//					the region causes a "guard region entered"
	//					condition to be raised in the subject process.
	//				PAGE_NOCACHE - Disable the placement of committed
	//					pages into the data cache.
	//			ULONG Type - The type of pages within the region.
	//				Type Values
	//				MEM_PRIVATE - The pages within the region are
	//					private.
	//				MEM_MAPPED - The pages within the region are mapped
	//					into the view of a section.
	//				MEM_IMAGE - The pages within the region are mapped
	//					into the view of an image section.
	//	MemoryInformationLength - Specifies the length in bytes  of
	//		the memory information buffer.
	//	ReturnLength - An optional pointer which, if specified,
	//		receives the number of bytes placed in the process
	//		information buffer.
	//Return Value:
	//	Returns the status
	//	TBS
	//Environment:
	//	Kernel mode.
	//--*/
	//{
	//	KPROCESSOR_MODE PreviousMode;
	//	PEPROCESS TargetProcess;
	//	NTSTATUS Status;
	//	PMMVAD Vad;
	//	BOOLEAN PteIsZero;
	//	PVOID Va;
	//	BOOLEAN Found;
	//	SIZE_T TheRegionSize;
	//	ULONG NewProtect;
	//	ULONG NewState;
	//	PVOID FilePointer;
	//	ULONG_PTR BaseVpn;
	//	MEMORY_BASIC_INFORMATION Info;
	//	LOGICAL Attached;
	//
	//	Found = FALSE;
	//	PteIsZero = FALSE;
	//
	//	//
	//	// Make sure the user's buffer is large enough for the requested operation.
	//	//
	//
	//	//
	//	// Check argument validity.
	//	//
	//	switch (MemoryInformationClass) {
	//	case MemoryBasicInformation:
	//		if (MemoryInformationLength < sizeof(MEMORY_BASIC_INFORMATION)) {
	//			return STATUS_INFO_LENGTH_MISMATCH;
	//		}
	//		break;
	//
	//	case MemoryWorkingSetInformation:
	//		if (MemoryInformationLength < sizeof(ULONG)) {
	//			return STATUS_INFO_LENGTH_MISMATCH;
	//		}
	//		break;
	//
	//	case MemoryMappedFilenameInformation:
	//		FilePointer = NULL;
	//		break;
	//	default:
	//		return STATUS_INVALID_INFO_CLASS;
	//	}
	//
	//	PreviousMode = KeGetPreviousMode();
	//
	//	if (PreviousMode != KernelMode) {
	//
	//		//
	//		// Check arguments.
	//		//
	//
	//		try {
	//
	//			ProbeForWrite(MemoryInformation,
	//				MemoryInformationLength,
	//				sizeof(ULONG_PTR));
	//
	//			if (ARGUMENT_PRESENT(ReturnLength)) {
	//				ProbeForWriteUlong(ReturnLength);
	//			}
	//
	//		} except(EXCEPTION_EXECUTE_HANDLER) {
	//
	//			//
	//			// If an exception occurs during the probe or capture
	//			// of the initial values, then handle the exception and
	//			// return the exception code as the status value.
	//			//
	//
	//			return GetExceptionCode();
	//		}
	//	}
	//	if (BaseAddress > MM_HIGHEST_USER_ADDRESS) {
	//		return STATUS_INVALID_PARAMETER;
	//	}
	//
	//	if ((BaseAddress >= MM_HIGHEST_VAD_ADDRESS)
	//#if defined(MM_SHARED_USER_DATA_VA)
	//		||
	//		(PAGE_ALIGN(BaseAddress) == (PVOID)MM_SHARED_USER_DATA_VA)
	//#endif
	//		) {
	//
	//		//
	//		// Indicate a reserved area from this point on.
	//		//
	//
	//		if (MemoryInformationClass == MemoryBasicInformation) {
	//
	//			try {
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->AllocationBase =
	//					(PCHAR)MM_HIGHEST_VAD_ADDRESS + 1;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->AllocationProtect =
	//					PAGE_READONLY;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->BaseAddress =
	//					PAGE_ALIGN(BaseAddress);
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->RegionSize =
	//					((PCHAR)MM_HIGHEST_USER_ADDRESS + 1) -
	//					(PCHAR)PAGE_ALIGN(BaseAddress);
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->State = MEM_RESERVE;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->Protect = PAGE_NOACCESS;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->Type = MEM_PRIVATE;
	//
	//				if (ARGUMENT_PRESENT(ReturnLength)) {
	//					*ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
	//				}
	//
	//#if defined(MM_SHARED_USER_DATA_VA)
	//				if (PAGE_ALIGN(BaseAddress) == (PVOID)MM_SHARED_USER_DATA_VA) {
	//
	//					//
	//					// This is the page that is double mapped between
	//					// user mode and kernel mode.
	//					//
	//
	//					((PMEMORY_BASIC_INFORMATION)MemoryInformation)->AllocationBase =
	//						(PVOID)MM_SHARED_USER_DATA_VA;
	//					((PMEMORY_BASIC_INFORMATION)MemoryInformation)->Protect =
	//						PAGE_READONLY;
	//					((PMEMORY_BASIC_INFORMATION)MemoryInformation)->RegionSize =
	//						PAGE_SIZE;
	//					((PMEMORY_BASIC_INFORMATION)MemoryInformation)->State =
	//						MEM_COMMIT;
	//				}
	//#endif
	//
	//			} except(EXCEPTION_EXECUTE_HANDLER) {
	//
	//				//
	//				// Just return success.
	//				//
	//			}
	//
	//			return STATUS_SUCCESS;
	//		}
	//		else {
	//			return STATUS_INVALID_ADDRESS;
	//		}
	//	}
	//
	//	if (ProcessHandle == NtCurrentProcess()) {
	//		TargetProcess = PsGetCurrentProcess();
	//	}
	//	else {
	//		Status = ObReferenceObjectByHandle(ProcessHandle,
	//			PROCESS_QUERY_INFORMATION,
	//			PsProcessType,
	//			PreviousMode,
	//			(PVOID *)&TargetProcess,
	//			NULL);
	//
	//		if (!NT_SUCCESS(Status)) {
	//			return Status;
	//		}
	//	}
	//
	//	if (MemoryInformationClass == MemoryWorkingSetInformation) {
	//
	//		MmLockPagableSectionByHandle(ExPageLockHandle);
	//
	//		Status = MiGetWorkingSetInfo(MemoryInformation,
	//			MemoryInformationLength,
	//			TargetProcess);
	//		MmUnlockPagableImageSection(ExPageLockHandle);
	//
	//		if (ProcessHandle != NtCurrentProcess()) {
	//			ObDereferenceObject(TargetProcess);
	//		}
	//		try {
	//
	//			if (ARGUMENT_PRESENT(ReturnLength)) {
	//				*ReturnLength = ((((PMEMORY_WORKING_SET_INFORMATION)
	//					MemoryInformation)->NumberOfEntries - 1) *
	//					sizeof(ULONG)) +
	//					sizeof(MEMORY_WORKING_SET_INFORMATION);
	//			}
	//
	//		} except(EXCEPTION_EXECUTE_HANDLER) {
	//		}
	//
	//		return STATUS_SUCCESS;
	//	}
	//
	//	//
	//	// If the specified process is not the current process, attach
	//	// to the specified process.
	//	//
	//
	//	if (ProcessHandle != NtCurrentProcess()) {
	//		KeAttachProcess(&TargetProcess->Pcb);
	//		Attached = TRUE;
	//	}
	//	else {
	//		Attached = FALSE;
	//	}
	//
	//	//
	//	// Get working set mutex and block APCs.
	//	//
	//
	//	LOCK_WS_AND_ADDRESS_SPACE(TargetProcess);
	//
	//	//
	//	// Make sure the address space was not deleted, if so, return an error.
	//	//
	//
	//	if (TargetProcess->AddressSpaceDeleted != 0) {
	//		UNLOCK_WS_AND_ADDRESS_SPACE(TargetProcess);
	//		if (Attached == TRUE) {
	//			KeDetachProcess();
	//			ObDereferenceObject(TargetProcess);
	//		}
	//		return STATUS_PROCESS_IS_TERMINATING;
	//	}
	//
	//	//
	//	// Locate the VAD that contains the base address or the VAD
	//	// which follows the base address.
	//	//
	//
	//	Vad = TargetProcess->VadRoot;
	//	BaseVpn = MI_VA_TO_VPN(BaseAddress);
	//
	//	for (;;) {
	//
	//		if (Vad == (PMMVAD)NULL) {
	//			break;
	//		}
	//
	//		if ((BaseVpn >= Vad->StartingVpn) &&
	//			(BaseVpn <= Vad->EndingVpn)) {
	//			Found = TRUE;
	//			break;
	//		}
	//
	//		if (BaseVpn < Vad->StartingVpn) {
	//			if (Vad->LeftChild == (PMMVAD)NULL) {
	//				break;
	//			}
	//			Vad = Vad->LeftChild;
	//
	//		}
	//		else {
	//			if (BaseVpn < Vad->EndingVpn) {
	//				break;
	//			}
	//			if (Vad->RightChild == (PMMVAD)NULL) {
	//				break;
	//			}
	//			Vad = Vad->RightChild;
	//		}
	//	}
	//
	//	if (!Found) {
	//
	//		//
	//		// There is no virtual address allocated at the base
	//		// address.  Return the size of the hole starting at
	//		// the base address.
	//		//
	//
	//		if (Vad == NULL) {
	//			TheRegionSize = ((PCHAR)MM_HIGHEST_VAD_ADDRESS + 1) -
	//				(PCHAR)PAGE_ALIGN(BaseAddress);
	//		}
	//		else {
	//			if (Vad->StartingVpn < BaseVpn) {
	//
	//				//
	//				// We are looking at the Vad which occupies the range
	//				// just before the desired range.  Get the next Vad.
	//				//
	//
	//				Vad = MiGetNextVad(Vad);
	//				if (Vad == NULL) {
	//					TheRegionSize = ((PCHAR)MM_HIGHEST_VAD_ADDRESS + 1) -
	//						(PCHAR)PAGE_ALIGN(BaseAddress);
	//				}
	//				else {
	//					TheRegionSize = (PCHAR)MI_VPN_TO_VA(Vad->StartingVpn) -
	//						(PCHAR)PAGE_ALIGN(BaseAddress);
	//				}
	//			}
	//			else {
	//				TheRegionSize = (PCHAR)MI_VPN_TO_VA(Vad->StartingVpn) -
	//					(PCHAR)PAGE_ALIGN(BaseAddress);
	//			}
	//		}
	//
	//		UNLOCK_WS_AND_ADDRESS_SPACE(TargetProcess);
	//
	//		if (Attached == TRUE) {
	//			KeDetachProcess();
	//			ObDereferenceObject(TargetProcess);
	//		}
	//
	//		//
	//		// Establish an exception handler and write the information and
	//		// returned length.
	//		//
	//
	//		if (MemoryInformationClass == MemoryBasicInformation) {
	//			try {
	//
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->AllocationBase =
	//					NULL;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->AllocationProtect =
	//					0;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->BaseAddress =
	//					PAGE_ALIGN(BaseAddress);
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->RegionSize =
	//					TheRegionSize;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->State = MEM_FREE;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->Protect = PAGE_NOACCESS;
	//				((PMEMORY_BASIC_INFORMATION)MemoryInformation)->Type = 0;
	//
	//				if (ARGUMENT_PRESENT(ReturnLength)) {
	//					*ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
	//				}
	//
	//			} except(EXCEPTION_EXECUTE_HANDLER) {
	//
	//				//
	//				// Just return success.
	//				//
	//			}
	//
	//			return STATUS_SUCCESS;
	//		}
	//		return STATUS_INVALID_ADDRESS;
	//	}
	//
	//	//
	//	// Found a VAD.
	//	//
	//
	//	Va = PAGE_ALIGN(BaseAddress);
	//	Info.BaseAddress = Va;
	//
	//	//
	//	// There is a page mapped at the base address.
	//	//
	//
	//	if (Vad->u.VadFlags.PrivateMemory) {
	//		Info.Type = MEM_PRIVATE;
	//	}
	//	else if (Vad->u.VadFlags.ImageMap == 0) {
	//		Info.Type = MEM_MAPPED;
	//
	//		if (MemoryInformationClass == MemoryMappedFilenameInformation) {
	//			if (Vad->ControlArea) {
	//				FilePointer = Vad->ControlArea->FilePointer;
	//			}
	//			if (!FilePointer) {
	//				FilePointer = (PVOID)1;
	//			}
	//			else {
	//				ObReferenceObject(FilePointer);
	//			}
	//		}
	//
	//	}
	//	else {
	//		Info.Type = MEM_IMAGE;
	//	}
	//
	//	Info.State = MiQueryAddressState(Va, Vad, TargetProcess, &Info.Protect);
	//
	//	Va = (PVOID)((PCHAR)Va + PAGE_SIZE);
	//
	//	while (MI_VA_TO_VPN(Va) <= Vad->EndingVpn) {
	//
	//		NewState = MiQueryAddressState(Va,
	//			Vad,
	//			TargetProcess,
	//			&NewProtect);
	//
	//		if ((NewState != Info.State) || (NewProtect != Info.Protect)) {
	//
	//			//
	//			// The state for this address does not match, calculate
	//			// size and return.
	//			//
	//
	//			break;
	//		}
	//		Va = (PVOID)((PCHAR)Va + PAGE_SIZE);
	//	} // end while
	//
	//	Info.RegionSize = ((PCHAR)Va - (PCHAR)Info.BaseAddress);
	//	Info.AllocationBase = MI_VPN_TO_VA(Vad->StartingVpn);
	//	Info.AllocationProtect = MI_CONVERT_FROM_PTE_PROTECTION(
	//		Vad->u.VadFlags.Protection);
	//
	//	//
	//	// A range has been found, release the mutexes, deattach from the
	//	// target process and return the information.
	//	//
	//
	//#if !(defined(_MIALT4K_))
	//
	//	UNLOCK_WS_AND_ADDRESS_SPACE(TargetProcess);
	//
	//#else
	//
	//	UNLOCK_WS_UNSAFE(TargetProcess);
	//
	//	if (TargetProcess->Wow64Process != NULL) {
	//
	//		Info.BaseAddress = PAGE_4K_ALIGN(BaseAddress);
	//
	//		MiQueryRegionFor4kPage(Info.BaseAddress,
	//			MI_VPN_TO_VA_ENDING(Vad->EndingVpn),
	//			&Info.RegionSize,
	//			&Info.State,
	//			&Info.Protect,
	//			TargetProcess);
	//	}
	//
	//	UNLOCK_ADDRESS_SPACE(TargetProcess);
	//
	//#endif
	//
	//	if (Attached == TRUE) {
	//		KeDetachProcess();
	//		ObDereferenceObject(TargetProcess);
	//	}
	//
	//#if DBG
	//	if (MmDebug & MM_DBG_SHOW_NT_CALLS) {
	//		if (!MmWatchProcess) {
	//			DbgPrint("queryvm base %lx allocbase %lx protect %lx size %lx\n",
	//				Info.BaseAddress, Info.AllocationBase, Info.AllocationProtect,
	//				Info.RegionSize);
	//			DbgPrint("    state %lx  protect %lx  type %lx\n",
	//				Info.State, Info.Protect, Info.Type);
	//		}
	//	}
	//#endif //DBG
	//
	//	if (MemoryInformationClass == MemoryBasicInformation) {
	//		try {
	//
	//			*(PMEMORY_BASIC_INFORMATION)MemoryInformation = Info;
	//
	//			if (ARGUMENT_PRESENT(ReturnLength)) {
	//				*ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
	//			}
	//
	//		} except(EXCEPTION_EXECUTE_HANDLER) {
	//		}
	//		return STATUS_SUCCESS;
	//	}
	//
	//	//
	//	// Try to return the name of the file that is mapped.
	//	//
	//
	//	if (!FilePointer) {
	//		return STATUS_INVALID_ADDRESS;
	//	}
	//	else if (FilePointer == (PVOID)1) {
	//		return STATUS_FILE_INVALID;
	//	}
	//
	//	//
	//	// We have a referenced pointer to the file. Call ObQueryNameString
	//	// and get the file name
	//	//
	//	//获取文件名///
	//	Status = ObQueryNameString(
	//		FilePointer,
	//		MemoryInformation,
	//		MemoryInformationLength,
	//		ReturnLength
	//	);
	//	//获取文件名/                                  ObDereferenceObject(FilePointer);
	//	return Status;
	//}


	typedef struct
	{
		HANDLE ProcessID;
		PEPROCESS PEProcess;
		HANDLE ProcessHandle;
		BOOLEAN Deleted;
	} ProcessListData, * PProcessListData;

	PRTL_GENERIC_TABLE InternalProcessList = NULL;



	RTL_GENERIC_COMPARE_RESULTS NTAPI ProcessListCompare(__in struct _RTL_GENERIC_TABLE* Table, __in PProcessListData FirstStruct, __in PProcessListData SecondStruct)
	{
		//DbgPrint("ProcessListCompate");

		if (FirstStruct->ProcessID == SecondStruct->ProcessID)
			return GenericEqual;
		else
		{
			if (SecondStruct->ProcessID < FirstStruct->ProcessID)
				return GenericLessThan;
			else
				return GenericGreaterThan;
		}
	}

	PVOID NTAPI ProcessListAlloc(__in struct _RTL_GENERIC_TABLE* Table, __in CLONG ByteSize)
	{
		PVOID r = ExAllocatePoolWithTag(PagedPool, ByteSize, 'pro');
		RtlZeroMemory(r, ByteSize);

		//DbgPrint("ProcessListAlloc %d",(int)ByteSize);
		return r;
	}

	VOID NTAPI ProcessListDealloc(__in struct _RTL_GENERIC_TABLE* Table, __in __drv_freesMem(Mem) __post_invalid PVOID Buffer)
	{
		//DbgPrint("ProcessListDealloc");
		ExFreePoolWithTag(Buffer, 'tag');
	}

	HANDLE GetProcessHandle(HANDLE dwPID) {

		if (InternalProcessList == 0)
		{
			InternalProcessList = (PRTL_GENERIC_TABLE)ExAllocatePoolWithTag(PagedPool, sizeof(RTL_GENERIC_TABLE), 'tag');
			if (InternalProcessList)
				RtlInitializeGenericTable(InternalProcessList, (PRTL_GENERIC_COMPARE_ROUTINE)ProcessListCompare,
					(PRTL_GENERIC_ALLOCATE_ROUTINE)ProcessListAlloc,
					(PRTL_GENERIC_FREE_ROUTINE)ProcessListDealloc, NULL);
		}
		if (InternalProcessList)
		{

			PEPROCESS selectedprocess = NULL;

			ProcessListData d;
			RtlZeroMemory(&d, sizeof(d));
			ProcessListData* r = 0;
			d.ProcessID = dwPID;
			r = (ProcessListData*)RtlLookupElementGenericTable(InternalProcessList, &d);
			if (r)
			{
				return r->ProcessHandle;
			}
			HANDLE hProcess = 0;
			NTSTATUS ntStatus = STATUS_SUCCESS;
			if (NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)(dwPID), &selectedprocess)))
			{
				ntStatus = ObOpenObjectByPointer(selectedprocess, 0, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
			}
			if (selectedprocess)
			{
				ObDereferenceObject(selectedprocess);
			}
			return hProcess;
		}
		return 0;
	}


	//void EnumObjInfo(LPVOID pBuffer, DWORD pid)
	//{
	//	char szType[128] = { 0 };
	//	char szName[512] = { 0 };
	//	DWORD dwFlags = 0;
	//	POBJECT_NAME_INFORMATION pNameInfo;
	//	POBJECT_NAME_INFORMATION pNameType;
	//	PSYSTEM_HANDLE_INFORMATION_EX pInfo = (PSYSTEM_HANDLE_INFORMATION_EX)pBuffer;
	//	ULONG OldPID = 0;
	//	for (DWORD i = 0; i < pInfo->NumberOfHandles; i++)
	//	{
	//		if (OldPID != pInfo->Information[i].ProcessId)
	//		{
	//			if (pInfo->Information[i].ProcessId == pid)
	//			{

	//				HANDLE newHandle;
	//				//DuplicateHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pInfo->Information[i].ProcessId), (HANDLE)pInfo->Information[i].Handle, GetCurrentProcess(), &newHandle, DUPLICATE_SAME_ACCESS, FALSE, DUPLICATE_SAME_ACCESS);
	//				//NTSTATUS status1 = NtQueryObject(newHandle, ObjectNameInformation, szName, 512, &dwFlags);
	//				//NTSTATUS status2 = NtQueryObject(newHandle, ObjectTypeInformation, szType, 128, &dwFlags);
	//				//if (strcmp(szName, "") && strcmp(szType, "") && status1 != 0xc0000008 && status2 != 0xc0000008)
	//				//{
	//				//	pNameInfo = (POBJECT_NAME_INFORMATION)szName;
	//				//	pNameType = (POBJECT_NAME_INFORMATION)szType;
	//				//	printf("%wZ   ", pNameType);
	//				//	printf("%wZ \n", pNameInfo);
	//				//}
	//			}
	//		}
	//	}

	//	｝


	//BOOL IsMmIsAddressValid(HANDLE dwPID, LPVOID Address) {
	//
	//	PEPROCESS process = NULL;
	//	BOOL r = 0;
	//	PsLookupProcessByProcessId(dwPID, &process);
	//	if (process)
	//	{
	//		KAPC_STATE stack = { 0 };
	//		KeStackAttachProcess(process, &stack);
	//		r = MmIsAddressValid(Address);
	//		KeUnstackDetachProcess(&stack);
	//		ObDereferenceObject(process);
	//	}
	//	return r;
	//}

	BOOLEAN IsAddressSafe(UINT_PTR StartAddress)
	{
#ifdef AMD64
		//cannonical check. Bits 48 to 63 must match bit 47
		UINT_PTR toppart = (StartAddress >> 47);
		if (toppart & 1)
		{
			//toppart must be 0x1ffff
			if (toppart != 0x1ffff)
				return FALSE;
		}
		else
		{
			//toppart must be 0
			if (toppart != 0)
				return FALSE;

		}

#endif

		//return TRUE;
		//if (loadedbydbvm)
		//{
		//	BYTE x = 0;
		//	UINT_PTR lasterror;
		//	disableInterrupts();
		//	vmx_disable_dataPageFaults();

		//	x = *(volatile BYTE*)StartAddress;

		//	vmx_enable_dataPageFaults();
		//	lasterror = vmx_getLastSkippedPageFault();
		//	enableInterrupts();

		//	DbgPrint("IsAddressSafe dbvm-mode: lastError=%p\n", lasterror);

		//	if (lasterror) return FALSE;
		//}


		{
#ifdef AMD64
			UINT_PTR kernelbase = 0x7fffffffffffffffULL;


			if (StartAddress < kernelbase)
				return TRUE;
			else
			{
				PHYSICAL_ADDRESS physical;
				physical.QuadPart = 0;
				physical = MmGetPhysicalAddress((PVOID)StartAddress);
				return (physical.QuadPart != 0);
			}
#else
			/*	MDL x;


				MmProbeAndLockPages(&x,KernelMode,IoModifyAccess);


				MmUnlockPages(&x);
				*/
			ULONG kernelbase = 0x7ffe0000;

			if ((!HiddenDriver) && (StartAddress < kernelbase))
				return TRUE;

			{
				UINT_PTR PTE, PDE;
				struct PTEStruct* x;

				/*
				PHYSICAL_ADDRESS physical;
				physical=MmGetPhysicalAddress((PVOID)StartAddress);
				return (physical.QuadPart!=0);*/


				PTE = (UINT_PTR)StartAddress;
				PTE = PTE / 0x1000 * PTESize + 0xc0000000;

				//now check if the address in PTE is valid by checking the page table directory at 0xc0300000 (same location as CR3 btw)
				PDE = PTE / 0x1000 * PTESize + 0xc0000000; //same formula

				x = (PVOID)PDE;
				if ((x->P == 0) && (x->A2 == 0))
				{
					//Not present or paged, and since paging in this area isn't such a smart thing to do just skip it
					//perhaps this is only for the 4 mb pages, but those should never be paged out, so it should be 1
					//bah, I've got no idea what this is used for
					return FALSE;
				}

				if (x->PS == 1)
				{
					//This is a 4 MB page (no pte list)
					//so, (startaddress/0x400000*0x400000) till ((startaddress/0x400000*0x400000)+(0x400000-1) ) ) is specified by this page
				}
				else //if it's not a 4 MB page then check the PTE
				{
					//still here so the page table directory agreed that it is a usable page table entry
					x = (PVOID)PTE;
					if ((x->P == 0) && (x->A2 == 0))
						return FALSE; //see for explenation the part of the PDE
				}

				return TRUE;
			}
#endif
		}

	}




	KSPIN_LOCK memoryLock;
	BOOLEAN iniMemory = FALSE;


	extern BOOLEAN writeSafeMemory(PVOID adr, PVOID val, DWORD valSize);
	extern BOOLEAN ReadSafeMemory(PVOID adr, PVOID val, DWORD valSize);


	//BOOLEAN MDLWriteMemory(PVOID pBaseAddress, PVOID pWriteData, SIZE_T writeDataSize)
	//{
	//	__try
	//	{
	//		PMDL pMdl = NULL;
	//		PVOID pNewAddress = NULL;
	//		// 创建 MDL
	//		pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	//		if (NULL == pMdl)
	//		{
	//			return FALSE;
	//		}
	//		// 更新 MDL 对物理内存的描述
	//		MmBuildMdlForNonPagedPool(pMdl);
	//		// 映射到虚拟内存中
	//		//pNewAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	//		pNewAddress = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	//		if (NULL == pNewAddress)
	//		{
	//			IoFreeMdl(pMdl);
	//			return FALSE;
	//		}
	//		if (!NT_SUCCESS(MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE)))
	//		{
	//			IoFreeMdl(pMdl);
	//			return FALSE;
	//		}
	//		// 写入数据
	//		RtlCopyMemory(pNewAddress, pWriteData, writeDataSize);
	//		// 释放
	//		MmUnmapLockedPages(pNewAddress, pMdl);
	//		IoFreeMdl(pMdl);
	//		return TRUE;
	//	}
	//	__except (1) {

	//		LOG_DEBUG("__except %s %08X\n", __FUNCTION__, GetExceptionCode());
	//	}
	//	return FALSE;
	//}




	ULONG  IsIsMmIsAddressValid(char* pAddress, DWORD nSzie) {

		if ((ULONGLONG)pAddress >= MM_USER_PROBE_ADDRESS) {
			return FALSE;
		}
		
		//ULONG nGsZ = 0;
		if (MmIsAddressValid(pAddress) &&
			MmIsAddressValid(pAddress + nSzie -1))
		{
			return TRUE;
		}
		return FALSE;

		//__try{
		//	ProbeForRead(pAddress, nSzie, 1);
		//	return TRUE;
		//}
		//__except (1) {


		//}

		//return FALSE;


		DWORD64 Adr = (DWORD64)pAddress;
		DWORD64 Adr2 =   (DWORD64)pAddress + nSzie - 1;
		if ((Adr2 >> 12) == (Adr >> 12))
		{
			PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(pAddress);
			if (phyAddress.QuadPart != 0)
			{
				return TRUE;
			}
			else
			{
				return FALSE;
			}

		}
		else
		{
			PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(pAddress);
			PHYSICAL_ADDRESS phyAddress2 = MmGetPhysicalAddress(pAddress + nSzie - 1);
			if (phyAddress.QuadPart != 0 && phyAddress2.QuadPart != 0)
			{
				return TRUE;
				//nGsZ |= 2;
			}
			else
			{
				return FALSE;
			}

		}




		//LOG_DEBUG("0 1 phyAddress = <%p>\n", phyAddress);

		return FALSE;
	}






	//NTSTATUS Brother_Memory(LPIOINFO pValue) {
	//
	//	if (!iniMemory) {
	//		iniMemory = TRUE;
	//		KeInitializeSpinLock(&memoryLock);
	//	}
	//	BOOL rError = STATUS_SUCCESS;
	//	if (pValue->Type == KERNEL_READ) {
	//		KeAcquireSpinLockAtDpcLevel(&memoryLock);
	//		PEPROCESS process = NULL;
	//		if (PsLookupProcessByProcessId((HANDLE)pValue->pID, &process) != STATUS_SUCCESS)
	//		{
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			return STATUS_SUCCESS;
	//		}
	//		if (process == NULL)
	//		{
	//			LOG_DEBUG("获取进程对象失败\n");
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			return 1;
	//		}
	//
	//		void* kBuffer = 0;
	//		__try
	//		{
	//			kBuffer = ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize, 'tag');
	//		}
	//		__except (1)
	//		{
	//			LOG_DEBUG("内存分配失败\n");
	//			ObDereferenceObject(process);
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			return 3;
	//		}
	//
	//		KAPC_STATE stack = { 0 };
	//		KeStackAttachProcess(process, &stack);
	//		if (!IsAddressSafe(pValue->pAdr))
	//		{
	//			ObDereferenceObject(process);
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			KeUnstackDetachProcess(&stack);
	//			return 3;
	//		}
	//
	//		PMDL pMdl = 0;
	//		__try
	//		{
	//			pMdl = IoAllocateMdl(pValue->pAdr, pValue->pAdrSize, 0, 0, 0);
	//			if (pMdl)
	//			{
	//				MmProbeAndLockPages(pMdl, UserMode, IoReadAccess);
	//			}
	//		}
	//		__except (1)
	//		{
	//			if (pMdl != NULL)
	//			{
	//				IoFreeMdl(pMdl);
	//			}
	//			ObDereferenceObject(process);
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			KeUnstackDetachProcess(&stack);
	//			return 3;
	//		}
	//
	//		DWORD ExceptionCode = 0;
	//		__try
	//		{
	//			ProbeForRead(pValue->pAdr, pValue->pAdrSize, 1);
	//			RtlCopyMemory(kBuffer, pValue->pAdr, pValue->pAdrSize);
	//		}
	//		__except (1)
	//		{
	//			ExceptionCode = GetExceptionCode();
	//		}
	//		if (ExceptionCode != 0)
	//		{
	//			if (ExceptionCode == 0xC0000005)
	//			{
	//				//KIRQL irql = WPOFFx64();
	//				//RtlCopyMemory(kBuffer, pValue->pAdr, pValue->pAdrSize);
	//				//WPONx64(irql);
	//				//LOG_DEBUG("ReadSafeMemory \n");
	//				//ReadSafeMemory(pValue->pAdr, kBuffer, pValue->pAdrSize);
	//				
	//				PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(pValue->pAdr);
	//				PHYSICAL_ADDRESS phyAddress2 = MmGetPhysicalAddress((char*)pValue->pAdr + pValue->pAdrSize - 1);
	//				if (phyAddress.QuadPart != 0 && phyAddress2.QuadPart != 0)
	//				{
	//					KIRQL irql = WPOFFx64();
	//					RtlCopyMemory(kBuffer, pValue->pAdr, pValue->pAdrSize);
	//					WPONx64(irql);
	//				}
	//
	//			}
	//			else
	//			{
	//				rError = 4;
	//			}
	//		}
	//		MmUnlockPages(pMdl);
	//		IoFreeMdl(pMdl);
	//
	//		KeUnstackDetachProcess(&stack);
	//		if (rError == 0)
	//		{
	//			__try
	//			{
	//				ProbeForWrite(pValue->pVal, pValue->pAdrSize, 1);
	//				RtlCopyMemory(pValue->pVal, kBuffer, pValue->pAdrSize);
	//			}
	//			__except (1)
	//			{
	//				LOG_DEBUG("内核到用户内存错误\n");
	//				rError = 5;
	//			}
	//		}
	//		ExFreePoolWithTag(kBuffer, 'tag');
	//		ObDereferenceObject(process);
	//		KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//	}
	//	else if (pValue->Type == KERNEL_WRITE)
	//	{
	//
	//		KeAcquireSpinLockAtDpcLevel(&memoryLock);
	//		PEPROCESS process = NULL;
	//		if (PsLookupProcessByProcessId((HANDLE)pValue->pID, &process) != STATUS_SUCCESS)
	//		{
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			return STATUS_SUCCESS;
	//		}
	//
	//		if (process == NULL)
	//		{
	//			LOG_DEBUG("获取进程对象失败\n");
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			return 1;
	//		}
	//		void* kBuffer = 0;
	//		__try
	//		{
	//			kBuffer = ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize, 'tag');
	//		}
	//		__except (1)
	//		{
	//			LOG_DEBUG("内存分配失败\n");
	//			ObDereferenceObject(process);
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			return 3;
	//		}
	//
	//		__try
	//		{
	//			ProbeForRead(pValue->pVal, pValue->pValSize, 1);
	//			RtlCopyMemory(kBuffer, pValue->pVal, pValue->pAdrSize);
	//		}
	//		__except (1)
	//		{
	//			LOG_DEBUG("到缓冲区内核错误\n");
	//			ExFreePoolWithTag(kBuffer, 'tag');
	//			ObDereferenceObject(process);
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			return 6;
	//		}
	//
	//		KAPC_STATE stack = { 0 };
	//		KeStackAttachProcess(process, &stack);
	//		if (!IsAddressSafe(pValue->pAdr))
	//		{
	//			KeUnstackDetachProcess(&stack);
	//			ExFreePoolWithTag(kBuffer, 'tag');
	//			ObDereferenceObject(process);
	//			KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//			return 3;
	//		}
	//
	//		DWORD ExceptionCode = 0;
	//		__try
	//		{
	//			ProbeForWrite(pValue->pAdr, pValue->pAdrSize, 1);
	//			RtlCopyMemory(pValue->pAdr, kBuffer, pValue->pAdrSize);
	//		}
	//		__except (1)
	//		{
	//			ExceptionCode = GetExceptionCode();
	//		}
	//		__try {
	//
	//			if (ExceptionCode != 0)
	//			{
	//				//MM_USER_PROBE_ADDRESS
	//				//MmIsAddressValid
	//				if (ExceptionCode == 0xC0000005)
	//				{
	//					LOG_DEBUG("writeSafeMemory \n");
	//					PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(pValue->pAdr);
	//					PHYSICAL_ADDRESS phyAddress2 = MmGetPhysicalAddress((char*)pValue->pAdr + pValue->pAdrSize -1);
	//					if (phyAddress.QuadPart != 0 && phyAddress2.QuadPart != 0)
	//					{
	//						KIRQL irql = WPOFFx64();
	//						RtlCopyMemory(pValue->pAdr, kBuffer, pValue->pAdrSize);
	//						WPONx64(irql);
	//						//LOG_DEBUG("MDLWriteMemory \n");
	//						//MDLWriteMemory(pValue->pAdr, kBuffer, pValue->pAdrSize);
	//					}
	//				}
	//				else
	//				{
	//					rError = 4;
	//				}
	//
	//			}
	//		}
	//		__except (1) {
	//
	//			LOG_DEBUG("error");
	//			rError = 4;
	//		}
	//
	//
	//		//MmUnlockPages(pMdl);
	//		//IoFreeMdl(pMdl);
	//
	//		KeUnstackDetachProcess(&stack);
	//		ExFreePoolWithTag(kBuffer, 'tag');
	//		ObDereferenceObject(process);
	//		KeReleaseSpinLockFromDpcLevel(&memoryLock);
	//	}
	//	else if (pValue->Type == KERNEL_POOL)
	//	{
	//
	//		PEPROCESS process = NULL;
	//		PsLookupProcessByProcessId((HANDLE)pValue->pID, &process);
	//		if (process == NULL)
	//		{
	//			LOG_DEBUG("获取进程对象失败\n");
	//			return 1;
	//		}
	//		KAPC_STATE stack = { 0 };
	//		KeStackAttachProcess(process, &stack);
	//
	//		PVOID AllocateAddress = 0;
	//		size_t RegionSize = pValue->pAdrSize;
	//		NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &AllocateAddress, 0, &RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//		if (NT_SUCCESS(status))
	//		{
	//			pValue->pAdr = AllocateAddress;
	//			LOG_DEBUG("ZwAllocateVirtualMemory  sucess  %08X\n", status);
	//		}
	//		else
	//		{
	//			pValue->pAdr = 0;
	//			LOG_DEBUG("ZwAllocateVirtualMemory  false  %08X\n", status);
	//		}
	//		KeUnstackDetachProcess(&stack);
	//		ObDereferenceObject(process);
	//	}
	//	return rError;
	//}






	// 得到传入的ring3层虚拟地址                       
	//pOutAddress = (size_t*)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);                        
	//RtlZeroMemory(&virtualAddress,sizeof(VIRTUAL_ADDRESS));                        
	//virtualAddress.ulVirtualAddress = *pOutAddress;                        // 得到页目录指针物理地址                        _asm{                                mov eax,  cr3;                                mov pdbr, eax;                        }                        // 映射为虚拟地址以便取值                        RtlZeroMemory(&phyAddress,sizeof(PHYSICAL_ADDRESS));                        phyAddress.LowPart = pdbr;                        pPdbr = (PULONG)MmMapIoSpace(phyAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);                        KdPrint(("pdbr = 0x%08X, 映射后的地址0x%p\n", pdbr, pPdbr));                        // 定位页目录指针表并获取页目录表物理页地址                        // ulDirAddress 为页目录表物理页地址                        ulPointerIdx = virtualAddress.stVirtualAddress.dirPointer;                        ulDirBaseAddress = pPdbr[ulPointerIdx];                        ulDirBaseAddress &= 0xFFFFF000;                        // 中间物理地址                        // 定位页表项                        ulDirAddress = ulDirBaseAddress + virtualAddress.stVirtualAddress.dirIndex * 0x8;                        phyAddress.LowPart = ulDirAddress;                        pPageTable = (PULONG)MmMapIoSpace(phyAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);                        ulPageTable = *pPageTable;                        ulPageTable &= 0xFFFFF000;                                 // 中间物理地址                        // 定位物理页面                        ulPageTable += virtualAddress.stVirtualAddress.tableIndex * 0x8;                        phyAddress.LowPart = ulPageTable;                        pPageBase = (PULONG)MmMapIoSpace(phyAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);                        ulPageBase = *pPageBase;                        ulPageBase &= 0xFFFFF000;                        // 得到物理地址                        ulPhyAddress = ulPageBase + virtualAddress.stVirtualAddress.offset;                        // 映射为虚拟地址，获取其值进行验证                        phyAddress.LowPart = ulPhyAddress;                        pPhyAddress = (PWCHAR)MmMapIoSpace(phyAddress, sizeof(PHYSICAL_ADDRESS), MmNonCached);                        KdPrint(("虚拟地址：0x%08X, 对应物理地址：0x%08X", *pOutAddress, ulPhyAddress))

	extern KSPIN_LOCK SpinLock_MapPoinerReadWrite;


	//NTSTATUS Brother_Memory(LPIOINFO pValue) {
	//	//	ExAcquireSpinLockAtDpcLevel(&SpinLock_MapPoinerReadWrite);
	//	BOOL rError = 1;
	//	do
	//	{
	//		if (pValue->Type == KERNEL_READ) {
	//			__try
	//			{
	//				PEPROCESS process = NULL;
	//				if (PsLookupProcessByProcessId((HANDLE)pValue->pID, &process) != STATUS_SUCCESS)
	//				{
	//					rError = 2;
	//					break;
	//				}
	//				if (process == NULL)
	//				{
	//					rError = 1;
	//					break;
	//				}
	//				ReadProcessMemory(process, pValue->pAdr, pValue->pVal, pValue->pAdrSize);
	//				ObDereferenceObject(process);
	//			}
	//			__except (1) {

	//				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());
	//				rError = GetExceptionCode();
	//			}
	//		}
	//		else if (pValue->Type == KERNEL_WRITE)
	//		{
	//			__try {
	//				PEPROCESS process = NULL;
	//				if (PsLookupProcessByProcessId((HANDLE)pValue->pID, &process) != STATUS_SUCCESS)
	//				{
	//					rError = 2;
	//					break;
	//				}
	//				if (process == NULL)
	//				{
	//					rError = 1;
	//					break;
	//				}
	//				WriteProcessMemory(process, pValue->pAdr, pValue->pVal, pValue->pAdrSize);
	//				ObDereferenceObject(process);
	//			}
	//			__except (1) {
	//				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());
	//				rError = GetExceptionCode();
	//			}
	//		}

	//	} while (FALSE);
	//	//ExReleaseSpinLockFromDpcLevel(&SpinLock_MapPoinerReadWrite);
	//	pValue->Error = rError;
	//	return rError;
	//}

	NTKERNELAPI NTSTATUS __stdcall ZwProtectVirtualMemory(HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PULONGLONG ProtectSize,
		ULONG NewProtect,
		PULONG OldProtect);


	//NTKERNELAPI NTSTATUS __stdcall ZwQuerySystemInformation(
	//	DWORD32 systemInformationClass,
	//	PVOID systemInformation,
	//	ULONG systemInformationLength,
	//	PULONG returnLength);


	//
// Define the dwOpenMode values for CreateNamedPipe
//

#define PIPE_ACCESS_INBOUND         0x00000001
#define PIPE_ACCESS_OUTBOUND        0x00000002
#define PIPE_ACCESS_DUPLEX          0x00000003

//
// Define the Named Pipe End flags for GetNamedPipeInfo
//

#define PIPE_CLIENT_END             0x00000000
#define PIPE_SERVER_END             0x00000001

//
// Define the dwPipeMode values for CreateNamedPipe
//

#define PIPE_WAIT                   0x00000000
#define PIPE_NOWAIT                 0x00000001
#define PIPE_READMODE_BYTE          0x00000000
#define PIPE_READMODE_MESSAGE       0x00000002
#define PIPE_TYPE_BYTE              0x00000000
#define PIPE_TYPE_MESSAGE           0x00000004
#define PIPE_ACCEPT_REMOTE_CLIENTS  0x00000000
#define PIPE_REJECT_REMOTE_CLIENTS  0x00000008

//
// Define the well known values for CreateNamedPipe nMaxInstances
//

#define PIPE_UNLIMITED_INSTANCES    255

	typedef struct _OVERLAPPED {
		ULONG_PTR Internal;
		ULONG_PTR InternalHigh;
		union {
			struct {
				DWORD Offset;
				DWORD OffsetHigh;
			} DUMMYSTRUCTNAME;
			PVOID Pointer;
		} DUMMYUNIONNAME;

		HANDLE  hEvent;
	} OVERLAPPED, * LPOVERLAPPED;

	//BOOL __stdcall ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped)
	//{
	//	LPOVERLAPPED IoStatusBlock; // rax
	//	LPOVERLAPPED v5; // r9
	//	HANDLE hEvent; // rdx
	//	NTSTATUS v7; // eax
	//	__int64 v9[3]; // [rsp+50h] [rbp-18h] BYREF

	//	v9[0] = 0i64;
	//	v9[1] = 0i64;
	//	if (lpOverlapped)
	//		lpOverlapped->Internal = 259i64;
	//	IoStatusBlock = (LPOVERLAPPED)v9;
	//	if (lpOverlapped)
	//		IoStatusBlock = lpOverlapped;
	//	if (lpOverlapped)
	//	{
	//		v5 = 0i64;
	//		if (((__int64)lpOverlapped->hEvent & 1) == 0)
	//			v5 = lpOverlapped;
	//	}
	//	else
	//	{
	//		v5 = 0i64;
	//	}
	//	if (lpOverlapped)
	//		hEvent = lpOverlapped->hEvent;
	//	else
	//		hEvent = 0i64;
	//	v7 = NtFsControlFile(hNamedPipe, hEvent, 0i64, v5, (PIO_STATUS_BLOCK)IoStatusBlock, 0x110008u, 0i64, 0, 0i64, 0);
	//	//FSCTL_DELETE_REPARSE_POINT
	//	LOG_DEBUG("NtFsControlFile  %08X\n", v7);
	//	if (!lpOverlapped && v7 == 259)
	//	{
	//		v7 = ZwWaitForSingleObject(hNamedPipe, 0, 0i64);
	//		if (v7 < 0)
	//		{
	//		LABEL_12:
	//			//BaseSetLastNTError((unsigned int)v7);
	//			LOG_DEBUG("NtFsControlFile  %08X\n", v7);
	//			return 0;
	//		}
	//		v7 =  v9[0];
	//	}
	//	if (v7 < 0 || v7 == 259)
	//		goto LABEL_12;
	//	return 1;
	//}

	HANDLE hPipe = 0;


	//BOOL __stdcall ReadFile(
	//	HANDLE hFile,
	//	LPVOID lpBuffer,
	//	DWORD nNumberOfBytesToRead,
	//	LPDWORD lpNumberOfBytesRead)
	//{
	//	HANDLE StandardError; // rsi
	//	LPOVERLAPPED v8; // r14
	//	unsigned int v9; // eax
	//	__int64 Status; // rcx
	//	HANDLE hEvent; // rdx
	//	LPOVERLAPPED v13; // r9
	//	NTSTATUS v14; // eax
	//	NTSTATUS v15; // eax
	//	struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+50h] [rbp-28h] BYREF
	//	union _LARGE_INTEGER ByteOffset; // [rsp+80h] [rbp+8h] BYREF
	//	LPDWORD v18; // [rsp+98h] [rbp+20h]

	//	v18 = lpNumberOfBytesRead;
	//	StandardError = hFile;
	//	IoStatusBlock.Pointer = 0i64;
	//	IoStatusBlock.Information = 0i64;
	//	if (lpNumberOfBytesRead)
	//		*lpNumberOfBytesRead = 0;
	//	v8 = 0;


	//	v9 = NtReadFile(StandardError, 0i64, 0i64, 0i64, &IoStatusBlock, lpBuffer, nNumberOfBytesToRead, 0i64, 0i64);
	//	Status = v9;
	//	if (v9 == 259)
	//	{
	//		v15 = ZwWaitForSingleObject(StandardError, 0, 0i64);
	//		Status = (unsigned int)v15;
	//		if (v15 >= 0)
	//			Status = (unsigned int)IoStatusBlock.Status;
	//	}
	//	if ((int)Status >= 0)
	//	{
	//		if (lpNumberOfBytesRead)
	//			*lpNumberOfBytesRead = IoStatusBlock.Information;
	//		return 1;
	//	}
	//	if ((DWORD)Status == -1073741807)
	//	{
	//		if (lpNumberOfBytesRead)
	//			*lpNumberOfBytesRead = 0;
	//		return 1;
	//	}
	//	if ((Status & 0xC0000000) == 0x80000000 && lpNumberOfBytesRead)
	//		*lpNumberOfBytesRead = IoStatusBlock.Information;
	//	return 0;
	//}

	HANDLE g_hClient = 0;


	UNICODE_STRING PipeString = {0};
	ACL wACL = { 0 };

	//VOID DriverSystemMsg(
	//	IN PVOID Nothing)
	//{

	//	LOG_DEBUG("CreateNamedPipeW  %ws\n", (LPCWSTR)Nothing);
	//	if (hPipe == 0 || hPipe == (HANDLE)-1)
	//	{
	//		hPipe = _CreateNamedPipeW((LPCWSTR)Nothing,
	//			PIPE_ACCESS_DUPLEX,
	//			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
	//			PIPE_UNLIMITED_INSTANCES,
	//			PAGE_SIZE,
	//			PAGE_SIZE,
	//			0);
	//		if (hPipe == 0 || hPipe == (HANDLE)-1){
	//			LOG_DEBUG(" CreateNamedPipeW  err\n");
	//			ExFreePoolWithTag(Nothing, 'Tag');
	//			return;
	//		}
	//	}

	//	LOG_DEBUG(" CreateNamedPipeW  %I64X\n", hPipe);
	//	BOOLEAN r = ConnectNamedPipe(hPipe, 0);
	//	LOG_DEBUG("ConnectNamedPipe  %d\n", r);

	//	char Buffer[PAGE_SIZE] = { 0 };
	//	while (TRUE)
	//	{
	//		ULONG nSize = 0;
	//		BOOL r =  ReadFile(hPipe, Buffer, PAGE_SIZE, &nSize);
	//		if (r)
	//		{
	//			LOG_DEBUG("ReadFile sucess");
	//		}
	//		else
	//		{
	//			LARGE_INTEGER Time = { 0 };
	//			Time.LowPart = 1;
	//			ZwWaitForSingleObject(NtCurrentThread(), 0, &Time);
	//		}

	//		//ZwReadFile(hPipe,)
	//	}


	//}

	IO_STATUS_BLOCK g_ioStatusBlock;



	void Msg_Socket_Init() {








	}

	NTSTATUS Brother_Msg(LPIOINFO pValue) {

		DWORD Type = pValue->Type;
		if (Type == 0){
			


			//UNICODE_STRING uniName;
			//OBJECT_ATTRIBUTES objAttr;

			//RtlInitUnicodeString(&uniName, (LPCWSTR)L"\\DosDevices\\pipe\\pipe02");
			//InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			//NTSTATUS status = ZwCreateFile(&g_hClient, GENERIC_READ | GENERIC_WRITE, 
			//	&objAttr, &g_ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
			//
			//LOG_DEBUG("ZwCreateFile %I64X   %I64X\n", g_hClient, status);

			//if (!g_hClient){
			//	return status;
			//}






			if ((hPipe == 0 || hPipe == (HANDLE)-1)){
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

				UNICODE_STRING Name;
				RtlInitUnicodeString(&Name, (LPCWSTR)pValue->pAdr);
				wchar_t* NameV = (wchar_t*)ExAllocatePoolWithTag(PagedPool, Name.MaximumLength, 'Tag');
				RtlCopyMemory(NameV, Name.Buffer, Name.Length);



				RtlCopyMemory(&wACL, pValue->pVal, sizeof(ACL));


				//Status = PsCreateSystemThread(
				//	&ThreadHandle,
				//	THREAD_ALL_ACCESS,
				//	&Attributes,
				//	NULL,
				//	NULL,
				//	DriverSystemMsg,
				//	NameV);
			}
		}





			//if (hPipe == 0 || hPipe == (HANDLE)-1)
			//{
			//	hPipe = _CreateNamedPipeW((LPCWSTR)pValue->pAdr,
			//		PIPE_ACCESS_DUPLEX,
			//		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			//		PIPE_UNLIMITED_INSTANCES,
			//		PAGE_SIZE,
			//		PAGE_SIZE,
			//		0,
			//		(PACL)pValue->pVal);



			//	LOG_DEBUG(" CreateNamedPipeW  %I64X\n", hPipe);



			//ZwFsControlFile()
		return STATUS_SUCCESS;
	}




	BOOLEAN ReadSafeMemoryV(PVOID adr, PVOID val, DWORD valSize) {

		if (adr == 0){
			return FALSE;
		}
		if (IsIsMmIsAddressValid((char *)adr, valSize)){

			return ReadSafeMemory(adr, val, valSize);
		}
		return FALSE;
	}



	typedef struct _ObjName_NewWorldCompoment {
		DWORD64 Val[2];
		DWORD64 Len;
		DWORD64 MaxLen;
	}ObjName_NewWorldCompoment;

	typedef struct _ADDRESS_PTE
	{
		union {
			struct PTE_NUMBER {
				ULONGLONG offset : 12;
				ULONGLONG PXE_PageNumber : 9;
				ULONGLONG PPE_PageNumber : 9;
				ULONGLONG PDE_PageNumber : 9;
				ULONGLONG PTE_PageNumber : 9;
				ULONGLONG High : 16;
			};
			ULONGLONG Address;
		}u;
	}ADDRESS_PTEV;


	//PHYSICAL_ADDRESS  MmGetPhysicalAddressSelf(PVOID _pGData, PEPROCESS Process, PVOID VirtualMem) {

	//	//Global_Data* pGData = (Global_Data*)_pGData;
	//	//NTOSKRNL_FUN* fNtos = &((Global_Data*)pGData)->fNtos;
	//	//SELF_F_ARRY* fArry = &((Global_Data*)pGData)->SelfFArry;
	//	//SELF_STRING_ARRY* AArry = &((Global_Data*)pGData)->SelfAArry;

	//	DWORD64 DirectoryTable = *(DWORD64*)((ULONGLONG)Process + 0x28);

	//	ULONGLONG BaseNumber = DirectoryTable >> 12;

	//	ADDRESS_PTEV VirAddress = *((ADDRESS_PTEV*)&VirtualMem);

	//	ULONGLONG PageOffet[4];
	//	PageOffet[0] = VirAddress.u.PXE_PageNumber;
	//	PageOffet[1] = VirAddress.u.PPE_PageNumber;
	//	PageOffet[2] = VirAddress.u.PDE_PageNumber;
	//	PageOffet[3] = VirAddress.u.PTE_PageNumber;
	//	char* Adr = 0;
	//	do
	//	{
	//		Adr = (char*)MmAllocateNonCachedMemory(PAGE_SIZE);
	//	} while (Adr == 0);


	//	PHYSICAL_ADDRESS rPhy; rPhy.QuadPart = 0;

	//	MMPTE* pMmpte = GetAddressPfn((DWORD64)Adr);

	//	if (pMmpte == 0) {
	//		return rPhy;
	//	}

	//	ULONGLONG _O_PageNumber = pMmpte->u.Hard.PageFrameNumber;
	//	int iPLM = 4;
	//	ULONGLONG bPageNumber = BaseNumber;
	//	do
	//	{
	//		iPLM--;
	//		pMmpte->u.Hard.PageFrameNumber = bPageNumber;
	//		__invlpg(pMmpte);
	//		MMPTE* bPTE_Ptr = (MMPTE*)Adr;
	//		MMPTE uPTE = bPTE_Ptr[PageOffet[iPLM]];
	//		if (uPTE.u.Hard.Valid == 0) {
	//			break;
	//		}
	//		if (uPTE.u.Hard.LargePage)
	//		{
	//			DWORD64 offsetV = 1;
	//			for (size_t im = 0; im < iPLM; im++) {
	//				offsetV = offsetV << 9;
	//			}
	//			rPhy.QuadPart = (uPTE.u.Hard.PageFrameNumber << 12) + (offsetV << 12);
	//			break;
	//		}
	//		if (iPLM == 0) {

	//			rPhy.QuadPart = (uPTE.u.Hard.PageFrameNumber << 12) + VirAddress.u.offset;
	//			break;
	//		}
	//		bPageNumber = uPTE.u.Hard.PageFrameNumber;
	//	} while (iPLM > 0);

	//	pMmpte->u.Hard.PageFrameNumber = _O_PageNumber;
	//	__invlpg(pMmpte);
	//	MmFreeNonCachedMemory(Adr, PAGE_SIZE);
	//	return rPhy;
	//}

	//DWORD64  MmCopyMemoryV(PVOID _pGData, PEPROCESS Process, PVOID  _Dst, PVOID VirtualMem, SIZE_T _nSize, int Flags) {

	//	//Global_Data* pGData = (Global_Data*)_pGData;
	//	//NTOSKRNL_FUN* fNtos = &((Global_Data*)pGData)->fNtos;
	//	//SELF_F_ARRY* fArry = &((Global_Data*)pGData)->SelfFArry;
	//	//SELF_STRING_ARRY* AArry = &((Global_Data*)pGData)->SelfAArry;

	//	ULONGLONG BasePtr = ((ULONGLONG)VirtualMem & 0xFFFFFFFFFFFFF000);
	//	ULONG Offset = (ULONGLONG)VirtualMem & 0xFFF;
	//	SIZE_T nPageSzie = (Offset + _nSize) / PAGE_SIZE;
	//	if ((Offset + _nSize) % PAGE_SIZE)
	//		nPageSzie++;


	//	//ULONGLONG PageNumber = BasePtr >> 12;

	//	typedef struct _MMPTE_READ_INFO {
	//		MMPTE* PTE;
	//		ULONGLONG _O_PageNumer;
	//	}MMPTE_READ_INFO;

	//	if (nPageSzie != 0)
	//	{
	//		char* Adr = 0;


	//		LOG_DEBUG("<%p><%08X>\n", nPageSzie, 0);

	//		do
	//		{
	//			Adr = (char*)MmAllocateNonCachedMemory(nPageSzie * PAGE_SIZE);
	//		} while (Adr == 0);

	//		MMPTE_READ_INFO* uRead = 0;

	//		LOG_DEBUG("<%p><%08X>\n", nPageSzie, 0);

	//		do
	//		{
	//			uRead = ExAllocatePoolWithTag(NonPagedPool, nPageSzie * sizeof(MMPTE_READ_INFO), 'Tag');

	//		} while (uRead == 0);
	//		//fNtos->memset(uRead, 0, sizeof(uRead));

	//		DWORD uIndex = 0;

	//		//_MmGetPhysicalAddressSelf uMmGetPhysicalAddressSelf = 0;
	//		//_FUNCTION_ENTRY(MmGetPhysicalAddressSelf, uMmGetPhysicalAddressSelf, _MmGetPhysicalAddressSelf);



	//		//fNtos->DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, AArry->Line_Ptr_DWORD.Ptr,
	//		//	__LINE__, nPageSzie, 0);


	//		for (size_t iPage = 0; iPage < nPageSzie; iPage++) {

	//			MMPTE* pMmpte = 0;
	//			char* bBegin = Adr + (PAGE_SIZE * iPage);
	//			GetAddressPfn((DWORD64)bBegin, pGData->PTE_BASE, pMmpte);
	//			if (pMmpte == 0) {

	//				break;
	//			}
	//			uRead[iPage]._O_PageNumer = pMmpte->u.Hard.PageFrameNumber;
	//			uRead[iPage].PTE = pMmpte;

	//			PHYSICAL_ADDRESS phyAddress = uMmGetPhysicalAddressSelf(pGData, Process, (PVOID)(BasePtr + iPage * 0x1000));
	//			ULONGLONG PageNumber = phyAddress.QuadPart >> 12;

	//			if (phyAddress.QuadPart == 0) {

	//				break;

	//			}

	//			pMmpte->u.Hard.PageFrameNumber = PageNumber;
	//			__invlpg(pMmpte);

	//			uIndex++;

	//		}

	//		FREE_FUNCTION_ENTRY(MmGetPhysicalAddressSelf, uMmGetPhysicalAddressSelf);

	//		fNtos->DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, AArry->Line_Ptr_DWORD.Ptr,
	//			__LINE__, uIndex, _nSize);

	//		if (uIndex == nPageSzie) {

	//			if (Flags) {

	//				fNtos->DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, AArry->Line_Ptr_DWORD.Ptr,
	//					__LINE__, nPageSzie, _nSize);

	//				fNtos->CopyMemory(Adr + Offset, _Dst, _nSize);
	//			}
	//			else {

	//				fNtos->DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, AArry->Line_Ptr_DWORD.Ptr,
	//					__LINE__, nPageSzie, _nSize);

	//				fNtos->CopyMemory(_Dst, Adr + Offset, _nSize);
	//			}
	//		}

	//		fNtos->DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, AArry->Line_Ptr_DWORD.Ptr,
	//			__LINE__, nPageSzie, _nSize);

	//		for (DWORD i = 0; i < uIndex; i++)
	//		{
	//			MMPTE* pMmpte = uRead[i].PTE;
	//			pMmpte->u.Hard.PageFrameNumber = uRead[i]._O_PageNumer;
	//			__invlpg(pMmpte);
	//		}
	//		fNtos->ExFreePoolWithTag(uRead, 'Tag');
	//		fNtos->MmFreeNonCachedMemory(Adr, nPageSzie * PAGE_SIZE);

	//		if (uIndex == nPageSzie) return 1;
	//	}
	//	return 0;
	//}


	NTSTATUS Brother_Memory(LPIOINFO pValue) {
		BOOL rError = STATUS_SUCCESS;
		if (pValue->Type == KERNEL_READ) {

			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };
			__try
			{

				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					return 5;
				}

				Mge |= 1;

				void* kBuffer = 0;

				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize, 'tag');
				}
				else
				{
					kBuffer = pValue->pVal;
				}

				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					Mge ^= 1;
					return 2;
				}

				KeStackAttachProcess(process, &stack);
				//KIRQL IRQL = KzRaiseIrql(APC_LEVEL);

				Mge |= 2;

				if (IsIsMmIsAddressValid((char*)pValue->pAdr, pValue->pAdrSize)) {
					//RtlCopyMemory(kBuffer, pValue->pAdr, pValue->pAdrSize);
					ReadSafeMemory(pValue->pAdr, kBuffer, pValue->pAdrSize);
				}
				else
				{
					rError = 3;
				}
				//KeLowerIrql(IRQL);

				// 内存读写  申请了 可能没有提交


				//__try {
				//	ProbeForRead(pValue->pAdr, pValue->pAdrSize, 1);
				//	//KIRQL Irql = KzRaiseIrql(DISPATCH_LEVEL);
				//	RtlCopyMemory(kBuffer, pValue->pAdr, pValue->pAdrSize);
				//	//KeLowerIrql(Irql);
				//}
				//__except (1) {
				//	rError = 3;
				//}



				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				ObDereferenceObject(process);
				Mge ^= 1;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress) {
					RtlCopyMemory(pValue->pVal, kBuffer, pValue->pAdrSize);
					ExFreePoolWithTag(kBuffer, 'tag');
				}
			}
			__except (1) {

				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}
				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());

			}
		}
		else if (pValue->Type == KERNEL_WRITE)
		{

			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };

			__try {
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					return 5;
				}
				if (process == NULL)
				{
					return 1;
				}
				Mge |= 1;
				void* kBuffer = 0;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize, 'tag');
				}
				else
				{
					kBuffer = pValue->pVal;
				}


				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					return 2;
				}
				RtlCopyMemory(kBuffer, pValue->pVal, pValue->pValSize);

				//LOG_DEBUG("Debug  <%p>   %I64X\n", pValue->pAdr, *(DWORD64*)kBuffer);


				KeStackAttachProcess(process, &stack);
				Mge |= 2;
				//	KIRQL IRQL = KzRaiseIrql(APC_LEVEL);
				if (IsIsMmIsAddressValid((char*)pValue->pAdr, pValue->pAdrSize))
				{
					writeSafeMemory(pValue->pAdr, kBuffer, pValue->pAdrSize);
				}
				else
				{
					LOG_DEBUG("Debug  %I64X   Err 3\n", *(DWORD64*)kBuffer);
					rError = 3;
				}

				//	KeLowerIrql(IRQL);

					//__try
					//{
					//	ProbeForWrite(pValue->pAdr, pValue->pAdrSize, 1);
					//	RtlCopyMemory(pValue->pAdr, kBuffer, pValue->pAdrSize);
					//}
					//__except (1) {
					//	rError = 3;
					//}
				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				//LOG_DEBUG("Debug  %I64X\n", *(DWORD64*)kBuffer);


				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					ExFreePoolWithTag(kBuffer, 'tag');
				}
				ObDereferenceObject(process);
				Mge ^= 1;
			}
			__except (1) {

				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}

				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());
			}
		}
		else if (pValue->Type == KERNEL_POOL) {

			PEPROCESS process = NULL;
			if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
			{
				return 5;
			}
			if (process == NULL)
			{
				return 1;
			}

			PVOID addr = 0;
			size_t size = pValue->pAdrSize;

			PHYSICAL_ADDRESS Phy_Address = { 0 };
			KAPC_STATE stack = { 0 };
			KeStackAttachProcess(process, &stack);
			NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&stack);
				ObDereferenceObject(process);
				return status;
			}
			if (addr != 0)
			{
				RtlZeroMemory(addr, size);
				Phy_Address = MmGetPhysicalAddress(addr);
				pValue->pAdr = (LPVOID)Phy_Address.QuadPart;
				//LOG_DEBUG(" PhysicalAddress %I64X \n", Phy_Address.QuadPart);

			}
			KeUnstackDetachProcess(&stack);
			//Mge ^= 2;
			if (addr != 0) {
				pValue->pVal = addr;
				//if (Phy_Address.QuadPart != 0)
				//{
				//	PVOID self = MmMapIoSpace(Phy_Address, size, MmCached);
				//	pValue->pAdr = self;
				//}
			}
			ObDereferenceObject(process);
			//Mge ^= 1;

			//void* kBuffer = ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize, 'tag');
			//if (kBuffer == NULL)
			//{
			//	ObDereferenceObject(process);
			//	return 2;
			//}
			////RtlCopyMemory(kBuffer, pValue->pVal, pValue->pValSize);
			//if (PsGetCurrentProcessId() == (HANDLE)pValue->pID)
			//{
			//	PMDL pMdl = 0;
			//	PVOID Buffer = LoadMemoryToUser(&pMdl, kBuffer, pValue->pAdrSize, UserMode, pValue->pValSize);
			//	if (Buffer != 0)
			//	{
			//		pValue->pVal = Buffer;
			//		pValue->pAdr = Buffer;
			//	}
			//	else
			//	{
			//		rError = 3;
			//	}

			//}
			//else
			//{
			//	KAPC_STATE stack = { 0 };
			//	KeStackAttachProcess(process, &stack);
			//	PMDL pMdl = 0;
			//	PVOID Buffer = LoadMemoryToUser(&pMdl, kBuffer, pValue->pAdrSize, UserMode, pValue->pValSize);
			//	pValue->pVal = Buffer;

			//	ULONG oldProtection = 0;
			//	NTSTATUS	status = ZwProtectVirtualMemory(ZwCurrentProcess(),
		 //                    &Buffer,
		 //                    &pValue->pAdrSize,
		 //                    PAGE_EXECUTE_READWRITE,
		 //                    &oldProtection);

			//	if (!NT_SUCCESS(status))
			//	{
			//		rError = 6;
			//	}
			//	KeUnstackDetachProcess(&stack);

			//	PVOID BufferSelf = LoadMemoryToUser(&pMdl, kBuffer, pValue->pAdrSize, UserMode, pValue->pValSize);
			//	pValue->pAdr = BufferSelf;
			//}
			//ObDereferenceObject(process);
		}
		else if (pValue->Type == KERNEL_READ_LIST) {


			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };

			__try
			{
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					return 5;
				}

				char* kBuffer = 0;
				Mge |= 1;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = (char*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE * 8, 'tag');
				}
				else
				{
					kBuffer = (char*)pValue->pVal;
				}

				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					return 2;
				}



				int nSize = 0;

				int ReadOffset = pValue->pAdrSize;

				//char* DBUFFER = kBuffer;

				int ReadSize = LOWORD(pValue->pValSize);

				int Readbegin = HIWORD(pValue->pValSize);

				int MaxSize = (SEND_SIZE - 12 - sizeof(IOINFO)) / ReadSize;






				LOG_DEBUG("ReadOffset %d ReadSize %d Readbegin %d MaxSize %d\n", ReadOffset, ReadSize, Readbegin, MaxSize);

				KeStackAttachProcess(process, &stack);
				//KIRQL IRQL = KzRaiseIrql(APC_LEVEL);
				Mge |= 2;
				DWORD64 _Begin = (DWORD64)pValue->pAdr;

				DWORD64 _Next = (DWORD64)_Begin;

				//for (size_t i = 0; i < 400; i++)
				//{
				//	IsIsMmIsAddressValid(_Next, ReadSize);
				//	ReadSafeMemory(_Next + ReadOffset, kBuffer, 8);
				//}

				do
				{
					if (!IsIsMmIsAddressValid((char*)_Next, ReadSize)) {

						break;
					}

					// 读指针数据
					//RtlCopyMemory(kBuffer + nSize * ReadSize, _Next + Readbegin, ReadSize);

					//RtlCopyMemory(&_Next, _Next + ReadOffset, 8);

					ReadSafeMemoryV((PVOID)(_Next + Readbegin), kBuffer + (nSize * ReadSize), ReadSize);
					// 下一个指针
					ReadSafeMemoryV((PVOID)(_Next + ReadOffset), &_Next, 8);
					//memcpy_s()
					if (_Next == (DWORD64)_Begin || _Next == 0 || (_Next % 4 != 0)) {
						break;
					}
					nSize++;
					if (nSize >= MaxSize) {
						break;
					}
				} while (_Next != (DWORD64)_Begin);

				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				ObDereferenceObject(process);
				Mge ^= 1;

				pValue->pValSize = nSize;
				pValue->pAdrSize = MaxSize;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					RtlCopyMemory(pValue->pVal, kBuffer, nSize * ReadSize);
					ExFreePoolWithTag(kBuffer, 'tag');
				}

			}
			__except (1) {

				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}



				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());

			}
		}
		else if (pValue->Type == KERNEL_READ_OFFSET) {

			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };

			__try
			{

				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					return 5;
				}
				if (process == NULL)
				{
					return 1;
				}
				Mge |= 1;
				char* kBuffer = 0;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = (char*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE * 8, 'tag');
					RtlCopyMemory(kBuffer, pValue->pVal, pValue->pValSize * 4);
				}
				else
				{
					kBuffer = (char*)pValue->pVal;
				}

				//void* kBuffer = pValue->pVal /*ExAllocatePoolWithTag(PagedPool, PAGE_SIZE * 8, 'tag')*/;
				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					return 2;
				}



				int nSize = pValue->pValSize;

				DWORD* DBUFFER = (DWORD*)kBuffer;


				KeStackAttachProcess(process, &stack);

				Mge |= 2;
				//KIRQL IRQL = KzRaiseIrql(APC_LEVEL);
				PVOID _Begin = (char*)pValue->pAdr;
				PVOID _Next = _Begin;

				for (size_t i = 0; i < nSize; i++)
				{

					int cSize = i != (nSize - 1) ? 8 : pValue->pAdrSize;

					if (!IsIsMmIsAddressValid((char*)((DWORD64)_Next + DBUFFER[i]), cSize)) {
						break;
					}

					if (i != (nSize - 1))
					{
						ReadSafeMemoryV((PVOID)((DWORD64)_Next + DBUFFER[i]), &_Next, 8);
					}
					else
					{
						ReadSafeMemoryV((PVOID)((DWORD64)_Next + DBUFFER[i]), kBuffer, pValue->pAdrSize);
					}
				}
				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				ObDereferenceObject(process);
				Mge ^= 1;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					RtlCopyMemory(pValue->pVal, kBuffer, pValue->pAdrSize);
					ExFreePoolWithTag(kBuffer, 'tag');
				}
			}
			__except (1) {
				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}
				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());

			}
		}
		else if (pValue->Type == KERNEL_READ_NEWWORLD_1) {

			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };
			__try
			{
				PEPROCESS process = NULL;
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					return 5;
				}

				char* kBuffer = 0;
				Mge |= 1;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = (char*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE * 8, 'tag');
				}
				else
				{
					kBuffer = (char*)pValue->pVal;
				}

				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					return 2;
				}

				//char* DBUFFER = kBuffer;

				int MaxSize = SEND_SIZE - 12 - sizeof(IOINFO);


				DWORD64* Adr = (DWORD64*)pValue->pAdr; // 数据的起始点

				DWORD nSizeAdr = pValue->pValSize;  // 要读的数据个数

				typedef struct _SizeName {
					DWORD Begin;
					DWORD Size;
				}SizeName;

				SizeName* pSizeName = (SizeName*)kBuffer;

				ULONG NameOffset = (sizeof(SizeName)) * nSizeAdr;

				char* Name = (char*)kBuffer;

				DWORD offsetA = LOWORD(pValue->pAdrSize);

				DWORD offsetB = HIWORD(pValue->pAdrSize);

				typedef struct _ObjName_NewWorld {
					DWORD64 Val[2];
					DWORD64 Len;
					DWORD64 MaxLen;
				}ObjName_NewWorld;



				//LOG_DEBUG("ReadOffset %08X ReadSize %08X Readbegin %08X MaxSize %08X\n", offsetA, offsetB, NameOffset, nSizeAdr);
				KeStackAttachProcess(process, &stack);

				Mge |= 2;

				for (size_t i = 0; i < nSizeAdr; i++) {

					DWORD64 Ptr = Adr[i];
					if (ReadSafeMemoryV((PVOID)(Ptr + offsetA), &Ptr, 8))
					{
						ObjName_NewWorld NameWorld = { 0 };
						if (ReadSafeMemoryV((PVOID)(Ptr + offsetB), &NameWorld, sizeof(NameWorld))) {

							//ULONG gLen = NameWorld.Len & 0xFFFFFFFF;
							if (NameOffset + NameWorld.Len > MaxSize) {

								break;
							}
							if (NameWorld.MaxLen < 0x10 && NameWorld.Len < 0x10) {

								pSizeName[i].Begin = NameOffset;
								pSizeName[i].Size = (DWORD)(NameWorld.Len + 1);
								RtlCopyMemory(Name + NameOffset, &NameWorld, pSizeName[i].Size);
								NameOffset += pSizeName[i].Size;
								continue;
							}
							else if (NameWorld.Len < 0x40)
							{
								pSizeName[i].Begin = NameOffset;
								pSizeName[i].Size = (DWORD)(NameWorld.Len + 1);
								//RtlCopyMemory(Name + NameOffset, &NameWorld, pSizeName[i].Size);
								ReadSafeMemoryV((PVOID)NameWorld.Val[0], Name + NameOffset, pSizeName[i].Size);
								NameOffset += pSizeName[i].Size;
								continue;
							}
						}
					}
					pSizeName[i].Begin = NameOffset;
					pSizeName[i].Size = 1;
					RtlZeroMemory(Name + NameOffset, 1);
					NameOffset++;
					if (NameOffset + 1 > (ULONG)MaxSize) {
						break;
					}
				}


				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				ObDereferenceObject(process);
				Mge ^= 1;

				pValue->pValSize = NameOffset;
				pValue->pAdrSize = NameOffset;

				if ((ULONG64)pValue->pVal < MmUserProbeAddress) {
					RtlCopyMemory(pValue->pVal, kBuffer, NameOffset);
					ExFreePoolWithTag(kBuffer, 'tag');
				}
			}
			__except (1) {
				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}
				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());
				rError = 5;
			}

		}
		else if (pValue->Type == KERNEL_READ_NEWWORLD_2) {

			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };
			__try
			{
				PEPROCESS process = NULL;
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					return 5;
				}

				char* kBuffer = 0;
				Mge |= 1;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = (char*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE * 8, 'tag');
				}
				else
				{
					kBuffer = (char*)pValue->pVal;
				}

				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					return 2;
				}

				//char* DBUFFER = kBuffer;

				int MaxSize = SEND_SIZE - 12 - sizeof(IOINFO);


				DWORD64* Adr = (DWORD64*)pValue->pAdr; // 数据的起始点

				DWORD nSizeAdr = pValue->pValSize;  // 要读的数据个数

				typedef struct _SizeName {
					DWORD Begin;
					DWORD Size;
				}SizeName;

				SizeName* pSizeName = (SizeName*)kBuffer;

				ULONG NameOffset = (sizeof(SizeName)) * nSizeAdr;

				char* Name = (char*)kBuffer;

				//DWORD offsetA = LOWORD(pValue->pAdrSize);

				//DWORD offsetB = HIWORD(pValue->pAdrSize);

				//typedef struct _ObjName_NewWorld {
				//	DWORD64 Val[2];
				//	DWORD64 Len;
				//}ObjName_NewWorld;
				//LOG_DEBUG("ReadOffset %08X ReadSize %08X Readbegin %08X MaxSize %08X\n", offsetA, offsetB, NameOffset, nSizeAdr);
				KeStackAttachProcess(process, &stack);
				Mge |= 2;
				for (size_t i = 0; i < nSizeAdr; i++) {

					DWORD64 Ptr = Adr[i];

					if (ReadSafeMemoryV((PVOID)Ptr, &Ptr, 8))
					{
						DWORD64 GetComponentNameAddr = 0;

						if (ReadSafeMemoryV((PVOID)(Ptr + 8), &GetComponentNameAddr, 8)) {

							//ULONG gLen = NameWorld.Len & 0xFFFFFFFF;
							DWORD componentNameOffset = 0;
							if (ReadSafeMemoryV((PVOID)(GetComponentNameAddr + 3), &componentNameOffset, 4)) {
								DWORD64 cn = GetComponentNameAddr + 7 + componentNameOffset;
								char tName[0x42] = { 0 };
								if (ReadSafeMemoryV((PVOID)cn, tName, 0x40)) {
									int Size = strnlen_s(tName, 0x42);

									pSizeName[i].Begin = NameOffset;
									pSizeName[i].Size = Size + 1;
									RtlCopyMemory(Name + NameOffset, tName, pSizeName[i].Size);
									NameOffset += pSizeName[i].Size;
									continue;
								}

							}
						}
					}
					pSizeName[i].Begin = NameOffset;
					pSizeName[i].Size = 1;
					RtlZeroMemory(Name + NameOffset, 1);
					NameOffset++;
					if (NameOffset + 1 > (ULONG)MaxSize) {
						break;
					}
				}

				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				ObDereferenceObject(process);
				Mge ^= 1;

				pValue->pValSize = NameOffset;
				pValue->pAdrSize = NameOffset;

				if ((ULONG64)pValue->pVal < MmUserProbeAddress) {
					RtlCopyMemory(pValue->pVal, kBuffer, NameOffset);
					ExFreePoolWithTag(kBuffer, 'tag');
				}
			}
			__except (1) {
				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}
				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());
				rError = 5;
			}

		}
		else if (pValue->Type == KERNEL_READ_NEWWORLD_3) {

			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };
			__try
			{

				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					return 5;
				}
				Mge |= 1;
				char* kBuffer = 0;

				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = (char*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE * 8, 'tag');
				}
				else
				{
					kBuffer = (char*)pValue->pVal;
				}

				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					return 2;
				}

				//char* DBUFFER = kBuffer;

				int MaxSize = SEND_SIZE - 12 - sizeof(IOINFO);


				DWORD64* Adr = (DWORD64*)pValue->pAdr; // 数据的起始点

				DWORD nSizeAdr = pValue->pValSize;  // 要读的数据个数

				typedef struct _SizeName {
					DWORD Begin;
					DWORD Size;
				}SizeName;

				SizeName* pSizeName = (SizeName*)kBuffer;

				ULONG NameOffset = (sizeof(SizeName)) * nSizeAdr;

				char* Name = (char*)kBuffer;

				DWORD offsetA = LOWORD(pValue->pAdrSize);

				DWORD offsetB = HIWORD(pValue->pAdrSize);

				typedef struct _ObjName_NewWorld {
					DWORD64 Val[2];
					DWORD64 Len;
					DWORD64 MaxLen;
				}ObjName_NewWorld;



				//LOG_DEBUG("ReadOffset %08X ReadSize %08X Readbegin %08X MaxSize %08X\n", offsetA, offsetB, NameOffset, nSizeAdr);
				KeStackAttachProcess(process, &stack);
				Mge |= 2;
				for (size_t i = 0; i < nSizeAdr; i++) {

					DWORD64 Ptr = Adr[i];


					ObjName_NewWorld NameWorld = { 0 };
					if (ReadSafeMemoryV((PVOID)(Ptr + offsetA), &NameWorld, sizeof(NameWorld))) {

						//ULONG gLen = NameWorld.Len & 0xFFFFFFFF;
						if (NameOffset + NameWorld.Len > MaxSize) {

							break;
						}
						if (NameWorld.MaxLen < 0x10 && NameWorld.Len < 0x10) {

							pSizeName[i].Begin = NameOffset;
							pSizeName[i].Size = (DWORD)(NameWorld.Len + 1);
							RtlCopyMemory(Name + NameOffset, &NameWorld, pSizeName[i].Size);
							NameOffset += pSizeName[i].Size;
							continue;
						}
						else if (NameWorld.Len < 0x40)
						{
							pSizeName[i].Begin = NameOffset;
							pSizeName[i].Size = (DWORD)(NameWorld.Len + 1);
							//RtlCopyMemory(Name + NameOffset, &NameWorld, pSizeName[i].Size);
							ReadSafeMemoryV((PVOID)NameWorld.Val[0], Name + NameOffset, pSizeName[i].Size);
							NameOffset += pSizeName[i].Size;
							continue;
						}
					}
					pSizeName[i].Begin = NameOffset;
					pSizeName[i].Size = 1;
					RtlZeroMemory(Name + NameOffset, 1);
					NameOffset++;
					if (NameOffset + 1 > (ULONG)MaxSize) {
						break;
					}
				}


				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				ObDereferenceObject(process);
				Mge ^= 1;

				pValue->pValSize = NameOffset;
				pValue->pAdrSize = NameOffset;

				if ((ULONG64)pValue->pVal < MmUserProbeAddress) {
					RtlCopyMemory(pValue->pVal, kBuffer, NameOffset);
					ExFreePoolWithTag(kBuffer, 'tag');
				}
			}
			__except (1) {
				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}
				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());
				rError = 5;
			}

		}
		else if (pValue->Type == KERNEL_READ_MEMORY_0) {

			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };
			__try
			{
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					//pValue->Error = 1;
					return 1;
				}

				char* kBuffer = 0;
				Mge |= 1;
				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = (char*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE * 8, 'tag');
				}
				else
				{
					kBuffer = (char*)pValue->pVal;
				}

				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					return 2;
				}

				//char* DBUFFER = kBuffer;

				int MaxSize = SEND_SIZE - 12 - sizeof(IOINFO);


				DWORD64* Adr = (DWORD64*)pValue->pAdr; // 数据的起始点

				DWORD nSizeAdr = pValue->pValSize;  // 要读的数据个数

				typedef struct _SizeName {
					DWORD Begin;
					DWORD Size;
				}SizeName;

				SizeName* pSizeName = (SizeName*)kBuffer;

				ULONG NameOffset = (sizeof(SizeName)) * nSizeAdr;

				char* Name = (char*)kBuffer;

				DWORD nStructSize = LOWORD(pValue->pAdrSize);

				///DWORD offsetB = HIWORD(pValue->pAdrSize);

				if (NameOffset + nStructSize * nSizeAdr > MaxSize) {


					if ((ULONG64)pValue->pVal < MmUserProbeAddress)
					{
						ExFreePoolWithTag(kBuffer, 'tag');
					}
					ObDereferenceObject(process);
					return 3;
				}

				//LOG_DEBUG("ReadOffset %08X ReadSize %08X Readbegin %08X MaxSize %08X\n", offsetA, offsetB, NameOffset, nSizeAdr);
				//KAPC_STATE stack = { 0 };
				KeStackAttachProcess(process, &stack);

				Mge |= 2;

				for (size_t i = 0; i < nSizeAdr; i++) {



					DWORD64 Ptr = Adr[i];


					if (NameOffset + pSizeName[i].Size > MaxSize) {

						break;
					}

					pSizeName[i].Begin = NameOffset;
					pSizeName[i].Size = nStructSize;
					ReadSafeMemoryV((PVOID)(Ptr), Name + NameOffset, pSizeName[i].Size);
					NameOffset += pSizeName[i].Size;
				}
				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				ObDereferenceObject(process);
				Mge ^= 1;
				pValue->pValSize = NameOffset;
				pValue->pAdrSize = NameOffset;

				if ((ULONG64)pValue->pVal < MmUserProbeAddress) {
					RtlCopyMemory(pValue->pVal, kBuffer, NameOffset);
					ExFreePoolWithTag(kBuffer, 'tag');
				}
			}
			__except (1) {
				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}
				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());
				rError = 5;
			}

		}
		else if (pValue->Type == KERNEL_READ_MEMORY_1) {
			DWORD Mge = 0;
			PEPROCESS process = NULL;
			KAPC_STATE stack = { 0 };
			__try
			{

				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pValue->pID, &process)))
				{
					return 5;
				}
				Mge |= 1;
				char* kBuffer = 0;

				if ((ULONG64)pValue->pVal < MmUserProbeAddress)
				{
					kBuffer = (char*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE * 8, 'tag');
				}
				else
				{
					kBuffer = (char*)pValue->pVal;
				}

				if (kBuffer == NULL)
				{
					ObDereferenceObject(process);
					return 2;
				}

				//char* DBUFFER = kBuffer;

				int MaxSize = SEND_SIZE - 12 - sizeof(IOINFO);


				typedef struct _Irregular {
					DWORD64 Ptr;
					DWORD64 nSize;
				}Irregular;


				Irregular* Adr = (Irregular*)pValue->pAdr; // 数据的起始点

				DWORD nSizeAdr = pValue->pValSize;  // 要读的数据个数

				typedef struct _SizeName {
					DWORD Begin;
					DWORD Size;
				}SizeName;

				SizeName* pSizeName = (SizeName*)kBuffer;

				ULONG NameOffset = (sizeof(SizeName)) * nSizeAdr;

				char* Name = (char*)kBuffer;

				//DWORD nStructSize = LOWORD(pValue->pAdrSize);

				///DWORD offsetB = HIWORD(pValue->pAdrSize);

				//if (NameOffset + nStructSize * nSizeAdr > MaxSize) {

				//	ObDereferenceObject(process);
				//	return 3;
				//}

				//LOG_DEBUG("ReadOffset %08X ReadSize %08X Readbegin %08X MaxSize %08X\n", offsetA, offsetB, NameOffset, nSizeAdr);
				KeStackAttachProcess(process, &stack);

				Mge |= 2;

				for (size_t i = 0; i < nSizeAdr; i++) {

					if (NameOffset + (Adr[i].nSize & 0xFFFF) > MaxSize) {
						break;
					}
					DWORD64 Ptr = Adr[i].Ptr;
					pSizeName[i].Begin = NameOffset;
					pSizeName[i].Size = (Adr[i].nSize & 0xFFFF);
					ReadSafeMemoryV((PVOID)(Ptr), Name + NameOffset, pSizeName[i].Size);
					NameOffset += pSizeName[i].Size;
				}
				KeUnstackDetachProcess(&stack);
				Mge ^= 2;
				ObDereferenceObject(process);
				Mge ^= 1;
				pValue->pValSize = NameOffset;
				pValue->pAdrSize = NameOffset;

				if ((ULONG64)pValue->pVal < MmUserProbeAddress) {
					RtlCopyMemory(pValue->pVal, kBuffer, NameOffset);
					ExFreePoolWithTag(kBuffer, 'tag');
				}
			}
			__except (1) {
				if (Mge & 1) {
					ObDereferenceObject(process);
				}
				if (Mge & 2)
				{
					KeUnstackDetachProcess(&stack);
				}
				LOG_DEBUG("except %s %08X\n ", __FUNCTION__, GetExceptionCode());
				rError = 5;
			}

		}
		return rError;

	}

	//typedef NTSTATUS(NTAPI *_ZwCreateThreadEx)(
	//	OUT PHANDLE ThreadHandle,
	//	IN ACCESS_MASK DesiredAccess,
	//	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	//	IN HANDLE ProcessHandle,
	//	IN PTHREAD_START_ROUTINE StartRoutine,
	//	IN PVOID StartContext,
	//	IN ULONG CreateThreadFlags,
	//	IN SIZE_T ZeroBits OPTIONAL,
	//	IN SIZE_T StackSize OPTIONAL,
	//	IN SIZE_T MaximumStackSize OPTIONAL,
	//	IN PPROC_THREAD_ATTRIBUTE_LIST AttributeList
	//	);


#define SystemProcessesAndThreadsInformation 5


#pragma pack(push, 8)

	typedef enum _THREAD_STATE
	{
		StateInitialized,
		StateReady,
		StateRunning,
		StateStandby,
		StateTerminated,
		StateWait,
		StateTransition,
		StateUnknown
	} THREAD_STATE;


	typedef struct _SYSTEM_THREADS_X64
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		KPRIORITY BasePriority;
		ULONG ContextSwitchCount;
		THREAD_STATE ThreadState;
		KWAIT_REASON WaitReason;
		ULONG Reserved;
	} SYSTEM_THREADS_X64, * PSYSTEM_THREADS_X64;

	typedef struct _SYSTEM_PROCESSES
	{
		ULONG NextEntryDelta; //构成结构序列的偏移量;
		ULONG ThreadCount; //线程数目;
		ULONG Reserved1[6];
		LARGE_INTEGER CreateTime; //创建时间;
		LARGE_INTEGER UserTime;//用户模式(Ring 3)的CPU时间;
		LARGE_INTEGER KernelTime; //内核模式(Ring 0)的CPU时间;
		UNICODE_STRING ProcessName; //进程名称;
		KPRIORITY BasePriority;//进程优先权;
		HANDLE ProcessId; //进程标识符;
		HANDLE InheritedFromProcessId; //父进程的标识符;
		ULONG HandleCount; //句柄数目;
		ULONG Reserved2[2];
		ULONG_PTR PageDirectoryBase;
		VM_COUNTERS  VmCounters; //虚拟存储器的结构，见下;
		SIZE_T PrivatePageCount;
		IO_COUNTERS IoCounters; //IO计数结构，见下;
		struct _SYSTEM_THREADS_X64 Threads[1]; //进程相关线程的结构数组

	} _SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;
#pragma pack(pop)

	NTSTATUS FindProcessID(UNICODE_STRING * ProcessName ,DWORD *pSize, DWORD * ProcessArry){

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PSYSTEM_PROCESSES pProcessInfo = NULL;
		PSYSTEM_PROCESSES pTemp = NULL;//这个留作以后释放指针的时候用。
		ULONG ulNeededSize;
		ULONG ulNextOffset;

		//第一次使用肯定是缓冲区不够，不过本人在极少数的情况下第二次也会出现不够，所以用while循环


		LOG_DEBUG("FindProcessID %ws \n", ProcessName->Buffer);
		*pSize = 0;
		status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pProcessInfo, 0, &ulNeededSize);
		if (STATUS_INFO_LENGTH_MISMATCH == status)
		{
			pProcessInfo = (PSYSTEM_PROCESSES)ExAllocatePoolWithTag(NonPagedPool, ulNeededSize, '1aes');
			pTemp = pProcessInfo;
			if (NULL == pProcessInfo)
			{
				KdPrint(("[allocatePoolWithTag] failed"));
				return status;
			}
			status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pProcessInfo, ulNeededSize, &ulNeededSize);

		}
		if (NT_SUCCESS(status))
		{
			KdPrint(("[ZwQuerySystemInformation]success bufferSize:%x", ulNeededSize));
		}
		else
		{
			KdPrint(("[error]:++++%d", status));
			return status;
		}

		do
		{
			KdPrint(("[imageName Buffer]:%08x", pProcessInfo->ProcessName.Buffer));
			if (MmIsAddressValid(pProcessInfo->ProcessName.Buffer) && NULL != pProcessInfo)
			{
				if (RtlEqualUnicodeString(ProcessName, &pProcessInfo->ProcessName, TRUE)){
					ProcessArry[*pSize] = (DWORD)(DWORD64)pProcessInfo->ProcessId;
					(*pSize)++;
					KdPrint(("find [ProcessID]:%d , [imageName]:%ws", pProcessInfo->ProcessId, pProcessInfo->ProcessName.Buffer));
				}

				//KPRIORITY BasePriority;//进程优先权;
				//HANDLE ProcessId; //进程标识符;
				//HANDLE InheritedFromProcessId; //父进程的标识符;
				//ULONG HandleCount; //句柄数目;
				//ULONG Reserved2[2];
				KdPrint(("[ProcessID]:%d , [imageName]:%ws", pProcessInfo->ProcessId, pProcessInfo->ProcessName.Buffer));
				//KdPrint(("[BasePriority]:%d", pProcessInfo->BasePriority));
				//KdPrint(("[InheritedFromProcessId]:%d", pProcessInfo->InheritedFromProcessId));
				//KdPrint(("[HandleCount]:%d", pProcessInfo->HandleCount));
				//KdPrint(("[Reserved2 0]:%d", pProcessInfo->Reserved2[0]));
				//KdPrint(("[Reserved2 1]:%d", pProcessInfo->Reserved2[1]));
			}

			ulNextOffset = pProcessInfo->NextEntryDelta;
			pProcessInfo = (PSYSTEM_PROCESSES)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryDelta);

		} while (ulNextOffset != 0);

		ExFreePoolWithTag(pTemp, '1aes');

		return status;
	}
	


	DWORD GetProcessSessionWithNumber(DWORD SessionID) {

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PSYSTEM_PROCESSES pProcessInfo = NULL;
		PSYSTEM_PROCESSES pTemp = NULL;//这个留作以后释放指针的时候用。
		ULONG ulNeededSize;
		ULONG ulNextOffset;

		//第一次使用肯定是缓冲区不够，不过本人在极少数的情况下第二次也会出现不够，所以用while循环
		status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pProcessInfo, 0, &ulNeededSize);
		while (STATUS_INFO_LENGTH_MISMATCH == status)
		{
			pProcessInfo = (PSYSTEM_PROCESSES)ExAllocatePoolWithTag(NonPagedPool, ulNeededSize, '1aes');
			pTemp = pProcessInfo;
			if (NULL == pProcessInfo)
			{
				KdPrint(("[allocatePoolWithTag] failed"));
				return status;
			}
			status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pProcessInfo, ulNeededSize, &ulNeededSize);
		}
		if (NT_SUCCESS(status))
		{
			//KdPrint(("[ZwQuerySystemInformation]success bufferSize:%x", ulNeededSize));
		}
		else
		{
			//KdPrint(("[error]:++++%d", status));
			return status;
		}

		do
		{
			//KdPrint(("[imageName Buffer]:%08x", pProcessInfo->ProcessName.Buffer));
			if (MmIsAddressValid(pProcessInfo->ProcessName.Buffer) && NULL != pProcessInfo){

				PEPROCESS eprocess;
				if (NT_SUCCESS(PsLookupProcessByProcessId(pProcessInfo->ProcessId, &eprocess)))
				{
					int SessID = PsGetProcessSessionId(eprocess);
					LOG_DEBUG("%08X  %d  %ws\n", SessID, pProcessInfo->ProcessId, pProcessInfo->ProcessName.Buffer);
					ObDereferenceObject(eprocess);

					if (SessID == SessionID){
						return (DWORD)(DWORD64)pProcessInfo->ProcessId;
					}
				}
	

				//KdPrint(("[ProcessID]:%d , [imageName]:%ws", pProcessInfo->ProcessId, pProcessInfo->ProcessName.Buffer));

			}
			ulNextOffset = pProcessInfo->NextEntryDelta;
			pProcessInfo = (PSYSTEM_PROCESSES)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryDelta);

		} while (ulNextOffset != 0);

		ExFreePoolWithTag(pTemp, '1aes');

		return status;
	}



	NTSTATUS Brother_Process(LPIOINFO pValue) {
		//LOG_DEBUG("HideProcess PID:%d Type :%d\n",pValue->pID, pValue->Type);
		if (pValue->Type == 0)
		{
			HideProcess((HANDLE)pValue->pID, pValue->pAdrSize);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 1)
		{
			ShowProcess((HANDLE)pValue->pID);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 2)
		{
			pValue->pAdr = GetProcessHandle((HANDLE)pValue->pID);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 3)
		{
			//pValue->pValSize = IsMmIsAddressValid((HANDLE)pValue->pID, pValue->pAdr);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 4)
		{
			UNICODE_STRING str1;
			RtlInitUnicodeString(&str1, L"ZwCreateThreadEx");
			MmGetSystemRoutineAddress(&str1);
			PEPROCESS process = NULL;
			PsLookupProcessByProcessId((HANDLE)pValue->pID, &process);
			if (process == NULL)
			{
				LOG_DEBUG("获取进程对象失败\n");
				return 1;
			}
			//KAPC_STATE stack = { 0 };
			//KeStackAttachProcess(process, &stack);
			//HANDLE handle = 0;
			////NTSTATUS status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), NULL,
			////	pValue->pAdr, pValue->pVal);
			//if (!NT_SUCCESS(status))
			//{
			//	pValue->Error = status;
			//}
			//KeUnstackDetachProcess(&stack);
			ObDereferenceObject(process);
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 5)
		{

			char* NAME = "steam.exe";
			TABLE_STRING_FILTER uFilter = { 0 };
			RtlInitString(&uFilter.stringSrc, NAME);
			TABLE_STRING_FILTER* pVl = wGetStringAvl(&uFilter);
			if (pVl != 0)
			{
				//LOG_DEBUG("find Table\n");
				pValue->pID = (DWORD)(DWORD64)findTablePID(pVl);

				if (pValue->pID != 0)
				{
					LOG_DEBUG("fIND STEAM\n");
				}

			}
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 6)
		{
			char* NAME = "steam.exe";
			TABLE_STRING_FILTER uFilter = { 0 };
			RtlInitString(&uFilter.stringSrc, NAME);
			TABLE_STRING_FILTER* pVl = wGetStringAvl(&uFilter);
			if (pVl != 0)
			{
				LOG_DEBUG("del STEAM\n");
				DelTable(pVl, (HANDLE)pValue->pID);
			}
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 7)
		{
			PEPROCESS eprocess = 0;
			PsLookupProcessByProcessId((HANDLE)pValue->pID, &eprocess);
			if (eprocess != 0)
			{
				PsResumeProcess(eprocess);
				ObDereferenceObject(eprocess);

			}
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 8)
		{

			//ZwQuerySystemInformation()

			//ObQueryNameString(,)

			//ZwQuerySystemInformation(16, );
			
			//DWORD dwNeedSize = 0;
			//if (STATUS_INFO_LENGTH_MISMATCH == ZwQuerySystemInformation(16, 0, 0, &dwNeedSize))
			//{
			//	PVOID Buffer = ExAllocatePoolWithTag(PagedPool, dwNeedSize + 0x100, 'tag');
			//	if (Buffer != NULL)
			//	{
			//		if (NT_SUCCESS(ZwQuerySystemInformation(16, Buffer, dwNeedSize + 0x100, 0)))
			//		{





			//			//ObjectNameInformation
			//			//ObjectTypeInformation
			//			//ZwQueryObject(,)


			//		}  
			//		ExFreePoolWithTag(Buffer, 'tag');
			//	}
			//} 
			//PEPROCESS eprocess = 0;
			//PsLookupProcessByProcessId((HANDLE)pValue->pID, &eprocess);
			//if (eprocess != 0)
			//{
			//	PsResumeProcess(eprocess);
			//	ObDereferenceObject(eprocess);

			//}
			//return STATUS_SUCCESS;
		}
		else if (pValue->Type == 9)
		{
		if (pValue->pAdrSize >= MAX_PATH)
		{
			pValue->Error = 1;
		}
		else
		{
			wchar_t wName[MAX_PATH] = { 0 };
			RtlCopyMemory(wName, pValue->pAdr, pValue->pAdrSize);

			UNICODE_STRING uNameProcess;
			RtlInitUnicodeString(&uNameProcess, wName);
			DWORD* dwPSize = (DWORD*)pValue->pVal;
			DWORD* pProcessArry = dwPSize + 1;
			FindProcessID(&uNameProcess, dwPSize, pProcessArry);
			pValue->pValSize = (*dwPSize + 1) * 4;
		}




		}
		return STATUS_SUCCESS;
	}

	NTSTATUS Brother_Window(LPIOINFO pValue) {

		LOG_DEBUG("Brother_Window PID:%d Type :%08X  pValSize: %08X\n", pValue->pID, pValue->Type, pValue->pValSize);

		if (pValue->Type == 0)
		{
			//LOG_DEBUG("Brother_Window PID:%d Type :%08X  HNWD:%08X\n", pValue->pID, pValue->pValSize);
			AddForeHwnd((HANDLE)pValue->pID, (HANDLE)pValue->pValSize);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 1)
		{
			BRPOINT p;
			RtlCopyMemory(&p, &pValue->pAdr, sizeof(p));
			AddFixPoint((HANDLE)pValue->pID, p, 1);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 2)
		{
			StopFixPoint((HANDLE)pValue->pID);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 3)
		{
			BRPOINT p;
			RtlCopyMemory(&p, &pValue->pAdr, sizeof(p));
			AddFixPoint((HANDLE)pValue->pID, p, 2);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 4)
		{
			StopFixPoint((HANDLE)pValue->pID);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 5)
		{
			pValue->pAdrSize = (DWORD)(DWORD64)GetForegroundWindow();
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 6){
			//StopFixPoint((HANDLE)pValue->pID);
			pValue->pAdrSize = SetForegroundWindow((HWND)pValue->pAdrSize);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 7) {
			//StopFixPoint((HANDLE)pValue->pID);
			UNICODE_STRING uClassName;
			UNICODE_STRING uWindowName;
			RtlInitUnicodeString(&uWindowName, (PCWSTR)pValue->pVal);
			RtlInitUnicodeString(&uClassName, (PCWSTR)pValue->pAdr);

			LOG_DEBUG("%wZ  %wZ\n", &uClassName, &uWindowName);
			pValue->pAdrSize = (DWORD)(DWORD64)FindWindowW(&uClassName, &uWindowName);
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 8) {
			//StopFixPoint((HANDLE)pValue->pID);
			pValue->Error = GetWindowRect_User((HWND)pValue->pAdrSize, (LPRECTK)pValue->pVal);
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 9) {
			//StopFixPoint((HANDLE)pValue->pID);
			pValue->Error = ClientToScreen_Kernel((HWND)pValue->pAdrSize, (LPPOINT)pValue->pVal);
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 10) {
			//StopFixPoint((HANDLE)pValue->pID);
			ULONG wcharSize = 0;
			pValue->pAdrSize = GetClipboardData((HWND)pValue->pAdrSize, (wchar_t *)pValue->pVal, &wcharSize);
			pValue->pValSize = wcharSize;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 11) {
			//StopFixPoint((HANDLE)pValue->pID);
			EmptyClipboardData();
			pValue->Error = 0;
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 12) {
			//StopFixPoint((HANDLE)pValue->pID);
			EmptyClipboardData();
			pValue->Error = SetClipboardData((HWND)pValue->pAdrSize, (wchar_t *)pValue->pVal, pValue->pValSize);
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 13) {
			//StopFixPoint((HANDLE)pValue->pID);

			pValue->Error = PostMessage((HWND)pValue->pAdrSize, pValue->pValSize, (LONG_PTR)pValue->pAdr, (LONG_PTR)pValue->pVal);
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 14) {
			//StopFixPoint((HANDLE)pValue->pID);
			DEVMODEW DevMod = { 0 };
			if (EnumDisplaySettingsExW(NULL, -1, &DevMod, 0) > 0){
				LOG_DEBUG("EnumDisplaySettingsExW  r %d  %d\n", DevMod.dmPelsWidth, DevMod.dmPelsHeight);

				pValue->pAdrSize = DevMod.dmPelsWidth;
				pValue->pValSize = DevMod.dmPelsHeight;
			}
			return STATUS_SUCCESS;
		}
		else if (pValue->Type == 15) {
		//PAGE_READ
		     pValue->Error = ClientToScreen_User((HWND)pValue->pAdrSize, (LPPOINT)pValue->pVal);
		     return STATUS_SUCCESS;
        }
		else if (pValue->Type == 17) {
		//PAGE_READ
		pValue->Error = _Kernel_SetWindowLongPtr((HWND)pValue->pAdrSize, pValue->pAdr, pValue->pValSize, pValue->pVal);
		return STATUS_SUCCESS;
		}
		else if (pValue->Type == 16) {


		//PAGE_READ
		     

			POINT P = {0};
			P.x = (pValue->pAdrSize >> 16) & 0xFFFF;
			P.y = pValue->pAdrSize & 0xFFFF;

			DWORD With = (pValue->pValSize >> 16) & 0xFFFF;
			DWORD Height = pValue->pValSize & 0xFFFF;


			LOG_DEBUG("x:%d y:%d with:%d  height:%d\n", P.x, P.y, With, Height);




			if (With * Height * 4 > SEND_SIZE){
				pValue->pValSize = 0;
				return STATUS_SUCCESS;
			}
		 //  PVOID rBuffer = ExAllocatePoolWithTag(PagedPool, With * Height * 4, 'Tag');
		   pValue->pValSize = PrintPicture(P, With, Height, pValue->pVal);
		   LOG_DEBUG("nSize %d:\n", pValue->pValSize);
		  // RtlCopyMemory(pValue->pVal, rBuffer, pValue->pValSize);
		  // ExFreePoolWithTag(rBuffer, 'Tag');

		   return STATUS_SUCCESS;

		}



		//_Kernel_SetWindowLongPtr
		//STATUS_NOT_SUPPORTED
		return STATUS_SUCCESS;
	}


	NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);



	//typedef struct _OBJECT_TYPE_INITIALIZER
	//{
	//	USHORT Length;                // Uint2B
	//	UCHAR ObjectTypeFlags;            // UChar
	//	ULONG ObjectTypeCode;             // Uint4B
	//	ULONG InvalidAttributes;          // Uint4B
	//	GENERIC_MAPPING GenericMapping;   // _GENERIC_MAPPING
	//	ULONG ValidAccessMask;       // Uint4B
	//	ULONG RetainAccess;         // Uint4B
	//	POOL_TYPE PoolType;        // _POOL_TYPE
	//	ULONG DefaultPagedPoolCharge;  // Uint4B
	//	ULONG DefaultNonPagedPoolCharge; // Uint4B
	//	PVOID DumpProcedure;       // Ptr64     void
	//	PVOID OpenProcedure;      // Ptr64     long
	//	PVOID CloseProcedure;     // Ptr64     void
	//	PVOID DeleteProcedure;        // Ptr64     void
	//	PVOID ParseProcedure;     // Ptr64     long
	//	PVOID SecurityProcedure;      // Ptr64     long
	//	PVOID QueryNameProcedure;     // Ptr64     long
	//	PVOID OkayToCloseProcedure;     // Ptr64     unsigned char
	//	ULONG WaitObjectFlagMask;     // Uint4B
	//	USHORT WaitObjectFlagOffset;    // Uint2B
	//	USHORT WaitObjectPointerOffset;   // Uint2B
	//}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

	typedef struct _OBJECT_TYPE
	{
		LIST_ENTRY TypeList;           // _LIST_ENTRY
		UNICODE_STRING Name;         // _UNICODE_STRING
		PVOID DefaultObject;         // Ptr64 Void
		UCHAR Index;             // UChar
		ULONG TotalNumberOfObjects;      // Uint4B
		ULONG TotalNumberOfHandles;      // Uint4B
		ULONG HighWaterNumberOfObjects;    // Uint4B
		ULONG HighWaterNumberOfHandles;    // Uint4B
		OBJECT_TYPE_INITIALIZER TypeInfo;  // _OBJECT_TYPE_INITIALIZER
		EX_PUSH_LOCK TypeLock;         // _EX_PUSH_LOCK
		ULONG Key;                 // Uint4B
		LIST_ENTRY CallbackList;       // _LIST_ENTRY
	}OBJECT_TYPE, * POBJECT_TYPE;

#pragma pack(1)
	typedef struct _OB_CALLBACK
	{
		LIST_ENTRY ListEntry;
		ULONGLONG Unknown;
		HANDLE ObHandle;
		PVOID ObTypeAddr;
		PVOID PreCall;
		PVOID PostCall;
	}OB_CALLBACK, * POB_CALLBACK;
#pragma pack()




	HANDLE csrssH = 0;




	HANDLE FindPid(PCSZ ProcessName) {


		STRING uniFileName;

		RtlInitString(&uniFileName, ProcessName);

		POB_CALLBACK pObCallback = NULL;
		// 直接获取 CallbackList 链表
		LIST_ENTRY CallbackList = ((POBJECT_TYPE)(*PsProcessType))->CallbackList;
		// 开始遍历
		pObCallback = (POB_CALLBACK)CallbackList.Flink;
		do
		{
			if (FALSE == MmIsAddressValid(pObCallback))
			{
				break;
			}
			if (NULL != pObCallback->ObHandle)
			{
				PEPROCESS eprocess = 0;
				if (NT_SUCCESS(PsLookupProcessByProcessId(pObCallback->ObHandle, &eprocess)))
				{
					UCHAR* nameM = PsGetProcessImageFileName(eprocess);


					char nameA[0x20] = { 0 };
					RtlCopyMemory(nameA, nameM, 16);

					ObDereferenceObject(eprocess);

					STRING cName;
					RtlInitString(&cName, (PCSZ)nameA);
					LOG_DEBUG("%s %d\n", cName.Buffer, pObCallback->ObHandle);
					if (RtlCompareString(&uniFileName, &cName, TRUE) == 0) {
						return pObCallback->ObHandle;
					}

				} 

			}
			// 获取下一链表信息
			pObCallback = (POB_CALLBACK)pObCallback->ListEntry.Flink;

		} while (CallbackList.Flink != (PLIST_ENTRY)pObCallback);
		return 0;
	}




	//int  ReadMemoryRingList() {



	//}





	HANDLE getCrssPID() {

		//return FindPid("csrss.exe");

		csrssH = 0;
		__try
		{
			PEPROCESS pEprocess = NULL;
			NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &pEprocess);
			if (!NT_SUCCESS(status)) {
				return FALSE;
				LOG_DEBUG("PsLookupProcessByProcessId ERROR PID:%d\n", 4);
			}
			DWORD64 offset = getProcessOffset();
			LIST_ENTRY* fEprocess = (PLIST_ENTRY)((UINT8*)pEprocess + offset * 8);
			LIST_ENTRY* tfEprocess = fEprocess->Flink;
			//KIRQL irql = WPOFFx64();

			while (tfEprocess != fEprocess)
			{
				if (tfEprocess == 0) {
					ObDereferenceObject(pEprocess);
					return 0;
				}

				if (!MmIsAddressValid(tfEprocess))
				{
					break;
				}


				HANDLE dwPID = *((HANDLE*)((char*)tfEprocess - 8));
				PEPROCESS cEprocess = NULL;
				NTSTATUS status = PsLookupProcessByProcessId(dwPID, &cEprocess);
				if (!NT_SUCCESS(status)) {
					LOG_DEBUG("PsLookupProcessByProcessId ERROR PID:%d\n", dwPID);
					tfEprocess = tfEprocess->Flink;
					continue;
				}
				UCHAR* nameM = PsGetProcessImageFileName(cEprocess);

				STRING uniFileName;
				RtlInitString(&uniFileName, "CSRSS.EXE");

				char nameA[0x20] = { 0 };
				RtlCopyMemory(nameA, nameM, 16);
				STRING cName;
				RtlInitString(&cName, (PCSZ)nameA);
				LOG_DEBUG("%s %d", cName.Buffer, dwPID);
				if (RtlCompareString(&uniFileName, &cName, TRUE) == 0) {
					LOG_DEBUG("%s %d", cName.Buffer, dwPID);
					csrssH = dwPID;

				}
				ObDereferenceObject(cEprocess);
				if (csrssH != 0)
				{
					LOG_DEBUG("%s %d\n", cName.Buffer, dwPID);
					break;
				}
				tfEprocess = tfEprocess->Flink;
			}
			//WPONx64(irql);
			ObDereferenceObject(pEprocess);
			return csrssH;
		}
		__except (1) {
			LOG_DEBUG("__except:%08X\n", GetExceptionCode());
			return 0;
		}
		return 0;
	}

	//	_CC_PARTITION	struct { __int16 NodeTypeCode; __int16 NodeByteSize; _EPARTITION* PartitionObject; _LIST_ENTRY CleanSharedCacheMapList; _LIST_ENTRY CleanSharedCacheMapWithLogHandleList; _SHARED_CACHE_MAP_LIST_CURSOR DirtySharedCacheMapList; _SHARED_CACHE_MAP_LIST_CURSOR LazyWriteCursor; _LIST_ENTRY DirtySharedCacheMapWithLogHandleList; __declspec(align(32)) unsigned __int64 PrivateLock; unsigned int ConsecutiveWorklessLazyScanCount; unsigned __int8 ForcedDisableLazywriteScan; __declspec(align(64)) unsigned __int64 WorkQueueLock; unsigned int NumberWorkerThreads; unsigned int NumberActiveWorkerThreads; _LIST_ENTRY IdleWorkerThreadList; _LIST_ENTRY FastTeardownWorkQueue; _LIST_ENTRY ExpressWorkQueue; _LIST_ENTRY RegularWorkQueue; _LIST_ENTRY PostTickWorkQueue; _LIST_ENTRY IdleExtraWriteBehindThreadList; unsigned int ActiveExtraWriteBehindThreads; unsigned int MaxExtraWriteBehindThreads; unsigned __int8 QueueThrottle; unsigned int PostTickWorkItemCount; unsigned int ThreadsActiveBeforeThrottle; unsigned int ExtraWBThreadsActiveBeforeThrottle; unsigned int ExecutingWriteBehindWorkItems; unsigned int ExecutingHighPriorityWorkItem; _KEVENT LowMemoryEvent; _KEVENT PowerEvent; _KEVENT PeriodicEvent; _KEVENT WaitingForTeardownEvent; _KEVENT CoalescingFlushEvent; unsigned int PagesYetToWrite; __declspec(align(8)) _LAZY_WRITER LazyWriter; _DIRTY_PAGE_STATISTICS DirtyPageStatistics; _DIRTY_PAGE_THRESHOLDS DirtyPageThresholds; _WRITE_BEHIND_THROUGHPUT* ThroughputStats; int ThroughputTrend; unsigned __int64 AverageAvailablePages; unsigned __int64 AverageDirtyPages; unsigned __int64 PagesSkippedDueToHotSpot; _LARGE_INTEGER PrevRegularQueueItemRunTime; _LARGE_INTEGER PrevExtraWBThreadCheckTime; unsigned __int8 AddExtraWriteBehindThreads; unsigned __int8 RemoveExtraThreadPending; _LIST_ENTRY DeferredWrites; __declspec(align(16)) unsigned __int64 DeferredWriteSpinLock; _LIST_ENTRY* IdleAsyncReadWorkerThreadList; unsigned int* NumberActiveAsyncReadWorkerThreads; unsigned int* NumberActiveCompleteAsyncReadWorkItems; _LIST_ENTRY* AsyncReadWorkQueue; _LIST_ENTRY* AsyncReadCompletionWorkQueue; _KEVENT* NewAsyncReadRequestEvent; _ASYNC_READ_THREAD_STATS* ReaderThreadsStats; _EX_PUSH_LOCK AsyncReadWorkQueueLock; _LIST_ENTRY VacbFreeHighPriorityList; unsigned int NumberOfFreeHighPriorityVacbs; _ETHREAD* LowPriWorkerThread; _SHARED_CACHE_MAP* LowPriSharedCacheMap; int LowPriOldCpuPriority; _IO_PRIORITY_HINT LowPriOldIoPriority; _EX_PUSH_LOCK LowPriorityWorkerThreadLock; unsigned int MaxNumberOfWriteBehindThreads; unsigned __int8 CoalescingState; unsigned __int8 ActivePartition; unsigned __int8 RundownPhase; __int64 RefCount; _KEVENT ExitEvent; _KEVENT FinalDereferenceEvent; void* LazyWriteScanThreadHandle; }	400

	int hookShow(char* Arg) {

		HANDLE CsrssPID = 0;
		CsrssPID = getCrssPID();
		LOG_DEBUG("wKey :%I64X pAdr:%I64X  CrssPID:%d\n", wKey, CsrssPID, CsrssPID);
		PEPROCESS eprocess;
		NTSTATUS status = PsLookupProcessByProcessId(CsrssPID, &eprocess);
		//return;
		if (!NT_SUCCESS(status))
		{
			LOG_DEBUG(" cant PsLookupProcessByProcessId !\n");
			return FALSE;
		}
		__try
		{

			//DISPATCH_LEVEL

			SSDT_Initialization_HOOK(HOOK_SSDT);
			//return STATUS_SUCCESS;
			// 
			// 
			
			//KeGetPcr()->CurrentPrcb


			//ULONG64  DpcRequestSummary = __readgsqword(0x32A);

			//LOG_DEBUG("DpcRequestSummary  %I64X", DpcRequestSummary);

			 //0x32A

			//kEGETCURRENTPRCN


			//if (Arg != 0)
			//{
				KAPC_STATE stack = { 0 };
				KeStackAttachProcess(eprocess, &stack);

				if (SSDT_Initialization_HOOK(HOOK_SSDTSHOW))
                {
	                LOG_DEBUG("SSDT_Initialization_HOOK < sucess >");
					HOOK_BEGIN();
                }
				KeUnstackDetachProcess(&stack);
				

				//HideProcess(PsGetCurrentProcessId(), 0);

			//}

			//KAPC_STATE stack = { 0 };
			//KeStackAttachProcess(eprocess, &stack);
			////if (SSDT_Initialization_HOOK(HOOK_SSDTSHOW))
			////{
			////	//ULONGLONG pTableShow = getKeServiceDescriptorTableShow();
			////	HOOK_BEGIN();
			////	//LOG_DEBUG("HOOK SSDTSHOW  pTable < %p >", pTableShow);
			////}
			//KeUnstackDetachProcess(&stack);
		}
		__except (1) {
			LOG_DEBUG("hookShow  False\n");
		}
		ObDereferenceObject(eprocess);
		return STATUS_SUCCESS;
	}


	//NTSTATUS ZwQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);




	NTSTATUS Brother_getKey(LPIOINFO pValue) {

		LOG_DEBUG("get Key\n");
		if (wKey == 0)
		{
			LARGE_INTEGER tick_count;
			ULONG myinc = KeQueryTimeIncrement();
			KeQueryTickCount(&tick_count);
			tick_count.QuadPart *= myinc;
			tick_count.QuadPart /= 10000;
			wKey = (uint32_t)tick_count.QuadPart;
		}
		RtlCopyMemory(pValue->pAdr, &wKey, sizeof(wKey));
		LOG_DEBUG("get Key %08X\n", wKey);
		return STATUS_SUCCESS;
	}




	//PEPROCESS getPeprocess(UNICODE_STRING* name) {
	//
	//
	//
	//
	//
	//	return csrssH;
	//}


	//ULONGLONG GetModuleBaseWow64(_In_ PEPROCESS pEProcess, _In_ UNICODE_STRING usModuleName) {
	//
	//	ULONGLONG BaseAddr = 0; 
	//	KAPC_STATE KAPC = { 0 }; 
	//	KeStackAttachProcess(pEProcess, &KAPC);
	//	PPEB32 pPeb = (PPEB32)PsGetProcessWow64Process(pEProcess);
	//	
	//	if (pPeb == NULL || pPeb->Ldr == 0) {
	//		KeUnstackDetachProcess(&KAPC); return 0;
	//	}
	//	for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList.Flink;
	//		pListEntry != &((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList;
	//		pListEntry = (PLIST_ENTRY32)pListEntry->Flink) {
	//		PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
	//		if (LdrEntry->BaseDllName.Buffer == NULL)
	//		{
	//			continue;
	//		} // 当前模块名链表 
	//		UNICODE_STRING usCurrentName = { 0 };
	//		RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer); // 比较模块名是否一致 
	//		if (RtlEqualUnicodeString(&usModuleName, &usCurrentName, TRUE)) {
	//			BaseAddr = (ULONGLONG)LdrEntry->DllBase;
	//			KeUnstackDetachProcess(&KAPC);
	//			return BaseAddr;
	//		}
	//	}
	//	KeUnstackDetachProcess(&KAPC); return 0;
	//}



	KSPIN_LOCK MoudleLock;
	BOOLEAN iniMoudle = FALSE;

	//DECLARE_HANDLE(HRAWINPUT);



	// By: LyShark
	//ULONGLONG GetModuleBaseWow64(_In_ PEPROCESS pEProcess, _In_ UNICODE_STRING usModuleName)
	//{
	//	ULONGLONG BaseAddr = 0;
	//	KAPC_STATE KAPC = { 0 };
	//	KeStackAttachProcess(pEProcess, &KAPC);
	//	PEB_LDR_DATA pPeb = getPeb(pEProcess);//(PPEB32)PsGetProcessWow64Process(pEProcess);
	//	if (pPeb == NULL || pPeb->Ldr == 0)
	//	{
	//		KeUnstackDetachProcess(&KAPC);
	//		return 0;
	//	}
	//	for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList.Flink;
	//		pListEntry != &((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList; pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
	//	{
	//		PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

	//		if (LdrEntry->BaseDllName.Buffer == NULL)
	//		{
	//			continue;
	//		}

	//		// 当前模块名链表
	//		UNICODE_STRING usCurrentName = { 0 };
	//		RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);

	//		// 比较模块名是否一致
	//		if (RtlEqualUnicodeString(&usModuleName, &usCurrentName, TRUE))
	//		{
	//			BaseAddr = (ULONGLONG)LdrEntry->DllBase;
	//			KeUnstackDetachProcess(&KAPC);
	//			return BaseAddr;
	//		}
	//	}
	//	KeUnstackDetachProcess(&KAPC);
	//	return 0;
	//}



	NTKERNELAPI PVOID NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);
	// By: LyShark
	ULONGLONG GetModuleBaseWow64(_In_ PEPROCESS pEProcess, _In_ UNICODE_STRING usModuleName, DWORD * nSize)
	{

	//	PsGetProcessWow64Process

		ULONGLONG BaseAddr = 0;
		KAPC_STATE KAPC = { 0 };
		KeStackAttachProcess(pEProcess, &KAPC);
		PVOID pPeb = PsGetProcessPeb(pEProcess);// getPeb(pEProcess); //
		if (pPeb == NULL)
		{
			KeUnstackDetachProcess(&KAPC);
			return 0;
		}


		ULONG64 ldr = *(PULONG64)((ULONG64)pPeb + 0x18);
		PLIST_ENTRY pListHead = (PLIST_ENTRY)(ldr + 0x10);


		for (PLIST_ENTRY pListEntry = (PLIST_ENTRY)(pListHead->Flink);
			 pListEntry != pListHead; 
		     pListEntry = (PLIST_ENTRY)pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (LdrEntry->BaseDllName.Buffer == NULL)
			{
				continue;
			}

			LOG_DEBUG("%wZ  %I64X \n", &LdrEntry->BaseDllName, LdrEntry->DllBase);
			// 当前模块名链表
			UNICODE_STRING usCurrentName = { 0 };
			RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);

			// 比较模块名是否一致
			if (RtlEqualUnicodeString(&usModuleName, &usCurrentName, TRUE))
			{
				BaseAddr = (ULONGLONG)LdrEntry->DllBase;
				*nSize = LdrEntry->SizeOfImage;
				LOG_DEBUG("sucess %wZ  %I64X \n", &LdrEntry->BaseDllName, LdrEntry->DllBase);
				KeUnstackDetachProcess(&KAPC);
				return BaseAddr;
			}
		}
		KeUnstackDetachProcess(&KAPC);
		return 0;
	}


	ULONGLONG GetModuleBaseWow64_Self(UNICODE_STRING usModuleName)
	{

		//	PsGetProcessWow64Process
		ULONGLONG BaseAddr = 0;
		PEPROCESS eprocess = PsGetCurrentProcess();
		PVOID pPeb = PsGetProcessPeb(eprocess);// getPeb(pEProcess); //
		if (pPeb == NULL)
		{
			return 0;
		}

		ULONG64 ldr = *(PULONG64)((ULONG64)pPeb + 0x18);
		PLIST_ENTRY pListHead = (PLIST_ENTRY)(ldr + 0x10);

		for (PLIST_ENTRY pListEntry = (PLIST_ENTRY)(pListHead->Flink);
			pListEntry != pListHead;
			pListEntry = (PLIST_ENTRY)pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (LdrEntry->BaseDllName.Buffer == NULL)
			{
				continue;
			}

			//LOG_DEBUG("%wZ  %I64X \n", &LdrEntry->BaseDllName, LdrEntry->DllBase);
			// 当前模块名链表
			UNICODE_STRING usCurrentName = { 0 };
			RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);

			// 比较模块名是否一致
			if (RtlEqualUnicodeString(&usModuleName, &usCurrentName, TRUE)){
				BaseAddr = (ULONGLONG)LdrEntry->DllBase;
				//LOG_DEBUG("sucess %wZ  %I64X \n", &LdrEntry->BaseDllName, LdrEntry->DllBase);
				return BaseAddr;
			}
		}
		return 0;
	}



#define NT_HEADER(Base) (PIMAGE_NT_HEADERS)((ULONG64)(Base) + ((PIMAGE_DOS_HEADER)(Base))->e_lfanew)

	PVOID GetProcAddress_Kernel(PVOID ModBase, const char* Name)
	{
		__try
		{
			PIMAGE_NT_HEADERS64 NT_Head = NT_HEADER(ModBase);
			PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);
			
			ULONG* AddressFun = (ULONG*) ( (ULONG64)ModBase + ExportDir->AddressOfFunctions);
			USHORT* AddressOfNameOrdinals = (USHORT*)( (ULONG64)ModBase + ExportDir->AddressOfNameOrdinals);
			ULONG* AddressOfNames = (ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames);
			for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
			{
				USHORT Ordinal = AddressOfNameOrdinals[i];
				const char* ExpName = (const char*)ModBase + AddressOfNames[i];
				if (_stricmp(Name, ExpName) == 0) {

					//LOG_DEBUG("%s %s  %08X \n", Name, ExpName, AddressFun[Ordinal]);
					return (PVOID)((ULONG64)ModBase + AddressFun[Ordinal]);
				}
					
			}
			return 0;
		}
		__except (1) {
			return 0;
		}
		return 0;

	}




	NTSTATUS Brother_Moudle(LPIOINFO pValue) {

		//LOG_DEBUG("Brother_Moudle PID:%d Type :%d\n", pValue->pID, pValue->Type);
		if (!iniMoudle)
		{
			iniMoudle = TRUE;
			KeInitializeSpinLock(&MoudleLock);
		}

		//return STATUS_SUCCESS;
		//GetModuleBaseWow64(,)
		if (pValue->Type == 0)
		{
			if (pValue->pAdrSize > MAX_PATH * 2)
			{
				pValue->Error = 3;
				return STATUS_SUCCESS;
			}






			//return STATUS_SUCCESS;
			//KeAcquireSpinLockAtDpcLevel(&MoudleLock);

			wchar_t wchar[MAX_PATH + 1] = { 0 };
			UNICODE_STRING s2String;
			RtlCopyMemory(wchar, pValue->pAdr, pValue->pAdrSize);
			RtlInitUnicodeString(&s2String, wchar);

			PEPROCESS pEprocess = NULL;
			KIRQL oldIrql;
			KeRaiseIrql(APC_LEVEL, &oldIrql);
			if (PsLookupProcessByProcessId((HANDLE)pValue->pID, &pEprocess) != STATUS_SUCCESS)
			{
				LOG_DEBUG("PsLookupProcessByProcessId Error  Brother_Moudle PID:%d Type :%d\n", pValue->pID, pValue->Type);
				pValue->Error = 1;
				KeLowerIrql(oldIrql);
				//KeReleaseSpinLockFromDpcLevel(&MoudleLock);
				return STATUS_SUCCESS;
			}
			KeLowerIrql(oldIrql);



			LOG_DEBUG("find %wZ \n", &s2String);

			DWORD nSzie = 0;
			pValue->pVal = (void *)GetModuleBaseWow64(pEprocess, s2String, &nSzie);
			pValue->pValSize = nSzie;


			//PPEB pEb = 0;
			//KAPC_STATE ApcState;
			//BOOLEAN uOK = FALSE;

			//__try {

			//	KeStackAttachProcess(pEprocess, &ApcState);
			//	uOK = TRUE;
			//	pEb = getPeb(pEprocess);
			//	if (pEb == NULL)
			//	{
			//		LOG_DEBUG("can't find peb\n");
			//		KeUnstackDetachProcess(&ApcState);
			//		ObDereferenceObject(pEprocess);
			//		KeReleaseSpinLockFromDpcLevel(&MoudleLock);
			//		return STATUS_SUCCESS;
			//	}
			//}
			//__except (1) {

			//	if (uOK)
			//	{
			//		KeUnstackDetachProcess(&ApcState);
			//	}
			//	ObDereferenceObject(pEprocess);
			//	KeReleaseSpinLockFromDpcLevel(&MoudleLock);
			//	return STATUS_SUCCESS;
			//}

			//PVOID BaseAddress = NULL;
			//ULONG nSzie = NULL;
			//__try {

			//	ULONG64 ldr = *(PULONG64)((ULONG64)pEb + 0x18);
			//	PLIST_ENTRY pListHead = (PLIST_ENTRY)(ldr + 0x10);
			//	PLIST_ENTRY pMod = pListHead->Flink;

			//	while (pMod != pListHead)
			//	{
			//		PLDR_DATA_TABLE_ENTRY pTable = (PLDR_DATA_TABLE_ENTRY)pMod;
			//		//	LOG_DEBUG("Brother_Moudle_Name %ws  BaseAddress：<%p> nSzie:%08X\n", pTable->BaseDllName.Buffer, pTable->DllBase, pTable->SizeOfImage);
			//		if (pTable->BaseDllName.Buffer == 0)
			//		{
			//			pMod = pMod->Flink;
			//			continue;
			//		}
			//		
			//		KIRQL irql = 0;
			//		KeRaiseIrql(PASSIVE_LEVEL, &irql);
			//		if (RtlCompareUnicodeString(&pTable->BaseDllName, &s2String, TRUE) == 0)
			//		{
			//			BaseAddress = pTable->DllBase;
			//			nSzie = pTable->SizeOfImage;

			//			//RtlCopyMemory(pValue->pVal,pLdrModule,0);
			//		//	LOG_DEBUG("Brother_Moudle_Name %ws  BaseAddress：<%p> nSzie:%08X\n", pTable->BaseDllName.Buffer, BaseAddress, nSzie);
			//			KeLowerIrql(irql);
			//			break;
			//		}
			//		KeLowerIrql(irql);

			//		pMod = pMod->Flink;
			//	}
			//}
			//__except (1) {

			//	LOG_DEBUG("Brother_Moudle_Name Faild!\n");

			//}
			//KeUnstackDetachProcess(&ApcState);
			////LOG_DEBUG("Brother_Moudle_Name %ws  BaseAddress：<%p> nSzie:%08X\n", s2String.Buffer, BaseAddress, nSzie);
			//__try {
			//	//LPIOINFO tInfo = (LPIOINFO)pValue->pVal;
			//	pValue->pVal = BaseAddress;
			//	pValue->pValSize = nSzie;
			//}
			//__except (1) {
			//	LOG_DEBUG("Brother_Moudle_Name No!\n");
			//}
			ObDereferenceObject(pEprocess);
			//KeReleaseSpinLockFromDpcLevel(&MoudleLock);
			return STATUS_SUCCESS;

		}
		else if (pValue->Type == 1)
		{
			if (pValue->pAdrSize > MAX_PATH * 2)
			{
				pValue->Error = 3;
				return STATUS_SUCCESS;
			}
			PEPROCESS pEprocess = NULL;
			PsLookupProcessByProcessId((HANDLE)pValue->pID, &pEprocess);
			if (pEprocess == NULL)
			{
				LOG_DEBUG("PsLookupProcessByProcessId Error  Brother_Moudle PID:%d Type :%d\n", pValue->pID, pValue->Type);
				pValue->Error = 1;
				return STATUS_SUCCESS;
			}
			KAPC_STATE ApcState;
			PPEB pEb = getPeb(pEprocess);
			KeStackAttachProcess(pEprocess, &ApcState);
			ULONG64 ldr = *(PULONG64)((ULONG64)pEb + 0x18);
			PLIST_ENTRY pListHead = (PLIST_ENTRY)(ldr + 0x10);
			pValue->pAdr = pListHead;
			KeUnstackDetachProcess(&ApcState);
			ObDereferenceObject(pEprocess);
			return STATUS_SUCCESS;
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS Brother_KeyBoard(LPIOINFO pValue) {

		LOG_DEBUG("Brother_KeyBoard PID:%d Type :%d\n", pValue->pID, pValue->Type);
		if (pValue->Type == 0 || pValue->Type == 1)
		{
			AddKeyBoard((HANDLE)pValue->pID, pValue->pAdrSize, pValue->Type);
		}
		else if (pValue->Type == 2)
		{
			StopKeyBoard((HANDLE)pValue->pID, pValue->Type);
		}
		else if (pValue->Type == 3)
		{
			AddInputData((HANDLE)pValue->pID, (RAWINPUT*)pValue->pAdr);
		}
		else if (pValue->Type == 4)
		{
			SetRawInput((HRAWINPUT)pValue->pAdr);
		}
		else if (pValue->Type == 5)
		{
			MOUSE_EVENT* pMouse = (MOUSE_EVENT*)pValue->pAdr;


			LOG_DEBUG("pMouse->dwFlags:%08X pMouse->dx:%08X pMouse->dy:%08X pMouse->dwData:%08X pMouse->dwExtraInfo:%08X\n",
				pMouse->dwFlags, pMouse->dx, pMouse->dy, pMouse->dwData, pMouse->dwExtraInfo);

			mouse_event(pMouse->dwFlags, pMouse->dx, pMouse->dy, pMouse->dwData, pMouse->dwExtraInfo);
		}
		else if (pValue->Type == 6)
		{
			KETBD_EVENT* pKeybd = (KETBD_EVENT*)pValue->pAdr;
			keybd_event(pKeybd->bVk, pKeybd->bScan, pKeybd->dwFlags, pKeybd->dwExtraInfo);
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS Brother_File(LPIOINFO pValue) {

		//ExFreePoolWithTag()
		LOG_DEBUG("Brother_File PID:%d Type :%d\n", pValue->pID, pValue->Type);


		//PVOID addr = 0;

		//size_t size = 0x700;

		//NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//if (NT_SUCCESS(status))
		//{
		//	RtlZeroMemory(addr, size);
		//	LOG_DEBUG("ZwAllocateVirtualMemory sucess\n");
		//	//size = 0;
		//	//status = ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		//	//LOG_DEBUG("ZwAllocateVirtualMemory %08X\n", status);
		//	//size = 0;
		//	//status = ZwFreeVirtualMemory(ZwCurrentProcess(), &addr, &size, MEM_RELEASE);
		//	//LOG_DEBUG("ZwAllocateVirtualMemory %08X\n", status);
		////	STATUS_ABANDONED
		//}






		if (pValue->Type == 0)
		{
			UNICODE_STRING str;
			size_t gLen = wcslen((wchar_t*)pValue->pAdr);
			wchar_t* r = (wchar_t*)ExAllocatePoolWithTag(PagedPool, (gLen + 1) * 2, 'tag');
			RtlZeroMemory(r, (gLen + 1) * 2);
			RtlCopyMemory(r, pValue->pAdr, gLen * 2);
			RtlInitUnicodeString(&str, r);
			//AddFileName(pValue->pID, &str);
		}
		else if (pValue->Type == 1)
		{
			UNICODE_STRING str;
			size_t gLen = wcslen((wchar_t*)pValue->pAdr);
			wchar_t* r = (wchar_t*)ExAllocatePoolWithTag(PagedPool, (gLen + 1) * 2, 'tag');
			RtlZeroMemory(r, (gLen + 1) * 2);
			RtlCopyMemory(r, pValue->pAdr, gLen * 2);
			RtlInitUnicodeString(&str, r);
			//DelFileName(pValue->pID, &str);
			ExFreePoolWithTag(r, 'tag');
		}
		else if (pValue->Type == 2)
		{
			//UNICODE_STRING str;
			size_t gLen = wcslen((wchar_t*)pValue->pAdr);

			wchar_t* r = (wchar_t*)ExAllocatePoolWithTag(PagedPool, (gLen + 1) * 2, 'tag');

			if (r == NULL)
			{
				return STATUS_SUCCESS;
			}

			RtlZeroMemory(r, (gLen + 1) * 2);

			RtlCopyMemory(r, pValue->pAdr, gLen * 2);
			//	DeviceDosPathToNtPath(pValue->pAdr, r);
			ForceDeleteFile(r);
			//DelFileName(pValue->pID, &str);
			ExFreePoolWithTag(r, 'tag');
		}
		//
		return STATUS_SUCCESS;
	}

	NTSTATUS Brother_Mutex(LPIOINFO pValue) {
		LOG_DEBUG("Brother_Mutex PID:%d Type :%d\n", pValue->pID, pValue->Type);
		if (pValue->Type == 0)
		{
			//Add_MUTEX(pValue->pID);
		}
		else if (pValue->Type == 1)
		{
			//	DEL_MUTEX(pValue->pID);
		}
		else if (pValue->Type >= 2 && pValue->Type < 16) {

			UNICODE_STRING name;
			UNICODE_STRING nameUPCASE;
			UNICODE_STRING cutName;
			UNICODE_STRING cutNameUPCASE;
			RtlInitUnicodeString(&name, (PCWSTR)pValue->pAdr);
			RtlInitUnicodeString(&cutName, (PCWSTR)pValue->pVal);
			RtlUpcaseUnicodeString(&nameUPCASE, &name, TRUE);
			RtlUpcaseUnicodeString(&cutNameUPCASE, &cutName, TRUE);

			if (pValue->Type == 2)
			{
				LOG_DEBUG("Brother_Mutex %ws %ws\n", pValue->pAdr, pValue->pVal);
				LOG_DEBUG("Brother_Mutex %wZ %wZ\n", &nameUPCASE, &cutNameUPCASE);
				//Add_MUTEX_TEXT(&nameUPCASE, &cutNameUPCASE, pValue->pAdrSize);
			}
			else if (pValue->Type == 8) {

				char* BufferFilter = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize + 2, 'tag');
				char* BufferPath = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pValSize + 2, 'tag');
				if (BufferFilter && BufferPath)
				{
					RtlZeroMemory(BufferFilter + pValue->pAdrSize, 2);
					RtlZeroMemory(BufferPath + pValue->pValSize, 2);

					RtlCopyMemory(BufferFilter, pValue->pAdr, pValue->pAdrSize);
					RtlCopyMemory(BufferPath, pValue->pVal, pValue->pValSize);

					UNICODE_STRING uFilter;
					UNICODE_STRING uPath;
					RtlInitUnicodeString(&uFilter, (PCWSTR)BufferFilter);
					RtlInitUnicodeString(&uPath, (PCWSTR)BufferPath);
					FilterFileName(&uFilter, &uPath);
				}
			}
			else if (pValue->Type == 9) {

				char* BufferFilter = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize + 2, 'tag');
				char* BufferPath = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pValSize + 2, 'tag');
				if (BufferFilter && BufferPath)
				{
					RtlZeroMemory(BufferFilter + pValue->pAdrSize, 2);
					RtlZeroMemory(BufferPath + pValue->pValSize, 2);

					RtlCopyMemory(BufferFilter, pValue->pAdr, pValue->pAdrSize);
					RtlCopyMemory(BufferPath, pValue->pVal, pValue->pValSize);

					UNICODE_STRING uFilter;
					UNICODE_STRING uPath;
					RtlInitUnicodeString(&uFilter, (PCWSTR)BufferFilter);
					RtlInitUnicodeString(&uPath, (PCWSTR)BufferPath);
					FilterProcessName(&uFilter, &uPath);
				}
			}
			else if (pValue->Type == 10) {

				char* BufferFilter = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize + 2, 'tag');
				char* BufferPath = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pValSize + 2, 'tag');
				if (BufferFilter && BufferPath)
				{
					RtlZeroMemory(BufferFilter + pValue->pAdrSize, 2);
					RtlZeroMemory(BufferPath + pValue->pValSize, 2);

					RtlCopyMemory(BufferFilter, pValue->pAdr, pValue->pAdrSize);
					RtlCopyMemory(BufferPath, pValue->pVal, pValue->pValSize);

					UNICODE_STRING uFilter;
					UNICODE_STRING uPath;
					RtlInitUnicodeString(&uFilter, (PCWSTR)BufferFilter);
					RtlInitUnicodeString(&uPath, (PCWSTR)BufferPath);
					FilterMutexName(&uFilter, &uPath);
				}
			}
			else if (pValue->Type == 11) {
				FilterAnsiString(0, 0);
			}
			else if (pValue->Type == 12) {

				char* BufferFilter = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize + 2, 'tag');
				char* BufferPath = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pValSize + 2, 'tag');
				if (BufferFilter && BufferPath)
				{
					RtlZeroMemory(BufferFilter + pValue->pAdrSize, 2);
					RtlZeroMemory(BufferPath + pValue->pValSize, 2);

					RtlCopyMemory(BufferFilter, pValue->pAdr, pValue->pAdrSize);
					RtlCopyMemory(BufferPath, pValue->pVal, pValue->pValSize);

					UNICODE_STRING uFilter;
					UNICODE_STRING uPath;
					RtlInitUnicodeString(&uFilter, (PCWSTR)BufferFilter);
					RtlInitUnicodeString(&uPath, (PCWSTR)BufferPath);
					FilterEventName(&uFilter, &uPath);
				}
			}
			else if (pValue->Type == 13)
			{

				char* BufferFilter = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize + 2, 'tag');
				char* BufferPath = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pValSize + 2, 'tag');
				if (BufferFilter && BufferPath)
				{
					RtlZeroMemory(BufferFilter + pValue->pAdrSize, 2);
					RtlZeroMemory(BufferPath + pValue->pValSize, 2);

					RtlCopyMemory(BufferFilter, pValue->pAdr, pValue->pAdrSize);
					RtlCopyMemory(BufferPath, pValue->pVal, pValue->pValSize);

					UNICODE_STRING uFilter;
					UNICODE_STRING uPath;
					RtlInitUnicodeString(&uFilter, (PCWSTR)BufferFilter);
					RtlInitUnicodeString(&uPath, (PCWSTR)BufferPath);
					FilterSectionName(&uFilter, &uPath);
				}
			}
			else if (pValue->Type == 14)
			{

			char* BufferFilter = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pAdrSize + 2, 'tag');
			char* BufferPath = (char*)ExAllocatePoolWithTag(PagedPool, pValue->pValSize + 2, 'tag');
			if (BufferFilter && BufferPath)
			{
				RtlZeroMemory(BufferFilter + pValue->pAdrSize, 2);
				RtlZeroMemory(BufferPath + pValue->pValSize, 2);

				RtlCopyMemory(BufferFilter, pValue->pAdr, pValue->pAdrSize);
				RtlCopyMemory(BufferPath, pValue->pVal, pValue->pValSize);

				UNICODE_STRING uFilter;
				UNICODE_STRING uPath;
				RtlInitUnicodeString(&uFilter, (PCWSTR)BufferFilter);
				RtlInitUnicodeString(&uPath, (PCWSTR)BufferPath);
				
				SandBoxFilter(&uFilter, &uPath);

				//FilterSectionName(&uFilter, &uPath);
			}
			}
		}

		return STATUS_SUCCESS;
	}


	PVOID kBuffer = 0;

	BOOLEAN  IOSysBuffer(DWORD IOMajor, PVOID64 gBuffer) {


		LPMSGCOMMON tInfo = (LPMSGCOMMON)gBuffer;
		LPIOINFO pInfo = (LPIOINFO)&tInfo->common;
		KIRQL irql = KeGetCurrentIrql();
		__try {

			if (IOMajor == BROTHER_DRIVERCODE_KEY)
			{
				Brother_getKey(pInfo);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MEMORY) {
				if (!Brother_Verification((LPIOINFO)tInfo)) {
					goto TOEND;
				}
				pInfo->Error = Brother_Memory(pInfo);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_PROCESS) {
				if (!Brother_Verification((LPIOINFO)tInfo)) {
					goto TOEND;
				}
				pInfo->Error = Brother_Process(pInfo);
				goto TOEND;
			}

			else if (IOMajor == BROTHER_DRIVERCODE_WINDOWS) {
				if (!Brother_Verification((LPIOINFO)tInfo)) {
					goto TOEND;
				}
				pInfo->Error = Brother_Window(pInfo);
				goto TOEND;
			}

			else if (IOMajor == BROTHER_DRIVERCODE_MOUDLE) {
				if (!Brother_Verification((LPIOINFO)tInfo)) {
					goto TOEND;
				}
				pInfo->Error = Brother_Moudle(pInfo);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_KEYBORAD) {
				if (!Brother_Verification((LPIOINFO)tInfo)) {
					goto TOEND;
				}
				pInfo->Error = Brother_KeyBoard(pInfo);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_FILE) {
				if (!Brother_Verification((LPIOINFO)tInfo)) {
					goto TOEND;
				}
				pInfo->Error = Brother_File(pInfo);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MUTEX) {
				if (!Brother_Verification((LPIOINFO)tInfo)) {
					goto TOEND;
				}
				pInfo->Error = Brother_Mutex(pInfo);
				goto TOEND;
			}

		}
		__except (1) {
			KeLowerIrql(irql);
			return FALSE;
		}

	TOEND:
		KeLowerIrql(irql);
		return FALSE;
	}

	NTSTATUS DriverIrpCtl(PDEVICE_OBJECT device, PIRP pirp)
	{
		UNREFERENCED_PARAMETER(device);
		PIO_STACK_LOCATION stack;
		//stack = IoGetCurrentIrpStackLocation(pirp);

		//LOG_DEBUG("DriverIrpCtl");
		LPIOINFO pInfo = 0;
		pirp->IoStatus.Status = STATUS_SUCCESS;
		DWORD nError = 0;
		PIO_STACK_LOCATION IrpSp = NULL;
		IrpSp = IoGetCurrentIrpStackLocation(pirp);
		DWORD uReadLength = IrpSp->Parameters.Read.Length;

		if (uReadLength != sizeof(IOINFO) + 12)
		{
			pirp->IoStatus.Information = 0;
			IoCompleteRequest(pirp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}

		LPMSGCOMMON tInfo = (LPMSGCOMMON)pirp->AssociatedIrp.SystemBuffer;

		if (tInfo == 0){
			pirp->IoStatus.Information = 0;
			IoCompleteRequest(pirp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;

		}
		pInfo = (LPIOINFO)&tInfo->common;
		if (IrpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
		{

			if (IrpSp->Parameters.DeviceIoControl.IoControlCode == BROTHER_DRIVERCODE_KEY)
			{
				Brother_getKey(pInfo);
				//pirp->IoStatus.Information = sizeof(pInfo);
				pirp->IoStatus.Information = sizeof(IOINFO) + 12;
				IoCompleteRequest(pirp, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}
			if (!Brother_Verification((LPIOINFO)tInfo)) {
				pirp->IoStatus.Information = sizeof(IOINFO) + 12;
				IoCompleteRequest(pirp, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}

			switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
			{

			case BROTHER_DRIVERCODE_MEMORY:
				pInfo->Error = Brother_Memory(pInfo);
				break;
			case BROTHER_DRIVERCODE_PROCESS:
				pInfo->Error = Brother_Process(pInfo);
				break;
			case BROTHER_DRIVERCODE_WINDOWS:
				pInfo->Error = Brother_Window(pInfo);
				break;
			case BROTHER_DRIVERCODE_MOUDLE:
				pInfo->Error = Brother_Moudle(pInfo);
				break;
			case BROTHER_DRIVERCODE_KEYBORAD:
				pInfo->Error = Brother_KeyBoard(pInfo);
				break;
			case BROTHER_DRIVERCODE_FILE:
				pInfo->Error = Brother_File(pInfo);
				break;
			case BROTHER_DRIVERCODE_MUTEX:
				pInfo->Error = Brother_Mutex(pInfo);
				break;

			case BROTHER_DRIVERCODE_MSG:
				pInfo->Error = Brother_Msg(pInfo);
				break;
			default:

				break;
			}

		}
		//IO_REPARSE_TAG_MOUNT_POINT
		pirp->IoStatus.Information = sizeof(IOINFO) + 12;
		IoCompleteRequest(pirp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}




	BOOLEAN SandBoxFilter(PUNICODE_STRING FilterName, PUNICODE_STRING PathName)
	{
		ImageForSandBox = *FilterName;
		SandBoxDirectory = *PathName;

		LOG_DEBUG("%wZ %wZ\n", FilterName, PathName);
		return TRUE;
	}




	NTSTATUS CreateDriverObject(PDRIVER_OBJECT pDriver) {

		NTSTATUS Status;               // 接收驱动程序的返回状态
		PDEVICE_OBJECT pDevObj;        // 用于返回创建设备
		//UNICODE_STRING DriverName;     // 用于存放设备的名称
		//UNICODE_STRING SymLinkName;    // 用于存放符号链接名称

		//RtlInitUnicodeString(&DriverName, LINK_DRIVERNAME);  // 将DrvierName填充为\\Device\\My_Device

		// 使用命令IoCreateDevice用来创建设备，并将创建后的状态保存在status
		Status = IoCreateDevice(pDriver, 0, &uszDeviceString, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
		LOG_DEBUG("当前命令IoCreateDevice状态: %d\n", Status);
		if (!NT_SUCCESS(Status))
		{
			// 调用IoCreateDevice成功与失败都会返回参数,将返回参数给Status用于判断
			// STATUS_INSUFFICIENT_RESOURCES   资源不足
			// STATUS_OBJECT_NAME_EXISTS       指定对象名存在
			// STATUS_OBJECT_NAME_COLLISION    对象名有冲突
			if (Status == STATUS_OBJECT_NAME_COLLISION)
			{
				LOG_DEBUG("对象名冲突..\n");
			}
			LOG_DEBUG("创建失败.\n");
		}
		if (NT_SUCCESS(Status))
		{
			pDevObj->Flags |= DO_BUFFERED_IO;
		}
                       // flags 标识有没有do_buffered_io位标识
		//RtlInitUnicodeString(&SymLinkName, LINK_SYMLINKNAME);      // 对symLinkName初始化字串为 "\\??\\My_Device"
		// 创建设备链接,驱动程序虽然有设备名称,但是这种设备名只能在内核态可见
		// 而对于应用程序是不可见的,因此驱动需要要暴露一个符号链接,该链接指向真正的设备名称
		Status = IoCreateSymbolicLink(&uszSymLinkString, &uszDeviceString);    // 调用命令IoCreateSymbolicLink用于创建符号链接
		LOG_DEBUG("当前命令IoCreateSymbolicLink状态: %d  %wZ  %wZ\n", Status, &uszSymLinkString, &uszDeviceString);
		if (!NT_SUCCESS(Status)) // 如果status不等于0 就执行
		{
			IoDeleteDevice(pDevObj);  // 调用命令IoDeleteDevice删除当前pDevObj设备
			LOG_DEBUG("删除设备成功...\n");
			return Status;
		}
		else
		{
			LOG_DEBUG("创建符号链接成功...\n");
		}
		return STATUS_SUCCESS;

	}




	
	typedef UINT (*F_NtUserSendInput)(
			UINT nInputs,
			void* pInput,
			INT cbSize);

	F_NtUserSendInput wNtUserSendInput = 0;















	VOID IniWin32K_f() {

		//GetSSDTSHOWFuncAddr()



	}



typedef	struct _SOCKET_UNICODESTRING_INFO{
		int offset[2];
		int Size[2];
	}SOCKET_UNICODESTRING_INFO;

	int  IOSocketBuffer(SOCKET s , DWORD IOMajor, LPIOINFO pInfo, char* rBuffer) {


		KIRQL irql = KeGetCurrentIrql();


		__try {

			if (IOMajor == BROTHER_DRIVERCODE_KEY)
			{
				Brother_getKey(pInfo);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MEMORY) {
				//LOG_DEBUG("BROTHER_DRIVERCODE_MEMORY \n");
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				if (gIoBuffer->Type == KERNEL_WRITE) {
					gIoBuffer->pVal = (void*)((DWORD64)pInfo + sizeof(IOINFO)); // 数据
					//LOG_DEBUG("KERNEL_WRITE   %I64X   nSize %d\n", gIoBuffer->pAdr, gIoBuffer->pValSize);
				}
				else if (gIoBuffer->Type == KERNEL_READ) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pAdrSize);
					goto TOEND;
				}
				else if (gIoBuffer->Type == KERNEL_READ_LIST) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					int nSize = LOWORD(gIoBuffer->pValSize);
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					if (gIoBuffer->Error == 0)
					{
						sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + LOWORD(gIoBuffer->pValSize) * nSize);
						goto TOEND;
					}
					else
					{
						sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
						goto TOEND;
					}

				}
				else if (gIoBuffer->Type == KERNEL_READ_OFFSET) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pAdrSize);
					goto TOEND;
				}
				else if (gIoBuffer->Type == KERNEL_READ_NEWWORLD_1 || gIoBuffer->Type == KERNEL_READ_NEWWORLD_3) {

					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));  // 数据

					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 输出文本
					//LOG_DEBUG("KERNEL_READ_NEWWORLD_1 \n");
					gIoBuffer->Error = Brother_Memory(gIoBuffer);

					sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize);
					goto TOEND;
				}
				else if (gIoBuffer->Type == KERNEL_READ_NEWWORLD_2) {

					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));  // 数据

					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 输出文本
					//LOG_DEBUG("KERNEL_READ_NEWWORLD_1 \n");
					gIoBuffer->Error = Brother_Memory(gIoBuffer);

					sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize);
					goto TOEND;
				}
				else if (gIoBuffer->Type == KERNEL_READ_MEMORY_0 || gIoBuffer->Type == KERNEL_READ_MEMORY_1) {

					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));  // 数据
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 输出文本
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize);
					goto TOEND;
				}
				gIoBuffer->Error = Brother_Memory(gIoBuffer);
				sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_PROCESS) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));

				if (gIoBuffer->Type == 9) {

					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO));
					gIoBuffer->Error = Brother_Process(gIoBuffer);
					sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize);
					goto TOEND;
				}

				gIoBuffer->Error = Brother_Process(gIoBuffer);
				sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_WINDOWS) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));


				LOG_DEBUG("Windows Type  %d\n", gIoBuffer->Type);
				if (gIoBuffer->Type == 7) {
					LOG_DEBUG("Windows Type  %d\n", gIoBuffer->Type);
					char* Begin = (char*)((DWORD64)pInfo + sizeof(IOINFO));
					SOCKET_UNICODESTRING_INFO* pSizeInfo = (SOCKET_UNICODESTRING_INFO*)Begin;

					LOG_DEBUG(" %d  %d %d %d\n", pSizeInfo->Size[0], pSizeInfo->Size[1],
						pSizeInfo->offset[0], pSizeInfo->offset[1]);


					if (pSizeInfo->Size[0] < 0 || pSizeInfo->Size[0]>256) {
						gIoBuffer->pAdrSize = 0;
					}
					else {
						gIoBuffer->pAdr = Begin + pSizeInfo->offset[0];
						gIoBuffer->pAdrSize = pSizeInfo->Size[0];
					}

					if (pSizeInfo->Size[1] < 0 || pSizeInfo->Size[1]>256) {
						gIoBuffer->pValSize = 0;
					}
					else
					{
						gIoBuffer->pVal = Begin + pSizeInfo->offset[1];
						gIoBuffer->pValSize = pSizeInfo->Size[1];
					}

					LOG_DEBUG("%ws  %ws\n", gIoBuffer->pAdr, gIoBuffer->pVal);
				}
				if (gIoBuffer->Type == 8 || gIoBuffer->Type == 9 || gIoBuffer->Type == 15) {
					gIoBuffer->pVal = &gIoBuffer->pAdr;
				}
				if (gIoBuffer->Type == 10) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO));
					gIoBuffer->pValSize = 0;
					gIoBuffer->Error = Brother_Window(gIoBuffer);
					sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize);
					goto TOEND;

				}
				if (gIoBuffer->Type == 12) {
					gIoBuffer->pVal = (void*)((DWORD64)pInfo + sizeof(IOINFO));
					gIoBuffer->Error = Brother_Window(gIoBuffer);
				}
				if (gIoBuffer->Type == 16) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO));//(void*)((DWORD64)pInfo + sizeof(IOINFO));
					gIoBuffer->Error = Brother_Window(gIoBuffer);
					sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize);
					goto TOEND;
				}
				gIoBuffer->Error = Brother_Window(gIoBuffer);
				sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MOUDLE) {

				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				if (gIoBuffer->Type == 0) {
					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO));
				}
				gIoBuffer->Error = Brother_Moudle(gIoBuffer);
				sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_KEYBORAD) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));

				if (gIoBuffer->Type == 5 || gIoBuffer->Type == 6) {
					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
				}
				gIoBuffer->Error = Brother_KeyBoard(gIoBuffer);
				sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_FILE) {


				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));

				gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));

				gIoBuffer->Error = Brother_File(gIoBuffer);
				sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MUTEX) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				gIoBuffer->Error = Brother_Mutex(gIoBuffer);
				sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else
			{
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				sendEncrypt(s, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}

		}
		__except (1) {
			KeLowerIrql(irql);
			return 0;
		}

	TOEND:
		KeLowerIrql(irql);
		return 0;
	}


	int IOSocketBufferUdp(SOCKET s, DWORD IOMajor, LPIOINFO pInfo, char* rBuffer, struct sockaddr* Addr, int SockLen) {

		KIRQL irql = KeGetCurrentIrql();
		__try {

/*			if (IOMajor == BROTHER_DRIVERCODE_KEY)
			{
				Brother_getKey(pInfo);
				goto TOEND;
			}
			else*/ 
			if (IOMajor == BROTHER_DRIVERCODE_MEMORY) {
				//LOG_DEBUG("BROTHER_DRIVERCODE_MEMORY \n");
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				if (gIoBuffer->Type == KERNEL_WRITE) {
					gIoBuffer->pVal = (void*)((DWORD64)pInfo + sizeof(IOINFO)); // 数据
					//LOG_DEBUG("KERNEL_WRITE   %I64X   nSize %d\n", gIoBuffer->pAdr, gIoBuffer->pValSize);
				}
				else if (gIoBuffer->Type == KERNEL_READ) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pAdrSize, Addr, SockLen);
					goto TOEND;
				}
				else if (gIoBuffer->Type == KERNEL_READ_LIST) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					int nSize = LOWORD(gIoBuffer->pValSize);
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize * nSize, Addr, SockLen);
					goto TOEND;
				}
				else if (gIoBuffer->Type == KERNEL_READ_OFFSET) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pAdrSize, Addr, SockLen);
					goto TOEND;
				}
				gIoBuffer->Error = Brother_Memory(gIoBuffer);
				sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO), Addr, SockLen);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_PROCESS) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));

				if (gIoBuffer->Type == 9) {

					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO));
					gIoBuffer->Error = Brother_Process(gIoBuffer);
					sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize, Addr, SockLen);
					goto TOEND;
				}

				gIoBuffer->Error = Brother_Process(gIoBuffer);
				sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO), Addr, SockLen);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_WINDOWS) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));


				LOG_DEBUG("Windows Type  %d\n", gIoBuffer->Type);
				if (gIoBuffer->Type == 7) {
					LOG_DEBUG("Windows Type  %d\n", gIoBuffer->Type);
					char* Begin = (char*)((DWORD64)pInfo + sizeof(IOINFO));
					SOCKET_UNICODESTRING_INFO* pSizeInfo = (SOCKET_UNICODESTRING_INFO*)Begin;

					LOG_DEBUG(" %d  %d %d %d\n", pSizeInfo->Size[0], pSizeInfo->Size[1],
						pSizeInfo->offset[0], pSizeInfo->offset[1]);


					if (pSizeInfo->Size[0] < 0 || pSizeInfo->Size[0]>256) {
						gIoBuffer->pAdrSize = 0;
					}
					else {
						gIoBuffer->pAdr = Begin + pSizeInfo->offset[0];
						gIoBuffer->pAdrSize = pSizeInfo->Size[0];
					}

					if (pSizeInfo->Size[1] < 0 || pSizeInfo->Size[1]>256) {
						gIoBuffer->pValSize = 0;
					}
					else
					{
						gIoBuffer->pVal = Begin + pSizeInfo->offset[1];
						gIoBuffer->pValSize = pSizeInfo->Size[1];
					}

					LOG_DEBUG("%ws  %ws\n", gIoBuffer->pAdr, gIoBuffer->pVal);
				}
				if (gIoBuffer->Type == 8 || gIoBuffer->Type == 9) {
					gIoBuffer->pVal = &gIoBuffer->pAdr;
				}
				gIoBuffer->Error = Brother_Window(gIoBuffer);
				sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO), Addr, SockLen);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MOUDLE) {

				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				if (gIoBuffer->Type == 0) {
					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO));
				}
				gIoBuffer->Error = Brother_Moudle(gIoBuffer);
				sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO), Addr, SockLen);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_KEYBORAD) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));

				if (gIoBuffer->Type == 5 || gIoBuffer->Type == 6) {
					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
				}
				gIoBuffer->Error = Brother_KeyBoard(gIoBuffer);
				sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO), Addr, SockLen);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_FILE) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				gIoBuffer->Error = Brother_File(gIoBuffer);
				sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO), Addr, SockLen);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MUTEX) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				gIoBuffer->Error = Brother_Mutex(gIoBuffer);
				sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO), Addr, SockLen);
				goto TOEND;
			}
			else
			{
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				sendEncryptUdp(s, 0x21212121, rBuffer, sizeof(IOINFO),Addr, SockLen);
				goto TOEND;
			}

		}
		__except (1) {
			KeLowerIrql(irql);
			return 0;
		}

	TOEND:
		KeLowerIrql(irql);
		return 0;

	}


	int  IOFileBuffer(HANDLE hFile, DWORD IOMajor, LPIOINFO pInfo, char* rBuffer) {
		KIRQL irql = KeGetCurrentIrql();
		__try {

			if (IOMajor == BROTHER_DRIVERCODE_KEY)
			{
				Brother_getKey(pInfo);
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MEMORY) {
				//LOG_DEBUG("BROTHER_DRIVERCODE_MEMORY \n");
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				if (gIoBuffer->Type == KERNEL_WRITE) {
					gIoBuffer->pVal = (void*)((DWORD64)pInfo + sizeof(IOINFO)); // 数据
					//LOG_DEBUG("KERNEL_WRITE   %I64X   nSize %d\n", gIoBuffer->pAdr, gIoBuffer->pValSize);
				}
				else if (gIoBuffer->Type == KERNEL_READ) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pAdrSize);
					goto TOEND;
				}
				else if (gIoBuffer->Type == KERNEL_READ_LIST) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					int nSize =   LOWORD(gIoBuffer->pValSize);
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize * nSize);
					goto TOEND;
				}
				else if (gIoBuffer->Type == KERNEL_READ_OFFSET) {
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO)); // 返回数据
					gIoBuffer->Error = Brother_Memory(gIoBuffer);
					//LOG_DEBUG("KERNEL_READ \n");
					sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pAdrSize);
					goto TOEND;
				}
				gIoBuffer->Error = Brother_Memory(gIoBuffer);
				sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_PROCESS) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));

				if (gIoBuffer->Type == 9) {

					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO));
					gIoBuffer->Error = Brother_Process(gIoBuffer);
					sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO) + gIoBuffer->pValSize);
					goto TOEND;
				}

				gIoBuffer->Error = Brother_Process(gIoBuffer);
				sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}

			else if (IOMajor == BROTHER_DRIVERCODE_WINDOWS) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));


				LOG_DEBUG("Windows Type  %d\n", gIoBuffer->Type);
				if (gIoBuffer->Type == 7) {
					LOG_DEBUG("Windows Type  %d\n", gIoBuffer->Type);
					char* Begin = (char*)((DWORD64)pInfo + sizeof(IOINFO));
					SOCKET_UNICODESTRING_INFO* pSizeInfo =(SOCKET_UNICODESTRING_INFO*)Begin;

					LOG_DEBUG(" %d  %d %d %d\n", pSizeInfo->Size[0], pSizeInfo->Size[1],
						pSizeInfo->offset[0], pSizeInfo->offset[1]);


					if (pSizeInfo->Size[0] < 0 || pSizeInfo->Size[0]>256) {
						gIoBuffer->pAdrSize = 0;
					}
					else {
						gIoBuffer->pAdr = Begin + pSizeInfo->offset[0];
						gIoBuffer->pAdrSize = pSizeInfo->Size[0];
					}

					if (pSizeInfo->Size[1] < 0 || pSizeInfo->Size[1]>256) {
						gIoBuffer->pValSize = 0;
					}
					else
					{
						gIoBuffer->pVal = Begin + pSizeInfo->offset[1];
						gIoBuffer->pValSize = pSizeInfo->Size[1];
					}

					LOG_DEBUG("%ws  %ws\n", gIoBuffer->pAdr, gIoBuffer->pVal);
				}
				if (gIoBuffer->Type == 8 || gIoBuffer->Type == 9) {
					gIoBuffer->pVal = &gIoBuffer->pAdr;
				}
				gIoBuffer->Error = Brother_Window(gIoBuffer);
				sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}

			else if (IOMajor == BROTHER_DRIVERCODE_MOUDLE) {

				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				if (gIoBuffer->Type == 0) {
					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
					gIoBuffer->pVal = (void*)((DWORD64)gIoBuffer + sizeof(IOINFO));
				}
				gIoBuffer->Error = Brother_Moudle(gIoBuffer);
				sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_KEYBORAD) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));

				if (gIoBuffer->Type == 5 || gIoBuffer->Type == 6) {
					gIoBuffer->pAdr = (void*)((DWORD64)pInfo + sizeof(IOINFO));
				}
				gIoBuffer->Error = Brother_KeyBoard(gIoBuffer);
				sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_FILE) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				gIoBuffer->Error = Brother_File(gIoBuffer);
				sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else if (IOMajor == BROTHER_DRIVERCODE_MUTEX) {
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				gIoBuffer->Error = Brother_Mutex(gIoBuffer);
				sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}
			else
			{
				LPIOINFO gIoBuffer = (LPIOINFO)rBuffer;
				RtlCopyMemory(gIoBuffer, pInfo, sizeof(IOINFO));
				sendEncryptFile(hFile, 0x21212121, rBuffer, sizeof(IOINFO));
				goto TOEND;
			}

		}
		__except (1) {
			KeLowerIrql(irql);
			return 0;
		}

	TOEND:
		KeLowerIrql(irql);
		return 0;
	}



	OB_PREOP_CALLBACK_STATUS DriverCreateCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {

		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {

			LOG_DEBUG("Create Driver  %I64X", OperationInformation->Object);

			PDRIVER_OBJECT pDriverObj = (PDRIVER_OBJECT)OperationInformation->Object;
			if (pDriverObj != 0) {
				LOG_DEBUG("DriverSection %I64X", pDriverObj->DriverSection);


				PLDR_DATA_TABLE_ENTRY pLdrTblEntry = (PLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;

				if (pLdrTblEntry->BaseDllName.Buffer != 0)
				{
					//GetDeviceInfo(pLdrTblEntry);
					LOG_DEBUG("%d  %wZ\t0x%I64X\t%I64u(B)\t0x%I64X\t%wZ\r\n", 0,
						&pLdrTblEntry->BaseDllName,
						pLdrTblEntry->DllBase,
						pLdrTblEntry->SizeOfImage,
						pDriverObj,
						&pLdrTblEntry->FullDllName
					);


					UNICODE_STRING EacDriverBaseName;
					RtlInitUnicodeString(&EacDriverBaseName, L"EasyAntiCheat.sys");

					if (RtlEqualUnicodeString(&pLdrTblEntry->BaseDllName, &EacDriverBaseName, TRUE))
					{



						LOG_DEBUG("Find Driver Object %wZ  <%p>\n", &pLdrTblEntry->BaseDllName, pDriverObj);
						//return (PDRIVER_OBJECT)pLdrTblEntry;
						//fObject = pCurDrvObj;

						RtlZeroMemory(&EAC_HOOK, sizeof(EAC_HOOK));
						for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
							EAC_HOOK.NewMajorFunction[i] = EACDispatchCtl;
						}
						START_HOOK_DRIVER(pDriverObj, &EAC_HOOK);

						//UNLoadProcess();


						HANDLE thread_handle;
	                    PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_IniHide, NULL);

						//START_HOOK_DRIVER(pDriverObj, &EAC_HOOK);

					}

				}





			}

		}
		else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			LOG_DEBUG("DUPLICATE Driver Object  %I64X", OperationInformation->Object);
		}

		return OB_PREOP_SUCCESS;

		//return 0;
	}

























#ifdef __cplusplus
}
#endif












