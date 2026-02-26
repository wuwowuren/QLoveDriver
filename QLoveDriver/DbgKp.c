#include "DbgKp.h"




//typedef struct _DBGKM_APIMSG {
//	PORT_MESSAGE h;
//	DBGKM_APINUMBER ApiNumber;
//	NTSTATUS ReturnedStatus;
//	union {
//		DBGKM_EXCEPTION Exception;
//		DBGKM_CREATE_THREAD CreateThread;
//		DBGKM_CREATE_PROCESS CreateProcessInfo;
//		DBGKM_EXIT_THREAD ExitThread;
//		DBGKM_EXIT_PROCESS ExitProcess;
//		DBGKM_LOAD_DLL LoadDll;
//		DBGKM_UNLOAD_DLL UnloadDll;
//	} u;
//} DBGKM_APIMSG, *PDBGKM_APIMSG;
//
//typedef struct _DBGKM_CREATE_PROCESS {
//	ULONG SubSystemKey;
//	HANDLE FileHandle;
//	PVOID BaseOfImage;
//	ULONG DebugInfoFileOffset;
//	ULONG DebugInfoSize;
//	DBGKM_CREATE_THREAD InitialThread;
//} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;
//
//
//
//NTSTATUS NtCreateDebugObject(
//	OUT PHANDLE DebugObjectHandle,
//	IN ACCESS_MASK DesiredAccess,
//	IN POBJECT_ATTRIBUTES ObjectAttributes,
//	IN ULONG Flags
//)
//
//{
//	NTSTATUS Status;
//	HANDLE Handle;
//	KPROCESSOR_MODE PreviousMode;
//	PDEBUG_OBJECT DebugObject;
//	//检测这个宏所在位置的IRQL级别，相当于一个断言，确定当前IRQL允许分页
//	PAGED_CODE();
//	//获取当前操作模式是内核还是用户
//	PreviousMode = KeGetPreviousMode();
//
//	try
//	{
//		if (PreviousMode != KernelMode)
//		{
//			//验证是否可读写（验证参数正确性）
//			ProbeForWriteHandle(DebugObjectHandle);
//		}
//		*DebugObjectHandle = NULL;
//
//	} except(ExSystemExceptionFilter())
//	{
//		return GetExceptionCode();
//	}
//
//	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
//		return STATUS_INVALID_PARAMETER;
//	}
//
//	//
//	// 创建调试对象
//	//
//
//	Status = ObCreateObject(PreviousMode,
//		DbgkDebugObjectType,
//		ObjectAttributes,
//		PreviousMode,
//		NULL,
//		sizeof(DEBUG_OBJECT),
//		0,
//		0,
//		&DebugObject);
//
//	if (!NT_SUCCESS(Status))
//	{
//		return Status;
//	}
//
//	ExInitializeFastMutex(&DebugObject->Mutex);
//	//初始化调试内核对象中的调试事件链表
//	InitializeListHead(&DebugObject->EventList);
//	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);
//
//	if (Flags & DEBUG_KILL_ON_CLOSE)
//	{
//		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
//	}
//	else
//	{
//		DebugObject->Flags = 0;
//	}
//
//	// 调试对象插入当前进程的句柄表
//	Status = ObInsertObject(DebugObject,
//		NULL,
//		DesiredAccess,
//		0,
//		NULL,
//		&Handle/*返回一个句柄*/);
//
//
//	if (!NT_SUCCESS(Status))
//	{
//		return Status;
//	}
//	//用异常处理进行安全复制
//	try
//	{
//		*DebugObjectHandle = Handle;
//	}
//	except(ExSystemExceptionFilter())
//	{
//
//		Status = GetExceptionCode();
//	}
//
//	return Status;
//}
//
//
//NTSTATUS
//DbgkpPostFakeThreadMessages(
//	IN PEPROCESS Process,
//	IN PDEBUG_OBJECT DebugObject,
//	IN PETHREAD StartThread,
//	OUT PETHREAD *pFirstThread,
//	OUT PETHREAD *pLastThread
//)
//
//{
//	NTSTATUS Status;
//	PETHREAD Thread, FirstThread, LastThread;
//	DBGKM_APIMSG ApiMsg;
//	BOOLEAN First = TRUE;
//	BOOLEAN IsFirstThread;
//	PIMAGE_NT_HEADERS NtHeaders;
//	ULONG Flags;
//	NTSTATUS Status1;
//	//验证IRQL
//	PAGED_CODE();
//
//	LastThread = FirstThread = NULL;
//
//	Status = STATUS_UNSUCCESSFUL;
//	//注意，上面传过来的就是NULL!!!
//	if (StartThread != NULL) {
//		//StartThread!=NULL说明当前线程有ID即当前线程不是初始线程
//		First = FALSE;//不是第一个
//		FirstThread = StartThread;
//		ObReferenceObject(FirstThread);
//	}
//	else
//	{
//		//==0说明当前线程是初始线程。也说明是在创建进程。
//		StartThread = PsGetNextProcessThread(Process, NULL);//这里获得的就是初始线程
//		First = TRUE;//是第一个
//	}
//
//	for (Thread = StartThread;
//		Thread != NULL;
//		//遍历进程的每一个线程
//		Thread = PsGetNextProcessThread(Process, Thread))
//	{
//		//设置调试事件不等待
//		Flags = DEBUG_EVENT_NOWAIT;
//		if (LastThread != NULL) {
//			ObDereferenceObject(LastThread);
//		}
//		//用来记录最后一个线程
//		LastThread = Thread;
//		ObReferenceObject(LastThread);
//		//锁住线程，防止线程终止
//		if (ExAcquireRundownProtection(&Thread->RundownProtect))
//		{
//			Flags |= DEBUG_EVENT_RELEASE;
//			//判断获得的线程是否是系统的线程
//			if (!IS_SYSTEM_THREAD(Thread))
//			{   //暂停线程
//				Status1 = PsSuspendThread(Thread, NULL);
//				if (NT_SUCCESS(Status1))
//				{
//					//暂停成功，加一个暂停标记
//					Flags |= DEBUG_EVENT_SUSPEND;
//				}
//			}
//		}
//		else
//		{
//			//获取锁失败，加上标记
//			Flags |= DEBUG_EVENT_PROTECT_FAILED;
//		}
//		//构造一个ApiMsg结构（DBGKM_APIMSG类型）
//		RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));
//
//		//如果申请成功，并且这个线程是第一个线程
//		//说明是进程创建
//		//这里会发生进程创建伪造消息
//		if (First && (Flags&DEBUG_EVENT_PROTECT_FAILED) == 0 &&
//			!IS_SYSTEM_THREAD(Thread) && Thread->GrantedAccess != 0)
//		{
//			IsFirstThread = TRUE;//说明是第一线程创建兼进程创建
//		}
//		else
//		{
//			IsFirstThread = FALSE;
//		}
//
//		if (IsFirstThread)
//		{
//			//这里设置了进程创建伪造消息的结构
//			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
//			if (Process->SectionObject != NULL) //
//			{
//				//把进程主模块的文件句柄保存在伪造消息的结构中
//				ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpSectionToFileHandle(Process->SectionObject);
//			}
//			else
//			{
//				ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
//			}
//
//			//把进程主模块基址保存在伪造信息的结构中
//			ApiMsg.u.CreateProcessInfo.BaseOfImage = Process->SectionBaseAddress;
//			//用异常处理增强稳定性
//			try
//			{
//				//获得PE结构的NT头部
//				NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
//				if (NtHeaders)
//				{
//					ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL; // Filling this in breaks MSDEV!
//					//解析NT头部中的调试信息，放入伪造信息的结构中
//					ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
//					ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
//				}
//			}
//			except(EXCEPTION_EXECUTE_HANDLER)
//			{
//				ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
//				ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
//				ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
//			}
//		}
//		else
//		{   //不是第一个，说明是线程创建，设置一个线程创建伪造信息结构
//			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
//			ApiMsg.u.CreateThread.StartAddress = Thread->StartAddress;
//		}
//
//		//把上面构造的消息包插入到队列中
//		Status = DbgkpQueueMessage(Process,
//			Thread,
//			&ApiMsg,
//			Flags,
//			DebugObject);
//		//错误处理
//		if (!NT_SUCCESS(Status))
//		{
//			if (Flags&DEBUG_EVENT_SUSPEND)
//			{
//				PsResumeThread(Thread, NULL);
//			}
//			if (Flags&DEBUG_EVENT_RELEASE)
//			{
//				ExReleaseRundownProtection(&Thread->RundownProtect);
//			}
//			if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL)
//			{
//				ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
//			}
//			PsQuitNextProcessThread(Thread);
//			break;
//		}
//		else if (IsFirstThread) {
//			First = FALSE;//已经处理完第一次了
//			ObReferenceObject(Thread);
//			FirstThread = Thread;
//		}
//	}
//
//
//	if (!NT_SUCCESS(Status)) {
//		if (FirstThread) {
//			ObDereferenceObject(FirstThread);
//		}
//		if (LastThread != NULL) {
//			ObDereferenceObject(LastThread);
//		}
//	}
//	else {
//		if (FirstThread) {
//			*pFirstThread = FirstThread;
//			*pLastThread = LastThread;
//		}
//		else {
//			Status = STATUS_UNSUCCESSFUL;
//		}
//	}
//	return Status;
//}