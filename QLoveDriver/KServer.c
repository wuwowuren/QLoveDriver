#include "KServer.h"
#include "KsSocket/berkeley.h"
#include "DEBUG_LOG.h"

#define server_ip 0x7F000001 // localhost





SOCKET create_server_socket(uint16_t port)
{
	SOCKADDR_IN address;
	
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY/*htonl(server_ip)*/;
	address.sin_port = htons(port);

	SOCKET sockfd = socket_listen(AF_INET, SOCK_STREAM, 0);
	if (sockfd == INVALID_SOCKET)
	{
		//log("Failed to create a valid server socket.\n");

		return INVALID_SOCKET;
	}

	if (bind(sockfd, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
	{
		//log("Failed to bind the server socket.\n");

		closesocket(sockfd);
		return INVALID_SOCKET;
	}

	if (listen(sockfd, 10) == SOCKET_ERROR)
	{
		//log("Failed to start listening in on the server socket.\n");
		closesocket(sockfd);
		return INVALID_SOCKET;
	}

	return sockfd;
}





SOCKET create_server_socket_UDP(uint16_t port)
{
	SOCKADDR_IN address;

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY/*htonl(server_ip)*/;
	address.sin_port = htons(port);

	SOCKET sockfd = socket_datagram(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	
	if (sockfd == INVALID_SOCKET)
	{
		LOG_DEBUG("Failed to create a valid server socket.\n");

		return INVALID_SOCKET;
	}

	if (bind(sockfd, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
	{
		LOG_DEBUG("Failed to bind the server socket.\n");

		closesocket(sockfd);
		return INVALID_SOCKET;
	}

	//if (listen(sockfd, 10) == SOCKET_ERROR)
	//{
	//	//log("Failed to start listening in on the server socket.\n");
	//	closesocket(sockfd);
	//	return INVALID_SOCKET;
	//}

	return sockfd;
}




//typedef int (*complete_hBuffer)(SOCKET s, char* pBuffer, uint32_t nLen);
//typedef int (*long_hBuffer)(SOCKET s, char* pBuffer, uint32_t nLen);

hBuffer g_hBuffer = 0;
hBufferUdp g_hBufferUdp = 0;


#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

VOID wSleepNs(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MICROSECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}



SOCKET_BUFFER BufferArry[128] = { 0 };

extern LONG ThreadStartRoutineOffsetBegin;
extern ULONG_PTR kernelBase;


KTIMER  Accept_Timer;

KTIMER  Recv_Timer[128];

//typedef struct	_KSINFO_SOCKET {
//	SOCKET s;
//
//
//}KSINFO_SOCKET;

typedef struct _TIMER_DPC_INFO {
	KDPC Dpc;
	PKDEFERRED_ROUTINE DeferredRoutine;
	SOCKET sockfd;
	KTIMER Timer;
	SOCKET_BUFFER* SocketBuffer;
}TIMER_DPC_INFO;

SOCKET_BUFFER* AllocateNewSocketBuffer(SOCKET* sockfd) {

	SOCKET connection = *sockfd;
	char* Buffer = 0;

	if (BufferArry[connection].BufferRecv == 0) {

		Buffer = MmAllocateNonCachedMemory(RECV_SIZE);    // ExAllocatePoolWithTag(PagedPool, RECV_SIZE, 'Mem');
		//  MmAllocateNonCachedMemory
		//PHYSICAL_ADDRESS Low = { 0 };
		//PHYSICAL_ADDRESS High = { MAXULONG64 };
	//	Buffer = MmAllocateContiguousMemorySpecifyCache(RECV_SIZE, Low, High, Low, MmNonCached);
		if (Buffer == NULL) {

			return 0;
		}
		if (Buffer != 0)
		{
			BufferArry[connection].RecvBuF.Offset = 0;
			BufferArry[connection].RecvBuF.Length = RECV_SIZE;
			BufferArry[connection].RecvBuF.Mdl = IoAllocateMdl(Buffer, RECV_SIZE, FALSE, FALSE, NULL);
			__try
			{
				MmProbeAndLockPages(BufferArry[connection].RecvBuF.Mdl, KernelMode, IoWriteAccess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				ExFreePoolWithTag(BufferArry[connection].BufferRecv, 'Mem');
				LOG_DEBUG("A server thread has terminated...   01\n");
				return 0;
			}
			BufferArry[connection].BufferRecv = Buffer;
		}

	}

	if (BufferArry[connection].BufferSend == 0) {


		PHYSICAL_ADDRESS Low = { 0 };
		//PHYSICAL_ADDRESS High = { MAXULONG64 };
		//Buffer = MmAllocateContiguousMemorySpecifyCache(SEND_SIZE, Low, High, Low, MmNonCached);

		BufferArry[connection].BufferSend = MmAllocateNonCachedMemory(SEND_SIZE + 0x1000);   // MmAllocateContiguousMemorySpecifyCache(SEND_SIZE, Low, High, Low, MmNonCached);          // ExAllocatePoolWithTag(PagedPool, SEND_SIZE, 'Mem');


		if (BufferArry[connection].BufferSend != 0)
		{
			BufferArry[connection].SendBuF.Offset = 0;
			BufferArry[connection].SendBuF.Length = SEND_SIZE + 0x1000;
			BufferArry[connection].SendBuF.Mdl = IoAllocateMdl(BufferArry[connection].BufferSend, SEND_SIZE + 0x1000, FALSE, FALSE, NULL);
		}
		__try
		{
			MmProbeAndLockPages(BufferArry[connection].SendBuF.Mdl, KernelMode, IoWriteAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			MmUnlockPages(BufferArry[connection].RecvBuF.Mdl);
			IoFreeMdl(BufferArry[connection].RecvBuF.Mdl);

			MmFreeNonCachedMemory(BufferArry[connection].BufferRecv, RECV_SIZE);
			//	ExFreePoolWithTag(BufferArry[connection].BufferRecv, 'Mem');
			BufferArry[connection].BufferRecv = 0;

			IoFreeMdl(BufferArry[connection].SendBuF.Mdl);
			//ExFreePoolWithTag(BufferArry[connection].BufferSend, 'Mem');
			MmFreeNonCachedMemory(BufferArry[connection].BufferSend, SEND_SIZE + 0x1000);
			BufferArry[connection].BufferSend = 0;
			LOG_DEBUG("A server thread has terminated...02\n");
			return 0;
		}
	}
	return &BufferArry[connection];
}


void FreeSocketBuffer(SOCKET* sockfd) {

	SOCKET connection = *sockfd;
	if (BufferArry[connection].BufferRecv != 0)
	{
		MmUnlockPages(BufferArry[connection].RecvBuF.Mdl);
		IoFreeMdl(BufferArry[connection].RecvBuF.Mdl);
		MmFreeNonCachedMemory(BufferArry[connection].BufferRecv, RECV_SIZE);
		//ExFreePoolWithTag(BufferArry[connection].BufferRecv, 'Mem');
		BufferArry[connection].BufferRecv = 0;
	}
	if (BufferArry[connection].BufferSend != 0)
	{
		MmUnlockPages(BufferArry[connection].SendBuF.Mdl);
		IoFreeMdl(BufferArry[connection].SendBuF.Mdl);
		MmFreeNonCachedMemory(BufferArry[connection].BufferSend, SEND_SIZE + 0x1000);
		//ExFreePoolWithTag(BufferArry[connection].BufferSend, 'Mem');
		BufferArry[connection].BufferSend = 0;

	}
}
 

void  RecvForBufferSocket(SOCKET* sockfd ,SOCKET_BUFFER* BufferSocket) {
	SOCKET connection = *sockfd;
	while (TRUE) {

		int result = recv(connection, BufferSocket->BufferRecv, RECV_SIZE, 0);
		if (result > 0) {
			//DWORD RSize = *(DWORD*)Buffer;
			if (g_hBuffer != 0) {
				int r = g_hBuffer(connection, BufferSocket->BufferRecv, result);
				if (r == -1) {
					closesocket(connection);
					break;
				}
			}
		}
		else if (result == 0) {
			wSleepNs(10);
		}
		else if (result < 0)
		{
			closesocket(connection);
			break;
		}
	}
	FreeSocketBuffer(sockfd);
}

#include "HandleHide.h"

void server_thread(SOCKET* sockfd)
{
	LOG_DEBUG("Connection received, server thread spawned.\n");

	while (ThreadStartRoutineOffsetBegin == 0)
	{
		//
		wSleepNs(10);
	}

	PETHREAD pThread = PsGetCurrentThread();
	*((DWORD64*)((DWORD64)pThread + ThreadStartRoutineOffsetBegin)) = (DWORD64)kernelBase;

	// RemoveSelfThread();

	SOCKET connection = *sockfd;
	LOG_DEBUG("Connection received, server thread spawned. %d \n", connection);
	__try {
		SOCKET_BUFFER* BufferSocket = AllocateNewSocketBuffer(sockfd);
		if (BufferSocket == NULL) {
			closesocket(connection);
			return;
		}
		RecvForBufferSocket(sockfd, BufferSocket);
	}
	__except (1) {

	}
	LOG_DEBUG("A server thread has terminated...\n");
}

SOCKET server_socket = -1;


VOID PollingRecvTimer(PKDPC pDpc, PVOID pContext, PVOID SysArg1, PVOID SysArg2) {
	KIRQL OldIrql = KeGetCurrentIrql();
	KeLowerIrql(PASSIVE_LEVEL);
	TIMER_DPC_INFO* pDpcRecv = (TIMER_DPC_INFO*)pContext;

	SOCKET connection = pDpcRecv->sockfd;



	int result = recv(connection, pDpcRecv->SocketBuffer->BufferRecv, RECV_SIZE, 0);
	if (result > 0) {
		//DWORD RSize = *(DWORD*)Buffer;
		if (g_hBuffer != 0) {
			int r = g_hBuffer(connection, pDpcRecv->SocketBuffer->BufferRecv, result);
			if (r == -1) {
				closesocket(connection);
				KeCancelTimer(&pDpcRecv->Timer);
				//break;
			}
		}
	}
	else if (result == 0) {
		//wSleepNs(10);
	}
	else if (result < 0)
	{
		closesocket(connection);
		KeCancelTimer(&pDpcRecv->Timer);
		//break;
	}


}










void server_accept(void* sockfd) {


	while (ThreadStartRoutineOffsetBegin == 0){//
		wSleepNs(10);
	}

	//PETHREAD pThread = PsGetCurrentThread();
	//*((DWORD64*)((DWORD64)pThread + ThreadStartRoutineOffsetBegin)) = (DWORD64)kernelBase;
	SOCKET listenfd = (SOCKET)server_socket;



	//RemoveSelfThread();

	__try
	{

		LOG_DEBUG("accept on s %d\n", listenfd);
		while (TRUE)
		{

			struct sockaddr socket_addr;
			socklen_t socket_length;

			SOCKET client_connection = accept(listenfd, &socket_addr, &socket_length);

			if (client_connection == INVALID_SOCKET)
			{
				LOG_DEBUG("Failed to accept client connection.\n");
			}
			else
			{
				HANDLE thread_handle;
				PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_thread, &client_connection);
			}
		}
	}
	__except (1) {

		LOG_DEBUG("The main thread has terminated.. __except\n");
	}

	LOG_DEBUG("The main thread has terminated...\n");
	closesocket(listenfd);


}

VOID PollingAcceptTimer(PKDPC pDpc, PVOID pContext, PVOID SysArg1, PVOID SysArg2) {


	KIRQL OldIrql = KeGetCurrentIrql();
	KeLowerIrql(PASSIVE_LEVEL);

	TIMER_DPC_INFO* pDpcAccept = (TIMER_DPC_INFO*)pContext;

	struct sockaddr socket_addr;
	socklen_t socket_length;
	SOCKET listenfd = pDpcAccept->sockfd;
	SOCKET client_connection = accept(listenfd, &socket_addr, &socket_length);
	if (client_connection == INVALID_SOCKET)
	{
		//LOG_DEBUG("Failed to accept client connection.\n");
		KfRaiseIrql(OldIrql);
		return;
	}
	else
	{
		//SOCKET connection = *sockfd;
		LOG_DEBUG("Add Dpc Timer  %d\n", client_connection);
		SOCKET_BUFFER* BufferSocket = AllocateNewSocketBuffer(&client_connection);

		if (BufferSocket != NULL) {

			TIMER_DPC_INFO* pDpcInfo = ExAllocatePoolWithTag(PagedPool, sizeof(TIMER_DPC_INFO), 'Tag');

			KeInitializeTimer(&pDpcInfo->Timer);
			pDpcInfo->DeferredRoutine = PollingRecvTimer;
			pDpcInfo->sockfd = client_connection;
			pDpcInfo->SocketBuffer = BufferSocket;

			KeInitializeDpc(&pDpcInfo->Dpc, PollingRecvTimer, pDpcInfo);

			LARGE_INTEGER DueTime; DueTime.QuadPart = 0;

			KeSetTimerEx(&pDpcInfo->Timer, DueTime, 1, &pDpcInfo->Dpc);

			LOG_DEBUG("Add Dpc Timer  %d\n", client_connection);
		}
		else
		{
			closesocket(client_connection);
		}

		//HANDLE thread_handle;
		//PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_thread, &client_connection);
	}
	KfRaiseIrql(OldIrql);
}

//_Kernel_entry_ NTSTATUS __stdcall IoInitializeTimer(PDEVICE_OBJECT DeviceObject, PIO_TIMER_ROUTINE TimerRoutine, PVOID Context);

BOOLEAN KServer_Start(int port, hBuffer CALL){

	NTSTATUS status = KsInitialize();
	if (!NT_SUCCESS(status)){
		LOG_DEBUG("Failed to initialize KSOCKET.\n");
		return  0;
	}
	server_socket = create_server_socket((uint16_t)port);
	if (server_socket == INVALID_SOCKET)
	{
		log("Failed to initialize the server socket.\n");
		KsDestroy();
		return 0;
	}
	LOG_DEBUG("Listening on port %d\n", port);
	g_hBuffer = CALL;


	RtlZeroMemory(BufferArry, sizeof(SOCKET_BUFFER) * 128);

	//HANDLE thread_handle;
	//PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_accept, NULL);



	KeInitializeTimer(&Accept_Timer);
	TIMER_DPC_INFO* pDpcInfo = ExAllocatePoolWithTag(PagedPool, sizeof(TIMER_DPC_INFO), 'Tag');
	pDpcInfo->DeferredRoutine = PollingAcceptTimer;
	pDpcInfo->sockfd = server_socket;
	KeInitializeDpc(&pDpcInfo->Dpc, PollingAcceptTimer, pDpcInfo);


	return 1;
}


BOOLEAN KServer_StartSign(DWORD RandSign, hBuffer CALL) {

	NTSTATUS status = KsInitialize();
	if (!NT_SUCCESS(status)) {
		LOG_DEBUG("Failed to initialize KSOCKET.\n");
		return  0;
	}
	int port = RandSign % 30000;
	if (port < 10000){
		port = port + 10000;
	}
	server_socket = create_server_socket((uint16_t)port);
	if (server_socket == INVALID_SOCKET)
	{
		log("Failed to initialize the server socket.\n");
		KsDestroy();
		return 0;
	}
	LOG_DEBUG("Listening on port %d\n", port);
	g_hBuffer = CALL;




	RtlZeroMemory(BufferArry, sizeof(SOCKET_BUFFER) * 128);
	HANDLE thread_handle = 0;
	status = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_accept, NULL);

	//if (NT_SUCCESS(status))
	//{
	//	LOG_DEBUG("Accept Thread <%p>\n", thread_handle);
	//}

	//TIMER_DPC_INFO* pDpcInfo = ExAllocatePoolWithTag(PagedPool, sizeof(TIMER_DPC_INFO), 'Tag');

	//KeInitializeTimer(&pDpcInfo->Timer);

	//pDpcInfo->DeferredRoutine = PollingAcceptTimer;
	//pDpcInfo->sockfd = server_socket;
	//KeInitializeDpc(&pDpcInfo->Dpc, PollingAcceptTimer, pDpcInfo);

	//LARGE_INTEGER DueTime; DueTime.QuadPart = 0;

	//KeSetTimerEx(&pDpcInfo->Timer, DueTime, 10, &pDpcInfo->Dpc);
	return 1;
}







void server_threadUdp(SOCKET* sockfd) {

	LOG_DEBUG("Connection received, server thread spawned.  %d \n", server_socket);
	SOCKET connection = server_socket;
	char* Buffer = 0;
	if (BufferArry[connection].BufferRecv == 0) {
		Buffer = ExAllocatePoolWithTag(PagedPool, RECV_SIZE, 'Mem');
		BufferArry[connection].BufferRecv = Buffer;
	}

	if (BufferArry[connection].BufferSend == 0) {
		BufferArry[connection].BufferSend = ExAllocatePoolWithTag(PagedPool, SEND_SIZE, 'Mem');
	}

	if (Buffer == NULL) {
		closesocket(connection);
		return;
	}
	int addr_len = sizeof(struct sockaddr_in);

	LOG_DEBUG("recvfrom  Begin\n");
	while (TRUE) {
		//MSG_PEEK
		//hBufferUdp
		struct sockaddr_in addr_cli;
		int result = recvfrom(connection, Buffer, RECV_SIZE, 0, (struct sockaddr*)&addr_cli, &addr_len);
		if (result > 0){
			g_hBufferUdp(connection, Buffer, result, (struct sockaddr*)&addr_cli, addr_len);
			LOG_DEBUG("recvfrom  Begin 0\n");
		}
		else if (result == 0) {
			LOG_DEBUG("recvfrom  Begin 1\n");
			wSleepNs(10);
		}
		else if (result < 0)
		{
			LOG_DEBUG("recvfrom  Begin %08X\n", result);
			//closesocket(connection);
			//break;
		}
		//int result = recv(connection, Buffer, RECV_SIZE, 0);
		//if (result > 0) {
		//	if (g_hBuffer != 0) {
		//		int r = g_hBuffer(connection, Buffer, result);
		//		if (r == -1) {
		//			closesocket(connection);
		//			break;
		//		}
		//	}
		//}
		//else if (result == 0) {
		//	wSleepNs(10);
		//}
		//else if (result < 0)
		//{
		//	closesocket(connection);
		//	break;
		//}
	}
	if (BufferArry[connection].BufferRecv != 0)
	{
		ExFreePoolWithTag(BufferArry[connection].BufferRecv, 'Mem');
		BufferArry[connection].BufferRecv = 0;
	}
	if (BufferArry[connection].BufferSend != 0)
	{
		ExFreePoolWithTag(BufferArry[connection].BufferSend, 'Mem');
		BufferArry[connection].BufferSend = 0;

	}
	LOG_DEBUG("A server thread has terminated...\n");
}







BOOLEAN KServer_StartUdp(int port, hBufferUdp CALL) {

	NTSTATUS status = KsInitialize();
	if (!NT_SUCCESS(status)) {
		LOG_DEBUG("Failed to initialize KSOCKET.\n");
		return 0;
	}
	server_socket = create_server_socket_UDP((uint16_t)port);
	if (server_socket == INVALID_SOCKET)
	{
		LOG_DEBUG("Failed to initialize the server socket.\n");
		KsDestroy();
		return 0;
	}
	LOG_DEBUG("Listening on port %d\n", port);
	g_hBufferUdp = CALL;

	RtlZeroMemory(BufferArry, sizeof(SOCKET_BUFFER) * 128);
	HANDLE thread_handle;
	PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, 0, 0, 0, server_threadUdp, NULL);
	return 1;
}