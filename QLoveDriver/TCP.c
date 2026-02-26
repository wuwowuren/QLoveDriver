#include "TCP.h"


#include <wdm.h>
#include <ntddk.h>
//#pragma warning(push)
//#pragma warning(disable:4201)       // unnamed struct/union
//#pragma warning(disable:4995)
#include <ndis.h>
#include <fwpsk.h>
//#pragma warning(pop)
#include <fwpmk.h>
#include <limits.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <ntstrsafe.h>


#define INITGUID
#include <guiddef.h>
#define bool BOOLEAN
#define true TRUE 
#define false FALSE


#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p) ExFreePool(_p)
// {6812FC83-7D3E-499a-A012-55E0D85F348B}
DEFINE_GUID (GUID_ALE_AUTH_CONNECT_CALLOUT_V4,
	0x6812fc83,
	0x7d3e,
	0x499a,
	0xa0, 0x12, 0x55, 0xe0, 0xd8, 0x5f, 0x34, 0x8b
);

DEFINE_GUID(GUID_ALE_AUTH_CONNECT_CALLOUT_V6,
	0xae1e820a, 0xc60a, 0x42a8, 0xb4, 0xa2, 0x9a, 0xcf, 0xb0, 0x50, 0x38, 0x7f);

PDEVICE_OBJECT  gDevObj;

HANDLE	gEngineHandle = 0;
HANDLE	gInjectHandle = 0;
//CalloutId
UINT32	gAleConnectCalloutId = 0;
//FilterId
UINT64	gAleConnectFilterId = 0;




//CalloutId v6
UINT32	gAleConnectCalloutIdv6 = 0;
//FilterId  v6
UINT64	gAleConnectFilterIdv6 = 0;


/*
以下两个回调函数没啥用
*/
NTSTATUS NTAPI WallNotifyFn
(
	IN FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER* filter
)
{
	return STATUS_SUCCESS;
}

VOID NTAPI WallFlowDeleteFn
(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
)
{
	return;
}

//协议代码转为名称
char* ProtocolIdToName(UINT16 id)
{
	char* ProtocolName = kmalloc(16);
	switch (id)	//http://www.ietf.org/rfc/rfc1700.txt
	{
	case 1:
		strcpy_s(ProtocolName, 4 + 1, "ICMP");
		break;
	case 2:
		strcpy_s(ProtocolName, 4 + 1, "IGMP");
		break;
	case 6:
		strcpy_s(ProtocolName, 3 + 1, "TCP");
		break;
	case 17:
		strcpy_s(ProtocolName, 3 + 1, "UDP");
		break;
	case 27:
		strcpy_s(ProtocolName, 3 + 1, "RDP");
		break;
	default:
		strcpy_s(ProtocolName, 7 + 1, "UNKNOWN");
		break;
	}
	return ProtocolName;
}

//最重要的过滤函数
//http://msdn.microsoft.com/en-us/library/windows/hardware/ff551238(v=vs.85).aspx
void NTAPI WallALEConnectClassify
(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
)
{

	__try {

//		char* ProtocolName = NULL;
		if (inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4)
		{

			DWORD LocalIp, RemoteIP;
			LocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
			RemoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;


			if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16 == 6)
			{
				//DbgPrint("[WFP]IRQL=%d;Path=%S;Local=%u.%u.%u.%u:%d;Remote=%u.%u.%u.%u:%d\n",
				//	(USHORT)KeGetCurrentIrql(),
				//	(PWCHAR)inMetaValues->processPath->data,	//NULL,//
				//	(LocalIp >> 24) & 0xFF, (LocalIp >> 16) & 0xFF, (LocalIp >> 8) & 0xFF, LocalIp & 0xFF,
				//	inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16,
				//	(RemoteIP >> 24) & 0xFF, (RemoteIP >> 16) & 0xFF, (RemoteIP >> 8) & 0xFF, RemoteIP & 0xFF,
				//	inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16);




				classifyOut->actionType = FWP_ACTION_PERMIT;//允许连接

				//DbgPrint("baidu to 163 ---\n");
				//UINT32 d163 = 113 << 24 + 250 << 16 + 84 << 8 + 162;
				//inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32 = d163;


			}
		}
		else if (inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6)
		{

			DWORD LocalIp, RemoteIP;
			LocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.uint32;
			RemoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.uint32;

			if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint16 == 6)
			{
				//DbgPrint("[WFP]IRQL=%d;Path=%S;Local=%u.%u.%u.%u:%d;Remote=%u.%u.%u.%u:%d\n",
				//	(USHORT)KeGetCurrentIrql(),
				//	(PWCHAR)inMetaValues->processPath->data,	//NULL,//
				//	(LocalIp >> 24) & 0xFF, (LocalIp >> 16) & 0xFF, (LocalIp >> 8) & 0xFF, LocalIp & 0xFF,
				//	inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16,
				//	(RemoteIP >> 24) & 0xFF, (RemoteIP >> 16) & 0xFF, (RemoteIP >> 8) & 0xFF, RemoteIP & 0xFF,
				//	inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16);




		//		classifyOut->actionType = FWP_ACTION_PERMIT;//允许连接

				//DbgPrint("baidu to 163 v6---\n");
				//UINT32 d163 = 113 << 24 + 250 << 16 + 84 << 8 + 162;
				//inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32 = d163;


			}
		}
		else 
		{
			classifyOut->actionType = FWP_ACTION_PERMIT;
			return;

		}





		//ProtocolName = ProtocolIdToName(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16);

		//kfree(ProtocolName);

	}
	__except (1) {

		//DbgPrint("__except Handle ---\n");

	}

	return;
}




// Context structure type for the WSK application's
// binding to the WSK subsystem
//typedef struct WSK_APP_BINDING_CONTEXT_ {
//	HANDLE NmrBindingHandle;
//	PWSK_CLIENT WskClient;
//	PWSK_PROVIDER_DISPATCH WskProviderDispatch;
//	 //   .
//		//. // Other application-specific members
//		//.
//} WSK_APP_BINDING_CONTEXT, * PWSK_APP_BINDING_CONTEXT;
//
//// Pool tag used for allocating the binding context
//#define BINDING_CONTEXT_POOL_TAG 'tpcb'
//
//// The WSK application uses version 1.0 of WSK
//#define WSK_APP_WSK_VERSION MAKE_WSK_VERSION(1,0)
//
//// Structure for the WSK application's dispatch table
//const WSK_CLIENT_DISPATCH WskAppDispatch = {
//  WSK_APP_WSK_VERSION,
//  0,
//  NULL  // No WskClientEvent callback
//};
//
//// ClientAttachProvider NMR API callback function
//NTSTATUS
//ClientAttachProvider(
//	IN HANDLE NmrBindingHandle,
//	IN PVOID ClientContext,
//	IN PNPI_REGISTRATION_INSTANCE ProviderRegistrationInstance
//)
//{
//	PNPI_MODULEID WskProviderModuleId;
//	PWSK_PROVIDER_CHARACTERISTICS WskProviderCharacteristics;
//	PWSK_APP_BINDING_CONTEXT BindingContext;
//	PWSK_CLIENT WskClient;
//	PWSK_PROVIDER_DISPATCH WskProviderDispatch;
//	NTSTATUS Status;
//
//	// Get pointers to the WSK subsystem's identification and
//	// characteristics structures
//	WskProviderModuleId = ProviderRegistrationInstance->ModuleId;
//	WskProviderCharacteristics =
//		(PWSK_PROVIDER_CHARACTERISTICS)
//		ProviderRegistrationInstance->NpiSpecificCharacteristics;
//
//	//
//	// The WSK application can use the data in the structures pointed
//	// to by ProviderRegistrationInstance, WskProviderModuleId, and
//	// WskProviderCharacteristics to determine if the WSK application
//	// can attach to the WSK subsystem.
//	//
//	// In this example, the WSK application does not perform any
//	// checks to determine if it can attach to the WSK subsystem.
//	//
//
//	// Allocate memory for the WSK application's binding
//	// context structure
//	BindingContext =
//		(PWSK_APP_BINDING_CONTEXT)
//		ExAllocatePoolWithTag(
//			NonPagedPool,
//			sizeof(WSK_APP_BINDING_CONTEXT),
//			BINDING_CONTEXT_POOL_TAG
//		);
//
//	// Check result of allocation
//	if (BindingContext == NULL)
//	{
//		// Return error status code
//		return STATUS_INSUFFICIENT_RESOURCES;
//	}
//
//	// Initialize the binding context structure
//	//...
//
//		// Continue with the attachment to the WSK subsystem
//		Status = NmrClientAttachProvider(
//			NmrBindingHandle,
//			BindingContext,
//			&WskAppDispatch,
//			&WskClient,
//			&WskProviderDispatch
//		);
//
//	// Check result of attachment
//	if (Status == STATUS_SUCCESS)
//	{
//		// Save NmrBindingHandle, WskClient, and
//		// WskProviderDispatch for future reference
//		BindingContext->NmrBindingHandle = NmrBindingHandle;
//		BindingContext->WskClient = WskClient;
//		BindingContext->WskProviderDispatch = WskProviderDispatch;
//	}
//
//	// Attachment did not succeed
//	else
//	{
//		// Free memory for application's binding context structure
//		ExFreePoolWithTag(
//			BindingContext,
//			BINDING_CONTEXT_POOL_TAG
//		);
//	}
//
//	// Return result of attachment
//	return Status;
//}



NTSTATUS RegisterCalloutForLayer
(
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	OUT UINT32* calloutId,
	OUT UINT64* filterId
)
{
	NTSTATUS        status = STATUS_SUCCESS;
	FWPS_CALLOUT    sCallout = { 0 };
	FWPM_FILTER     mFilter = { 0 };
	FWPM_FILTER_CONDITION mFilter_condition[1] = { 0 };
	FWPM_CALLOUT    mCallout = { 0 };
	FWPM_DISPLAY_DATA mDispData = { 0 };
	BOOLEAN         bCalloutRegistered = FALSE;
	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = classifyFn;
	sCallout.flowDeleteFn = flowDeleteNotifyFn;
	sCallout.notifyFn = notifyFn;
	//要使用哪个设备对象注册
	status = FwpsCalloutRegister(gDevObj, &sCallout, calloutId);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("error FwpsCalloutRegister");
		goto exit;
	}
		
	bCalloutRegistered = TRUE;
	mDispData.name = L"WFP GAME";
	mDispData.description = L"WFP Filter";
	//你感兴趣的内容
	mCallout.applicableLayer = *layerKey;
	//你感兴趣的内容的GUID
	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = mDispData;
	//添加回调函数
	status = FwpmCalloutAdd(gEngineHandle, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("error FwpmCalloutAdd");
		goto exit;
	}
	
	mFilter.action.calloutKey = *calloutKey;
	//在callout里决定
	mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	mFilter.displayData.name = L"WFP GAME";
	mFilter.displayData.description = L"WFP Filter";
	mFilter.layerKey = *layerKey;
	mFilter.numFilterConditions = 0;
	mFilter.filterCondition = mFilter_condition;
	mFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	mFilter.weight.type = FWP_EMPTY;
	//添加过滤器
	status = FwpmFilterAdd(gEngineHandle, &mFilter, NULL, filterId);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("FwpmFilterAdd FwpmCalloutAdd");
		goto exit;
	}
		
exit:
	if (!NT_SUCCESS(status))
	{
		if (bCalloutRegistered)
		{
			FwpsCalloutUnregisterById(*calloutId);
		}
	}
	return status;
}
NTSTATUS WallRegisterCallouts()
{
	NTSTATUS    status = STATUS_SUCCESS;
	BOOLEAN     bInTransaction = FALSE;
	BOOLEAN     bEngineOpened = FALSE;
	FWPM_SESSION session = { 0 };
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	//开启WFP引擎
	status = FwpmEngineOpen(NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&gEngineHandle);
	if (!NT_SUCCESS(status))
		goto exit;
	bEngineOpened = TRUE;
	//确认过滤权限
	status = FwpmTransactionBegin(gEngineHandle, 0);
	if (!NT_SUCCESS(status))
		goto exit;
	bInTransaction = TRUE;
	//注册回调函数
	status = RegisterCalloutForLayer(
		&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		&GUID_ALE_AUTH_CONNECT_CALLOUT_V4,
		WallALEConnectClassify,
		WallNotifyFn,
		WallFlowDeleteFn,
		&gAleConnectCalloutId,
		&gAleConnectFilterId);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("RegisterCalloutForLayer-FWPM_LAYER_ALE_AUTH_CONNECT_V4 failed!\n");
		goto exit;
	}

	status = RegisterCalloutForLayer(
		&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
		&GUID_ALE_AUTH_CONNECT_CALLOUT_V6,
		WallALEConnectClassify,
		WallNotifyFn,
		WallFlowDeleteFn,
		&gAleConnectCalloutId,
		&gAleConnectFilterId);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("RegisterCalloutForLayer-FWPM_LAYER_ALE_AUTH_CONNECT_V6 failed!\n");
		goto exit;
	}



	//确认所有内容并提交，让回调函数正式发挥作用
	status = FwpmTransactionCommit(gEngineHandle);
	if (!NT_SUCCESS(status))
		goto exit;
	bInTransaction = FALSE;
exit:
	if (!NT_SUCCESS(status))
	{
		if (bInTransaction)
		{
			FwpmTransactionAbort(gEngineHandle);
		}
		if (bEngineOpened)
		{
			FwpmEngineClose(gEngineHandle);
			gEngineHandle = 0;
		}
	}
	return status;
}




NTSTATUS WallUnRegisterCallouts()
{
	if (gEngineHandle != 0)
	{
		//删除FilterId
		FwpmFilterDeleteById(gEngineHandle, gAleConnectFilterId);
		//删除CalloutId
		FwpmCalloutDeleteById(gEngineHandle, gAleConnectCalloutId);
		//清空FilterId
		gAleConnectFilterId = 0;
		//反注册CalloutId
		FwpsCalloutUnregisterById(gAleConnectCalloutId);
		//清空CalloutId
		gAleConnectCalloutId = 0;
		//关闭引擎
		FwpmEngineClose(gEngineHandle);
		gEngineHandle = 0;
	}
	return STATUS_SUCCESS;
}


BOOL Start_Hook_Http() {

	//Fwp
	//ClientAttachProvider()

	FWPM_SERVICE_STATE  bfeState = 0;
	//c_n_a_device()
	//FWPM_SESSION fwpm_s;

	LARGE_INTEGER WaitTime;

	int WaitCycles = 20;

	 bfeState = FwpmBfeStateGet0();
	if (bfeState != FWPM_SERVICE_RUNNING)
	{
		WaitTime.QuadPart = (-5000000);   // wait 500000us (500ms) relative
		do {
			KeDelayExecutionThread(KernelMode, FALSE, &WaitTime);
			bfeState = FwpmBfeStateGet0();
			WaitCycles--;
		} while (bfeState != FWPM_SERVICE_RUNNING && WaitCycles > 0);
	}
	if (bfeState != FWPM_SERVICE_RUNNING)
	{
		// log and error handling
	}

	return  (WallRegisterCallouts() == STATUS_SUCCESS);
}




//signed __int64 __fastcall EtwpReserveTraceBuffer(
//	_WMI_LOGGER_CONTEXT* a1,
//	__int64 a2,
//	__int64 a3,
//	LARGE_INTEGER* a4,
//	int a5)
//{
//	unsigned int BufferSize; // r9d
//	__int64 LoggerId; // r8
//	int v10; // r12d
//	_ETW_SILO_TRACING_BLOCK* v11; // rsi
//	$BB8EE954816131378E4A6F7494882A4D* v12; // r14
//	signed __int64 Value; // rbx
//	signed __int64 v14; // rax
//	int v15; // eax
//	unsigned __int32 v16; // ebp
//	unsigned __int64 GetCpuClock; // rax
//	LARGE_INTEGER v18; // rax
//	unsigned __int32 v19; // eax
//	signed __int64 v20; // rax
//	signed __int64 i; // rcx
//	signed __int64 v22; // rtt
//	signed __int64 result; // rax
//	int v24; // eax
//	int v25; // ebx
//	signed __int64 v26; // rax
//	signed __int64 v27; // rtt
//	signed __int64 v28; // r11
//	unsigned __int32 v29; // eax
//	bool v30; // zf
//	LARGE_INTEGER PerformanceCounter; // rax
//	LONGLONG v32; // r8
//	signed __int64 QuadPart; // r9
//	__int64 v34; // rcx
//	unsigned int v35; // [rsp+30h] [rbp-58h]
//	unsigned int v36; // [rsp+34h] [rbp-54h]
//	unsigned int Number; // [rsp+38h] [rbp-50h]
//	signed __int64 v38; // [rsp+40h] [rbp-48h] BYREF
//	LARGE_INTEGER v39; // [rsp+48h] [rbp-40h] BYREF
//	LARGE_INTEGER v40; // [rsp+50h] [rbp-38h] BYREF
//	unsigned __int64 v41; // [rsp+58h] [rbp-30h]
//	char v42; // [rsp+90h] [rbp+8h] BYREF
//
//	if (a1->AcceptNewEvents < 0 || (unsigned int)a2 > a1->MaximumEventSize)
//	{
//	LABEL_40:
//		EtwpUpdateEventsLostCount(a1);
//		return 0i64;
//	}
//	BufferSize = a1->BufferSize;
//	LoggerId = a1->LoggerId;
//	v10 = (a2 + 7) & 0xFFFFFFF8;
//	v35 = BufferSize;
//	v36 = a1->LoggerId;
//	while (1)
//	{
//		Number = KeGetCurrentPrcb()->Number;
//		v11 = &a1->SiloState->ProcessorBlocks[(unsigned __int64)Number];
//		if ((a1->LoggerMode & 0x10000000) != 0)
//			v12 = &a1->144;
//		else
//			v12 = ($BB8EE954816131378E4A6F7494882A4D*)&v11->ProcessorBuffers[(unsigned int)LoggerId];
//		v42 = 0;
//		_m_prefetchw(v12);
//		Value = v12->CurrentBuffer.Value;
//		if ((v12->CurrentBuffer.Value & 0xF) != 0)
//		{
//			do
//			{
//				v14 = _InterlockedCompareExchange64((volatile signed __int64*)v12, Value - 1, Value);
//				if (Value == v14)
//					break;
//				Value = v14;
//			} while ((v14 & 0xF) != 0);
//		}
//		if (Value)
//		{
//			v15 = Value & 0xF;
//			if ((Value & 0xF) != 0)
//			{
//				Value &= 0xFFFFFFFFFFFFFFF0ui64;
//				if (v15 == 1)
//				{
//					_InterlockedExchangeAdd((volatile signed __int32*)(Value + 12), 0xFu);
//					_m_prefetchw(v12);
//					v26 = v12->CurrentBuffer.Value;
//					while ((v26 & 0xF) == 0)
//					{
//						if (Value != (v26 & 0xFFFFFFFFFFFFFFF0ui64))
//							break;
//						v27 = v26;
//						v26 = _InterlockedCompareExchange64((volatile signed __int64*)v12, v26 + 15, v26);
//						if (v27 == v26)
//							goto LABEL_11;
//					}
//					_InterlockedExchangeAdd((volatile signed __int32*)(Value + 12), 0xFFFFFFF1);
//				}
//			}
//			else
//			{
//				EtwpLockBufferList(a1, &v42);
//				Value = v12->CurrentBuffer.Value & 0xFFFFFFFFFFFFFFF0ui64;
//				if (Value)
//					_InterlockedIncrement((volatile signed __int32*)(Value + 12));
//				EtwpUnlockBufferList(a1, &v42);
//				LoggerId = v36;
//				BufferSize = v35;
//			}
//		LABEL_11:
//			if (Value)
//			{
//				v38 = 0i64;
//				v39.QuadPart = 0i64;
//				_m_prefetchw((const void*)(Value + 8));
//				v16 = *(_DWORD*)(Value + 8);
//				if (v16 <= BufferSize)
//					break;
//			}
//		}
//	LABEL_29:
//		v25 = EtwpSwitchBuffer((_DWORD)a1, Value, (_DWORD)v12, Number, a5);
//		if ((a1->LoggerMode & 0x4000000) != 0)
//		{
//			PerformanceCounter = KeQueryPerformanceCounter(0i64);
//			v32 = PerformanceCounter.QuadPart
//				- _InterlockedExchange64((volatile __int64*)&a1->LastBufferSwitchTime, PerformanceCounter.QuadPart);
//			do
//			{
//				QuadPart = a1->BufferWriteDuration.QuadPart;
//				if (QuadPart)
//				{
//					a2 = ((QuadPart + v32 + 2 * QuadPart) >> 63) & 3;
//					v34 = (QuadPart + v32 + 2 * QuadPart) / 4;
//				}
//				else
//				{
//					v34 = v32;
//				}
//			} while (QuadPart != _InterlockedCompareExchange64(
//				(volatile signed __int64*)&a1->BufferWriteDuration,
//				v34,
//				QuadPart));
//		}
//		if (v25 < 0)
//			goto LABEL_40;
//		LoggerId = v36;
//		BufferSize = v35;
//	}
//	while (1)
//	{
//		if ((a1->Flags & 0x8000000) != 0)
//		{
//			if ((unsigned int)EtwpGetTimeStampAndQpcDelta(a1, &v39, &v38))
//			{
//				LoggerId = v36;
//			LABEL_62:
//				BufferSize = v35;
//				goto LABEL_34;
//			}
//			LoggerId = v36;
//			v28 = v11->QpcDelta[v36];
//			v41 = 8i64 * v36;
//			if (v38 != v28 || v16 == 72)
//			{
//				v29 = _InterlockedCompareExchange((volatile signed __int32*)(Value + 8), v16 + 24, v16);
//				if (v16 == v29)
//				{
//					if ((unsigned __int64)v29 + 24 > v35)
//					{
//						*(_DWORD*)(Value + 4) = v29;
//						goto LABEL_29;
//					}
//					a2 = (__int64)&v11->QpcDelta[v41 / 8];
//					v30 = v28 == _InterlockedCompareExchange64((volatile signed __int64*)a2, v38, v28);
//					*(_DWORD*)(v29 + Value + 4) = 5308440;
//					v16 = v29;
//					*(LARGE_INTEGER*)(v29 + Value + 8) = v39;
//					if (v30)
//					{
//						*(_QWORD*)(v29 + Value + 16) = v38;
//						*(_DWORD*)(v29 + Value) = -1072627710;
//					}
//					else
//					{
//						*(_DWORD*)(v29 + Value) = -1072627711;
//						*(_QWORD*)(v29 + Value + 16) = 0i64;
//					}
//				}
//				else
//				{
//					v16 = v29;
//				}
//				goto LABEL_62;
//			}
//			v18 = v39;
//			BufferSize = v35;
//		}
//		else
//		{
//			GetCpuClock = a1->GetCpuClock;
//			if (GetCpuClock > 3)
//				goto LABEL_70;
//			if ((_DWORD)GetCpuClock == 3)
//			{
//				v18.QuadPart = __rdtsc();
//			}
//			else if ((_DWORD)GetCpuClock)
//			{
//				v24 = GetCpuClock - 1;
//				if (v24)
//				{
//					if (v24 != 1)
//						LABEL_70:
//					__fastfail(0x3Du);
//					v40.QuadPart = 0i64;
//					((void(__fastcall*)(LARGE_INTEGER*, __int64, __int64))off_140C009E0[0])(&v40, a2, LoggerId);
//					v18 = v40;
//					LoggerId = v36;
//					BufferSize = v35;
//				}
//				else
//				{
//					v18 = KeQueryPerformanceCounter(0i64);
//					LoggerId = v36;
//					BufferSize = v35;
//				}
//			}
//			else
//			{
//				v18.QuadPart = RtlGetSystemTimePrecise();
//				LoggerId = v36;
//				BufferSize = v35;
//			}
//		}
//		*a4 = v18;
//		v19 = _InterlockedCompareExchange((volatile signed __int32*)(Value + 8), v10 + v16, v16);
//		a2 = v19;
//		if (v16 == v19)
//			break;
//		v16 = v19;
//	LABEL_34:
//		if (v16 > BufferSize)
//			goto LABEL_29;
//	}
//	if (v19 + v10 > BufferSize)
//	{
//		*(_DWORD*)(Value + 4) = v19;
//		goto LABEL_29;
//	}
//	if ((a1->LoggerMode & 0x400) != 0)
//	{
//		v20 = *(_QWORD*)(Value + 16);
//		for (i = a4->QuadPart; a4->QuadPart > v20; i = a4->QuadPart)
//		{
//			v22 = v20;
//			v20 = _InterlockedCompareExchange64((volatile signed __int64*)(Value + 16), i, v20);
//			if (v22 == v20)
//				break;
//		}
//	}
//	++v11->EventsLoggedCount[(unsigned int)LoggerId];
//	result = Value + a2;
//	*(_QWORD*)a3 = Value;
//	*(_QWORD*)(a3 + 8) = v12;
//	*(_DWORD*)(a3 + 16) = a2;
//	return result;











