

#include "SSDT_HOOK.h"
#include "PhysicalMemory.h"
#define HOOKDBG

#ifdef DEBUG
#ifdef HOOKDBG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format,__LINE__, __VA_ARGS__);
#else
#define LOG_DEBUG(format,...) 
#endif // HOOKDBG
#else
#define LOG_DEBUG(format,...) 
#endif // DEBUG

//#ifdef DEBUG
//#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format,__LINE__, __VA_ARGS__);
//#else
//#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
//#endif

#pragma warning(disable:4819)

//-----------------------------------

#include "HookBuffer.h"




#pragma pack(1)    //设置字节对齐

typedef struct _tagJMPEX
{
	char A[2];
	ULONG Pointer;
	ULONGLONG P_new_SSDT;
}*LPJMPEX, JMPEX;

typedef struct _tagJMPEX2
{
  char A[3];
  ULONGLONG P_new_SSDT;
  char B[2];
}*LPJMPEX2, JMPEX2;

typedef struct _tagJMPEX3
{
  char A[2];
  ULONGLONG P_new_SSDT;
  char B[2];
}*LPJMPEX3, JMPEX3;

typedef struct _tagJMPEX_IN
{
  char sg[24];
  char A[2];
  ULONG Pointer;
  ULONGLONG P_new_SSDT;
}*LPJMPEX_IN, JMPEX_IN;


#pragma pack()     //取消字节对齐


//static ULONGLONG OLD_SSDT_ADDRESS[4096] = {0};
static ULONGLONG OLD_SSDTSHOW_ADDRESS[4096] = { 0 };


static PULONG OLD_TABLEBASE = NULL;
//static PULONG OLD_TABLEBASE2 = NULL;
static PULONG OLD_SHOW_TABLEBASE = NULL;
static ULONGLONG SSDT_NumberOfServices = 0;
static ULONGLONG SSDTSHOW_NumberOfServices = 0;

static JMPEX * SSDTJmpArry = NULL;
static JMPEX * SSDTSHOWJmpArry = NULL;
static BOOLEAN b_SSDTHOOK = FALSE;
static BOOLEAN b_SSDTSHOWHOOK = FALSE;


char *Round_SSDT = 0;
char *Round_ShaShow = 0;

ULONG BuildNumber;




//UINT32
//NTAPI
//DetourGetInstructionLength(
//	__in PVOID ControlPc
//);


BOOLEAN  SSDT_HOOK_SHOW_NOW(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN, BOOLEAN bWrite, PVOID SingleMemory);

ULONG GetOffsetAddress(ULONGLONG std, ULONGLONG FuncAddr, CHAR paramCount)
{
	LONG dwtmp = (LONG)((LONGLONG)FuncAddr - (LONGLONG)std);
	dwtmp = dwtmp << 4;
	return dwtmp + paramCount;
}


//获取SSDT中的函数地址
ULONGLONG GetSSDTFuncCurrentAddr(PSYSTEM_SERVICE_TABLE std, ULONG id)
{
	if (std != 0)
	{
		LONG dwtemp = 0;
		PULONG ServiceTableBase = NULL;
		ServiceTableBase = (PULONG)std->ServiceTableBase;
		dwtemp = ServiceTableBase[id];
		dwtemp = dwtemp >> 4;
		return (LONGLONG)dwtemp + (ULONGLONG)ServiceTableBase;
	}
	return 0;
}

ULONGLONG GetSSDTFuncAddr(ULONG id)
{
	if (id>SSDT_NumberOfServices)
	{
		return 0;
	}
	return GetSSDTFuncCurrentAddr((PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable(),id);
}

ULONGLONG GetSSDTSHOWFuncAddr(ULONG id)
{
	if (id>SSDTSHOW_NumberOfServices)
	{
		return 0;
	}
	return GetSSDTFuncCurrentAddr((PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTableShow(), id);
}




PVOID LoadMoudleMem(PVOID Buffer, size_t nSize) {

	PVOID KernelBuffer = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PMDL pMdl = IoAllocateMdl(Buffer, nSize, 0, 0, NULL);
	if (pMdl == 0)
	{
		return 0;
	}
	__try
	{
		MmBuildMdlForNonPagedPool(pMdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return 0;
	}
	__try {
		KernelBuffer = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(pMdl);
		return 0;
	}
	status = MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		IoFreeMdl(pMdl);
		return 0;
	}
	return KernelBuffer;
}



static int bRunIAT = 0;

extern ULONG_PTR kernelBase;
extern ULONG _Begin_TEXT;
extern ULONG _Lenth_TEXT;


PVOID  LoadMemoryToUser(PMDL* pMdl, PVOID addr, unsigned long nSize, KPROCESSOR_MODE Mode, ULONG Protect);
BOOLEAN  SSDT_HOOK_NOW(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN);

BOOLEAN  SSDT_HOOK_NOW_TYPE(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN, BOOLEAN bGlobal) {
	BOOLEAN bWrite = FALSE;
	PVOID SingleMemory = 0;
	if (!bGlobal) {
		bWrite = MiSingleProcessMemory(IoGetCurrentProcess(), (PVOID)((DWORD64)pOldFun & 0xFFFFFFFFFFFFF000), PAGE_SIZE, &SingleMemory);
	}
	return SSDT_HOOK_SHOW_NOW(pNewFun, pOldFun, CALLFUN, bWrite, (PVOID)((DWORD64)SingleMemory|((DWORD64)pOldFun & 0xFFF)));
}

BOOLEAN SSDT_SHOW_HOOK_NOW_TYPE(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN, BOOLEAN bGlobal)
{
	BOOLEAN bWrite = FALSE;
	PVOID SingleMemory = 0;
	if (!bGlobal) {
		bWrite = MiSingleProcessMemory(IoGetCurrentProcess(), (PVOID)((DWORD64)pOldFun & 0xFFFFFFFFFFFFF000), PAGE_SIZE, &SingleMemory);
	}
	return SSDT_HOOK_SHOW_NOW(pNewFun, pOldFun, CALLFUN, bWrite, (PVOID)((DWORD64)SingleMemory | ((DWORD64)pOldFun & 0xFFF)));
}

BOOLEAN  SSDT_HOOK_NOW(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN) {

//	return FALSE;
	__try {


		LONGLONG pFun = (LONGLONG)pOldFun;
		LONGLONG NewFun = (LONGLONG)pNewFun;
		LONG Offset = 0;
		char* NowPtr = (char*)pOldFun;




		//if (/*NowPtr[0] == (char)0x48  &&*/
		//	NowPtr[0] == (char)0xFF &&
		//	NowPtr[1] == (char)0x25)
		//{

		//	LOG_DEBUG("Logdebug   %p  real HOOK\n", pOldFun);
		//	return FALSE;
		//}

		//if (NowPtr[0] == (char)0x48  &&
		//	NowPtr[1] == (char)0xFF &&
		//	NowPtr[2] == (char)0x25)
		//{

		//	LOG_DEBUG("Logdebug   %p  real HOOK\n", pOldFun);
		//	return FALSE;
		//}

		int gLen = 0;
		int bLen = 0;

		int arry[20];
		RtlZeroMemory(&arry[0], 20 * 4);

		int maxCodeLen = 15;
		int newOffsetNo = 0;
		ULONGLONG BeginText = (ULONGLONG)kernelBase + _Begin_TEXT;
		ULONGLONG EndText = (ULONGLONG)kernelBase + _Begin_TEXT + _Lenth_TEXT;

		//LOG_DEBUG(" Base:  <%p> <%p>")


		//KIRQL irql = WPOFFx64();

		char* pNewAz = pOldFun;
		
		//for (int i = 0; i < 0x500; i++)
		//{
		//	DWORD64 hg = 0;
		//	ULONGLONG uAddress = (ULONGLONG)pNewAz + i;
		//	if (!(uAddress >= BeginText && uAddress < EndText))
		//	{
		//		break;
		//	}
		//	RtlCopyMemory(&hg, pNewAz + i, sizeof(DWORD64));
		//	if (hg == 0xCCCCCCCCCCCCCCCC && 
		//		(((ULONGLONG)(pNewAz + i)) % 0x1000 != 0) &&
		//		(((ULONGLONG)(pNewAz + i)) % 0x8 == 0))
		//	{
		//		maxCodeLen = maxCodeLen - 8;
		//		newOffsetNo = i;
		//		break;
		//	}

		//}
		//WPONx64(irql);




		int bi = 0;
		while (gLen < maxCodeLen)
		{
			bLen = DetourGetInstructionLength(NowPtr + gLen);
			arry[bi] = bLen;
			gLen += bLen;
			bi++;
			if (bLen == 0)
			{
				return FALSE;
			}
		}

		LOG_DEBUG("HOOK_LEN ID [%d]\n", gLen);

		if (Round_SSDT == 0)
		{
			return FALSE;
		}

		char* pNow = Round_SSDT;
		LOG_DEBUG("HOOK_LEN ID [%d]  <%p>\n", gLen, pNow);

		*((PULONGLONG)CALLFUN) = (ULONGLONG)pNow;
		LONG nSize = ((gLen + 7) / 8) + 1;
		LONGLONG* pCode = (LONGLONG*)pNow;
		//irql = WPOFFx64();

		memset(pNow, 0xCC, (nSize + 2) * 8);
		//RtlZeroMemory()
		pCode[nSize] = (LONGLONG)pOldFun + gLen;

		//WPONx64(irql);
		// 8字节对齐 // 倒数字节用于
		int hLen = 0;
		unsigned char* tNow = 0;


		int hLenI = 0;
		for (size_t i = 0; i < 20; i++)
		{
			if (arry[i] == 0)
			{
				break;
			}
			if (arry[i] == 7)
			{
				tNow = (char*)pOldFun + hLen;
				unsigned char code = tNow[0];
				if (code % 2 == 0 && code >= (unsigned char)0x3E && code < (unsigned char)0x50)
				{

					//PMDL pMdl = 0; 
					//char * pAr = LoadMemoryToUser(&pMdl, tNow, arry[i], KernelMode, PAGE_EXECUTE_READWRITE);
					//if (pAr != 0)
					//{
						LOG_DEBUG("run Far len [%d]  <%p>\n", gLen, pNow);
						hLenI++;
						//	KIRQL irql = WPOFFx64();
						RtlCopyMemory(&Offset, tNow + 3, sizeof(LONG));
						LOG_DEBUG("run Far len [%d]\n", __LINE__);
						RtlCopyMemory(pNow, tNow, arry[i]);
						//pCode[nSize + hLenI] = (ULONGLONG)tNow + (ULONG)Offset + 7;

						LOG_DEBUG("run Far len [%d]\n", __LINE__);
						RtlCopyMemory(&pCode[nSize + hLenI], (PVOID)((ULONGLONG)tNow + Offset + 7), 8);
						LOG_DEBUG("run Far len [%d]\n", __LINE__);
						LONG size = (LONG)(((ULONGLONG)&pCode[nSize + hLenI]) - (ULONGLONG)(pNow)-7);
						RtlCopyMemory(pNow + 3, &size, sizeof(LONG));
						LOG_DEBUG("run Far len [%d]\n", __LINE__);

						//	WPONx64(irql);


						//MmUnmapLockedPages(pAr, pMdl);
						//IoFreeMdl(pMdl);

						hLen += arry[i];
						pNow += arry[i];

						continue;

				//	}



				}
			}
			if (arry[i] == 5)
			{
				tNow = (char*)pOldFun + hLen;
				unsigned char code = tNow[0];

				if (code == (unsigned char)0xE9)
				{
					//KIRQL irql = WPOFFx64();
					RtlCopyMemory(&Offset, ((char*)tNow + 1), sizeof(LONG));
					pCode[nSize] = (ULONGLONG)(tNow + Offset + 5);
					//WPONx64(irql);
					break;
					//  遭遇 JMP 跳转就结束吧
				}


			}
			//KIRQL irql = WPOFFx64();
			RtlCopyMemory(pNow, ((char*)pOldFun + hLen), arry[i]);
			//WPONx64(irql);
			hLen += arry[i];
			pNow += arry[i];
		}

		Round_SSDT += ((nSize + hLenI + 2) * 8);

		//irql = WPOFFx64();

		// 跳回原始的地址
		char* uJMP = pNow;
		uJMP[0] = (char)0x48;
		uJMP[1] = (char)0xFF;
		uJMP[2] = (char)0x25;
		LONG  kOffset = (LONG)((LONGLONG)&pCode[nSize] - (LONGLONG)&uJMP[0] - 7);
		RtlCopyMemory(&uJMP[3], &kOffset, 4);
		//*((DWORD64*)&uJMP[3]) = ;





		ULONGLONG pFUN_OLD = ((ULONGLONG)pOldFun) & 0xFFFFFFFFFFFFF000;
		ULONG nLong = ((ULONGLONG)pOldFun) & 0xFFF;

		PMDL pMdl = 0;
		PVOID pADR = LoadMemoryToUser(&pMdl, (PVOID)pFUN_OLD, PAGE_SIZE, KernelMode, PAGE_EXECUTE_READWRITE);

		if (pADR != 0)
		{
			if (maxCodeLen >= 15 && newOffsetNo == 0)
			{
				char JPE[15] = { 0 };
				JPE[0] = (char)0x48;
				JPE[1] = (char)0xFF;
				JPE[2] = (char)0x25;
				//*((INT*)&JPE[3]) = 0;

				kOffset = 0;
				RtlCopyMemory(&JPE[3], &kOffset, 4);
				//*((DWORD64*)&JPE[7]) = NewFun;
				RtlCopyMemory(&JPE[7], &pNewFun, 8);
				RtlCopyMemory((char *)pADR + nLong, &JPE[0], 15);

			}
			else
			{
				char JPE[15] = { 0 };
				JPE[0] = (char)0x48;
				JPE[1] = (char)0xFF;
				JPE[2] = (char)0x25;
				//*((INT*)&JPE[3]) = 0;

				kOffset = newOffsetNo - 7;
				RtlCopyMemory(&JPE[3], &kOffset, 4);
				
				


				ULONGLONG pFUN_OLD_0 = ((ULONGLONG)pOldFun + newOffsetNo) & 0xFFFFFFFFFFFFF000;
				ULONG nLong_0 = ((ULONGLONG)pOldFun + newOffsetNo) & 0xFFF;

				PMDL pMdl0 = 0;
				PVOID pADRA = LoadMemoryToUser(&pMdl0, (PVOID)pFUN_OLD_0, PAGE_SIZE, KernelMode, PAGE_EXECUTE_READWRITE);
				if (pADRA != 0)
				{
					
					//LOG_DEBUG("%d\n", __LINE__);
					//_disable();
					RtlCopyMemory((char*)pADRA + nLong_0, &pNewFun, 8);
					RtlCopyMemory((char*)pADR + nLong, &JPE[0], maxCodeLen);
					//_enable();

					MmUnmapLockedPages(pADRA, pMdl0);
					IoFreeMdl(pMdl0);
				}
				else
				{
					LOG_DEBUG("Can't Lock Memory\n");
				}
				

				
			}
			//LOG_DEBUG("%d\n", __LINE__);
			MmUnmapLockedPages(pADR, pMdl);
			IoFreeMdl(pMdl);
		}
		else
		{
			LOG_DEBUG("error LoadMemoryToUser\n");
		}


		//WPONx64(irql);
		LOG_DEBUG("hook 0 < %p >  <%p> newfun <%p>\n", pNow, pOldFun, NewFun);

		return TRUE;

	}
	__except (1) {

		LOG_DEBUG("__except  %s %08X\n", __FUNCTION__, GetExceptionCode());

	}
	return FALSE;
}


typedef struct _REPROTECT_CONTEXT
{
	PMDL   Mdl;
	PUCHAR LockedVa;
} REPROTECT_CONTEXT, * PREPROTECT_CONTEXT;


NTSTATUS
MmLockVaForWrite(
	__in PVOID Va,
	__in ULONG Length,
	__out PREPROTECT_CONTEXT ReprotectContext
)
{
	NTSTATUS Status;

	Status = STATUS_SUCCESS;

	ReprotectContext->Mdl = 0;
	ReprotectContext->LockedVa = 0;

	ReprotectContext->Mdl = IoAllocateMdl(
		Va,
		Length,
		FALSE,
		FALSE,
		0
	);

	if (!ReprotectContext->Mdl)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//  
	// Retrieve a locked VA mapping.  
	//  

	__try
	{
		MmProbeAndLockPages(
			ReprotectContext->Mdl,
			KernelMode,
			IoModifyAccess
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}

	ReprotectContext->LockedVa = (PUCHAR)MmMapLockedPagesSpecifyCache(
		ReprotectContext->Mdl,
		KernelMode,
		MmCached,
		0,
		FALSE,
		NormalPagePriority
	);

	if (!ReprotectContext->LockedVa)
	{


		IoFreeMdl(
			ReprotectContext->Mdl
		);

		ReprotectContext->Mdl = 0;

		return STATUS_ACCESS_VIOLATION;
	}

	//  
	// Reprotect.  
	//  

	Status = MmProtectMdlSystemAddress(
		ReprotectContext->Mdl,
		PAGE_EXECUTE_READWRITE
	);

	if (!NT_SUCCESS(Status))
	{


		MmUnmapLockedPages(
			ReprotectContext->LockedVa,
			ReprotectContext->Mdl
		);
		MmUnlockPages(
			ReprotectContext->Mdl
		);
		IoFreeMdl(
			ReprotectContext->Mdl
		);

		ReprotectContext->LockedVa = 0;
		ReprotectContext->Mdl = 0;
	}

	return Status;
}

NTSTATUS
MmUnlockVaForWrite(
	__in PREPROTECT_CONTEXT ReprotectContext
)
{
	if (ReprotectContext->LockedVa)
	{
		MmUnmapLockedPages(
			ReprotectContext->LockedVa,
			ReprotectContext->Mdl
		);
		MmUnlockPages(
			ReprotectContext->Mdl
		);
		IoFreeMdl(
			ReprotectContext->Mdl
		);

		ReprotectContext->LockedVa = 0;
		ReprotectContext->Mdl = 0;
	}

	return STATUS_SUCCESS;
}







//BOOLEAN WriteSafePoiner(PVOID , PVOID )



extern BOOLEAN writeSafeMemory(PVOID adr, PVOID val, DWORD valSize);



BOOLEAN  SSDT_HOOK_SHOW_NOW(PVOID pNewFun, PVOID pOldFun, PVOID CALLFUN, BOOLEAN bWrite, PVOID SingleMemory) {


	//MiSingleProcessMemory(IoGetCurrentProcess(), (DWORD64)pOldFun & 0xFFFFFFFFFFFFF000, PAGE_SIZE);

	//return FALSE;
	__try {
		LONGLONG pFun = (LONGLONG)pOldFun;
		LONGLONG NewFun = (LONGLONG)pNewFun;
		LONG Offset = 0;
		char* NowPtr = (char*)pOldFun;


		__invlpg(pOldFun);
		__invlpg(SingleMemory);

		//if (/*NowPtr[0] == (char)0x48  &&*/
		//	NowPtr[0] == (char)0xFF && 
		//	NowPtr[1] == (char)0x25)
		//{
		//	LOG_DEBUG("Logdebug   %p  real HOOK 0\n", pOldFun);

		//	return FALSE;
		//}

		//if (NowPtr[0] == (char)0x48  &&
		//	NowPtr[1] == (char)0xFF &&
		//	NowPtr[2] == (char)0x25)
		//{
		//	LOG_DEBUG("Logdebug   %p  real HOOK 1\n", pOldFun);
		//	return FALSE;
		//}


		//if (/*NowPtr[0] == (char)0x48  &&*/
		//	NowPtr[0] == (char)0x50 &&
		//	NowPtr[1] == (char)0x48 &&
		//	NowPtr[2] == (char)0xB8)
		//{
		//	LOG_DEBUG("Logdebug   %p  real HOOK 2 \n", pOldFun);
		//	return FALSE;
		//}


		int gLen = 0;
		int bLen = 0;

		int arry[20];
		RtlZeroMemory(&arry[0], 20 * 4);
		int bi = 0;


		//ULONGLONG BeginText = (ULONGLONG)kernelBase + _Begin_TEXT;
		//ULONGLONG EndText = (ULONGLONG)kernelBase + _Begin_TEXT + _Lenth_TEXT;


		int maxCodeLen = 14;
		int newOffsetNo = 0;

	//	KIRQL irql = WPOFFx64();
		char* pNewAz = pOldFun;
		//for (int i = 0; i < 0x500; i++)
		//{
		//	DWORD64 hg = 0;

		//	//ULONGLONG uAddress = (ULONGLONG)pNewAz + i;
		//	//if (!(uAddress >= BeginText && uAddress < EndText))
		//	//{
		//	//	break;
		//	//}

		//	RtlCopyMemory(&hg, pNewAz + i, sizeof(DWORD64));
		//	if (hg == 0xCCCCCCCCCCCCCCCC &&
		//		(((ULONGLONG)(pNewAz + i)) % 0x1000 != 0) &&
		//		(((ULONGLONG)(pNewAz + i)) % 0x8 == 0))
		//	{
		//		maxCodeLen = maxCodeLen - 8;
		//		newOffsetNo = i;
		//		break;
		//	}

		//}
		//WPONx64(irql);



		//STATUS_ABANDON_HIBERFILE

		while (gLen < maxCodeLen)
		{
			bLen = DetourGetInstructionLength(NowPtr + gLen);
			arry[bi] = bLen;
			gLen += bLen;
			bi++;
			if (bLen == 0)
			{
				return FALSE;
			}
		}
		//return 0;



		LOG_DEBUG("HOOK_LEN ID [%d]\n", gLen);

		if (Round_ShaShow == 0)
		{
			return FALSE;
		}

		char* pNow = Round_ShaShow;
		LOG_DEBUG("New Fun [%d]  <%p>\n", gLen, pNow);

		*((PULONGLONG)CALLFUN) = (ULONGLONG)pNow;
		LONG nSize = ((gLen + 7) / 8) + 1;
		LONGLONG* pCode = (LONGLONG*)pNow;
		//irql = WPOFFx64();

		memset(pNow, 0xCC, (nSize + 2) * 8);
		//RtlZeroMemory()
		pCode[nSize] = (LONGLONG)pOldFun + gLen;

		//WPONx64(irql);
		// 8字节对齐 // 倒数字节用于
		int hLen = 0;

		unsigned char* tNow = 0;

		int hLenI = 0;



		for (size_t i = 0; i < 20; i++)
		{
			if (arry[i] == 0)
			{
				break;
			}
			if (arry[i] == 7)
			{
				tNow = (char*)pOldFun + hLen;
				unsigned char code = tNow[0];

				if (code % 2 == 0 && code >= (unsigned char)0x3E && code < (unsigned char)0x50)
				{
					if (tNow[0] == (char)0x48 && tNow[1] == (char)0xFF && tNow[2] == (char)0x25)
					{
						RtlCopyMemory(&Offset, ((char*)tNow + 3), sizeof(LONG));
						pCode[nSize] = (LONGLONG)(tNow + Offset + 7);
						break;
					}

					LOG_DEBUG("run Far len [%d]  <%p>\n", gLen, pNow);

					hLenI++;

					RtlCopyMemory(&Offset, ((char*)tNow + 3), sizeof(LONG));				
					
					RtlCopyMemory(pNow, ((char*)pOldFun + hLen), arry[i]);
					
					RtlCopyMemory(&pCode[nSize + hLenI], (PVOID)((ULONGLONG)tNow + Offset + 7), 8);

					LOG_DEBUG("Value  Address   %p   %p   %p \n", (ULONGLONG)tNow + Offset + 7, pCode[nSize + hLenI], &pCode[nSize + hLenI]);
					LONG size = (LONG)(((ULONGLONG)&pCode[nSize + hLenI]) - (ULONGLONG)(pNow)-7); // - arry[i]
					RtlCopyMemory(pNow + 3, &size, sizeof(LONG));
					//LOG_DEBUG("run Far len [%d]\n", __LINE__);

					//WPONx64(irql);

					hLen += arry[i];
					pNow += arry[i];

					continue;
				}
			}

			if (arry[i] == 5)
			{
				tNow = (char*)pOldFun + hLen;
				unsigned char code = tNow[0];

				if (code == (unsigned char)0xE9)
				{
					//KIRQL irql = WPOFFx64();
					RtlCopyMemory(&Offset, ((char*)tNow + 1), sizeof(LONG));
					pCode[nSize] = (LONGLONG)(tNow + Offset + 5);
					//WPONx64(irql);
					break;
					//  遭遇 JMP 跳转就结束吧
				}


			}
			if (arry[i] == 6)
			{
				// 遭遇JMP 跳转就结束
				tNow = (char*)pOldFun + hLen;
				if (tNow[0] == (char)0xFF && tNow[1] == (char)0x25)
				{
					//KIRQL irql = WPOFFx64();
					RtlCopyMemory(&Offset, ((char*)tNow + 2), sizeof(LONG));
					pCode[nSize] = (LONGLONG)(tNow + Offset + 6);
					//WPONx64(irql);
					break;
				}

			}

			//KIRQL irql = WPOFFx64();
			RtlCopyMemory(pNow, ((char*)pOldFun + hLen), arry[i]);
			//WPONx64(irql);
			hLen += arry[i];
			pNow += arry[i];
		}

		Round_ShaShow += ((nSize + hLenI + 2) * 8);


		//irql = WPOFFx64();


		// 跳回原始的地址
		char* uJMP = pNow;

		uJMP[0] = (char)0x48;
		uJMP[1] = (char)0xFF;
		uJMP[2] = (char)0x25;
		LONG  kOffset = (LONG)((LONGLONG)&pCode[nSize] - (LONGLONG)&uJMP[0] - 7);
		RtlCopyMemory(&uJMP[3], &kOffset, 4);
		//*((DWORD64*)&uJMP[3]) = ;


		if (!bWrite)
		{
			ULONGLONG pFUN_OLD = ((ULONGLONG)pOldFun) & 0xFFFFFFFFFFFFF000;
			ULONG nLong = ((ULONGLONG)pOldFun) & 0xFFF;

			PMDL pMdl = 0;
			PVOID pADR = LoadMemoryToUser(&pMdl, (PVOID)pFUN_OLD, PAGE_SIZE, KernelMode, PAGE_EXECUTE_READWRITE);

			if (pADR != 0)
			{
				if (maxCodeLen >= 14 && newOffsetNo == 0)
				{
					char JPE[15] = { 0 };

					//char JPE[14] = { 0 };

					//JPE[0] = (char)0x48;
					//JPE[1] = (char)0xFF;
					//JPE[2] = (char)0x25;
					//kOffset = 0;
					//RtlCopyMemory(&JPE[3], &kOffset, 4);
					//RtlCopyMemory(&JPE[7], &pNewFun, 8);
					//RtlCopyMemory((char*)pADR + nLong, &JPE[0], 15);

					JPE[0] = (char)0xFF;
					JPE[1] = (char)0x25;
					kOffset = 0;
					RtlCopyMemory(&JPE[2], &kOffset, 4);
					RtlCopyMemory(&JPE[6], &pNewFun, 8);
					RtlCopyMemory((char*)pADR + nLong, &JPE[0], 14);

					//*((DWORD64*)&JPE[7]) = NewFun;

					//KeLowerIrql(Irql);
					//RtlCopyMemory(&JPE[2], &kOffset, 4);
					////*((DWORD64*)&JPE[7]) = NewFun;
					//RtlCopyMemory(&JPE[6], &pNewFun, 8);
					//RtlCopyMemory((char*)pADR + nLong, &JPE[0], 14);

				}
				else
				{
					char JPE[15] = { 0 };
					JPE[0] = (char)0x48;
					JPE[1] = (char)0xFF;
					JPE[2] = (char)0x25;
					//*((INT*)&JPE[3]) = 0;

					kOffset = newOffsetNo - 7;
					RtlCopyMemory(&JPE[3], &kOffset, 4);

					ULONGLONG pFUN_OLD_0 = ((ULONGLONG)pOldFun + newOffsetNo) & 0xFFFFFFFFFFFFF000;
					ULONG nLong_0 = ((ULONGLONG)pOldFun + newOffsetNo) & 0xFFF;

					PMDL pMdl0 = 0;
					PVOID pADRA = LoadMemoryToUser(&pMdl0, (PVOID)pFUN_OLD_0, PAGE_SIZE, KernelMode, PAGE_EXECUTE_READWRITE);
					if (pADRA != 0)
					{
						RtlCopyMemory((char*)pADRA + nLong_0, &pNewFun, 8);
						RtlCopyMemory((char*)pADR + nLong, &JPE[0], maxCodeLen);


						LOG_DEBUG("%d\n", __LINE__);
						MmUnmapLockedPages(pADRA, pMdl0);
						IoFreeMdl(pMdl0);
						//LOG_DEBUG("%d\n", __LINE__);
					}
					else
					{
						LOG_DEBUG("Can't Lock Memory\n");
					}



				}
				LOG_DEBUG("%d\n", __LINE__);
				MmUnmapLockedPages(pADR, pMdl);
				IoFreeMdl(pMdl);
			}
			else
			{
				LOG_DEBUG("error LoadMemoryToUser\n");
			}
			LOG_DEBUG("hook 0 < %p >  <%p> newfun <%p>\n", pNow, pOldFun, NewFun);
		}
		else
		{
			char JPE[15] = { 0x90 };

			//JPE[0] = (char)0xFF;
			//JPE[1] = (char)0x25;
			//kOffset = 0;
			//RtlCopyMemory(&JPE[2], &kOffset, 4);
			//RtlCopyMemory(&JPE[6], &pNewFun, 8);
			////RtlCopyMemory(SingleMemory, &JPE[0], 14);
			//writeSafeMemory(pOldFun, JPE, 14);

			//LOG_DEBUG("LogDebug Old Fun<%p> \n", pOldFun);

			char* uJMP = Round_ShaShow;
			Round_ShaShow += 0x20;

			uJMP[0] = (char)0x58;
			uJMP[1] = (char)0x48;
			uJMP[2] = (char)0xFF;
			uJMP[3] = (char)0x25;
			LONG  kOffset = 0;
			RtlCopyMemory(&uJMP[4], &kOffset, 4);
			RtlCopyMemory(&uJMP[8], &pNewFun, 8);


			JPE[0] = (char)0x50;
			JPE[1] = (char)0x48;
			JPE[2] = (char)0xb8;
			RtlCopyMemory(&JPE[3], &uJMP, 8);
			JPE[11] = 0xFF;
			JPE[12] = 0xE0;
			//__wbinvd();
		

			//KIRQL irql = KzRaiseIrql(HIGH_LEVEL);

			__invlpg(pOldFun);
			__invlpg(SingleMemory);

			////RtlCopyMemory(SingleMemory, &JPE[0], 13);
			//char* SingleEx = SingleMemory;
			//for (size_t i = 0; i < 13; i++){
			//	SingleEx[i] = JPE[i];
			//}
			//__invlpg(pOldFun);
			//__invlpg(SingleMemory);
			//__wbinvd();
			//KeLowerIrql(irql);

			writeSafeMemory(pOldFun, JPE, 13);
			__invlpg(pOldFun);
			__invlpg(SingleMemory);
			__wbinvd();

		}
	}
	__except (1) {

		LOG_DEBUG("__except  %s %08X\n", __FUNCTION__, GetExceptionCode());

		return FALSE;
	}
	return TRUE;

}






BOOLEAN SSDT_Initialization_HOOK(int SSDT_TYPE) {


    PsGetVersion(NULL, NULL, &BuildNumber, NULL);
	bRunIAT = 0;
	if (BuildNumber >= 7600 && BuildNumber < 9200)
	{
		bRunIAT = 1;
	}
	else
	{
		bRunIAT = 0;
	}


	PSYSTEM_SERVICE_TABLE pTable = NULL;
	char * Round = NULL;
	JMPEX * JmpArry = NULL;




	if (SSDT_TYPE == HOOK_SSDT) {

		pTable = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable();
		if (pTable == NULL) {
			//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			//	"SSDT_Initialization_HOOK FALSE   getKeServiceDescriptorTable == NULL\n");
			return FALSE;
		}
		if (Round_SSDT != 0) {
			return TRUE;
		}
		char * Round_SSDTw = ExAllocatePoolWithTag(NonPagedPool, 10 * PAGE_SIZE,'tag');

		if (Round_SSDTw == NULL)
		{
		   return FALSE;
		}

		Round_SSDT = LoadMoudleMem(Round_SSDTw, 10 * PAGE_SIZE);
		if (Round_SSDT == NULL)
		{

			LOG_DEBUG("LoadMoudleMem error\n");
		    ExFreePoolWithTag(Round_SSDTw,'tag');
		    return  FALSE;
		}

		//设置为可读可写可执行
		// 开始设置
		SSDT_NumberOfServices = pTable->NumberOfServices;
		b_SSDTHOOK = TRUE;
		OLD_TABLEBASE = (PULONG)pTable->ServiceTableBase;
		SSDTJmpArry = (JMPEX *)(Round_SSDT + (SSDT_NumberOfServices * sizeof(ULONG)));
		JmpArry = SSDTJmpArry;
		Round = Round_SSDT;
		// sizeof(JMPEX)


		ULONGLONG numberOf = pTable->NumberOfServices;
		PULONG TableBase = (PULONG)pTable->ServiceTableBase;
		PULONG new_TableBase = (PULONG)Round;
		for (ULONG i = 0; i < numberOf; i++) {

			ULONG OLD_APP = TableBase[i];
		
		ULONG new_SSDT =
				GetOffsetAddress((ULONGLONG)new_TableBase, (ULONGLONG)&JmpArry[i],
					OLD_APP & 0x0000000F);
		
		ULONGLONG OLD_ADDRESS = GetSSDTFuncCurrentAddr(pTable, i);

			//OLD_SSDT_ADDRESS[i] = OLD_ADDRESS;
		
		 //   if (bRunIAT == 1)
			//{
			//	KIRQL irql = WPOFFx64();
			//	new_TableBase[i] = new_SSDT;
			//	JmpArry[i].A[0] = 0xFF;
			//	JmpArry[i].A[1] = 0x25;
			//	JmpArry[i].Pointer = 0;
			//	JmpArry[i].P_new_SSDT = OLD_ADDRESS;
			//	WPONx64(irql);
			//}


		}


		//PSYSTEM_SERVICE_TABLE pTable2 = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable2();

		//if (bRunIAT == 1)
		//{
		//	OLD_TABLEBASE = pTable->ServiceTableBase;
		//	KIRQL irql = WPOFFx64();

		//	pTable->ServiceTableBase = (PVOID)new_TableBase;
		//	//pTable2->ServiceTableBase = (PVOID)new_TableBase;
		//	WPONx64(irql);
		//}



	}
	else if (SSDT_TYPE == HOOK_SSDTSHOW) {


		pTable = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTableShow();
		if (pTable == NULL) {
			//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			//	"SSDT_Initialization_HOOK FALSE   getKeServiceDescriptorTableShow == NULL\n");

			return FALSE;
		}
		if (Round_ShaShow != NULL) {
			//DbgPrintEx(
			//	DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			//	"HOOK_SSDTSHOW FALSE ： ServiceTableBase == ALL  HOOK\n");
			return TRUE;
		}

		//Round_ShaShow = (char *)&m_MmGroundShow;


		char * Round_ShaShowW = ExAllocatePoolWithTag(NonPagedPool, 10 * PAGE_SIZE, 'tag');
		if (Round_ShaShowW == NULL)
		{
		    return FALSE;
		}
		Round_ShaShow = LoadMoudleMem(Round_ShaShowW, 10 * PAGE_SIZE);
		if (Round_ShaShow == NULL)
		{
		    ExFreePoolWithTag(Round_ShaShowW, 'tag');
			return  FALSE;
		}



		SSDTSHOW_NumberOfServices = pTable->NumberOfServices;
		b_SSDTSHOWHOOK = TRUE;
		OLD_SHOW_TABLEBASE = (PULONG)pTable->ServiceTableBase;
		SSDTSHOWJmpArry = (JMPEX *)(Round_ShaShow + (SSDTSHOW_NumberOfServices * sizeof(ULONG)));
		JmpArry = SSDTSHOWJmpArry;
		Round = Round_ShaShow;


		ULONGLONG numberOf = pTable->NumberOfServices;
		PULONG TableBase = (PULONG)pTable->ServiceTableBase;

		LOG_DEBUG("TableBase  <  %p > < %p >  <%p>\n",pTable,TableBase,pTable->NumberOfServices);

		PULONG new_TableBase = (PULONG)Round;


		for (ULONG i = 0; i < numberOf; i++) {
			ULONG OLD_APP = TableBase[i];
			ULONG new_SSDT = GetOffsetAddress((ULONGLONG)new_TableBase, (ULONGLONG)&JmpArry[i],
					OLD_APP & 0x0000000F);
			
			ULONGLONG OLD_ADDRESS = GetSSDTFuncCurrentAddr(pTable, i);

			OLD_SSDTSHOW_ADDRESS[i] = OLD_ADDRESS;
			
			if (bRunIAT == 1)
			{
				//KIRQL irql = WPOFFx64();
				new_TableBase[i] = new_SSDT;
				JmpArry[i].A[0] = 0xFF;
				JmpArry[i].A[1] = 0x25;
				JmpArry[i].Pointer = 0;
				JmpArry[i].P_new_SSDT = OLD_ADDRESS;
				//WPONx64(irql);
			}


		}

		if (bRunIAT == 1)
		{
			OLD_SHOW_TABLEBASE = pTable->ServiceTableBase;
			//KIRQL irql = WPOFFx64();
			pTable->ServiceTableBase = (PVOID)new_TableBase;
			//WPONx64(irql);
		}

		return TRUE;
	}
	else {
		//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
		//	"HOOK_SSDT UNKNOW FALSE ： ServiceTableBase == ALL  HOOK\n");
		return FALSE;

	}



    LOG_DEBUG("Table:%I64X\n", pTable);
	return TRUE;
}

BOOLEAN SSDT_HOOK(ULONG ID, PVOID pNewFun, PVOID pOldFun) {
	if (ID < SSDT_NumberOfServices)
	{
		//if (OLD_SSDT_ADDRESS[ID] == 0) {

		//	LOG_DEBUG(" 0== TableBase ID [%d] < %p >  <%p>\n", ID, pNewFun, pOldFun);
		//	return FALSE;
		//}
			//return FALSE;
		

		PSYSTEM_SERVICE_TABLE pTableSSDT = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable();
		if (pTableSSDT == NULL)
		{
			return FALSE;
		}
		PVOID OLD_ADDRESS = (PVOID)GetSSDTFuncCurrentAddr(pTableSSDT, ID);
		LOG_DEBUG("TableBase ID [%d] < %p >  <%p>\n", ID, pNewFun, pOldFun);
		return SSDT_HOOK_NOW(pNewFun, OLD_ADDRESS, pOldFun);

		//if (OLD_SSDT_ADDRESS[ID] == 0)
		//	return FALSE;
		//if (SSDTJmpArry == NULL)
		//	return FALSE;
		//KIRQL irql = WPOFFx64();
		//OLD_SSDT_ADDRESS[ID] = SSDTJmpArry[ID].P_new_SSDT;
		//SSDTJmpArry[ID].P_new_SSDT = (ULONGLONG)pNewFun;
		//WPONx64(irql);
		//*((PULONGLONG)pOldFun) = OLD_SSDT_ADDRESS[ID];
		//return TRUE;
	}
	return FALSE;
}

BOOLEAN SSDT_HOOKW(wchar_t * Pfun, PVOID pNewFun, PVOID pOldFun)
{
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, Pfun);
	ULONGLONG longAddress = (ULONGLONG)MmGetSystemRoutineAddress(&routineName);
	LOG_DEBUG("%ws  %I64X\n", Pfun, longAddress);
	if (longAddress != 0)
	{
		//for (auto i = 0; i < 4096; i++)
		//{
		//	if (OLD_SSDT_ADDRESS [i] == 0)
		//	{
		//		break;
		//	}
		//	if (longAddress == OLD_SSDT_ADDRESS[i])
		//	{
		//		LOG_DEBUG("%ws  %d\n", Pfun, i);
		//		SSDT_HOOK(i, pNewFun, pOldFun);
		//		return TRUE;
		//	}
		//}
		return SSDT_HOOK_NOW(pNewFun, (PVOID)longAddress, pOldFun);
	}
	return FALSE;
}




extern int NTAPI DetourGetInstructionLength(__in PVOID ControlPc);



typedef struct _HOOK_INFO
{
   int uType;
   PVOID OLD_KERNRL;
   PVOID NEW_KERNRL;
   char * OLD_CODE;
   INT * CODE_LEN;
}HOOK_INFO;




void GET_HOOK_INFO(PVOID pOldFun , HOOK_INFO * F) {

     int uType = 0;
     char * pTarget =(char *)pOldFun;
	 int len =  DetourGetInstructionLength(pOldFun);

	 LOG_DEBUG("DetourGetInstructionLength[%d] \n", len);
	 if (len == 7)
	 {
		 LOG_DEBUG("%02X  %02X   %02X\n", pTarget[0], pTarget[1], pTarget[2]);
		 if (pTarget[0] == (char)0x48 &&
			 pTarget[1] == (char)0xFF &&
			 pTarget[2] == (char)0x25)
		 {
			   uType = 1;
		 }
		 LOG_DEBUG("uType[%d] \n", uType);
	 }
	 if (len == 5) {
		 if (pTarget[0] == (char)0xE9){
			 uType = 2;
		 }
		 LOG_DEBUG("uType[%d] \n", uType);
	 }
	 F->uType = uType;
	 LOG_DEBUG("uType[%d] \n", F->uType);
}







BOOLEAN SSDT_SHOW_HOOK(ULONG ID, PVOID pNewFun, PVOID pOldFun)
{
  if (ID < SSDTSHOW_NumberOfServices)
  {
	  if (bRunIAT == 1)
	  {
		  if (OLD_SSDTSHOW_ADDRESS[ID] == 0)
			  return FALSE;
		  if (SSDTSHOWJmpArry == NULL)
			  return FALSE;
		  OLD_SSDTSHOW_ADDRESS[ID] = SSDTJmpArry[ID].P_new_SSDT;
		  SSDTJmpArry[ID].P_new_SSDT = (ULONGLONG)pNewFun;
		  *(PULONGLONG)pOldFun = OLD_SSDTSHOW_ADDRESS[ID];
		  return TRUE;
	  }
	  PSYSTEM_SERVICE_TABLE pTableSSDTSHOW = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTableShow();
	  if (pTableSSDTSHOW == NULL){
		  return FALSE;
	  }
	  PVOID OLD_ADDRESS = (PVOID)GetSSDTFuncCurrentAddr(pTableSSDTSHOW, ID);
	  return  SSDT_SHOW_HOOK_NOW_TYPE(pNewFun, OLD_ADDRESS, pOldFun, TRUE);
  }
  return FALSE;
}


BOOLEAN SSDT_SHOW_HOOKW(wchar_t * Pfun, PVOID pNewFun, PVOID pOldFun)
{
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, Pfun);
	ULONGLONG longAddress  = (ULONGLONG)MmGetSystemRoutineAddress(&routineName);
	LOG_DEBUG("%ws  %I64X\n", Pfun, longAddress);
	if (longAddress != 0)
	{
		LOG_DEBUG("TableBase longAddress [%p] pNewFun< %p > pOldFun <%p>\n", longAddress, pNewFun, pOldFun);
		return SSDT_SHOW_HOOK_NOW_TYPE(pNewFun, (PVOID)longAddress, pOldFun, TRUE);

	}
	return FALSE;
}

BOOLEAN SSDT_UNHOOK(ULONG ID) {
	//if (ID < SSDT_NumberOfServices)
	//{
	//	if (OLD_SSDT_ADDRESS[ID] == 0)
	//		return FALSE;
	//	if (SSDTJmpArry == NULL)
	//		return FALSE;
	//	KIRQL irql = WPOFFx64();
	//	SSDTJmpArry[ID].P_new_SSDT = OLD_SSDT_ADDRESS[ID];
 //        OLD_SSDT_ADDRESS[ID]=0;
	//	WPONx64(irql);
	//	return TRUE;
	//}
	return FALSE;
}

BOOLEAN SSDT_SHOW_UNHOOK(ULONG ID)
{
  if (ID < SSDTSHOW_NumberOfServices)
  {


  }
  return FALSE;
}

BOOLEAN SSDT_ISHOOK(int SSDT_STYLE)
{
  if (SSDT_STYLE == HOOK_SSDT)
  {
    return Round_SSDT ? TRUE :FALSE;
  }
  else if (SSDT_STYLE == HOOK_SSDTSHOW)
  {
    return Round_ShaShow ? TRUE : FALSE;
  }
  return FALSE;

}



void IniTable(int SSDT_TYPE, PSYSTEM_SERVICE_TABLE pTable)
{
  ULONGLONG numberOf = pTable->NumberOfServices;
  PULONG TableBase = (PULONG)pTable->ServiceTableBase;
  for (ULONG i = 0; i < numberOf; i++) {
    ULONGLONG OLD_ADDRESS = GetSSDTFuncCurrentAddr(pTable, i);

  }
}






//int getTableIndex(int SSDT_TYPE,char * FUN_NAME) {
//
//  int iR = -1;
//   // Windows7
//  if (BuildNumber >= 7600 && BuildNumber<9200)
//  {
//    if (SSDT_TYPE == HOOK_SSDT)
//    {
//
//      for (auto i = 0;i<2000;i++)
//      {
//          if (_stricmp(TableNameWin7[i], "End") == 0)
//          {
//             return iR;
//          }
//          if (_stricmp(TableNameWin7[i], FUN_NAME) == 0)
//          {
//            return i;
//          }
//      }
//    }
//    if (SSDT_TYPE == HOOK_SSDTSHOW)
//    {
//
//      for (auto i = 0; i < 2000; i++)
//      {
//        if (_stricmp(TableShowNameWin7[i], "End") == 0)
//        {
//          return iR;
//        }
//        if (_stricmp(TableShowNameWin7[i], FUN_NAME) == 0)
//        {
//          return i;
//        }
//      }
//    }
//
//  }
//  else if (BuildNumber > 10000) {
//
//    if (SSDT_TYPE == HOOK_SSDT)
//    {
//      for (auto i = 0; i < 2000; i++)
//      {
//        if (_stricmp(TableNameWin10[i], "End") == 0)
//        {
//          return iR;
//        }
//        if (_stricmp(TableNameWin10[i], FUN_NAME) == 0)
//        {
//          return i;
//        }
//      }
//    }
//    if (SSDT_TYPE == HOOK_SSDTSHOW)
//    {
//      for (auto i = 0; i < 2000; i++)
//      {
//        if (_stricmp(TableShowNameWin10[i], "End") == 0)
//        {
//          return iR;
//        }
//        if (_stricmp(TableShowNameWin10[i], FUN_NAME) == 0)
//        {
//          return i;
//        }
//      }
//    }
//  }
//  return iR;
//}

//ULONGLONG getTablePtr(int SSDT_TYPE, char * FUN_NAME) {
//
//  int Index = getTableIndex(SSDT_TYPE,FUN_NAME);
//  if (Index == -1)
//  {
//      return 0;
//  }
//  PSYSTEM_SERVICE_TABLE pTable = 0;
//  if (SSDT_TYPE == HOOK_SSDT)
//  {
//    pTable = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable();
//  }
//  else if (SSDT_TYPE == HOOK_SSDTSHOW) {
//
//    pTable = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTableShow();
//  }
//  else
//  {
//    pTable = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable();
//  }
//  return GetSSDTFuncCurrentAddr(pTable,Index);
//}

BOOLEAN SSDT_Initialization_HOOK2(int SSDT_STYLE)
{

  PsGetVersion(NULL, NULL, &BuildNumber, NULL);
  PSYSTEM_SERVICE_TABLE pTable = NULL;
  char * Round = NULL;
  JMPEX * JmpArry = NULL;
  if (SSDT_STYLE == HOOK_SSDT) {

    pTable = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable();
    if (pTable == NULL) {
      return FALSE;
    }
    if (Round_SSDT != 0) {
      return TRUE;
    }

	//NtQueryVirtualMemory()

    Round_SSDT = 0;

    //设置为可读可写可执行
    // 开始设置
    SSDT_NumberOfServices = pTable->NumberOfServices;
    b_SSDTHOOK = TRUE;
    OLD_TABLEBASE = (PULONG)pTable->ServiceTableBase;
    SSDTJmpArry = (JMPEX *)Round_SSDT;

  }
  else if (SSDT_STYLE == HOOK_SSDTSHOW) {
    pTable = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTableShow();
    if (pTable == NULL) {
      return FALSE;
    }

    if (Round_ShaShow != NULL) {
      return TRUE;
    }
    Round_ShaShow = 0;
    SSDTSHOW_NumberOfServices = pTable->NumberOfServices;
    b_SSDTSHOWHOOK = TRUE;
    OLD_SHOW_TABLEBASE = (PULONG)pTable->ServiceTableBase;
    SSDTSHOWJmpArry = (JMPEX *)Round_ShaShow;
  }
  else {
    return FALSE;

  }

  IniTable(SSDT_STYLE,pTable);

  LOG_DEBUG("Table:%I64X\n", pTable);
  return TRUE;
}

//BOOLEAN SSDT_HOOK2(char * FUN_NAME, PVOID pNewFun, PVOID pOldFun)
//{
//    int Index = getTableIndex(HOOK_SSDT,FUN_NAME);
//    if (Index == -1)
//    {
//      LOG_DEBUG("can't find fun\n");
//      return FALSE;
//    }
//
//    LOG_DEBUG("Index %d\n",Index);
//
//	return SSDT_HOOK3(Index,pNewFun,pOldFun);
//
//
// //   char * pFun = (char *)OLD_SSDT_ADDRESS[Index];
// //   LONG CodeSize = 0;
// //   do
// //   {
//
// //     long nSzie = DetourGetInstructionLength(pFun + CodeSize);
// //     CodeSize += nSzie;
//
// //   } while (CodeSize < 13);
//
// //   if (CodeSize > 23)
// //   {
// //     LOG_DEBUG("code too long\n");
// //     return FALSE;
// //   }
//
// //   JMPEX_IN * pJMP=(JMPEX_IN *)&m_MmGround;
// //   KIRQL irql = WPOFFx64();
// //   memset(&pJMP[Index].sg,0x90,24);
// //   pJMP[Index].A[0] = 0xFF;
// //   pJMP[Index].A[1] = 0x25;
// //   pJMP[Index].Pointer = 0;
// //   pJMP[Index].P_new_SSDT = OLD_SSDT_ADDRESS[Index] + CodeSize;
//
// //   RtlCopyMemory(&pJMP[Index].sg, pFun, CodeSize);
// //   WPONx64(irql);
// //   *((PULONGLONG)pOldFun) = (ULONGLONG)&pJMP[Index];
//
//
// //   LOG_DEBUG("Jmp Code %p  %p Size:%d \n", pJMP, &pJMP[Index], CodeSize);
//
// // //  return TRUE;
//
// //   JMPEX3 new_fun;
// //   new_fun.A[0] = 0x48;
// //   new_fun.A[1] = 0xB8;
// //   new_fun.P_new_SSDT = (ULONGLONG)pNewFun;
// //   new_fun.B[0] = 0xFF;
// //   new_fun.B[1] = 0xE0;
//
//
//	//irql = WPOFFx64();
//	//RtlCopyMemory(pFun, &new_fun, sizeof(new_fun));
//	//WPONx64(irql);
//
//
//    //return true;
//
//   //return HideMemory(pFun, sizeof(new_fun), (PVOID)&new_fun,NULL);
//
//  //  return TRUE;
//
//}

BOOLEAN SSDT_HOOK3(ULONG ID, PVOID pNewFun, PVOID pOldFun)
{
	//char * pFun = (char *)OLD_SSDT_ADDRESS[ID];
	//LONG CodeSize = 0;
	//do
	//{

	//	long nSzie = DetourGetInstructionLength(pFun + CodeSize);
	//	CodeSize += nSzie;

	//} while (CodeSize < 14);

	//if (CodeSize > 23)
	//{
	//	LOG_DEBUG("code too long\n");
	//	return FALSE;
	//}

	//JMPEX_IN * pJMP = 0;
	//KIRQL irql = WPOFFx64();
	//memset(&pJMP[ID].sg, 0x90, 24);
	//pJMP[ID].A[0] = 0xFF;
	//pJMP[ID].A[1] = 0x25;
	//pJMP[ID].Pointer = 0;
	//pJMP[ID].P_new_SSDT = OLD_SSDT_ADDRESS[ID] + CodeSize;
	//RtlCopyMemory(&pJMP[ID].sg, pFun, CodeSize);
	//WPONx64(irql);
	//*((PULONGLONG)pOldFun) = (ULONGLONG)&pJMP[ID];


	//LOG_DEBUG("Jmp Code %p  %p Size:%d \n", pJMP, &pJMP[ID], CodeSize);

	////  return TRUE;

	//JMPEX new_fun;
	//new_fun.A[0] = 0xFF;
	//new_fun.A[1] = 0x25;
	//new_fun.Pointer = 0;
	//new_fun.P_new_SSDT = (ULONGLONG)pNewFun;


	//irql = WPOFFx64();
	//RtlCopyMemory(pFun, &new_fun, sizeof(new_fun));
	//WPONx64(irql);


	//return true;

   //return HideMemory(pFun, sizeof(new_fun), (PVOID)&new_fun,NULL);

	return TRUE;
}

BOOLEAN SSDT_SHOW_HOOK2(ULONG ID, PVOID pNewFun, PVOID pOldFun)
{
	//char * pFun = (char *)OLD_SSDTSHOW_ADDRESS[ID];
	//LONG CodeSize = 0;
	//do
	//{

	//	long nSzie = DetourGetInstructionLength(pFun + CodeSize);
	//	CodeSize += nSzie;

	//} while (CodeSize < 14);

	//if (CodeSize > 23)
	//{
	//	LOG_DEBUG("code too long\n");
	//	return FALSE;
	//}


	//LOG_DEBUG("pFun %p \n", pFun);

	//JMPEX_IN * pJMP = 0;
	//KIRQL irql = WPOFFx64();
	//memset(&pJMP[ID].sg, 0x90, 24);
	//pJMP[ID].A[0] = 0xFF;
	//pJMP[ID].A[1] = 0x25;
	//pJMP[ID].Pointer = 0;
	//pJMP[ID].P_new_SSDT = OLD_SSDTSHOW_ADDRESS[ID] + CodeSize;
	//RtlCopyMemory(&pJMP[ID].sg, pFun, CodeSize);
	//WPONx64(irql);
	//*((PULONGLONG)pOldFun) = (ULONGLONG)&pJMP[ID];
	//LOG_DEBUG("Jmp Code %p  %p Size:%d \n", pJMP, &pJMP[ID], CodeSize);

	////  return TRUE;

	//JMPEX new_fun;
	//new_fun.A[0] = 0xFF;
	//new_fun.A[1] = 0x25;
	//new_fun.Pointer = 0;
	//new_fun.P_new_SSDT = (ULONGLONG)pNewFun;


	//irql = WPOFFx64();
	//RtlCopyMemory(pFun, &new_fun, sizeof(new_fun));
	//WPONx64(irql);

	return TRUE;
}

BOOLEAN SSDT_STOP_HOOK(int SSDT_STYLE)
{
	if (SSDT_STYLE & HOOK_SSDT)
	{
		PSYSTEM_SERVICE_TABLE pTable = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable();
		//PSYSTEM_SERVICE_TABLE pTable2 = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTable2();
		if (OLD_TABLEBASE && pTable /*&& pTable2*/) {
			pTable->ServiceTableBase = OLD_TABLEBASE;
			//pTable2->ServiceTableBase = OLD_TABLEBASE;
		}
	}
	if (SSDT_STYLE & HOOK_SSDTSHOW)
	{
		PSYSTEM_SERVICE_TABLE pTableShow = (PSYSTEM_SERVICE_TABLE)getKeServiceDescriptorTableShow();
		if (OLD_SHOW_TABLEBASE && pTableShow) {
			pTableShow->ServiceTableBase = OLD_SHOW_TABLEBASE;
		}
	}

	return TRUE;
}
