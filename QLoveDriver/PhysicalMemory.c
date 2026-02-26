#include "PhysicalMemory.h"
#include "PAGE_CR0_DISABLE.h"
#include "SSDT_NEW_FUN.h"

#define MEMORYDBG

#ifdef DEBUG
#ifdef MEMORYDBG
#define LOG_DEBUG(format,...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"[%d]" format,__LINE__, __VA_ARGS__);
#else
#define LOG_DEBUG(format,...) 
#endif // HOOKDBG
#else
#define LOG_DEBUG(format,...) //DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#endif



//#define PXE_BASE          PXE_BASE
//#define PXE_SELFMAP       0xFFFFF6FB7DBEDF68UI64
//#define PPE_BASE          0xFFFFF6FB7DA00000UI64
//#define PDE_BASE          0xFFFFF6FB40000000UI64
//#define PTE_BASE          0xFFFFF68000000000UI64

#define  _QWORD  DWORD64

DWORD * MiFlags = 0;
UCHAR* pPhysicalByte = 0;

extern DWORD64 PTE_BASE;
extern DWORD64 PDE_BASE;
extern DWORD64 PPE_BASE;
extern DWORD64 PXE_BASE;
extern DWORD64 PXE_SELFMAP;

typedef struct _PAGE_PVOID_PHY
{
	HANDLE dwPID;

	SIZE_T nPageSize;

	PHYSICAL_ADDRESS  PPE_PhyAdr;
	PHYSICAL_ADDRESS  PDE_PhyAdr;
	PHYSICAL_ADDRESS  PTE_PhyAdr;

	MMPTE* PPE_VA;
	MMPTE* PDE_VA;
	MMPTE* PTE_VA;

	MMPTE* PPE;
	MMPTE* PDE;
	MMPTE* PTE;

	MMPTE* SLECT_BASE;

	MMPTE PLM4[4];
	DWORD64 uPageNumber;//PTE pagenumber
	DWORD64 uBASE_ADDRESS;

	MMPTE uPTE;
}PAGE_PVOID_PHY;

KSPIN_LOCK SpinLock_MapPoiner = 0;

//DWORD64 PLM4[5] = { 0 };






















__int64 __fastcall MI_READ_PTE_LOCK_FREE(unsigned __int64 a1, PEPROCESS Process);


PVOID MapToPoiner(PHYSICAL_ADDRESS  phyAddress, SIZE_T PageSize, PAGE_PVOID_PHY* hMapPoiner);

PVOID UnMapToPoiner(PAGE_PVOID_PHY* hMapPoiner);




//MmProtectVirtualMemory
void KiFlushCurrentTbOnly() {
	KIRQL CurrentIrql = KeGetCurrentIrql();
	__writecr8(0xCui64);
	ULONGLONG Cr3 = __readcr3();
	__writecr3(Cr3);
	__writecr8(CurrentIrql);
}

// MmFreeContiguousMemory
PVOID NewPhyAddressPageSize() {
	PHYSICAL_ADDRESS Low = { 0 };
	PHYSICAL_ADDRESS High = { MAXULONG64 };
	PVOID TempPage = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Low, High, Low, MmCached);
	return TempPage;
}

BOOLEAN ReadPhysicalAddress(PHYSICAL_ADDRESS BaseAddress, PVOID Val, DWORD nSize) {

	PAGE_PVOID_PHY MapTpPoiner = { 0 };
	DWORD uPageSzie = (((BaseAddress.QuadPart & 0xFFF) + nSize) / PAGE_SIZE) + 1;
	volatile PVOID Buffer = MapToPoiner(BaseAddress, uPageSzie, &MapTpPoiner);
	if (Buffer == 0)
	{
		LOG_DEBUG("ReadPhysicalAddress Can't MapToPoiner \n");
		return FALSE;
	}
	__try{
		RtlCopyMemory(Val, (PVOID)((DWORD64)Buffer + (BaseAddress.QuadPart & 0xFFF)), nSize);
	}
	__except (1) {
		LOG_DEBUG("__except ReadPhysicalAddress %08X \n", GetExceptionCode());
    }
	//LOG_DEBUG("VA  <%p>  %d\n", ((DWORD64)Buffer + (BaseAddress.QuadPart & 0xFFF)), uPageSzie);
	UnMapToPoiner(&MapTpPoiner);
	return TRUE;
}



BOOLEAN WritePhysicalAddress(PHYSICAL_ADDRESS BaseAddress, PVOID Val, DWORD nSize) {
	PAGE_PVOID_PHY MapTpPoiner = { 0 };
	DWORD uPageSzie = (((BaseAddress.QuadPart & 0xFFF) + nSize) / PAGE_SIZE) + 1;
	volatile PVOID Buffer = MapToPoiner(BaseAddress, uPageSzie, &MapTpPoiner);
	if (Buffer == 0)
	{
		LOG_DEBUG("WritePhysicalAddress Can't MapToPoiner \n");
		return FALSE;
	}
	__try {
		RtlCopyMemory((PVOID)((DWORD64)Buffer + (BaseAddress.QuadPart & 0xFFF)), Val, nSize);
	}
	__except (1) {
		LOG_DEBUG("__except WritePhysicalAddress %08X \n", GetExceptionCode());
	}
	UnMapToPoiner(&MapTpPoiner);
	return TRUE;
}






//BOOLEAN ReadPhysicalMemory2(PHYSICAL_ADDRESS pPhysicalAddress, PVOID oVirtualAddress, UINT_PTR nSize)
//{
//	if (ReadPhysicalAddress(pPhysicalAddress, oVirtualAddress, nSize))
//	{
//		LOG_DEBUG("ReadPhysicalAddress SUCESS\n");
//		return TRUE;
//	}
//	HANDLE hPhysical = 0;
//	OBJECT_ATTRIBUTES attributes;
//	UNICODE_STRING physmemString;
//	RtlInitUnicodeString(&physmemString, L"\\device\\physicalmemory");
//	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);
//	if (!NT_SUCCESS(ZwOpenSection(&hPhysical, SECTION_ALL_ACCESS, &attributes)))
//	{
//		return FALSE;
//	}
//	PVOID BaseAddress = 0;
//	LOG_DEBUG("Handle  %I64X\n", hPhysical);
//	DWORD bSize = ((nSize / PAGE_SIZE) + 2) * PAGE_SIZE;
//
//
//	PHYSICAL_ADDRESS pPhyBegin;
//	pPhyBegin.QuadPart = pPhysicalAddress.QuadPart;
//
//	//SIZE_T offset = 0xFFF & pPhysicalAddress.QuadPart;
//
//	NTSTATUS ntStatus = ZwMapViewOfSection(
//		hPhysical,  //sectionhandle
//		NtCurrentProcess(), //processhandle (should be -1)
//		&BaseAddress, //BaseAddress
//		0L, //ZeroBits
//		bSize, //CommitSize
//		&pPhyBegin, //SectionOffset
//		&bSize, //ViewSize
//		ViewShare,
//		0,
//		PAGE_READWRITE);
//
//	if (!NT_SUCCESS(ntStatus))
//	{
//		LOG_DEBUG("error ZwMapViewOfSection  %08X\n", ntStatus);
//		ZwClose(hPhysical);
//		//STATUS_ABANDONED
//		return FALSE;
//	}
//
//	if (BaseAddress == 0)
//	{
//		LOG_DEBUG("BaseAddress==0  %08X\n", ntStatus);
//		//ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
//		//STATUS_ABANDON_HIBERFILE
//		ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
//		ZwClose(hPhysical);
//		return FALSE;;
//	}
//	SIZE_T offset = pPhysicalAddress.QuadPart - pPhyBegin.QuadPart;
//	LOG_DEBUG("BaseAddress  %I64X  %I64X   %I64X  %08X\n", BaseAddress, pPhysicalAddress.QuadPart, pPhyBegin.QuadPart, nSize);
//	__try {
//		if (nSize + offset <= bSize){
//			RtlCopyMemory(oVirtualAddress , (UCHAR*)BaseAddress + offset, nSize);
//		}
//	}
//	__except (1) {
//		LOG_DEBUG("__except %s %08X\n", __FUNCTION__, GetExceptionCode());
//	}
//	ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
//	ZwClose(hPhysical);
//	return TRUE;
//}

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PTI_MASK_AMD64 (PTE_PER_PAGE - 1)
#define PDI_MASK_AMD64 (PDE_PER_PAGE - 1)
#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define PTE_SHIFT 3

#define MiGetPxeOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PXI_SHIFT) & PXI_MASK))
#define MiGetPteAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))
#define MiGetPdeAddress(va)  \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + PDE_BASE))
#define MiGetPpeAddress(va)   \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + PPE_BASE))
#define MiGetPxeAddress(va)   ((PMMPTE)PXE_BASE + MiGetPxeOffset(va))







//typedef struct _MAPINFO {
//	DWORD64 virtual;
//}MAPINFO;
// 物理页面像PAGE_SIZE 向下取整


DWORD GetUserPage(DWORD64 Base) {
	DWORD nOffset = 0;
	__try {
		for (int i = 0; i < PTE_PER_PAGE; i++)
		{
			DWORD64 MMTP = *((DWORD64*)(Base + i * 8));
			if (MMTP != 0){
				return i;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 0x200;
	}
	return 0x200;
}








BOOLEAN ExAllocateMapPoinerEx(PAGE_PVOID_PHY * hMapPoiner) {

	PVOID PAGE_PTE = NewPhyAddressPageSize();  //ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 3, 'tag');
	PVOID PAGE_PDE = NewPhyAddressPageSize();
	PVOID PAGE_PPE = NewPhyAddressPageSize();
	//NewPhyAddressPageSize
	if (PAGE_PTE == 0 || PAGE_PDE == 0 || PAGE_PPE == 0)
	{
		if (PAGE_PTE != 0)MmFreeContiguousMemory(PAGE_PTE);
		if (PAGE_PDE != 0)MmFreeContiguousMemory(PAGE_PDE);
		if (PAGE_PPE != 0)MmFreeContiguousMemory(PAGE_PPE);
		return FALSE;
	}
	RtlZeroMemory(PAGE_PTE, PAGE_SIZE);
	RtlZeroMemory(PAGE_PDE, PAGE_SIZE);
	RtlZeroMemory(PAGE_PPE, PAGE_SIZE);

	PHYSICAL_ADDRESS PHY_ADDRESS_PTE = MmGetPhysicalAddress(PAGE_PTE);
	PHYSICAL_ADDRESS PHY_ADDRESS_PDE = MmGetPhysicalAddress(PAGE_PDE);
	PHYSICAL_ADDRESS PHY_ADDRESS_PPE = MmGetPhysicalAddress(PAGE_PPE);
	if (PHY_ADDRESS_PPE.QuadPart == 0 || PHY_ADDRESS_PDE.QuadPart == 0 || PHY_ADDRESS_PTE.QuadPart == 0)
	{
		if (PAGE_PTE != 0)MmFreeContiguousMemory(PAGE_PTE);
		if (PAGE_PDE != 0)MmFreeContiguousMemory(PAGE_PDE);
		if (PAGE_PPE != 0)MmFreeContiguousMemory(PAGE_PPE);
		return FALSE;
	}
	hMapPoiner->PPE_VA = PAGE_PPE;
	hMapPoiner->PPE_PhyAdr = PHY_ADDRESS_PPE;

	hMapPoiner->PDE_VA = PAGE_PDE;
	hMapPoiner->PDE_PhyAdr = PHY_ADDRESS_PDE;

	hMapPoiner->PTE_VA = PAGE_PTE;
	hMapPoiner->PTE_PhyAdr = PHY_ADDRESS_PTE;
	return TRUE;
}

void ExFreeMapPoinerEx(PAGE_PVOID_PHY* hMapPoiner) {
	if (hMapPoiner->PTE_VA != 0)MmFreeContiguousMemory(hMapPoiner->PTE_VA);
	if (hMapPoiner->PDE_VA != 0)MmFreeContiguousMemory(hMapPoiner->PPE_VA);
	if (hMapPoiner->PPE_VA != 0)MmFreeContiguousMemory(hMapPoiner->PPE_VA);
}




BOOLEAN ExAllocateMapPoiner(PAGE_PVOID_PHY* hMapPoiner) {

	PVOID PAGE_PTE = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 3, 'tag');

	//NewPhyAddressPageSize
	if (PAGE_PTE == 0)
	{
		return FALSE;
	}
	PHYSICAL_ADDRESS PHY_ADDRESS_PTE = MmGetPhysicalAddress(PAGE_PTE);
	PHYSICAL_ADDRESS PHY_ADDRESS_PDE = MmGetPhysicalAddress((PVOID)((DWORD64)PAGE_PTE + PAGE_SIZE));
	PHYSICAL_ADDRESS PHY_ADDRESS_PPE = MmGetPhysicalAddress((PVOID)((DWORD64)PAGE_PTE + PAGE_SIZE * 2));

	if (PHY_ADDRESS_PPE.QuadPart == 0 || PHY_ADDRESS_PDE.QuadPart == 0 || PHY_ADDRESS_PTE.QuadPart == 0)
	{
		ExFreePoolWithTag(PAGE_PTE, 'tag');
		return FALSE;
	}
	RtlZeroMemory(PAGE_PTE, PAGE_SIZE * 3);

	hMapPoiner->PPE_VA = (MMPTE*)((DWORD64)PAGE_PTE + PAGE_SIZE * 2);
	hMapPoiner->PPE_PhyAdr = PHY_ADDRESS_PPE;

	hMapPoiner->PDE_VA = (MMPTE*)((DWORD64)PAGE_PTE + PAGE_SIZE);
	hMapPoiner->PDE_PhyAdr = PHY_ADDRESS_PDE;

	hMapPoiner->PTE_VA = (MMPTE*)PAGE_PTE;
	hMapPoiner->PTE_PhyAdr = PHY_ADDRESS_PTE;
	return TRUE;
}



void ExFreeMapPoiner(PAGE_PVOID_PHY* hMapPoiner) {
	ExFreePoolWithTag(hMapPoiner->PTE_VA, 'tag');
}




#define MAP_POINER_EMPTY 0
#define MAP_POINER_DEL 1
#define MAP_POINER_SET 2


PVOID LOCK_MAP_POINER(DWORD TYPE, PVOID PDT, MMPTE* uPTE, DWORD uPageSzie)
{
	PVOID rPoiner = 0;
	ExAcquireSpinLockAtDpcLevel(&SpinLock_MapPoiner);
	if (TYPE == MAP_POINER_EMPTY){

		DWORD uMaxPage = PDE_PER_PAGE - (((DWORD64)PDT & 0xFFF) / 8);
		if (uMaxPage > uPageSzie)
		{
			uMaxPage -= uPageSzie;
			for (size_t i = 0; i < uMaxPage; i++)
			{
				DWORD64* rVal = (DWORD64*)((DWORD64)PDT + i * 8);
				if (*rVal == 0)
				{
					*rVal = 1;
					__invlpg(rVal);
					rPoiner = rVal;
				}
			}
		}

	}
	else if (TYPE == MAP_POINER_DEL)
	{
		//rPoiner = _InterlockedCompareExchange64(PDT, *(LONG64*)uPTE, 0);
		//*(DWORD64 *)PDT = 0;
		volatile LONG64* TF = PDT;
		//rPoiner = InterlockedExchange64(TF, 0);
		*TF = 0;
		__invlpg(TF);
	}
	else if (TYPE == MAP_POINER_SET)
	{
		//DWORD64 pTe = 0;
		//volatile LONG64* TF = PDT;
		//rPoiner = InterlockedExchange64(TF, *(LONG64*)uPTE);
		*(MMPTE*)PDT = *uPTE;
		__invlpg(PDT);
	}
	ExReleaseSpinLockFromDpcLevel(&SpinLock_MapPoiner);
	return rPoiner;
}

typedef struct _ADDRESS_PTE
{
	union 
	{
		struct PTE_NUMBER
		{
			ULONGLONG offset : 12;
			ULONGLONG PXE_PageFrameNumber : 9;
			ULONGLONG PPE_PageFrameNumber : 9;
			ULONGLONG PDE_PageFrameNumber : 9;
			ULONGLONG PTE_PageFrameNumber : 9;
			ULONGLONG High : 16;
		};
		ULONGLONG Address;
	}u;
}ADDRESS_PTE;




// 初始化映射  
PVOID IniMapPoiner(PAGE_PVOID_PHY* hMapPoiner, SIZE_T PageSize){

	if (PageSize >= 512) {
		LOG_DEBUG("__LINE %d  \n", __LINE__);
		return 0;
	}
	LOG_DEBUG("__LINE %d  \n", __LINE__);

	DWORD64 PLM4_BASE[4] = { 0 };
	DWORD64 BasePniner = (DWORD64)hMapPoiner->PTE_VA;//PsGetCurrentProcess()
	MiFillPteHierarchy(BasePniner, PLM4_BASE);
	for (int i = 3; i >= 0; i--) {
		DWORD64 PTE = *(DWORD64*)(PLM4_BASE[i]);
		if (PTE == 0)
		{
			LOG_DEBUG("__LINE %d  \n", __LINE__);
			return 0;
		}
	}
	DWORD64 KERNEL_PLM4_BASE[4] = { 0 };
	MiFillPteHierarchy(MM_USER_PROBE_ADDRESS, KERNEL_PLM4_BASE);

	// 从内核空间开始
	DWORD64 bBase = (PLM4_BASE[3] & 0xFFFFFFFFFFFFF000) + (KERNEL_PLM4_BASE[3] & 0xFFF);
	//DWORD64 Cr3 = __readcr3();
	//__writecr3(Cr3);
//
	//LOG_DEBUG("KERNEL pageSize <%p>\n", PageSize);

	//LOG_DEBUG("bBase gBase<%p> <%p>\n", bBase, gBase);
	
	MMPTE uPTE = *(MMPTE*)(PLM4_BASE[0]);
	hMapPoiner->PLM4[0] = uPTE;
	//LOG_DEBUG("uPTE <%p>  %d  %d\n", uPTE, uPTE.u.Hard.CopyOnWrite, uPTE.u.Hard.NoExecute);
	for (size_t i = 0; i < PageSize; i++) {

		uPTE.u.Hard.PageFrameNumber = (hMapPoiner->PTE_PhyAdr.QuadPart >> 12) + i;
		hMapPoiner->PPE_VA[i] = uPTE;

	}
	__invlpg(hMapPoiner->PPE_VA);
	//__writecr3(Cr3);

	uPTE = *(MMPTE*)(PLM4_BASE[1]);
	uPTE.u.Hard.PageFrameNumber = hMapPoiner->PPE_PhyAdr.QuadPart >> 12;
	////DWORD64 PDE_PageNumber = 
	hMapPoiner->PDE_VA[0] = uPTE;
	__invlpg(hMapPoiner->PDE_VA);
	//__writecr3(Cr3);


	uPTE = *(MMPTE*)(PLM4_BASE[2]);
	uPTE.u.Hard.PageFrameNumber = hMapPoiner->PDE_PhyAdr.QuadPart >> 12;
	hMapPoiner->PTE_VA[0] = uPTE;
	__invlpg(hMapPoiner->PTE_VA);
	//__writecr3(Cr3);

	//LOG_DEBUG("uPTE <%p>  <%p>\n", uPTE, *(DWORD64*)gBase);
	//LOG_DEBUG("bBase gBase<%p> <%p>\n", bBase, gBase);
	uPTE = *(MMPTE*)(PLM4_BASE[3]);
	uPTE.u.Hard.PageFrameNumber = hMapPoiner->PTE_PhyAdr.QuadPart >> 12;
	DWORD64 gBase = (DWORD64)LOCK_MAP_POINER(MAP_POINER_EMPTY, (PVOID)bBase, &uPTE, 1);
	if (gBase == 0)
	{
		LOG_DEBUG("__LINE %d  \n", __LINE__);
		return 0;
	}
	DWORD64 PageNumber = (gBase & 0xFFF) / 8;
	//if (PageNumber >= 511)
	//{
	//	LOG_DEBUG("Page Error <%p>\n", PageNumber);
	//	return 0;
	//}

	hMapPoiner->uPTE = uPTE;
	hMapPoiner->PDE = (MMPTE*)gBase;
	if (*(DWORD64*)gBase != *(DWORD64*)&uPTE)
	{
		LOG_DEBUG("errrrr   bBase gBase<%p> <%p>\n", bBase, gBase);
		return 0;
	}
	DWORD64 rPniner = BasePniner & 0xFFFFFFFFFFFFF000;
	ADDRESS_PTE* pAddress = (ADDRESS_PTE*)&rPniner;
	//sizeof(ADDRESS_PTE)
	pAddress->u.PXE_PageFrameNumber = 0;
	pAddress->u.PPE_PageFrameNumber = 0;
	pAddress->u.PDE_PageFrameNumber = 0;
	pAddress->u.PTE_PageFrameNumber = PageNumber;
	hMapPoiner->uBASE_ADDRESS = rPniner;
	return (PVOID)rPniner;
}





PVOID MapToPoinerV(PEPROCESS Process, PAGE_PVOID_PHY* hMapPoiner, PVOID VirtualAddress, DWORD nSize) 
{
	DWORD64 DirectoryTableBase = *(DWORD64*)((ULONGLONG)Process + 0x28);
	DirectoryTableBase &= 0xFFFFFFFFFFFFF000;
	DWORD64 PLM4[4] = { 0 };
	MiFillPteHierarchy((ULONGLONG)VirtualAddress, PLM4);
	MMPTE bPTE = { 0 };

	DWORD64 PLM4_BASE[4] = { 0 };
	DWORD64 BasePniner = (DWORD64)hMapPoiner->PTE_VA;//PsGetCurrentProcess()
	MiFillPteHierarchy(BasePniner, PLM4_BASE);

	DWORD nPLM4 = 4;
	//MMPTE uPTE = *(MMPTE*)(PLM4_BASE[3]);
	bPTE.u.Hard.PageFrameNumber = DirectoryTableBase >> 12;
	MMPTE PLM4_PTE[4] = { 0 };
	MMPTE TablePTE[512] = { 0 };
	DWORD uPageSzie = ((((DWORD64)VirtualAddress & 0xFFF) + nSize) / PAGE_SIZE) + 1;
	if ((((PLM4[0] & 0xFFF) / 8) + uPageSzie) > 0x1FF)
	{
		//  小PAGE 页面
		LOG_DEBUG(" PAGE TOO BIG\n");
		return 0;
	}
	do
	{
		//__wbinvd();
		nPLM4--;
		__invlpg(PLM4_BASE[nPLM4]);
		MMPTE uPTE = *(MMPTE*)(PLM4_BASE[nPLM4]);
		uPTE.u.Hard.PageFrameNumber = bPTE.u.Hard.PageFrameNumber; 


		__invlpg(hMapPoiner->PPE_VA);
		hMapPoiner->PPE_VA[0] = uPTE;
		__invlpg(hMapPoiner->PPE_VA);
		//__writecr3(Cr3);

		LOG_DEBUG(" %d  uPTE<%p> \n", nPLM4, uPTE);
		if (nPLM4 == 0){
			for (size_t i = 0; i < uPageSzie; i++)
			{
				MMPTE* pPTE = (MMPTE*)(hMapPoiner->uBASE_ADDRESS + (PLM4[nPLM4] & 0xFFF) + i * 8);
				__invlpg(pPTE);
				bPTE = *pPTE;
				uPTE.u.Hard.PageFrameNumber = bPTE.u.Hard.PageFrameNumber;
				uPTE.u.Hard.Write = 1;

				hMapPoiner->PPE_VA[i] = uPTE;
				__invlpg(&hMapPoiner->PPE_VA[i]);
				//TablePTE[i] = uPTE;
				LOG_DEBUG(" %d  <%p> \n", nPLM4, bPTE);
			}
			break;
		}
		else
		{
			MMPTE* pPTE = (MMPTE*)(hMapPoiner->uBASE_ADDRESS + (PLM4[nPLM4] & 0xFFF));
			__invlpg(pPTE);
			//__writecr3(Cr3);
			bPTE = *pPTE;
			LOG_DEBUG(" %d  <%p> <%08X>\n", nPLM4, bPTE, (PLM4[nPLM4] & 0xFFF));
		}
		PLM4_PTE[nPLM4] = bPTE;
		if (bPTE.u.Hard.PageFrameNumber == 0) {
			LOG_DEBUG(" PageFrameNumber == 0 <%p>\n", bPTE);
			return 0;
		}
	} while (nPLM4 > 0);

	//RtlCopyMemory(hMapPoiner->PPE_VA, TablePTE, uPageSzie * sizeof(MMPTE));
	//__invlpg(hMapPoiner->PPE_VA);
	DWORD64 rAddress = (hMapPoiner->uBASE_ADDRESS + ((DWORD64)VirtualAddress & 0xFFF));
	__invlpg(rAddress);
	
	//__writecr3(Cr3);
//	RtlCopyMemory(oVirtualAddress,hMapPoiner->uBASE_ADDRESS + (VirtualAddress &))
	return (PVOID)rAddress;
}


PVOID MapToPoiner(PHYSICAL_ADDRESS  phyAddress, SIZE_T PageSize, PAGE_PVOID_PHY* hMapPoiner) //  具体映射几个物理页面 
{
	PHYSICAL_ADDRESS  uPhyAdr = { 0 };
	uPhyAdr.QuadPart = phyAddress.QuadPart & 0xFFFFFFFFFFFFF000;
	if (PageSize >= 512) {
		LOG_DEBUG("__LINE %d  \n", __LINE__);
		return 0;
	}

	if (!ExAllocateMapPoiner(hMapPoiner)){
		LOG_DEBUG("__LINE %d  \n", __LINE__);
		return 0;
	} 

//	LOG_DEBUG("__LINE %d  \n", __LINE__);

	DWORD64 PLM4_BASE[4] = { 0 };
	DWORD64 BasePniner = (DWORD64)hMapPoiner->PTE_VA;//PsGetCurrentProcess()
	MiFillPteHierarchy(BasePniner, PLM4_BASE);

	//DWORD64 DirectoryTableBase = __readcr3();
	//LOG_DEBUG("CurDirectoryTableBase  %I64X\n", DirectoryTableBase);

	for (int i = 3; i >= 0; i--){
		DWORD64 PTE = *(DWORD64*)(PLM4_BASE[i]);
		if (PTE == 0)
		{
			LOG_DEBUG("__LINE  PTE == 0 %d  \n", __LINE__);
			ExFreeMapPoiner(hMapPoiner);
			return 0;
		}
	}
	//DWORD64 PTE = *(DWORD64*)(PLM4_BASE[3]);
	//if (PTE == 0)
	//{
	//	LOG_DEBUG("__LINE %d  \n", __LINE__);
	//	ExFreeMapPoiner(hMapPoiner);
	//	return 0;
	//}


	DWORD64 KERNEL_PLM4_BASE[4] = { 0 };
	MiFillPteHierarchy(MM_USER_PROBE_ADDRESS, KERNEL_PLM4_BASE);
	// 从内核空间开始
	DWORD64 bBase = (PLM4_BASE[3] & 0xFFFFFFFFFFFFF000) + (KERNEL_PLM4_BASE[3] & 0xFFF);

	//LOG_DEBUG("KERNEL pageSize <%p>\n", PageSize);
	DWORD64 gBase = (DWORD64)LOCK_MAP_POINER(MAP_POINER_EMPTY, (PVOID)bBase, NULL, 1);
	if (gBase == 0)
	{
		LOG_DEBUG("__LINE %d  \n", __LINE__);
		ExFreeMapPoiner(hMapPoiner);
		return 0;
	}
	DWORD64 PageNumber = (gBase & 0xFFF) / 8;
	//if (PageNumber >= 511)
	//{
	//	LOG_DEBUG("Page Error <%p>\n", PageNumber);
	//	ExFreeMapPoiner(hMapPoiner);
	//	return 0;
	//}
	//LOG_DEBUG("bBase gBase<%p> <%p>\n", bBase, gBase);


	hMapPoiner->PDE = (MMPTE *)gBase;


	MMPTE uPTE = *(MMPTE*)(PLM4_BASE[0]);
	//LOG_DEBUG("uPTE <%p>  %d  %d\n", uPTE, uPTE.u.Hard.CopyOnWrite, uPTE.u.Hard.NoExecute);
	for (size_t i = 0; i < PageSize; i++){

		uPTE.u.Hard.PageFrameNumber = (phyAddress.QuadPart >> 12) + i;
		hMapPoiner->PPE_VA[i] = uPTE;
	}

	uPTE = *(MMPTE*)(PLM4_BASE[1]);
	uPTE.u.Hard.PageFrameNumber = hMapPoiner->PPE_PhyAdr.QuadPart >> 12;
	////DWORD64 PDE_PageNumber = 
	hMapPoiner->PDE_VA[0] = uPTE;

	uPTE = *(MMPTE*)(PLM4_BASE[2]);
	uPTE.u.Hard.PageFrameNumber = hMapPoiner->PDE_PhyAdr.QuadPart >> 12;
	hMapPoiner->PTE_VA[0] = uPTE;

	//LOG_DEBUG("uPTE <%p>  <%p>\n", uPTE, *(DWORD64*)gBase);
	//LOG_DEBUG("bBase gBase<%p> <%p>\n", bBase, gBase);


	uPTE = *(MMPTE*)(PLM4_BASE[3]);
	uPTE.u.Hard.PageFrameNumber = hMapPoiner->PTE_PhyAdr.QuadPart >> 12;
	LOCK_MAP_POINER(MAP_POINER_SET, (PVOID)gBase, &uPTE, (DWORD)PageSize);
	if (*(DWORD64 *)gBase != *(DWORD64*)&uPTE)
	{
		return 0;
	}
	 DWORD64 rPniner = BasePniner & 0xFFFFFFFFFFFFF000;
	ADDRESS_PTE* pAddress = (ADDRESS_PTE*)&rPniner;
	pAddress->u.PXE_PageFrameNumber = 0;
	pAddress->u.PPE_PageFrameNumber = 0;
	pAddress->u.PDE_PageFrameNumber = 0;
	pAddress->u.PTE_PageFrameNumber = PageNumber;

	//pAddress->High
	//LOG_DEBUG("BasePniner rPniner<%p> <%p>\n", BasePniner, rPniner);
	return (PVOID)rPniner;
}

PVOID UnMapToPoiner(PAGE_PVOID_PHY* hMapPoiner) {
	LOCK_MAP_POINER(MAP_POINER_DEL, hMapPoiner->PDE, NULL, 0);
	//KIRQL Irql = KfRaiseIrql(DISPATCH_LEVEL);
	//DWORD64 Cr3 = __readcr3();
	//__writecr3(Cr3);
	//KfRaiseIrql(Irql);

	//LOG_DEBUG("*hMapPoiner->PDE <%p>\n", *(hMapPoiner->PDE));
	ExFreeMapPoiner(hMapPoiner);
	return 0;
}

PVOID UnMapToPoinerEx(PAGE_PVOID_PHY* hMapPoiner) {
	LOCK_MAP_POINER(MAP_POINER_DEL, hMapPoiner->PDE, NULL, 0);
	ExFreeMapPoinerEx(hMapPoiner);
	return 0;
}


BOOLEAN wIsPhysicalAddress(PEPROCESS Process, PVOID VirtualAddress) {

	DWORD64 PLM4[5] = { 0 };
	MiFillPteHierarchy((ULONGLONG)VirtualAddress, &PLM4[1]);
	DWORD64 DirectoryTableBase = *(DWORD64*)((ULONGLONG)Process + 0x28);
	DWORD64 TableBaseV = DirectoryTableBase & 0xFFFFFFFFFFFFF000;
	int i = 0;
	for (i = 4; i > 0; i--) {
		PHYSICAL_ADDRESS TableBase = { 0 }; //sizeof(LARGE_INTEGER)
		TableBase.QuadPart = TableBaseV + (PLM4[i] & 0xFFF);
		DWORD64 MPTE = 0;
		if (!ReadPhysicalAddress(TableBase, &MPTE, sizeof(MMPTE)))
		{
			break;
		}
		MMPTE* pMM = (MMPTE*)&MPTE;
		TableBaseV = pMM->u.Hard.PageFrameNumber << 12;
		UCHAR AddressPolicy = *(UCHAR*)((ULONGLONG)Process + 0x390);
		if (PLM4[i] >= PXE_BASE
			&& PLM4[i] <= PXE_SELFMAP
			&& (*MiFlags & 0xC00000) != 0
			&& AddressPolicy != 1)
		{
			if ((MPTE & 1) == 0)
				return 0i64;
			if ((MPTE & 0x20) == 0 || (MPTE & 0x42) == 0)
			{
				__try
				{
					PLIST_ENTRY Flink = (PLIST_ENTRY)*(DWORD64*)((ULONGLONG)Process + 0x788);
					if (Flink)
					{
						DWORD64 v7 = *((_QWORD*)&Flink->Flink + ((PLM4[i] >> 3) & 0x1FF));
						DWORD64 v8 = MPTE | 0x20;
						if ((v7 & 0x20) == 0)
							v8 = MPTE;
						//LOBYTE(v4) = v8;
						MPTE = (MPTE & 0xFFFFFFFFFFFFFF00) | v8;
						if ((v7 & 0x42) != 0)
							MPTE = (MPTE & 0xFFFFFFFFFFFFFF00) | v8 | 0x42;//LOBYTE(v4) = v8 | 0x42;
					}
				}
				__except (1) {

				}


			}
		}
		if ((MPTE & 1) == 0)
			return 0i64;
		if ((MPTE & 0x80u) != 0i64)
			break;
		if (i == 1)
			return 0i64;
	}
	return (BOOLEAN)i;
}










//BOOLEAN wReadProcessMemory(PEPROCESS Process, PVOID VirtualAddress) {
//
//	DWORD64 PLM4[5] = { 0 };
//	MiFillPteHierarchy(VirtualAddress, &PLM4[1]);
//	DWORD64 DirectoryTableBase = *(DWORD64*)((ULONGLONG)Process + 0x28);
//	DWORD64 TableBaseV = DirectoryTableBase & 0xFFFFFFFFFFFFF000;
//
//
//
//	int i = 0;
//	for (i = 4; i > 0; i--) {
//		PHYSICAL_ADDRESS TableBase = { 0 }; //sizeof(LARGE_INTEGER)
//		TableBase.QuadPart = TableBaseV + (PLM4[i] & 0xFFF);
//		DWORD64 MPTE = 0;
//		if (!ReadPhysicalAddress(TableBase, &MPTE, sizeof(MMPTE)))
//		{
//			break;
//		}
//		MMPTE* pMM = &MPTE;
//		TableBaseV = pMM->u.Hard.PageFrameNumber << 12;
//		UCHAR AddressPolicy = *(UCHAR*)((ULONGLONG)Process + 0x390);
//		if (PLM4[i] >= PXE_BASE
//			&& PLM4[i] <= PXE_SELFMAP
//			&& (*MiFlags & 0xC00000) != 0
//			&& AddressPolicy != 1)
//		{
//			if ((MPTE & 1) == 0)
//				return 0i64;
//			if ((MPTE & 0x20) == 0 || (MPTE & 0x42) == 0)
//			{
//				__try
//				{
//					PLIST_ENTRY Flink = *(DWORD64*)((ULONGLONG)Process + 0x788);
//					if (Flink)
//					{
//						DWORD64 v7 = *((_QWORD*)&Flink->Flink + ((PLM4[i] >> 3) & 0x1FF));
//						DWORD64 v8 = MPTE | 0x20;
//						if ((v7 & 0x20) == 0)
//							v8 = MPTE;
//						//LOBYTE(v4) = v8;
//						MPTE = (MPTE & 0xFFFFFFFFFFFFFF00) | v8;
//						if ((v7 & 0x42) != 0)
//							MPTE = (MPTE & 0xFFFFFFFFFFFFFF00) | v8 | 0x42;//LOBYTE(v4) = v8 | 0x42;
//					}
//				}
//				__except (1) {
//
//				}
//
//
//			}
//		}
//		if ((MPTE & 1) == 0)
//			return 0i64;
//		if ((MPTE & 0x80u) != 0i64)
//			break;
//		if (i == 1)
//			return 0i64;
//	}
//	return i;
//}











PHYSICAL_ADDRESS wGetPhysicalAddressV(PEPROCESS Process, PVOID VirtualAddress) {

	DWORD64 DirectoryTableBase = *(DWORD64*)((ULONGLONG)Process + 0x28);
	LOG_DEBUG(" DirectoryTableBase1 <%p>\n", DirectoryTableBase);
	DirectoryTableBase &= 0xFFFFFFFFFFFFF000;

	LOG_DEBUG(" DirectoryTableBase2 <%p>\n", DirectoryTableBase);
	DWORD64 PLM4[4] = { 0 };
	MiFillPteHierarchy((ULONGLONG)VirtualAddress, PLM4);
	MMPTE bPTE = { 0 };
	PHYSICAL_ADDRESS TableBase = {0}; //sizeof(LARGE_INTEGER)
	PHYSICAL_ADDRESS TableBaseR = { 0 };


	TableBase.QuadPart = DirectoryTableBase;
	//PVOID pPoiner = MapToPoiner(TableBase, 1);
	//LOG_DEBUG(" pPoiner <%p> \n", pPoiner);
	//LOG_DEBUG(" pPoiner <%p> \n", *(DWORD64*)pPoiner);

	LOG_DEBUG(" QuadPart <%p> <%p>\n", TableBase.QuadPart, PLM4[3]);
	TableBase.QuadPart = DirectoryTableBase + (PLM4[3] & 0xFFF);
	if (!ReadPhysicalAddress(TableBase, &bPTE, sizeof(MMPTE)))
	{
		LOG_DEBUG(" ReadPhysicalMemory2 FALSE <%p>\n", bPTE);
		return TableBaseR;
	}
	if (bPTE.u.Hard.PageFrameNumber == 0) {
		LOG_DEBUG(" PageFrameNumber == 0 <%p>\n", bPTE);
		return TableBaseR;
	}

	LOG_DEBUG("3  PTM4 <%p>\n", bPTE);
	DWORD64 TableBaseE = ((*(DWORD64*)&bPTE) >> 12) & 0xFFFFFFFFF;
	TableBaseE = TableBaseE << 12;
	TableBase.QuadPart = TableBaseE & 0xFFFFFFFF00000000;
	TableBase.LowPart = ((((ULONGLONG)(PLM4[2]) & 0xFFF) + TableBaseE) & 0xFFFFFFFF);


	LOG_DEBUG(" QuadPart <%p> <%p>\n", TableBase.QuadPart, PLM4[2]);
	RtlZeroMemory(&bPTE, sizeof(MMPTE));
	if (!ReadPhysicalAddress(TableBase, &bPTE, sizeof(MMPTE)))
	{
		LOG_DEBUG(" ReadPhysicalMemory FALSE <%p>\n", bPTE);
		return TableBaseR;
	}
	if (bPTE.u.Hard.PageFrameNumber == 0) {
		LOG_DEBUG(" PageFrameNumber == 0 <%p>\n", bPTE);
		return TableBaseR;
	}

	LOG_DEBUG("2  PTM4 <%p>\n", bPTE);
	TableBaseE = ((*(DWORD64*)&bPTE) >> 12) & 0xFFFFFFFFF;
	TableBaseE = TableBaseE << 12;
	TableBase.QuadPart = TableBaseE & 0xFFFFFFFF00000000;
	TableBase.LowPart = ((((ULONGLONG)(PLM4[1]) & 0xFFF) + TableBaseE) & 0xFFFFFFFF);


	LOG_DEBUG(" QuadPart <%p> <%p>\n", TableBase.QuadPart, PLM4[1]);
	RtlZeroMemory(&bPTE, sizeof(MMPTE));
	if (!ReadPhysicalAddress(TableBase, &bPTE, sizeof(MMPTE)))
	{
		LOG_DEBUG(" ReadPhysicalMemory FALSE <%p>\n", bPTE);
		return TableBaseR;
	}
	if (bPTE.u.Hard.PageFrameNumber == 0) {
		LOG_DEBUG(" PageFrameNumber == 0 <%p>\n", bPTE);
		return TableBaseR;
	}

	LOG_DEBUG("1  PTM4 <%p>\n", bPTE);
	TableBaseE = ((*(DWORD64*)&bPTE) >> 12) & 0xFFFFFFFFF;
	TableBaseE = TableBaseE << 12;
	TableBase.QuadPart = TableBaseE & 0xFFFFFFFF00000000;
	TableBase.LowPart = ((((ULONGLONG)(PLM4[0]) & 0xFFF) + TableBaseE) & 0xFFFFFFFF);
	LOG_DEBUG(" QuadPart <%p> <%p>\n", TableBase.QuadPart, PLM4[0]);
	RtlZeroMemory(&bPTE, sizeof(MMPTE));
	if (!ReadPhysicalAddress(TableBase, &bPTE, sizeof(MMPTE)))
	{
		LOG_DEBUG(" ReadPhysicalMemory2 FALSE <%p>\n", bPTE);
		return TableBaseR;
	}
	if (bPTE.u.Hard.PageFrameNumber == 0) {
		LOG_DEBUG(" PageFrameNumber == 0 <%p>\n", bPTE);
		return TableBaseR;
	}
	LOG_DEBUG("0  PTM4 <%p> <%08X>\n", TableBase, bPTE.u.Hard.PageFrameNumber);
	TableBaseE = ((*(DWORD64*)&bPTE) >> 12) & 0xFFFFFFFFF;
	TableBaseE = TableBaseE << 12;
	TableBase.QuadPart = TableBaseE & 0xFFFFFFFF00000000;
	TableBase.LowPart = ((((ULONGLONG)VirtualAddress & 0xFFF) + TableBaseE) & 0xFFFFFFFF);
	return TableBase;
}








BOOLEAN ReadProcessMemoryV(PEPROCESS Process, PVOID SrcVirtualAddress, PVOID wVirtualAddress, DWORD nSize) {

	//// 先查询一下该地址 是否是物理地址
	//if (wIsPhysicalAddress(Process, wVirtualAddress))
	//{
	//	LOG_DEBUG("PhysicalAddress ==TRUE\n");
	//	return FALSE;
	//}
	
	//__readgsqword
	//	STATUS_ACCESS_VIOLATION


	PAGE_PVOID_PHY MapTpPoiner = { 0 };
	DWORD uPageSzie = ((((DWORD64)SrcVirtualAddress & 0xFFF) + nSize) / PAGE_SIZE) + 1;
	if (!ExAllocateMapPoiner(&MapTpPoiner))
	{
		return FALSE;
	}
	char * uBuffer = IniMapPoiner(&MapTpPoiner, uPageSzie);
	if (uBuffer == 0)
	{
		ExFreeMapPoiner(&MapTpPoiner);
		return FALSE;
	}
	char* vBuffer = 0;
	BOOLEAN r = FALSE;
	__try
	{
		vBuffer = MapToPoinerV(Process, &MapTpPoiner, SrcVirtualAddress, nSize);
		if (vBuffer != 0){
			RtlCopyMemory(wVirtualAddress, vBuffer, nSize);
			r = TRUE;
		}
	}
	__except (1) {
		LOG_DEBUG("__except %s %08X\n", __FUNCTION__, GetExceptionCode());
		r = FALSE;
    }
	UnMapToPoiner(&MapTpPoiner);
	return r;
}

BOOLEAN WriteProcessMemoryV(PEPROCESS Process, PVOID SrcVirtualAddress, PVOID wVirtualAddress, DWORD nSize) {
	PAGE_PVOID_PHY MapTpPoiner = { 0 };
	DWORD uPageSzie = ((((DWORD64)SrcVirtualAddress & 0xFFF) + nSize) / PAGE_SIZE) + 1;
	if (!ExAllocateMapPoiner(&MapTpPoiner))
	{
		return FALSE;
	}
	char* uBuffer = IniMapPoiner(&MapTpPoiner, uPageSzie);
	if (uBuffer == 0)
	{
		ExFreeMapPoiner(&MapTpPoiner);
		return FALSE;
	}
	char* vBuffer = 0;
	BOOLEAN r = FALSE;
	__try
	{
		vBuffer = MapToPoinerV(Process, &MapTpPoiner, SrcVirtualAddress, nSize);
		if (vBuffer != 0) {
			RtlCopyMemory(vBuffer, wVirtualAddress, nSize);
			r = TRUE;
		}
	}
	__except (1) {
		LOG_DEBUG("__except %s %08X\n", __FUNCTION__, GetExceptionCode());
		r = FALSE;
	}
	return r;
}

BOOLEAN ReadProcessMemoryEx(PEPROCESS Process, PVOID SrcVirtualAddress, PVOID wVirtualAddress, DWORD nSize) {

	PAGE_PVOID_PHY MapTpPoiner = { 0 };
	DWORD uPageSzie = ((((DWORD64)SrcVirtualAddress & 0xFFF) + nSize) / PAGE_SIZE) + 1;
	if (!ExAllocateMapPoinerEx(&MapTpPoiner))
	{
		return FALSE;
	}
	char* uBuffer = IniMapPoiner(&MapTpPoiner, uPageSzie);
	if (uBuffer == 0)
	{
		ExFreeMapPoinerEx(&MapTpPoiner);
		return FALSE;
	}
	char* vBuffer = 0;
	BOOLEAN r = FALSE;
	__try
	{
		vBuffer = MapToPoinerV(Process, &MapTpPoiner, SrcVirtualAddress, nSize);
		if (vBuffer != 0) {
			RtlCopyMemory(wVirtualAddress, vBuffer, nSize);
			r = TRUE;
		}
	}
	__except (1) {
		LOG_DEBUG("__except %s %08X\n", __FUNCTION__, GetExceptionCode());
		r = FALSE;
	}
	UnMapToPoinerEx(&MapTpPoiner);
	return r;
}

BOOLEAN WriteProcessMemoryEx(PEPROCESS Process, PVOID SrcVirtualAddress, PVOID wVirtualAddress, DWORD nSize) {
	PAGE_PVOID_PHY MapTpPoiner = { 0 };
	DWORD uPageSzie = ((((DWORD64)SrcVirtualAddress & 0xFFF) + nSize) / PAGE_SIZE) + 1;
	if (!ExAllocateMapPoinerEx(&MapTpPoiner))
	{
		return FALSE;
	}
	char* uBuffer = IniMapPoiner(&MapTpPoiner, uPageSzie);
	if (uBuffer == 0)
	{
		ExFreeMapPoinerEx(&MapTpPoiner);
		return FALSE;
	}
	char* vBuffer = 0;
	BOOLEAN r = FALSE;
	__try
	{
		vBuffer = MapToPoinerV(Process, &MapTpPoiner, SrcVirtualAddress, nSize);
		if (vBuffer != 0) {
			RtlCopyMemory(vBuffer, wVirtualAddress, nSize);
			r = TRUE;
		}
	}
	__except (1) {
		LOG_DEBUG("__except %s %08X\n", __FUNCTION__, GetExceptionCode());
		r = FALSE;
	}
	UnMapToPoinerEx(&MapTpPoiner);
	return r;
}














__int64 __fastcall MI_READ_PTE_LOCK_FREE(unsigned __int64 a1, PEPROCESS Process)
{
	__int64 result; // rax
	LIST_ENTRY* Flink; // rdx
	__int64 v3; // r8
	__int64 v4; // rcx
	LOG_DEBUG(" %s %d  <%p>\n", __FUNCTION__, __LINE__, a1);
	UCHAR AddressPolicy = *(UCHAR*)((ULONGLONG)Process + 0x390);


	// 读其他Process 地址需要切换 CR3
	//ULONGLONG TableBase = __readcr3();
	//__writecr3(*(DWORD64 *)((ULONGLONG)Process + 0x28));
	result = *(_QWORD*)a1;
	//__writecr3(TableBase);


	if (a1 >= PXE_BASE
		&& a1 <= PXE_SELFMAP
		&& ( *MiFlags & 0xC00000) != 0
		&& AddressPolicy != 1
		&& (result & 1) != 0
		&& ((result & 0x20) == 0 || (result & 0x42) == 0))
	{
		Flink =  (LIST_ENTRY *)*(DWORD64*)((ULONGLONG)Process + 0x788);
		if (Flink)
		{
			LOG_DEBUG("  2222  %s %d  <%p>\n", __FUNCTION__, __LINE__, a1);
			v3 = result | 0x20;
			v4 = *((_QWORD*)&Flink->Flink + ((a1 >> 3) & 0x1FF));
			if ((v4 & 0x20) == 0) {
				LOG_DEBUG("333 %s %d  <%p>\n", __FUNCTION__, __LINE__, a1);
				v3 = result;
			}
				
			result = v3;
			if ((v4 & 0x42) != 0) {

				LOG_DEBUG("444 %s %d  <%p>\n", __FUNCTION__, __LINE__, a1);
				return v3 | 0x42;
			}
				
		}
	}
	LOG_DEBUG("555 %s %d  <%p>\n", __FUNCTION__, __LINE__, a1);
	return result;
}

__int64 __fastcall MI_IS_PHYSICAL_ADDRESS(unsigned __int64 a1, PEPROCESS Process)
{
	unsigned int v1; // r10d
	__int64 v2; // rdx
	unsigned __int64 v3; // r9
	__int64 v4; // rcx
	LIST_ENTRY* Flink; // rax
	__int64 v7; // rax
	char v8; // r9
	DWORD64 R8 = 0x7FFFFFFFF8;

	DWORD64 PLM4[5] = { 0 };

	PLM4[0] = PTE_BASE;

	LOG_DEBUG(" %s %d\n", __FUNCTION__, __LINE__);
	v1 = 4;


	//LOG_DEBUG(" PTE_BASE <%p>\n", PLM4[0]);

	PLM4[1] = ((a1 >> 9) & R8) + PLM4[0];


	//LOG_DEBUG(" PDE_BASE <%p>\n", PLM4[1]);
	PLM4[2] = ((PLM4[1] >> 9) & R8) + PLM4[0];	
	//LOG_DEBUG(" PPE_BASE <%p>\n", PLM4[2]);
	PLM4[3] = ((PLM4[2] >> 9) & R8) + PLM4[0];
	//LOG_DEBUG(" PXE_BASE <%p>\n", PLM4[3]);
	PLM4[4] = ((PLM4[3] >> 9) & R8) + PLM4[0];
	//LOG_DEBUG(" PXE_SELFMAP <%p>\n", PLM4[4]);


	//PLM4[1] = ((a1 >> 9) & 0x7FFFFFFFF8i64) - 0x98000000000i64;
	//PLM4[2] = ((PLM4[1] >> 9) & 0x7FFFFFFFF8i64) - 0x98000000000i64;
	//PLM4[3] = ((PLM4[2] >> 9) & 0x7FFFFFFFF8i64) - 0x98000000000i64;
	//PLM4[4] = ((PLM4[3] >> 9) & 0x7FFFFFFFF8i64) - 0x98000000000i64;

	v2 = 4i64;
	while (1)
	{
		v3 = PLM4[v2--];         //*(&v9 + v2--);
		//LOG_DEBUG(" v3 <%p>\n", v3);
		--v1;
		v4 = *(_QWORD*)v3;

		UCHAR AddressPolicy = *(UCHAR*)((ULONGLONG)Process + 0x390);
		if (v3 >= PXE_BASE
			&& v3 <= PXE_SELFMAP
			&& (*MiFlags & 0xC00000) != 0
			&& AddressPolicy != 1)
		{
			if ((v4 & 1) == 0)
				return 0i64;
			if ((v4 & 0x20) == 0 || (v4 & 0x42) == 0)
			{
				Flink = (LIST_ENTRY*)*(DWORD64*)((ULONGLONG)Process + 0x788);
				if (Flink)
				{
					v7 = *((_QWORD*)&Flink->Flink + ((v3 >> 3) & 0x1FF));
					v8 = (char)v4 | 0x20;
					if ((v7 & 0x20) == 0)
						v8 = (char)v4;
					//LOBYTE(v4) = v8;
					v4 = (v4 & 0xFFFFFFFFFFFFFF00) | v8;
					if ((v7 & 0x42) != 0)
						v4 = (v4 & 0xFFFFFFFFFFFFFF00) | v8 | 0x42;//LOBYTE(v4) = v8 | 0x42;
				}
			}
		}
		if ((v4 & 1) == 0)
			return 0i64;
		if ((v4 & 0x80u) != 0i64)
			break;
		if (v2 == 1)
			return 0i64;
	}
	return v1;
}


__int64 __fastcall MI_IS_PHYSICAL_ADDRESS2(unsigned __int64 a1)
{
	unsigned int v1; // r10d
	__int64 v2; // rdx
	unsigned __int64 v3; // r9
	__int64 v4; // rcx

	DWORD64 R8 = 0x7FFFFFFFF8;

	DWORD64 PLM4[5] = { 0 };

	PLM4[0] = PTE_BASE;

	v1 = 4;
	PLM4[1] = ((a1 >> 9) & R8) + PLM4[0];
	PLM4[2] = ((PLM4[1] >> 9) & R8) + PLM4[0];
	PLM4[3] = ((PLM4[2] >> 9) & R8) + PLM4[0];
	PLM4[4] = ((PLM4[3] >> 9) & R8) + PLM4[0];

	v2 = 4i64;
	while (1){
		v3 = PLM4[v2--];
		--v1;
		v4 = *(_QWORD*)v3;

		if ((v4 & 1) == 0)
			return 0i64;
		if ((v4 & 0x80u) != 0i64)
			break;
		if (v2 == 1)
			return 0i64;
	}
	return v1;
}



unsigned __int64 __fastcall MiFillPteHierarchy(unsigned __int64 a1, unsigned __int64* a2)
{
	//LOG_DEBUG(" %s %d\n", __FUNCTION__, __LINE__);
	DWORD64 R8 = 0x7FFFFFFFF8;
	a2[0] = ((a1 >> 9) & R8) + PTE_BASE;
	a2[1] = ((a2[0] >> 9) & R8) + PTE_BASE;;
	a2[2] = ((a2[1] >> 9) & R8) + PTE_BASE;;
	a2[3] = ((a2[2] >> 9) & R8) + PTE_BASE;;
	return PTE_BASE;
}






DWORD64  GetAddressPteHierarchy(unsigned __int64 a1, unsigned __int64* a2) {
	DWORD64 R8 = 0x7FFFFFFFF8;
	a2[0] = ((a1 >> 9) & R8) + PTE_BASE;
	a2[1] = ((a2[0] >> 9) & R8) + PTE_BASE;;
	a2[2] = ((a2[1] >> 9) & R8) + PTE_BASE;;
	a2[3] = ((a2[2] >> 9) & R8) + PTE_BASE;;
	return PTE_BASE;
}

//DWORD64 PLM4L[4] = { 0 };
//MiFillPteHierarchy(PLM4[i], PLM4L);
//
//MMPTE pNewI = *(MMPTE*)PLM4L[3];
//
//MMPTE pNewNew = pNewI;
//pNewNew.u.Hard.Write = 1;
//*(MMPTE*)PLM4L[3] = pNewNew;
//__invlpg(PLM4L[3]);
//
//
//LOG_DEBUG("PLM4:%d Valid:%d Writable:%d Owner:%d WriteThrough:%d CacheDisable:%d Accessed:%d Dirty:%d LargePage:%d Global:%d CopyOnWrite:%d Prototype:%d Write:%d PageFrameNumber:%08X NoExecute:%d \n", i, pNewI.u.Hard.Valid,
//	pNewI.u.Hard.Writable,
//	pNewI.u.Hard.Owner,
//	pNewI.u.Hard.WriteThrough,
//	pNewI.u.Hard.CacheDisable,
//	pNewI.u.Hard.Accessed,
//	pNewI.u.Hard.Dirty,
//	pNewI.u.Hard.LargePage,
//	pNewI.u.Hard.Global,
//	pNewI.u.Hard.CopyOnWrite,
//	pNewI.u.Hard.Prototype,
//	pNewI.u.Hard.Write,
//	pNewI.u.Hard.PageFrameNumber,
//	pNewI.u.Hard.NoExecute);
//
//LOG_DEBUG("PLM4:%d reserved1:%d SoftwareWsIndex:%d\n", i, pNewI.u.Hard.reserved1, pNewI.u.Hard.SoftwareWsIndex);


BOOL SetAddressTlb(ULONGLONG Address, ULONGLONG PageNumber, ULONGLONG referAddress) {

	DWORD64 PLM4[4] = { 0 };
	MiFillPteHierarchy(Address, PLM4);

	int i = 4;
	do
	{
		i--;

		MMPTE pCurMM = *(MMPTE*)PLM4[i];





		if (pCurMM.u.Hard.Valid == 0)
		{
			PHYSICAL_ADDRESS Low = { 0 };
			PHYSICAL_ADDRESS High = { MAXULONG64 };

			MMPTE pNewNow = { 0 };
			pNewNow.u.Hard.Valid = 1;
			pNewNow.u.Hard.Writable = 1;
			pNewNow.u.Hard.Accessed = 1;
			pNewNow.u.Hard.Dirty = 1;
			pNewNow.u.Hard.Write = 1;
			if (i!= 0)
			{



				MMPTE pNewI = *(MMPTE*)PLM4[i];
				//LOG_DEBUG("PLM4:%d Valid:%d Writable:%d Owner:%d WriteThrough:%d CacheDisable:%d Accessed:%d Dirty:%d LargePage:%d Global:%d CopyOnWrite:%d Prototype:%d Write:%d PageFrameNumber:%08X NoExecute:%d \n", i, pNewI.u.Hard.Valid,
				//	pNewI.u.Hard.Writable,
				//	pNewI.u.Hard.Owner,
				//	pNewI.u.Hard.WriteThrough,
				//	pNewI.u.Hard.CacheDisable,
				//	pNewI.u.Hard.Accessed,
				//	pNewI.u.Hard.Dirty,
				//	pNewI.u.Hard.LargePage,
				//	pNewI.u.Hard.Global,
				//	pNewI.u.Hard.CopyOnWrite,
				//	pNewI.u.Hard.Prototype,
				//	pNewI.u.Hard.Write,
				//	pNewI.u.Hard.PageFrameNumber,
				//	pNewI.u.Hard.NoExecute);
				//LOG_DEBUG("PLM4:%d reserved1:%d SoftwareWsIndex:%d\n", i, pNewI.u.Hard.reserved1, pNewI.u.Hard.SoftwareWsIndex);

				PVOID TempPage = 0;;
				do
				{
					TempPage = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Low, High, Low, MmCached);
					if (TempPage != 0)
					{
						PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(TempPage);
						pNewNow.u.Hard.PageFrameNumber = ((ULONGLONG)phyAddress.QuadPart) >> 12;
						pNewNow.u.Hard.NoExecute = 1;
						pNewNow.u.Hard.SoftwareWsIndex = 160;
						//LOG_DEBUG("PLM4:%d   NewTable\n");
						break;
					}

				} while (TempPage == 0);


			}
			else
			{
				pNewNow.u.Hard.SoftwareWsIndex = 160;
				pNewNow.u.Hard.PageFrameNumber = PageNumber;
				pNewNow.u.Hard.Global = 1;
				pNewNow.u.Hard.NoExecute = 0;
				//LOG_DEBUG("PLM4:0   NewTable Number %08X\n", PageNumber);
			}

			//
			//do
			//{
			((MMPTE*)PLM4[i])->u.Long = pNewNow.u.Long;
			//InterlockedExchange64((LONG64*)PLM4[i], pNewNow.u.Long);
			__invlpg(PLM4[i]);
			//} while (((MMPTE*)PLM4[i])->u.Long !=
			//	pNewNow.u.Long);

			//__invlpg(PLM4[i]);




			//MMPTE pNewI = *(MMPTE*)PLM4[i];
			//LOG_DEBUG("New PLM4:%d Valid:%d Writable:%d Owner:%d WriteThrough:%d CacheDisable:%d Accessed:%d Dirty:%d LargePage:%d Global:%d CopyOnWrite:%d Prototype:%d Write:%d PageFrameNumber:%08X NoExecute:%d \n", i, pNewI.u.Hard.Valid,
			//	pNewI.u.Hard.Writable,
			//	pNewI.u.Hard.Owner,
			//	pNewI.u.Hard.WriteThrough,
			//	pNewI.u.Hard.CacheDisable,
			//	pNewI.u.Hard.Accessed,
			//	pNewI.u.Hard.Dirty,
			//	pNewI.u.Hard.LargePage,
			//	pNewI.u.Hard.Global,
			//	pNewI.u.Hard.CopyOnWrite,
			//	pNewI.u.Hard.Prototype,
			//	pNewI.u.Hard.Write,
			//	pNewI.u.Hard.PageFrameNumber,
			//	pNewI.u.Hard.NoExecute);
			//LOG_DEBUG("PLM4:%d reserved1:%d SoftwareWsIndex:%d\n", i, pNewI.u.Hard.reserved1, pNewI.u.Hard.SoftwareWsIndex);


		}
		else if (pCurMM.u.Hard.LargePage == 1)
		{

			MMPTE pNewOld = *(MMPTE*)PLM4[i];
			pNewOld.u.Hard.Write = 1;
			pNewOld.u.Hard.Writable = 1;
			pNewOld.u.Hard.NoExecute = 0;
			*(MMPTE*)PLM4[i] = pNewOld;
			__invlpg(PLM4[i]);
			break;
		}

	} while (i != 0);
	return TRUE;

	//MMPTE pNewI2 = *(MMPTE*)PLM4[2];
	//if (pNewI2.u.Hard.Valid == 0)
	//{
	//	PHYSICAL_ADDRESS Low = { 0 };
	//	PHYSICAL_ADDRESS High = { MAXULONG64 };
	//	PVOID TempPage = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Low, High, Low, MmCached);

	//	PHYSICAL_ADDRESS phyAddress = MmGetPhysicalAddress(TempPage);

	//	MMPTE pNewNow = { 0 };
	//	pNewNow.u.Hard.Valid = 1;
	//	pNewNow.u.Hard.Writable = 1;
	//	pNewNow.u.Hard.Accessed = 1;
	//	pNewNow.u.Hard.Dirty = 1;
	//	pNewNow.u.Hard.PageFrameNumber = phyAddress.QuadPart >> 12;
	//	*(MMPTE*)PLM4[2] = pNewNow;
	//	__invlpg(PLM4[2]);
	//}






}

MMPTE* GetAddressPfn(ULONGLONG Address)
{
	DWORD64 PLM4[4] = { 0 };
	MiFillPteHierarchy(Address, PLM4);

	int i = 4;
	do
	{
		i--;
		MMPTE pCurMM = *(MMPTE*)PLM4[i];

		if (pCurMM.u.Hard.LargePage == 1){
			return PLM4[i];
		}
		if (pCurMM.u.Hard.Valid == 0)
		{
			return 0;
		}
	} while (i != 0);
	return PLM4[0];
}








typedef struct HOOK_PAGE {
	MMPTE OLD_PTE;
	MMPTE NEW_PTE;
	char* PAGE;
	struct HOOK_PAGE* uNextLevel;
}HOOK_PAGE;


typedef struct PID_PAGE{

	DWORD64 LockSelf;
	HANDLE PID;
	HOOK_PAGE  nPAGE[512];
	DWORD64 Type;
}PID_PAGE,*LPPID_PAGE;



PID_PAGE PAGE_PROCESS = { 0 };

//  查看是否已经迭代过  
//  Hide /










//typedef struct _FILTER_PID {
//	DWORD64 LockSelf;
//	HANDLE dwPID;
//	HWND hwnd;
//	BRPOINT p;
//	BOOLEAN bON;
//	RAWINPUT Raw;
//	unsigned char key[256];
//	int Type;
//	int VKey;
//}FILTER_PID, * PFILTER_PID;


//---------------------------------------------------------------------
_Function_class_(RTL_AVL_COMPARE_ROUTINE)
RTL_GENERIC_COMPARE_RESULTS CompareMemoryAVL(struct _RTL_AVL_TABLE* Table, PVOID  FirstStruct, PVOID  SecondStruct)
{
	LPPID_PAGE first = (LPPID_PAGE)FirstStruct;
	LPPID_PAGE second = (LPPID_PAGE)SecondStruct;
	UNREFERENCED_PARAMETER(Table);
	if (first->PID > second->PID)
		return GenericGreaterThan;
	if (first->PID < second->PID)
		return GenericLessThan;
	return GenericEqual;
}

_Function_class_(RTL_AVL_ALLOCATE_ROUTINE)
PVOID AllocateMemoryAVL(struct _RTL_AVL_TABLE* Table, CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	PVOID r = ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'tag');
	RtlZeroMemory(r, ByteSize);
	return r;
}

_Function_class_(RTL_AVL_FREE_ROUTINE)
VOID FreeMemoryAVL(struct _RTL_AVL_TABLE* Table, PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	ExFreePoolWithTag(Buffer, 'tag');
}



AVL_INFO MemoryAVL;

BOOLEAN IniMemoryAvl = FALSE;


PVOID AVL_LOCK_MEMORY_VOID(DWORD flags, PAVL_INFO Avl, PVOID pInfo, DWORD nSize)
{
	PVOID fID = 0;
	KIRQL irql = 0;
	KeAcquireSpinLock(&Avl->Lock, &irql);
	__try
	{
		//KeAcquireSpinLockAtDpcLevel(&Avl->Lock);
		if (flags == AVL_ADD) {
			BOOLEAN r = FALSE;
			RtlInsertElementGenericTableAvl(&Avl->AVL_Table, pInfo, nSize, &r);
			if (r) {
				fID = pInfo;
			}
		}
		else if (flags == AVL_DEL) {

			PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
			if (pInfoV != 0) {
				//RtlCopyMemory(pInfo, pInfoV, nSize);
				if (*(DWORD64*)pInfoV == 0)
				{
					if (RtlDeleteElementGenericTableAvl(&Avl->AVL_Table, pInfo)) {
						fID = pInfo;
					}
				}
			}
		}
		else if (flags == AVL_GET) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
			if (pInfoV != 0)
			{
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_MOD) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
			if (pInfoV != 0) {
				RtlCopyMemory(pInfoV, pInfo, nSize);
				fID = pInfoV;
			}
		}
		else if (flags == AVL_LOCK) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
			if (pInfoV != 0)
			{
				(*(DWORD64*)pInfoV)++;
				RtlCopyMemory(pInfo, pInfoV, nSize);
			}
			fID = pInfoV;
		}
		else if (flags == AVL_UNLOCK) {
			PVOID pInfoV = RtlLookupElementGenericTableAvl(&Avl->AVL_Table, pInfo);
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
	KeReleaseSpinLock(&Avl->Lock, irql);
	return fID;
}








static PID_PAGE nGlobalPage;



 //wIsPhysicalAddress()
 // PhyAddress

BOOLEAN MiSingleProcessPhyMemory(PEPROCESS Process, PVOID Poiner, SIZE_T nSize, PVOID* NewPoiner) {

	DWORD64 DirectoryTableBase = *(DWORD64*)((ULONGLONG)Process + 0x28);
	DWORD64 PLM4[4] = { 0 };
	MiFillPteHierarchy((ULONGLONG)Poiner, PLM4);

	DWORD uPML4 = 4;
	HOOK_PAGE* pInfo = nGlobalPage.nPAGE;
	PHYSICAL_ADDRESS pHyAddress;
	pHyAddress.QuadPart = DirectoryTableBase;
	MMPTE uPTE = { 0 };

	do
	{
		uPML4--;
		DWORD offset = (PLM4[uPML4] & 0xFFF) >> 3;
		if (pInfo == 0)
		{
			break;
		}

		if (pInfo[offset].PAGE == 0)
		{
			__invlpg(PLM4[uPML4]);
			uPTE = *((MMPTE*)PLM4[uPML4]);
			LOG_DEBUG("uPTE READ %I64X   %d\n", uPTE, uPML4);
			if (uPML4 == 0)
			{
				break;
			}
			if (uPTE.u.Hard.LargePage == 1)
			{
				break;
			}

			pInfo[offset].OLD_PTE = uPTE;
			PHYSICAL_ADDRESS Low = { 0 };
			PHYSICAL_ADDRESS High = { MAXULONG64 };
			PVOID TempPage = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Low, High, Low, MmCached);
			pInfo[offset].PAGE = TempPage;

			RtlCopyMemory(TempPage, (PVOID)(PLM4[uPML4 - 1] & 0xFFFFFFFFFFFFF000), PAGE_SIZE);
			pInfo[offset].PAGE = TempPage;

			LOG_DEBUG("New PAGE %d %p\n", uPML4, pInfo[offset].PAGE);
			if (uPML4 != 0 && pInfo[offset].uNextLevel == 0)
			{
				pInfo[offset].uNextLevel = ExAllocatePoolWithTag(PagedPool, sizeof(HOOK_PAGE) * 512, 'tag');
				RtlZeroMemory(pInfo[offset].uNextLevel, sizeof(HOOK_PAGE) * 512);
			}

			LOG_DEBUG("NewTable[%d] %p \n", uPML4, pInfo[offset].uNextLevel);
			PHYSICAL_ADDRESS Now = MmGetPhysicalAddress(pInfo[offset].PAGE);
			if (Now.QuadPart == 0)
			{
				LOG_DEBUG("ReadPhysicalAddress==0 False %d\n", __LINE__);
				break;
			}
			MMPTE fPTE = uPTE;
			fPTE.u.Hard.PageFrameNumber = Now.QuadPart >> 12;
			LONG64 Rlong = 0;
			RtlCopyMemory(&Rlong, &fPTE, sizeof(fPTE));
			__invlpg(PLM4[uPML4]);
			do
			{
				InterlockedExchange64((LONG64*)PLM4[uPML4], Rlong);
				__invlpg(PLM4[uPML4]);
			} while ((*((PMMPTE)PLM4[uPML4])).u.Long != 
				fPTE.u.Long);
			pInfo[offset].NEW_PTE = fPTE;
			pInfo = pInfo[offset].uNextLevel;


#ifdef DEBUG
			DWORD64 NowTTE = 0;
			RtlCopyMemory(&NowTTE, PLM4[uPML4], sizeof(MMPTE));
			LOG_DEBUG("Check  %I64X  TO  %I64X  TO %I64X %d \n", uPTE, fPTE, NowTTE, uPML4);
#endif // DEBUG
		}
		else
		{
			//RtlCopyMemory(&uPTE, PLM4[uPML4], sizeof(MMPTE));
			__invlpg(PLM4[uPML4]);
			uPTE = *((MMPTE*)PLM4[uPML4]);
			if (uPML4 == 0) {
				break;
			}
			if (uPTE.u.Hard.LargePage == 1) {
				//pInfo = pInfo[offset].uNextLevel;
				break;
			}
			if (uPTE.u.Hard.PageFrameNumber != 
				pInfo[offset].NEW_PTE.u.Hard.PageFrameNumber)
			{
				LONG64 Rlong = 0;
				RtlCopyMemory(&Rlong, &pInfo[offset].NEW_PTE, sizeof(pInfo[offset].NEW_PTE));
				do
				{
					InterlockedExchange64((LONG64*)PLM4[uPML4], Rlong);
					__invlpg(PLM4[uPML4]);
				} while ((*((PMMPTE)PLM4[uPML4])).u.Long != 
					pInfo[offset].NEW_PTE.u.Long);
				LOG_DEBUG("set NewPTE %d %d    %I64X\n", uPML4, __LINE__, pInfo[offset].NEW_PTE);
			}

			pInfo = pInfo[offset].uNextLevel;
			LOG_DEBUG("pInfo[offset].PAGE != 0  %d %d    %I64X\n", uPML4, __LINE__, uPTE);
		}

	} while (uPML4 > 0);

	if (uPML4 == 0)
	{
		return FALSE;
	}
	DWORD offset = (PLM4[uPML4] & 0xFFF) >> 3;
	if (uPML4 == 1)
	{
		__invlpg(PLM4[uPML4]);
		uPTE = *((MMPTE*)PLM4[uPML4]);
		if (pInfo[offset].PAGE == 0) {

			PHYSICAL_ADDRESS Low = { 0 };
			PHYSICAL_ADDRESS High = { MAXULONG64 };
			PHYSICAL_ADDRESS    BoundaryAddressMultiple = { 512 * PAGE_SIZE };
			
			PVOID TempPageBuffer = MmAllocateContiguousMemorySpecifyCache(512 * PAGE_SIZE, Low, High, BoundaryAddressMultiple, MmNonCached);

			PVOID AddressBegin =  (PVOID)((DWORD64)Poiner & (~((0x1FF << 12) | 0xFFF)));
			LOG_DEBUG("AddressBegin <%p> <%p>\n", Poiner, AddressBegin);
			RtlCopyMemory(TempPageBuffer, AddressBegin, 512 * PAGE_SIZE);
			pInfo[offset].PAGE = TempPageBuffer;
			PHYSICAL_ADDRESS Now = MmGetPhysicalAddress(pInfo[offset].PAGE);
			if (Now.QuadPart == 0)
			{
				LOG_DEBUG("MmGetPhysicalAddress False %d\n", __LINE__);
				return 0;
			}

			//- 拆分成细小的块
			//MMPTE* TempPageBufferFiv = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Low, High, BoundaryAddressMultiple, MmCached);
			//int IndexPage = Now.QuadPart >> 12;
			//PHYSICAL_ADDRESS NowFiv = MmGetPhysicalAddress(TempPageBufferFiv);
			//if (uPML4 != 0 && pInfo[offset].uNextLevel == 0){
			//	pInfo[offset].uNextLevel = ExAllocatePoolWithTag(PagedPool, sizeof(HOOK_PAGE) * 512, 'tag');
			//	RtlZeroMemory(pInfo[offset].uNextLevel, sizeof(HOOK_PAGE) * 512);
			//}
			//MMPTE uSinglePte;
			//uSinglePte.u.Long = 0x10000010BE47021;
			//uSinglePte.u.Hard.Write = 1;
			////0x10000010BE47021
			//for (size_t i = 0; i < 512; i++) {

			//	uSinglePte.u.Hard.PageFrameNumber = IndexPage + i;
			//	uSinglePte.u.Hard.NoExecute = 0;
			//	pInfo[offset].uNextLevel[i].NEW_PTE = uSinglePte;
			//	pInfo[offset].uNextLevel[i].OLD_PTE = uSinglePte;
			//	pInfo[offset].uNextLevel[i].PAGE = ((char*)TempPageBuffer) + i * PAGE_SIZE;
			//	TempPageBufferFiv[i] = uSinglePte;
			//}
			//pInfo[offset].PAGE = TempPageBufferFiv;


			LOG_DEBUG("end uPTE %d    %I64X\n", __LINE__, uPTE);
			//MMPTE fPTE = uPTE;
			MMPTE fPTE = uPTE;
			fPTE.u.HardLarge.PageFrameNumber = (Now.QuadPart >> 12) >> 9;
			//fPTE.u.Hard.PageFrameNumber = Now.QuadPart >> 12;
			//fPTE.u.HardLarge.Write = 1;
			//fPTE.u.Hard.Write = 1;
			//fPTE.u.Hard.Writable = 1;
		//	fPTE.u.Hard.WriteThrough = 1;
			//fPTE.u.Hard.Write = 1;
			//fPTE.u.Hard.Writable = 1;

			DWORD64 Rlong = 0;
			RtlCopyMemory(&Rlong, &fPTE, sizeof(fPTE));
			__invlpg(PLM4[uPML4]);
			do
			{
				//*((MMPTE*)PLM4[uPML4]) = fPTE;
				InterlockedExchange64((LONG64*)PLM4[uPML4], Rlong);
				__invlpg(PLM4[uPML4]);
			} while ((*((PMMPTE)PLM4[uPML4])).u.Long != 
				fPTE.u.Long);

			pInfo[offset].NEW_PTE = fPTE;
			pInfo[offset].OLD_PTE = uPTE;
			__invlpg(PLM4[0]);

#ifdef DEBUG
			DWORD64 NowTTE = 0;
			RtlCopyMemory(&NowTTE, PLM4[uPML4], sizeof(MMPTE));
			LOG_DEBUG("Check  %I64X  TO  %I64X  TO %I64X %d \n", uPTE, fPTE, NowTTE, uPML4);

			LOG_DEBUG("PhyAddress <%p>\n", MmGetPhysicalAddress(Poiner).QuadPart);
#endif // DEBUG

			//*NewPoiner = pInfo[offset].PAGE;

			ADDRESS_PTE uAddress;
			uAddress.u.Address = (ULONGLONG)TempPageBuffer;
			ADDRESS_PTE oAddress;
			oAddress.u.Address = (ULONGLONG)Poiner;
			uAddress.u.PXE_PageFrameNumber = oAddress.u.PXE_PageFrameNumber;
			*NewPoiner = (PVOID)uAddress.u.Address;

			LOG_DEBUG(" OUT PAGE_<%p><%p>\n", pInfo[offset].PAGE, uAddress.u.Address);
			return TRUE;
		}
		else
		{
			__invlpg(PLM4[uPML4]);
			uPTE = *((MMPTE*)PLM4[uPML4]);
			LOG_DEBUG("uPTE %d  %I64X\n", __LINE__, uPTE);
			if (uPTE.u.Long != 
				pInfo[offset].NEW_PTE.u.Long)
			{
				LOG_DEBUG("set New uPTE %d  %I64X\n", __LINE__, pInfo[offset].NEW_PTE);
				LONG64 Rlong = 0;
				RtlCopyMemory(&Rlong, &pInfo[offset].NEW_PTE, sizeof(pInfo[offset].NEW_PTE));
				do
				{
					InterlockedExchange64((LONG64*)PLM4[uPML4], Rlong);
					__invlpg(PLM4[uPML4]);
				} while ((*((PMMPTE)PLM4[uPML4])).u.Long != 
					pInfo[offset].NEW_PTE.u.Long);
			}
			LOG_DEBUG("Sucess %d  %I64X\n", __LINE__, uPTE);

			ADDRESS_PTE uAddress;
			uAddress.u.Address = (ULONGLONG)pInfo[offset].PAGE;
			ADDRESS_PTE oAddress;
			oAddress.u.Address = (ULONGLONG)Poiner;
			uAddress.u.PXE_PageFrameNumber = oAddress.u.PXE_PageFrameNumber;
			*NewPoiner = (PVOID)uAddress.u.Address;
			LOG_DEBUG(" OUT PAGE_<%p><%p>\n", pInfo[offset].PAGE, uAddress.u.Address);
			return TRUE;
		}
	}
	return FALSE;



}

BOOLEAN MiSingleProcessVirtualMemory(PEPROCESS Process, PVOID Poiner, SIZE_T nSize, PVOID* NewPoiner) {

	DWORD64 DirectoryTableBase = *(DWORD64*)((ULONGLONG)Process + 0x28);
	DWORD64 PLM4[4] = { 0 };
	MiFillPteHierarchy((ULONGLONG)Poiner, PLM4);

	DWORD uPML4 = 4;
	HOOK_PAGE* pInfo = nGlobalPage.nPAGE;
	PHYSICAL_ADDRESS pHyAddress;
	pHyAddress.QuadPart = DirectoryTableBase;
	MMPTE uPTE = { 0 };


	PHYSICAL_ADDRESS Low = { 0 };
	PHYSICAL_ADDRESS High = { MAXULONG64 };
	PVOID TempPageBuffer = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Low, High, Low, MmCached);
	if (TempPageBuffer == NULL)
	{
		return FALSE;
	}
	RtlCopyMemory(TempPageBuffer, Poiner, PAGE_SIZE);

	//if (MmGetPhysicalAddress(Poiner).QuadPart != 0)
	//{
	//	uPTE = *((MMPTE*)PLM4[0]);
	//	LOG_DEBUG("uPTE <uPTE  %p>\n", uPTE);
	//}

	do
	{
		uPML4--;
		DWORD offset = (PLM4[uPML4] & 0xFFF) >> 3;
		if (pInfo == 0)
		{
			break;
		}

		if (pInfo[offset].PAGE == 0)
		{
			uPTE = *((MMPTE*)PLM4[uPML4]);

			LOG_DEBUG("uPTE READ %I64X   %d\n", uPTE, uPML4);

			if (uPML4 == 0)
			{
				break;
			}
			pInfo[offset].OLD_PTE = uPTE;

			PHYSICAL_ADDRESS Low = { 0 };
			PHYSICAL_ADDRESS High = { MAXULONG64 };
			PVOID TempPage = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Low, High, Low, MmNonCached);

			pInfo[offset].PAGE = TempPage;//ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, 'tag');

			RtlCopyMemory(TempPage, (PVOID)(PLM4[uPML4 - 1] & 0xFFFFFFFFFFFFF000), PAGE_SIZE);
			pInfo[offset].PAGE = TempPage;

			LOG_DEBUG("New PAGE %d %p\n", uPML4, pInfo[offset].PAGE);
			if (uPML4 != 0 && pInfo[offset].uNextLevel == 0)
			{
				pInfo[offset].uNextLevel = ExAllocatePoolWithTag(PagedPool, sizeof(HOOK_PAGE) * 512, 'tag');
				RtlZeroMemory(pInfo[offset].uNextLevel, sizeof(HOOK_PAGE) * 512);
			}

			LOG_DEBUG("NewTable[%d] %p \n", uPML4, pInfo[offset].uNextLevel);

			PHYSICAL_ADDRESS Now = MmGetPhysicalAddress(pInfo[offset].PAGE);
			if (Now.QuadPart == 0)
			{
				LOG_DEBUG("ReadPhysicalAddress==0 False %d\n", __LINE__);
				break;
			}
			MMPTE fPTE = uPTE;
			fPTE.u.Hard.PageFrameNumber = Now.QuadPart >> 12;
			fPTE.u.Hard.Writable = 1;
			fPTE.u.Hard.Write = 1;
			LONG64 Rlong = 0;
			RtlCopyMemory(&Rlong, &fPTE, sizeof(fPTE));
			__invlpg(PLM4[uPML4]);
			do
			{
				InterlockedExchange64((LONG64*)PLM4[uPML4], Rlong);
				__invlpg(PLM4[uPML4]);
			} while ((*((PMMPTE)PLM4[uPML4])).u.Long != 
				fPTE.u.Long);
			pInfo[offset].NEW_PTE = fPTE;
			pInfo = pInfo[offset].uNextLevel;


#ifdef DEBUG
			DWORD64 NowTTE = 0;
			RtlCopyMemory(&NowTTE, PLM4[uPML4], sizeof(MMPTE));
			LOG_DEBUG("Check  %I64X  TO  %I64X  TO %I64X %d \n", uPTE, fPTE, NowTTE, uPML4);
#endif // DEBUG
		}
		else
		{
			//RtlCopyMemory(&uPTE, PLM4[uPML4], sizeof(MMPTE));
			__invlpg(PLM4[uPML4]);
			uPTE = *((MMPTE*)PLM4[uPML4]);
			if (uPML4 == 0) {
				break;
			}
			if (uPTE.u.Long != 
				pInfo[offset].NEW_PTE.u.Long)
			{
				LONG64 Rlong = 0;
				RtlCopyMemory(&Rlong, &pInfo[offset].NEW_PTE, sizeof(pInfo[offset].NEW_PTE));
				do
				{
					InterlockedExchange64((LONG64*)PLM4[uPML4], Rlong);
					__invlpg(PLM4[uPML4]);
				} while ((*((PMMPTE)PLM4[uPML4])).u.Long != 
					pInfo[offset].NEW_PTE.u.Long);
				LOG_DEBUG("set NewPTE %d %d    %I64X\n", uPML4, __LINE__, pInfo[offset].NEW_PTE);
			}

			pInfo = pInfo[offset].uNextLevel;
			LOG_DEBUG("pInfo[offset].PAGE != 0  %d %d    %I64X\n", uPML4, __LINE__, uPTE);
		}

	} while (uPML4 > 0);

	if (uPML4 != 0)
	{
		MmFreeContiguousMemory(TempPageBuffer);
		return FALSE;
	}
	__invlpg(PLM4[0]);
	DWORD offset = (PLM4[0] & 0xFFF) >> 3;
	if (pInfo[offset].PAGE == 0)
	{
		uPTE = *((MMPTE*)PLM4[0]);
		pInfo[offset].OLD_PTE = uPTE;

		LOG_DEBUG("Run uPTE %d    %I64X   <%p>\n", __LINE__, uPTE, uPTE.u.Hard.PageFrameNumber << 12);

		pInfo[offset].PAGE = TempPageBuffer;

		LOG_DEBUG("Run uPTE %d    %I64X\n", __LINE__, uPTE);

		PHYSICAL_ADDRESS Now = MmGetPhysicalAddress(pInfo[offset].PAGE);
		if (Now.QuadPart == 0)
		{
			LOG_DEBUG("MmGetPhysicalAddress False %d\n", __LINE__);
			return 0;
		}

		LOG_DEBUG("end uPTE %d    %I64X\n", __LINE__, uPTE);
		MMPTE fPTE = uPTE;
		fPTE.u.Hard.PageFrameNumber = Now.QuadPart >> 12;
		fPTE.u.Hard.Write = 1;


		LONG64 Rlong = 0;
		RtlCopyMemory(&Rlong, &fPTE, sizeof(fPTE));


		//	KIRQL Irql = KzRaiseIrql(HIGH_LEVEL);
			//RtlCopyMemory(PLM4[0], &uPTE, sizeof(MMPTE));

		__invlpg(PLM4[0]);
		do
		{
		//	*((MMPTE*)PLM4[0]) = fPTE;
			InterlockedExchange64((LONG64*)PLM4[0], Rlong);
			__invlpg(PLM4[0]);
		} while ((*((PMMPTE)PLM4[0])).u.Long != 
			fPTE.u.Long);
		pInfo[offset].NEW_PTE = fPTE;
		MMPTE NowTTE = { 0 };
		NowTTE = *((MMPTE*)PLM4[0]);

		*NewPoiner = pInfo[offset].PAGE;

		//RtlCopyMemory(&NowTTE, PLM4[0], sizeof(MMPTE));
		LOG_DEBUG("Check  %I64X  TO  %I64X  TO %I64X 0 \n", uPTE, fPTE, NowTTE);
		return TRUE;

	}
	else
	{
		MmFreeContiguousMemory(TempPageBuffer);
		//RtlCopyMemory(&uPTE, PLM4[0], sizeof(MMPTE));
		__invlpg(PLM4[0]);
		uPTE = *((MMPTE*)PLM4[0]);
		if (uPTE.u.Long != 
			pInfo[offset].NEW_PTE.u.Long)
		{
			LONG64 Rlong = 0;
			RtlCopyMemory(&Rlong, &pInfo[offset].NEW_PTE, sizeof(pInfo[offset].NEW_PTE));
			do
			{
				InterlockedExchange64((LONG64*)PLM4[0], Rlong);
				__invlpg(PLM4[0]);
			} while ((*((PMMPTE)PLM4[0])).u.Long != 
				pInfo[offset].NEW_PTE.u.Long);
			LOG_DEBUG("set NewPTE %d %d    %I64X\n", uPML4, __LINE__, pInfo[offset].NEW_PTE);
		}
		*NewPoiner = pInfo[offset].PAGE;
		LOG_DEBUG("pInfo[offset].PAGE != 0  %d %d    %I64X\n", uPML4, __LINE__, uPTE);
		return TRUE;
	}
	return FALSE;
}


BOOLEAN MiSingleProcessMemory(PEPROCESS Process, PVOID Poiner, SIZE_T nSize, PVOID* NewPoiner)
{
	if (!IniMemoryAvl)
	{
		RtlInitializeGenericTableAvl(&MemoryAVL.AVL_Table, CompareMemoryAVL, AllocateMemoryAVL, FreeMemoryAVL, NULL);
		KeInitializeSpinLock(&MemoryAVL.Lock);
		RtlZeroMemory(&nGlobalPage, sizeof(PID_PAGE));
		IniMemoryAvl = TRUE;
	}
	LONGLONG bLargePage = MI_IS_PHYSICAL_ADDRESS2((ULONGLONG)Poiner);
	if (!bLargePage)
	{
		return MiSingleProcessVirtualMemory(Process, Poiner, nSize, NewPoiner);
	}
	return MiSingleProcessPhyMemory(Process, Poiner, nSize, NewPoiner);
}




unsigned __int64 __fastcall MiVaToPfn(unsigned __int64 a1, PEPROCESS Process)
{
	int v2; // edi
	__int64 v3; // rsi
	unsigned __int64 v4; // rcx
	__int64 v5; // rax
	unsigned __int64 v6; // rcx
	__int64 v7; // rdx
	unsigned __int64 v8; // rbx
	__int16 v9; // ax
	__int64 v10; // rax
	DWORD64 v13[4]; // [rsp+20h] [rbp-28h] BYREF
	__int64 v14; // [rsp+58h] [rbp+10h] BYREF
	LOG_DEBUG(" %s %d\n", __FUNCTION__, __LINE__);
	memset(v13, 0, 32);
	MiFillPteHierarchy(a1, v13);
	v2 = 4;
	v3 = 4i64;
	do
	{
		v4 = v13[v3 - 1];
		v3--;
		--v2;
		v5 = MI_READ_PTE_LOCK_FREE(v4, Process);
		v14 = v5;
	} while (v3 && (v5 & 0x80u) == 0i64);
	v6 = ((unsigned __int64)MI_READ_PTE_LOCK_FREE((unsigned __int64)&v14, Process) >> 12) & 0xFFFFFFFFFi64;
	if (v2)
	{
		v7 = 1i64;
		v8 = a1 >> 12;
		do
		{
			v9 = (short)v8;
			v8 >>= 9;
			v10 = v7 * (v9 & 0x1FF);
			v7 <<= 9;
			v6 += v10;
			--v2;
		} while (v2);
	}
	return v6;
}

signed __int64 __fastcall MiSetNonPagedPoolNoSteal(volatile signed __int64* a1, PEPROCESS Process)
{
	signed __int64 result; // rax
	signed __int64 v6; // rtt
	LOG_DEBUG(" %s %d\n", __FUNCTION__, __LINE__);
	result = MI_READ_PTE_LOCK_FREE((ULONGLONG)a1, Process);
	do
	{
		if ((result & 0x200) != 0)
			break;
		v6 = result;
		result = _InterlockedCompareExchange64(a1, result | 0x220, result);
	} while (v6 != result);
	return result;
}

BOOLEAN __fastcall MiPteInShadowRange(unsigned __int64 a1)
{
	LOG_DEBUG(" %s %d\n", __FUNCTION__, __LINE__);
	return a1 >= PXE_BASE && a1 <= PXE_SELFMAP;
}

__int64 __fastcall MiGetSystemRegionType(unsigned __int64 a1)
{
	LOG_DEBUG(" %s %d\n", __FUNCTION__, __LINE__);
	if (a1 < 0xFFFF800000000000ui64)
		return 0i64;
	else
		return (unsigned __int8)pPhysicalByte[((a1 >> 39) & 0x1FF) - 256];
}

__int64 __fastcall MiGetPhysicalAddress(__int64 a1, unsigned __int64* a2, DWORD* a3,PEPROCESS Process)
{
	int v6; // eax
	__int64 v7; // rsi
	__int64 v8; // rbx
	BOOLEAN v9; // zf
	__int64 v10; // rbx
	__int64 result; // rax
	__int64 v12; // rbx
	unsigned __int64 v13; // rcx
	volatile signed __int64* v14; // rsi
	unsigned __int64 v15; // rbx
	__int64 v16; // rdx
	__int64 v17; // r8
	__int64 v18; // r9
	int SystemRegionType; // r14d
	LIST_ENTRY* Flink; // rdx
	__int64 v21; // rax
	__int64 v22; // rdx
	__int64 v23; // [rsp+18h] [rbp-28h]
	DWORD64 v24[4]; // [rsp+20h] [rbp-20h] BYREF
	unsigned __int64 v25; // [rsp+80h] [rbp+40h] BYREF




	LOG_DEBUG(" %s %d\n", __FUNCTION__, __LINE__);

	*a3 = 0;
	memset(v24, 0, sizeof(v24));
	MiFillPteHierarchy(a1, v24);
	v6 = (int)MI_IS_PHYSICAL_ADDRESS((ULONGLONG)a1,Process);

	LOG_DEBUG(" MI_IS_PHYSICAL_ADDRESS r <%p>\n", v6);

	v7 = v6;
	if (v6)
	{
		LOG_DEBUG("What?? PHYSICAL_ADDRESS True  \n");
		v8 = MiVaToPfn(a1,Process);
		v9 = (MI_READ_PTE_LOCK_FREE(*((_QWORD*)v24 + v7),Process) & 0x800) == 0;
	}
	else
	{
		v12 = 4i64;
		do
		{
			v13 = v24[v12 - 1];
			if ((MI_READ_PTE_LOCK_FREE(v13,Process) & 1) == 0)
				return 0i64;
			v12--;
		} while (v12 != 1);


		v14 = *(volatile signed __int64**)&v24[0];
		LOG_DEBUG("v14<%p>\n", v14);
		v25 = MI_READ_PTE_LOCK_FREE(*(unsigned __int64*)&v24[0], Process);
		LOG_DEBUG("v25<%p>\n", v25);
		
		v15 = v25;

		SystemRegionType = (int)MiGetSystemRegionType((ULONGLONG)a1);
		if (SystemRegionType == 12)
			//MiQueuePinDriverAddressLog(a1, v15, 0i64);
		if ((v15 & 1) == 0)
			return 0i64;
		if (SystemRegionType == 5)
		{
			MiSetNonPagedPoolNoSteal(v14, Process);
			v15 = MI_READ_PTE_LOCK_FREE((unsigned __int64)v14, Process);
			v25 = v15;
			LOG_DEBUG("v15<%p>  %d\n", v15, __LINE__);
		}

		// 这一节有用吗  毛用都没有 下面只是权限问题 
		UCHAR AddressPolicy = *(UCHAR*)((ULONGLONG)Process + 0x390);
		if ((unsigned int)MiPteInShadowRange((ULONGLONG)&v25)
			&& (*MiFlags & 0xC00000) != 0
			&& AddressPolicy != 1
			&& (v15 & 1) != 0
			&& ((v15 & 0x20) == 0 || (v15 & 0x42) == 0))
		{
			Flink =  (LIST_ENTRY*)*(DWORD64*)((ULONGLONG)Process + 0x788);
			if (Flink)
			{
				LOG_DEBUG("Fink  Read  %d\n", __LINE__);
				v21 = *((_QWORD*)&Flink->Flink + (((unsigned __int64)&v25 >> 3) & 0x1FF));
				v22 = v15 | 0x20;
				if ((v21 & 0x20) == 0)
					v22 = v15;
				v15 = v22;
				if ((v21 & 0x42) != 0)
					v15 = v22 | 0x42;
			}
		}
		v8 = (v15 >> 12) & 0xFFFFFFFFFi64;

		v9 = (v25 & 0x800) == 0;
	}
	if (!v9)
		*a3 = 1;
	v10 = v8 << 12;
	//HIDWORD(v25) = HIDWORD(v10);
	// LODWORD(v25) = (a1 & 0xFFF) + v10;
	v25 = (v10 & 0xFFFFFFFF00000000) | (((a1 & 0xFFF) + v10) & 0xFFFFFFFF);

	result = 1i64;
	
	*a2 = v25;
	return result;
}

PHYSICAL_ADDRESS __stdcall wMmGetPhysicalAddress(PVOID BaseAddress, PEPROCESS eprocess)
{
	int PhysicalAddress; // eax
	int v3; // [rsp+38h] [rbp+10h] BYREF
	__int64 v4; // [rsp+40h] [rbp+18h] BYREF

	v3 = 0;
	v4 = 0i64;
	PhysicalAddress = (int)MiGetPhysicalAddress((LONGLONG)BaseAddress, &v4, &v3, eprocess);

	PHYSICAL_ADDRESS Physical;
	Physical.QuadPart = (v4 & -(__int64)(PhysicalAddress != 0));
	return Physical;
}








DWORD64 WeGetProcessType(HANDLE PID)
{
	if (!IniMemoryAvl)
	{
		RtlInitializeGenericTableAvl(&MemoryAVL.AVL_Table, CompareMemoryAVL, AllocateMemoryAVL, FreeMemoryAVL, NULL);
		KeInitializeSpinLock(&MemoryAVL.Lock);
		RtlZeroMemory(&nGlobalPage, sizeof(PID_PAGE));
		IniMemoryAvl = TRUE;
	}
	PID_PAGE PageInfo = { 0 };
	PageInfo.PID = PID;
	LPPID_PAGE pPageI = AVL_LOCK_MEMORY_VOID(AVL_LOCK, &MemoryAVL, &PageInfo, sizeof(PID_PAGE));
	if (pPageI == 0)
	{
		return 0;
	}
	DWORD64 Type = pPageI->Type;
	AVL_LOCK_MEMORY_VOID(AVL_UNLOCK, &MemoryAVL, &PageInfo, sizeof(PID_PAGE));
	return Type;
}

DWORD64 WeSetProcessType(HANDLE PID, DWORD64 dwType)
{
	if (!IniMemoryAvl)
	{
		RtlInitializeGenericTableAvl(&MemoryAVL.AVL_Table, CompareMemoryAVL, AllocateMemoryAVL, FreeMemoryAVL, NULL);
		KeInitializeSpinLock(&MemoryAVL.Lock);
		RtlZeroMemory(&nGlobalPage, sizeof(PID_PAGE));
		IniMemoryAvl = TRUE;
	}
	PID_PAGE PageInfo = { 0 };
	PageInfo.PID = PID;
	LPPID_PAGE pPageI = AVL_LOCK_MEMORY_VOID(AVL_LOCK, &MemoryAVL, &PageInfo, sizeof(PID_PAGE));
	if (pPageI == 0)
	{
		PageInfo.Type = dwType;
		AVL_LOCK_MEMORY_VOID(AVL_ADD, &MemoryAVL, &PageInfo, sizeof(PID_PAGE));
		return 0;
	}
	pPageI->Type  = dwType;
	AVL_LOCK_MEMORY_VOID(AVL_UNLOCK, &MemoryAVL, &PageInfo, sizeof(PID_PAGE));
	return dwType;
}
